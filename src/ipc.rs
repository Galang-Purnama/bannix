use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, info};

use crate::config::AppConfig;
use crate::engine::BanRegistry;
use crate::firewall::FirewallBackend;

pub const DEFAULT_SOCKET: &str = "/run/bannix/bannix.sock";
pub const FALLBACK_SOCKETS: &[&str] = &[
    "/run/bannix/bannix.sock",
    "/run/bannix.sock",
    "/tmp/bannix.sock",
];

// ponytail: single socket path without dynamic bind migration; fine until multi-tenant daemons needed
pub fn resolve_socket_path(preferred: &str) -> PathBuf {
    let p = Path::new(preferred);
    if let Some(parent) = p.parent() {
        if !parent.as_os_str().is_empty() && fs::create_dir_all(parent).is_ok() {
            return p.to_path_buf();
        }
    }
    if Path::new("/run").is_dir()
        && fs::metadata("/run")
            .map(|m| !m.permissions().readonly())
            .unwrap_or(false)
    {
        PathBuf::from("/run/bannix.sock")
    } else {
        PathBuf::from("/tmp/bannix.sock")
    }
}

pub fn find_socket_path(custom: Option<&str>) -> Option<PathBuf> {
    if let Some(c) = custom {
        let p = PathBuf::from(c);
        if p.exists() {
            return Some(p);
        }
    }
    for candidate in FALLBACK_SOCKETS {
        let p = PathBuf::from(candidate);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

pub async fn send_command(socket_path: &Path, command: &str) -> Result<String, std::io::Error> {
    let mut stream = UnixStream::connect(socket_path).await?;
    stream.write_all(command.as_bytes()).await?;
    if !command.ends_with('\n') {
        stream.write_all(b"\n").await?;
    }
    stream.shutdown().await?;

    let mut response = String::new();
    let mut reader = TokioBufReader::new(stream);
    reader.read_to_string(&mut response).await?;
    Ok(response)
}

pub async fn run_ipc_server(
    socket_path: PathBuf,
    cfg: Arc<RwLock<AppConfig>>,
    fw: Arc<Mutex<Box<dyn FirewallBackend>>>,
    bans: Arc<RwLock<BanRegistry>>,
    start_time: Instant,
) -> Result<(), std::io::Error> {
    if let Some(parent) = socket_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path)?;
    info!("IPC control socket listening at {:?}", socket_path);

    loop {
        match listener.accept().await {
            Ok((mut stream, _)) => {
                let cfg_ref = Arc::clone(&cfg);
                let fw_ref = Arc::clone(&fw);
                let bans_ref = Arc::clone(&bans);

                tokio::spawn(async move {
                    let (reader, mut writer) = stream.split();
                    let mut buf_reader = TokioBufReader::new(reader);
                    let mut line = String::new();

                    if buf_reader.read_line(&mut line).await.is_ok() {
                        let response = handle_ipc_command(
                            line.trim(),
                            &cfg_ref,
                            &fw_ref,
                            &bans_ref,
                            start_time,
                        );
                        let _ = writer.write_all(response.as_bytes()).await;
                        let _ = writer.shutdown().await;
                    }
                });
            }
            Err(e) => {
                debug!("IPC accept error: {}", e);
            }
        }
    }
}

pub fn handle_ipc_command(
    cmd: &str,
    cfg: &Arc<RwLock<AppConfig>>,
    fw: &Arc<Mutex<Box<dyn FirewallBackend>>>,
    bans: &Arc<RwLock<BanRegistry>>,
    start_time: Instant,
) -> String {
    let trimmed = cmd.trim();
    if trimmed.eq_ignore_ascii_case("PING") {
        return "PONG\n".to_string();
    }
    if trimmed.eq_ignore_ascii_case("STATUS") {
        return format_status(cfg, fw, bans, start_time);
    }
    if let Some(arg) = trimmed
        .strip_prefix("UNBAN ")
        .or_else(|| trimmed.strip_prefix("unban "))
    {
        return handle_unban(arg.trim(), fw, bans);
    }
    if let Some(arg) = trimmed
        .strip_prefix("BAN ")
        .or_else(|| trimmed.strip_prefix("ban "))
    {
        return handle_ban(arg.trim(), fw, bans);
    }

    if let Some(arg) = trimmed
        .strip_prefix("LIST_JSON")
        .or_else(|| trimmed.strip_prefix("list_json"))
    {
        let jail = arg.trim();
        return format_list_jails(
            cfg,
            fw,
            bans,
            if jail.is_empty() { None } else { Some(jail) },
            true,
        );
    }
    if let Some(arg) = trimmed
        .strip_prefix("LIST")
        .or_else(|| trimmed.strip_prefix("list"))
    {
        let jail = arg.trim();
        return format_list_jails(
            cfg,
            fw,
            bans,
            if jail.is_empty() { None } else { Some(jail) },
            false,
        );
    }

    if let Some(arg) = trimmed
        .strip_prefix("BANNED_JSON")
        .or_else(|| trimmed.strip_prefix("banned_json"))
    {
        let jail = arg.trim();
        return format_banned_ips(
            cfg,
            fw,
            bans,
            if jail.is_empty() { None } else { Some(jail) },
            true,
        );
    }
    if let Some(arg) = trimmed
        .strip_prefix("BANNED")
        .or_else(|| trimmed.strip_prefix("banned"))
    {
        let jail = arg.trim();
        return format_banned_ips(
            cfg,
            fw,
            bans,
            if jail.is_empty() { None } else { Some(jail) },
            false,
        );
    }

    "ERROR: Unknown command. Supported: status, list [jail], banned [jail], unban <IP>, ban <IP> [seconds], ping\n".to_string()
}

fn handle_unban(
    arg: &str,
    fw: &Arc<Mutex<Box<dyn FirewallBackend>>>,
    bans: &Arc<RwLock<BanRegistry>>,
) -> String {
    match arg.parse::<IpAddr>() {
        Ok(ip) => {
            let mut fw_lock = fw.lock().unwrap();
            match fw_lock.unban_ip(ip) {
                Ok(_) => {
                    bans.write().unwrap().remove_ban(&ip);
                    format!("OK: Unbanned IP {}\n", ip)
                }
                Err(e) => format!("ERROR: Failed to unban {}: {}\n", ip, e),
            }
        }
        Err(_) => format!("ERROR: Invalid IP address '{}'\n", arg),
    }
}

fn handle_ban(
    arg: &str,
    fw: &Arc<Mutex<Box<dyn FirewallBackend>>>,
    bans: &Arc<RwLock<BanRegistry>>,
) -> String {
    let parts: Vec<&str> = arg.split_whitespace().collect();
    if parts.is_empty() {
        return "ERROR: Missing IP address\n".to_string();
    }
    match parts[0].parse::<IpAddr>() {
        Ok(ip) => {
            let timeout = parts
                .get(1)
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(3600);
            let jail = parts.get(2).copied().unwrap_or("manual");
            let mut fw_lock = fw.lock().unwrap();
            match fw_lock.ban_ip(ip, timeout) {
                Ok(_) => {
                    bans.write().unwrap().record_ban(ip, jail, timeout);
                    format!("OK: Banned IP {} for {}s (jail: {})\n", ip, timeout, jail)
                }
                Err(e) => format!("ERROR: Failed to ban {}: {}\n", ip, e),
            }
        }
        Err(_) => format!("ERROR: Invalid IP address '{}'\n", parts[0]),
    }
}

fn format_status(
    cfg: &Arc<RwLock<AppConfig>>,
    fw: &Arc<Mutex<Box<dyn FirewallBackend>>>,
    bans: &Arc<RwLock<BanRegistry>>,
    start_time: Instant,
) -> String {
    let cfg_read = cfg.read().unwrap();
    let fw_lock = fw.lock().unwrap();
    let uptime = start_time.elapsed().as_secs();

    let mut out = String::new();
    out.push_str(&format!("bannix daemon v{}\n", env!("CARGO_PKG_VERSION")));
    out.push_str(&format!("Uptime: {}s\n", uptime));
    out.push_str(&format!(
        "Backend: {} (table: {})\n",
        fw_lock.name(),
        cfg_read.daemon.table_name
    ));
    out.push_str(&format!(
        "Whitelisted: {} entries\n",
        cfg_read.whitelist.ips.len()
    ));
    out.push_str(&format!(
        "Currently Banned: {} IP(s)\n",
        bans.read().unwrap().total_active()
    ));

    let mut active_jails: Vec<_> = cfg_read.jails.iter().filter(|(_, j)| j.enabled).collect();
    active_jails.sort_by_key(|(name, _)| *name);
    out.push_str(&format!("Active Jails ({}):\n", active_jails.len()));
    for (name, jail) in active_jails {
        let jail_banned = bans.read().unwrap().count_for_jail(name);
        out.push_str(&format!(
            "  • {:<10} | log: {} | mode: {} | retry: {}/{}s | ban: {}s | banned: {}\n",
            name, jail.log_path, jail.mode, jail.maxretry, jail.findtime, jail.bantime, jail_banned
        ));
    }
    out
}

fn format_list_jails(
    cfg: &Arc<RwLock<AppConfig>>,
    fw: &Arc<Mutex<Box<dyn FirewallBackend>>>,
    bans: &Arc<RwLock<BanRegistry>>,
    jail_filter: Option<&str>,
    is_json: bool,
) -> String {
    // 1. Sync with kernel firewall first
    {
        let fw_lock = fw.lock().unwrap();
        let kernel_bans = fw_lock.list_banned();
        bans.write().unwrap().sync_with_kernel(&kernel_bans);
    }

    let cfg_read = cfg.read().unwrap();
    let registry = bans.read().unwrap();
    let now = BanRegistry::current_timestamp();

    // If a specific jail was requested
    if let Some(jail_name) = jail_filter {
        if let Some(jail) = cfg_read.jails.get(jail_name) {
            let active_bans = registry.list_active(Some(jail_name));
            if is_json {
                let mut json = String::new();
                json.push_str(&format!(
                    "{{\"name\": \"{}\", \"enabled\": {}, \"mode\": \"{}\", \"log_path\": \"{}\", \"maxretry\": {}, \"findtime\": {}, \"bantime\": {}, \"banned_count\": {}, \"banned_ips\": [",
                    jail_name, jail.enabled, jail.mode, jail.log_path, jail.maxretry, jail.findtime, jail.bantime, active_bans.len()
                ));
                for (i, b) in active_bans.iter().enumerate() {
                    if i > 0 {
                        json.push_str(", ");
                    }
                    let rem_str = b
                        .remaining_secs(now)
                        .map(|r| r.to_string())
                        .unwrap_or_else(|| "null".to_string());
                    json.push_str(&format!(
                        "{{\"ip\": \"{}\", \"remaining\": {}}}",
                        b.ip, rem_str
                    ));
                }
                json.push_str("]}\n");
                return json;
            }

            let mut out = String::new();
            out.push_str("========================================================================================\n");
            out.push_str(&format!(
                "                                   Jail Details: {:<20}\n",
                jail_name
            ));
            out.push_str("========================================================================================\n");
            out.push_str(&format!(
                "Status         : {}\n",
                if jail.enabled { "active" } else { "disabled" }
            ));
            out.push_str(&format!("Log Path       : {}\n", jail.log_path));
            out.push_str(&format!("Mode           : {}\n", jail.mode));
            out.push_str(&format!("Max Retries    : {} strikes\n", jail.maxretry));
            out.push_str(&format!(
                "Find Time      : {}s ({})\n",
                jail.findtime,
                format_duration_short(jail.findtime)
            ));
            out.push_str(&format!(
                "Ban Time       : {}s ({})\n",
                jail.bantime,
                format_duration_short(jail.bantime)
            ));
            out.push_str(&format!("Active Bans    : {} IP(s)\n", active_bans.len()));
            out.push_str(&format!("\nDFA Patterns ({}):\n", jail.patterns.len()));
            for (idx, p) in jail.patterns.iter().enumerate() {
                out.push_str(&format!("  [{}] {}\n", idx + 1, p));
            }

            out.push_str(&format!(
                "\nCurrently Banned IPs ({}):\n",
                active_bans.len()
            ));
            if active_bans.is_empty() {
                out.push_str("  (None)\n");
            } else {
                for b in &active_bans {
                    let rem_str = match b.remaining_secs(now) {
                        Some(r) => format!("expires in {}", format_duration_short(r)),
                        None => "Permanent".to_string(),
                    };
                    out.push_str(&format!("  • {:<16} ({})\n", b.ip, rem_str));
                }
            }
            out.push_str("========================================================================================\n");
            return out;
        } else {
            let mut available: Vec<_> = cfg_read.jails.keys().cloned().collect();
            available.sort();
            return format!(
                "ERROR: Jail '{}' not found. Configured jails: {}\n",
                jail_name,
                available.join(", ")
            );
        }
    }

    // Otherwise list all jails
    let mut jail_entries: Vec<_> = cfg_read.jails.iter().collect();
    jail_entries.sort_by_key(|(k, _)| (*k).clone());

    if is_json {
        let mut json = String::new();
        json.push_str(&format!(
            "{{\"total_jails\": {}, \"active_jails\": {}, \"total_banned\": {}, \"jails\": [",
            jail_entries.len(),
            jail_entries.iter().filter(|(_, j)| j.enabled).count(),
            registry.total_active()
        ));
        for (i, (name, j)) in jail_entries.iter().enumerate() {
            if i > 0 {
                json.push_str(", ");
            }
            let count = registry.count_for_jail(name);
            json.push_str(&format!(
                "{{\"name\": \"{}\", \"enabled\": {}, \"mode\": \"{}\", \"log_path\": \"{}\", \"maxretry\": {}, \"findtime\": {}, \"bantime\": {}, \"banned_count\": {}}}",
                name, j.enabled, j.mode, j.log_path, j.maxretry, j.findtime, j.bantime, count
            ));
        }
        json.push_str("]}\n");
        return json;
    }

    let mut out = String::new();
    out.push_str("========================================================================================\n");
    out.push_str("                                   bannix Jails Status                                  \n");
    out.push_str("========================================================================================\n");
    out.push_str(&format!(
        "{:<10} {:<10} {:<10} {:<26} {:<7} {:<10} {:<10} {:<8}\n",
        "JAIL", "STATUS", "MODE", "LOG PATH", "RETRY", "FINDTIME", "BANTIME", "BANNED"
    ));
    out.push_str(&format!("{}\n", "-".repeat(95)));

    let mut active_count = 0;
    for (name, jail) in &jail_entries {
        if jail.enabled {
            active_count += 1;
        }
        let banned_cnt = registry.count_for_jail(name);
        out.push_str(&format!(
            "{:<10} {:<10} {:<10} {:<26} {:<7} {:<10} {:<10} {:<8}\n",
            name,
            if jail.enabled { "active" } else { "disabled" },
            jail.mode,
            jail.log_path,
            jail.maxretry,
            format!("{}s", jail.findtime),
            format!("{}s", jail.bantime),
            banned_cnt
        ));
    }

    out.push_str(&format!("{}\n", "-".repeat(95)));
    out.push_str(&format!(
        "Total Configured: {} | Active Jails: {} | Total Active Bans: {}\n",
        jail_entries.len(),
        active_count,
        registry.total_active()
    ));
    out.push_str(
        "Tip: Run 'bannix list <JAIL>' for details, or 'bannix banned' to see all banned IPs.\n",
    );
    out.push_str("========================================================================================\n");
    out
}

fn format_banned_ips(
    cfg: &Arc<RwLock<AppConfig>>,
    fw: &Arc<Mutex<Box<dyn FirewallBackend>>>,
    bans: &Arc<RwLock<BanRegistry>>,
    jail_filter: Option<&str>,
    is_json: bool,
) -> String {
    // 1. Sync with kernel firewall
    {
        let fw_lock = fw.lock().unwrap();
        let kernel_bans = fw_lock.list_banned();
        bans.write().unwrap().sync_with_kernel(&kernel_bans);
    }

    let active_bans = bans.read().unwrap().list_active(jail_filter);
    let now = BanRegistry::current_timestamp();

    if is_json {
        let mut json = String::new();
        json.push_str(&format!("{{\"total\": {}, \"bans\": [", active_bans.len()));
        for (i, ban) in active_bans.iter().enumerate() {
            if i > 0 {
                json.push_str(", ");
            }
            let remaining = ban
                .remaining_secs(now)
                .map(|r| r.to_string())
                .unwrap_or_else(|| "null".to_string());
            json.push_str(&format!(
                "{{\"ip\": \"{}\", \"jail\": \"{}\", \"banned_at\": {}, \"duration\": {}, \"remaining\": {}, \"expires_at\": {}}}",
                ban.ip,
                ban.jail,
                ban.banned_at,
                ban.duration_secs,
                remaining,
                ban.expires_at.map(|e| e.to_string()).unwrap_or_else(|| "null".to_string()),
            ));
        }
        json.push_str("]}\n");
        return json;
    }

    let mut out = String::new();
    out.push_str("========================================================================================\n");
    if let Some(j) = jail_filter {
        out.push_str(&format!(
            "                                 bannix Banned IPs ({})\n",
            j
        ));
    } else {
        out.push_str("                                    bannix Banned IPs                                   \n");
    }
    out.push_str("========================================================================================\n");

    if active_bans.is_empty() {
        if let Some(j) = jail_filter {
            out.push_str(&format!(
                "No IP addresses are currently banned in jail '{}'.\n",
                j
            ));
        } else {
            out.push_str("No IP addresses are currently banned.\n");
        }
    } else {
        out.push_str(&format!(
            "{:<18} {:<10} {:<21} {:<10} {:<16} {:<8}\n",
            "IP ADDRESS", "JAIL", "BANNED AT (UTC)", "DURATION", "EXPIRES IN", "STATUS"
        ));
        out.push_str(&format!("{}\n", "-".repeat(88)));

        for ban in &active_bans {
            let remaining_str = match ban.remaining_secs(now) {
                Some(rem) => format_duration_short(rem),
                None => "Permanent".to_string(),
            };
            let duration_str = if ban.duration_secs == 0 {
                "Permanent".to_string()
            } else {
                format!("{}s", ban.duration_secs)
            };
            let banned_at_str = format_unix_timestamp(ban.banned_at);

            out.push_str(&format!(
                "{:<18} {:<10} {:<21} {:<10} {:<16} {:<8}\n",
                ban.ip.to_string(),
                ban.jail,
                banned_at_str,
                duration_str,
                remaining_str,
                "Active"
            ));
        }
        out.push_str(&format!("{}\n", "-".repeat(88)));
    }

    let fw_lock = fw.lock().unwrap();
    let cfg_read = cfg.read().unwrap();
    out.push_str(&format!(
        "Total Banned: {} IP(s) | Firewall: {} (table: {})\n",
        active_bans.len(),
        fw_lock.name(),
        cfg_read.daemon.table_name
    ));
    out.push_str("Tip: Use 'bannix unban <IP>' to unban an IP manually.\n");
    out.push_str("========================================================================================\n");
    out
}

pub fn format_duration_short(secs: u64) -> String {
    if secs >= 86400 {
        let days = secs / 86400;
        let hours = (secs % 86400) / 3600;
        format!("{}d {}h", days, hours)
    } else if secs >= 3600 {
        let hours = secs / 3600;
        let mins = (secs % 3600) / 60;
        format!("{}h {}m", hours, mins)
    } else if secs >= 60 {
        let mins = secs / 60;
        let s = secs % 60;
        format!("{}m {}s", mins, s)
    } else {
        format!("{}s", secs)
    }
}

pub fn format_unix_timestamp(ts: u64) -> String {
    let sec = (ts % 60) as u32;
    let min = ((ts / 60) % 60) as u32;
    let hour = ((ts / 3600) % 24) as u32;
    let mut days = (ts / 86400) as i64;

    let mut year = 1970;
    loop {
        let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        let days_in_year = if is_leap { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }

    let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let days_in_months = [
        31,
        if is_leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1;
    for &d in &days_in_months {
        if days < d {
            break;
        }
        days -= d;
        month += 1;
    }
    let day = (days + 1) as u32;

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        year, month, day, hour, min, sec
    )
}
