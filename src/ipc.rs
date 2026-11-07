use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, info};

use crate::config::AppConfig;
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

                tokio::spawn(async move {
                    let (reader, mut writer) = stream.split();
                    let mut buf_reader = TokioBufReader::new(reader);
                    let mut line = String::new();

                    if buf_reader.read_line(&mut line).await.is_ok() {
                        let response = handle_ipc_command(line.trim(), &cfg_ref, &fw_ref, start_time);
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
    start_time: Instant,
) -> String {
    let trimmed = cmd.trim();
    if trimmed.eq_ignore_ascii_case("PING") {
        return "PONG\n".to_string();
    }
    if trimmed.eq_ignore_ascii_case("STATUS") {
        return format_status(cfg, fw, start_time);
    }
    if let Some(arg) = trimmed.strip_prefix("UNBAN ").or_else(|| trimmed.strip_prefix("unban ")) {
        return handle_unban(arg.trim(), fw);
    }
    if let Some(arg) = trimmed.strip_prefix("BAN ").or_else(|| trimmed.strip_prefix("ban ")) {
        return handle_ban(arg.trim(), fw);
    }

    "ERROR: Unknown command. Supported: status, unban <IP>, ban <IP> [seconds], ping\n".to_string()
}

fn handle_unban(arg: &str, fw: &Arc<Mutex<Box<dyn FirewallBackend>>>) -> String {
    match arg.parse::<IpAddr>() {
        Ok(ip) => {
            let mut fw_lock = fw.lock().unwrap();
            match fw_lock.unban_ip(ip) {
                Ok(_) => format!("OK: Unbanned IP {}\n", ip),
                Err(e) => format!("ERROR: Failed to unban {}: {}\n", ip, e),
            }
        }
        Err(_) => format!("ERROR: Invalid IP address '{}'\n", arg),
    }
}

fn handle_ban(arg: &str, fw: &Arc<Mutex<Box<dyn FirewallBackend>>>) -> String {
    let parts: Vec<&str> = arg.split_whitespace().collect();
    if parts.is_empty() {
        return "ERROR: Missing IP address\n".to_string();
    }
    match parts[0].parse::<IpAddr>() {
        Ok(ip) => {
            let timeout = parts.get(1).and_then(|s| s.parse::<u64>().ok()).unwrap_or(3600);
            let mut fw_lock = fw.lock().unwrap();
            match fw_lock.ban_ip(ip, timeout) {
                Ok(_) => format!("OK: Banned IP {} for {}s\n", ip, timeout),
                Err(e) => format!("ERROR: Failed to ban {}: {}\n", ip, e),
            }
        }
        Err(_) => format!("ERROR: Invalid IP address '{}'\n", parts[0]),
    }
}

fn format_status(
    cfg: &Arc<RwLock<AppConfig>>,
    fw: &Arc<Mutex<Box<dyn FirewallBackend>>>,
    start_time: Instant,
) -> String {
    let cfg_read = cfg.read().unwrap();
    let fw_lock = fw.lock().unwrap();
    let uptime = start_time.elapsed().as_secs();

    let mut out = String::new();
    out.push_str(&format!("bannix daemon v{}\n", env!("CARGO_PKG_VERSION")));
    out.push_str(&format!("Uptime: {}s\n", uptime));
    out.push_str(&format!("Backend: {} (table: {})\n", fw_lock.name(), cfg_read.daemon.table_name));
    out.push_str(&format!("Whitelisted: {} entries\n", cfg_read.whitelist.ips.len()));

    let mut active_jails: Vec<_> = cfg_read.jails.iter().filter(|(_, j)| j.enabled).collect();
    active_jails.sort_by_key(|(name, _)| *name);
    out.push_str(&format!("Active Jails ({}):\n", active_jails.len()));
    for (name, jail) in active_jails {
        out.push_str(&format!(
            "  • {:<10} | log: {} | mode: {} | retry: {}/{}s | ban: {}s\n",
            name, jail.log_path, jail.mode, jail.maxretry, jail.findtime, jail.bantime
        ));
    }
    out
}
