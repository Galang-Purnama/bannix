use std::env;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::signal::unix::{signal, SignalKind};
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use bannix::config::{AppConfig, JailConfig};
use bannix::engine::ban_registry::BanRegistry;
use bannix::engine::matcher::PatternMatcher;
use bannix::engine::parser::IpParser;
use bannix::engine::tracker::{SlidingWindowTracker, StrikeResult};
use bannix::firewall::{self, FirewallBackend};
use bannix::watcher::{InotifyWatcher, JournalWatcher};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let mut config_path = PathBuf::from("config/bannix.toml");
    let mut custom_socket: Option<String> = None;
    let mut dry_run = false;
    let mut test_config_only = false;
    let mut json_output = false;
    let mut subcommand: Option<String> = None;
    let mut sub_args: Vec<String> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "status" | "ping" => {
                subcommand = Some(args[i].clone());
            }
            "unban" | "ban" => {
                subcommand = Some(args[i].clone());
                while i + 1 < args.len() && !args[i + 1].starts_with('-') {
                    sub_args.push(args[i + 1].clone());
                    i += 1;
                }
            }
            "list" | "banned" | "bans" | "jails" => {
                subcommand = Some(args[i].clone());
                while i + 1 < args.len() && !args[i + 1].starts_with('-') {
                    sub_args.push(args[i + 1].clone());
                    i += 1;
                }
            }
            "-j" | "--json" => {
                json_output = true;
            }
            "-s" | "--socket" => {
                if i + 1 < args.len() {
                    custom_socket = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-c" | "--config" => {
                if i + 1 < args.len() {
                    config_path = PathBuf::from(&args[i + 1]);
                    i += 1;
                }
            }
            "--dry-run" => {
                dry_run = true;
            }
            "--test-config" => {
                test_config_only = true;
            }
            "-v" | "--version" => {
                println!("bannix v{}", VERSION);
                return Ok(());
            }
            "-h" | "--help" => {
                print_help();
                return Ok(());
            }
            unknown => {
                eprintln!("Unknown option or command: {}", unknown);
                print_help();
                std::process::exit(1);
            }
        }
        i += 1;
    }

    // Handle CLI Subcommands via IPC socket
    if let Some(cmd) = subcommand {
        let sock_path = match bannix::ipc::find_socket_path(custom_socket.as_deref()) {
            Some(p) => p,
            None => {
                eprintln!("Error: Cannot connect to bannix daemon. No active socket found.");
                eprintln!(
                    "Is bannix daemon running? (checked: {})",
                    bannix::ipc::FALLBACK_SOCKETS.join(", ")
                );
                std::process::exit(1);
            }
        };

        let request = match cmd.as_str() {
            "status" => "STATUS".to_string(),
            "ping" => "PING".to_string(),
            "list" => {
                let is_banned_sub = sub_args.first().map(|s| s.as_str()) == Some("banned")
                    || sub_args.first().map(|s| s.as_str()) == Some("bans");
                if is_banned_sub {
                    let jail = sub_args.get(1).map(|s| s.as_str()).unwrap_or("");
                    if json_output {
                        format!("BANNED_JSON {}", jail).trim().to_string()
                    } else {
                        format!("BANNED {}", jail).trim().to_string()
                    }
                } else if sub_args.first().map(|s| s.as_str()) == Some("jails") {
                    let jail = sub_args.get(1).map(|s| s.as_str()).unwrap_or("");
                    if json_output {
                        format!("LIST_JSON {}", jail).trim().to_string()
                    } else {
                        format!("LIST {}", jail).trim().to_string()
                    }
                } else {
                    let jail = sub_args.first().map(|s| s.as_str()).unwrap_or("");
                    if json_output {
                        format!("LIST_JSON {}", jail).trim().to_string()
                    } else {
                        format!("LIST {}", jail).trim().to_string()
                    }
                }
            }
            "banned" | "bans" => {
                let jail = sub_args.first().map(|s| s.as_str()).unwrap_or("");
                if json_output {
                    format!("BANNED_JSON {}", jail).trim().to_string()
                } else {
                    format!("BANNED {}", jail).trim().to_string()
                }
            }
            "jails" => {
                let jail = sub_args.first().map(|s| s.as_str()).unwrap_or("");
                if json_output {
                    format!("LIST_JSON {}", jail).trim().to_string()
                } else {
                    format!("LIST {}", jail).trim().to_string()
                }
            }
            "unban" => {
                if sub_args.is_empty() {
                    eprintln!("Error: Missing IP address to unban.");
                    eprintln!("Usage: bannix unban <IP>");
                    std::process::exit(1);
                }
                format!("UNBAN {}", sub_args[0])
            }
            "ban" => {
                if sub_args.is_empty() {
                    eprintln!("Error: Missing IP address to ban.");
                    eprintln!("Usage: bannix ban <IP> [SECONDS]");
                    std::process::exit(1);
                }
                let timeout = sub_args.get(1).map(|s| s.as_str()).unwrap_or("3600");
                format!("BAN {} {}", sub_args[0], timeout)
            }
            _ => unreachable!(),
        };

        match bannix::ipc::send_command(&sock_path, &request).await {
            Ok(resp) => {
                print!("{}", resp);
                if resp.starts_with("ERROR:") {
                    std::process::exit(1);
                }
                return Ok(());
            }
            Err(e) => {
                eprintln!("Error communicating with daemon at {:?}: {}", sock_path, e);
                std::process::exit(1);
            }
        }
    }

    if !config_path.exists() && PathBuf::from("/etc/bannix/bannix.toml").exists() {
        config_path = PathBuf::from("/etc/bannix/bannix.toml");
    }

    // --test-config Mode
    if test_config_only {
        return run_config_test(&config_path);
    }

    println!("Starting bannix v{} (Ultra-Lightweight IPS)...", VERSION);
    if dry_run {
        println!("⚠️ Running in DRY-RUN mode. No firewall rules or webhooks will be applied.");
    }

    let cfg = match AppConfig::load_from_file(&config_path) {
        Ok(c) => {
            println!("Loaded configuration from {:?}", config_path);
            c
        }
        Err(e) => {
            eprintln!("Error loading configuration from {:?}: {}", config_path, e);
            std::process::exit(1);
        }
    };

    let log_level = match cfg.daemon.log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let subscriber = FmtSubscriber::builder().with_max_level(log_level).finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    info!(
        "bannix daemon initialized (log_level: {}, backend: {}, dry_run: {})",
        cfg.daemon.log_level, cfg.daemon.backend, dry_run
    );

    // Initialize Firewall Backend
    let mut fw = firewall::detect_backend(&cfg.daemon.backend, &cfg.daemon.table_name);
    info!("Firewall backend selected: {}", fw.name());

    if !dry_run {
        fw.init()?;
    } else {
        info!("[DRY-RUN] Firewall initialization skipped.");
    }

    let bans_arc = Arc::new(RwLock::new(BanRegistry::new()));
    let state_file = BanRegistry::default_state_path();
    let loaded_count = bans_arc
        .write()
        .unwrap()
        .load_from_file(&state_file)
        .unwrap_or(0);
    if loaded_count > 0 {
        info!(
            "Loaded {} active ban(s) from persistent state file",
            loaded_count
        );
        if !dry_run {
            let now = BanRegistry::current_timestamp();
            let loaded = bans_arc.read().unwrap().list_active(None);
            for ban in loaded {
                let remaining = ban.remaining_secs(now).unwrap_or(0);
                if let Err(e) = fw.ban_ip(ban.ip, remaining) {
                    warn!(
                        "Failed to restore persistent ban for IP {} to firewall: {}",
                        ban.ip, e
                    );
                }
            }
        }
    }
    if !dry_run {
        let kernel_bans = fw.list_banned();
        bans_arc.write().unwrap().sync_with_kernel(&kernel_bans);
        let _ = bans_arc.read().unwrap().save_to_file(&state_file);
    }

    let firewall_arc: Arc<Mutex<Box<dyn FirewallBackend>>> = Arc::new(Mutex::new(fw));
    let cfg_arc = Arc::new(RwLock::new(cfg));

    // Spawn Jail Workers
    {
        let cfg_read = cfg_arc.read().unwrap();
        let mut active_jails = 0;
        for (jail_name, jail) in &cfg_read.jails {
            if !jail.enabled {
                continue;
            }
            active_jails += 1;
            let jail_name_cloned = jail_name.clone();
            let jail_cloned = jail.clone();
            let cfg_ref = Arc::clone(&cfg_arc);
            let fw_ref = Arc::clone(&firewall_arc);
            let bans_ref = Arc::clone(&bans_arc);

            tokio::spawn(async move {
                run_jail_worker(
                    jail_name_cloned,
                    jail_cloned,
                    cfg_ref,
                    fw_ref,
                    bans_ref,
                    dry_run,
                )
                .await;
            });
        }
        info!(
            "All active jails launched (total: {}). Daemon listening for attacks.",
            active_jails
        );
    }

    // Start IPC Control Socket Server
    let socket_path = bannix::ipc::resolve_socket_path(&cfg_arc.read().unwrap().daemon.socket_path);
    let start_time = std::time::Instant::now();
    let socket_path_cloned = socket_path.clone();
    let cfg_ipc = Arc::clone(&cfg_arc);
    let fw_ipc = Arc::clone(&firewall_arc);
    let bans_ipc = Arc::clone(&bans_arc);

    tokio::spawn(async move {
        if let Err(e) =
            bannix::ipc::run_ipc_server(socket_path_cloned, cfg_ipc, fw_ipc, bans_ipc, start_time)
                .await
        {
            error!("Failed to run IPC server: {}", e);
        }
    });

    // Unix Signals: SIGINT, SIGTERM, SIGHUP
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sighup = signal(SignalKind::hangup())?;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Received SIGINT (Ctrl+C). Shutting down bannix daemon...");
                break;
            }
            _ = sigterm.recv() => {
                info!("Received SIGTERM. Shutting down bannix daemon...");
                break;
            }
            _ = sighup.recv() => {
                info!("Received SIGHUP. Reloading configuration from {:?}...", config_path);
                match AppConfig::load_from_file(&config_path) {
                    Ok(new_cfg) => {
                        let mut cfg_write = cfg_arc.write().unwrap();
                        *cfg_write = new_cfg;
                        info!("Configuration successfully reloaded! Active whitelist count: {}", cfg_write.whitelist.ips.len());
                    }
                    Err(e) => {
                        error!("Failed to reload configuration: {}. Retaining previous configuration.", e);
                    }
                }
            }
        }
    }

    // Cleanup IPC socket
    let _ = std::fs::remove_file(&socket_path);

    // Save persistent ban state
    let _ = bans_arc.read().unwrap().save_to_file(&state_file);

    // Cleanup on exit if configured
    let purge_on_exit = cfg_arc.read().unwrap().daemon.purge_on_exit;
    if purge_on_exit && !dry_run {
        info!("Purging firewall table upon exit as configured by purge_on_exit = true");
        let mut fw_lock = firewall_arc.lock().unwrap();
        let _ = fw_lock.cleanup();
    } else if !dry_run {
        info!("Retaining active kernel firewall bans (purge_on_exit = false)");
    }

    info!("bannix daemon exited cleanly.");
    Ok(())
}

fn print_help() {
    println!(
        "bannix v{} - Ultra-Lightweight Intrusion Prevention System",
        VERSION
    );
    println!("Usage: bannix [COMMAND] [OPTIONS]");
    println!();
    println!("Commands:");
    println!("  status               Show daemon status, uptime, backend, and active jails");
    println!("  list [JAIL]          List configured jails, status, and ban counts (or details of a jail)");
    println!("  banned [JAIL]        List all currently banned IPs in the kernel firewall");
    println!("  unban <IP>           Manually unban an IP from kernel firewall");
    println!("  ban <IP> [SECONDS]   Manually ban an IP (default: 3600 seconds)");
    println!("  ping                 Test connectivity to running bannix daemon");
    println!();
    println!("Options:");
    println!("  -c, --config <PATH>  Path to configuration file (default: config/bannix.toml)");
    println!(
        "  -s, --socket <PATH>  Path to IPC control socket (default: /run/bannix/bannix.sock)"
    );
    println!("  -j, --json           Output in JSON format (for list and banned commands)");
    println!("      --dry-run        Simulate attacks and rate-limiting without modifying kernel firewall");
    println!("      --test-config    Validate syntax and semantics of configuration and exit");
    println!("  -v, --version        Show version information");
    println!("  -h, --help           Show help information");
}

fn run_config_test(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("Validating bannix configuration from {:?}...", path);
    let cfg = match AppConfig::load_from_file(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("❌ Configuration validation FAILED: {}", e);
            std::process::exit(1);
        }
    };

    println!("  ✓ TOML syntax and structure: Valid");
    println!(
        "  ✓ Daemon backend: '{}', log_level: '{}'",
        cfg.daemon.backend, cfg.daemon.log_level
    );

    // Validate whitelist
    for entry in &cfg.whitelist.ips {
        let trimmed = entry.trim();
        if trimmed.parse::<std::net::IpAddr>().is_err() && trimmed.split_once('/').is_none() {
            eprintln!("❌ Invalid whitelist entry: '{}'", entry);
            std::process::exit(1);
        }
    }
    println!(
        "  ✓ Whitelist entries: {} validated",
        cfg.whitelist.ips.len()
    );

    // Validate jails
    let mut valid_jails = 0;
    for (name, jail) in &cfg.jails {
        if jail.patterns.is_empty() && jail.enabled {
            eprintln!(
                "⚠️ Warning: Jail '{}' is enabled but has no patterns defined.",
                name
            );
        }
        if let Err(e) = PatternMatcher::new(&jail.patterns) {
            eprintln!("❌ Jail '{}' pattern compilation FAILED: {}", name, e);
            std::process::exit(1);
        }
        valid_jails += 1;
    }
    println!(
        "  ✓ Jails configured: {} (compiled DFA pattern engines successfully)",
        valid_jails
    );

    println!("\n✅ Configuration syntax and logic are completely VALID!");
    Ok(())
}

async fn run_jail_worker(
    name: String,
    jail: JailConfig,
    cfg: Arc<RwLock<AppConfig>>,
    fw: Arc<Mutex<Box<dyn FirewallBackend>>>,
    bans: Arc<RwLock<BanRegistry>>,
    dry_run: bool,
) {
    info!(
        "Starting jail '{}' monitoring '{}' (mode: {})",
        name, jail.log_path, jail.mode
    );

    let matcher = match PatternMatcher::new(&jail.patterns) {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to compile patterns for jail '{}': {}", name, e);
            return;
        }
    };

    let tracker = SlidingWindowTracker::new(jail.findtime, jail.maxretry);

    if jail.mode == "journald" {
        let mut journal = JournalWatcher::new(&jail.log_path);
        let mut last_prune = SlidingWindowTracker::current_timestamp();

        loop {
            journal.poll_next_lines(|line| {
                process_line_event(
                    &name, line, &matcher, &tracker, &cfg, &jail, &fw, &bans, dry_run,
                );
            });

            let now = SlidingWindowTracker::current_timestamp();
            if now.saturating_sub(last_prune) >= 60 {
                tracker.prune_expired();
                last_prune = now;
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    } else {
        let mut inotify = loop {
            match InotifyWatcher::new(&jail.log_path, true) {
                Ok(w) => break w,
                Err(e) => {
                    warn!(
                        "Could not open '{}' for jail '{}': {}. Retrying in 5 seconds...",
                        jail.log_path, name, e
                    );
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        };

        let mut last_prune = SlidingWindowTracker::current_timestamp();

        loop {
            let _ = inotify.poll_next_lines(200, |line| {
                process_line_event(
                    &name, line, &matcher, &tracker, &cfg, &jail, &fw, &bans, dry_run,
                );
            });

            let now = SlidingWindowTracker::current_timestamp();
            if now.saturating_sub(last_prune) >= 60 {
                tracker.prune_expired();
                last_prune = now;
            }

            tokio::task::yield_now().await;
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn process_line_event(
    jail_name: &str,
    line: &[u8],
    matcher: &PatternMatcher,
    tracker: &SlidingWindowTracker,
    cfg_arc: &Arc<RwLock<AppConfig>>,
    jail: &JailConfig,
    fw: &Arc<Mutex<Box<dyn FirewallBackend>>>,
    bans: &Arc<RwLock<BanRegistry>>,
    dry_run: bool,
) {
    if !matcher.is_match(line) {
        return;
    }

    let ip = match IpParser::extract_ip_from_bytes(line) {
        Some(ip) => ip,
        None => return,
    };

    let now = SlidingWindowTracker::current_timestamp();
    let result = {
        let cfg = cfg_arc.read().unwrap();
        tracker.evaluate_strike(ip, now, |target_ip| cfg.is_ip_whitelisted(target_ip))
    };

    match result {
        StrikeResult::Whitelisted => {
            // Whitelisted IP, do nothing
        }
        StrikeResult::Recorded { strikes } => {
            info!(
                "Jail '{}': Strike {}/{} for IP {}",
                jail_name, strikes, jail.maxretry, ip
            );
        }
        StrikeResult::BanTriggered { strikes } => {
            warn!(
                "🚨 Jail '{}': Triggering ban for IP {} (strikes: {}, bantime: {}s)",
                jail_name, ip, strikes, jail.bantime
            );

            if !dry_run {
                // Direct Kernel Ban (in-process Netlink, zero subprocess!)
                let mut fw_lock = fw.lock().unwrap();
                if let Err(e) = fw_lock.ban_ip(ip, jail.bantime) {
                    error!("Failed to ban IP {} via firewall: {}", ip, e);
                } else {
                    info!("Successfully banned IP {} in kernel firewall", ip);
                    bans.write()
                        .unwrap()
                        .record_ban(ip, jail_name, jail.bantime);
                    let _ = bans
                        .read()
                        .unwrap()
                        .save_to_file(BanRegistry::default_state_path());
                }
            } else {
                info!("[DRY-RUN] Would ban IP {} for {}s", ip, jail.bantime);
                bans.write()
                    .unwrap()
                    .record_ban(ip, jail_name, jail.bantime);
                let _ = bans
                    .read()
                    .unwrap()
                    .save_to_file(BanRegistry::default_state_path());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_present() {
        assert!(!VERSION.is_empty());
    }
}
