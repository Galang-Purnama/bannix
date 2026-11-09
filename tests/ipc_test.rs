use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use bannix::config::{AppConfig, JailConfig};
use bannix::engine::BanRegistry;
use bannix::firewall::iptables::IptablesBackend;
use bannix::firewall::FirewallBackend;
use bannix::ipc::{run_ipc_server, send_command};

#[tokio::test]
async fn test_ipc_commands_lifecycle() {
    let socket_path = PathBuf::from(format!("/tmp/bannix_ipc_test_{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&socket_path);

    let mut default_cfg = AppConfig::default();
    default_cfg
        .jails
        .insert("ssh".to_string(), JailConfig::default());
    default_cfg
        .jails
        .insert("nginx".to_string(), JailConfig::default());
    let cfg = Arc::new(RwLock::new(default_cfg));
    let fw: Arc<Mutex<Box<dyn FirewallBackend>>> =
        Arc::new(Mutex::new(Box::new(IptablesBackend::new("bannix_ipc_fw"))));
    let bans = Arc::new(RwLock::new(BanRegistry::new()));
    let start_time = Instant::now();

    let sock_clone = socket_path.clone();
    let cfg_clone = Arc::clone(&cfg);
    let fw_clone = Arc::clone(&fw);
    let bans_clone = Arc::clone(&bans);

    tokio::spawn(async move {
        let _ = run_ipc_server(sock_clone, cfg_clone, fw_clone, bans_clone, start_time).await;
    });

    // Wait briefly for socket binding
    for _ in 0..20 {
        if socket_path.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(socket_path.exists(), "Socket file should exist");

    // 1. Test PING
    let ping_resp = send_command(&socket_path, "PING").await.expect("send PING");
    assert_eq!(ping_resp.trim(), "PONG");

    // 2. Test STATUS
    let status_resp = send_command(&socket_path, "STATUS")
        .await
        .expect("send STATUS");
    assert!(status_resp.contains("bannix daemon v"));
    assert!(status_resp.contains("Backend:"));
    assert!(status_resp.contains("Whitelisted:"));
    assert!(status_resp.contains("Currently Banned: 0 IP(s)"));

    // 3. Test BAN
    let ban_resp = send_command(&socket_path, "BAN 192.0.2.55 600 ssh")
        .await
        .expect("send BAN");
    assert!(ban_resp.starts_with("OK: Banned IP 192.0.2.55"));

    // 4. Test LIST (Jails overview)
    let list_resp = send_command(&socket_path, "LIST").await.expect("send LIST");
    assert!(list_resp.contains("bannix Jails Status"));
    assert!(list_resp.contains("ssh"));
    assert!(list_resp.contains("nginx"));

    // 5. Test BANNED (Banned IPs list)
    let banned_resp = send_command(&socket_path, "BANNED")
        .await
        .expect("send BANNED");
    assert!(banned_resp.contains("bannix Banned IPs"));
    assert!(banned_resp.contains("192.0.2.55"));
    assert!(banned_resp.contains("ssh"));

    // 6. Test JSON outputs
    let banned_json = send_command(&socket_path, "BANNED_JSON")
        .await
        .expect("send BANNED_JSON");
    assert!(banned_json.contains("\"total\": 1"));
    assert!(banned_json.contains("\"ip\": \"192.0.2.55\""));

    let list_json = send_command(&socket_path, "LIST_JSON")
        .await
        .expect("send LIST_JSON");
    assert!(list_json.contains("\"total_jails\":"));

    // 7. Test UNBAN
    let unban_resp = send_command(&socket_path, "UNBAN 192.0.2.55")
        .await
        .expect("send UNBAN");
    assert_eq!(unban_resp.trim(), "OK: Unbanned IP 192.0.2.55");

    // After unban, verify BANNED shows empty
    let banned_empty = send_command(&socket_path, "BANNED")
        .await
        .expect("send BANNED empty");
    assert!(banned_empty.contains("No IP addresses are currently banned."));

    // 8. Test Invalid IP
    let err_resp = send_command(&socket_path, "UNBAN not-an-ip")
        .await
        .expect("send invalid UNBAN");
    assert!(err_resp.starts_with("ERROR: Invalid IP"));

    // 9. Test Unknown Command
    let unk_resp = send_command(&socket_path, "UNKNOWN_CMD")
        .await
        .expect("send unknown");
    assert!(unk_resp.starts_with("ERROR: Unknown command"));

    let _ = std::fs::remove_file(&socket_path);
}
