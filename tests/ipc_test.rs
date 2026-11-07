use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use bannix::config::AppConfig;
use bannix::firewall::iptables::IptablesBackend;
use bannix::firewall::FirewallBackend;
use bannix::ipc::{run_ipc_server, send_command};

#[tokio::test]
async fn test_ipc_commands_lifecycle() {
    let socket_path = PathBuf::from(format!("/tmp/bannix_ipc_test_{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&socket_path);

    let cfg = Arc::new(RwLock::new(AppConfig::default()));
    let fw: Arc<Mutex<Box<dyn FirewallBackend>>> =
        Arc::new(Mutex::new(Box::new(IptablesBackend::new("bannix_ipc_fw"))));
    let start_time = Instant::now();

    let sock_clone = socket_path.clone();
    let cfg_clone = Arc::clone(&cfg);
    let fw_clone = Arc::clone(&fw);

    tokio::spawn(async move {
        let _ = run_ipc_server(sock_clone, cfg_clone, fw_clone, start_time).await;
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
    let status_resp = send_command(&socket_path, "STATUS").await.expect("send STATUS");
    assert!(status_resp.contains("bannix daemon v"));
    assert!(status_resp.contains("Backend:"));
    assert!(status_resp.contains("Whitelisted:"));

    // 3. Test BAN
    let ban_resp = send_command(&socket_path, "BAN 192.0.2.55 600").await.expect("send BAN");
    assert!(ban_resp.starts_with("OK: Banned IP 192.0.2.55"));

    // 4. Test UNBAN
    let unban_resp = send_command(&socket_path, "UNBAN 192.0.2.55").await.expect("send UNBAN");
    assert_eq!(unban_resp.trim(), "OK: Unbanned IP 192.0.2.55");

    // 5. Test Invalid IP
    let err_resp = send_command(&socket_path, "UNBAN not-an-ip").await.expect("send invalid UNBAN");
    assert!(err_resp.starts_with("ERROR: Invalid IP"));

    // 6. Test Unknown Command
    let unk_resp = send_command(&socket_path, "UNKNOWN_CMD").await.expect("send unknown");
    assert!(unk_resp.starts_with("ERROR: Unknown command"));

    let _ = std::fs::remove_file(&socket_path);
}
