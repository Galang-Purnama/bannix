
use bannix::engine::ban_registry::BanRegistry;
use bannix::firewall::iptables::IptablesBackend;
use bannix::firewall::FirewallBackend;
use std::net::IpAddr;

fn main() {
    let registry = BanRegistry::new();
    let state_path = "/tmp/test_restart_bug.state";
    let now = BanRegistry::current_timestamp();
    
    // 1. Prior daemon run records a ban 60 seconds ago with 3540s remaining
    let ip: IpAddr = "198.51.100.10".parse().unwrap();
    registry.record_ban_at(ip, "ssh", 3600, now - 60);
    registry.save_to_file(state_path).unwrap();
    println!("Saved initial state with 1 ban.");

    // 2. Daemon restarts: creates new registry, loads from state file
    let new_registry = BanRegistry::new();
    let n = new_registry.load_from_file(state_path).unwrap();
    println!("Restart: Loaded {} bans from file", n);
    assert_eq!(n, 1);

    // 3. Current code in main.rs:
    // It does NOT restore bans to firewall backend, but immediately calls:
    let mut fw = IptablesBackend::new("bannix_test");
    let kernel_bans = fw.list_banned(); // kernel has 0 bans
    println!("Kernel bans count: {}", kernel_bans.len());

    new_registry.sync_with_kernel(&kernel_bans);
    println!("Bans in registry after sync_with_kernel: {}", new_registry.total_active());
    new_registry.save_to_file(state_path).unwrap();

    let final_registry = BanRegistry::new();
    let loaded_after = final_registry.load_from_file(state_path).unwrap();
    println!("Final loaded bans: {}", loaded_after);
}
