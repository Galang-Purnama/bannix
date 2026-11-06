use std::net::IpAddr;

pub mod ipset;
pub mod iptables;
pub mod netlink;

pub trait FirewallBackend: Send + Sync {
    /// Initializes firewall tables, sets, chains, and rules.
    fn init(&mut self) -> Result<(), Box<dyn std::error::Error>>;

    /// Bans an IP address for `timeout_secs` seconds (0 = permanent).
    fn ban_ip(&mut self, ip: IpAddr, timeout_secs: u64) -> Result<(), Box<dyn std::error::Error>>;

    /// Unbans an IP address manually.
    fn unban_ip(&mut self, ip: IpAddr) -> Result<(), Box<dyn std::error::Error>>;

    /// Cleans up created firewall tables/sets upon daemon exit.
    fn cleanup(&mut self) -> Result<(), Box<dyn std::error::Error>>;

    /// Tests if this backend is supported and functional in the current environment.
    fn is_supported(&mut self) -> bool;

    /// Returns human-readable name of the backend.
    fn name(&self) -> &'static str;
}

/// Auto-detects the best available firewall backend in order:
/// 1. nftables via Netlink (KVM, modern LXC, Bare Metal)
/// 2. ipset (OpenVZ, Virtuozzo, restricted LXC)
/// 3. iptables (Universal fallback)
pub fn auto_detect(table_name: &str) -> Box<dyn FirewallBackend> {
    let mut nft = netlink::NetlinkBackend::new(table_name);
    if nft.is_supported() {
        return Box::new(nft);
    }

    let mut ipset = ipset::IpsetBackend::new(table_name);
    if ipset.is_supported() {
        return Box::new(ipset);
    }

    Box::new(iptables::IptablesBackend::new(table_name))
}

pub fn detect_backend(preferred: &str, table_name: &str) -> Box<dyn FirewallBackend> {
    match preferred {
        "nftables" => Box::new(netlink::NetlinkBackend::new(table_name)),
        "ipset" => Box::new(ipset::IpsetBackend::new(table_name)),
        "iptables" => Box::new(iptables::IptablesBackend::new(table_name)),
        _ => auto_detect(table_name),
    }
}
