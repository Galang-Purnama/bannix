use super::FirewallBackend;
use std::collections::HashSet;
use std::net::IpAddr;

#[allow(dead_code)]
pub struct IptablesBackend {
    table_name: String,
    banned_ips: HashSet<IpAddr>,
    initialized: bool,
}

impl IptablesBackend {
    pub fn new(table_name: &str) -> Self {
        Self {
            table_name: table_name.to_string(),
            banned_ips: HashSet::new(),
            initialized: false,
        }
    }

    pub fn is_ip_banned(&self, ip: &IpAddr) -> bool {
        self.banned_ips.contains(ip)
    }
}

impl FirewallBackend for IptablesBackend {
    fn is_supported(&mut self) -> bool {
        // Universal fallback: always available
        true
    }

    fn init(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.initialized = true;
        Ok(())
    }

    fn ban_ip(&mut self, ip: IpAddr, _timeout_secs: u64) -> Result<(), Box<dyn std::error::Error>> {
        self.banned_ips.insert(ip);
        Ok(())
    }

    fn unban_ip(&mut self, ip: IpAddr) -> Result<(), Box<dyn std::error::Error>> {
        self.banned_ips.remove(&ip);
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.banned_ips.clear();
        self.initialized = false;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "iptables"
    }

    fn list_banned(&self) -> Vec<(IpAddr, Option<u64>)> {
        self.banned_ips.iter().map(|ip| (*ip, None)).collect()
    }
}
