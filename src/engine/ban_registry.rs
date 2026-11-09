use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanEntry {
    pub ip: IpAddr,
    pub jail: String,
    pub banned_at: u64,          // Unix timestamp in seconds
    pub duration_secs: u64,      // 0 = permanent
    pub expires_at: Option<u64>, // None = permanent, Some(unix timestamp)
}

impl BanEntry {
    pub fn is_expired(&self, now: u64) -> bool {
        match self.expires_at {
            Some(exp) => now >= exp,
            None => false,
        }
    }

    pub fn remaining_secs(&self, now: u64) -> Option<u64> {
        self.expires_at.map(|exp| exp.saturating_sub(now))
    }
}

pub struct BanRegistry {
    bans: RwLock<HashMap<IpAddr, BanEntry>>,
}

impl Default for BanRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl BanRegistry {
    pub fn new() -> Self {
        Self {
            bans: RwLock::new(HashMap::new()),
        }
    }

    pub fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    pub fn record_ban(&self, ip: IpAddr, jail: &str, duration_secs: u64) {
        self.record_ban_at(ip, jail, duration_secs, Self::current_timestamp());
    }

    pub fn record_ban_at(&self, ip: IpAddr, jail: &str, duration_secs: u64, timestamp: u64) {
        let expires_at = if duration_secs > 0 {
            Some(timestamp.saturating_add(duration_secs))
        } else {
            None
        };

        let entry = BanEntry {
            ip,
            jail: jail.to_string(),
            banned_at: timestamp,
            duration_secs,
            expires_at,
        };

        let mut map = self.bans.write().unwrap();
        map.insert(ip, entry);
    }

    pub fn remove_ban(&self, ip: &IpAddr) -> bool {
        let mut map = self.bans.write().unwrap();
        map.remove(ip).is_some()
    }

    pub fn prune_expired(&self, now: u64) {
        let mut map = self.bans.write().unwrap();
        map.retain(|_, entry| !entry.is_expired(now));
    }

    pub fn list_active(&self, jail_filter: Option<&str>) -> Vec<BanEntry> {
        let now = Self::current_timestamp();
        self.prune_expired(now);

        let map = self.bans.read().unwrap();
        let mut list: Vec<BanEntry> = map
            .values()
            .filter(|entry| {
                if let Some(j) = jail_filter {
                    if !j.is_empty() && !entry.jail.eq_ignore_ascii_case(j) {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        // Sort by expiration ascending (soonest unban first), permanent at the end
        list.sort_by_key(|e| e.expires_at.unwrap_or(u64::MAX));
        list
    }

    pub fn count_for_jail(&self, jail: &str) -> usize {
        let now = Self::current_timestamp();
        let map = self.bans.read().unwrap();
        map.values()
            .filter(|e| !e.is_expired(now) && e.jail.eq_ignore_ascii_case(jail))
            .count()
    }

    pub fn total_active(&self) -> usize {
        let now = Self::current_timestamp();
        let map = self.bans.read().unwrap();
        map.values().filter(|e| !e.is_expired(now)).count()
    }

    /// Synchronizes in-memory registry with kernel firewall active bans.
    /// Preserves jail labels for known bans and adopts unknown kernel bans.
    pub fn sync_with_kernel(&self, kernel_bans: &[(IpAddr, Option<u64>)]) {
        let now = Self::current_timestamp();
        let mut map = self.bans.write().unwrap();

        // Build quick lookup of active kernel IPs
        let kernel_map: HashMap<IpAddr, Option<u64>> = kernel_bans.iter().copied().collect();

        // Update remaining time or mark unknown kernel elements
        for (ip, remaining) in &kernel_map {
            if let Some(entry) = map.get_mut(ip) {
                // If kernel reports exact remaining seconds, sync expires_at
                if let Some(rem) = remaining {
                    entry.expires_at = Some(now.saturating_add(*rem));
                }
            } else {
                // Pre-existing kernel ban not yet in registry (e.g. from prior daemon run)
                let duration = remaining.unwrap_or(3600);
                let expires_at = remaining.map(|r| now.saturating_add(r));
                map.insert(
                    *ip,
                    BanEntry {
                        ip: *ip,
                        jail: "kernel".to_string(),
                        banned_at: now,
                        duration_secs: duration,
                        expires_at,
                    },
                );
            }
        }

        // Remove entries if kernel has already expired them (only if kernel report was non-empty)
        if !kernel_map.is_empty() {
            map.retain(|ip, entry| {
                if kernel_map.contains_key(ip) {
                    true
                } else {
                    // Retain if it was just added in the last 2 seconds (race condition guard)
                    now.saturating_sub(entry.banned_at) < 2
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ban_entry_lifecycle() {
        let registry = BanRegistry::new();
        let ip: IpAddr = "192.0.2.100".parse().unwrap();
        let now = BanRegistry::current_timestamp();

        registry.record_ban_at(ip, "ssh", 300, now);
        assert_eq!(registry.total_active(), 1);
        assert_eq!(registry.count_for_jail("ssh"), 1);
        assert_eq!(registry.count_for_jail("nginx"), 0);

        let active = registry.list_active(None);
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].ip, ip);
        assert_eq!(active[0].jail, "ssh");
        assert_eq!(active[0].duration_secs, 300);
        assert_eq!(active[0].expires_at, Some(now + 300));
        assert!(active[0].remaining_secs(now).unwrap() <= 300);

        // Test remove
        assert!(registry.remove_ban(&ip));
        assert_eq!(registry.total_active(), 0);
    }

    #[test]
    fn test_ban_prune_expired() {
        let registry = BanRegistry::new();
        let ip1: IpAddr = "192.0.2.1".parse().unwrap();
        let ip2: IpAddr = "192.0.2.2".parse().unwrap();
        let now = BanRegistry::current_timestamp();

        // ip1 expired (now - 100), ip2 active (now + 500)
        registry.record_ban_at(ip1, "ssh", 100, now.saturating_sub(200)); // expired
        registry.record_ban_at(ip2, "ssh", 500, now); // active

        registry.prune_expired(now);
        assert_eq!(registry.total_active(), 1);

        let remaining = registry.list_active(None);
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].ip, ip2);
    }

    #[test]
    fn test_sync_with_kernel() {
        let registry = BanRegistry::new();
        let ip_known: IpAddr = "192.0.2.1".parse().unwrap();
        let ip_kernel_only: IpAddr = "192.0.2.2".parse().unwrap();
        let now = BanRegistry::current_timestamp();

        // 1. Record known ban in SSH jail
        registry.record_ban_at(ip_known, "ssh", 3600, now);

        // 2. Kernel reports ip_known with 500s remaining, and ip_kernel_only with 1000s remaining
        let kernel_bans = vec![(ip_known, Some(500)), (ip_kernel_only, Some(1000))];
        registry.sync_with_kernel(&kernel_bans);

        let list = registry.list_active(None);
        assert_eq!(list.len(), 2);

        let known_entry = list.iter().find(|e| e.ip == ip_known).unwrap();
        assert_eq!(known_entry.jail, "ssh"); // Preserved original jail!

        let kernel_entry = list.iter().find(|e| e.ip == ip_kernel_only).unwrap();
        assert_eq!(kernel_entry.jail, "kernel");
    }
}
