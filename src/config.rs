use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct DaemonConfig {
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_backend")]
    pub backend: String,
    #[serde(default = "default_table_name")]
    pub table_name: String,
    #[serde(default)]
    pub purge_on_exit: bool,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_backend() -> String {
    "auto".to_string()
}

fn default_table_name() -> String {
    "bannix_filter".to_string()
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
            backend: default_backend(),
            table_name: default_table_name(),
            purge_on_exit: false,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct WhitelistConfig {
    #[serde(default)]
    pub ips: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JailConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub log_path: String,
    #[serde(default = "default_mode")]
    pub mode: String, // inotify | journald
    #[serde(default = "default_findtime")]
    pub findtime: u64,
    #[serde(default = "default_maxretry")]
    pub maxretry: u16,
    #[serde(default = "default_bantime")]
    pub bantime: u64,
    #[serde(default)]
    pub patterns: Vec<String>,
}

fn default_true() -> bool {
    true
}

fn default_mode() -> String {
    "inotify".to_string()
}

fn default_findtime() -> u64 {
    600
}

fn default_maxretry() -> u16 {
    5
}

fn default_bantime() -> u64 {
    3600
}

impl Default for JailConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_path: "/var/log/auth.log".to_string(),
            mode: default_mode(),
            findtime: default_findtime(),
            maxretry: default_maxretry(),
            bantime: default_bantime(),
            patterns: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub daemon: DaemonConfig,
    #[serde(default)]
    pub whitelist: WhitelistConfig,
    #[serde(default)]
    pub jails: HashMap<String, JailConfig>,
}

impl AppConfig {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let path_ref = path.as_ref();
        let content = fs::read_to_string(path_ref)?;
        let mut config: AppConfig = toml::from_str(&content)?;

        // Check if there is a jails.d directory in the same folder or /etc/bannix/jails.d
        if let Some(parent) = path_ref.parent() {
            let jails_d = parent.join("jails.d");
            if jails_d.is_dir() {
                config.load_jails_d(&jails_d)?;
            }
        }

        Ok(config)
    }

    pub fn load_jails_d<P: AsRef<Path>>(&mut self, dir_path: P) -> Result<(), Box<dyn std::error::Error>> {
        let entries = fs::read_dir(dir_path)?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("toml") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    let content = fs::read_to_string(&path)?;
                    // Try parsing as flat JailConfig
                    if let Ok(jail) = toml::from_str::<JailConfig>(&content) {
                        self.jails.insert(stem.to_string(), jail);
                    } else if let Ok(wrapped) = toml::from_str::<HashMap<String, JailConfig>>(&content) {
                        // Support [stem] or [jail] sections
                        for (k, v) in wrapped {
                            let jail_name = if k == "jail" || k == stem { stem.to_string() } else { k };
                            self.jails.insert(jail_name, v);
                        }
                    } else if let Ok(nested) = toml::from_str::<AppConfig>(&content) {
                        // Support full AppConfig with [jails.*]
                        for (k, v) in nested.jails {
                            self.jails.insert(k, v);
                        }
                    } else {
                        eprintln!("Warning: Failed to parse jail drop-in {:?}", path);
                    }
                }
            }
        }
        Ok(())
    }

    pub fn is_ip_whitelisted(&self, ip: IpAddr) -> bool {
        // Also check unmapped IPv4 if this is an IPv4-mapped IPv6 address (e.g. ::ffff:192.168.1.1)
        let mapped_v4 = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped(),
            _ => None,
        };

        for entry in &self.whitelist.ips {
            let trimmed = entry.trim();
            if trimmed.is_empty() {
                continue;
            }

            if let Ok(parsed_ip) = trimmed.parse::<IpAddr>() {
                if parsed_ip == ip {
                    return true;
                }
                if let Some(v4) = mapped_v4 {
                    if parsed_ip == IpAddr::V4(v4) {
                        return true;
                    }
                }
            } else if let Some((cidr_ip, prefix_len)) = trimmed.split_once('/') {
                if let (Ok(net_ip), Ok(bits)) = (cidr_ip.parse::<IpAddr>(), prefix_len.parse::<u8>()) {
                    if Self::ip_matches_cidr(ip, net_ip, bits) {
                        return true;
                    }
                    if let Some(v4) = mapped_v4 {
                        if Self::ip_matches_cidr(IpAddr::V4(v4), net_ip, bits) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    fn ip_matches_cidr(ip: IpAddr, net_ip: IpAddr, bits: u8) -> bool {
        match (ip, net_ip) {
            (IpAddr::V4(target), IpAddr::V4(net)) => {
                if bits == 0 {
                    return true;
                }
                if bits > 32 {
                    return false;
                }
                let mask = if bits == 32 { !0u32 } else { !0u32 << (32 - bits) };
                let target_u32 = u32::from(target);
                let net_u32 = u32::from(net);
                (target_u32 & mask) == (net_u32 & mask)
            }
            (IpAddr::V6(target), IpAddr::V6(net)) => {
                if bits == 0 {
                    return true;
                }
                if bits > 128 {
                    return false;
                }
                let mask = if bits == 128 { !0u128 } else { !0u128 << (128 - bits) };
                let target_u128 = u128::from(target);
                let net_u128 = u128::from(net);
                (target_u128 & mask) == (net_u128 & mask)
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_whitelist_exact_and_cidr() {
        let mut cfg = AppConfig::default();
        cfg.whitelist.ips = vec![
            "127.0.0.1".to_string(),
            "::1".to_string(),
            "192.168.0.0/16".to_string(),
            "10.0.0.0/8".to_string(),
            "172.16.0.0/12".to_string(),
            "2001:db8::/32".to_string(),
        ];

        // Localhost
        assert!(cfg.is_ip_whitelisted("127.0.0.1".parse().unwrap()));
        assert!(cfg.is_ip_whitelisted("::1".parse().unwrap()));

        // 192.168.0.0/16
        assert!(cfg.is_ip_whitelisted("192.168.1.1".parse().unwrap()));
        assert!(cfg.is_ip_whitelisted("192.168.254.254".parse().unwrap()));
        assert!(!cfg.is_ip_whitelisted("192.169.1.1".parse().unwrap()));

        // 10.0.0.0/8
        assert!(cfg.is_ip_whitelisted("10.200.5.1".parse().unwrap()));
        assert!(!cfg.is_ip_whitelisted("11.0.0.1".parse().unwrap()));

        // 172.16.0.0/12
        assert!(cfg.is_ip_whitelisted("172.16.0.1".parse().unwrap()));
        assert!(cfg.is_ip_whitelisted("172.31.255.254".parse().unwrap()));
        assert!(!cfg.is_ip_whitelisted("172.32.0.1".parse().unwrap()));

        // IPv6 CIDR
        assert!(cfg.is_ip_whitelisted("2001:db8:ffff::1".parse().unwrap()));
        assert!(!cfg.is_ip_whitelisted("2001:db9::1".parse().unwrap()));

        // IPv4-mapped IPv6
        let mapped_v6: IpAddr = "::ffff:192.168.1.50".parse().unwrap();
        assert!(cfg.is_ip_whitelisted(mapped_v6));
    }
}
