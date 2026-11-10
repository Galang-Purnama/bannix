use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpStrikeHistory {
    pub first_seen: u64,
    pub last_seen: u64,
    pub strikes: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrikeResult {
    Whitelisted,
    Recorded { strikes: u16 },
    BanTriggered { strikes: u16 },
}

/// High-performance sliding-window strike rate limiter.
/// Tracks attacker offenses and enforces strike thresholds within `findtime`.
pub struct SlidingWindowTracker {
    history: RwLock<HashMap<IpAddr, IpStrikeHistory>>,
    findtime: u64,
    maxretry: u16,
}

const MAX_TRACKER_ENTRIES: usize = 50_000;

impl SlidingWindowTracker {
    pub fn new(findtime: u64, maxretry: u16) -> Self {
        Self {
            history: RwLock::new(HashMap::new()),
            findtime,
            maxretry,
        }
    }

    pub fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Records a strike at the current wall-clock timestamp.
    /// Returns true if strike count reaches or exceeds `maxretry`.
    pub fn record_strike(&self, ip: IpAddr) -> bool {
        self.record_strike_at(ip, Self::current_timestamp())
    }

    /// Records a strike at a specific Unix timestamp (zero-sleep deterministic execution).
    pub fn record_strike_at(&self, ip: IpAddr, timestamp: u64) -> bool {
        let mut map = self.history.write().unwrap();
        if map.len() >= MAX_TRACKER_ENTRIES {
            map.retain(|_, v| timestamp.saturating_sub(v.last_seen) <= self.findtime);
        }

        let entry = map.entry(ip).or_insert(IpStrikeHistory {
            first_seen: timestamp,
            last_seen: timestamp,
            strikes: 0,
        });

        // If outside findtime window, reset window to start fresh from current strike
        if timestamp.saturating_sub(entry.first_seen) > self.findtime {
            entry.first_seen = timestamp;
            entry.strikes = 1;
        } else {
            entry.strikes = entry.strikes.saturating_add(1);
        }
        entry.last_seen = timestamp;

        entry.strikes >= self.maxretry
    }

    /// Evaluates a strike while verifying against a whitelist check.
    /// If the IP is whitelisted, no strike is recorded and `StrikeResult::Whitelisted` is returned.
    pub fn evaluate_strike<W>(&self, ip: IpAddr, timestamp: u64, is_whitelisted: W) -> StrikeResult
    where
        W: Fn(IpAddr) -> bool,
    {
        if is_whitelisted(ip) {
            return StrikeResult::Whitelisted;
        }

        let mut map = self.history.write().unwrap();
        if map.len() >= MAX_TRACKER_ENTRIES {
            map.retain(|_, v| timestamp.saturating_sub(v.last_seen) <= self.findtime);
        }

        let entry = map.entry(ip).or_insert(IpStrikeHistory {
            first_seen: timestamp,
            last_seen: timestamp,
            strikes: 0,
        });

        if timestamp.saturating_sub(entry.first_seen) > self.findtime {
            entry.first_seen = timestamp;
            entry.strikes = 1;
        } else {
            entry.strikes = entry.strikes.saturating_add(1);
        }
        entry.last_seen = timestamp;

        if entry.strikes >= self.maxretry {
            StrikeResult::BanTriggered {
                strikes: entry.strikes,
            }
        } else {
            StrikeResult::Recorded {
                strikes: entry.strikes,
            }
        }
    }

    /// Periodic garbage collection of expired strike entries to maintain strict RAM budget.
    pub fn prune_expired(&self) {
        self.prune_expired_at(Self::current_timestamp());
    }

    pub fn prune_expired_at(&self, timestamp: u64) {
        let mut map = self.history.write().unwrap();
        map.retain(|_, history| timestamp.saturating_sub(history.last_seen) <= self.findtime);
    }

    pub fn reset_ip(&self, ip: &IpAddr) {
        let mut map = self.history.write().unwrap();
        map.remove(ip);
    }

    pub fn get_strikes(&self, ip: &IpAddr) -> Option<IpStrikeHistory> {
        let map = self.history.read().unwrap();
        map.get(ip).copied()
    }

    pub fn clear(&self) {
        let mut map = self.history.write().unwrap();
        map.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracker_sliding_window_threshold() {
        let tracker = SlidingWindowTracker::new(600, 3);
        let ip: IpAddr = "192.0.2.10".parse().unwrap();

        assert!(!tracker.record_strike_at(ip, 1000));
        assert_eq!(tracker.get_strikes(&ip).unwrap().strikes, 1);

        assert!(!tracker.record_strike_at(ip, 1100));
        assert_eq!(tracker.get_strikes(&ip).unwrap().strikes, 2);

        assert!(tracker.record_strike_at(ip, 1200));
        assert_eq!(tracker.get_strikes(&ip).unwrap().strikes, 3);
    }

    #[test]
    fn test_tracker_window_expiry_reset() {
        let tracker = SlidingWindowTracker::new(600, 3);
        let ip: IpAddr = "192.0.2.20".parse().unwrap();

        assert!(!tracker.record_strike_at(ip, 1000));
        assert!(!tracker.record_strike_at(ip, 1100));

        // Window expired at 1701 (> 600s after 1000)
        assert!(!tracker.record_strike_at(ip, 1701));
        assert_eq!(tracker.get_strikes(&ip).unwrap().strikes, 1);
    }

    #[test]
    fn test_tracker_evaluate_with_whitelist() {
        let tracker = SlidingWindowTracker::new(600, 2);
        let whitelisted_ip: IpAddr = "127.0.0.1".parse().unwrap();
        let attacker_ip: IpAddr = "198.51.100.55".parse().unwrap();

        let is_whitelist = |ip: IpAddr| ip == whitelisted_ip;

        // Whitelisted IP is never recorded
        assert_eq!(
            tracker.evaluate_strike(whitelisted_ip, 1000, is_whitelist),
            StrikeResult::Whitelisted
        );
        assert_eq!(tracker.get_strikes(&whitelisted_ip), None);

        // Attacker IP strike 1
        assert_eq!(
            tracker.evaluate_strike(attacker_ip, 1000, is_whitelist),
            StrikeResult::Recorded { strikes: 1 }
        );

        // Attacker IP strike 2 (reaches maxretry 2 -> triggers ban)
        assert_eq!(
            tracker.evaluate_strike(attacker_ip, 1010, is_whitelist),
            StrikeResult::BanTriggered { strikes: 2 }
        );
    }
}
