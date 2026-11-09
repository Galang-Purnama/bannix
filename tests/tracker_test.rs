use std::net::IpAddr;

use bannix::config::AppConfig;
use bannix::engine::tracker::{SlidingWindowTracker, StrikeResult};

#[test]
fn test_sliding_window_rate_limiter() {
    // findtime = 600s, maxretry = 3
    let tracker = SlidingWindowTracker::new(600, 3);
    let ip: IpAddr = "198.51.100.1".parse().unwrap();

    // Strike 1
    assert_eq!(
        tracker.evaluate_strike(ip, 1000, |_| false),
        StrikeResult::Recorded { strikes: 1 }
    );
    assert_eq!(tracker.get_strikes(&ip).unwrap().strikes, 1);

    // Strike 2
    assert_eq!(
        tracker.evaluate_strike(ip, 1200, |_| false),
        StrikeResult::Recorded { strikes: 2 }
    );
    assert_eq!(tracker.get_strikes(&ip).unwrap().strikes, 2);

    // Strike 3: reaches maxretry (3) -> triggers ban
    assert_eq!(
        tracker.evaluate_strike(ip, 1300, |_| false),
        StrikeResult::BanTriggered { strikes: 3 }
    );
}

#[test]
fn test_sliding_window_reset_after_findtime() {
    let tracker = SlidingWindowTracker::new(300, 3);
    let ip: IpAddr = "198.51.100.2".parse().unwrap();

    // Strike 1 at t=1000
    assert_eq!(
        tracker.evaluate_strike(ip, 1000, |_| false),
        StrikeResult::Recorded { strikes: 1 }
    );
    // Strike 2 at t=1100
    assert_eq!(
        tracker.evaluate_strike(ip, 1100, |_| false),
        StrikeResult::Recorded { strikes: 2 }
    );

    // Strike 3 at t=1401 (> 300s after first_seen 1000): window resets to 1
    assert_eq!(
        tracker.evaluate_strike(ip, 1401, |_| false),
        StrikeResult::Recorded { strikes: 1 }
    );
    assert_eq!(tracker.get_strikes(&ip).unwrap().strikes, 1);
}

#[test]
fn test_cidr_whitelist_protection() {
    let mut config = AppConfig::default();
    config.whitelist.ips = vec![
        "127.0.0.1".to_string(),
        "::1".to_string(),
        "10.0.0.0/8".to_string(),
        "192.168.0.0/16".to_string(),
        "172.16.0.0/12".to_string(),
        "203.0.113.50".to_string(),
    ];

    let tracker = SlidingWindowTracker::new(600, 2);

    let check_whitelist = |ip: IpAddr| config.is_ip_whitelisted(ip);

    // 1. Localhost should never receive a strike
    let localhost_v4: IpAddr = "127.0.0.1".parse().unwrap();
    let localhost_v6: IpAddr = "::1".parse().unwrap();
    assert_eq!(
        tracker.evaluate_strike(localhost_v4, 1000, check_whitelist),
        StrikeResult::Whitelisted
    );
    assert_eq!(
        tracker.evaluate_strike(localhost_v6, 1000, check_whitelist),
        StrikeResult::Whitelisted
    );

    // 2. Private LAN IPs (10.x, 192.168.x, 172.16.x)
    let lan1: IpAddr = "10.254.1.2".parse().unwrap();
    let lan2: IpAddr = "192.168.1.100".parse().unwrap();
    let lan3: IpAddr = "172.20.5.1".parse().unwrap();
    assert_eq!(
        tracker.evaluate_strike(lan1, 1000, check_whitelist),
        StrikeResult::Whitelisted
    );
    assert_eq!(
        tracker.evaluate_strike(lan2, 1000, check_whitelist),
        StrikeResult::Whitelisted
    );
    assert_eq!(
        tracker.evaluate_strike(lan3, 1000, check_whitelist),
        StrikeResult::Whitelisted
    );

    // 3. Custom management IP
    let admin_ip: IpAddr = "203.0.113.50".parse().unwrap();
    assert_eq!(
        tracker.evaluate_strike(admin_ip, 1000, check_whitelist),
        StrikeResult::Whitelisted
    );

    // Ensure none of the whitelisted IPs were recorded in the tracker history
    assert_eq!(tracker.get_strikes(&localhost_v4), None);
    assert_eq!(tracker.get_strikes(&lan2), None);
    assert_eq!(tracker.get_strikes(&admin_ip), None);

    // 4. Actual attacker IP outside whitelist
    let attacker_ip: IpAddr = "185.220.101.5".parse().unwrap();
    assert_eq!(
        tracker.evaluate_strike(attacker_ip, 1000, check_whitelist),
        StrikeResult::Recorded { strikes: 1 }
    );
    assert_eq!(
        tracker.evaluate_strike(attacker_ip, 1005, check_whitelist),
        StrikeResult::BanTriggered { strikes: 2 }
    );
}
