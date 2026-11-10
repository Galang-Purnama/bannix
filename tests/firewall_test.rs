use bannix::firewall::ipset::IpsetBackend;
use bannix::firewall::iptables::IptablesBackend;
use bannix::firewall::netlink::NetlinkBackend;
use bannix::firewall::{auto_detect, detect_backend, FirewallBackend};
use std::net::IpAddr;

#[test]
fn test_backend_detection() {
    let nft = detect_backend("nftables", "bannix_test");
    assert_eq!(nft.name(), "nftables (Netlink)");

    let ipset = detect_backend("ipset", "bannix_test");
    assert_eq!(ipset.name(), "ipset");

    let iptables = detect_backend("iptables", "bannix_test");
    assert_eq!(iptables.name(), "iptables");

    let auto = auto_detect("bannix_test");
    // In our Linux environment with root, auto should select nftables
    assert_eq!(auto.name(), "nftables (Netlink)");
}

#[test]
fn test_iptables_backend_lifecycle() {
    let mut ipt = IptablesBackend::new("bannix_ipt_test");
    assert!(ipt.is_supported());
    assert!(ipt.init().is_ok());

    let ip1: IpAddr = "192.0.2.1".parse().unwrap();
    let ip2: IpAddr = "192.0.2.2".parse().unwrap();

    assert!(ipt.ban_ip(ip1, 300).is_ok());
    assert!(ipt.is_ip_banned(&ip1));
    assert!(!ipt.is_ip_banned(&ip2));
    assert_eq!(ipt.list_banned().len(), 1);

    assert!(ipt.unban_ip(ip1).is_ok());
    assert!(!ipt.is_ip_banned(&ip1));
    assert_eq!(ipt.list_banned().len(), 0);

    assert!(ipt.cleanup().is_ok());
}

#[test]
fn test_ipset_backend_lifecycle() {
    let mut ipset = IpsetBackend::new("bannix_ipset_test");
    assert!(ipset.is_supported());
    assert!(ipset.init().is_ok());

    let ip_v4: IpAddr = "198.51.100.10".parse().unwrap();
    assert!(ipset.ban_ip(ip_v4, 60).is_ok());
    assert!(ipset.unban_ip(ip_v4).is_ok());

    let ip_v6: IpAddr = "2001:db8::10".parse().unwrap();
    assert!(ipset.ban_ip(ip_v6, 60).is_ok());
    assert!(ipset.unban_ip(ip_v6).is_ok());

    assert!(ipset.cleanup().is_ok());
}

#[test]
fn test_netlink_kernel_bridge_lifecycle() {
    let table = "bannix_nl_test";
    let mut nft = NetlinkBackend::new(table);

    // 1. Check support
    assert!(
        nft.is_supported(),
        "Kernel netlink socket must be supported"
    );

    // 2. Initialize table, sets (v4 & v6 with timeout flag), chains, and rules
    let init_res = nft.init();
    assert!(
        init_res.is_ok(),
        "Netlink init failed: {:?}",
        init_res.err()
    );

    // 3. Ban IPv4 with dynamic kernel timeout (30 seconds)
    let ip_v4: IpAddr = "198.51.100.199".parse().unwrap();
    let ban_v4_res = nft.ban_ip(ip_v4, 30);
    assert!(
        ban_v4_res.is_ok(),
        "Netlink ban IPv4 failed: {:?}",
        ban_v4_res.err()
    );

    // 4. Ban IPv6 with dynamic kernel timeout (30 seconds)
    let ip_v6: IpAddr = "2001:db8:ffff::99".parse().unwrap();
    let ban_v6_res = nft.ban_ip(ip_v6, 30);
    assert!(
        ban_v6_res.is_ok(),
        "Netlink ban IPv6 failed: {:?}",
        ban_v6_res.err()
    );

    // 5. Unban IPv4
    let unban_v4_res = nft.unban_ip(ip_v4);
    assert!(
        unban_v4_res.is_ok(),
        "Netlink unban IPv4 failed: {:?}",
        unban_v4_res.err()
    );

    // 6. Unban IPv6
    let unban_v6_res = nft.unban_ip(ip_v6);
    assert!(
        unban_v6_res.is_ok(),
        "Netlink unban IPv6 failed: {:?}",
        unban_v6_res.err()
    );

    // 7. Cleanup test table
    let clean_res = nft.cleanup();
    assert!(
        clean_res.is_ok(),
        "Netlink cleanup table failed: {:?}",
        clean_res.err()
    );
}
