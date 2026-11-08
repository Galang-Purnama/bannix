use bannix::engine::matcher::PatternMatcher;
use bannix::engine::parser::IpParser;

#[test]
fn test_openssh_real_log_variations() {
    let patterns = vec![
        "Failed password for".to_string(),
        "Invalid user".to_string(),
        "authentication failure; logname=".to_string(),
        "Connection closed by authenticating user".to_string(),
    ];
    let matcher = PatternMatcher::new(&patterns).expect("build matcher");

    // Case 1: Failed password for existing user
    let log1 = b"Nov  5 14:22:50 server sshd[12345]: Failed password for root from 192.168.1.105 port 54321 ssh2";
    assert!(matcher.is_match(log1));
    assert_eq!(IpParser::extract_ip_from_bytes(log1), Some("192.168.1.105".parse().unwrap()));

    // Case 2: Failed password for invalid user
    let log2 = b"Nov  5 14:22:51 server sshd[12346]: Failed password for invalid user admin from 10.0.0.99 port 22222 ssh2";
    assert!(matcher.is_match(log2));
    assert_eq!(IpParser::extract_ip_from_bytes(log2), Some("10.0.0.99".parse().unwrap()));

    // Case 3: Invalid user probe
    let log3 = b"Nov  5 14:22:52 server sshd[12347]: Invalid user test from 172.16.0.40 port 12345";
    assert!(matcher.is_match(log3));
    assert_eq!(IpParser::extract_ip_from_bytes(log3), Some("172.16.0.40".parse().unwrap()));

    // Case 4: Connection closed during authentication
    let log4 = b"Nov  5 14:22:53 server sshd[12348]: Connection closed by authenticating user root 192.168.1.200 port 22 [preauth]";
    assert!(matcher.is_match(log4));
    assert_eq!(IpParser::extract_ip_from_bytes(log4), Some("192.168.1.200".parse().unwrap()));

    // Case 5: PAM authentication failure with rhost
    let log5 = b"Nov  5 14:22:54 server sshd:auth: authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.88";
    assert!(matcher.is_match(log5));
    assert_eq!(IpParser::extract_ip_from_bytes(log5), Some("203.0.113.88".parse().unwrap()));

    // Case 6: IPv6 SSH attack
    let log6 = b"Nov  5 14:22:55 server sshd[12349]: Failed password for root from 2001:db8:85a3::8a2e:370:7334 port 43210 ssh2";
    assert!(matcher.is_match(log6));
    assert_eq!(IpParser::extract_ip_from_bytes(log6), Some("2001:db8:85a3::8a2e:370:7334".parse().unwrap()));

    // Case 7: Legitimate SSH login (should NOT match)
    let log7 = b"Nov  5 14:22:56 server sshd[12350]: Accepted publickey for root from 192.168.1.1 port 55555 ssh2";
    assert!(!matcher.is_match(log7));

    let log8 = b"Nov  5 14:22:57 server sshd[12351]: Failed password for invalid user from 1.1.1.1 from 203.0.113.199 port 54321 ssh2";
    assert!(matcher.is_match(log8));
    assert_eq!(IpParser::extract_ip_from_bytes(log8), Some("203.0.113.199".parse().unwrap()));
}

#[test]
fn test_nginx_and_web_log_variations() {
    let patterns = vec![
        "access forbidden by rule".to_string(),
        "directory index of".to_string(),
    ];
    let matcher = PatternMatcher::new(&patterns).expect("build matcher");

    let log1 = b"2026/11/05 14:00:00 [error] 1234#0: *1 access forbidden by rule, client: 198.51.100.23, server: example.com";
    assert!(matcher.is_match(log1));
    assert_eq!(IpParser::extract_ip_from_bytes(log1), Some("198.51.100.23".parse().unwrap()));

    let log2 = b"2026/11/05 14:00:01 [error] 1234#0: *2 directory index of \"/var/www/secret\" is forbidden, client: 198.51.100.24, server: example.com";
    assert!(matcher.is_match(log2));
    assert_eq!(IpParser::extract_ip_from_bytes(log2), Some("198.51.100.24".parse().unwrap()));
}

#[test]
fn test_web_application_custom_auth_logs() {
    let patterns = vec![
        "Invalid credentials provided".to_string(),
        "Two-factor authentication failed".to_string(),
    ];
    let matcher = PatternMatcher::new(&patterns).expect("build matcher");

    let log1 = b"[2026-11-05 14:00:00] production.ERROR: Invalid credentials provided for user admin from 192.168.10.50 [] []";
    assert!(matcher.is_match(log1));
    assert_eq!(IpParser::extract_ip_from_bytes(log1), Some("192.168.10.50".parse().unwrap()));

    let log2 = b"[2026-11-05 14:00:01] production.ERROR: Two-factor authentication failed from 192.168.10.51:8080 [] []";
    assert!(matcher.is_match(log2));
    assert_eq!(IpParser::extract_ip_from_bytes(log2), Some("192.168.10.51".parse().unwrap()));
}

#[test]
fn test_malformed_and_dirty_inputs_no_panic() {
    let patterns = vec!["Failed password".to_string()];
    let matcher = PatternMatcher::new(&patterns).expect("build matcher");

    // Empty buffer
    assert!(!matcher.is_match(b""));
    assert_eq!(IpParser::extract_ip_from_bytes(b""), None);

    // Whitespace only
    assert!(!matcher.is_match(b"   \t\r\n   "));
    assert_eq!(IpParser::extract_ip_from_bytes(b"   \t\r\n   "), None);

    // Arbitrary binary bytes and null bytes
    let dirty_bytes = &[0x00, 0xff, 0xfe, 0x80, 0x01, 0x02, 0x7f, 0x00, 0x46, 0x61, 0x69, 0x6c];
    assert!(!matcher.is_match(dirty_bytes));
    assert_eq!(IpParser::extract_ip_from_bytes(dirty_bytes), None);

    // SQL Injection / special chars inside log
    let sqli = b"Failed password for user '; DROP TABLE users; -- from 192.168.1.5 port 22";
    assert!(matcher.is_match(sqli));
    assert_eq!(IpParser::extract_ip_from_bytes(sqli), Some("192.168.1.5".parse().unwrap()));

    // Incomplete or invalid IP tokens
    let invalid_ip = b"Failed password for root from 999.999.999.999 port 22";
    assert!(matcher.is_match(invalid_ip));
    assert_eq!(IpParser::extract_ip_from_bytes(invalid_ip), None);

    let incomplete_ip = b"Failed password for root from 192.168. port 22";
    assert!(matcher.is_match(incomplete_ip));
    assert_eq!(IpParser::extract_ip_from_bytes(incomplete_ip), None);

    // High volume large buffer (100 KB) without panic
    let large_buffer = vec![b'x'; 100_000];
    assert!(!matcher.is_match(&large_buffer));
    assert_eq!(IpParser::extract_ip_from_bytes(&large_buffer), None);
}

