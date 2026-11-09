use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Zero-copy fast IP address extractor.
/// Scans raw byte buffer slices (`&[u8]`) for IPv4 and IPv6 representations
/// without heap allocations and without regular expression engines.
pub struct IpParser;

impl IpParser {
    /// Extracts the most likely offender IP address directly from a raw byte slice.
    pub fn extract_ip_from_bytes(line: &[u8]) -> Option<IpAddr> {
        // Fast-path: High-speed C SIMD/pointer parser via FFI
        if let Some(ip) = crate::c_ffi::FastIpBridge::extract_ip(line) {
            return Some(ip);
        }
        // Priority 1: High-confidence prefix needles in SSH, PAM, Nginx, and system auth logs
        const PREFIXES: &[&[u8]] = &[
            b"from ",
            b"client: ",
            b"client ",
            b"rhost=",
            b"SRC=",
            b"src=",
        ];

        let mut best: Option<(usize, IpAddr)> = None;

        for &prefix in PREFIXES {
            if prefix.is_empty() || line.len() < prefix.len() {
                continue;
            }
            let mut search_len = line.len();
            while search_len >= prefix.len() {
                if let Some(pos) = line[..search_len]
                    .windows(prefix.len())
                    .rposition(|w| w == prefix)
                {
                    let after = &line[pos + prefix.len()..];
                    if let Some(ip) = Self::extract_first_ip_token_bytes(after) {
                        if best.as_ref().is_none_or(|(best_pos, _)| pos > *best_pos) {
                            best = Some((pos, ip));
                        }
                        break;
                    }
                    if pos == 0 {
                        break;
                    }
                    search_len = pos;
                } else {
                    break;
                }
            }
        }

        if let Some((_, ip)) = best {
            return Some(ip);
        }

        // Priority 2: Scan tokens from right to left (IP addresses usually reside at the end of logs)
        for token in Self::split_whitespace_rev(line) {
            let cleaned = Self::clean_token_bytes(token);
            if let Some(ip) = Self::parse_ip_token_bytes(cleaned) {
                return Some(ip);
            }
        }

        None
    }

    /// Convenience wrapper for string slices.
    #[inline]
    pub fn extract_ip(line: &str) -> Option<IpAddr> {
        Self::extract_ip_from_bytes(line.as_bytes())
    }

    fn extract_first_ip_token_bytes(slice: &[u8]) -> Option<IpAddr> {
        // Skip leading whitespace
        let mut start = 0;
        while start < slice.len()
            && (slice[start] == b' '
                || slice[start] == b'\t'
                || slice[start] == b'\r'
                || slice[start] == b'\n')
        {
            start += 1;
        }
        if start >= slice.len() {
            return None;
        }

        // Find end of token
        let mut end = start;
        while end < slice.len()
            && slice[end] != b' '
            && slice[end] != b'\t'
            && slice[end] != b'\r'
            && slice[end] != b'\n'
        {
            end += 1;
        }

        let token = &slice[start..end];
        let cleaned = Self::clean_token_bytes(token);
        Self::parse_ip_token_bytes(cleaned)
    }

    #[inline]
    fn clean_token_bytes(token: &[u8]) -> &[u8] {
        let is_wrapper = |b: u8| -> bool {
            b == b'['
                || b == b']'
                || b == b'('
                || b == b')'
                || b == b'{'
                || b == b'}'
                || b == b','
                || b == b';'
                || b == b'\''
                || b == b'"'
                || b == b'<'
                || b == b'>'
        };

        let mut start = 0;
        while start < token.len() && is_wrapper(token[start]) {
            start += 1;
        }

        let mut end = token.len();
        while end > start && is_wrapper(token[end - 1]) {
            end -= 1;
        }

        &token[start..end]
    }

    /// Iterator over whitespace-delimited tokens in reverse order (zero allocation).
    fn split_whitespace_rev(slice: &[u8]) -> WhitespaceRevIter<'_> {
        WhitespaceRevIter {
            slice,
            end: slice.len(),
        }
    }

    /// Fast, zero-allocation parser for IPv4 byte slices (e.g. `b"192.168.1.1"`).
    pub fn parse_ipv4_bytes(bytes: &[u8]) -> Option<Ipv4Addr> {
        if let Some(v4) = crate::c_ffi::FastIpBridge::parse_ipv4(bytes) {
            return Some(v4);
        }
        let mut octets = [0u8; 4];
        let mut octet_idx = 0;
        let mut current_val: u16 = 0;
        let mut has_digits = false;

        for &b in bytes {
            if b == b'.' {
                if !has_digits || octet_idx >= 3 || current_val > 255 {
                    return None;
                }
                octets[octet_idx] = current_val as u8;
                octet_idx += 1;
                current_val = 0;
                has_digits = false;
            } else if b.is_ascii_digit() {
                has_digits = true;
                current_val = current_val
                    .checked_mul(10)?
                    .checked_add((b - b'0') as u16)?;
                if current_val > 255 {
                    return None;
                }
            } else {
                return None;
            }
        }

        if octet_idx == 3 && has_digits && current_val <= 255 {
            octets[3] = current_val as u8;
            Some(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
        } else {
            None
        }
    }

    /// Parses an IP token from bytes directly.
    pub fn parse_ip_token_bytes(token: &[u8]) -> Option<IpAddr> {
        if token.is_empty() || token.len() > 64 {
            return None;
        }

        // Fast Path 1: Standard IPv4 without port
        if let Some(ipv4) = Self::parse_ipv4_bytes(token) {
            return Some(IpAddr::V4(ipv4));
        }

        // Fast Path 2: IPv4 with port (e.g. `b"192.168.1.1:8080"`)
        if let Some(colon_pos) = token.iter().rposition(|&b| b == b':') {
            let (ip_part, port_part) = token.split_at(colon_pos);
            let port_bytes = &port_part[1..];
            if !port_bytes.is_empty() && port_bytes.iter().all(|b| b.is_ascii_digit()) {
                if let Some(ipv4) = Self::parse_ipv4_bytes(ip_part) {
                    return Some(IpAddr::V4(ipv4));
                }
            }
        }

        // Fast Path 3: IPv6 (with or without brackets / port)
        if let Ok(s) = std::str::from_utf8(token) {
            // Trim any remaining brackets
            let trimmed = s.trim_matches(|c: char| c == '[' || c == ']');
            if let Ok(ipv6) = trimmed.parse::<Ipv6Addr>() {
                return Some(IpAddr::V6(ipv6));
            }
            if let Ok(sock) = s.parse::<SocketAddr>() {
                return Some(sock.ip());
            }
        }

        None
    }
}

struct WhitespaceRevIter<'a> {
    slice: &'a [u8],
    end: usize,
}

impl<'a> Iterator for WhitespaceRevIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        while self.end > 0 && Self::is_space(self.slice[self.end - 1]) {
            self.end -= 1;
        }
        if self.end == 0 {
            return None;
        }

        let token_end = self.end;
        while self.end > 0 && !Self::is_space(self.slice[self.end - 1]) {
            self.end -= 1;
        }
        let token_start = self.end;

        Some(&self.slice[token_start..token_end])
    }
}

impl<'a> WhitespaceRevIter<'a> {
    #[inline]
    fn is_space(b: u8) -> bool {
        b == b' ' || b == b'\t' || b == b'\r' || b == b'\n'
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4_bytes_direct() {
        assert_eq!(
            IpParser::parse_ipv4_bytes(b"1.2.3.4"),
            Some(Ipv4Addr::new(1, 2, 3, 4))
        );
        assert_eq!(
            IpParser::parse_ipv4_bytes(b"255.255.255.255"),
            Some(Ipv4Addr::new(255, 255, 255, 255))
        );
        assert_eq!(
            IpParser::parse_ipv4_bytes(b"0.0.0.0"),
            Some(Ipv4Addr::new(0, 0, 0, 0))
        );
        assert_eq!(IpParser::parse_ipv4_bytes(b"256.1.1.1"), None);
        assert_eq!(IpParser::parse_ipv4_bytes(b"1.2.3"), None);
        assert_eq!(IpParser::parse_ipv4_bytes(b"1.2.3.4.5"), None);
        assert_eq!(IpParser::parse_ipv4_bytes(b"abc.def.ghi.jkl"), None);
    }

    #[test]
    fn test_extract_from_byte_slice() {
        let line = b"Nov  5 14:22:50 host sshd[12345]: Failed password for root from 192.168.1.100 port 45222 ssh2";
        assert_eq!(
            IpParser::extract_ip_from_bytes(line),
            Some("192.168.1.100".parse().unwrap())
        );
    }

    #[test]
    fn test_extract_ssh_log_injection() {
        let line = b"Nov  5 14:22:50 server sshd[12345]: Failed password for invalid user from 1.1.1.1 from 203.0.113.199 port 54321 ssh2";
        assert_eq!(
            IpParser::extract_ip_from_bytes(line),
            Some("203.0.113.199".parse().unwrap())
        );
    }
}
