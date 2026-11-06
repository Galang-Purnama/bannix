use aho_corasick::{AhoCorasick, Match};

/// Multi-pattern deterministic string matcher using Aho-Corasick DFA.
/// Scans stream buffers directly in O(n) linear time with zero dynamic heap allocations per scan.
pub struct PatternMatcher {
    ac: Option<AhoCorasick>,
    patterns: Vec<String>,
}

impl PatternMatcher {
    /// Compiles pattern strings into an Aho-Corasick state machine at startup.
    pub fn new(patterns: &[String]) -> Result<Self, aho_corasick::BuildError> {
        let valid_patterns: Vec<&str> = patterns
            .iter()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();

        if valid_patterns.is_empty() {
            return Ok(Self {
                ac: None,
                patterns: Vec::new(),
            });
        }

        let ac = AhoCorasick::builder()
            .ascii_case_insensitive(false)
            .build(&valid_patterns)?;

        Ok(Self {
            ac: Some(ac),
            patterns: patterns.to_vec(),
        })
    }

    /// Searches for matching failure patterns directly over a byte slice buffer.
    #[inline]
    pub fn find_match(&self, buffer: &[u8]) -> Option<Match> {
        self.ac.as_ref()?.find(buffer)
    }

    /// Checks if a byte slice buffer contains any compiled pattern in linear time.
    #[inline]
    pub fn is_match(&self, buffer: &[u8]) -> bool {
        match &self.ac {
            Some(ac) => ac.is_match(buffer),
            None => false,
        }
    }

    /// Convenience wrapper for string slices.
    #[inline]
    pub fn find_match_str(&self, text: &str) -> Option<Match> {
        self.find_match(text.as_bytes())
    }

    /// Convenience wrapper for string slices.
    #[inline]
    pub fn is_match_str(&self, text: &str) -> bool {
        self.is_match(text.as_bytes())
    }

    pub fn patterns(&self) -> &[String] {
        &self.patterns
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matcher_byte_slice() {
        let patterns = vec![
            "Failed password for".to_string(),
            "Invalid user".to_string(),
        ];
        let matcher = PatternMatcher::new(&patterns).expect("build matcher");

        let log_bytes = b"Nov  5 14:22:50 host sshd[123]: Failed password for root from 1.2.3.4";
        assert!(matcher.is_match(log_bytes));

        let m = matcher.find_match(log_bytes).unwrap();
        assert_eq!(m.pattern().as_usize(), 0);

        let ok_bytes = b"Nov  5 14:22:50 host sshd[123]: Accepted publickey for root";
        assert!(!matcher.is_match(ok_bytes));
    }

    #[test]
    fn test_matcher_empty() {
        let matcher = PatternMatcher::new(&[]).expect("build empty");
        assert!(!matcher.is_match(b"any string"));
    }
}
