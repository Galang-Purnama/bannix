use std::net::IpAddr;
use crate::engine::matcher::PatternMatcher;
use crate::engine::parser::IpParser;

pub mod inotify;
pub mod journal;

pub use inotify::InotifyWatcher;
pub use journal::JournalWatcher;

/// Integrates log stream lines with the Aho-Corasick pattern matcher and zero-copy IP extractor.
/// Returns the detected offender IP if the line matches any active failure pattern.
#[inline]
pub fn process_log_line(line: &[u8], matcher: &PatternMatcher) -> Option<IpAddr> {
    if matcher.is_match(line) {
        IpParser::extract_ip_from_bytes(line)
    } else {
        None
    }
}
