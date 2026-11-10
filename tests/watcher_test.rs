use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::thread::{self, sleep};
use std::time::Duration;

use bannix::engine::matcher::PatternMatcher;
use bannix::watcher::{process_log_line, InotifyWatcher, JournalWatcher};

#[test]
fn test_inotify_append_and_rotation_lifecycle() {
    let test_dir = PathBuf::from("/tmp/bannix_watcher_test");
    let _ = fs::remove_dir_all(&test_dir);
    fs::create_dir_all(&test_dir).expect("create test dir");

    let log_file = test_dir.join("auth.log");
    let rotated_file = test_dir.join("auth.log.1");

    // 1. Create initial log file
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&log_file)
            .expect("create log file");
        writeln!(f, "Initial header line").unwrap();
    }

    // 2. Initialize inotify watcher (seek_to_end = false so we read from start)
    let mut watcher = InotifyWatcher::new(&log_file, false).expect("init watcher");
    assert!(watcher.is_active());

    let patterns = vec![
        "Failed password for".to_string(),
        "Invalid user".to_string(),
    ];
    let matcher = PatternMatcher::new(&patterns).expect("init matcher");

    // Initial drain of existing file content
    let mut collected: Vec<IpAddr> = Vec::new();
    let n = watcher.drain_file_to_eof(|line| {
        if let Some(ip) = process_log_line(line, &matcher) {
            collected.push(ip);
        }
    });
    assert_eq!(n, 1); // "Initial header line" (not an attack, so collected is empty)
    assert!(collected.is_empty());

    // 3. Append new attack line
    {
        let mut f = OpenOptions::new()
            .append(true)
            .open(&log_file)
            .expect("open for append");
        writeln!(
            f,
            "Nov  5 14:00:00 server sshd[100]: Failed password for root from 192.168.100.5 port 22"
        )
        .unwrap();
    }

    // Poll watcher
    sleep(Duration::from_millis(50));
    let n = watcher
        .poll_next_lines(200, |line| {
            if let Some(ip) = process_log_line(line, &matcher) {
                collected.push(ip);
            }
        })
        .unwrap();
    assert_eq!(n, 1);
    assert_eq!(collected.len(), 1);
    assert_eq!(collected[0], "192.168.100.5".parse::<IpAddr>().unwrap());

    // 4. Simulate Logrotate: Move auth.log -> auth.log.1, then create fresh auth.log
    fs::rename(&log_file, &rotated_file).expect("rename file (simulate logrotate)");

    // Create new log file with new content
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&log_file)
            .expect("create new auth.log after rotate");
        writeln!(
            f,
            "Nov  5 14:00:05 server sshd[101]: Invalid user admin from 10.20.30.40 port 22"
        )
        .unwrap();
    }

    // Poll watcher (should detect IN_MOVE_SELF and auto-reopen new auth.log)
    sleep(Duration::from_millis(100));
    let mut rotated_collected: Vec<IpAddr> = Vec::new();
    let n = watcher
        .poll_next_lines(300, |line| {
            if let Some(ip) = process_log_line(line, &matcher) {
                rotated_collected.push(ip);
            }
        })
        .unwrap();

    assert!(n >= 1, "Watcher must read lines from rotated file");
    assert_eq!(rotated_collected.len(), 1);
    assert_eq!(
        rotated_collected[0],
        "10.20.30.40".parse::<IpAddr>().unwrap()
    );

    // Clean up test dir
    let _ = fs::remove_dir_all(&test_dir);
}

#[test]
fn test_inotify_fragmented_partial_writes() {
    let test_dir = PathBuf::from("/tmp/bannix_fragment_test");
    let _ = fs::remove_dir_all(&test_dir);
    fs::create_dir_all(&test_dir).expect("create test dir");

    let log_file = test_dir.join("partial.log");
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&log_file)
            .unwrap();
        // Write partial line without newline
        write!(
            f,
            "Nov  5 14:00:10 server sshd[102]: Failed password for invalid user "
        )
        .unwrap();
    }

    let mut watcher = InotifyWatcher::new(&log_file, false).expect("init watcher");
    let patterns = vec!["Failed password for".to_string()];
    let matcher = PatternMatcher::new(&patterns).expect("init matcher");

    let mut collected: Vec<IpAddr> = Vec::new();
    let n = watcher.drain_file_to_eof(|line| {
        if let Some(ip) = process_log_line(line, &matcher) {
            collected.push(ip);
        }
    });
    // Line was incomplete, so 0 lines emitted
    assert_eq!(n, 0);
    assert!(collected.is_empty());

    // Now write the remainder with newline
    {
        let mut f = OpenOptions::new().append(true).open(&log_file).unwrap();
        writeln!(f, "hacker from 172.16.50.99 port 22").unwrap();
    }

    sleep(Duration::from_millis(50));
    let n2 = watcher
        .poll_next_lines(200, |line| {
            if let Some(ip) = process_log_line(line, &matcher) {
                collected.push(ip);
            }
        })
        .unwrap();

    // Now the full reassembled line is emitted!
    assert_eq!(n2, 1);
    assert_eq!(collected.len(), 1);
    assert_eq!(collected[0], "172.16.50.99".parse::<IpAddr>().unwrap());

    let _ = fs::remove_dir_all(&test_dir);
}

#[test]
fn test_inotify_discards_oversized_lines_without_merging_next_line() {
    let test_dir = PathBuf::from(format!("/tmp/bannix_oversize_{}", std::process::id()));
    let _ = fs::remove_dir_all(&test_dir);
    fs::create_dir_all(&test_dir).expect("create test dir");
    let log_file = test_dir.join("auth.log");
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&log_file)
        .unwrap();
    file.write_all(&vec![b'x'; 70 * 1024]).unwrap();
    writeln!(file).unwrap();
    writeln!(file, "Failed password from 192.0.2.44").unwrap();
    drop(file);

    let mut watcher = InotifyWatcher::new(&log_file, false).expect("init watcher");
    let mut lines = Vec::new();
    watcher.drain_file_to_eof(|line| lines.push(line.to_vec()));
    assert_eq!(lines, vec![b"Failed password from 192.0.2.44".to_vec()]);
    let _ = fs::remove_dir_all(&test_dir);
}

#[test]
fn test_journal_watcher_unix_socket_stream() {
    let sock_path = PathBuf::from("/tmp/bannix_journal_mock.sock");
    let _ = fs::remove_file(&sock_path);

    // Create mock Unix socket server simulating systemd-journald
    let listener = UnixListener::bind(&sock_path).expect("bind mock unix socket");

    let server_handle = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let msg = b"Nov  5 14:00:20 server sshd[105]: Failed password for root from 192.0.2.77 port 22\n";
            let _ = stream.write_all(msg);
            let _ = stream.flush();
        }
    });

    sleep(Duration::from_millis(50));

    let mut journal_watcher = JournalWatcher::new(&sock_path);
    assert!(journal_watcher.is_connected());

    let patterns = vec!["Failed password for".to_string()];
    let matcher = PatternMatcher::new(&patterns).expect("init matcher");

    sleep(Duration::from_millis(50));
    let mut collected: Vec<IpAddr> = Vec::new();
    let n = journal_watcher.poll_next_lines(|line| {
        if let Some(ip) = process_log_line(line, &matcher) {
            collected.push(ip);
        }
    });

    assert_eq!(n, 1);
    assert_eq!(collected.len(), 1);
    assert_eq!(collected[0], "192.0.2.77".parse::<IpAddr>().unwrap());

    server_handle.join().unwrap();
    let _ = fs::remove_file(&sock_path);
}
