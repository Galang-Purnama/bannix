use std::io::{self, Read};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

const CHUNK_SIZE: usize = 64 * 1024; // 64 KB fixed buffer

/// Direct socket reader for systemd-journald stdout stream.
/// Eliminates intermediate rsyslog disk writing and read polling.
pub struct JournalWatcher {
    socket_path: PathBuf,
    stream: Option<UnixStream>,
    buffer: Box<[u8; CHUNK_SIZE]>,
    carry_over: Vec<u8>,
}

impl JournalWatcher {
    pub fn new<P: AsRef<Path>>(socket_path: P) -> Self {
        let path = socket_path.as_ref().to_path_buf();
        let stream = UnixStream::connect(&path).ok().and_then(|s| {
            s.set_nonblocking(true).ok()?;
            Some(s)
        });

        Self {
            socket_path: path,
            stream,
            buffer: Box::new([0u8; CHUNK_SIZE]),
            carry_over: Vec::with_capacity(512),
        }
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    pub fn reconnect(&mut self) -> io::Result<()> {
        let stream = UnixStream::connect(&self.socket_path)?;
        stream.set_nonblocking(true)?;
        self.stream = Some(stream);
        Ok(())
    }

    /// Reads available lines from the journal stream without blocking.
    pub fn poll_next_lines<F>(&mut self, mut callback: F) -> usize
    where
        F: FnMut(&[u8]),
    {
        let stream = match &mut self.stream {
            Some(s) => s,
            None => {
                let _ = self.reconnect();
                match &mut self.stream {
                    Some(s) => s,
                    None => return 0,
                }
            }
        };

        let mut lines_count = 0;

        loop {
            match stream.read(&mut self.buffer[..]) {
                Ok(0) => {
                    // Stream closed
                    self.stream = None;
                    break;
                }
                Ok(n) => {
                    let chunk = &self.buffer[..n];
                    let mut start = 0;

                    for (idx, &b) in chunk.iter().enumerate() {
                        if b == b'\n' {
                            let line_part = &chunk[start..idx];
                            start = idx + 1;

                            if !self.carry_over.is_empty() {
                                self.carry_over.extend_from_slice(line_part);
                                let line = if self.carry_over.ends_with(b"\r") {
                                    &self.carry_over[..self.carry_over.len() - 1]
                                } else {
                                    &self.carry_over[..]
                                };
                                callback(line);
                                self.carry_over.clear();
                            } else {
                                let line = if line_part.ends_with(b"\r") {
                                    &line_part[..line_part.len() - 1]
                                } else {
                                    line_part
                                };
                                callback(line);
                            }
                            lines_count += 1;
                        }
                    }

                    if start < chunk.len() {
                        self.carry_over.extend_from_slice(&chunk[start..]);
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    break;
                }
                Err(_) => {
                    self.stream = None;
                    break;
                }
            }
        }

        lines_count
    }
}
