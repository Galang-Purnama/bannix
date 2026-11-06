use std::ffi::CString;
use std::io;
use std::path::{Path, PathBuf};

const CHUNK_SIZE: usize = 64 * 1024; // 64 KB fixed buffer

/// Non-blocking, zero-allocation log file reader using inotify and epoll.
/// Handles log rotations (`IN_MOVE_SELF`, `IN_DELETE_SELF`, `IN_ATTRIB`) automatically.
pub struct InotifyWatcher {
    file_path: PathBuf,
    file_fd: i32,
    inotify_fd: i32,
    epoll_fd: i32,
    watch_desc: i32,
    buffer: Box<[u8; CHUNK_SIZE]>,
    carry_over: Vec<u8>,
    seek_to_end: bool,
}

impl InotifyWatcher {
    pub fn new<P: AsRef<Path>>(file_path: P, seek_to_end: bool) -> Result<Self, io::Error> {
        let path_buf = file_path.as_ref().to_path_buf();
        let mut watcher = Self {
            file_path: path_buf,
            file_fd: -1,
            inotify_fd: -1,
            epoll_fd: -1,
            watch_desc: -1,
            buffer: Box::new([0u8; CHUNK_SIZE]),
            carry_over: Vec::with_capacity(512),
            seek_to_end,
        };

        // Try initial open (if file already exists)
        let _ = watcher.open_and_watch();
        Ok(watcher)
    }

    pub fn file_path(&self) -> &Path {
        &self.file_path
    }

    pub fn is_active(&self) -> bool {
        self.file_fd >= 0 && self.watch_desc >= 0
    }

    fn open_and_watch(&mut self) -> Result<(), io::Error> {
        self.close_current();

        if !self.file_path.exists() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "Log file does not exist yet"));
        }

        let c_path = CString::new(self.file_path.to_string_lossy().as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        if self.seek_to_end {
            unsafe { libc::lseek(fd, 0, libc::SEEK_END) };
        }

        // Initialize inotify and epoll if not already created
        if self.inotify_fd < 0 {
            let ifd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
            if ifd < 0 {
                unsafe { libc::close(fd) };
                return Err(io::Error::last_os_error());
            }
            self.inotify_fd = ifd;

            let efd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
            if efd < 0 {
                let err = io::Error::last_os_error();
                unsafe {
                    libc::close(fd);
                    libc::close(ifd);
                };
                self.inotify_fd = -1;
                return Err(err);
            }
            self.epoll_fd = efd;

            let mut event = libc::epoll_event {
                events: libc::EPOLLIN as u32,
                u64: ifd as u64,
            };
            let ret = unsafe { libc::epoll_ctl(efd, libc::EPOLL_CTL_ADD, ifd, &mut event) };
            if ret < 0 {
                let err = io::Error::last_os_error();
                unsafe {
                    libc::close(fd);
                    libc::close(ifd);
                    libc::close(efd);
                };
                self.inotify_fd = -1;
                self.epoll_fd = -1;
                return Err(err);
            }
        }

        let mask = libc::IN_MODIFY | libc::IN_MOVE_SELF | libc::IN_DELETE_SELF | libc::IN_ATTRIB;
        let wd = unsafe { libc::inotify_add_watch(self.inotify_fd, c_path.as_ptr(), mask) };
        if wd < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err);
        }

        self.file_fd = fd;
        self.watch_desc = wd;
        Ok(())
    }

    fn close_current(&mut self) {
        if self.watch_desc >= 0 && self.inotify_fd >= 0 {
            unsafe { libc::inotify_rm_watch(self.inotify_fd, self.watch_desc) };
            self.watch_desc = -1;
        }
        if self.file_fd >= 0 {
            unsafe { libc::close(self.file_fd) };
            self.file_fd = -1;
        }
    }

    /// Polls for incoming log lines and delivers them as borrowed byte slices to `callback`.
    /// Zero heap allocation per line.
    pub fn poll_next_lines<F>(&mut self, timeout_ms: i32, mut callback: F) -> Result<usize, io::Error>
    where
        F: FnMut(&[u8]),
    {
        // If file not currently watched (e.g. rotated), attempt reopen
        if self.file_fd < 0 {
            if self.open_and_watch().is_ok() {
                // If reopened after rotation, read new content from start
                return Ok(self.drain_file_to_eof(&mut callback));
            }
            if timeout_ms > 0 {
                std::thread::sleep(std::time::Duration::from_millis(timeout_ms as u64));
            }
            return Ok(0);
        }

        let mut events = [libc::epoll_event { events: 0, u64: 0 }; 4];
        let nfds = unsafe {
            libc::epoll_wait(
                self.epoll_fd,
                events.as_mut_ptr(),
                events.len() as i32,
                timeout_ms,
            )
        };

        if nfds < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                return Ok(0);
            }
            return Err(err);
        }

        if nfds == 0 {
            return Ok(0);
        }

        let mut total_lines = 0;
        let mut inotify_buf = [0u8; 4096];

        loop {
            let n = unsafe {
                libc::read(
                    self.inotify_fd,
                    inotify_buf.as_mut_ptr() as *mut libc::c_void,
                    inotify_buf.len(),
                )
            };

            if n <= 0 {
                break;
            }

            let mut offset = 0;
            let n_read = n as usize;

            while offset + std::mem::size_of::<libc::inotify_event>() <= n_read {
                let event_ptr = unsafe {
                    &*(inotify_buf[offset..].as_ptr() as *const libc::inotify_event)
                };

                let mask = event_ptr.mask;
                offset += std::mem::size_of::<libc::inotify_event>() + event_ptr.len as usize;

                if (mask & (libc::IN_MOVE_SELF | libc::IN_DELETE_SELF)) != 0 {
                    // Log rotation detected!
                    // 1. Drain whatever is remaining in the old file
                    total_lines += self.drain_file_to_eof(&mut callback);

                    // 2. Mark seek_to_end = false so that the rotated replacement file is read from byte 0
                    self.seek_to_end = false;
                    self.close_current();

                    // 3. Attempt to open newly created log file and drain any lines written during rotation
                    if self.open_and_watch().is_ok() {
                        total_lines += self.drain_file_to_eof(&mut callback);
                    }
                } else if (mask & (libc::IN_MODIFY | libc::IN_ATTRIB)) != 0 {
                    total_lines += self.drain_file_to_eof(&mut callback);
                }
            }
        }

        Ok(total_lines)
    }

    /// Reads all currently available bytes from `file_fd` up to EOF and emits complete lines.
    pub fn drain_file_to_eof<F>(&mut self, mut callback: F) -> usize
    where
        F: FnMut(&[u8]),
    {
        if self.file_fd < 0 {
            return 0;
        }

        let mut lines_count = 0;

        loop {
            let n = unsafe {
                libc::read(
                    self.file_fd,
                    self.buffer.as_mut_ptr() as *mut libc::c_void,
                    self.buffer.len(),
                )
            };

            if n <= 0 {
                break;
            }

            let chunk = &self.buffer[..n as usize];
            lines_count += Self::process_chunk_data(&mut self.carry_over, chunk, &mut callback);
        }

        lines_count
    }

    fn process_chunk_data<F>(carry_over: &mut Vec<u8>, chunk: &[u8], mut callback: F) -> usize
    where
        F: FnMut(&[u8]),
    {
        let mut count = 0;
        let mut start = 0;

        for (idx, &b) in chunk.iter().enumerate() {
            if b == b'\n' {
                let line_part = &chunk[start..idx];
                start = idx + 1;

                if !carry_over.is_empty() {
                    carry_over.extend_from_slice(line_part);
                    // Trim trailing \r if CRLF
                    let line = if carry_over.ends_with(b"\r") {
                        &carry_over[..carry_over.len() - 1]
                    } else {
                        &carry_over[..]
                    };
                    callback(line);
                    carry_over.clear();
                } else {
                    let line = if line_part.ends_with(b"\r") {
                        &line_part[..line_part.len() - 1]
                    } else {
                        line_part
                    };
                    callback(line);
                }
                count += 1;
            }
        }

        // Store incomplete trailing bytes in carry_over for next read
        if start < chunk.len() {
            carry_over.extend_from_slice(&chunk[start..]);
        }

        count
    }
}

impl Drop for InotifyWatcher {
    fn drop(&mut self) {
        self.close_current();
        if self.epoll_fd >= 0 {
            unsafe { libc::close(self.epoll_fd) };
        }
        if self.inotify_fd >= 0 {
            unsafe { libc::close(self.inotify_fd) };
        }
    }
}
