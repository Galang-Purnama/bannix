use std::ffi::CString;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[allow(dead_code)]
extern "C" {
    pub fn fast_ip_parse_ipv4(buf: *const u8, len: usize, out_be32: *mut u32) -> libc::c_int;
    pub fn fast_ip_extract(
        buf: *const u8,
        len: usize,
        out_is_v6: *mut u8,
        out_ip_bytes: *mut u8,
    ) -> libc::c_int;

    pub fn c_netlink_open() -> libc::c_int;
    pub fn c_netlink_close(fd: libc::c_int);
    pub fn c_netlink_is_supported() -> libc::c_int;
    pub fn c_netlink_init_table_and_set(
        fd: libc::c_int,
        table_name: *const libc::c_char,
        set_name: *const libc::c_char,
        seq: *mut u32,
    ) -> libc::c_int;
    pub fn c_netlink_add_set_elem_v4(
        fd: libc::c_int,
        table_name: *const libc::c_char,
        set_name: *const libc::c_char,
        ip_be32: u32,
        timeout_secs: u64,
        seq: *mut u32,
    ) -> libc::c_int;
    pub fn c_netlink_del_set_elem_v4(
        fd: libc::c_int,
        table_name: *const libc::c_char,
        set_name: *const libc::c_char,
        ip_be32: u32,
        seq: *mut u32,
    ) -> libc::c_int;
    pub fn c_netlink_del_table(
        fd: libc::c_int,
        table_name: *const libc::c_char,
        seq: *mut u32,
    ) -> libc::c_int;

    // Kernel probe declarations
    pub fn c_kernel_get_version(buf: *mut libc::c_char, max_len: libc::size_t) -> libc::c_int;
    pub fn c_kernel_detect_environment() -> libc::c_int;
    pub fn c_kernel_has_net_admin() -> libc::c_int;
    pub fn c_kernel_probe_nftables_support() -> libc::c_int;

    // Raw socket declarations
    pub fn c_socket_tune_buffers(
        fd: libc::c_int,
        rcvbuf_bytes: libc::c_int,
        sndbuf_bytes: libc::c_int,
    ) -> libc::c_int;
    pub fn c_socket_set_nonblocking(fd: libc::c_int) -> libc::c_int;
    pub fn c_net_get_ifindex(ifname: *const libc::c_char) -> libc::c_int;
    pub fn c_net_is_iface_up(ifname: *const libc::c_char) -> libc::c_int;
}

/// Safe Rust wrapper for C fast_ip parser.
pub struct FastIpBridge;

impl FastIpBridge {
    #[inline]
    pub fn parse_ipv4(buf: &[u8]) -> Option<Ipv4Addr> {
        let mut be32: u32 = 0;
        let ret = unsafe { fast_ip_parse_ipv4(buf.as_ptr(), buf.len(), &mut be32) };
        if ret == 0 {
            Some(Ipv4Addr::from(u32::from_be(be32)))
        } else {
            None
        }
    }

    #[inline]
    pub fn extract_ip(buf: &[u8]) -> Option<IpAddr> {
        let mut is_v6: u8 = 0;
        let mut ip_bytes = [0u8; 16];
        let ret =
            unsafe { fast_ip_extract(buf.as_ptr(), buf.len(), &mut is_v6, ip_bytes.as_mut_ptr()) };
        if ret == 0 {
            if is_v6 == 0 {
                let mut v4_bytes = [0u8; 4];
                v4_bytes.copy_from_slice(&ip_bytes[..4]);
                Some(IpAddr::V4(Ipv4Addr::from(v4_bytes)))
            } else {
                Some(IpAddr::V6(Ipv6Addr::from(ip_bytes)))
            }
        } else {
            None
        }
    }
}

/// Safe Rust wrapper for C netlink raw socket bridge.
pub struct RawNetlinkBridge {
    fd: libc::c_int,
    seq: u32,
}

impl RawNetlinkBridge {
    pub fn open() -> Result<Self, io::Error> {
        let fd = unsafe { c_netlink_open() };
        if fd < 0 {
            Err(io::Error::from_raw_os_error(-fd))
        } else {
            Ok(Self { fd, seq: 1 })
        }
    }

    pub fn is_supported() -> bool {
        unsafe { c_netlink_is_supported() == 1 }
    }

    pub fn init_table_and_set(&mut self, table: &str, set: &str) -> Result<(), io::Error> {
        let c_table =
            CString::new(table).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let c_set =
            CString::new(set).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let ret = unsafe {
            c_netlink_init_table_and_set(self.fd, c_table.as_ptr(), c_set.as_ptr(), &mut self.seq)
        };
        if ret < 0 {
            Err(io::Error::from_raw_os_error(-ret))
        } else {
            Ok(())
        }
    }

    pub fn add_set_elem_v4(
        &mut self,
        table: &str,
        set: &str,
        ip: Ipv4Addr,
        timeout_secs: u64,
    ) -> Result<(), io::Error> {
        let c_table =
            CString::new(table).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let c_set =
            CString::new(set).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let be32 = u32::from_ne_bytes(ip.octets());
        let ret = unsafe {
            c_netlink_add_set_elem_v4(
                self.fd,
                c_table.as_ptr(),
                c_set.as_ptr(),
                be32,
                timeout_secs,
                &mut self.seq,
            )
        };
        if ret < 0 {
            Err(io::Error::from_raw_os_error(-ret))
        } else {
            Ok(())
        }
    }

    pub fn del_set_elem_v4(
        &mut self,
        table: &str,
        set: &str,
        ip: Ipv4Addr,
    ) -> Result<(), io::Error> {
        let c_table =
            CString::new(table).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let c_set =
            CString::new(set).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let be32 = u32::from_ne_bytes(ip.octets());
        let ret = unsafe {
            c_netlink_del_set_elem_v4(
                self.fd,
                c_table.as_ptr(),
                c_set.as_ptr(),
                be32,
                &mut self.seq,
            )
        };
        if ret < 0 {
            Err(io::Error::from_raw_os_error(-ret))
        } else {
            Ok(())
        }
    }

    pub fn del_table(&mut self, table: &str) -> Result<(), io::Error> {
        let c_table =
            CString::new(table).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let ret = unsafe { c_netlink_del_table(self.fd, c_table.as_ptr(), &mut self.seq) };
        if ret < 0 {
            Err(io::Error::from_raw_os_error(-ret))
        } else {
            Ok(())
        }
    }
}

impl Drop for RawNetlinkBridge {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe { c_netlink_close(self.fd) };
            self.fd = -1;
        }
    }
}

/// Safe Rust wrapper for C kernel environment prober.
pub struct KernelProbeBridge;

impl KernelProbeBridge {
    pub fn get_kernel_release() -> Option<String> {
        let mut buf = [0u8; 128];
        let ret = unsafe { c_kernel_get_version(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
        if ret == 0 {
            let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
            String::from_utf8(buf[..len].to_vec()).ok()
        } else {
            None
        }
    }

    pub fn detect_environment() -> i32 {
        unsafe { c_kernel_detect_environment() }
    }

    pub fn has_net_admin() -> bool {
        unsafe { c_kernel_has_net_admin() == 1 }
    }

    pub fn probe_nftables_support() -> bool {
        unsafe { c_kernel_probe_nftables_support() == 1 }
    }
}

/// Safe Rust wrapper for C raw socket & network interface helpers.
pub struct RawSocketBridge;

impl RawSocketBridge {
    pub fn tune_socket_buffers(fd: i32, rcvbuf: i32, sndbuf: i32) -> bool {
        unsafe { c_socket_tune_buffers(fd, rcvbuf, sndbuf) == 0 }
    }

    pub fn set_nonblocking(fd: i32) -> bool {
        unsafe { c_socket_set_nonblocking(fd) == 0 }
    }

    pub fn get_ifindex(ifname: &str) -> Option<i32> {
        let c_name = CString::new(ifname).ok()?;
        let ret = unsafe { c_net_get_ifindex(c_name.as_ptr()) };
        if ret > 0 {
            Some(ret)
        } else {
            None
        }
    }

    pub fn is_iface_up(ifname: &str) -> bool {
        let c_name = match CString::new(ifname) {
            Ok(c) => c,
            Err(_) => return false,
        };
        unsafe { c_net_is_iface_up(c_name.as_ptr()) == 1 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c_fast_ip_parse_ipv4() {
        let ip = FastIpBridge::parse_ipv4(b"192.168.1.100").expect("parse ipv4");
        assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 100));

        assert!(FastIpBridge::parse_ipv4(b"256.0.0.1").is_none());
        assert!(FastIpBridge::parse_ipv4(b"1.2.3").is_none());
        assert!(FastIpBridge::parse_ipv4(b"not an ip").is_none());
    }

    #[test]
    fn test_c_fast_ip_extract() {
        let log = b"Nov 5 15:00:00 server sshd[123]: Failed password for root from 203.0.113.195 port 44321 ssh2";
        let extracted = FastIpBridge::extract_ip(log).expect("extract ip");
        assert_eq!(extracted, "203.0.113.195".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_c_netlink_is_supported_probe() {
        let supported = RawNetlinkBridge::is_supported();
        println!("C Netlink supported on this kernel: {}", supported);
    }

    #[test]
    fn test_c_kernel_probe() {
        let release = KernelProbeBridge::get_kernel_release().expect("kernel release");
        assert!(!release.is_empty(), "Kernel release should not be empty");
        println!("Kernel release: {}", release);

        let env_type = KernelProbeBridge::detect_environment();
        println!("Environment type: {}", env_type);
        assert!(env_type >= 0);

        let has_admin = KernelProbeBridge::has_net_admin();
        println!("Has CAP_NET_ADMIN: {}", has_admin);
    }

    #[test]
    fn test_c_raw_socket_helpers() {
        let lo_idx = RawSocketBridge::get_ifindex("lo");
        assert!(lo_idx.is_some(), "Loopback interface 'lo' should exist");

        let lo_up = RawSocketBridge::is_iface_up("lo");
        assert!(lo_up, "Loopback interface 'lo' should be UP");

        assert!(RawSocketBridge::get_ifindex("nonexistent_if_xyz").is_none());
        assert!(!RawSocketBridge::is_iface_up("nonexistent_if_xyz"));
    }
}
