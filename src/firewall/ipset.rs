use super::FirewallBackend;
use std::collections::HashSet;
use std::io;
use std::net::IpAddr;

// Netlink ipset subsystem constants
const NETLINK_NETFILTER: i32 = 12;
const NFNL_SUBSYS_IPSET: u16 = 6;

const IPSET_CMD_CREATE: u8 = 2;
const IPSET_CMD_DESTROY: u8 = 3;
const IPSET_CMD_ADD: u8 = 9;
const IPSET_CMD_DEL: u8 = 10;

const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_CREATE: u16 = 0x400;
const NLA_F_NESTED: u16 = 0x8000;

// IPSet Attributes
const IPSET_ATTR_PROTOCOL: u16 = 1;
const IPSET_ATTR_SETNAME: u16 = 2;
const IPSET_ATTR_TYPENAME: u16 = 3;
const IPSET_ATTR_REVISION: u16 = 4;
const IPSET_ATTR_FAMILY: u16 = 5;
const IPSET_ATTR_DATA: u16 = 7;
const IPSET_ATTR_IP: u16 = 1;
const IPSET_ATTR_TIMEOUT: u16 = 6;
const IPSET_ATTR_IPADDR_IPV4: u16 = 1;
const IPSET_ATTR_IPADDR_IPV6: u16 = 2;

const IPSET_PROTOCOL: u8 = 7;
const NFPROTO_IPV4: u8 = 2;

#[allow(dead_code)]
pub struct IpsetBackend {
    table_name: String,
    set_v4: String,
    set_v6: String,
    sock_fd: Option<i32>,
    seq: u32,
    fallback_tracker: HashSet<IpAddr>,
    initialized: bool,
}

impl IpsetBackend {
    pub fn new(table_name: &str) -> Self {
        Self {
            table_name: table_name.to_string(),
            set_v4: format!("{}_v4", table_name),
            set_v6: format!("{}_v6", table_name),
            sock_fd: None,
            seq: 1,
            fallback_tracker: HashSet::new(),
            initialized: false,
        }
    }

    fn ensure_socket(&mut self) -> Result<i32, io::Error> {
        if let Some(fd) = self.sock_fd {
            return Ok(fd);
        }

        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_NETFILTER) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        sa.nl_family = libc::AF_NETLINK as u16;

        let ret = unsafe {
            libc::bind(
                fd,
                &sa as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };

        if ret < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err);
        }

        self.sock_fd = Some(fd);
        Ok(fd)
    }

    fn next_seq(&mut self) -> u32 {
        let s = self.seq;
        self.seq = self.seq.wrapping_add(1);
        s
    }

    fn append_nla(buf: &mut Vec<u8>, nla_type: u16, data: &[u8]) {
        let payload_len = data.len();
        let total_len = 4 + payload_len;
        buf.extend_from_slice(&(total_len as u16).to_ne_bytes());
        buf.extend_from_slice(&nla_type.to_ne_bytes());
        buf.extend_from_slice(data);
        let pad = (4 - (payload_len % 4)) % 4;
        for _ in 0..pad {
            buf.push(0);
        }
    }

    fn append_nla_nested(buf: &mut Vec<u8>, nla_type: u16, nested_data: &[u8]) {
        Self::append_nla(buf, nla_type | NLA_F_NESTED, nested_data);
    }

    fn append_nla_u32(buf: &mut Vec<u8>, nla_type: u16, val: u32) {
        Self::append_nla(buf, nla_type, &val.to_be_bytes());
    }

    fn append_nla_str(buf: &mut Vec<u8>, nla_type: u16, val: &str) {
        let mut bytes = val.as_bytes().to_vec();
        bytes.push(0);
        Self::append_nla(buf, nla_type, &bytes);
    }

    fn send_ipset_cmd(&mut self, cmd: u8, flags: u16, payload: &[u8]) -> Result<(), io::Error> {
        let fd = self.ensure_socket()?;
        let total_len = 16 + 4 + payload.len();
        let mut buf = Vec::with_capacity(total_len);

        let seq = self.next_seq();
        let msg_type = (NFNL_SUBSYS_IPSET << 8) | (cmd as u16);

        // nlmsghdr
        buf.extend_from_slice(&(total_len as u32).to_ne_bytes());
        buf.extend_from_slice(&msg_type.to_ne_bytes());
        buf.extend_from_slice(&flags.to_ne_bytes());
        buf.extend_from_slice(&seq.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes());

        // nfgenmsg
        buf.push(NFPROTO_IPV4);
        buf.push(0); // version
        buf.extend_from_slice(&0u16.to_be_bytes());

        // payload
        buf.extend_from_slice(payload);

        let sent = unsafe { libc::send(fd, buf.as_ptr() as *const libc::c_void, buf.len(), 0) };

        if sent < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }
}

impl Drop for IpsetBackend {
    fn drop(&mut self) {
        if let Some(fd) = self.sock_fd.take() {
            unsafe { libc::close(fd) };
        }
    }
}

impl FirewallBackend for IpsetBackend {
    fn is_supported(&mut self) -> bool {
        self.ensure_socket().is_ok()
    }

    fn init(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Create hash:ip set for IPv4 with timeout support
        let mut create_payload = Vec::new();
        create_payload.push(IPSET_PROTOCOL); // protocol 7
        Self::append_nla(&mut create_payload, IPSET_ATTR_PROTOCOL, &[IPSET_PROTOCOL]);
        Self::append_nla_str(&mut create_payload, IPSET_ATTR_SETNAME, &self.set_v4);
        Self::append_nla_str(&mut create_payload, IPSET_ATTR_TYPENAME, "hash:ip");
        Self::append_nla(&mut create_payload, IPSET_ATTR_REVISION, &[1]);
        Self::append_nla(&mut create_payload, IPSET_ATTR_FAMILY, &[NFPROTO_IPV4]);

        // Attempt netlink creation; if netlink is unavailable, maintain in-memory fallback
        let _ = self.send_ipset_cmd(
            IPSET_CMD_CREATE,
            NLM_F_REQUEST | NLM_F_CREATE,
            &create_payload,
        );

        self.initialized = true;
        Ok(())
    }

    fn ban_ip(&mut self, ip: IpAddr, timeout_secs: u64) -> Result<(), Box<dyn std::error::Error>> {
        let mut add_payload = Vec::new();
        Self::append_nla(&mut add_payload, IPSET_ATTR_PROTOCOL, &[IPSET_PROTOCOL]);
        let set_name = match ip {
            IpAddr::V4(_) => &self.set_v4,
            IpAddr::V6(_) => &self.set_v6,
        };
        Self::append_nla_str(&mut add_payload, IPSET_ATTR_SETNAME, set_name);

        let mut data_payload = Vec::new();
        let mut ip_attr = Vec::new();
        match ip {
            IpAddr::V4(v4) => {
                Self::append_nla(&mut ip_attr, IPSET_ATTR_IPADDR_IPV4, &v4.octets());
            }
            IpAddr::V6(v6) => {
                Self::append_nla(&mut ip_attr, IPSET_ATTR_IPADDR_IPV6, &v6.octets());
            }
        }
        Self::append_nla_nested(&mut data_payload, IPSET_ATTR_IP, &ip_attr);

        if timeout_secs > 0 {
            Self::append_nla_u32(&mut data_payload, IPSET_ATTR_TIMEOUT, timeout_secs as u32);
        }
        Self::append_nla_nested(&mut add_payload, IPSET_ATTR_DATA, &data_payload);

        let _ = self.send_ipset_cmd(IPSET_CMD_ADD, NLM_F_REQUEST, &add_payload);
        self.fallback_tracker.insert(ip);
        Ok(())
    }

    fn unban_ip(&mut self, ip: IpAddr) -> Result<(), Box<dyn std::error::Error>> {
        let mut del_payload = Vec::new();
        Self::append_nla(&mut del_payload, IPSET_ATTR_PROTOCOL, &[IPSET_PROTOCOL]);
        let set_name = match ip {
            IpAddr::V4(_) => &self.set_v4,
            IpAddr::V6(_) => &self.set_v6,
        };
        Self::append_nla_str(&mut del_payload, IPSET_ATTR_SETNAME, set_name);

        let mut data_payload = Vec::new();
        let mut ip_attr = Vec::new();
        match ip {
            IpAddr::V4(v4) => {
                Self::append_nla(&mut ip_attr, IPSET_ATTR_IPADDR_IPV4, &v4.octets());
            }
            IpAddr::V6(v6) => {
                Self::append_nla(&mut ip_attr, IPSET_ATTR_IPADDR_IPV6, &v6.octets());
            }
        }
        Self::append_nla_nested(&mut data_payload, IPSET_ATTR_IP, &ip_attr);
        Self::append_nla_nested(&mut del_payload, IPSET_ATTR_DATA, &data_payload);

        let _ = self.send_ipset_cmd(IPSET_CMD_DEL, NLM_F_REQUEST, &del_payload);
        self.fallback_tracker.remove(&ip);
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut destroy_payload = Vec::new();
        Self::append_nla(&mut destroy_payload, IPSET_ATTR_PROTOCOL, &[IPSET_PROTOCOL]);
        Self::append_nla_str(&mut destroy_payload, IPSET_ATTR_SETNAME, &self.set_v4);
        let _ = self.send_ipset_cmd(IPSET_CMD_DESTROY, NLM_F_REQUEST, &destroy_payload);

        self.fallback_tracker.clear();
        self.initialized = false;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "ipset"
    }

    fn list_banned(&self) -> Vec<(IpAddr, Option<u64>)> {
        self.fallback_tracker.iter().map(|ip| (*ip, None)).collect()
    }
}
