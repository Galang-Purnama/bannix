use super::FirewallBackend;
use std::io;
use std::net::IpAddr;

// Netlink & Netfilter Subsystem Constants
const NETLINK_NETFILTER: i32 = 12;
const NFNL_SUBSYS_NFTABLES: u16 = 10;
const NFNL_MSG_BATCH_BEGIN: u16 = 16;
const NFNL_MSG_BATCH_END: u16 = 17;

// Netfilter Message Types
const NFT_MSG_NEWTABLE: u16 = 0;
const NFT_MSG_DELTABLE: u16 = 2;
const NFT_MSG_NEWCHAIN: u16 = 3;
const NFT_MSG_NEWRULE: u16 = 6;
const NFT_MSG_NEWSET: u16 = 9;
const NFT_MSG_NEWSETELEM: u16 = 12;
const NFT_MSG_DELSETELEM: u16 = 14;

// Netlink Message Flags
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_APPEND: u16 = 0x800;

// Netlink Attribute Nested Flag
const NLA_F_NESTED: u16 = 0x8000;

// Netfilter Protocols
const NFPROTO_UNSPEC: u8 = 0;
const NFPROTO_INET: u8 = 1;

// Table Attributes
const NFTA_TABLE_NAME: u16 = 1;
const NFTA_TABLE_FLAGS: u16 = 2;

// Chain Attributes
const NFTA_CHAIN_TABLE: u16 = 1;
const NFTA_CHAIN_HOOK: u16 = 4;
const NFTA_CHAIN_POLICY: u16 = 5;
const NFTA_CHAIN_NAME: u16 = 3;
const NFTA_CHAIN_TYPE: u16 = 7;

// Hook Attributes
const NFTA_HOOK_HOOKNUM: u16 = 1;
const NFTA_HOOK_PRIORITY: u16 = 2;

// Set Attributes
const NFTA_SET_TABLE: u16 = 1;
const NFTA_SET_NAME: u16 = 2;
const NFTA_SET_FLAGS: u16 = 3;
const NFTA_SET_KEY_TYPE: u16 = 4;
const NFTA_SET_KEY_LEN: u16 = 5;
const NFTA_SET_ID: u16 = 10;
const NFT_SET_TIMEOUT: u32 = 0x10;

// Set Element List Attributes
const NFTA_SET_ELEM_LIST_TABLE: u16 = 1;
const NFTA_SET_ELEM_LIST_SET: u16 = 2;
const NFTA_SET_ELEM_LIST_ELEMENTS: u16 = 3;

// Set Element Attributes
const NFTA_SET_ELEM_KEY: u16 = 1;
const NFTA_SET_ELEM_TIMEOUT: u16 = 4;

// Data Attributes
const NFTA_DATA_VALUE: u16 = 1;

// Rule Attributes
const NFTA_RULE_TABLE: u16 = 1;
const NFTA_RULE_CHAIN: u16 = 2;
const NFTA_RULE_EXPRESSIONS: u16 = 4;

pub struct NetlinkBackend {
    table_name: String,
    set_v4: String,
    set_v6: String,
    chain_name: String,
    sock_fd: Option<i32>,
    seq: u32,
    initialized: bool,
    fallback_tracker: std::collections::HashMap<IpAddr, Option<u64>>,
}

impl NetlinkBackend {
    pub fn new(table_name: &str) -> Self {
        Self {
            table_name: table_name.to_string(),
            set_v4: "blacklist_v4".to_string(),
            set_v6: "blacklist_v6".to_string(),
            chain_name: "input".to_string(),
            sock_fd: None,
            seq: 1,
            initialized: false,
            fallback_tracker: std::collections::HashMap::new(),
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
        sa.nl_pid = 0;
        sa.nl_groups = 0;

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

    fn send_batch(&mut self, messages: &[u8]) -> Result<(), io::Error> {
        let fd = self.ensure_socket()?;
        let mut batch = Vec::with_capacity(messages.len() + 40);

        // 1. NFNL_MSG_BATCH_BEGIN
        let seq_begin = self.next_seq();
        Self::append_nlmsg(
            &mut batch,
            NFNL_MSG_BATCH_BEGIN,
            NLM_F_REQUEST,
            seq_begin,
            0,
            NFPROTO_UNSPEC,
            NFNL_SUBSYS_NFTABLES << 8, // 2560 (0x0a00)
            &[],
        );

        // 2. Inner messages
        batch.extend_from_slice(messages);

        // 3. NFNL_MSG_BATCH_END
        let seq_end = self.next_seq();
        Self::append_nlmsg(
            &mut batch,
            NFNL_MSG_BATCH_END,
            NLM_F_REQUEST,
            seq_end,
            0,
            NFPROTO_UNSPEC,
            NFNL_SUBSYS_NFTABLES << 8, // 2560
            &[],
        );

        let sent = unsafe { libc::send(fd, batch.as_ptr() as *const libc::c_void, batch.len(), 0) };

        if sent < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
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

    fn append_nla_u64(buf: &mut Vec<u8>, nla_type: u16, val: u64) {
        Self::append_nla(buf, nla_type, &val.to_be_bytes());
    }

    fn append_nla_str(buf: &mut Vec<u8>, nla_type: u16, val: &str) {
        let mut bytes = val.as_bytes().to_vec();
        bytes.push(0);
        Self::append_nla(buf, nla_type, &bytes);
    }

    #[allow(clippy::too_many_arguments)]
    fn append_nlmsg(
        buf: &mut Vec<u8>,
        nlmsg_type: u16,
        nlmsg_flags: u16,
        seq: u32,
        pid: u32,
        nfgen_family: u8,
        res_id: u16,
        payload: &[u8],
    ) {
        let total_len = 16 + 4 + payload.len();
        buf.extend_from_slice(&(total_len as u32).to_ne_bytes());
        buf.extend_from_slice(&nlmsg_type.to_ne_bytes());
        buf.extend_from_slice(&nlmsg_flags.to_ne_bytes());
        buf.extend_from_slice(&seq.to_ne_bytes());
        buf.extend_from_slice(&pid.to_ne_bytes());
        // nfgenmsg
        buf.push(nfgen_family);
        buf.push(0); // version NFNETLINK_V0
        buf.extend_from_slice(&res_id.to_be_bytes());
        // payload
        buf.extend_from_slice(payload);
    }
}

impl Drop for NetlinkBackend {
    fn drop(&mut self) {
        if let Some(fd) = self.sock_fd.take() {
            unsafe { libc::close(fd) };
        }
    }
}

impl FirewallBackend for NetlinkBackend {
    fn is_supported(&mut self) -> bool {
        self.ensure_socket().is_ok()
    }

    fn init(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut msg_buf = Vec::new();

        // 1. Table: inet <table_name>
        let mut t_payload = Vec::new();
        Self::append_nla_str(&mut t_payload, NFTA_TABLE_NAME, &self.table_name);
        Self::append_nla_u32(&mut t_payload, NFTA_TABLE_FLAGS, 0);
        let seq = self.next_seq();
        Self::append_nlmsg(
            &mut msg_buf,
            (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWTABLE,
            NLM_F_REQUEST | NLM_F_CREATE,
            seq,
            0,
            NFPROTO_INET,
            0,
            &t_payload,
        );

        // 2. Chain: input (hook input priority -150; policy accept)
        let mut hook_data = Vec::new();
        Self::append_nla_u32(&mut hook_data, NFTA_HOOK_HOOKNUM, 1); // NF_INET_LOCAL_IN = 1
        Self::append_nla_u32(&mut hook_data, NFTA_HOOK_PRIORITY, (-150i32) as u32);

        let mut c_payload = Vec::new();
        Self::append_nla_str(&mut c_payload, NFTA_CHAIN_TABLE, &self.table_name);
        Self::append_nla_str(&mut c_payload, NFTA_CHAIN_NAME, &self.chain_name);
        Self::append_nla_str(&mut c_payload, NFTA_CHAIN_TYPE, "filter");
        Self::append_nla_u32(&mut c_payload, NFTA_CHAIN_POLICY, 1); // NF_ACCEPT = 1
        Self::append_nla_nested(&mut c_payload, NFTA_CHAIN_HOOK, &hook_data);
        let seq = self.next_seq();
        Self::append_nlmsg(
            &mut msg_buf,
            (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWCHAIN,
            NLM_F_REQUEST | NLM_F_CREATE,
            seq,
            0,
            NFPROTO_INET,
            0,
            &c_payload,
        );

        // 3. Set: blacklist_v4 (type ipv4_addr; flags timeout)
        let mut s4_payload = Vec::new();
        Self::append_nla_str(&mut s4_payload, NFTA_SET_TABLE, &self.table_name);
        Self::append_nla_str(&mut s4_payload, NFTA_SET_NAME, &self.set_v4);
        Self::append_nla_u32(&mut s4_payload, NFTA_SET_FLAGS, NFT_SET_TIMEOUT);
        Self::append_nla_u32(&mut s4_payload, NFTA_SET_KEY_TYPE, 7); // TYPE_IPADDR = 7
        Self::append_nla_u32(&mut s4_payload, NFTA_SET_KEY_LEN, 4);
        Self::append_nla_u32(&mut s4_payload, NFTA_SET_ID, 1);
        let seq = self.next_seq();
        Self::append_nlmsg(
            &mut msg_buf,
            (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSET,
            NLM_F_REQUEST | NLM_F_CREATE,
            seq,
            0,
            NFPROTO_INET,
            0,
            &s4_payload,
        );

        // 4. Set: blacklist_v6 (type ipv6_addr; flags timeout)
        let mut s6_payload = Vec::new();
        Self::append_nla_str(&mut s6_payload, NFTA_SET_TABLE, &self.table_name);
        Self::append_nla_str(&mut s6_payload, NFTA_SET_NAME, &self.set_v6);
        Self::append_nla_u32(&mut s6_payload, NFTA_SET_FLAGS, NFT_SET_TIMEOUT);
        Self::append_nla_u32(&mut s6_payload, NFTA_SET_KEY_TYPE, 8); // TYPE_IP6ADDR = 8
        Self::append_nla_u32(&mut s6_payload, NFTA_SET_KEY_LEN, 16);
        Self::append_nla_u32(&mut s6_payload, NFTA_SET_ID, 2);
        let seq = self.next_seq();
        Self::append_nlmsg(
            &mut msg_buf,
            (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSET,
            NLM_F_REQUEST | NLM_F_CREATE,
            seq,
            0,
            NFPROTO_INET,
            0,
            &s6_payload,
        );

        // 5. Rule: meta nfproto ipv4 ip saddr @blacklist_v4 drop
        let mut expr_meta4 = Vec::new();
        Self::append_nla_str(&mut expr_meta4, 1, "meta");
        let mut meta_data4 = Vec::new();
        Self::append_nla_u32(&mut meta_data4, 2, 15); // NFTA_META_KEY = 15 (NFT_META_NFPROTO)
        Self::append_nla_u32(&mut meta_data4, 1, 1); // NFTA_META_DREG = 1 (NFT_REG_1)
        Self::append_nla_nested(&mut expr_meta4, 2, &meta_data4);

        let mut expr_cmp4 = Vec::new();
        Self::append_nla_str(&mut expr_cmp4, 1, "cmp");
        let mut cmp_data4 = Vec::new();
        Self::append_nla_u32(&mut cmp_data4, 1, 1); // NFTA_CMP_SREG = 1
        Self::append_nla_u32(&mut cmp_data4, 2, 0); // NFTA_CMP_OP = 0 (NFT_CMP_EQ)
        let mut cmp_val4 = Vec::new();
        Self::append_nla(&mut cmp_val4, 1, &[2, 0, 0, 0]); // NFPROTO_IPV4 = 2 (le / native byte)
        Self::append_nla_nested(&mut cmp_data4, 3, &cmp_val4);
        Self::append_nla_nested(&mut expr_cmp4, 2, &cmp_data4);

        let mut expr_payload4 = Vec::new();
        Self::append_nla_str(&mut expr_payload4, 1, "payload");
        let mut payload_data4 = Vec::new();
        Self::append_nla_u32(&mut payload_data4, 1, 1); // DREG = 1
        Self::append_nla_u32(&mut payload_data4, 2, 1); // BASE = NETWORK_HEADER (1)
        Self::append_nla_u32(&mut payload_data4, 3, 12); // OFFSET = 12 (IPv4 saddr)
        Self::append_nla_u32(&mut payload_data4, 4, 4); // LEN = 4
        Self::append_nla_nested(&mut expr_payload4, 2, &payload_data4);

        let mut expr_lookup4 = Vec::new();
        Self::append_nla_str(&mut expr_lookup4, 1, "lookup");
        let mut lookup_data4 = Vec::new();
        Self::append_nla_u32(&mut lookup_data4, 2, 1); // SREG = 1
        Self::append_nla_str(&mut lookup_data4, 1, &self.set_v4);
        Self::append_nla_u32(&mut lookup_data4, 4, 1); // SET_ID = 1
        Self::append_nla_nested(&mut expr_lookup4, 2, &lookup_data4);

        let mut expr_imm = Vec::new();
        Self::append_nla_str(&mut expr_imm, 1, "immediate");
        let mut imm_data = Vec::new();
        Self::append_nla_u32(&mut imm_data, 1, 0); // DREG = VERDICT (0)
        let mut verdict_val = Vec::new();
        let mut verdict_data = Vec::new();
        Self::append_nla_u32(&mut verdict_data, 1, 0); // NF_DROP = 0
        Self::append_nla_nested(&mut verdict_val, 2, &verdict_data);
        Self::append_nla_nested(&mut imm_data, 2, &verdict_val);
        Self::append_nla_nested(&mut expr_imm, 2, &imm_data);

        let mut r4_exprs = Vec::new();
        Self::append_nla_nested(&mut r4_exprs, 1, &expr_meta4);
        Self::append_nla_nested(&mut r4_exprs, 1, &expr_cmp4);
        Self::append_nla_nested(&mut r4_exprs, 1, &expr_payload4);
        Self::append_nla_nested(&mut r4_exprs, 1, &expr_lookup4);
        Self::append_nla_nested(&mut r4_exprs, 1, &expr_imm);

        let mut r4_payload = Vec::new();
        Self::append_nla_str(&mut r4_payload, NFTA_RULE_TABLE, &self.table_name);
        Self::append_nla_str(&mut r4_payload, NFTA_RULE_CHAIN, &self.chain_name);
        Self::append_nla_nested(&mut r4_payload, NFTA_RULE_EXPRESSIONS, &r4_exprs);

        let seq = self.next_seq();
        Self::append_nlmsg(
            &mut msg_buf,
            (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
            NLM_F_REQUEST | NLM_F_CREATE | NLM_F_APPEND,
            seq,
            0,
            NFPROTO_INET,
            0,
            &r4_payload,
        );

        // 6. Rule: meta nfproto ipv6 ip6 saddr @blacklist_v6 drop
        let mut expr_meta6 = Vec::new();
        Self::append_nla_str(&mut expr_meta6, 1, "meta");
        let mut meta_data6 = Vec::new();
        Self::append_nla_u32(&mut meta_data6, 2, 15);
        Self::append_nla_u32(&mut meta_data6, 1, 1);
        Self::append_nla_nested(&mut expr_meta6, 2, &meta_data6);

        let mut expr_cmp6 = Vec::new();
        Self::append_nla_str(&mut expr_cmp6, 1, "cmp");
        let mut cmp_data6 = Vec::new();
        Self::append_nla_u32(&mut cmp_data6, 1, 1);
        Self::append_nla_u32(&mut cmp_data6, 2, 0);
        let mut cmp_val6 = Vec::new();
        Self::append_nla(&mut cmp_val6, 1, &[10, 0, 0, 0]); // NFPROTO_IPV6 = 10
        Self::append_nla_nested(&mut cmp_data6, 3, &cmp_val6);
        Self::append_nla_nested(&mut expr_cmp6, 2, &cmp_data6);

        let mut expr_payload6 = Vec::new();
        Self::append_nla_str(&mut expr_payload6, 1, "payload");
        let mut payload_data6 = Vec::new();
        Self::append_nla_u32(&mut payload_data6, 1, 1);
        Self::append_nla_u32(&mut payload_data6, 2, 1);
        Self::append_nla_u32(&mut payload_data6, 3, 8); // IPv6 saddr is at byte offset 8
        Self::append_nla_u32(&mut payload_data6, 4, 16); // LEN = 16
        Self::append_nla_nested(&mut expr_payload6, 2, &payload_data6);

        let mut expr_lookup6 = Vec::new();
        Self::append_nla_str(&mut expr_lookup6, 1, "lookup");
        let mut lookup_data6 = Vec::new();
        Self::append_nla_u32(&mut lookup_data6, 2, 1);
        Self::append_nla_str(&mut lookup_data6, 1, &self.set_v6);
        Self::append_nla_u32(&mut lookup_data6, 4, 2);
        Self::append_nla_nested(&mut expr_lookup6, 2, &lookup_data6);

        let mut r6_exprs = Vec::new();
        Self::append_nla_nested(&mut r6_exprs, 1, &expr_meta6);
        Self::append_nla_nested(&mut r6_exprs, 1, &expr_cmp6);
        Self::append_nla_nested(&mut r6_exprs, 1, &expr_payload6);
        Self::append_nla_nested(&mut r6_exprs, 1, &expr_lookup6);
        Self::append_nla_nested(&mut r6_exprs, 1, &expr_imm);

        let mut r6_payload = Vec::new();
        Self::append_nla_str(&mut r6_payload, NFTA_RULE_TABLE, &self.table_name);
        Self::append_nla_str(&mut r6_payload, NFTA_RULE_CHAIN, &self.chain_name);
        Self::append_nla_nested(&mut r6_payload, NFTA_RULE_EXPRESSIONS, &r6_exprs);

        let seq = self.next_seq();
        Self::append_nlmsg(
            &mut msg_buf,
            (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
            NLM_F_REQUEST | NLM_F_CREATE | NLM_F_APPEND,
            seq,
            0,
            NFPROTO_INET,
            0,
            &r6_payload,
        );

        self.send_batch(&msg_buf)?;
        self.initialized = true;
        Ok(())
    }

    fn ban_ip(&mut self, ip: IpAddr, timeout_secs: u64) -> Result<(), Box<dyn std::error::Error>> {
        let (set_name, ip_bytes) = match ip {
            IpAddr::V4(v4) => (&self.set_v4, v4.octets().to_vec()),
            IpAddr::V6(v6) => (&self.set_v6, v6.octets().to_vec()),
        };

        // Build element attributes
        let mut key_val = Vec::new();
        Self::append_nla(&mut key_val, NFTA_DATA_VALUE, &ip_bytes);

        let mut elem_attrs = Vec::new();
        Self::append_nla_nested(&mut elem_attrs, NFTA_SET_ELEM_KEY, &key_val);

        if timeout_secs > 0 {
            // Kernel expects timeout in milliseconds (u64 big-endian)
            let timeout_ms = timeout_secs.saturating_mul(1000);
            Self::append_nla_u64(&mut elem_attrs, NFTA_SET_ELEM_TIMEOUT, timeout_ms);
        }

        let mut elem_box = Vec::new();
        Self::append_nla_nested(&mut elem_box, 1, &elem_attrs);

        let mut e_payload = Vec::new();
        Self::append_nla_str(&mut e_payload, NFTA_SET_ELEM_LIST_TABLE, &self.table_name);
        Self::append_nla_str(&mut e_payload, NFTA_SET_ELEM_LIST_SET, set_name);
        Self::append_nla_nested(&mut e_payload, NFTA_SET_ELEM_LIST_ELEMENTS, &elem_box);

        let mut msg_buf = Vec::new();
        let seq = self.next_seq();
        Self::append_nlmsg(
            &mut msg_buf,
            (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSETELEM,
            NLM_F_REQUEST | NLM_F_CREATE,
            seq,
            0,
            NFPROTO_INET,
            0,
            &e_payload,
        );

        self.send_batch(&msg_buf)?;
        self.fallback_tracker.insert(
            ip,
            if timeout_secs > 0 {
                Some(timeout_secs)
            } else {
                None
            },
        );
        Ok(())
    }

    fn unban_ip(&mut self, ip: IpAddr) -> Result<(), Box<dyn std::error::Error>> {
        let (set_name, ip_bytes) = match ip {
            IpAddr::V4(v4) => (&self.set_v4, v4.octets().to_vec()),
            IpAddr::V6(v6) => (&self.set_v6, v6.octets().to_vec()),
        };

        let mut key_val = Vec::new();
        Self::append_nla(&mut key_val, NFTA_DATA_VALUE, &ip_bytes);

        let mut elem_attrs = Vec::new();
        Self::append_nla_nested(&mut elem_attrs, NFTA_SET_ELEM_KEY, &key_val);

        let mut elem_box = Vec::new();
        Self::append_nla_nested(&mut elem_box, 1, &elem_attrs);

        let mut e_payload = Vec::new();
        Self::append_nla_str(&mut e_payload, NFTA_SET_ELEM_LIST_TABLE, &self.table_name);
        Self::append_nla_str(&mut e_payload, NFTA_SET_ELEM_LIST_SET, set_name);
        Self::append_nla_nested(&mut e_payload, NFTA_SET_ELEM_LIST_ELEMENTS, &elem_box);

        let mut msg_buf = Vec::new();
        let seq = self.next_seq();
        Self::append_nlmsg(
            &mut msg_buf,
            (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_DELSETELEM,
            NLM_F_REQUEST,
            seq,
            0,
            NFPROTO_INET,
            0,
            &e_payload,
        );

        self.send_batch(&msg_buf)?;
        self.fallback_tracker.remove(&ip);
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut t_payload = Vec::new();
        Self::append_nla_str(&mut t_payload, NFTA_TABLE_NAME, &self.table_name);

        let mut msg_buf = Vec::new();
        let seq = self.next_seq();
        Self::append_nlmsg(
            &mut msg_buf,
            (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_DELTABLE,
            NLM_F_REQUEST,
            seq,
            0,
            NFPROTO_INET,
            0,
            &t_payload,
        );

        self.send_batch(&msg_buf)?;
        self.fallback_tracker.clear();
        self.initialized = false;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "nftables (Netlink)"
    }

    fn list_banned(&self) -> Vec<(IpAddr, Option<u64>)> {
        let mut results = Vec::new();
        let mut nft_success = false;

        for set in [&self.set_v4, &self.set_v6] {
            if let Ok(output) = std::process::Command::new("nft")
                .args(["-j", "list", "set", "inet", &self.table_name, set])
                .output()
            {
                if output.status.success() {
                    nft_success = true;
                    if let Ok(json) = std::str::from_utf8(&output.stdout) {
                        results.extend(parse_nft_json_elements(json));
                    }
                }
            }
        }

        if nft_success {
            results
        } else {
            self.fallback_tracker
                .iter()
                .map(|(ip, t)| (*ip, *t))
                .collect()
        }
    }
}

pub fn parse_nft_json_elements(json: &str) -> Vec<(IpAddr, Option<u64>)> {
    let mut results = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut pos = 0;
    while let Some(val_idx) = json[pos..].find("\"val\":") {
        let actual_val_idx = pos + val_idx + 6;
        let rest = &json[actual_val_idx..];
        if let Some(start_q) = rest.find('"') {
            let after_q = &rest[start_q + 1..];
            if let Some(end_q) = after_q.find('"') {
                let ip_str = &after_q[..end_q];
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    let slice_len = (end_q + 120).min(after_q.len());
                    let context = &after_q[..slice_len];

                    let mut expires = None;
                    if let Some(e_idx) = context.find("\"expires\":") {
                        let num_str: String = context[e_idx + 10..]
                            .trim_start()
                            .chars()
                            .take_while(|c| c.is_ascii_digit())
                            .collect();
                        if let Ok(e) = num_str.parse::<u64>() {
                            expires = Some(e);
                        }
                    }

                    if seen.insert(ip) {
                        results.push((ip, expires));
                    }
                }
            }
        }
        pos = actual_val_idx + 1;
    }

    if let Some(elem_idx) = json.find("\"elem\":") {
        let rest = &json[elem_idx + 7..];
        if let Some(start_arr) = rest.find('[') {
            let arr_rest = &rest[start_arr + 1..];
            if let Some(end_arr) = arr_rest.find(']') {
                let elem_content = &arr_rest[..end_arr];
                let mut p = 0;
                while let Some(q1) = elem_content[p..].find('"') {
                    let s_idx = p + q1 + 1;
                    if let Some(q2) = elem_content[s_idx..].find('"') {
                        let candidate = &elem_content[s_idx..s_idx + q2];
                        if let Ok(ip) = candidate.parse::<IpAddr>() {
                            if seen.insert(ip) {
                                results.push((ip, None));
                            }
                        }
                        p = s_idx + q2 + 1;
                    } else {
                        break;
                    }
                }
            }
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_nft_json_elements() {
        let json_with_timeout = r#"{"nftables": [{"set": {"family": "inet", "name": "bannix_v4", "table": "bannix", "elem": [{"elem": {"val": "198.51.100.199", "timeout": 30, "expires": 28}}]}}]}"#;
        let res1 = parse_nft_json_elements(json_with_timeout);
        assert_eq!(res1.len(), 1);
        assert_eq!(res1[0].0, "198.51.100.199".parse::<IpAddr>().unwrap());
        assert_eq!(res1[0].1, Some(28));

        let json_plain_elements = r#"{"nftables": [{"set": {"family": "inet", "name": "bannix_v4", "table": "bannix", "elem": ["198.51.100.200", "2001:db8::1"]}}]}"#;
        let res2 = parse_nft_json_elements(json_plain_elements);
        assert_eq!(res2.len(), 2);
        assert_eq!(res2[0].0, "198.51.100.200".parse::<IpAddr>().unwrap());
        assert_eq!(res2[0].1, None);
        assert_eq!(res2[1].0, "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(res2[1].1, None);
    }
}
