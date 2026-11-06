#include "netlink_raw.h"
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <endian.h>

#ifndef NFPROTO_UNSPEC
#define NFPROTO_UNSPEC 0
#endif

#ifndef NFPROTO_INET
#define NFPROTO_INET 1
#endif

#define NLA_ALIGNTO 4
#define NLA_ALIGN(len) (((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))

#define NFNL_SUBSYS_NFTABLES 10

#undef NFNL_MSG_BATCH_BEGIN
#define NFNL_MSG_BATCH_BEGIN ((NFNL_SUBSYS_NFTABLES << 8) | 0x10)

#undef NFNL_MSG_BATCH_END
#define NFNL_MSG_BATCH_END   ((NFNL_SUBSYS_NFTABLES << 8) | 0x11)

#define NFT_MSG_NEWTABLE   ((NFNL_SUBSYS_NFTABLES << 8) | 0)
#define NFT_MSG_DELTABLE   ((NFNL_SUBSYS_NFTABLES << 8) | 1)
#define NFT_MSG_NEWCHAIN   ((NFNL_SUBSYS_NFTABLES << 8) | 3)
#define NFT_MSG_NEWSET     ((NFNL_SUBSYS_NFTABLES << 8) | 9)
#define NFT_MSG_NEWSETELEM ((NFNL_SUBSYS_NFTABLES << 8) | 12)
#define NFT_MSG_DELSETELEM ((NFNL_SUBSYS_NFTABLES << 8) | 13)
#define NFT_MSG_NEWRULE    ((NFNL_SUBSYS_NFTABLES << 8) | 6)

// nftables attributes
#define NFTA_TABLE_NAME 1
#define NFTA_SET_TABLE 1
#define NFTA_SET_NAME 2
#define NFTA_SET_FLAGS 3
#define NFTA_SET_KEY_TYPE 4
#define NFTA_SET_KEY_LEN 5

#define NFTA_SET_ELEM_LIST_TABLE 1
#define NFTA_SET_ELEM_LIST_SET 2
#define NFTA_SET_ELEM_LIST_ELEMENTS 3

#define NFTA_SET_ELEM_KEY 1
#define NFTA_SET_ELEM_TIMEOUT 3
#define NFTA_DATA_VALUE 1

#define NFT_SET_TIMEOUT 0x08
#define NFPROTO_INET 1

int c_netlink_open(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
    if (fd < 0) {
        return -errno;
    }
    return fd;
}

void c_netlink_close(int fd) {
    if (fd >= 0) {
        close(fd);
    }
}

int c_netlink_is_supported(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
    if (fd < 0) {
        return 0;
    }
    close(fd);
    return 1;
}

static inline void append_bytes(uint8_t *buf, size_t *offset, size_t max_len, const void *data, size_t data_len) {
    if (*offset + data_len <= max_len) {
        memcpy(buf + *offset, data, data_len);
        *offset += data_len;
    }
}

static inline void append_nla(uint8_t *buf, size_t *offset, size_t max_len, uint16_t nla_type, const void *data, size_t data_len) {
    uint16_t nla_len = (uint16_t)(sizeof(struct nlattr) + data_len);
    struct nlattr nla;
    nla.nla_len = nla_len;
    nla.nla_type = nla_type;

    append_bytes(buf, offset, max_len, &nla, sizeof(nla));
    if (data && data_len > 0) {
        append_bytes(buf, offset, max_len, data, data_len);
    }
    size_t aligned = NLA_ALIGN(nla_len);
    size_t pad = aligned - nla_len;
    if (pad > 0) {
        uint8_t zero[NLA_ALIGNTO] = {0};
        append_bytes(buf, offset, max_len, zero, pad);
    }
}

static inline void append_nla_str(uint8_t *buf, size_t *offset, size_t max_len, uint16_t nla_type, const char *str) {
    size_t slen = strlen(str) + 1; // null-terminated
    append_nla(buf, offset, max_len, nla_type, str, slen);
}

static inline void append_nlmsg(
    uint8_t *buf, size_t *offset, size_t max_len,
    uint16_t nlmsg_type, uint16_t nlmsg_flags, uint32_t seq,
    uint8_t nfgen_family, uint16_t res_id,
    const uint8_t *payload, size_t payload_len
) {
    uint32_t total_len = (uint32_t)(sizeof(struct nlmsghdr) + sizeof(struct nfgenmsg) + payload_len);
    struct nlmsghdr nlh;
    nlh.nlmsg_len = total_len;
    nlh.nlmsg_type = nlmsg_type;
    nlh.nlmsg_flags = nlmsg_flags;
    nlh.nlmsg_seq = seq;
    nlh.nlmsg_pid = 0;

    struct nfgenmsg nfg;
    nfg.nfgen_family = nfgen_family;
    nfg.version = NFNETLINK_V0;
    nfg.res_id = htons(res_id);

    append_bytes(buf, offset, max_len, &nlh, sizeof(nlh));
    append_bytes(buf, offset, max_len, &nfg, sizeof(nfg));
    if (payload && payload_len > 0) {
        append_bytes(buf, offset, max_len, payload, payload_len);
    }
}

static int send_batch(int fd, const uint8_t *msg_buf, size_t msg_len, uint32_t *seq) {
    uint8_t packet[8192];
    size_t offset = 0;

    uint32_t s = seq ? ++(*seq) : 1;

    // 1. Batch begin
    append_nlmsg(packet, &offset, sizeof(packet),
                 NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, s,
                 NFPROTO_UNSPEC, 10 << 8, NULL, 0);

    // 2. Transaction messages
    append_bytes(packet, &offset, sizeof(packet), msg_buf, msg_len);

    // 3. Batch end
    append_nlmsg(packet, &offset, sizeof(packet),
                 NFNL_MSG_BATCH_END, NLM_F_REQUEST, s,
                 NFPROTO_UNSPEC, 10 << 8, NULL, 0);

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    ssize_t ret = sendto(fd, packet, offset, 0, (struct sockaddr *)&sa, sizeof(sa));
    if (ret < 0) {
        return -errno;
    }
    return 0;
}

int c_netlink_init_table_and_set(int fd, const char *table_name, const char *set_name, uint32_t *seq) {
    if (fd < 0 || !table_name || !set_name) return -EINVAL;

    uint8_t msg_buf[4096];
    size_t msg_len = 0;

    uint32_t s = seq ? ++(*seq) : 1;

    // 1. Table
    uint8_t t_payload[512];
    size_t t_len = 0;
    append_nla_str(t_payload, &t_len, sizeof(t_payload), NFTA_TABLE_NAME, table_name);
    append_nlmsg(msg_buf, &msg_len, sizeof(msg_buf),
                 NFT_MSG_NEWTABLE, NLM_F_REQUEST | NLM_F_CREATE, s,
                 NFPROTO_INET, 0, t_payload, t_len);

    // 2. Set with timeout
    uint8_t s_payload[512];
    size_t s_len = 0;
    append_nla_str(s_payload, &s_len, sizeof(s_payload), NFTA_SET_TABLE, table_name);
    append_nla_str(s_payload, &s_len, sizeof(s_payload), NFTA_SET_NAME, set_name);
    uint32_t flags = htonl(NFT_SET_TIMEOUT);
    append_nla(s_payload, &s_len, sizeof(s_payload), NFTA_SET_FLAGS, &flags, 4);
    uint32_t key_type = htonl(7); // TYPE_IPADDR
    append_nla(s_payload, &s_len, sizeof(s_payload), NFTA_SET_KEY_TYPE, &key_type, 4);
    uint32_t key_len = htonl(4); // 4 bytes
    append_nla(s_payload, &s_len, sizeof(s_payload), NFTA_SET_KEY_LEN, &key_len, 4);

    append_nlmsg(msg_buf, &msg_len, sizeof(msg_buf),
                 NFT_MSG_NEWSET, NLM_F_REQUEST | NLM_F_CREATE, s,
                 NFPROTO_INET, 0, s_payload, s_len);

    return send_batch(fd, msg_buf, msg_len, seq);
}

int c_netlink_add_set_elem_v4(int fd, const char *table_name, const char *set_name, uint32_t ip_be32, uint64_t timeout_secs, uint32_t *seq) {
    if (fd < 0 || !table_name || !set_name) return -EINVAL;

    // Build element payload
    uint8_t elem_key_nla[64];
    size_t elem_key_len = 0;
    append_nla(elem_key_nla, &elem_key_len, sizeof(elem_key_nla), NFTA_DATA_VALUE, &ip_be32, 4);

    uint8_t elem_nested[128];
    size_t elem_nested_len = 0;
    append_nla(elem_nested, &elem_nested_len, sizeof(elem_nested), NFTA_SET_ELEM_KEY | NLA_F_NESTED, elem_key_nla, elem_key_len);

    if (timeout_secs > 0) {
        uint64_t timeout_ms_be = htobe64(timeout_secs * 1000);
        append_nla(elem_nested, &elem_nested_len, sizeof(elem_nested), NFTA_SET_ELEM_TIMEOUT, &timeout_ms_be, 8);
    }

    uint8_t list_elems[256];
    size_t list_elems_len = 0;
    append_nla(list_elems, &list_elems_len, sizeof(list_elems), 1 | NLA_F_NESTED, elem_nested, elem_nested_len);

    uint8_t payload[512];
    size_t payload_len = 0;
    append_nla_str(payload, &payload_len, sizeof(payload), NFTA_SET_ELEM_LIST_TABLE, table_name);
    append_nla_str(payload, &payload_len, sizeof(payload), NFTA_SET_ELEM_LIST_SET, set_name);
    append_nla(payload, &payload_len, sizeof(payload), NFTA_SET_ELEM_LIST_ELEMENTS | NLA_F_NESTED, list_elems, list_elems_len);

    uint8_t msg_buf[1024];
    size_t msg_len = 0;
    uint32_t s = seq ? ++(*seq) : 1;
    append_nlmsg(msg_buf, &msg_len, sizeof(msg_buf),
                 NFT_MSG_NEWSETELEM, NLM_F_REQUEST | NLM_F_CREATE, s,
                 NFPROTO_INET, 0, payload, payload_len);

    return send_batch(fd, msg_buf, msg_len, seq);
}

int c_netlink_del_set_elem_v4(int fd, const char *table_name, const char *set_name, uint32_t ip_be32, uint32_t *seq) {
    if (fd < 0 || !table_name || !set_name) return -EINVAL;

    uint8_t elem_key_nla[64];
    size_t elem_key_len = 0;
    append_nla(elem_key_nla, &elem_key_len, sizeof(elem_key_nla), NFTA_DATA_VALUE, &ip_be32, 4);

    uint8_t elem_nested[128];
    size_t elem_nested_len = 0;
    append_nla(elem_nested, &elem_nested_len, sizeof(elem_nested), NFTA_SET_ELEM_KEY | NLA_F_NESTED, elem_key_nla, elem_key_len);

    uint8_t list_elems[256];
    size_t list_elems_len = 0;
    append_nla(list_elems, &list_elems_len, sizeof(list_elems), 1 | NLA_F_NESTED, elem_nested, elem_nested_len);

    uint8_t payload[512];
    size_t payload_len = 0;
    append_nla_str(payload, &payload_len, sizeof(payload), NFTA_SET_ELEM_LIST_TABLE, table_name);
    append_nla_str(payload, &payload_len, sizeof(payload), NFTA_SET_ELEM_LIST_SET, set_name);
    append_nla(payload, &payload_len, sizeof(payload), NFTA_SET_ELEM_LIST_ELEMENTS | NLA_F_NESTED, list_elems, list_elems_len);

    uint8_t msg_buf[1024];
    size_t msg_len = 0;
    uint32_t s = seq ? ++(*seq) : 1;
    append_nlmsg(msg_buf, &msg_len, sizeof(msg_buf),
                 NFT_MSG_DELSETELEM, NLM_F_REQUEST, s,
                 NFPROTO_INET, 0, payload, payload_len);

    return send_batch(fd, msg_buf, msg_len, seq);
}

int c_netlink_del_table(int fd, const char *table_name, uint32_t *seq) {
    if (fd < 0 || !table_name) return -EINVAL;

    uint8_t payload[256];
    size_t payload_len = 0;
    append_nla_str(payload, &payload_len, sizeof(payload), NFTA_TABLE_NAME, table_name);

    uint8_t msg_buf[512];
    size_t msg_len = 0;
    uint32_t s = seq ? ++(*seq) : 1;
    append_nlmsg(msg_buf, &msg_len, sizeof(msg_buf),
                 NFT_MSG_DELTABLE, NLM_F_REQUEST, s,
                 NFPROTO_INET, 0, payload, payload_len);

    return send_batch(fd, msg_buf, msg_len, seq);
}
