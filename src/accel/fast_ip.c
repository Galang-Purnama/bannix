#include "fast_ip.h"
#include <string.h>
#include <arpa/inet.h>

int fast_ip_parse_ipv4(const uint8_t *buf, size_t len, uint32_t *out_be32) {
    if (!buf || len < 7 || len > 15 || !out_be32) {
        return -1;
    }

    const uint8_t *ptr = buf;
    const uint8_t *end = buf + len;
    uint32_t octets[4] = {0, 0, 0, 0};
    int octet_idx = 0;
    int digits_in_octet = 0;

    while (ptr < end) {
        uint8_t c = *ptr++;
        if (c >= '0' && c <= '9') {
            octets[octet_idx] = octets[octet_idx] * 10 + (c - '0');
            digits_in_octet++;
            if (digits_in_octet > 3 || octets[octet_idx] > 255) {
                return -1;
            }
        } else if (c == '.') {
            if (digits_in_octet == 0 || octet_idx >= 3) {
                return -1;
            }
            octet_idx++;
            digits_in_octet = 0;
        } else {
            // Unexpected character in IPv4 token
            return -1;
        }
    }

    if (octet_idx != 3 || digits_in_octet == 0) {
        return -1;
    }

    uint32_t ip = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
    *out_be32 = htonl(ip);
    return 0;
}

static inline int is_token_delim(uint8_t c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '[' || c == ']' ||
           c == '(' || c == ')' || c == ',' || c == ';' || c == '"' || c == '\'';
}

static int try_parse_ip_token(const uint8_t *token, size_t len, uint8_t *out_is_v6, uint8_t *out_ip_bytes) {
    if (len == 0 || len > 45) {
        return -1;
    }

    // Strip port if formatted as ip:port (IPv4)
    size_t effective_len = len;
    int colon_count = 0;
    for (size_t i = 0; i < len; i++) {
        if (token[i] == ':') {
            colon_count++;
        }
    }

    if (colon_count == 1) {
        // Potential IPv4 with port (e.g. 1.2.3.4:5678)
        for (size_t i = 0; i < len; i++) {
            if (token[i] == ':') {
                effective_len = i;
                break;
            }
        }
    }

    // Try IPv4 first
    uint32_t v4_be = 0;
    if (fast_ip_parse_ipv4(token, effective_len, &v4_be) == 0) {
        *out_is_v6 = 0;
        memcpy(out_ip_bytes, &v4_be, 4);
        return 0;
    }

    // Try IPv6 if colons are present
    if (colon_count >= 2) {
        char temp_str[48];
        if (len < sizeof(temp_str)) {
            memcpy(temp_str, token, len);
            temp_str[len] = '\0';
            struct in6_addr in6;
            if (inet_pton(AF_INET6, temp_str, &in6) == 1) {
                *out_is_v6 = 1;
                memcpy(out_ip_bytes, &in6.s6_addr, 16);
                return 0;
            }
        }
    }

    return -1;
}

int fast_ip_extract(const uint8_t *buf, size_t len, uint8_t *out_is_v6, uint8_t *out_ip_bytes) {
    if (!buf || len == 0 || !out_is_v6 || !out_ip_bytes) {
        return -1;
    }

    static const struct {
        const char *prefix;
        size_t len;
    } prefixes[] = {
        {"from ", 5},
        {"client: ", 8},
        {"client ", 7},
        {"rhost=", 6},
        {"SRC=", 4},
        {"src=", 4},
    };
    const size_t num_prefixes = sizeof(prefixes) / sizeof(prefixes[0]);

    // Priority 1: Prefix search
    for (size_t p = 0; p < num_prefixes; p++) {
        const char *needle = prefixes[p].prefix;
        size_t nlen = prefixes[p].len;
        if (len < nlen) continue;

        for (size_t i = 0; i <= len - nlen; i++) {
            if (memcmp(buf + i, needle, nlen) == 0) {
                const uint8_t *start = buf + i + nlen;
                while (start < buf + len && (*start == ' ' || *start == '\t')) {
                    start++;
                }
                const uint8_t *end = start;
                while (end < buf + len && !is_token_delim(*end)) {
                    end++;
                }
                size_t token_len = (size_t)(end - start);
                if (try_parse_ip_token(start, token_len, out_is_v6, out_ip_bytes) == 0) {
                    return 0;
                }
            }
        }
    }

    // Priority 2: Reverse token scan
    const uint8_t *ptr = buf + len;
    while (ptr > buf) {
        while (ptr > buf && is_token_delim(*(ptr - 1))) {
            ptr--;
        }
        const uint8_t *token_end = ptr;
        while (ptr > buf && !is_token_delim(*(ptr - 1))) {
            ptr--;
        }
        const uint8_t *token_start = ptr;
        size_t tlen = (size_t)(token_end - token_start);

        if (tlen > 0) {
            // Trim leading [ ( or trailing ] )
            while (tlen > 0 && (*token_start == '[' || *token_start == '(')) {
                token_start++;
                tlen--;
            }
            while (tlen > 0 && (token_start[tlen - 1] == ']' || token_start[tlen - 1] == ')' || token_start[tlen - 1] == ',')) {
                tlen--;
            }

            if (try_parse_ip_token(token_start, tlen, out_is_v6, out_ip_bytes) == 0) {
                return 0;
            }
        }
    }

    return -1;
}

