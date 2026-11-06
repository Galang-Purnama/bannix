#ifndef BANNIX_FAST_IP_H
#define BANNIX_FAST_IP_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Fast pointer-arithmetic IPv4 parser.
 * Parses a dotted-decimal IPv4 address from `buf` with length `len`.
 * Returns 0 on success (writing big-endian 32-bit IP to *out_be32), or -1 on error.
 */
int fast_ip_parse_ipv4(const uint8_t *buf, size_t len, uint32_t *out_be32);

/**
 * High-speed zero-copy IP address extractor.
 * Searches for known log prefixes ("from ", "client: ", "rhost=", "SRC=")
 * and parses either IPv4 (out_is_v6 = 0, 4 bytes written) or IPv6 (out_is_v6 = 1, 16 bytes written).
 * Returns 0 on success, or -1 if no valid IP found.
 */
int fast_ip_extract(const uint8_t *buf, size_t len, uint8_t *out_is_v6, uint8_t *out_ip_bytes);

#ifdef __cplusplus
}
#endif

#endif /* BANNIX_FAST_IP_H */

