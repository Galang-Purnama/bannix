#ifndef BANNIX_NETLINK_RAW_H
#define BANNIX_NETLINK_RAW_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Opens a raw AF_NETLINK socket in NETLINK_NETFILTER family.
 * Returns socket file descriptor >= 0 on success, or -1 on error.
 */
int c_netlink_open(void);

/**
 * Closes the netlink socket descriptor.
 */
void c_netlink_close(int fd);

/**
 * Probes whether the Linux kernel supports Netlink nftables in the current environment.
 * Returns 1 if supported, 0 otherwise.
 */
int c_netlink_is_supported(void);

/**
 * Initializes the nftables table, input hook chain, and set with timeout flag.
 * Returns 0 on success, or negative errno on error.
 */
int c_netlink_init_table_and_set(int fd, const char *table_name, const char *set_name, uint32_t *seq);

/**
 * Adds an IPv4 address to the blacklist set with dynamic kernel auto-unban timeout.
 * Returns 0 on success, or negative errno on error.
 */
int c_netlink_add_set_elem_v4(int fd, const char *table_name, const char *set_name, uint32_t ip_be32, uint64_t timeout_secs, uint32_t *seq);

/**
 * Deletes an IPv4 address from the blacklist set.
 * Returns 0 on success, or negative errno on error.
 */
int c_netlink_del_set_elem_v4(int fd, const char *table_name, const char *set_name, uint32_t ip_be32, uint32_t *seq);

/**
 * Purges and deletes the nftables table and associated chains/sets.
 * Returns 0 on success, or negative errno on error.
 */
int c_netlink_del_table(int fd, const char *table_name, uint32_t *seq);

#ifdef __cplusplus
}
#endif

#endif /* BANNIX_NETLINK_RAW_H */

