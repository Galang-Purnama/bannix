#ifndef BANNIX_RAW_SOCKET_H
#define BANNIX_RAW_SOCKET_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Tunes socket receive and send buffer sizes for high-throughput packet processing.
 * Tries SO_RCVBUFFORCE / SO_RCVBUF and SO_SNDBUFFORCE / SO_SNDBUF.
 * Returns 0 on success, or -1 on error.
 */
int c_socket_tune_buffers(int fd, int rcvbuf_bytes, int sndbuf_bytes);

/**
 * Atomically sets non-blocking and close-on-exec flags on a file descriptor.
 * Returns 0 on success, or -1 on error.
 */
int c_socket_set_nonblocking(int fd);

/**
 * Queries network interface index by interface name (e.g. "lo", "eth0").
 * Returns interface index > 0 on success, or -1 on error.
 */
int c_net_get_ifindex(const char *ifname);

/**
 * Checks if a network interface is UP and running.
 * Returns 1 if UP, 0 if DOWN, or -1 on error.
 */
int c_net_is_iface_up(const char *ifname);

#ifdef __cplusplus
}
#endif

#endif /* BANNIX_RAW_SOCKET_H */
