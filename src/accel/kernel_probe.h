#ifndef BANNIX_KERNEL_PROBE_H
#define BANNIX_KERNEL_PROBE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Virtualization & Container detection constants */
#define BANNIX_ENV_BAREMETAL 0
#define BANNIX_ENV_DOCKER    1
#define BANNIX_ENV_LXC       2
#define BANNIX_ENV_OPENVZ    3
#define BANNIX_ENV_WSL       4

/**
 * Retrieves the Linux kernel release string into `buf`.
 * Returns 0 on success, or -1 on error.
 */
int c_kernel_get_version(char *buf, size_t max_len);

/**
 * Probes the execution environment (bare metal, Docker, LXC, OpenVZ, WSL).
 * Returns one of BANNIX_ENV_* constants.
 */
int c_kernel_detect_environment(void);

/**
 * Checks if the current process has CAP_NET_ADMIN privileges in Linux kernel.
 * Returns 1 if present, 0 if unprivileged.
 */
int c_kernel_has_net_admin(void);

/**
 * Probes whether the Linux kernel supports Netlink nftables in current environment.
 * Returns 1 if supported, 0 otherwise.
 */
int c_kernel_probe_nftables_support(void);

#ifdef __cplusplus
}
#endif

#endif /* BANNIX_KERNEL_PROBE_H */
