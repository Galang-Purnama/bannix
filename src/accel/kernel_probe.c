#define _GNU_SOURCE
#include "kernel_probe.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#ifndef NETLINK_NETFILTER
#define NETLINK_NETFILTER 12
#endif

int c_kernel_get_version(char *buf, size_t max_len) {
    if (!buf || max_len == 0) return -1;

    struct utsname uts;
    if (uname(&uts) != 0) {
        return -1;
    }

    strncpy(buf, uts.release, max_len - 1);
    buf[max_len - 1] = '\0';
    return 0;
}

int c_kernel_detect_environment(void) {
    struct stat st;

    // 1. Docker detection
    if (stat("/.dockerenv", &st) == 0) {
        return BANNIX_ENV_DOCKER;
    }

    // 2. OpenVZ / Virtuozzo detection
    if (stat("/proc/vz", &st) == 0) {
        return BANNIX_ENV_OPENVZ;
    }

    // 3. WSL detection
    FILE *fp_ver = fopen("/proc/version", "r");
    if (fp_ver) {
        char line[256];
        if (fgets(line, sizeof(line), fp_ver)) {
            if (strcasestr(line, "microsoft") || strcasestr(line, "wsl")) {
                fclose(fp_ver);
                return BANNIX_ENV_WSL;
            }
        }
        fclose(fp_ver);
    }

    // 4. Container cgroup inspection (Docker / LXC)
    FILE *fp_cg = fopen("/proc/1/cgroup", "r");
    if (fp_cg) {
        char line[256];
        while (fgets(line, sizeof(line), fp_cg)) {
            if (strstr(line, "docker") || strstr(line, "containerd")) {
                fclose(fp_cg);
                return BANNIX_ENV_DOCKER;
            }
            if (strstr(line, "lxc")) {
                fclose(fp_cg);
                return BANNIX_ENV_LXC;
            }
        }
        fclose(fp_cg);
    }

    // 5. systemd container indicator
    if (stat("/run/systemd/container", &st) == 0) {
        return BANNIX_ENV_LXC;
    }

    return BANNIX_ENV_BAREMETAL;
}

int c_kernel_has_net_admin(void) {
    if (geteuid() == 0) {
        // Root typically has CAP_NET_ADMIN unless restricted in container
        // Fall through to verify CapEff bitmask from kernel
    }

    FILE *fp = fopen("/proc/self/status", "r");
    if (!fp) {
        return geteuid() == 0 ? 1 : 0;
    }

    char line[128];
    uint64_t cap_eff = 0;
    int found = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "CapEff:\t", 8) == 0) {
            unsigned long long val = 0;
            if (sscanf(line + 8, "%llx", &val) == 1) {
                cap_eff = (uint64_t)val;
                found = 1;
            }
            break;
        }
    }
    fclose(fp);

    if (found) {
        // CAP_NET_ADMIN is bit 12 (1ULL << 12)
        return (cap_eff & (1ULL << 12)) ? 1 : 0;
    }

    return geteuid() == 0 ? 1 : 0;
}

int c_kernel_probe_nftables_support(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
    if (fd < 0) {
        return 0;
    }
    close(fd);
    return 1;
}
