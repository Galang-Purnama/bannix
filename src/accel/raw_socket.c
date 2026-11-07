#define _GNU_SOURCE
#include "raw_socket.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>

int c_socket_tune_buffers(int fd, int rcvbuf_bytes, int sndbuf_bytes) {
    if (fd < 0) return -1;

    if (rcvbuf_bytes > 0) {
#ifdef SO_RCVBUFFORCE
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf_bytes, sizeof(rcvbuf_bytes)) != 0) {
            setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf_bytes, sizeof(rcvbuf_bytes));
        }
#else
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf_bytes, sizeof(rcvbuf_bytes));
#endif
    }

    if (sndbuf_bytes > 0) {
#ifdef SO_SNDBUFFORCE
        if (setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &sndbuf_bytes, sizeof(sndbuf_bytes)) != 0) {
            setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf_bytes, sizeof(sndbuf_bytes));
        }
#else
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf_bytes, sizeof(sndbuf_bytes));
#endif
    }

    return 0;
}

int c_socket_set_nonblocking(int fd) {
    if (fd < 0) return -1;

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return -1;

    int fd_flags = fcntl(fd, F_GETFD, 0);
    if (fd_flags < 0) return -1;
    if (fcntl(fd, F_SETFD, fd_flags | FD_CLOEXEC) < 0) return -1;

    return 0;
}

int c_net_get_ifindex(const char *ifname) {
    if (!ifname || !*ifname) return -1;

    unsigned int idx = if_nametoindex(ifname);
    return idx > 0 ? (int)idx : -1;
}

int c_net_is_iface_up(const char *ifname) {
    if (!ifname || !*ifname) return -1;

    int sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sock < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    int ret = ioctl(sock, SIOCGIFFLAGS, &ifr);
    close(sock);

    if (ret < 0) return -1;

    return (ifr.ifr_flags & IFF_UP) ? 1 : 0;
}
