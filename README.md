<div align="center">

# 🛡️ bannix

**Ultra-fast, zero-overhead Intrusion Prevention System (IPS) for Linux.**  
*A modern, single-binary drop-in alternative to Fail2ban built with pure Rust and native kernel Netlink.*

[![Language](https://img.shields.io/badge/Language-Rust%201.85+-orange.svg?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20(x86__64%20%7C%20aarch64)-brightgreen.svg?style=flat-square&logo=linux)](https://kernel.org)
[![Binary Size](https://img.shields.io/badge/Binary%20Size-%3C%201%20MB-success.svg?style=flat-square)]()
[![RAM Footprint](https://img.shields.io/badge/RAM%20Idle-%3C%203.0%20MB-blueviolet.svg?style=flat-square)]()
[![Subprocess Overhead](https://img.shields.io/badge/Subprocess%20Forks-0%20(Pure%20Netlink)-purple.svg?style=flat-square)]()

</div>

---

## ⚡ Overview

**bannix** is an industrial-grade intrusion prevention daemon engineered to protect Linux servers against brute-force attacks, scanner probes, and distributed denial-of-service attempts without the resource bloat of traditional tools.

While Python-based alternatives like Fail2ban spawn hundreds of shell subprocesses and consume tens of megabytes of memory under load, **bannix** operates directly within kernel space via **raw Netlink sockets (`AF_NETLINK`)**, achieving **sub-millisecond detection-to-ban latency** with **zero subprocess forks** and a memory footprint under 3 MB.

### ✨ Key Highlights

- **Zero-Fork Kernel Engine**: Direct `AF_NETLINK` communication with `nftables` and `ipset`. Zero `fork()` or `exec()` overhead during active attacks.
- **Microsecond Pattern Matching**: Linear-time $O(n)$ pattern searching powered by the **Aho-Corasick DFA** algorithm—immune to Regular Expression Denial of Service (ReDoS).
- **Zero-Copy IP Parser**: Extracts IPv4 and IPv6 addresses directly from raw log byte buffers without heap allocations.
- **Kernel-Level Expiry**: Uses native kernel set timeouts (`NFTA_SET_ELEM_TIMEOUT`). The kernel unbans automatically—no userland polling threads required.
- **Dual Log Ingestion**: High-performance non-blocking `inotify` + `epoll` pipeline with automatic log rotation handling and native systemd `journald` support.
- **Zero-Downtime Hot Reload**: Update configuration and jail definitions on the fly without interrupting log streams via `SIGHUP` or `systemctl reload`.

---

## 🚀 Quick Start (One-Line Install)

Run the automated installer on your server (requires `root` or `sudo` privileges):

```bash
curl -sSL https://raw.githubusercontent.com/Galang-Purnama/bannix/main/install.sh | sudo bash
```

The installer detects your CPU architecture (`x86_64` or `aarch64`), provisions `/etc/bannix/` configurations, configures the `systemd` service unit, and immediately activates kernel-level protection.

---

## 📊 Performance Comparison

| Metric / Feature | Fail2ban | CrowdSec | **bannix** |
| :--- | :--- | :--- | :--- |
| **Runtime & Language** | Python 3 + Runtime VM | Go Runtime + Agent | **Pure Rust (Native Static Binary)** |
| **Idle Memory (VmRSS)** | $50\text{ MB} - 120\text{ MB}$ | $40\text{ MB} - 80\text{ MB}$ | **$\mathbf{\le 3.0\text{ MB}}$** |
| **Firewall Interaction** | Subprocess fork (`/sbin/nft`) | Subprocess bouncer | **Direct Kernel Netlink (`AF_NETLINK`)** |
| **Fork Overhead per Ban** | 1–3 forks per strike/ban | Subprocess IPC | **0 Forks (Zero-Fork Architecture)** |
| **Pattern Search Algorithm** | Dynamic Regex (ReDoS risk) | Yaml scenarios + Regex | **Aho-Corasick DFA ($O(n)$ Linear)** |
| **IP Buffer Parsing** | String heap copy | String heap copy | **Zero-Copy Parser on `&[u8]`** |
| **Unban Execution** | Polling thread loop | Userland API polling | **Kernel Dynamic Set (`NFTA_SET_ELEM_TIMEOUT`)** |
| **Binary Footprint** | System Python packages | $\sim 45\text{ MB}$ | **$< 1\text{ MB}$** |

---

## 🔧 Operational Guide

### 1. View Currently Banned IPs (`bannix banned`)
Inspect all currently banned attackers, the jail that triggered the ban, ban duration, and remaining expiry time:
```bash
bannix banned
# or filter by specific jail:
bannix banned ssh
# or output machine-readable JSON:
bannix banned --json
```
*Example output:*
```text
========================================================================================
                                    bannix Banned IPs                                   
========================================================================================
IP ADDRESS         JAIL       BANNED AT (UTC)       DURATION   EXPIRES IN       STATUS  
----------------------------------------------------------------------------------------
45.148.10.141      ssh        2026-11-09 02:42:10   3600s      9m 47s           Active  
2.57.121.25        ssh        2026-11-09 02:42:10   3600s      28m 49s          Active  
45.148.10.151      ssh        2026-11-09 02:42:10   3600s      31m 11s          Active  
193.47.62.69       ssh        2026-11-09 02:42:10   3600s      38m 21s          Active  
----------------------------------------------------------------------------------------
Total Banned: 4 IP(s) | Firewall: nftables (Netlink) (table: bannix_filter)
Tip: Use 'bannix unban <IP>' to unban an IP manually.
========================================================================================
```

### 2. View Jails & Status (`bannix list`)
List all configured jails, their enabled/disabled state, log source, rules, and active ban count:
```bash
bannix list
# or inspect details and DFA patterns for a specific jail:
bannix list ssh
```
*Example output:*
```text
========================================================================================
                                   bannix Jails Status                                  
========================================================================================
JAIL       STATUS     MODE       LOG PATH                   RETRY   FINDTIME   BANTIME    BANNED  
----------------------------------------------------------------------------------------
nginx      disabled   inotify    /var/log/nginx/error.log   10      300s       1800s      0       
ssh        active     inotify    /var/log/auth.log          5       600s       3600s      4       
----------------------------------------------------------------------------------------
Total Configured: 2 | Active Jails: 1 | Total Active Bans: 4
Tip: Run 'bannix list <JAIL>' for details, or 'bannix banned' to see all banned IPs.
========================================================================================
```

### 3. Service & Daemon Status (`bannix status`)
Check daemon health, uptime, and active jails via IPC socket:
```bash
bannix status
```
*Example output:*
```text
bannix daemon v0.1.6
Uptime: 1420s
Backend: nftables (Netlink) (table: bannix_filter)
Whitelisted: 5 entries
Currently Banned: 4 IP(s)
Active Jails (1):
  • ssh        | log: /var/log/auth.log | mode: inotify | retry: 5/600s | ban: 3600s | banned: 4
```

### 4. Manual Unban & Ban via CLI
Unban an IP immediately from the kernel firewall without restarting the daemon:
```bash
bannix unban 192.168.1.50
```

Manually ban an attacker for a custom duration (default: 3600s):
```bash
bannix ban 203.0.113.99 7200
```

### 5. Live Attack Monitoring
Follow brute-force detection and kernel ban executions in real time:
```bash
journalctl -u bannix -f
```

### 6. Inspect Kernel Banned IP Sets Directly
Because bannix programs kernel sets directly, view blocked attackers in `nftables`:
```bash
nft list set inet bannix_filter blacklist_v4
```

*Example output:*
```text
table inet bannix_filter {
    set blacklist_v4 {
        type ipv4_addr
        flags timeout
        elements = { 45.148.10.152 timeout 1h expires 52m19s, 193.46.255.86 timeout 1h expires 57m46s }
    }
}
```

### 7. Validate Configuration Syntax
Verify configuration syntax and compile patterns before applying changes:
```bash
bannix --test-config
# or specify a path:
bannix -c /etc/bannix/bannix.toml --test-config
```

### 8. Zero-Downtime Hot Reload
Reload configuration without dropping connections or restarting the daemon:
```bash
systemctl reload bannix
# or via POSIX signal:
kill -HUP $(pidof bannix)
```

---

## ⚙️ Configuration

Configuration is modular and structured under `/etc/bannix/`:

```
/etc/bannix/
├── bannix.toml        # Master daemon settings & global whitelist
└── jails.d/           # Modular jail definitions
    ├── ssh.toml       # OpenSSH protection
    └── nginx.toml     # Nginx web server protection
```

### Master Configuration (`/etc/bannix/bannix.toml`)

```toml
[daemon]
log_level = "info"              # trace | debug | info | warn | error
backend = "auto"                # auto (recommended) | nftables | ipset | iptables
table_name = "bannix_filter"
purge_on_exit = false           # Keep kernel rules intact during daemon restarts

[whitelist]
# IP addresses and CIDR subnets that are NEVER banned
ips = [
    "127.0.0.1",
    "::1",
    "192.168.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "203.0.113.50"              # Static Administrator IP
]
```

### Modular Jails (`/etc/bannix/jails.d/*.toml`)

Each file inside `/etc/bannix/jails.d/` represents an isolated jail.

Example: `/etc/bannix/jails.d/ssh.toml`
```toml
enabled = true
log_path = "/var/log/auth.log"   # Target log file
mode = "inotify"                # inotify | journald
findtime = 600                  # Sliding evaluation window in seconds (10 mins)
maxretry = 5                    # Failure count before banning
bantime = 3600                  # Ban duration in seconds (1 hour; 0 = permanent)
patterns = [
    "Failed password for",
    "Invalid user",
    "authentication failure; logname=",
    "Connection closed by authenticating user"
]
```

Apply updates instantly:
```bash
systemctl reload bannix
```

---

## 🛠️ Building from Source

### Prerequisites
- Linux Kernel $\ge 3.10$ with Netlink support enabled
- Rust toolchain $1.85+$ (`rustup`)
- `gcc` or `clang` for the C acceleration bridge (`src/accel`)

```bash
# 1. Clone repository
git clone https://github.com/Galang-Purnama/bannix.git
cd bannix

# 2. Run unit & integration test suite
cargo test

# 3. Build optimized release binary
cargo build --release

# 4. Optional: Run automated benchmark & smoke test
bash scripts/benchmark.sh

# 5. Install to system
sudo make install
```

---

## 🔄 Updating bannix

To update the `bannix` binary to the latest release on any server:

```bash
curl -sSL https://raw.githubusercontent.com/Galang-Purnama/bannix/main/install.sh | sudo bash -s -- --update
```

Or from a local git repository:
```bash
sudo ./install.sh --update
```

The updater downloads the latest static pre-compiled binary for your architecture (`x86_64` or `aarch64`), verifies it, replaces `/usr/local/bin/bannix`, checks configuration compatibility, and automatically restarts the systemd service.

---

## 🗑️ Uninstallation

To remove bannix completely from your system:

```bash
curl -sSL https://raw.githubusercontent.com/Galang-Purnama/bannix/main/install.sh | sudo bash -s -- --uninstall
```

To purge configuration files (`/etc/bannix/`) as well:
```bash
curl -sSL https://raw.githubusercontent.com/Galang-Purnama/bannix/main/install.sh | sudo bash -s -- --uninstall --purge
```

---

## 📄 License

Licensed under the [GNU General Public License v3.0 (GPL-3.0)](LICENSE).  
Authored by **Galang Purnama** (<support@nekohost.id>).
