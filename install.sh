#!/usr/bin/env bash
# ==============================================================================
# bannix - Ultra-Lightweight Intrusion Prevention System Installer
# Repository: https://github.com/Galang-Purnama/bannix
# ==============================================================================
set -euo pipefail

PREFIX="/usr/local"
BIN_DIR="$PREFIX/bin"
CONF_DIR="/etc/bannix"
JAILS_DIR="$CONF_DIR/jails.d"
SYSTEMD_DIR="/etc/systemd/system"
GITHUB_REPO="Galang-Purnama/bannix"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

# Check root privileges
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as root (use sudo).${NC}" >&2
        exit 1
    fi
}

# Uninstall handler
uninstall_bannix() {
    check_root
    echo -e "${YELLOW}======================================================"
    echo -e "           Uninstalling bannix IPS                    "
    echo -e "======================================================${NC}"
    
    echo -e "${BLUE}Stopping and disabling bannix service...${NC}"
    if systemctl is-active --quiet bannix 2>/dev/null; then
        systemctl stop bannix 2>/dev/null || true
    fi
    systemctl disable bannix 2>/dev/null || true

    echo -e "${BLUE}Removing binary and systemd service...${NC}"
    rm -f "$BIN_DIR/bannix"
    rm -f "$SYSTEMD_DIR/bannix.service"
    systemctl daemon-reload || true

    if [[ "${1:-}" == "--purge" ]]; then
        echo -e "${YELLOW}Purging configuration directory: ${CONF_DIR}...${NC}"
        rm -rf "$CONF_DIR"
    else
        echo -e "${GREEN}Configuration directory ${CONF_DIR} was preserved.${NC}"
        echo -e "To delete all configurations, run: ${YELLOW}rm -rf ${CONF_DIR}${NC}"
    fi

    # Clean up kernel nftables table if it still exists
    if command -v nft >/dev/null 2>&1; then
        nft delete table inet bannix_filter 2>/dev/null || true
    fi

    echo -e "${GREEN}✓ bannix has been completely uninstalled.${NC}"
    exit 0
}

# Parse command line flags
for arg in "$@"; do
    case "$arg" in
        --uninstall)
            uninstall_bannix "${2:-}"
            ;;
        --purge)
            uninstall_bannix "--purge"
            ;;
    esac
done

check_root

echo -e "${BLUE}======================================================"
echo -e "       bannix IPS - Industrial Installer              "
echo -e "======================================================${NC}"

# Detect CPU Architecture
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)
        TARGET_ARCH="x86_64"
        ;;
    aarch64|arm64)
        TARGET_ARCH="aarch64"
        ;;
    *)
        echo -e "${RED}Error: Unsupported architecture: ${ARCH}. bannix supports x86_64 and aarch64.${NC}" >&2
        exit 1
        ;;
esac
echo -e "Detected Architecture: ${BOLD}${TARGET_ARCH}${NC}"

# Detect Script Context (Local Git Checkout vs Curl Pipe)
SCRIPT_DIR=""
if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
fi

TEMP_DIR=""
cleanup() {
    if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
    fi
}
trap cleanup EXIT

# 1. Acquire Binary
echo -e "\n${BLUE}[1/4] Preparing bannix binary...${NC}"
BINARY_PATH=""

# Check if pre-compiled binary exists in local target dir
if [[ -n "$SCRIPT_DIR" ]]; then
    if [[ -f "$SCRIPT_DIR/target/${TARGET_ARCH}-unknown-linux-musl/release/bannix" ]]; then
        BINARY_PATH="$SCRIPT_DIR/target/${TARGET_ARCH}-unknown-linux-musl/release/bannix"
    elif [[ -f "$SCRIPT_DIR/target/release/bannix" ]]; then
        BINARY_PATH="$SCRIPT_DIR/target/release/bannix"
    elif [[ -f "$SCRIPT_DIR/Cargo.toml" ]] && command -v cargo >/dev/null 2>&1; then
        echo -e "${YELLOW}Building release binary from local source...${NC}"
        (cd "$SCRIPT_DIR" && cargo build --release --target "${TARGET_ARCH}-unknown-linux-musl" 2>/dev/null || cargo build --release)
        if [[ -f "$SCRIPT_DIR/target/${TARGET_ARCH}-unknown-linux-musl/release/bannix" ]]; then
            BINARY_PATH="$SCRIPT_DIR/target/${TARGET_ARCH}-unknown-linux-musl/release/bannix"
        elif [[ -f "$SCRIPT_DIR/target/release/bannix" ]]; then
            BINARY_PATH="$SCRIPT_DIR/target/release/bannix"
        fi
    fi
fi

# If still not found, try downloading from GitHub releases
if [[ -z "$BINARY_PATH" ]]; then
    TEMP_DIR="$(mktemp -d)"
    DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/latest/download/bannix-${TARGET_ARCH}-linux-musl"
    echo -e "Attempting to download pre-built binary from:"
    echo -e "  ${DOWNLOAD_URL}"

    if curl -sSL -f -o "$TEMP_DIR/bannix" "$DOWNLOAD_URL" 2>/dev/null; then
        chmod +x "$TEMP_DIR/bannix"
        BINARY_PATH="$TEMP_DIR/bannix"
        echo -e "${GREEN}✓ Downloaded pre-built static binary successfully.${NC}"
    else
        echo -e "${YELLOW}Pre-built release asset not found. Checking local system cargo toolchain...${NC}"
        if command -v cargo >/dev/null 2>&1 && command -v git >/dev/null 2>&1; then
            echo -e "Cloning source code and compiling statically..."
            git clone --depth 1 "https://github.com/${GITHUB_REPO}.git" "$TEMP_DIR/source"
            (cd "$TEMP_DIR/source" && cargo build --release --target "${TARGET_ARCH}-unknown-linux-musl" 2>/dev/null || cargo build --release)
            if [[ -f "$TEMP_DIR/source/target/${TARGET_ARCH}-unknown-linux-musl/release/bannix" ]]; then
                BINARY_PATH="$TEMP_DIR/source/target/${TARGET_ARCH}-unknown-linux-musl/release/bannix"
            else
                BINARY_PATH="$TEMP_DIR/source/target/release/bannix"
            fi
        elif [[ -f "$BIN_DIR/bannix" ]]; then
            echo -e "${YELLOW}Using currently installed /usr/local/bin/bannix binary.${NC}"
            BINARY_PATH="$BIN_DIR/bannix"
        else
            echo -e "${RED}Error: Could not obtain bannix binary.${NC}" >&2
            echo -e "Please ensure Cargo is installed or download the binary manually." >&2
            exit 1
        fi
    fi
fi

if [[ "$BINARY_PATH" != "$BIN_DIR/bannix" ]]; then
    install -d "$BIN_DIR"
    install -m 755 "$BINARY_PATH" "$BIN_DIR/bannix"
fi
echo -e "${GREEN}✓ Binary installed: $($BIN_DIR/bannix --version)${NC}"

# 2. Setup Configuration
echo -e "\n${BLUE}[2/4] Setting up configuration in ${CONF_DIR}...${NC}"
install -d -m 750 "$CONF_DIR"
install -d -m 750 "$JAILS_DIR"

# Install master config bannix.toml
if [[ ! -f "$CONF_DIR/bannix.toml" ]]; then
    if [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/config/bannix.toml" ]]; then
        install -m 640 "$SCRIPT_DIR/config/bannix.toml" "$CONF_DIR/bannix.toml"
    else
        cat << 'EOF' > "$CONF_DIR/bannix.toml"
[daemon]
log_level = "info"              # trace, debug, info, warn, error
backend = "auto"                # auto | nftables | ipset | iptables
table_name = "bannix_filter"
purge_on_exit = false           # Pertahankan blokir saat service direstart

[whitelist]
# IP dan Subnet yang DILARANG KERAS diblokir (Localhost, Private LAN, Management IP)
ips = [
    "127.0.0.1",
    "::1",
    "192.168.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12"
]

# ==============================================================================
# Jails Configuration
# ==============================================================================

[jails.ssh]
enabled = true
log_path = "/var/log/auth.log"
mode = "inotify"                # inotify | journald
findtime = 600                  # 10 menit evaluasi
maxretry = 5                    # 5 kali salah password langsung ban
bantime = 3600                  # 1 jam ban (0 = permanen)
patterns = [
    "Failed password for",
    "Invalid user",
    "authentication failure; logname="
]

[jails.nginx]
enabled = false
log_path = "/var/log/nginx/error.log"
mode = "inotify"
findtime = 300
maxretry = 10
bantime = 1800                  # 30 menit ban
patterns = [
    "directory index of [^ ]* is forbidden",
    "access forbidden by rule"
]
EOF
        chmod 640 "$CONF_DIR/bannix.toml"
    fi
    echo -e "${GREEN}✓ Created default config: ${CONF_DIR}/bannix.toml${NC}"
else
    echo -e "${YELLOW}ℹ Preserved existing config: ${CONF_DIR}/bannix.toml${NC}"
fi

# Install default jail drop-in ssh.toml
if [[ ! -f "$JAILS_DIR/ssh.toml" ]]; then
    if [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/config/jails.d/ssh.toml" ]]; then
        install -m 640 "$SCRIPT_DIR/config/jails.d/ssh.toml" "$JAILS_DIR/ssh.toml"
    else
        cat << 'EOF' > "$JAILS_DIR/ssh.toml"
enabled = true
log_path = "/var/log/auth.log"
mode = "inotify"
findtime = 600
maxretry = 5
bantime = 3600
patterns = [
    "Failed password for",
    "Invalid user",
    "authentication failure; logname=",
    "Connection closed by authenticating user"
]
EOF
        chmod 640 "$JAILS_DIR/ssh.toml"
    fi
    echo -e "${GREEN}✓ Created jail config: ${JAILS_DIR}/ssh.toml${NC}"
else
    echo -e "${YELLOW}ℹ Preserved existing jail config: ${JAILS_DIR}/ssh.toml${NC}"
fi

# Install nginx.toml if present
if [[ ! -f "$JAILS_DIR/nginx.toml" ]]; then
    if [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/config/jails.d/nginx.toml" ]]; then
        install -m 640 "$SCRIPT_DIR/config/jails.d/nginx.toml" "$JAILS_DIR/nginx.toml"
    else
        cat << 'EOF' > "$JAILS_DIR/nginx.toml"
enabled = false
log_path = "/var/log/nginx/error.log"
mode = "inotify"
findtime = 300
maxretry = 10
bantime = 1800
patterns = [
    "directory index of [^ ]* is forbidden",
    "access forbidden by rule"
]
EOF
        chmod 640 "$JAILS_DIR/nginx.toml"
    fi
fi

# Validate Configuration
echo -e "\n${BLUE}[3/4] Validating configuration...${NC}"
"$BIN_DIR/bannix" -c "$CONF_DIR/bannix.toml" --test-config

# 3. Setup and Enable Systemd Service
echo -e "\n${BLUE}[4/4] Setting up systemd service and starting bannix...${NC}"
install -d "$SYSTEMD_DIR"

if [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/systemd/bannix.service" ]]; then
    install -m 644 "$SCRIPT_DIR/systemd/bannix.service" "$SYSTEMD_DIR/bannix.service"
else
    cat << 'EOF' > "$SYSTEMD_DIR/bannix.service"
[Unit]
Description=bannix - Ultra-Lightweight Intrusion Prevention Daemon
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/bannix --config /etc/bannix/bannix.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=3
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectControlGroups=true
MemoryDenyWriteExecute=true
ReadWritePaths=/etc/bannix

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 "$SYSTEMD_DIR/bannix.service"
fi

systemctl daemon-reload
systemctl enable --now bannix

sleep 1
if systemctl is-active --quiet bannix; then
    echo -e "${GREEN}✓ bannix service successfully started and enabled on boot!${NC}"
else
    echo -e "${RED}⚠️ Warning: bannix service failed to start. Check 'journalctl -u bannix -n 50'.${NC}"
fi

echo -e "\n${GREEN}======================================================"
echo -e "       bannix INSTALLED & RUNNING SUCCESSFULLY!       "
echo -e "======================================================${NC}"
echo -e "Management Commands:"
echo -e "  • Check status     : ${BOLD}systemctl status bannix${NC}"
echo -e "  • Live attack logs : ${BOLD}journalctl -u bannix -f${NC}"
echo -e "  • Reload config    : ${BOLD}systemctl reload bannix${NC} (or kill -HUP \$(pidof bannix))"
echo -e "  • Test config      : ${BOLD}bannix --test-config${NC}"
echo -e "  • Check kernel set : ${BOLD}nft list set inet bannix_filter blacklist_v4${NC}"
echo -e "  • Uninstall        : ${BOLD}curl -sSL https://raw.githubusercontent.com/${GITHUB_REPO}/main/install.sh | sudo bash -s -- --uninstall${NC}"
echo -e "======================================================\n"
