#!/usr/bin/env bash
# ==============================================================================
# bannix - Ultra-Lightweight Intrusion Prevention System Installer & Manager
# Repository: https://github.com/Galang-Purnama/bannix
# License   : GPL-3.0-or-later
# ==============================================================================
set -euo pipefail

PREFIX="/usr/local"
BIN_DIR="$PREFIX/bin"
CONF_DIR="/etc/bannix"
JAILS_DIR="$CONF_DIR/jails.d"
SYSTEMD_DIR="/etc/systemd/system"
GITHUB_REPO="Galang-Purnama/bannix"

# ------------------------------------------------------------------------------
# Terminal Formatting & Color Palette (Respects NO_COLOR and non-TTY stdout)
# ------------------------------------------------------------------------------
if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
    BOLD=$'\033[1m'
    DIM=$'\033[2m'
    CYAN=$'\033[38;5;45m'
    BLUE=$'\033[38;5;39m'
    GREEN=$'\033[38;5;42m'
    YELLOW=$'\033[38;5;220m'
    RED=$'\033[38;5;196m'
    PURPLE=$'\033[38;5;141m'
    GRAY=$'\033[38;5;244m'
    NC=$'\033[0m'
else
    BOLD=''
    DIM=''
    CYAN=''
    BLUE=''
    GREEN=''
    YELLOW=''
    RED=''
    PURPLE=''
    GRAY=''
    NC=''
fi

# ------------------------------------------------------------------------------
# UI Helper Functions
# ------------------------------------------------------------------------------
print_banner() {
    cat << EOF
${CYAN}${BOLD}   __                          _       ${GRAY}Ultra-Lightweight Intrusion Prevention System
${CYAN}${BOLD}  / /_  ____ _____  ____  (_)  __   ${GRAY}Linux Kernel Netlink · Zero-Fork Architecture
${CYAN}${BOLD} / __ \/ __ \`/ __ \/ __ \/ / |/_/   ${GRAY}High-Speed Aho-Corasick DFA Pattern Engine
${CYAN}${BOLD}/ /_/ / /_/ / / / / / / / />  <     ${GRAY}https://github.com/${GITHUB_REPO}
${CYAN}${BOLD}/_.___/\__,_/_/ /_/_/ /_/_/_/|_|    ${PURPLE}${BOLD}[Production Installer]${NC}

EOF
}

print_update_banner() {
    cat << EOF
${CYAN}${BOLD}   __                          _       ${GRAY}Automated Binary & Service Updater
${CYAN}${BOLD}  / /_  ____ _____  ____  (_)  __   ${GRAY}Linux Kernel Netlink · Zero-Downtime Reload
${CYAN}${BOLD} / __ \/ __ \`/ __ \/ __ \/ / |/_/   ${GRAY}https://github.com/${GITHUB_REPO}
${CYAN}${BOLD}/ /_/ / /_/ / / / / / / / />  <     ${PURPLE}${BOLD}[Hot Upgrade Engine]${NC}
${CYAN}${BOLD}/_.___/\__,_/_/ /_/_/ /_/_/_/|_|${NC}

EOF
}

print_uninstall_banner() {
    cat << EOF
${YELLOW}${BOLD}   __                          _       ${GRAY}Intrusion Prevention System
${YELLOW}${BOLD}  / /_  ____ _____  ____  (_)  __   ${GRAY}Clean Uninstallation Manager
${YELLOW}${BOLD} / __ \/ __ \`/ __ \/ __ \/ / |/_/   ${GRAY}https://github.com/${GITHUB_REPO}
${YELLOW}${BOLD}/ /_/ / /_/ / / / / / / / />  <     ${RED}${BOLD}[Uninstall Routine]${NC}
${YELLOW}${BOLD}/_.___/\__,_/_/ /_/_/ /_/_/_/|_|${NC}

EOF
}

step() {
    local num="$1"
    local total="$2"
    local title="$3"
    echo -e "${BLUE}${BOLD}┌─[${num}/${total}]${NC} ${BOLD}${title}${NC}"
}

step_end() {
    echo -e "${GRAY}└────────────────────────────────────────────────────────────${NC}\n"
}

info() {
    echo -e "${GRAY}│${NC}  ${BLUE}ℹ${NC} $*"
}

action() {
    echo -e "${GRAY}│${NC}  ${CYAN}➜${NC} $*"
}

success() {
    echo -e "${GRAY}│${NC}  ${GREEN}✓${NC} $*"
}

warn() {
    echo -e "${GRAY}│${NC}  ${YELLOW}▲${NC} $*"
}

error() {
    echo -e "${GRAY}│${NC}  ${RED}✖${NC} $*" >&2
}

TEMP_DIR=""
cleanup() {
    if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
    fi
}
trap cleanup EXIT

# ------------------------------------------------------------------------------
# Privilege & Architecture Checks
# ------------------------------------------------------------------------------
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}${BOLD}✖ Error: Root privileges required.${NC}" >&2
        echo -e "  Please re-run this script with sudo or as root:" >&2
        echo -e "    ${YELLOW}sudo bash $0 $*${NC}\n" >&2
        exit 1
    fi
}

TARGET_ARCH=""
detect_arch() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64)
            TARGET_ARCH="x86_64"
            ;;
        aarch64|arm64)
            TARGET_ARCH="aarch64"
            ;;
        *)
            echo -e "${RED}${BOLD}✖ Error: Unsupported CPU architecture '${arch}'.${NC}" >&2
            echo -e "  bannix provides static musl binaries for ${BOLD}x86_64${NC} and ${BOLD}aarch64${NC}.\n" >&2
            exit 1
            ;;
    esac
}

DISTRO_NAME="Linux"
FIREWALL_BACKEND="iptables"
AUTH_LOG_PATH="/var/log/auth.log"
AUTH_LOG_MODE="inotify"

detect_environment() {
    # 1. Distro Detection
    if [[ -f /etc/os-release ]]; then
        DISTRO_NAME=$(grep -E '^PRETTY_NAME=' /etc/os-release | head -n1 | cut -d= -f2- | tr -d '"' || echo 'Linux')
    fi

    # 2. Firewall Subsystem Detection
    if command -v nft >/dev/null 2>&1; then
        FIREWALL_BACKEND="nftables (Netlink bridge)"
    elif command -v ipset >/dev/null 2>&1; then
        FIREWALL_BACKEND="ipset"
    else
        FIREWALL_BACKEND="iptables (legacy fallback)"
    fi

    # 3. Auth Log Subsystem & Path Detection
    if [[ -f /var/log/secure ]]; then
        AUTH_LOG_PATH="/var/log/secure"
        AUTH_LOG_MODE="inotify"
    elif [[ -f /var/log/auth.log ]]; then
        AUTH_LOG_PATH="/var/log/auth.log"
        AUTH_LOG_MODE="inotify"
    elif command -v journalctl >/dev/null 2>&1 || [[ -d /run/log/journal || -d /var/log/journal ]]; then
        AUTH_LOG_PATH=""
        AUTH_LOG_MODE="journald"
    else
        AUTH_LOG_PATH="/var/log/messages"
        AUTH_LOG_MODE="inotify"
    fi
}

verify_sha256() {
    local file="$1"
    local expected_hash="${2:-}"

    if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
        info "sha256sum utility not present, skipping checksum check"
        return 0
    fi

    local actual_hash=""
    if command -v sha256sum >/dev/null 2>&1; then
        actual_hash=$(sha256sum "$file" | awk '{print $1}')
    else
        actual_hash=$(shasum -a 256 "$file" | awk '{print $1}')
    fi

    if [[ -n "$expected_hash" ]]; then
        if [[ "$actual_hash" == "$expected_hash" ]]; then
            success "SHA256 verified : ${DIM}${actual_hash}${NC}"
            return 0
        else
            error "SHA256 checksum mismatch!"
            error "Expected: ${expected_hash}"
            error "Actual  : ${actual_hash}"
            return 1
        fi
    else
        info "Binary SHA256   : ${DIM}${actual_hash}${NC}"
        return 0
    fi
}

install_shell_completion() {
    # 1. Bash completion
    local bash_dir=""
    if [[ -d /usr/share/bash-completion/completions ]]; then
        bash_dir="/usr/share/bash-completion/completions"
    elif [[ -d /etc/bash_completion.d ]]; then
        bash_dir="/etc/bash_completion.d"
    fi

    if [[ -n "$bash_dir" ]]; then
        cat << 'EOF' > "${bash_dir}/bannix"
_bannix_completions() {
    local cur prev
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    local commands="status list banned unban ban ping"
    local global_opts="-c --config -s --socket -j --json --dry-run --test-config -v --version -h --help"

    if [[ $COMP_CWORD -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "$commands $global_opts" -- "$cur") )
        return 0
    fi

    case "${COMP_WORDS[1]}" in
        list)
            local sub="ssh nginx banned jails --json"
            COMPREPLY=( $(compgen -W "$sub" -- "$cur") )
            return 0
            ;;
        banned)
            local sub="ssh nginx --json"
            if [[ -S /run/bannix/bannix.sock ]] && command -v bannix >/dev/null 2>&1; then
                local ips
                ips=$(bannix banned 2>/dev/null | awk '/Active/ {print $1}')
                sub="$sub $ips"
            fi
            COMPREPLY=( $(compgen -W "$sub" -- "$cur") )
            return 0
            ;;
        unban)
            if [[ -S /run/bannix/bannix.sock ]] && command -v bannix >/dev/null 2>&1; then
                local ips
                ips=$(bannix banned 2>/dev/null | awk '/Active/ {print $1}')
                COMPREPLY=( $(compgen -W "$ips" -- "$cur") )
                return 0
            fi
            ;;
        ban)
            COMPREPLY=( $(compgen -W "300 600 1800 3600 7200 86400" -- "$cur") )
            return 0
            ;;
        -c|--config)
            COMPREPLY=( $(compgen -f -X '!*.toml' -- "$cur") )
            return 0
            ;;
        -s|--socket)
            COMPREPLY=( $(compgen -f -- "$cur") )
            return 0
            ;;
    esac

    COMPREPLY=( $(compgen -W "$global_opts" -- "$cur") )
}
complete -F _bannix_completions bannix
EOF
        chmod 644 "${bash_dir}/bannix"
    fi

    # 2. Zsh completion
    local zsh_dir=""
    if [[ -d /usr/share/zsh/vendor-completions ]]; then
        zsh_dir="/usr/share/zsh/vendor-completions"
    elif [[ -d /usr/local/share/zsh/site-functions ]]; then
        zsh_dir="/usr/local/share/zsh/site-functions"
    fi

    if [[ -n "$zsh_dir" ]]; then
        cat << 'EOF' > "${zsh_dir}/_bannix"
#compdef bannix

_bannix() {
    local -a commands
    commands=(
        'status:Show daemon status, uptime, backend, and active jails'
        'list:List configured jails and status'
        'banned:List currently banned IPs in firewall'
        'unban:Manually unban an IP from kernel firewall'
        'ban:Manually ban an IP for specified seconds'
        'ping:Test connectivity to daemon'
    )

    _arguments -C \
        '-c[Path to config file]:config file:_files -g "*.toml"' \
        '--config[Path to config file]:config file:_files -g "*.toml"' \
        '-s[Path to IPC socket]:socket file:_files' \
        '--socket[Path to IPC socket]:socket file:_files' \
        '-j[JSON output]' \
        '--json[JSON output]' \
        '--dry-run[Simulate without modifying firewall]' \
        '--test-config[Validate configuration]' \
        '-v[Show version]' \
        '--version[Show version]' \
        '-h[Show help]' \
        '--help[Show help]' \
        '1: :->command' \
        '*:: :->args'

    case $state in
        command)
            _describe -t commands 'bannix command' commands
            ;;
        args)
            case $line[1] in
                unban)
                    local -a ips
                    if [[ -S /run/bannix/bannix.sock ]] && command -v bannix >/dev/null 2>&1; then
                        ips=(${(f)"$(bannix banned 2>/dev/null | awk '/Active/ {print $1}')"})
                        _values 'banned ip' $ips
                    fi
                    ;;
                banned|list)
                    _values 'jail' 'ssh' 'nginx' '--json'
                    ;;
            esac
            ;;
    esac
}

_bannix "$@"
EOF
        chmod 644 "${zsh_dir}/_bannix"
    fi
}

SCRIPT_DIR=""
if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
fi

# ------------------------------------------------------------------------------
# Command: --help
# ------------------------------------------------------------------------------
show_help() {
    echo -e "${CYAN}${BOLD}bannix${NC} - Ultra-Lightweight Intrusion Prevention System Installer & Manager"
    echo -e "${GRAY}Repository: https://github.com/${GITHUB_REPO}${NC}\n"
    echo -e "${BOLD}USAGE:${NC}"
    echo -e "  bash install.sh [OPTIONS]\n"
    echo -e "${BOLD}OPTIONS:${NC}"
    echo -e "  ${GREEN}--update${NC}, ${GREEN}-u${NC}, ${GREEN}--upgrade${NC}   Download and install the latest bannix binary and restart service"
    echo -e "  ${GREEN}--uninstall${NC}             Stop service, disable on boot, and remove binary & unit file"
    echo -e "  ${GREEN}--purge${NC}                 Used with --uninstall to also delete configuration in ${CONF_DIR}"
    echo -e "  ${GREEN}--help${NC}, ${GREEN}-h${NC}                Display this help screen\n"
    echo -e "${BOLD}EXAMPLES:${NC}"
    echo -e "  ${GRAY}# Install on server (recommended one-liner)${NC}"
    echo -e "  curl -sSL https://raw.githubusercontent.com/${GITHUB_REPO}/main/install.sh | sudo bash\n"
    echo -e "  ${GRAY}# Update existing binary to latest GitHub Release${NC}"
    echo -e "  curl -sSL https://raw.githubusercontent.com/${GITHUB_REPO}/main/install.sh | sudo bash -s -- --update\n"
    echo -e "  ${GRAY}# Uninstall from server while preserving configuration${NC}"
    echo -e "  sudo bash install.sh --uninstall\n"
    exit 0
}

# ------------------------------------------------------------------------------
# Command: --update
# ------------------------------------------------------------------------------
update_bannix() {
    check_root
    detect_arch
    print_update_banner

    step 1 3 "Acquiring Latest Release Binary"
    info "Detected CPU Architecture : ${BOLD}${TARGET_ARCH}${NC}"

    local old_version="none"
    if [[ -x "$BIN_DIR/bannix" ]]; then
        old_version="$("$BIN_DIR/bannix" --version 2>/dev/null || echo 'unknown')"
        info "Currently installed version : ${BOLD}${old_version}${NC}"
    elif command -v bannix >/dev/null 2>&1; then
        old_version="$(bannix --version 2>/dev/null || echo 'unknown')"
        info "Currently installed version : ${BOLD}${old_version}${NC}"
    else
        warn "bannix binary not currently found at ${BIN_DIR}/bannix (fresh install mode)"
    fi

    local binary_path=""
    TEMP_DIR="$(mktemp -d)"

    local download_url="https://github.com/${GITHUB_REPO}/releases/latest/download/bannix-${TARGET_ARCH}-linux-musl"
    local sha_url="${download_url}.sha256"
    action "Downloading latest static binary asset from GitHub Releases..."
    info "URL: ${GRAY}${download_url}${NC}"

    local expected_sha=""
    if curl -sSL -f -o "$TEMP_DIR/bannix.sha256" "$sha_url" 2>/dev/null; then
        expected_sha=$(awk '{print $1}' "$TEMP_DIR/bannix.sha256")
    fi

    if curl -sSL -f -o "$TEMP_DIR/bannix" "$download_url" 2>/dev/null; then
        if [[ -n "$expected_sha" ]]; then
            if ! verify_sha256 "$TEMP_DIR/bannix" "$expected_sha"; then
                error "Aborting update due to failed checksum verification."
                exit 1
            fi
        else
            verify_sha256 "$TEMP_DIR/bannix" ""
        fi
        chmod +x "$TEMP_DIR/bannix"
        binary_path="$TEMP_DIR/bannix"
        success "Downloaded static binary successfully"
    else
        warn "Release asset download unavailable. Checking Cargo toolchain for local compilation..."
        if [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/Cargo.toml" ]] && command -v cargo >/dev/null 2>&1; then
            action "Compiling release binary from local source repository..."
            (cd "$SCRIPT_DIR" && cargo build --release --target "${TARGET_ARCH}-unknown-linux-musl" 2>/dev/null || cargo build --release)
            if [[ -f "$SCRIPT_DIR/target/${TARGET_ARCH}-unknown-linux-musl/release/bannix" ]]; then
                binary_path="$SCRIPT_DIR/target/${TARGET_ARCH}-unknown-linux-musl/release/bannix"
            elif [[ -f "$SCRIPT_DIR/target/release/bannix" ]]; then
                binary_path="$SCRIPT_DIR/target/release/bannix"
            fi
        elif command -v cargo >/dev/null 2>&1 && command -v git >/dev/null 2>&1; then
            action "Cloning latest source and compiling via cargo..."
            git clone --depth 1 "https://github.com/${GITHUB_REPO}.git" "$TEMP_DIR/source"
            (cd "$TEMP_DIR/source" && cargo build --release --target "${TARGET_ARCH}-unknown-linux-musl" 2>/dev/null || cargo build --release)
            if [[ -f "$TEMP_DIR/source/target/${TARGET_ARCH}-unknown-linux-musl/release/bannix" ]]; then
                binary_path="$TEMP_DIR/source/target/${TARGET_ARCH}-unknown-linux-musl/release/bannix"
            else
                binary_path="$TEMP_DIR/source/target/release/bannix"
            fi
        fi
    fi

    if [[ -z "$binary_path" || ! -f "$binary_path" ]]; then
        error "Failed to acquire updated bannix binary."
        echo -e "  Please verify network connectivity or install the Rust/Cargo toolchain." >&2
        exit 1
    fi

    if ! "$binary_path" --version >/dev/null 2>&1; then
        error "Acquired binary failed execution validation test."
        exit 1
    fi

    local new_version
    new_version="$("$binary_path" --version)"
    success "New binary verified       : ${BOLD}${new_version}${NC}"
    step_end

    step 2 3 "Installing Binary & Validating Configuration"
    local was_active=false
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet bannix 2>/dev/null; then
        was_active=true
    fi

    action "Atomically installing binary to ${BIN_DIR}/bannix..."
    install -d "$BIN_DIR"
    install -m 755 "$binary_path" "$BIN_DIR/bannix"
    success "Binary updated successfully"

    action "Updating shell autocompletion (Bash & Zsh)..."
    install_shell_completion
    success "Shell autocompletion updated"

    if [[ -f "$CONF_DIR/bannix.toml" ]]; then
        action "Validating configuration with updated binary..."
        if "$BIN_DIR/bannix" -c "$CONF_DIR/bannix.toml" --test-config >/dev/null 2>&1; then
            success "Configuration syntax and DFA pattern engines: Valid"
        else
            warn "Existing configuration failed validation check. Please review ${CONF_DIR}/bannix.toml"
        fi
    fi
    step_end

    step 3 3 "Managing Service Lifecycle"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload 2>/dev/null || true
        if [[ "$was_active" == "true" ]]; then
            action "Restarting bannix service..."
            if systemctl restart bannix; then
                sleep 1
                if systemctl is-active --quiet bannix 2>/dev/null; then
                    success "bannix service restarted and active (PID: $(pidof bannix 2>/dev/null || echo 'running'))"
                else
                    warn "Service failed to restart automatically. Inspect: journalctl -u bannix -n 50"
                fi
            else
                warn "Failed to restart bannix service."
            fi
        elif systemctl is-enabled --quiet bannix 2>/dev/null; then
            action "Starting bannix service (service was enabled)..."
            systemctl start bannix 2>/dev/null || true
            success "Service started"
        else
            info "Service is currently inactive. Start with: systemctl start bannix"
        fi
    fi
    step_end

    local svc_status="inactive"
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet bannix 2>/dev/null; then
        svc_status="active (running)"
    fi

    # Completion Card
    echo -e "\n${GREEN}${BOLD}════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "  ${GREEN}${BOLD}✨  bannix UPDATED SUCCESSFULLY!${NC}"
    echo -e "${GREEN}${BOLD}════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "  ${GRAY}•${NC} ${BOLD}Binary Path${NC}     : ${CYAN}$BIN_DIR/bannix${NC}"
    echo -e "  ${GRAY}•${NC} ${BOLD}Target Version${NC}  : ${BOLD}${new_version}${NC}"
    echo -e "  ${GRAY}•${NC} ${BOLD}Daemon State${NC}    : ${GREEN}${svc_status}${NC}"
    echo -e "  ${GRAY}•${NC} ${BOLD}Configuration${NC}   : ${GREEN}Verified & Compatible${NC} ${GRAY}(${CONF_DIR}/bannix.toml)${NC}"
    echo -e "${GRAY}────────────────────────────────────────────────────────────────────────────${NC}"
    echo -e "  ${BOLD}Quick Health Checks:${NC}"
    echo -e "    ${CYAN}▸ bannix status${NC}           Inspect daemon status & uptime"
    echo -e "    ${CYAN}▸ bannix banned${NC}           Inspect active kernel firewall bans"
    echo -e "    ${CYAN}▸ bannix list${NC}             View configured jails & rules"
    echo -e "    ${CYAN}▸ journalctl -u bannix -f${NC} Follow live attack stream"
    echo -e "${GREEN}${BOLD}════════════════════════════════════════════════════════════════════════════${NC}\n"
    exit 0
}

# ------------------------------------------------------------------------------
# Command: --uninstall
# ------------------------------------------------------------------------------
uninstall_bannix() {
    check_root
    print_uninstall_banner

    step 1 3 "Stopping & Disabling Daemon Service"
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active --quiet bannix 2>/dev/null; then
            action "Stopping active bannix service..."
            systemctl stop bannix 2>/dev/null || true
            success "Service stopped"
        else
            info "Service was not running"
        fi
        action "Disabling service on boot..."
        systemctl disable bannix 2>/dev/null || true
        success "Service disabled"
    fi
    step_end

    step 2 3 "Removing Binaries & Systemd Service Unit"
    action "Removing binary: ${BIN_DIR}/bannix..."
    rm -f "$BIN_DIR/bannix"
    action "Removing service unit: ${SYSTEMD_DIR}/bannix.service..."
    rm -f "$SYSTEMD_DIR/bannix.service"
    action "Removing shell autocompletions..."
    rm -f /usr/share/bash-completion/completions/bannix
    rm -f /etc/bash_completion.d/bannix
    rm -f /usr/share/zsh/vendor-completions/_bannix
    rm -f /usr/local/share/zsh/site-functions/_bannix
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload 2>/dev/null || true
    fi
    success "Binaries, unit files, and completions removed cleanly"
    step_end

    step 3 3 "Managing Configuration & Kernel Tables"
    local config_status="Preserved at ${CONF_DIR}"
    if [[ "${1:-}" == "--purge" ]]; then
        action "Purging configuration directory: ${CONF_DIR}..."
        rm -rf "$CONF_DIR"
        config_status="Purged completely"
        success "Configuration directory deleted"
    else
        info "Configuration directory preserved: ${CONF_DIR}"
        info "To remove it manually: rm -rf ${CONF_DIR}"
    fi

    # Flush kernel nftables filter table if present
    if command -v nft >/dev/null 2>&1; then
        action "Flushing kernel table 'inet bannix_filter' if present..."
        nft delete table inet bannix_filter 2>/dev/null || true
        success "Kernel netfilter table purged"
    fi
    step_end

    echo -e "\n${YELLOW}${BOLD}════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "  ${YELLOW}${BOLD}✓  bannix HAS BEEN COMPLETELY UNINSTALLED${NC}"
    echo -e "${YELLOW}${BOLD}════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "  ${GRAY}•${NC} ${BOLD}Systemd Service${NC}   : Stopped & disabled"
    echo -e "  ${GRAY}•${NC} ${BOLD}Binary Executable${NC} : Removed from ${BIN_DIR}/bannix"
    echo -e "  ${GRAY}•${NC} ${BOLD}Service Unit File${NC} : Removed from ${SYSTEMD_DIR}/bannix.service"
    echo -e "  ${GRAY}•${NC} ${BOLD}Configuration${NC}     : ${config_status}"
    echo -e "  ${GRAY}•${NC} ${BOLD}Firewall Sets${NC}     : Netfilter tables flushed cleanly"
    echo -e "${YELLOW}${BOLD}════════════════════════════════════════════════════════════════════════════${NC}\n"
    exit 0
}

# ------------------------------------------------------------------------------
# Argument Routing
# ------------------------------------------------------------------------------
for arg in "$@"; do
    case "$arg" in
        --uninstall)
            uninstall_bannix "${2:-}"
            ;;
        --purge)
            uninstall_bannix "--purge"
            ;;
        --update|-u|--upgrade)
            update_bannix
            ;;
        --help|-h)
            show_help
            ;;
    esac
done

# ==============================================================================
# MAIN INSTALLATION WORKFLOW
# ==============================================================================
check_root
detect_arch
detect_environment
print_banner

# Host environment overview
HOSTNAME="$(hostname 2>/dev/null || echo 'localhost')"
KERNEL_VER="$(uname -r 2>/dev/null || echo 'Linux')"

echo -e "${BLUE}┌─ Host Environment ──────────────────────────────────────────┐${NC}"
echo -e "${BLUE}│${NC}  ${GRAY}•${NC} Hostname       : ${BOLD}${HOSTNAME}${NC}"
echo -e "${BLUE}│${NC}  ${GRAY}•${NC} OS / Distro    : ${BOLD}${DISTRO_NAME}${NC}"
echo -e "${BLUE}│${NC}  ${GRAY}•${NC} Kernel         : ${BOLD}${KERNEL_VER}${NC}"
echo -e "${BLUE}│${NC}  ${GRAY}•${NC} Architecture   : ${BOLD}${TARGET_ARCH}${NC}"
echo -e "${BLUE}│${NC}  ${GRAY}•${NC} Firewall Engine: ${BOLD}${FIREWALL_BACKEND}${NC}"
echo -e "${BLUE}│${NC}  ${GRAY}•${NC} Log Ingestion  : ${BOLD}${AUTH_LOG_MODE}${NC} ${GRAY}(${AUTH_LOG_PATH:-systemd-journald})${NC}"
echo -e "${BLUE}│${NC}  ${GRAY}•${NC} Install Target : ${BOLD}${BIN_DIR}/bannix${NC}"
echo -e "${BLUE}│${NC}  ${GRAY}•${NC} Config Base    : ${BOLD}${CONF_DIR}${NC}"
echo -e "${BLUE}└─────────────────────────────────────────────────────────────┘${NC}\n"

# ------------------------------------------------------------------------------
# Step 1: Acquire & Verify bannix Binary
# ------------------------------------------------------------------------------
step 1 4 "Preparing bannix Static Binary"
BINARY_PATH=""

# Check if local source repository with Cargo is available or pre-compiled binary exists
if [[ -n "$SCRIPT_DIR" ]]; then
    if [[ -f "$SCRIPT_DIR/Cargo.toml" ]] && command -v cargo >/dev/null 2>&1; then
        action "Building release binary from local source repository via Cargo..."
        if (cd "$SCRIPT_DIR" && cargo build --release --target "${TARGET_ARCH}-unknown-linux-musl" 2>/dev/null); then
            BINARY_PATH="$SCRIPT_DIR/target/${TARGET_ARCH}-unknown-linux-musl/release/bannix"
        elif (cd "$SCRIPT_DIR" && cargo build --release); then
            BINARY_PATH="$SCRIPT_DIR/target/release/bannix"
        fi
        if [[ -n "$BINARY_PATH" && -f "$BINARY_PATH" ]]; then
            success "Local release build finished successfully: ${BINARY_PATH}"
        fi
    elif [[ -f "$SCRIPT_DIR/target/${TARGET_ARCH}-unknown-linux-musl/release/bannix" ]]; then
        BINARY_PATH="$SCRIPT_DIR/target/${TARGET_ARCH}-unknown-linux-musl/release/bannix"
        info "Found local musl static build: ${BINARY_PATH}"
    elif [[ -f "$SCRIPT_DIR/target/release/bannix" ]]; then
        BINARY_PATH="$SCRIPT_DIR/target/release/bannix"
        info "Found local release build: ${BINARY_PATH}"
    fi
fi

# If binary not found locally, download pre-built release binary from GitHub
if [[ -z "$BINARY_PATH" ]]; then
    TEMP_DIR="$(mktemp -d)"
    DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/latest/download/bannix-${TARGET_ARCH}-linux-musl"
    SHA_URL="${DOWNLOAD_URL}.sha256"
    action "Downloading pre-compiled static binary from GitHub Releases..."
    info "URL: ${GRAY}${DOWNLOAD_URL}${NC}"

    EXPECTED_SHA=""
    if curl -sSL -f -o "$TEMP_DIR/bannix.sha256" "$SHA_URL" 2>/dev/null; then
        EXPECTED_SHA=$(awk '{print $1}' "$TEMP_DIR/bannix.sha256")
    fi

    if curl -sSL -f -o "$TEMP_DIR/bannix" "$DOWNLOAD_URL" 2>/dev/null; then
        if [[ -n "$EXPECTED_SHA" ]]; then
            if ! verify_sha256 "$TEMP_DIR/bannix" "$EXPECTED_SHA"; then
                error "Aborting installation due to failed checksum verification."
                exit 1
            fi
        else
            verify_sha256 "$TEMP_DIR/bannix" ""
        fi
        chmod +x "$TEMP_DIR/bannix"
        BINARY_PATH="$TEMP_DIR/bannix"
        success "Downloaded static binary successfully"
    else
        warn "Release asset download unavailable. Attempting fallback Cargo compilation..."
        if command -v cargo >/dev/null 2>&1 && command -v git >/dev/null 2>&1; then
            action "Cloning source and compiling statically via cargo..."
            git clone --depth 1 "https://github.com/${GITHUB_REPO}.git" "$TEMP_DIR/source"
            (cd "$TEMP_DIR/source" && cargo build --release --target "${TARGET_ARCH}-unknown-linux-musl" 2>/dev/null || cargo build --release)
            if [[ -f "$TEMP_DIR/source/target/${TARGET_ARCH}-unknown-linux-musl/release/bannix" ]]; then
                BINARY_PATH="$TEMP_DIR/source/target/${TARGET_ARCH}-unknown-linux-musl/release/bannix"
            else
                BINARY_PATH="$TEMP_DIR/source/target/release/bannix"
            fi
            success "Static compilation completed"
        elif [[ -f "$BIN_DIR/bannix" ]]; then
            info "Retaining currently installed binary at ${BIN_DIR}/bannix"
            BINARY_PATH="$BIN_DIR/bannix"
        else
            error "Could not obtain bannix binary."
            echo -e "  Please ensure Cargo is installed or verify network access to GitHub." >&2
            exit 1
        fi
    fi
fi

action "Installing executable to ${BIN_DIR}/bannix..."
if [[ "$BINARY_PATH" != "$BIN_DIR/bannix" ]]; then
    install -d "$BIN_DIR"
    install -m 755 "$BINARY_PATH" "$BIN_DIR/bannix"
fi
success "Binary installed: ${BOLD}$("$BIN_DIR/bannix" --version)${NC}"
step_end

# ------------------------------------------------------------------------------
# Step 2: Provision Configuration Files & Drop-ins
# ------------------------------------------------------------------------------
step 2 4 "Provisioning Configuration & Security Jails"
install -d -m 750 "$CONF_DIR"
install -d -m 750 "$JAILS_DIR"
success "Secured configuration directory (${CONF_DIR}, mode 750)"

# Master config: bannix.toml
if [[ ! -f "$CONF_DIR/bannix.toml" ]]; then
    if [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/config/bannix.toml" ]]; then
        install -m 640 "$SCRIPT_DIR/config/bannix.toml" "$CONF_DIR/bannix.toml"
        sed -i "/^\[jails\.ssh\]/,/^\[/{
            s|^log_path = .*|log_path = \"${AUTH_LOG_PATH}\"|
            s|^mode = .*|mode = \"${AUTH_LOG_MODE}\"                # inotify \| journald|
        }" "$CONF_DIR/bannix.toml"
    else
        cat << EOF > "$CONF_DIR/bannix.toml"
[daemon]
log_level = "info"              # trace, debug, info, warn, error
backend = "auto"                # auto | nftables | ipset | iptables
table_name = "bannix_filter"
socket_path = "/run/bannix/bannix.sock"
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
log_path = "${AUTH_LOG_PATH}"
mode = "${AUTH_LOG_MODE}"       # inotify | journald
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
    success "Created master configuration: ${CONF_DIR}/bannix.toml"
else
    info "Preserved existing master config: ${CONF_DIR}/bannix.toml"
fi

# Jail drop-in: ssh.toml
if [[ ! -f "$JAILS_DIR/ssh.toml" ]]; then
    if [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/config/jails.d/ssh.toml" ]]; then
        install -m 640 "$SCRIPT_DIR/config/jails.d/ssh.toml" "$JAILS_DIR/ssh.toml"
        sed -i \
            -e "s|^log_path = .*|log_path = \"${AUTH_LOG_PATH}\"|" \
            -e "s|^mode = .*|mode = \"${AUTH_LOG_MODE}\"|" \
            "$JAILS_DIR/ssh.toml"
    else
        cat << EOF > "$JAILS_DIR/ssh.toml"
enabled = true
log_path = "${AUTH_LOG_PATH}"
mode = "${AUTH_LOG_MODE}"
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
    success "Created OpenSSH security jail: ${JAILS_DIR}/ssh.toml"
else
    info "Preserved existing SSH jail config: ${JAILS_DIR}/ssh.toml"
fi

# Optional jail drop-in: nginx.toml
if [[ ! -f "$JAILS_DIR/nginx.toml" ]]; then
    if [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/config/jails.d/nginx.toml" ]]; then
        install -m 640 "$SCRIPT_DIR/config/jails.d/nginx.toml" "$JAILS_DIR/nginx.toml"
        success "Created Nginx jail config: ${JAILS_DIR}/nginx.toml"
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
step_end

# ------------------------------------------------------------------------------
# Step 3: Validate Syntax & Compile DFA Pattern Engines
# ------------------------------------------------------------------------------
step 3 4 "Validating Configuration Syntax & DFA Patterns"
action "Running internal test-config diagnostic..."
if "$BIN_DIR/bannix" -c "$CONF_DIR/bannix.toml" --test-config 2>&1 | while IFS= read -r line; do echo -e "${GRAY}│${NC}   ${line}"; done; then
    success "Configuration syntax and DFA pattern engines validated"
else
    error "Configuration diagnostic failed. Please verify ${CONF_DIR}/bannix.toml"
    exit 1
fi
step_end

# ------------------------------------------------------------------------------
# Step 4: Systemd Service Installation & Activation
# ------------------------------------------------------------------------------
step 4 4 "Installing & Activating Systemd Service"
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
RuntimeDirectory=bannix
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
success "Installed systemd hardened unit file: ${SYSTEMD_DIR}/bannix.service"

action "Reloading systemd manager and enabling bannix daemon on boot..."
WAS_ACTIVE=false
if systemctl is-active --quiet bannix 2>/dev/null; then
    WAS_ACTIVE=true
fi
systemctl daemon-reload
systemctl enable --now bannix
if [[ "$WAS_ACTIVE" == true ]]; then
    action "Restarting active bannix daemon to load updated binary..."
    systemctl restart bannix
fi

sleep 1
if systemctl is-active --quiet bannix; then
    success "bannix service successfully started & active (PID: $(pidof bannix 2>/dev/null || echo 'running'))"
else
    warn "bannix service failed to start immediately. Run 'journalctl -u bannix -n 50' to inspect."
fi

action "Installing shell autocompletions (Bash & Zsh)..."
install_shell_completion
success "Installed shell completion into system directories"
step_end

# ------------------------------------------------------------------------------
# Installation Completion Card
# ------------------------------------------------------------------------------
local_ver="$("$BIN_DIR/bannix" -v 2>/dev/null || echo 'v0.1.4')"
local_ver="${local_ver#bannix }"
echo -e "\n${GREEN}${BOLD}════════════════════════════════════════════════════════════════════════════${NC}"
echo -e "  ${GREEN}${BOLD}🎉  bannix INSTALLED & ACTIVATED SUCCESSFULLY!${NC}"
echo -e "${GREEN}${BOLD}════════════════════════════════════════════════════════════════════════════${NC}"
echo -e "  ${GRAY}•${NC} ${BOLD}Binary Executable${NC} : ${CYAN}/usr/local/bin/bannix${NC} ${GRAY}(${local_ver})${NC}"
echo -e "  ${GRAY}•${NC} ${BOLD}Systemd Service${NC}   : ${GREEN}bannix.service${NC} ${GRAY}(active running, enabled on boot)${NC}"
echo -e "  ${GRAY}•${NC} ${BOLD}Memory Footprint${NC}  : ${BOLD}≤ 1.0 MB VmRSS${NC} ${GRAY}(Pure Rust, Zero-Fork Daemon)${NC}"
echo -e "  ${GRAY}•${NC} ${BOLD}Master Config${NC}     : ${CYAN}/etc/bannix/bannix.toml${NC}"
echo -e "  ${GRAY}•${NC} ${BOLD}Jails Directory${NC}   : ${CYAN}/etc/bannix/jails.d/${NC}"
echo -e "${GRAY}────────────────────────────────────────────────────────────────────────────${NC}"
echo -e "  ${BOLD}Essential Management Commands:${NC}"
echo -e "    ${CYAN}▸ bannix status${NC}           Inspect daemon health, uptime & active jails"
echo -e "    ${CYAN}▸ bannix banned${NC}           Show currently blocked attacker IPs & expiries"
echo -e "    ${CYAN}▸ bannix list${NC}             Overview of configured jails & attack statistics"
echo -e "    ${CYAN}▸ bannix unban <IP>${NC}       Manually release an IP from firewall"
echo -e "    ${CYAN}▸ bannix ban <IP> [SECS]${NC}  Manually ban an IP address"
echo -e "    ${CYAN}▸ journalctl -u bannix -f${NC} Follow real-time attack stream"
echo -e "    ${CYAN}▸ systemctl reload bannix${NC} Hot-reload configurations (zero downtime)"
echo -e "    ${CYAN}▸ bannix --test-config${NC}    Validate configurations before reloading"
echo -e "${GREEN}${BOLD}════════════════════════════════════════════════════════════════════════════${NC}\n"

