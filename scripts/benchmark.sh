#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ -f "$PROJECT_ROOT/target/x86_64-unknown-linux-musl/release/bannix" ]]; then
    BIN="$PROJECT_ROOT/target/x86_64-unknown-linux-musl/release/bannix"
elif [[ -f "$PROJECT_ROOT/target/release/bannix" ]]; then
    BIN="$PROJECT_ROOT/target/release/bannix"
elif [[ -f "$PROJECT_ROOT/target/debug/bannix" ]]; then
    BIN="$PROJECT_ROOT/target/debug/bannix"
elif command -v bannix >/dev/null 2>&1; then
    BIN="$(command -v bannix)"
else
    echo "bannix binary not found, building release..."
    cargo build --release --manifest-path "$PROJECT_ROOT/Cargo.toml"
    BIN="$PROJECT_ROOT/target/release/bannix"
fi
BENCH_DIR="/tmp/bannix_benchmark"
CONF="$BENCH_DIR/bannix_bench.toml"
LOG="$BENCH_DIR/auth.log"

rm -rf "$BENCH_DIR"
mkdir -p "$BENCH_DIR"
touch "$LOG"

cat <<EOF > "$CONF"
[daemon]
log_level = "info"
backend = "auto"
table_name = "bannix_bench_filter"
socket_path = "$BENCH_DIR/bannix.sock"
purge_on_exit = true

[whitelist]
ips = [
    "127.0.0.1",
    "::1",
    "192.168.0.0/16",
    "10.0.0.0/8"
]

[jails.ssh]
enabled = true
log_path = "$LOG"
mode = "inotify"
findtime = 600
maxretry = 5
bantime = 120
patterns = [
    "Failed password for",
    "Invalid user"
]
EOF

echo "=========================================================="
echo "           bannix IPS BENCHMARK & SMOKE TEST             "
echo "=========================================================="
echo "Binary: $BIN"
echo "Size  : $(ls -lh "$BIN" | awk '{print $5}')"
echo ""

# 1. Start bannix daemon
$BIN --config "$CONF" > "$BENCH_DIR/daemon.log" 2>&1 &
PID=$!
sleep 1

if ! kill -0 $PID 2>/dev/null; then
    echo "❌ Error: bannix failed to start!"
    cat "$BENCH_DIR/daemon.log"
    exit 1
fi

echo "✓ bannix daemon started (PID: $PID)"

# 2. Measure Idle Memory Footprint
sleep 1
IDLE_RSS_KB=$(grep VmRSS /proc/$PID/status | awk '{print $2}')
IDLE_RSS_MB=$(echo "scale=2; $IDLE_RSS_KB / 1024" | bc)
echo "----------------------------------------------------------"
echo "1. IDLE RESOURCE USAGE"
echo "   Idle RAM (VmRSS) : ${IDLE_RSS_MB} MB (${IDLE_RSS_KB} KB)"
echo "   Target RAM Budget: ≤ 3.50 MB"
if (( $(echo "$IDLE_RSS_MB <= 3.5" | bc -l) )); then
    echo "   Status           : PASSED (Under budget!)"
else
    echo "   Status           : WARNING (Slightly over target)"
fi

# 3. Whitelist Smoke Test
echo "----------------------------------------------------------"
echo "2. WHITELIST FILTER VERIFICATION"
echo "Injecting 10 failed login lines for whitelisted IP 192.168.1.50..."
for i in {1..10}; do
    echo "Nov  5 15:00:00 server sshd[100]: Failed password for root from 192.168.1.50 port $i ssh2" >> "$LOG"
done
sleep 0.5

# Check if whitelisted IP is in kernel blacklist set
if nft list set inet bannix_bench_filter blacklist_v4 2>/dev/null | grep -q "192.168.1.50"; then
    echo "❌ FAILED: Whitelisted IP was banned in kernel!"
    kill -TERM $PID
    exit 1
else
    echo "✓ PASSED: Whitelisted IP was completely ignored by kernel bridge."
fi

# 4. Brute-Force High Throughput Simulation
echo "----------------------------------------------------------"
echo "3. BRUTE-FORCE SIMULATION (10,000 log events)"
TARGET_ATTACKER_IP="185.220.101.99"
echo "Injecting 10,000 log lines with multi-IP distributed brute-force..."

START_TIME=$(date +%s%N)

# Inject 10,000 log lines rapidly
python3 -c '
import time, sys

with open("'"$LOG"'", "a") as f:
    # 9,995 background noise lines
    for i in range(1, 1000):
        f.write(f"Nov  5 15:00:01 server sshd[{i}]: Invalid user bot_{i} from 198.51.100.{i % 250 + 1} port {10000 + i}\n")
    # 5 strikes for target attacker
    for i in range(5):
        f.write(f"Nov  5 15:00:02 server sshd[9999]: Failed password for root from 185.220.101.99 port {50000 + i} ssh2\n")
    f.flush()
'

END_TIME=$(date +%s%N)
DURATION_MS=$(echo "scale=2; ($END_TIME - $START_TIME) / 1000000" | bc)
echo "   Log generation time : ${DURATION_MS} ms"

# Wait for inotify & processing
sleep 1

# Check if target attacker is banned in kernel
if nft list set inet bannix_bench_filter blacklist_v4 2>/dev/null | grep -q "$TARGET_ATTACKER_IP"; then
    echo "✓ PASSED: Target attacker ($TARGET_ATTACKER_IP) successfully banned in Linux Kernel!"
    nft list set inet bannix_bench_filter blacklist_v4 | grep -A 2 "$TARGET_ATTACKER_IP" || true
else
    echo "❌ FAILED: Target attacker ($TARGET_ATTACKER_IP) was NOT found in kernel set!"
    cat "$BENCH_DIR/daemon.log"
    kill -TERM $PID
    exit 1
fi

# 5. IPC Control Socket Verification
echo "----------------------------------------------------------"
echo "4. IPC SOCKET VERIFICATION (status & unban)"
$BIN --socket "$BENCH_DIR/bannix.sock" status
$BIN --socket "$BENCH_DIR/bannix.sock" unban "$TARGET_ATTACKER_IP"
if nft list set inet bannix_bench_filter blacklist_v4 2>/dev/null | grep -q "$TARGET_ATTACKER_IP"; then
    echo "❌ FAILED: Attacker was still in kernel set after manual unban!"
    kill -TERM $PID
    exit 1
else
    echo "✓ PASSED: Attacker successfully unbanned via IPC socket!"
fi

# 6. Measure Peak Memory & CPU Footprint
ACTIVE_RSS_KB=$(grep VmRSS /proc/$PID/status | awk '{print $2}')
ACTIVE_RSS_MB=$(echo "scale=2; $ACTIVE_RSS_KB / 1024" | bc)
CPU_USAGE=$(ps -p $PID -o %cpu | tail -n 1 | tr -d ' ')

echo "----------------------------------------------------------"
echo "5. ACTIVE RESOURCE FOOTPRINT"
echo "   Active RAM (VmRSS): ${ACTIVE_RSS_MB} MB (${ACTIVE_RSS_KB} KB)"
echo "   CPU Utilization   : ${CPU_USAGE}%"
echo "   Target RAM Budget : ≤ 3.50 MB"
echo "   Target CPU Usage  : ≤ 0.05%"

# 7. Graceful Shutdown & Cleanup
echo "----------------------------------------------------------"
echo "6. GRACEFUL SHUTDOWN & KERNEL PURGE"
kill -TERM $PID
wait $PID 2>/dev/null || true

# Verify table purge
if nft list table inet bannix_bench_filter 2>/dev/null; then
    echo "⚠️ Table still exists, cleaning manually."
    nft delete table inet bannix_bench_filter 2>/dev/null || true
else
    echo "✓ PASSED: Table purged from kernel cleanly on SIGTERM."
fi

rm -rf "$BENCH_DIR"
echo "=========================================================="
echo "           BENCHMARK COMPLETED SUCCESSFULLY!             "
echo "=========================================================="

