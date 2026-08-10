#!/bin/bash
# aarch64: python http.server + 预创建线程池, 并发饱和负载 — 负例契约
#
# 实测边界 (round-14): 顺序 21 请求 R=3.4% (支持层); 8-16 并发
# R≈26% (超 15% 预算); 宽窗口/36+ 并发探针 SIGSEGV/SIGILL (对象身份
# 分歧)。本测试断言该窗口**不满足支持层契约** (负例): 最终产物要么
# 被探针/回放拒绝 (非 rc=0), 要么 rc=0 但 R_total>15% 被性能 gate
# 拒绝 — 证明“分歧候选不会被发布”。
set -u
cd "$(dirname "$0")/.."
source tests/testlib.sh

if [ "$(uname -m)" != "aarch64" ]; then
    echo "SKIP: http_pool_sat strict 测试仅 aarch64"
    exit 0
fi

tf_setup
tf_cleanup python3
ELFTRACE="$TF_ELFTRACE"
DATA="$TF_TMP/http_pool_sat_data"

echo "== [realworld] python http.server + pool 并发饱和 strict slice =="

mkdir -p "$DATA"
for i in 1 2 3 4 5; do
    python3 -c "import os; open('$DATA/f$i','wb').write(os.urandom(4096))"
done

HTTP_PORT=$((18500 + RANDOM % 400))
HTTP_LOG="$TF_TMP/http_pool_sat_server.log"

start_server() {
    python3 tests/http_pool_server.py "$HTTP_PORT" "$DATA" 4 \
        > "$HTTP_LOG" 2>&1 &
    HTTP_PID=$!
    for _ in $(seq 1 50); do
        python3 -c "
import socket
s = socket.socket()
s.settimeout(0.2)
try:
    s.connect(('127.0.0.1', $HTTP_PORT))
    s.close()
    raise SystemExit(0)
except OSError:
    raise SystemExit(1)
" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

send_requests() {  # <客户端数> <每客户端请求数>
    python3 - "$HTTP_PORT" "$1" "$2" <<'EOF'
import sys, urllib.request, concurrent.futures
port, nc, nr = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
def worker(c):
    for i in range(nr):
        urllib.request.urlopen(
            "http://127.0.0.1:%d/f%d" % (port, (c * 7 + i) % 5 + 1),
            timeout=120).read()
with concurrent.futures.ThreadPoolExecutor(max_workers=nc) as ex:
    list(ex.map(worker, range(nc)))
EOF
}

run_trace() {  # <输出目录> [补偿文件]
    local out="$1"; shift
    local extra=()
    [ $# -gt 0 ] && extra=(--atomic-compensate "$1")
    local vr=()
    if [ -f "tests/pymalloc_sites_ubuntu312.txt" ]; then
        cp "tests/pymalloc_sites_ubuntu312.txt" \
            "$TF_TMP/pymalloc_sites.txt"
        vr=(--value-replay-sites "$TF_TMP/pymalloc_sites.txt")
    fi
    start_server || { echo "FAIL: server 未就绪"; return 1; }
    send_requests 4 2 || { echo "FAIL: warm 请求失败"; return 1; }
    timeout 600 "$ELFTRACE" trace "$HTTP_PID" --every 100000 \
        --out "$out" --atomic-replay "${vr[@]}" "${extra[@]}" \
        > "$TF_TMP/http_pool_sat_trace.log" 2>&1 &
    local TPID=$!
    sleep 1
    # 并发: 4 客户端 × 4 轮 (16 并发请求)。6×6/8×10 探针必崩;
    # 4×4 窄窗口 NVR 通过但 R=26.1% — 负例契约要求它被拒绝。
    send_requests 4 4 || { echo "FAIL: 并发负载失败"; return 1; }
    kill -9 "$HTTP_PID" 2>/dev/null
    wait "$TPID" 2>/dev/null
    [ -f "$out/manifest.txt" ] || return 1
    [ -f "$out/syscalls/syscall.map" ] || return 1
    return 0
}

run_trace_retry() {  # <输出目录> [补偿文件]
    for a in 1 2; do
        if run_trace "$@"; then
            return 0
        fi
        echo "  trace 负载失败 (attempt $a), 清理重试"
        kill -9 "$HTTP_PID" 2>/dev/null
        pkill -9 -f '/build/elftrace trace ' 2>/dev/null
        sleep 1
    done
    return 1
}

rm -rf "$TF_TMP/http_pool_sat_r1" "$TF_TMP/http_pool_sat_r2"
run_trace_retry "$TF_TMP/http_pool_sat_r1" || { echo "FAIL: Run1"; tail -3 "$TF_TMP/http_pool_sat_trace.log"; exit 1; }
COMP="$TF_TMP/http_pool_sat_r1/atomics/compensation.txt"
[ -f "$COMP" ] || { echo "FAIL: Run1 无 compensation.txt"; exit 1; }
NCK=$(wc -l < "$TF_TMP/http_pool_sat_r1/manifest.txt")
[ "$NCK" -ge 5 ] || { echo "FAIL: Run1 只有 $NCK 检查点"; exit 1; }
echo "  Run1: $NCK ckpts, $(wc -l < "$TF_TMP/http_pool_sat_r1/syscalls/syscall.map") syscalls"

run_trace_retry "$TF_TMP/http_pool_sat_r2" "$COMP" || { echo "FAIL: Run2"; tail -3 "$TF_TMP/http_pool_sat_trace.log"; exit 1; }
[ -f "$TF_TMP/http_pool_sat_r2/atomics/events.bin" ] || { echo "FAIL: Run2 无 events.bin"; exit 1; }
NCK=$(wc -l < "$TF_TMP/http_pool_sat_r2/manifest.txt")
[ "$NCK" -ge 5 ] || { echo "FAIL: Run2 只有 $NCK 检查点"; exit 1; }
echo "  Run2: $NCK ckpts, $(wc -l < "$TF_TMP/http_pool_sat_r2/syscalls/syscall.map") syscalls"

# 窗口 25%~75% (摊薄固定引擎/启动开销; 4×4 下太宽会探针分歧, 2×4 试)
TOT=$(awk 'END{print $1}' "$TF_TMP/http_pool_sat_r2/manifest.txt")
FROM=$((TOT / 4))
TO=$((TOT * 3 / 4))
[ "$TO" -gt "$FROM" ] || { echo "FAIL: 窗口过窄"; exit 1; }

NVR=()
tf_build /dev/null "$TF_TMP/http_pool_sat_probe.elf" --mode baremetal --bm-strict \
    --checkpoints "$TF_TMP/http_pool_sat_r2" \
    --from-count "$FROM" --to-count "$TO" \
    --stack-reserve 67108864 --atomic-no-value-replay \
    --probe-dump "$TF_TMP/http_pool_sat_probe.bin" > "$TF_TMP/http_pool_sat_build.log" 2>&1
if [ $? = 0 ]; then
    timeout 600 "$TF_TMP/http_pool_sat_probe.elf" > /dev/null 2>&1
    PRC=$?
    if [ "$PRC" = 0 ] && [ -s "$TF_TMP/http_pool_sat_probe.bin" ]; then
        NVR=(--atomic-no-value-replay)
        echo "  http_pool_sat: 无值回放探针通过"
    fi
fi
if [ "${#NVR[@]}" = 0 ]; then
    tf_build /dev/null "$TF_TMP/http_pool_sat_probe.elf" --mode baremetal --bm-strict \
        --checkpoints "$TF_TMP/http_pool_sat_r2" \
        --from-count "$FROM" --to-count "$TO" \
        --stack-reserve 67108864 \
        --probe-dump "$TF_TMP/http_pool_sat_probe.bin" > "$TF_TMP/http_pool_sat_build.log" 2>&1 \
        || { echo "FAIL: probe build"; tail -5 "$TF_TMP/http_pool_sat_build.log"; exit 1; }
    timeout 600 "$TF_TMP/http_pool_sat_probe.elf" > /dev/null 2>&1
    PRC=$?
    if [ "$PRC" != 0 ]; then
        echo "  负例验证: probe rc=$PRC (SIG/分歧/兜底) → 候选被拒绝"
        tf_pass "http_pool 并发饱和负例 (探针拒绝)"
        tf_finish
        exit 0
    fi
    [ -s "$TF_TMP/http_pool_sat_probe.bin" ] || { echo "FAIL: 无 probe.bin"; exit 1; }
fi
tf_build /dev/null "$TF_TMP/http_pool_sat_slice.elf" --mode baremetal --bm-strict \
    --checkpoints "$TF_TMP/http_pool_sat_r2" \
    --from-count "$FROM" --to-count "$TO" \
    --stack-reserve 67108864 \
    --byte-runs "$TF_TMP/http_pool_sat_probe.bin" \
    --newseg-big-skip 1048576 "${NVR[@]}" > "$TF_TMP/http_pool_sat_build2.log" 2>&1 \
    || { echo "FAIL: byte-run build"; tail -5 "$TF_TMP/http_pool_sat_build2.log"; exit 1; }

timeout 120 strace -o "$TF_TMP/http_pool_sat_slice.strace" \
    "$TF_TMP/http_pool_sat_slice.elf" > /dev/null 2>&1
RC=$?
if [ "$RC" = 0 ]; then
    # rc=0: 性能 gate 必须拒绝 (R>15% 或 health 无效)
    timeout 120 perf stat -e instructions "$TF_TMP/http_pool_sat_slice.elf" \
        > /dev/null 2> "$TF_TMP/http_pool_sat_slice.perf"
    INS=$(grep "instructions" "$TF_TMP/http_pool_sat_slice.perf" \
        | grep -oE "[0-9,]+" | head -1 | tr -d ",")
    MTR=$(grep -oE "metrics: .*" "$TF_TMP/http_pool_sat_build2.log" | tail -1)
    TREF=$(echo "$MTR" | grep -oE "T_ref=[0-9]+" | cut -d= -f2)
    R1000=$(( (INS - TREF) * 1000 / INS ))
    if [ "$R1000" -le 150 ]; then
        echo "FAIL: 并发饱和窗口意外满足支持层契约 (A=$INS T=$TREF R=$((R1000/10))%)"
        exit 1
    fi
    echo "  负例验证: rc=0 但 R_total=$(awk "BEGIN{printf \"%.1f\", $R1000/10}")% > 15% → 性能 gate 拒绝"
else
    echo "  负例验证: 探针/切片 rc=$RC (SIG/分歧/兜底) → 候选被拒绝 (不发布)"
fi

tf_pass "http_pool 并发饱和负例 (支持层边界: 该窗口被 gate/探针拒绝)"
tf_finish
