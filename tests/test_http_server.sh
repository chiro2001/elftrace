#!/bin/bash
# aarch64: python http.server (ThreadingHTTPServer, 每请求 clone 线程)
# 负载的 strict baremetal 切片 — 多线程真实场景
#
# 流程:
#   Run 1: trace --atomic-replay → 校准 (compensation.txt)
#   Run 2: trace --atomic-replay --atomic-compensate → 原始空间检查点
#   build: 中间窗口 strict 切片 (原子回放 + 边界 diff + mock 扫描),
#          先 probe (整页回放 + 预状态 dump) 再 byte-runs (32B granule
#          回放表, 只补写切片未自然复现的并发写入)
# 断言:
#   1. 切片 rc=0 (不超时/不死锁);
#   2. 目标阶段 (rt_sigreturn 后) 除 exit_group 外零 syscall;
#   3. 输出指令数 (报告; granule 回放已把服务器窗口从 ~2.8M 压到
#      ~500K; 手机窗口受 Python 等待自旋主导, 只报告不 gate)。
set -u
cd "$(dirname "$0")/.."
source tests/testlib.sh

if [ "$(uname -m)" != "aarch64" ]; then
    echo "SKIP: http.server strict 测试仅 aarch64"
    exit 0
fi

tf_setup
tf_cleanup python3
ELFTRACE="$TF_ELFTRACE"
DATA="$TF_TMP/http_serve"

echo "== [realworld] python http.server strict slice (two-run) =="

# 服务器数据: 5 个小文件
mkdir -p "$DATA"
for i in 1 2 3 4 5; do
    python3 -c "import os; open('$DATA/f$i','wb').write(os.urandom(4096))"
done

HTTP_PORT=$((18100 + RANDOM % 500))
HTTP_LOG="$TF_TMP/http_server.log"

start_server() {
    python3 -m http.server "$HTTP_PORT" --bind 127.0.0.1 \
        --directory "$DATA" > "$HTTP_LOG" 2>&1 &
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

send_requests() {  # <次数>
    python3 - "$HTTP_PORT" "$1" <<'EOF'
import sys, urllib.request
port, n = int(sys.argv[1]), int(sys.argv[2])
for i in range(n):
    urllib.request.urlopen("http://127.0.0.1:%d/f%d" % (port, i % 5 + 1),
                           timeout=120).read()
EOF
}

run_trace() {  # <输出目录> [补偿文件]
    local out="$1"; shift
    local extra=()
    [ $# -gt 0 ] && extra=(--atomic-compensate "$1")
    start_server || { echo "FAIL: http.server 未就绪"; return 1; }
    send_requests 3 || { echo "FAIL: warm 请求失败"; return 1; }
    timeout 600 "$ELFTRACE" trace "$HTTP_PID" --every 200000 \
        --out "$out" --atomic-replay "${extra[@]}" \
        > "$TF_TMP/http_trace.log" 2>&1 &
    local TPID=$!
    sleep 1
    send_requests 18 || { echo "FAIL: 负载请求失败"; return 1; }
    kill -9 "$HTTP_PID" 2>/dev/null
    wait "$TPID" 2>/dev/null
    [ -f "$out/manifest.txt" ] || return 1
    [ -f "$out/syscalls/syscall.map" ] || return 1
    return 0
}

rm -rf "$TF_TMP/http_r1" "$TF_TMP/http_r2"
run_trace "$TF_TMP/http_r1" || { echo "FAIL: Run1"; tail -3 "$TF_TMP/http_trace.log"; exit 1; }
COMP="$TF_TMP/http_r1/atomics/compensation.txt"
[ -f "$COMP" ] || { echo "FAIL: Run1 无 compensation.txt"; exit 1; }
NCK=$(wc -l < "$TF_TMP/http_r1/manifest.txt")
[ "$NCK" -ge 6 ] || { echo "FAIL: Run1 只有 $NCK 检查点"; exit 1; }
echo "  Run1: $NCK ckpts, $(wc -l < "$TF_TMP/http_r1/syscalls/syscall.map") syscalls"

run_trace "$TF_TMP/http_r2" "$COMP" || { echo "FAIL: Run2"; tail -3 "$TF_TMP/http_trace.log"; exit 1; }
[ -f "$TF_TMP/http_r2/atomics/events.bin" ] || { echo "FAIL: Run2 无 events.bin"; exit 1; }
NCK=$(wc -l < "$TF_TMP/http_r2/manifest.txt")
[ "$NCK" -ge 6 ] || { echo "FAIL: Run2 只有 $NCK 检查点"; exit 1; }
echo "  Run2: $NCK ckpts, $(wc -l < "$TF_TMP/http_r2/syscalls/syscall.map") syscalls"

# 中间窗口切片 (600K..1M), 两阶段:
#   1) probe 切片: 整页回放 + 每个 newseg/dirty 应用前 dump 预状态
#   2) byte-run 切片: 用 probe 预状态压缩成 32B granule 回放表,
#      主线程自身已复现的写入整体跳过, 回放指令数大幅下降
tf_build /dev/null "$TF_TMP/http_probe.elf" --mode baremetal --bm-strict \
    --checkpoints "$TF_TMP/http_r2" --from 3 --to 5 \
    --stack-reserve 67108864 \
    --probe-dump "$TF_TMP/http_probe.bin" > "$TF_TMP/http_build.log" 2>&1 \
    || { echo "FAIL: probe build"; tail -5 "$TF_TMP/http_build.log"; exit 1; }
timeout 600 "$TF_TMP/http_probe.elf" > /dev/null 2>&1
PRC=$?
[ "$PRC" = 0 ] || { echo "FAIL: probe slice rc=$PRC"; exit 1; }
[ -s "$TF_TMP/http_probe.bin" ] || { echo "FAIL: 无 probe.bin"; exit 1; }
tf_build /dev/null "$TF_TMP/http_slice.elf" --mode baremetal --bm-strict \
    --checkpoints "$TF_TMP/http_r2" --from 3 --to 5 \
    --stack-reserve 67108864 \
    --byte-runs "$TF_TMP/http_probe.bin" > "$TF_TMP/http_build2.log" 2>&1 \
    || { echo "FAIL: byte-run build"; tail -5 "$TF_TMP/http_build2.log"; exit 1; }

# 目标阶段零 syscall
timeout 120 strace -o "$TF_TMP/http_slice.strace" \
    "$TF_TMP/http_slice.elf" > /dev/null 2>&1
RC=$?
[ "$RC" = 0 ] || { echo "FAIL: 切片 rc=$RC"; exit 1; }
AFTER=$(awk '/rt_sigreturn/{f=1} f' "$TF_TMP/http_slice.strace")
if echo "$AFTER" | grep -E "openat|read\(|write\(|ioctl|mmap|brk|futex|poll|recvfrom|sendto|accept|clone|clock_gettime"; then
    echo "FAIL: 目标阶段真实 syscall"
    echo "$AFTER"
    exit 1
fi
grep -q "exit_group(0)" "$TF_TMP/http_slice.strace" \
    || { echo "FAIL: 无 exit_group(0)"; exit 1; }

# 指令数报告 (多线程边界 diff 回放数据量大, 不 gate 5%)
timeout 120 perf stat -e instructions "$TF_TMP/http_slice.elf" \
    > /dev/null 2> "$TF_TMP/http_slice.perf"
INS=$(grep "instructions" "$TF_TMP/http_slice.perf" \
    | grep -oE "[0-9,]+" | head -1 | tr -d ",")
echo "  slice instructions: ${INS:-?} (window 400000 + replay 数据应用)"

tf_pass "http.server strict (rc=0, zero target syscalls, ${INS:-?} insns)"
tf_finish
