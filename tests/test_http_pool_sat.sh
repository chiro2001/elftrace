#!/bin/bash
# aarch64: python http.server + 预创建线程池, 并发饱和负载 strict 切片
#
# 与 test_http_pool.sh 的区别: 8 个并发客户端 × 每客户端 10 轮短连接,
# 让 worker 池在窗口内持续争用 (accept/submit/队列/GIL/分配), 验证
# 并发饱和下支持层契约: rc=0 + 零真实 syscall + R_total <= 15%。
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
    # 并发: 4 客户端 × 4 轮 (16 并发请求)。6×6 (36) 回退全值回放
    # R=35.8%, 8×10 (80) 探针 SIGSEGV, 均超出支持层。
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
[ "$NCK" -ge 6 ] || { echo "FAIL: Run1 只有 $NCK 检查点"; exit 1; }
echo "  Run1: $NCK ckpts, $(wc -l < "$TF_TMP/http_pool_sat_r1/syscalls/syscall.map") syscalls"

run_trace_retry "$TF_TMP/http_pool_sat_r2" "$COMP" || { echo "FAIL: Run2"; tail -3 "$TF_TMP/http_pool_sat_trace.log"; exit 1; }
[ -f "$TF_TMP/http_pool_sat_r2/atomics/events.bin" ] || { echo "FAIL: Run2 无 events.bin"; exit 1; }
NCK=$(wc -l < "$TF_TMP/http_pool_sat_r2/manifest.txt")
[ "$NCK" -ge 6 ] || { echo "FAIL: Run2 只有 $NCK 检查点"; exit 1; }
echo "  Run2: $NCK ckpts, $(wc -l < "$TF_TMP/http_pool_sat_r2/syscalls/syscall.map") syscalls"

# 窗口取 25%~75% (比 40%~60% 大, 摊薄固定引擎/启动开销)
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
    [ "$PRC" = 0 ] || { echo "FAIL: probe slice rc=$PRC"; exit 1; }
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
[ "$RC" = 0 ] || { echo "FAIL: 切片 rc=$RC (支持层要求 rc=0)"; exit 1; }
AFTER=$(awk '/rt_sigreturn/{f=1; next} f' "$TF_TMP/http_pool_sat_slice.strace")
BAD=$(echo "$AFTER" | grep -vE "^(exit_group|\\+\\+\\+ exited)")
if [ -n "$BAD" ]; then
    echo "FAIL: 目标阶段出现非 exit_group 的 syscall 行"
    echo "$BAD"
    exit 1
fi
grep -q "exit_group(0)" "$TF_TMP/http_pool_sat_slice.strace" \
    || { echo "FAIL: 无 exit_group(0)"; exit 1; }

timeout 120 perf stat -e instructions "$TF_TMP/http_pool_sat_slice.elf" \
    > /dev/null 2> "$TF_TMP/http_pool_sat_slice.perf"
INS=$(grep "instructions" "$TF_TMP/http_pool_sat_slice.perf" \
    | grep -oE "[0-9,]+" | head -1 | tr -d ",")
MTR=$(grep -oE "metrics: .*" "$TF_TMP/http_pool_sat_build2.log" | tail -1)
TREF=$(echo "$MTR" | grep -oE "T_ref=[0-9]+" | cut -d= -f2)
HEALTH=$(echo "$MTR" | grep -oE "health_x1000=[0-9]+" | cut -d= -f2)
if [ -n "${TREF:-}" ] && [ "${TREF:-0}" -gt 0 ] && [ -n "${INS:-}" ] \
    && [ "${INS:-0}" -gt 0 ]; then
    R1000=$(( (INS - TREF) * 1000 / INS ))
    if [ "$R1000" -lt 0 ]; then
        echo "FAIL: 提前退出 (A=$INS < T_ref=$TREF), 无效测量"
        exit 1
    fi
    HFLAG=""
    [ -n "${HEALTH:-}" ] && [ "$HEALTH" -ge 700 ] && [ "$HEALTH" -le 1400 ] \
        || HFLAG=" INVALID(health=$HEALTH)"
    echo "  metrics: T_ref=$TREF A=$INS R_total=$(awk "BEGIN{printf \"%.1f\", $R1000/10}")%$HFLAG"
    if [ "$R1000" -gt 150 ]; then
        echo "FAIL: 支持层 R_total=$(awk "BEGIN{printf \"%.1f\", $R1000/10}")% > 15%"
        exit 1
    fi
    [ -z "$HFLAG" ] || { echo "FAIL: 指标健康异常"; exit 1; }
fi

tf_pass "http.server+pool 并发饱和 strict 支持层 (rc=0, zero target syscalls, ${INS:-?} insns)"
tf_finish
