#!/bin/bash
# aarch64: python http.server + 预创建线程池 (ThreadPoolExecutor) strict
# 切片 — 多线程 HTTP 支持层负载 (窗口内无 clone3)。
#
# 与 test_http_server.sh (ThreadingHTTPServer, 每请求 clone) 的区别:
# worker 在 trace 前创建, 主线程只做 accept/submit; 期望 byte-run
# 切片 rc=0 (支持层), 而非 fail-closed 66。
#
# 流程:
#   Run 1: trace --atomic-replay → 校准 (compensation.txt)
#   Run 2: trace --atomic-replay --atomic-compensate → 原始空间检查点
#   build: 中间窗口 strict 切片 (probe + byte-runs)
# 断言:
#   1. probe rc=0, byte-run rc=0;
#   2. 目标阶段 (rt_sigreturn 后) 除 exit_group 外零 syscall;
#   3. 指令数报告 (不 gate)。
set -u
cd "$(dirname "$0")/.."
source tests/testlib.sh

if [ "$(uname -m)" != "aarch64" ]; then
    echo "SKIP: http_pool strict 测试仅 aarch64"
    exit 0
fi

tf_setup
tf_cleanup python3
ELFTRACE="$TF_ELFTRACE"
DATA="$TF_TMP/http_pool_data"

echo "== [realworld] python http.server + thread pool strict slice =="

mkdir -p "$DATA"
for i in 1 2 3 4 5; do
    python3 -c "import os; open('$DATA/f$i','wb').write(os.urandom(4096))"
done

HTTP_PORT=$((18300 + RANDOM % 500))
HTTP_LOG="$TF_TMP/http_pool_server.log"

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
    local vr=()
    if [ -f "tests/pymalloc_sites_ubuntu312.txt" ]; then
        cp "tests/pymalloc_sites_ubuntu312.txt" \
            "$TF_TMP/pymalloc_sites.txt"
        vr=(--value-replay-sites "$TF_TMP/pymalloc_sites.txt")
    fi
    start_server || { echo "FAIL: server 未就绪"; return 1; }
    send_requests 3 || { echo "FAIL: warm 请求失败"; return 1; }
    timeout 600 "$ELFTRACE" trace "$HTTP_PID" --every 100000 \
        --out "$out" --atomic-replay "${vr[@]}" "${extra[@]}" \
        > "$TF_TMP/http_pool_trace.log" 2>&1 &
    local TPID=$!
    sleep 1
    send_requests 18 || { echo "FAIL: 负载请求失败"; return 1; }
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

# 两跑采集 + probe (NVR 优先, 失败回退全值), 整体最多重试 2 次
# (trace 数据相关分歧会让探针偶发 SIGILL/SIGSEGV, 重采得到干净数据)
NVR=()
FROM=0
TO=0
trace_and_probe() {
    NVR=()
    rm -rf "$TF_TMP/http_pool_r1" "$TF_TMP/http_pool_r2"
    run_trace_retry "$TF_TMP/http_pool_r1" || { echo "FAIL: Run1"; return 1; }
    COMP="$TF_TMP/http_pool_r1/atomics/compensation.txt"
    [ -f "$COMP" ] || { echo "FAIL: Run1 无 compensation.txt"; return 1; }
    NCK=$(wc -l < "$TF_TMP/http_pool_r1/manifest.txt")
    [ "$NCK" -ge 6 ] || { echo "FAIL: Run1 只有 $NCK 检查点"; return 1; }
    echo "  Run1: $NCK ckpts, $(wc -l < "$TF_TMP/http_pool_r1/syscalls/syscall.map") syscalls"

    run_trace_retry "$TF_TMP/http_pool_r2" "$COMP" || { echo "FAIL: Run2"; return 1; }
    [ -f "$TF_TMP/http_pool_r2/atomics/events.bin" ] || { echo "FAIL: Run2 无 events.bin"; return 1; }
    NCK=$(wc -l < "$TF_TMP/http_pool_r2/manifest.txt")
    [ "$NCK" -ge 6 ] || { echo "FAIL: Run2 只有 $NCK 检查点"; return 1; }
    echo "  Run2: $NCK ckpts, $(wc -l < "$TF_TMP/http_pool_r2/syscalls/syscall.map") syscalls"

    TOT=$(awk 'END{print $1}' "$TF_TMP/http_pool_r2/manifest.txt")
    FROM=$((TOT * 2 / 5))
    TO=$((TOT * 3 / 5))
    [ "$TO" -gt "$FROM" ] || { echo "FAIL: 窗口过窄"; return 1; }
    # NVR 优先: 探针验证通过则跳过全部值回放 (省 ~75K 引擎指令)
    tf_build /dev/null "$TF_TMP/http_pool_probe.elf" --mode baremetal --bm-strict \
        --checkpoints "$TF_TMP/http_pool_r2" \
        --from-count "$FROM" --to-count "$TO" \
        --stack-reserve 67108864 --atomic-no-value-replay \
        --probe-dump "$TF_TMP/http_pool_probe.bin" > "$TF_TMP/http_pool_build.log" 2>&1
    if [ $? = 0 ]; then
        timeout 600 "$TF_TMP/http_pool_probe.elf" > /dev/null 2>&1
        PRC=$?
        if [ "$PRC" = 0 ] && [ -s "$TF_TMP/http_pool_probe.bin" ]; then
            NVR=(--atomic-no-value-replay)
            echo "  http_pool: 无值回放探针通过 (边界 diff 足够)"
            return 0
        fi
        echo "  http_pool: NVR 探针 rc=$PRC, 回退全值回放"
    fi
    tf_build /dev/null "$TF_TMP/http_pool_probe.elf" --mode baremetal --bm-strict \
        --checkpoints "$TF_TMP/http_pool_r2" \
        --from-count "$FROM" --to-count "$TO" \
        --stack-reserve 67108864 \
        --probe-dump "$TF_TMP/http_pool_probe.bin" > "$TF_TMP/http_pool_build.log" 2>&1 \
        || { echo "FAIL: probe build"; tail -5 "$TF_TMP/http_pool_build.log"; return 1; }
    timeout 600 "$TF_TMP/http_pool_probe.elf" > /dev/null 2>&1
    PRC=$?
    if [ "$PRC" != 0 ]; then
        echo "  http_pool: 全值探针 rc=$PRC (trace 数据分歧), 重采重试"
        return 1
    fi
    [ -s "$TF_TMP/http_pool_probe.bin" ] || { echo "FAIL: 无 probe.bin"; return 1; }
    return 0
}

trace_and_probe || trace_and_probe || { tail -3 "$TF_TMP/http_pool_trace.log"; exit 1; }
tf_build /dev/null "$TF_TMP/http_pool_slice.elf" --mode baremetal --bm-strict \
    --checkpoints "$TF_TMP/http_pool_r2" \
    --from-count "$FROM" --to-count "$TO" \
    --stack-reserve 67108864 \
    --byte-runs "$TF_TMP/http_pool_probe.bin" \
    --newseg-big-skip 1048576 "${NVR[@]}" > "$TF_TMP/http_pool_build2.log" 2>&1 \
    || { echo "FAIL: byte-run build"; tail -5 "$TF_TMP/http_pool_build2.log"; exit 1; }

timeout 120 strace -o "$TF_TMP/http_pool_slice.strace" \
    "$TF_TMP/http_pool_slice.elf" > /dev/null 2>&1
RC=$?
[ "$RC" = 0 ] || { echo "FAIL: 切片 rc=$RC (支持层要求 rc=0)"; exit 1; }
AFTER=$(awk '/rt_sigreturn/{f=1; next} f' "$TF_TMP/http_pool_slice.strace")
BAD=$(echo "$AFTER" | grep -vE "^(exit_group|\\+\\+\\+ exited)")
if [ -n "$BAD" ]; then
    echo "FAIL: 目标阶段出现非 exit_group 的 syscall 行"
    echo "$BAD"
    exit 1
fi
grep -q "exit_group(0)" "$TF_TMP/http_pool_slice.strace" \
    || { echo "FAIL: 无 exit_group(0)"; exit 1; }

timeout 120 perf stat -e instructions "$TF_TMP/http_pool_slice.elf" \
    > /dev/null 2> "$TF_TMP/http_pool_slice.perf"
INS=$(grep "instructions" "$TF_TMP/http_pool_slice.perf" \
    | grep -oE "[0-9,]+" | head -1 | tr -d ",")
echo "  slice instructions: ${INS:-?} (window $((TO - FROM)) + replay 数据应用)"

# 指标: T_ref=build 实际窗口 (manifest 原始计数), R_total=(A-T_ref)/A;
# health=measured/名义, 偏离 [0.7,1.4] 判 INVALID
MTR=$(grep -oE "metrics: .*" "$TF_TMP/http_pool_build2.log" | tail -1)
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
    if [ -n "${HEALTH:-}" ] && [ "$HEALTH" -ge 700 ] && [ "$HEALTH" -le 1400 ]; then
        :
    else
        HFLAG=" INVALID(health=$HEALTH)"
    fi
    echo "  metrics: T_ref=$TREF A=$INS R_total=$(awk "BEGIN{printf \"%.1f\", $R1000/10}")%$HFLAG"
    # 支持层契约: 总补偿 <15% (用户目标); 健康异常判无效
    if [ "$R1000" -gt 150 ]; then
        echo "FAIL: 支持层 R_total=$(awk "BEGIN{printf \"%.1f\", $R1000/10}")% > 15%"
        exit 1
    fi
    [ -z "$HFLAG" ] || { echo "FAIL: 指标健康异常 (perf 基线/补偿校准)"; exit 1; }
fi

tf_pass "http.server+pool strict 支持层 (rc=0, zero target syscalls, ${INS:-?} insns)"
tf_finish
