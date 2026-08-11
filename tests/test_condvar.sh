#!/bin/bash
# aarch64: mutex+condvar 紧密乒乓 (生产者/消费者高频交接) strict 切片
#
# 两跑补偿 + probe/byte-runs 流程 (与 test_http_server.sh 相同):
#   Run1: trace --atomic-replay → compensation.txt (校准)
#   Run2: trace --atomic-compensate → 原始空间检查点
#   probe 切片 → byte-run 切片 (中间窗口, --newseg-big-skip)
# 断言:
#   1. 切片 rc=0 (不超时/不死锁);
#   2. 目标阶段 (rt_sigreturn 后) 除 exit_group 外零 syscall;
#   3. 输出指令数 (报告; 不 gate — 窗口覆盖取决于分歧)。
set -u
cd "$(dirname "$0")/.."
source tests/testlib.sh

if [ "$(uname -m)" != "aarch64" ]; then
    echo "SKIP: condvar 测试仅 aarch64 (--bm-strict + --atomic-replay)"
    exit 0
fi

tf_setup
tf_cleanup prog_condvar_pingpong
ELFTRACE="$TF_ELFTRACE"

echo "== [realworld] condvar ping-pong strict slice (two-run) =="
gcc -O2 -g -pthread -o "$TF_TMP/prog_condvar_pingpong" \
    tests/prog_condvar_pingpong.c || exit 1

run_trace() {  # <输出目录> [补偿文件]
    local out="$1"; shift
    local extra=()
    [ $# -gt 0 ] && extra=(--atomic-compensate "$1")
    "$TF_TMP/prog_condvar_pingpong" 20000 8 50000 40000 \
        > "$TF_TMP/cv.out" 2>&1 &
    local PID=$!
    sleep 0.3
    timeout 600 "$ELFTRACE" trace "$PID" --every 50000000 \
        --out "$out" --atomic-replay "${extra[@]}" \
        > "$TF_TMP/cv_trace.log" 2>&1
    # trace 数据来自检查点, 不依赖目标跑完; 优雅 detach 后目标可能
    # 死锁 (两线程都在 condvar 上睡死), 不 kill 会让 wait 永久阻塞
    kill -9 "$PID" 2>/dev/null
    wait $PID 2>/dev/null
    [ -f "$out/manifest.txt" ] || { tail -3 "$TF_TMP/cv_trace.log"; return 1; }
}

rm -rf "$TF_TMP/cv_r1" "$TF_TMP/cv_r2"
run_trace "$TF_TMP/cv_r1" || { echo "FAIL: Run1"; exit 1; }
COMP="$TF_TMP/cv_r1/atomics/compensation.txt"
[ -f "$COMP" ] || { echo "FAIL: Run1 no compensation.txt"; exit 1; }
NCK=$(wc -l < "$TF_TMP/cv_r1/manifest.txt")
[ "$NCK" -ge 4 ] || { echo "FAIL: Run1 only $NCK checkpoints"; exit 1; }
echo "  Run1: $NCK ckpts, $(wc -l < "$TF_TMP/cv_r1/syscalls/syscall.map") syscalls"

run_trace "$TF_TMP/cv_r2" "$COMP" || { echo "FAIL: Run2"; exit 1; }
NCK=$(wc -l < "$TF_TMP/cv_r2/manifest.txt")
[ "$NCK" -ge 4 ] || { echo "FAIL: Run2 only $NCK checkpoints"; exit 1; }
echo "  Run2: $NCK ckpts, $(wc -l < "$TF_TMP/cv_r2/syscalls/syscall.map") syscalls"

# 中间窗口: 总指令数的 40%~60% (原始计数)
TOT=$(awk 'END{print $1}' "$TF_TMP/cv_r2/manifest.txt")
FROM=$((TOT * 2 / 5))
TO=$((TOT * 3 / 5))

tf_build /dev/null "$TF_TMP/cv_probe.elf" --mode baremetal --bm-strict \
    --checkpoints "$TF_TMP/cv_r2" --from-count "$FROM" --to-count "$TO" \
    --stack-reserve 67108864 --probe-dump "$TF_TMP/cv_probe.bin" \
    > "$TF_TMP/cv_build.log" 2>&1 \
    || { echo "FAIL: probe build"; tail -5 "$TF_TMP/cv_build.log"; exit 1; }
timeout 600 "$TF_TMP/cv_probe.elf" > /dev/null 2>&1
PRC=$?
[ "$PRC" = 0 ] || { echo "FAIL: probe slice rc=$PRC"; exit 1; }
[ -s "$TF_TMP/cv_probe.bin" ] || { echo "FAIL: 无 probe.bin"; exit 1; }

tf_build /dev/null "$TF_TMP/cv_slice.elf" --mode baremetal --bm-strict \
    --checkpoints "$TF_TMP/cv_r2" --from-count "$FROM" --to-count "$TO" \
    --stack-reserve 67108864 --byte-runs "$TF_TMP/cv_probe.bin" \
    --newseg-big-skip 1048576 > "$TF_TMP/cv_build2.log" 2>&1 \
    || { echo "FAIL: byte-run build"; tail -5 "$TF_TMP/cv_build2.log"; exit 1; }

timeout 120 strace -o "$TF_TMP/cv_slice.strace" \
    "$TF_TMP/cv_slice.elf" > /dev/null 2>&1
RC=$?
[ "$RC" = 0 ] || { echo "FAIL: 切片 rc=$RC"; exit 1; }
AFTER=$(awk '/rt_sigreturn/{f=1; next} f' "$TF_TMP/cv_slice.strace")
if echo "$AFTER" | grep -E "openat|read\(|write\(|ioctl\(|mmap|brk|futex|poll|recvfrom|sendto|accept|clone|clock"; then
    echo "FAIL: 目标阶段真实 syscall"
    echo "$AFTER"
    exit 1
fi

timeout 120 perf stat -e instructions "$TF_TMP/cv_slice.elf" \
    > /dev/null 2> "$TF_TMP/cv_slice.perf"
INS=$(grep "instructions" "$TF_TMP/cv_slice.perf" \
    | grep -oE "[0-9,]+" | head -1 | tr -d ",")
echo "  slice instructions: ${INS:-?} (window $((TO - FROM)) + replay)"
tf_pass "condvar ping-pong strict (rc=0, zero target syscalls, ${INS:-?} insns)"
tf_finish
