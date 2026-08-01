#!/bin/bash
# 角落条件测试: 多线程进程冻结 (语义未定义, 仅验证可预期行为)
#
# elftrace 仅冻结主线程; worker 线程无限自旋。验证:
#   1. freeze/build/切片运行不崩溃、不挂死
#   2. 主线程输出与退出码与基准一致 (worker 的独立计算丢失可接受)
set -u
cd "$(dirname "$0")/.."
ROOT=$(pwd)
TMP="$ROOT/tmp"
ELFTRACE="$ROOT/build/elftrace"
PROG="$TMP/prog_thread"
SNAP="$TMP/snap_thread.elftrace"
SLICED="$TMP/sliced_thread.elf"

mkdir -p "$TMP"
gcc -O0 -pthread -o "$PROG" tests/prog_thread.c || exit 1

# 1. 基准
"$PROG" > "$TMP/thread_ref.out" 2>&1
REF_RC=$?
grep -q "^DONE" "$TMP/thread_ref.out" || { echo "FAIL: ref has no DONE"; exit 1; }
echo "ref rc=$REF_RC"

# 2. 冻结: 等待 CHECKPOINT 3 (此时 worker 仍在运行, 进程有 2 线程)
"$PROG" > "$TMP/thread_frozen.out" 2>&1 &
PID=$!
for i in $(seq 1 300); do
    grep -q "CHECKPOINT 3" "$TMP/thread_frozen.out" 2>/dev/null && break
    sleep 0.05
done
sleep 0.3
grep -q "CHECKPOINT 3" "$TMP/thread_frozen.out" || { echo "FAIL: CHECKPOINT 3 not seen"; kill -9 $PID; exit 1; }
# 确认此时确实是多线程进程
NTHR=$(awk '/^Threads/{print $2}' /proc/$PID/status 2>/dev/null)
[ "${NTHR:-0}" -ge 2 ] || { echo "FAIL: expected >=2 threads, got $NTHR"; kill -9 $PID; exit 1; }
echo "threads at freeze: $NTHR"

"$ELFTRACE" freeze "$PID" -o "$SNAP" > "$TMP/thread_freeze.out" 2>&1
[ $? = 0 ] || { echo "FAIL: freeze"; kill -9 $PID; exit 1; }
kill -9 $PID 2>/dev/null; wait $PID 2>/dev/null

# 3. 组装 + 运行切片 (主线程续跑; worker 线程不复存在)
"$ELFTRACE" build "$SNAP" -o "$SLICED" >/dev/null 2>&1 || { echo "FAIL: build"; exit 1; }
timeout 60 "$SLICED" > /dev/null 2>&1
S_RC=$?

# 4. 断言: 不崩溃 + 主线程输出/退出码与基准一致
[ "$S_RC" = "$REF_RC" ] || { echo "FAIL: sliced rc=$S_RC != ref $REF_RC"; exit 1; }
diff -q "$TMP/thread_frozen.out" "$TMP/thread_ref.out" >/dev/null \
    || { echo "FAIL: output mismatch"; diff "$TMP/thread_frozen.out" "$TMP/thread_ref.out" | head -5; exit 1; }
grep -q "^DONE" "$TMP/thread_frozen.out" || { echo "FAIL: no DONE"; exit 1; }

echo "PASS: multithreaded process (no crash, main-thread output/rc match ref, rc=$S_RC)"
exit 0
