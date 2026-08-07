#!/bin/bash
# 角落条件测试: 冻结阻塞在 syscall (nanosleep) 中的进程
#
# 验证:
#   1. freeze 检测到 in-flight syscall 并告警 (stderr 含 "frozen inside syscall")
#   2. 切片从 syscall 指令重新执行 (sleep 重做), 最终输出/退出码与基准一致
#
# 同步技巧: 等待 "SLEEP 1" 后轮询 /proc/<pid>/wchan == hrtimer_nanosleep,
# 确保冻结时刻进程确实在内核 syscall 中, 而非用户态。
set -u
cd "$(dirname "$0")/.."
ROOT=$(pwd)
TMP="$ROOT/tmp"
ELFTRACE="$ROOT/build/elftrace"
PROG="$TMP/prog_syscall"
SNAP="$TMP/snap_syscall.elftrace"
SLICED="$TMP/sliced_syscall.elf"

mkdir -p "$TMP"
gcc -O0 -o "$PROG" tests/prog_syscall.c || exit 1

# 1. 基准运行 (~10s)
"$PROG" > "$TMP/syscall_ref.out" 2>&1
REF_RC=$?
[ "$REF_RC" = 0 ] || { echo "FAIL: ref rc=$REF_RC"; exit 1; }
grep -q "^DONE$" "$TMP/syscall_ref.out" || { echo "FAIL: ref has no DONE"; exit 1; }
echo "ref rc=0, $(wc -l < "$TMP/syscall_ref.out") lines"

# 2. 目标: 等待 SLEEP 1, 再等进程进入内核 sleep (wchan = hrtimer_nanosleep)
"$PROG" > "$TMP/syscall_frozen.out" 2>&1 &
PID=$!
for i in $(seq 1 200); do
    grep -q "SLEEP 1" "$TMP/syscall_frozen.out" 2>/dev/null && break
    sleep 0.05
done
grep -q "SLEEP 1" "$TMP/syscall_frozen.out" || { echo "FAIL: SLEEP 1 not seen"; kill $PID; exit 1; }

IN_SYSCALL=""
for i in $(seq 1 32); do
    W=$(cat /proc/$PID/wchan 2>/dev/null)
    # x86: hrtimer_nanosleep; aarch64: __arm64_sys_nanosleep
    [ "$W" = "hrtimer_nanosleep" ] || [ "$W" = "__arm64_sys_nanosleep" ] \
        && { IN_SYSCALL=1; break; }
    sleep 0.05
done
[ -n "$IN_SYSCALL" ] || { echo "FAIL: target never observed in nanosleep (wchan=$W)"; kill $PID; exit 1; }

# 3. 冻结: 必须出现 in-flight syscall 告警
"$ELFTRACE" freeze "$PID" -o "$SNAP" > "$TMP/syscall_freeze.out" 2> "$TMP/syscall_freeze.err"
FRC=$?
[ "$FRC" = 0 ] || { echo "FAIL: freeze rc=$FRC"; cat "$TMP/syscall_freeze.err"; kill -9 $PID 2>/dev/null; exit 1; }
grep -q "frozen inside syscall" "$TMP/syscall_freeze.err" \
    || { echo "FAIL: no in-flight syscall warning in freeze stderr:"; cat "$TMP/syscall_freeze.err"; exit 1; }
kill -9 $PID 2>/dev/null; wait $PID 2>/dev/null
echo "freeze warning OK: $(grep -o 'frozen inside syscall [0-9]*;.*' "$TMP/syscall_freeze.err")"

# 4. 组装 + 运行切片 (重新执行被中断的 sleep, 总时长仍有限)
"$ELFTRACE" build "$SNAP" -o "$SLICED" --mode real >/dev/null 2>&1 || { echo "FAIL: build"; exit 1; }
timeout 30 "$SLICED" > /dev/null 2>&1
S_RC=$?
[ "$S_RC" = "$REF_RC" ] || { echo "FAIL: sliced rc=$S_RC != ref $REF_RC"; exit 1; }

# 5. 断言: 输出与基准完全一致 (fd 1 恢复回冻结前文件, 切片续写)
diff -q "$TMP/syscall_frozen.out" "$TMP/syscall_ref.out" >/dev/null \
    || { echo "FAIL: frozen.out != ref.out"; diff "$TMP/syscall_frozen.out" "$TMP/syscall_ref.out" | head -5; exit 1; }
grep -q "^DONE$" "$TMP/syscall_frozen.out" || { echo "FAIL: no DONE"; exit 1; }

echo "PASS: in-flight syscall (freeze warning + slice completes, rc=$S_RC, output identical)"
exit 0
