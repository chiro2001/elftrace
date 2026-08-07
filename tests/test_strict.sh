#!/bin/bash
# aarch64 strict baremetal 统一测试:
#   1. freeze 快照 + strict mock (无回放表): 目标阶段零 syscall
#   2. trace + strict 回放: 窗口内 syscall 精确回放 + 循环退出
#   3. ioctl 设备操作负载: 设备 syscall 也在窗口内被回放
# 断言: rc 与期望一致; strace 中目标阶段 (rt_sigreturn 后) 除
# exit_group 外无任何 syscall。
set -u
cd "$(dirname "$0")/.."
source tests/testlib.sh

if [ "$(uname -m)" != "aarch64" ]; then
    echo "SKIP: strict baremetal 测试仅 aarch64 (--bm-strict)"
    exit 0
fi

tf_setup
tf_cleanup prog_ioctl prog_simple prog_loopread_a64

ELFTRACE="$TF_ELFTRACE"

# ============ 1. freeze + strict mock ============
echo "== [strict] freeze mock =="
gcc -O0 -g -o "$TF_TMP/prog_simple" tests/prog_simple.c || exit 1
"$TF_TMP/prog_simple" > /dev/null 2>&1
REF_RC=$?
"$TF_TMP/prog_simple" > "$TF_TMP/strict_fz.out" 2>&1 &
PID=$!
tf_wait_marker "strict_fz" "CHECKPOINT 3" 30 || { echo "FAIL: no ckpt"; exit 1; }
tf_freeze "$PID" "$TF_TMP/strict_snap.elftrace" || exit 1
kill -9 $PID 2>/dev/null; wait $PID 2>/dev/null
tf_build "$TF_TMP/strict_snap.elftrace" "$TF_TMP/strict_mock.elf" \
    --mode baremetal --bm-strict --stack-reserve 67108864 >/dev/null || exit 1
timeout 60 strace -o "$TF_TMP/strict_mock.strace" "$TF_TMP/strict_mock.elf" \
    > /dev/null 2>&1
RC=$?
[ "$RC" = "$REF_RC" ] || { echo "FAIL[1]: rc=$RC != ref $REF_RC"; exit 1; }
AFTER=$(awk '/rt_sigreturn/{f=1} f' "$TF_TMP/strict_mock.strace")
echo "$AFTER" | grep -E "openat|read\(|write\(|ioctl|mmap|brk" \
    && { echo "FAIL[1]: target-phase real syscalls"; echo "$AFTER"; exit 1; }
grep -q "exit_group" "$TF_TMP/strict_mock.strace" \
    || { echo "FAIL[1]: no exit_group"; exit 1; }
echo "PASS[1]: freeze+strict mock, target phase clean"

# ============ 2. trace + strict 回放 (含循环退出) ============
echo "== [strict] trace replay =="
rm -rf "$TF_TMP/strict_ckpts"
"$TF_TMP/prog_simple" > "$TF_TMP/strict_tr.out" 2>&1 &
PID=$!
sleep 0.3
timeout 120 "$ELFTRACE" trace "$PID" --every 100000000 \
    --out "$TF_TMP/strict_ckpts" > /dev/null 2>&1
wait $PID 2>/dev/null
NCK=$(wc -l < "$TF_TMP/strict_ckpts/manifest.txt")
[ "$NCK" -ge 8 ] || { echo "FAIL[2]: only $NCK checkpoints"; exit 1; }
tf_build /dev/null "$TF_TMP/strict_replay.elf" --mode baremetal --bm-strict \
    --checkpoints "$TF_TMP/strict_ckpts" --from 2 --to 6 \
    --stack-reserve 67108864 > /dev/null || exit 1
timeout 60 strace -o "$TF_TMP/strict_replay.strace" \
    "$TF_TMP/strict_replay.elf" > /dev/null 2>&1
RC=$?
[ "$RC" = 0 ] || { echo "FAIL[2]: rc=$RC"; exit 1; }
AFTER=$(awk '/rt_sigreturn/{f=1} f' "$TF_TMP/strict_replay.strace")
echo "$AFTER" | grep -E "openat|read\(|write\(|ioctl|mmap|brk" \
    && { echo "FAIL[2]: target-phase real syscalls"; echo "$AFTER"; exit 1; }
echo "PASS[2]: trace+strict replay (middle window, loop exit, clean)"

# ============ 3. ioctl 设备操作 ============
echo "== [strict] ioctl device workload =="
gcc -O0 -g -o "$TF_TMP/prog_ioctl" tests/prog_ioctl.c || exit 1
"$TF_TMP/prog_ioctl" 2000 /dev/null 10 > "$TF_TMP/ioctl_ref.out" 2>&1
REF_RC=$?
echo "ioctl ref: $(cat "$TF_TMP/ioctl_ref.out") rc=$REF_RC"
rm -rf "$TF_TMP/ioctl_ckpts"
"$TF_TMP/prog_ioctl" 2000 /dev/null 10 > "$TF_TMP/ioctl_tr.out" 2>&1 &
PID=$!
sleep 0.1
timeout 200 "$ELFTRACE" trace "$PID" --every 20000000 \
    --out "$TF_TMP/ioctl_ckpts" > /dev/null 2>&1
wait $PID 2>/dev/null
NIOCTL=$(grep -cE " 29 " "$TF_TMP/ioctl_ckpts/syscalls/syscall.map" 2>/dev/null)
[ "$NIOCTL" -ge 20 ] || { echo "FAIL[3]: only $NIOCTL ioctl records"; exit 1; }
NCK=$(wc -l < "$TF_TMP/ioctl_ckpts/manifest.txt")
[ "$NCK" -ge 4 ] || { echo "FAIL[3]: only $NCK checkpoints"; exit 1; }
tf_build /dev/null "$TF_TMP/ioctl_slice.elf" --mode baremetal --bm-strict \
    --checkpoints "$TF_TMP/ioctl_ckpts" --from 1 --to 3 \
    --stack-reserve 67108864 > /dev/null || exit 1
timeout 60 strace -o "$TF_TMP/ioctl_slice.strace" "$TF_TMP/ioctl_slice.elf" \
    > /dev/null 2>&1
RC=$?
[ "$RC" = 0 ] || { echo "FAIL[3]: rc=$RC"; exit 1; }
AFTER=$(awk '/rt_sigreturn/{f=1} f' "$TF_TMP/ioctl_slice.strace")
if echo "$AFTER" | grep -E "ioctl|openat|read\(|write\(|mmap|brk"; then
    echo "FAIL[3]: target-phase real syscalls"; echo "$AFTER"; exit 1
fi
# 窗口内应有 ioctl 记录且站点被替换 (切片目标阶段无 ioctl)
echo "PASS[3]: ioctl device workload strict-sliced (${NIOCTL} ioctl recs, rc=$RC)"

tf_cleanup prog_ioctl prog_simple
tf_pass "strict baremetal (mock + replay + ioctl device)"
tf_finish
