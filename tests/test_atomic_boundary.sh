#!/bin/bash
# aarch64: 原子 acquire 语义边界 (已知限制) 固化测试。
#
# 场景: 辅助线程先写 payload 再 release 递增 seq; 被切片的主线程用
# acquire 自旋读 seq 后读取 payload。回放跳板按录制序号返回 seq=1,
# 但 payload 在切片里是冻结值 —— 程序不死锁但读到陈旧数据, 退出码
# 为 0; 参考运行读到 NEW, 退出码 7。本测试断言 ref=7 且切片=0,
# 等价于 xfail: 把"回放值来自未来、保护数据仍是冻结值"的边界固化。
set -u
cd "$(dirname "$0")/.."
source tests/testlib.sh

if [ "$(uname -m)" != "aarch64" ]; then
    echo "SKIP: atomic boundary 测试仅 aarch64"
    exit 0
fi

tf_setup
tf_cleanup prog_atomic_boundary
ELFTRACE="$TF_ELFTRACE"

echo "== [atomic] acquire boundary (documented limitation) =="
gcc -O2 -g -pthread -o "$TF_TMP/prog_atomic_boundary" \
    tests/prog_atomic_boundary.c || exit 1

"$TF_TMP/prog_atomic_boundary" > "$TF_TMP/boundary_ref.out" 2>&1
REF_RC=$?
grep -q "DATA=NEW" "$TF_TMP/boundary_ref.out" || {
    echo "FAIL: ref not NEW (rc=$REF_RC)"; exit 1; }
[ "$REF_RC" = 7 ] || { echo "FAIL: ref rc=$REF_RC != 7"; exit 1; }

rm -rf "$TF_TMP/boundary_ck"
"$TF_TMP/prog_atomic_boundary" > "$TF_TMP/boundary_tr.out" 2>&1 &
PID=$!
sleep 0.3
timeout 180 "$ELFTRACE" trace "$PID" --every 50000000 \
    --out "$TF_TMP/boundary_ck" --atomic-replay > /dev/null 2>&1
wait $PID 2>/dev/null
NCK=$(wc -l < "$TF_TMP/boundary_ck/manifest.txt")
[ "$NCK" -ge 3 ] || { echo "FAIL: only $NCK checkpoints"; exit 1; }
[ -f "$TF_TMP/boundary_ck/atomics/events.bin" ] || {
    echo "FAIL: no atomics"; exit 1; }

RC=1
for TO in $(seq 1 $((NCK - 1))); do
    [ "$TO" -lt "$NCK" ] || continue
    tf_build /dev/null "$TF_TMP/boundary_slice.elf" --mode baremetal \
        --bm-strict --checkpoints "$TF_TMP/boundary_ck" \
        --from 0 --to "$TO" --bm-exit-count 1000000000 \
        --stack-reserve 67108864 \
        > "$TF_TMP/boundary_build.log" 2>&1 || continue
    # 退出点必须可计数 (count target insn), 且不在原子站点上
    grep -q "count target insn" "$TF_TMP/boundary_build.log" || continue
    grep -q "first-hit" "$TF_TMP/boundary_build.log" && continue
    # 窗口必须包含 seq 变化 (运行段 >= 2), 否则切片会走负载上限退出,
    # 根本没读到 payload, 断言无意义
    NRUN=$(grep -oE "atomic: [0-9]+ sites, [0-9]+ window run segments" \
        "$TF_TMP/boundary_build.log" | grep -oE "[0-9]+" | tail -1)
    [ "${NRUN:-0}" -ge 2 ] || continue
    timeout 60 "$TF_TMP/boundary_slice.elf" \
        > "$TF_TMP/boundary_slice.out" 2>&1
    RC=$?
    [ "$RC" = 0 ] && break
    # rc=7 说明切片真的读到了 NEW (检查点晚于写 payload): 测试设置问题
    if [ "$RC" = 7 ]; then
        echo "FAIL: slice reproduced NEW (checkpoint after writer?)"
        exit 1
    fi
done
[ "$RC" = 0 ] || {
    echo "FAIL: slice rc=$RC (ref=7, expected 0 = stale data)"
    exit 1; }

timeout 60 strace -o "$TF_TMP/boundary_slice.strace" \
    "$TF_TMP/boundary_slice.elf" > /dev/null 2>&1
AFTER=$(awk '/rt_sigreturn/{f=1} f' "$TF_TMP/boundary_slice.strace")
echo "$AFTER" | grep -E "openat|read\(|write\(|ioctl|mmap|brk|futex|clone" \
    && { echo "FAIL: target-phase real syscalls"; exit 1; }

echo "PASS: acquire boundary documented (ref=NEW rc=7, slice=OLD rc=0, clean)"
tf_pass "atomic acquire boundary (documented limitation)"
tf_finish
