#!/bin/bash
# 测试2: 含文件读写的单线程程序
# 冻结在计算循环中, 切片恢复后:
#   1. fd 偏移正确 (续写 BBB 落在 AAA 之后)
#   2. 读回验证通过 (AAABBB), 退出码与"原进程从冻结点继续"一致
set -u
cd "$(dirname "$0")/.."
ROOT=$(pwd)
TMP="$ROOT/tmp"
ELFTRACE="$ROOT/build/elftrace"
PROG="$TMP/prog_fd_rw"
SNAP="$TMP/snap_fd_rw.elftrace"
SLICED="$TMP/sliced_fd_rw.elf"
F_OUT="$TMP/fd_rw_ref.txt"
F_FROZEN="$TMP/fd_rw_frozen.txt"

mkdir -p "$TMP"
gcc -O0 -o "$PROG" tests/prog_fd_rw.c || exit 1

# 1. 基准 (完整运行)
"$PROG" "$F_OUT" > /dev/null 2>&1
REF_RC=$?
[ "$REF_RC" = 0 ] || { echo "FAIL: ref rc=$REF_RC"; exit 1; }
[ "$(cat "$F_OUT")" = "AAABBB" ] || { echo "FAIL: ref content"; exit 1; }
echo "ref rc=0 content=AAABBB OK"

# 2. 冻结运行
"$PROG" "$F_FROZEN" > "$TMP/fd_rw_frozen.out" 2>&1 &
PID=$!
for i in $(seq 1 200); do
    grep -q "STAGE1" "$TMP/fd_rw_frozen.out" 2>/dev/null && break
    sleep 0.05
done
sleep 0.3
grep -q "STAGE1" "$TMP/fd_rw_frozen.out" || { echo "FAIL: no STAGE1"; kill $PID; exit 1; }
"$ELFTRACE" freeze "$PID" -o "$SNAP" >/dev/null 2>&1 || { echo "FAIL: freeze"; exit 1; }
kill -CONT $PID 2>/dev/null
wait $PID 2>/dev/null
ORIG_RC=$?
[ "$ORIG_RC" = 0 ] || { echo "FAIL: orig-from-frozen rc=$ORIG_RC"; exit 1; }
echo "orig-from-frozen rc=0 OK"

# 3. 切片
"$ELFTRACE" build "$SNAP" -o "$SLICED" --mode real >/dev/null 2>&1 || { echo "FAIL: build"; exit 1; }
timeout 60 "$SLICED" > /dev/null 2>&1
S_RC=$?
[ "$S_RC" = "$ORIG_RC" ] || { echo "FAIL: sliced rc=$S_RC != $ORIG_RC"; exit 1; }

# 4. 文件内容验证 (切片继续写入同一文件)
[ "$(cat "$F_FROZEN")" = "AAABBB" ] || { echo "FAIL: content [$(cat "$F_FROZEN")]"; exit 1; }

# 5. STAGE2/DONE 应出现在冻结前的输出文件 (fd 恢复语义)
grep -q "STAGE2" "$TMP/fd_rw_frozen.out" || { echo "FAIL: no STAGE2"; exit 1; }
grep -q "DONE" "$TMP/fd_rw_frozen.out" || { echo "FAIL: no DONE"; exit 1; }

echo "PASS: file read/write slice (content=AAABBB, rc=$S_RC)"

# ============ baremetal 变体 ============
# 文件 syscall 被 mock: 冻结前已打开的 fd 3 续写成功 (write mock),
# verify 的新 open 被 mock 为 -ENOENT, 程序走失败路径退出 (rc=7)。
# 断言: 目标阶段 (rt_sigreturn 后) 无真实文件 syscall (全部经 SIGTRAP mock),
#       且没有未支持的 syscall (rc != 94)。
"$ELFTRACE" build "$SNAP" -o "$SLICED" --mode baremetal >/dev/null 2>&1 || exit 1
timeout 60 strace -o "$TMP/fd_rw_bm.strace" "$SLICED" > /dev/null 2>&1
BM_RC=$?
[ "$BM_RC" != 94 ] || { echo "FAIL[bm]: unsupported syscall (rc=94)"; exit 1; }
AFTER=$(awk '/rt_sigreturn/{found=1} found' "$TMP/fd_rw_bm.strace")
if echo "$AFTER" | grep -E "openat|read\(|write\(|lseek" | grep -qE "= [0-9-]+$| = "; then
    echo "FAIL[bm]: real file syscalls in baremetal target phase"
    echo "$AFTER" | grep -E "openat|read\(|write\(|lseek" | head -3
    exit 1
fi
NMOCK=$(grep -cE "^--- SIGTRAP" "$TMP/fd_rw_bm.strace")
[ "$NMOCK" -ge 2 ] || { echo "FAIL[bm]: too few mocked syscalls ($NMOCK)"; exit 1; }
echo "PASS[bm]: file syscalls mocked ($NMOCK SIGTRAPs, rc=$BM_RC, no real file ops)"

echo "PASS: file read/write slice (real + baremetal)"
exit 0
