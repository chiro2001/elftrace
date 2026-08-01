#!/bin/bash
# 进阶功能3测试: fd 与文件恢复
# 目标程序打开文件写入 "AAA" 后进入忙循环; 冻结后切片进程应:
#   1. 通过路径重开文件, 恢复 fd 编号与文件偏移
#   2. 在冻结前的偏移处继续写 "BBB"
#   3. 文件最终内容 = "AAABBB" (与基准一致)
set -u
cd "$(dirname "$0")/.."
ROOT=$(pwd)
TMP="$ROOT/tmp"
ELFTRACE="$ROOT/build/elftrace"
PROG="$TMP/prog_fd"
SNAP="$TMP/snap_fd.elftrace"
SLICED="$TMP/sliced_fd.elf"
F_OUT="$TMP/fd_out.txt"
F_REF="$TMP/fd_ref.txt"
F_FROZEN="$TMP/fd_frozen.txt"

mkdir -p "$TMP"
gcc -O0 -o "$PROG" tests/prog_fd.c || exit 1

# 1. 基准运行 (完整跑完)
"$PROG" "$F_REF" > /dev/null 2>&1
REF_CONTENT=$(cat "$F_REF")
[ "$REF_CONTENT" = "AAABBB" ] || { echo "FAIL: ref content [$REF_CONTENT]"; exit 1; }

# 2. 冻结运行: 等待 OPENED 出现后冻结 (此时 fd 已打开, 处于忙循环)
"$PROG" "$F_FROZEN" > "$TMP/fd_frozen.out" 2>&1 &
PID=$!
for i in $(seq 1 200); do
    grep -q "OPENED" "$TMP/fd_frozen.out" 2>/dev/null && break
    sleep 0.05
done
sleep 0.3
grep -q "OPENED" "$TMP/fd_frozen.out" || { echo "FAIL: OPENED not seen"; kill $PID; exit 1; }

"$ELFTRACE" freeze "$PID" -o "$SNAP" || { echo "FAIL: freeze"; exit 1; }

# 3. 组装 (含 fd 恢复)
"$ELFTRACE" build "$SNAP" -o "$SLICED" || { echo "FAIL: build"; exit 1; }

# 4. 运行切片
timeout 60 "$SLICED" > "$TMP/fd_sliced.out" 2>&1
RC=$?
[ "$RC" = 0 ] || { echo "FAIL: sliced rc=$RC"; cat "$TMP/fd_sliced.out"; exit 1; }

# 5. 断言: 文件内容与基准一致 (偏移恢复 + 内容续写)
CONTENT=$(cat "$F_FROZEN")
[ "$CONTENT" = "AAABBB" ] || { echo "FAIL: content [$CONTENT] != AAABBB"; exit 1; }
# "CLOSED" 经恢复后的 fd 1 写入冻结前的重定向文件
grep -q "CLOSED" "$TMP/fd_frozen.out" || { echo "FAIL: no CLOSED output"; exit 1; }

echo "PASS: fd restore (reopen + offset continue, content=$CONTENT)"
exit 0
