#!/bin/bash
# 角落条件测试: O_APPEND 追加模式 fd 的偏移语义
#
# 程序: O_APPEND 打开文件 -> 写 AAA -> 冻结 -> lseek(0) -> 写 BBB
# 验证:
#   1. 快照 fd 记录保留了 O_APPEND 标志 (dump 显示 flags=0102001)
#   2. 切片中 "BBB" 追加到末尾 (AAABBB) 而非覆盖开头 (BBB) ——
#      O_APPEND 恢复正确, 偏移恢复为 pos=3 后追加写仍生效
set -u
cd "$(dirname "$0")/.."
ROOT=$(pwd)
TMP="$ROOT/tmp"
ELFTRACE="$ROOT/build/elftrace"
PROG="$TMP/prog_append"
SNAP="$TMP/snap_append.elftrace"
SLICED="$TMP/sliced_append.elf"
F_REF="$TMP/append_ref.txt"
F_FROZEN="$TMP/append_frozen.txt"

mkdir -p "$TMP"
gcc -O0 -o "$PROG" tests/prog_append.c || exit 1

# 1. 基准: O_APPEND 语义下 BBB 落在末尾
"$PROG" "$F_REF" > /dev/null 2>&1
[ "$(cat "$F_REF")" = "AAABBB" ] || { echo "FAIL: ref content [$(cat "$F_REF")] != AAABBB"; exit 1; }
echo "ref content=AAABBB OK"

# 2. 冻结: 等待 OPENED (fd 已打开, 偏移=3)
"$PROG" "$F_FROZEN" > "$TMP/append_frozen.out" 2>&1 &
PID=$!
for i in $(seq 1 200); do
    grep -q "OPENED" "$TMP/append_frozen.out" 2>/dev/null && break
    sleep 0.05
done
sleep 0.3
grep -q "OPENED" "$TMP/append_frozen.out" || { echo "FAIL: OPENED not seen"; kill $PID; exit 1; }

"$ELFTRACE" freeze "$PID" -o "$SNAP" >/dev/null 2>&1 || { echo "FAIL: freeze"; kill -9 $PID; exit 1; }
kill -9 $PID 2>/dev/null; wait $PID 2>/dev/null

# 3. 快照中该 fd 应带 O_APPEND 标志 (0102001 = O_LARGEFILE|O_APPEND|O_WRONLY)
DUMP=$("$ELFTRACE" dump "$SNAP")
FD_LINE=$(echo "$DUMP" | grep -E "^\s+fd [0-9]+ .*$F_FROZEN" | head -1)
echo "fd record: ${FD_LINE##*fd }"
echo "$FD_LINE" | grep -q "flags=0102001" \
    || { echo "FAIL: O_APPEND flag not captured: ${FD_LINE##*fd }"; exit 1; }

# 4. 组装 + 运行切片
"$ELFTRACE" build "$SNAP" -o "$SLICED" --mode real >/dev/null 2>&1 || { echo "FAIL: build"; exit 1; }
timeout 60 "$SLICED" > /dev/null 2>&1
S_RC=$?
[ "$S_RC" = 0 ] || { echo "FAIL: sliced rc=$S_RC"; exit 1; }

# 5. 断言: BBB 追加到末尾 (O_APPEND 语义保留); 原始进程的 CLOSED 也应出现
[ "$(cat "$F_FROZEN")" = "AAABBB" ] \
    || { echo "FAIL: content [$(cat "$F_FROZEN")] != AAABBB (O_APPEND lost?)"; exit 1; }
grep -q "CLOSED" "$TMP/append_frozen.out" || { echo "FAIL: no CLOSED"; exit 1; }

echo "PASS: O_APPEND fd restore (content=AAABBB, append-after-lseek works)"
exit 0
