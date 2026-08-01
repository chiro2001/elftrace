#!/bin/bash
# 进阶功能2测试: 调试符号保留
# 1. 冻结 -g 编译的程序, 组装切片
# 2. 断言: 符号地址已加 PIE bias, DWARF 行号与运行时地址一致
# 3. 在冻结点注入 int3, 运行切片, 断言 gdb 能定位到源码行并给出栈回溯
set -u
cd "$(dirname "$0")/.."
ROOT=$(pwd)
TMP="$ROOT/tmp"
ELFTRACE="$ROOT/build/elftrace"
PROG="$TMP/prog_simple"
SNAP="$TMP/snap.elftrace"
SLICED="$TMP/sliced_dbg.elf"
CP="CHECKPOINT 3"

mkdir -p "$TMP"
gcc -O0 -g -o "$PROG" tests/prog_simple.c || exit 1

"$PROG" > "$TMP/dbg_frozen.out" 2>&1 &
PID=$!
for i in $(seq 1 200); do
    grep -q "$CP" "$TMP/dbg_frozen.out" 2>/dev/null && break
    sleep 0.05
done
sleep 0.3
grep -q "$CP" "$TMP/dbg_frozen.out" || { echo "FAIL: checkpoint not reached"; kill $PID; exit 1; }
"$ELFTRACE" freeze "$PID" -o "$SNAP" || exit 1

BIAS=$("$ELFTRACE" dump "$SNAP" | awk '/exe_bias/{print $2}')
ENTRY=$("$ELFTRACE" dump "$SNAP" | awk '/entry_pc/{print $2}')
[ "$BIAS" != "0x0" ] || { echo "FAIL: PIE bias is zero"; exit 1; }

"$ELFTRACE" build "$SNAP" -o "$SLICED" || exit 1

# 1. 符号地址 = 文件地址 + bias
MAIN_FILE=$(nm "$PROG" | awk '$3=="main"{print $1}')
MAIN_SLICED=$(nm "$SLICED" | awk '$3=="main"{print $1}')
EXPECT=$(printf "0x%x" $((0x$MAIN_FILE + BIAS)))
MAIN_SLICED="0x$(echo "$MAIN_SLICED" | sed 's/^0*//')"
[ "$MAIN_SLICED" = "$EXPECT" ] || { echo "FAIL: main addr $MAIN_SLICED != $EXPECT"; exit 1; }
echo "symbol main: $MAIN_SLICED (bias-adjusted) OK"

# 2. gdb 行号信息与运行时地址一致
L=$(timeout 60 gdb -batch -ex "file $SLICED" -ex "info line main" 2>/dev/null | grep "starts at address")
echo "$L" | grep -q "$EXPECT" || { echo "FAIL: line info address mismatch: $L (expect $EXPECT)"; exit 1; }
echo "line info: $L OK"

# 3. 冻结点注入 int3, gdb 运行切片应命中并给出源码位置/栈
"$ELFTRACE" build "$SNAP" -o "$SLICED" --breakpoint "$ENTRY" || exit 1
OUT=$(timeout 90 gdb -batch -ex "run" -ex "bt 2" -ex "info locals" "$SLICED" 2>/dev/null)
echo "$OUT" | grep -q "SIGTRAP" || { echo "FAIL: no SIGTRAP"; exit 1; }
echo "$OUT" | grep -q "prog_simple.c:" || { echo "FAIL: no source line in backtrace"; echo "$OUT"; exit 1; }
echo "$OUT" | grep -qE "^x = " || { echo "FAIL: no locals"; echo "$OUT"; exit 1; }
echo "gdb breakpoint at resume point OK"

echo "PASS: debug symbols preserved (bias, line info, gdb backtrace)"
exit 0
