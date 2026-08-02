#!/bin/bash
# 基础功能测试: 冻结一个运行中的循环程序, 组装为 ELF, 恢复执行并验证等价性。
#
# 验证方式:
#   1. 参考运行: 目标程序完整跑完, 记录输出与退出码 (基准)
#   2. 切片运行: 冻结在 CHECKPOINT 3 之后, 组装, 运行切片
#   3. 断言: 切片输出是基准输出的一个后缀 (从冻结点继续), 退出码一致
set -u
cd "$(dirname "$0")/.."
ROOT=$(pwd)
TMP="$ROOT/tmp"
ELFTRACE="$ROOT/build/elftrace"
PROG="$TMP/prog_simple"
SNAP="$TMP/snap.elftrace"
SLICED="$TMP/sliced.elf"
CP="CHECKPOINT 3"

mkdir -p "$TMP"
gcc -O0 -g -o "$PROG" tests/prog_simple.c || exit 1

# 1. 基准运行
"$PROG" > "$TMP/ref.out" 2>&1
REF_RC=$?
echo "ref rc=$REF_RC last=$(tail -1 "$TMP/ref.out")"

# 2. 切片: 后台运行目标, 等待 CHECKPOINT 3 出现后冻结
"$PROG" > "$TMP/frozen.out" 2>&1 &
PID=$!
for i in $(seq 1 200); do
    grep -q "$CP" "$TMP/frozen.out" 2>/dev/null && break
    sleep 0.05
done
sleep 0.3   # 确保已进入下一轮计算循环 (用户态)
grep -q "$CP" "$TMP/frozen.out" || { echo "FAIL: checkpoint not reached"; kill $PID; exit 1; }

"$ELFTRACE" freeze "$PID" -o "$SNAP" || { echo "FAIL: freeze"; exit 1; }

# 3. 组装
"$ELFTRACE" build "$SNAP" -o "$SLICED" --mode real || { echo "FAIL: build"; exit 1; }

# 4. 运行切片
timeout 60 "$SLICED" > "$TMP/sliced.out" 2>&1
SLICED_RC=$?
echo "sliced rc=$SLICED_RC last=$(tail -1 "$TMP/sliced.out")"

# 5. 断言
if [ "$SLICED_RC" != "$REF_RC" ]; then
    echo "FAIL: exit code $SLICED_RC != $REF_RC"
    echo "--- sliced.out ---"; cat "$TMP/sliced.out"
    exit 1
fi
# 切片进程的 fd 1 指向冻结前打开的文件 (frozen.out), 恢复后继续写入原文件,
# 因此完整输出 (CHECKPOINT 0..9 + DONE) 应在 frozen.out 中, 且与基准一致。
if ! diff -q "$TMP/frozen.out" "$TMP/ref.out" >/dev/null; then
    echo "FAIL: frozen.out != ref.out"
    echo "--- frozen.out ---"; cat "$TMP/frozen.out"
    echo "--- ref.out ---"; cat "$TMP/ref.out"
    exit 1
fi
# 冻结时已输出到第 3 行, 恢复后继续从 CHECKPOINT 4 开始
if ! grep -q "^CHECKPOINT 4" "$TMP/frozen.out" || grep -q "^CHECKPOINT 4" "$TMP/sliced.out"; then
    echo "FAIL: continuation markers wrong"
    exit 1
fi

echo "PASS: basic feature (continue from freeze point, rc=$SLICED_RC)"
exit 0
