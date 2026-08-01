#!/bin/bash
# 角落条件测试: 大内存程序 (128MB 匿名映射, payload ~130MB)
#
# 验证:
#   1. 大 payload 切片正确组装/恢复
#   2. 映射内容完整 (随机访问计算 + 最终 checksum 与基准一致)
#   3. 输出/退出码与基准一致
set -u
cd "$(dirname "$0")/.."
ROOT=$(pwd)
TMP="$ROOT/tmp"
ELFTRACE="$ROOT/build/elftrace"
PROG="$TMP/prog_bigmem"
SNAP="$TMP/snap_bigmem.elftrace"
SLICED="$TMP/sliced_bigmem.elf"

mkdir -p "$TMP"
gcc -O0 -o "$PROG" tests/prog_bigmem.c || exit 1

# 1. 基准 (~7s)
"$PROG" > "$TMP/bigmem_ref.out" 2>&1
REF_RC=$?
grep -q "^DONE" "$TMP/bigmem_ref.out" || { echo "FAIL: ref has no DONE"; exit 1; }
echo "ref rc=$REF_RC $(grep '^DONE' "$TMP/bigmem_ref.out" | head -c 60)..."

# 2. 冻结: 等待 CKPT 2 出现后冻结 (计算循环中)
"$PROG" > "$TMP/bigmem_frozen.out" 2>&1 &
PID=$!
for i in $(seq 1 300); do
    grep -q "CKPT 2" "$TMP/bigmem_frozen.out" 2>/dev/null && break
    sleep 0.05
done
sleep 0.4
grep -q "CKPT 2" "$TMP/bigmem_frozen.out" || { echo "FAIL: CKPT 2 not seen"; kill -9 $PID; exit 1; }

"$ELFTRACE" freeze "$PID" -o "$SNAP" > "$TMP/bigmem_freeze.out" 2>&1
[ $? = 0 ] || { echo "FAIL: freeze"; kill -9 $PID; exit 1; }
kill -9 $PID 2>/dev/null; wait $PID 2>/dev/null
PAYLOAD=$(grep -o "[0-9]* bytes payload" "$TMP/bigmem_freeze.out" | head -1)
echo "freeze OK ($PAYLOAD)"

# 3. 组装 + 运行切片
"$ELFTRACE" build "$SNAP" -o "$SLICED" >/dev/null 2>&1 || { echo "FAIL: build"; exit 1; }
timeout 90 "$SLICED" > /dev/null 2>&1
S_RC=$?
[ "$S_RC" = "$REF_RC" ] || { echo "FAIL: sliced rc=$S_RC != ref $REF_RC"; exit 1; }

# 4. 断言: 完整输出一致 (含 128MB 内容校验和)
diff -q "$TMP/bigmem_frozen.out" "$TMP/bigmem_ref.out" >/dev/null \
    || { echo "FAIL: output mismatch"; diff "$TMP/bigmem_frozen.out" "$TMP/bigmem_ref.out" | head -5; exit 1; }
grep -q "^DONE" "$TMP/bigmem_frozen.out" || { echo "FAIL: no DONE"; exit 1; }

echo "PASS: big memory slice ($PAYLOAD, rc=$S_RC, checksum identical)"
exit 0
