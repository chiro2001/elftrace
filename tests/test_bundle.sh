#!/bin/bash
# 测试: trace bundle (归档) 格式
# 1. trace 采集检查点 (差异格式)
# 2. bundle 打包为单文件
# 3. build --checkpoints 从 bundle 组装区间切片, 指令数正确
# 4. bundle --unpack 解包, 与原始目录一致
set -u
cd "$(dirname "$0")/.."
source tests/testlib.sh

tf_setup
tf_cleanup prog_cpp prog_bundle
N=5000000
PROG="$TF_TMP/prog_bundle"
CKPTS="$TF_TMP/ckpts_bundle"
BUNDLE="$TF_TMP/trace.bundle"
UNPACK="$TF_TMP/bundle_unpack"

g++ -O2 -o "$PROG" tests/prog_cpp.cpp || { echo "FAIL: compile"; exit 1; }

# 1. trace 采集
rm -rf "$CKPTS" "$UNPACK"
tf_run_bg "tr" "$PROG"
sleep 0.3
timeout 8 "$TF_ELFTRACE" trace "$TF_PID" --every "$N" --out "$CKPTS" \
    > /dev/null 2>&1
tf_cleanup prog_cpp prog_bundle
[ -f "$CKPTS/manifest.txt" ] || { echo "FAIL: no manifest"; exit 1; }

# 2. bundle 打包
"$TF_ELFTRACE" bundle "$CKPTS" -o "$BUNDLE" >/dev/null 2>&1 \
    || { echo "FAIL: bundle"; exit 1; }
NCKPT=$(wc -l < "$CKPTS/manifest.txt")
[ "$NCKPT" -ge 10 ] || { echo "FAIL: only $NCKPT checkpoints"; exit 1; }
echo "trace: $NCKPT checkpoints"

# 3. build 从 bundle 组装区间切片 (from 3 to 8 = 25m 条)
"$TF_ELFTRACE" build /dev/null -o "$TF_TMP/slice_bun.elf" --mode real \
    --checkpoints "$BUNDLE" --from 3 --to 8 >/dev/null 2>&1 \
    || { echo "FAIL: build from bundle"; exit 1; }
: > "$TF_TMP/tr.out"
timeout 90 "$TF_TMP/slice_bun.elf" > /dev/null 2>&1
CNT=$(tr -d '\0' < "$TF_TMP/tr.out" | grep "IPC:" | tail -1 \
       | grep -oE "[0-9]+")
EXP=$(( (8 - 3) * N ))
[ -n "$CNT" ] || { echo "FAIL: no IPC count"; exit 1; }
OK=$(python3 -c "print(0 if abs(int('$CNT') - $EXP) / $EXP < 0.05 else 1)")
[ "$OK" = 0 ] || { echo "FAIL: cnt=$CNT expect=$EXP"; exit 1; }
echo "  bundle slice: cnt=$CNT expect=$EXP OK"

# 4. 解包一致性
"$TF_ELFTRACE" bundle "$BUNDLE" --unpack -o "$UNPACK" >/dev/null 2>&1 \
    || { echo "FAIL: unpack"; exit 1; }
diff -q "$CKPTS/manifest.txt" "$UNPACK/manifest.txt" >/dev/null \
    || { echo "FAIL: manifest mismatch"; exit 1; }
for f in ckpt_000000.elftrace ckpt_000001.elftrace; do
    cmp -s "$CKPTS/$f" "$UNPACK/$f" || { echo "FAIL: $f mismatch"; exit 1; }
done
echo "  unpack consistent"

tf_cleanup prog_cpp prog_bundle
echo "PASS: trace bundle (pack/build-from-bundle/unpack consistent)"
exit 0
