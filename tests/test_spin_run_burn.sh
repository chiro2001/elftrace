#!/bin/bash
# aarch64: run-burn 整 run 烧录原型验收 (单 load 自旋循环)
#
# 负载: prog_spin_single —— 主线程 (切片目标) 在 worker 置位前全程
# 单 load 自旋 (ldar; cbz → site), 之后进入 busy 循环并退出。
# busy 尾部必须长到覆盖一个补偿后检查点间隔 (自旋采集膨胀 ~20x,
# 触发间隔被放大后尾部太短会没有"自旋后"检查点)。
# 窗口: 从自旋段中段取到自旋结束后的 checkpoint。
#
# 断言:
#   1. run-burn 构建日志含 "run-burn spin site" (模式确实命中);
#   2. 切片 rc ∈ {0,67};
#   3. 同窗口同 K 下, run-burn 动态指令数 < 逐访问基线 (A_burn < A_base);
#   4. 报告指令倍率 A/T 与相对降幅 (run-burn 目标是把倍率拉到 ~1)。
set -u
cd "$(dirname "$0")/.."
source tests/testlib.sh

if [ "$(uname -m)" != "aarch64" ]; then
    echo "SKIP: spin-run-burn 测试仅 aarch64"
    exit 0
fi

tf_setup
tf_cleanup prog_spin_single
ELFTRACE="$TF_ELFTRACE"

echo "== [atomic] single-load spin run-burn (A_burn vs A_base) =="
gcc -O2 -g -pthread -o "$TF_TMP/prog_spin_single" \
    tests/prog_spin_single.c || exit 1

# ---------- Run 1: 补偿比例校准 ----------
rm -rf "$TF_TMP/srb_r1" "$TF_TMP/srb_r2"
"$TF_TMP/prog_spin_single" 3000000 300000000 \
    > "$TF_TMP/srb_r1.out" 2>&1 &
PID=$!
sleep 0.3
ELFTRACE_CAS_RECORD=1 timeout 600 "$ELFTRACE" trace "$PID" \
    --every 50000000 --out "$TF_TMP/srb_r1" --atomic-replay \
    > "$TF_TMP/srb_t1.log" 2>&1
wait $PID 2>/dev/null
[ -f "$TF_TMP/srb_r1/atomics/compensation.txt" ] || {
    echo "FAIL: Run1 no compensation.txt"
    tail -5 "$TF_TMP/srb_t1.log"
    exit 1
}

# ---------- Run 2: 正式采集 ----------
"$TF_TMP/prog_spin_single" 3000000 300000000 \
    > "$TF_TMP/srb_r2.out" 2>&1 &
PID=$!
sleep 0.3
ELFTRACE_CAS_RECORD=1 timeout 600 "$ELFTRACE" trace "$PID" \
    --every 50000000 --out "$TF_TMP/srb_r2" --atomic-replay \
    --atomic-compensate "$TF_TMP/srb_r1/atomics/compensation.txt" \
    > "$TF_TMP/srb_t2.log" 2>&1
wait $PID 2>/dev/null
NCK=$(wc -l < "$TF_TMP/srb_r2/manifest.txt")
[ "$NCK" -ge 8 ] || { echo "FAIL: Run2 only $NCK checkpoints"; exit 1; }

# ---------- 选窗: 自旋站点计数增长的窗口中段 → 自旋结束后 ----------
# 注意: 采集期 perf 样本的 PC 常落在记录跳板内, 不能用"检查点 pc ==
# 站点"识别自旋; 正确信号是站点执行计数 (atomics/ckpt_*.bin) 的增长。
WIN=$(python3 - "$TF_TMP/srb_r2" <<'EOF'
import struct
import sys
d = sys.argv[1]
b = open(d + "/atomics/sites.bin", "rb").read()
off = 0
def u64():
    global off
    v = struct.unpack_from("<Q", b, off)[0]
    off += 8
    return v
assert u64() == 0x53495445 and u64() == 1
n_sites = u64(); u64(); u64(); n_pages = u64()
u64(); u64(); u64()
off += n_pages * 8
sites = []
for i in range(n_sites):
    pc = u64()
    w, kind = struct.unpack_from("<II", b, off)
    off += 8
    sites.append((pc, kind))
def counts(k):
    bb = open("%s/atomics/ckpt_%06d.bin" % (d, k), "rb").read()
    return [struct.unpack_from("<QQQ", bb, 24 + i * 24)[0]
            for i in range(n_sites)]
man = open(d + "/manifest.txt").read().splitlines()
cnt = [int(l.split()[0]) for l in man]
pcs = [int(l.split()[1], 16) for l in man]
n = len(cnt)
if n < 6:
    sys.exit(2)
# 自旋站点 = kind<=3 中累计执行增量最大的站点
tot = [0] * n_sites
for k in range(1, n):
    c0 = counts(k - 1)
    c1 = counts(k)
    for i in range(n_sites):
        if sites[i][1] <= 3 and c1[i] > c0[i]:
            tot[i] += c1[i] - c0[i]
best = max(range(n_sites), key=lambda i: tot[i] if sites[i][1] <= 3 else -1)
if tot[best] < 1000000:
    sys.exit(2)
sc = [counts(k)[best] for k in range(n)]
total_gain = sc[-1] - sc[0]
target = sc[0] + total_gain // 3
from_k = None
for k in range(1, n):
    if sc[k] >= target:
        from_k = k
        break
if from_k is None or from_k >= n - 2:
    sys.exit(2)
site_set = {s[0] for s in sites}
to_k = None
for k in range(from_k + 1, n):
    if sc[k] == sc[k - 1] and pcs[k] not in site_set:
        to_k = k
        break
if to_k is None:
    sys.exit(2)
print(best, hex(sites[best][0]), cnt[from_k], cnt[to_k],
      sc[from_k], sc[to_k])
EOF
)
case $? in
    0) ;;
    2) echo "FAIL: 未找到自旋窗口 (检查点太少或自旋/尾部比例异常)"; exit 1 ;;
    *) echo "FAIL: window selection error"; exit 1 ;;
esac
read -r SPIN_ID SPIN_PC FROM_C TO_C SPIN_FROM SPIN_TO <<EOF
$WIN
EOF
T=$((TO_C - FROM_C))
[ "$T" -gt 100000000 ] || {
    echo "FAIL: window too small T=$T"; exit 1; }
echo "atomic: spin window pc=$SPIN_PC site=$SPIN_ID from=$FROM_C to=$TO_C T=$T"
echo "atomic: spin accesses=$((SPIN_TO - SPIN_FROM)) (窗口内)"
# T_orig 用 build 账本 T_ref (ck_orig 差: measured − Σord×(base−1)):
# manifest 名义计数 (k×every) 用全局 r 缩放, 自旋阶段会被低缩放
# (~5x 而非 ~20x), 不是精确原始口径。
T_ORIG=0

# ---------- 测量: 基线 (逐访问) vs run-burn ----------
measure() {  # $1 = 标签, $2 = 额外构建参数
    local label="$1" extra="${2:-}"
    tf_build /dev/null "$TF_TMP/srb_slice.elf" --mode baremetal \
        --bm-strict --checkpoints "$TF_TMP/srb_r2" \
        --from-count "$FROM_C" --to-count "$TO_C" \
        --stack-reserve 67108864 $extra \
        > "$TF_TMP/srb_build.log" 2>&1 || {
        echo "FAIL: build $label"; exit 1; }
    if [ "$label" = burn ]; then
        T_ORIG=$(grep -oE "T_ref=[0-9]+" "$TF_TMP/srb_build.log" \
            | head -1 | cut -d= -f2)
        T_ORIG=${T_ORIG:-0}
        [ "$T_ORIG" -gt 10000000 ] || {
            echo "FAIL: build 无有效 T_ref (T_orig=$T_ORIG)"; exit 1; }
        echo "atomic: T_orig=$T_ORIG (build 账本原始指令口径)"
    fi
    local rc
    timeout 120 perf stat -e instructions "$TF_TMP/srb_slice.elf" \
        > /dev/null 2> "$TF_TMP/srb.perf"
    rc=$?
    [ "$rc" = 0 ] || [ "$rc" = 67 ] || {
        echo "FAIL: $label slice rc=$rc"; exit 1; }
    local a
    a=$(grep "instructions" "$TF_TMP/srb.perf" \
        | grep -oE "[0-9,]+" | head -1 | tr -d ",")
    a=${a:-0}
    echo "$label: rc=$rc A=$a T=$T"
    eval "${label}_A=$a"
}

measure base "--no-atomic-run-burn"
A_BASE=${base_A:-0}
measure burn
A_BURN=${burn_A:-0}

[ "$A_BASE" -gt 0 ] && [ "$A_BURN" -gt 0 ] || {
    echo "FAIL: invalid A (base=$A_BASE burn=$A_BURN)"; exit 1; }

grep -q "run-burn spin site" "$TF_TMP/srb_build.log" || {
    echo "FAIL: run-burn 未命中自旋站点 (构建日志无 run-burn spin site)"
    exit 1; }

MB=$((A_BASE * 100 / T_ORIG))
MR=$((A_BURN * 100 / T_ORIG))
echo "atomic: multiplier base=$(printf '%d.%02d' $((MB / 100)) $((MB % 100)))x " \
     "burn=$(printf '%d.%02d' $((MR / 100)) $((MR % 100)))x (T_orig=$T_ORIG)"

if [ "$A_BURN" -lt "$A_BASE" ]; then
    tf_pass "atomic run-burn 降低动态指令数 (A_burn=$A_BURN < A_base=$A_BASE)"
else
    tf_fail "run-burn 未降低动态指令数 (A_burn=$A_BURN >= A_base=$A_BASE)"
fi
if awk -v b=$MR -v g=115 'BEGIN{exit !(b < g)}'; then
    tf_pass "atomic run-burn 指令倍率 < 1.15x (multiplier=$(printf '%d.%02d' $((MR / 100)) $((MR % 100)))x)"
else
    tf_fail "run-burn 指令倍率 >= 1.15x (multiplier=$(printf '%d.%02d' $((MR / 100)) $((MR % 100)))x)"
fi
tf_finish
