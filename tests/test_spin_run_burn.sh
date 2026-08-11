#!/bin/bash
# aarch64: run-burn 整 run 烧录原型验收 (单 load 自旋循环)
#
# 负载: prog_spin_single —— 主线程 (切片目标) 在 worker 置位前全程
# 单 load 自旋 (ldar; cbz → site), 之后进入 busy 循环并退出。
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
"$TF_TMP/prog_spin_single" 1000000 30000000 \
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
"$TF_TMP/prog_spin_single" 1000000 30000000 \
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

# ---------- 选窗: 从自旋段 (连续同 pc 检查点) 到自旋后 ----------
WIN=$(python3 - "$TF_TMP/srb_r2" <<'EOF'
import sys
d = sys.argv[1]
b = open(d + "/atomics/sites.bin", "rb").read()
off = 0
def u64():
    global off
    v = __import__("struct").unpack_from("<Q", b, off)[0]
    off += 8
    return v
assert u64() == 0x53495445 and u64() == 1
n_sites = u64(); u64(); u64(); n_pages = u64()
u64(); u64(); u64()
off += n_pages * 8
site_pcs = set()
for i in range(n_sites):
    pc = u64()
    w, kind = __import__("struct").unpack_from("<II", b, off)
    off += 8
    if kind <= 3:
        site_pcs.add(pc)
man = open(d + "/manifest.txt").read().splitlines()
cnt = [int(l.split()[0]) for l in man]
pcs = [int(l.split()[1], 16) for l in man]
# 连续同 pc 最长的站点 = 自旋站点
best = -1
best_pc = None
i = 0
while i < len(pcs):
    if pcs[i] in site_pcs:
        j = i
        while j < len(pcs) and pcs[j] == pcs[i]:
            j += 1
        if j - i > best:
            best = j - i
            best_pc = pcs[i]
        i = j
    else:
        i += 1
if best < 3 or best_pc is None:
    sys.exit(2)
# from = 自旋段第 2 个检查点 (确保 run 中段), to = 自旋后第一个检查点
run = []
for k, pc in enumerate(pcs):
    if pc == best_pc:
        run.append(k)
to_k = run[-1] + 1
if to_k >= len(cnt) or to_k - run[0] < 2:
    sys.exit(2)
from_k = run[0] + 1
print(best, hex(best_pc), cnt[from_k], cnt[to_k])
EOF
)
case $? in
    0) ;;
    2) echo "FAIL: 未找到连续自旋窗口 (spin_pc=$WIN)"; exit 1 ;;
    *) echo "FAIL: window selection error"; exit 1 ;;
esac
read -r SPIN_HITS SPIN_PC FROM_C TO_C <<EOF
$WIN
EOF
T=$((TO_C - FROM_C))
[ "$T" -gt 100000000 ] || {
    echo "FAIL: window too small T=$T"; exit 1; }
echo "atomic: spin window pc=$SPIN_PC hits=$SPIN_HITS from=$FROM_C to=$TO_C T=$T"

# ---------- 测量: 基线 (逐访问) vs run-burn ----------
measure() {  # $1 = 标签, $2 = 额外构建参数
    local label="$1" extra="${2:-}"
    tf_build /dev/null "$TF_TMP/srb_slice.elf" --mode baremetal \
        --bm-strict --checkpoints "$TF_TMP/srb_r2" \
        --from-count "$FROM_C" --to-count "$TO_C" \
        --stack-reserve 67108864 $extra \
        > "$TF_TMP/srb_build.log" 2>&1 || {
        echo "FAIL: build $label"; exit 1; }
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

MB=$((A_BASE * 100 / T))
MR=$((A_BURN * 100 / T))
echo "atomic: multiplier base=$((MB / 100)).$((MB % 100))x " \
     "burn=$((MR / 100)).$((MR % 100))x (T=$T)"

if [ "$A_BURN" -lt "$A_BASE" ]; then
    tf_pass "atomic run-burn 降低动态指令数 (A_burn=$A_BURN < A_base=$A_BASE)"
else
    tf_fail "run-burn 未降低动态指令数 (A_burn=$A_BURN >= A_base=$A_BASE)"
fi
tf_finish
