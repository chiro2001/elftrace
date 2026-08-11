#!/bin/bash
# aarch64: 单 load 自旋窗口"结束在自旋内"的 run-burn K 融合验收
#
# 窗口两端都选在自旋段内 (检查点 pc == 自旋站点, 站点计数仍在增长):
# build 把退出站点融合进 burn 块 —— 无独立 K counter, 到达 ordinal
# 预算 (load_limit) 时干净退出 (rc=0)。预期 A ≈ T_spin_est (纯自旋
# 窗口无尾部越界, 仅首访问 + 每 run 边界固定开销)。
#
# 断言:
#   1. 构建日志含 "run-burn spin site" 与 "[fused-exit]" 与
#      "fused exit site ... removed";
#   2. 切片 rc=0 (干净退出, 不是 67 bail);
#   3. 0.98 <= A/T_spin_est <= 1.05;
#   4. 目标阶段零 syscall (strace)。
set -u
cd "$(dirname "$0")/.."
source tests/testlib.sh

if [ "$(uname -m)" != "aarch64" ]; then
    echo "SKIP: spin-single-saturated 测试仅 aarch64"
    exit 0
fi

tf_setup
tf_cleanup prog_spin_single
ELFTRACE="$TF_ELFTRACE"

echo "== [atomic] single-load spin window ending inside spin (fused exit) =="
gcc -O2 -g -pthread -o "$TF_TMP/prog_spin_single" \
    tests/prog_spin_single.c || exit 1

# 自旋 3s; 检查点 10M (补偿后每 ~10M 原始指令一个, 自旋段内会有大量
# 检查点, 提高"检查点 pc == 自旋站点"的命中率, 融合才可触发)
rm -rf "$TF_TMP/ss_r1" "$TF_TMP/ss_r2"
"$TF_TMP/prog_spin_single" 3000000 300000000 \
    > "$TF_TMP/ss_r1.out" 2>&1 &
PID=$!
sleep 0.3
ELFTRACE_CAS_RECORD=1 timeout 900 "$ELFTRACE" trace "$PID" \
    --every 10000000 --out "$TF_TMP/ss_r1" --atomic-replay \
    > "$TF_TMP/ss_t1.log" 2>&1
wait $PID 2>/dev/null
[ -f "$TF_TMP/ss_r1/atomics/compensation.txt" ] || {
    echo "FAIL: Run1 no compensation.txt"; tail -5 "$TF_TMP/ss_t1.log"; exit 1; }

"$TF_TMP/prog_spin_single" 3000000 300000000 \
    > "$TF_TMP/ss_r2.out" 2>&1 &
PID=$!
sleep 0.3
ELFTRACE_CAS_RECORD=1 timeout 900 "$ELFTRACE" trace "$PID" \
    --every 10000000 --out "$TF_TMP/ss_r2" --atomic-replay \
    --atomic-compensate "$TF_TMP/ss_r1/atomics/compensation.txt" \
    > "$TF_TMP/ss_t2.log" 2>&1
wait $PID 2>/dev/null
NCK=$(wc -l < "$TF_TMP/ss_r2/manifest.txt")
[ "$NCK" -ge 20 ] || { echo "FAIL: Run2 only $NCK checkpoints"; exit 1; }

# 选窗: 自旋站点, 两个"检查点 pc == 站点且计数增长"的位置
WIN=$(python3 - "$TF_TMP/ss_r2" <<'EOF'
import struct, sys
d = sys.argv[1]
b = open(d + "/atomics/sites.bin", "rb").read()
off = 0
def u64():
    global off
    v = struct.unpack_from("<Q", b, off)[0]; off += 8; return v
assert u64() == 0x53495445 and u64() == 1
n_sites = u64(); u64(); u64(); n_pages = u64()
u64(); u64(); u64()
tramp_pages = []
for i in range(n_pages):
    tramp_pages.append(u64())
sites = []
for i in range(n_sites):
    pc = u64(); w, kind = struct.unpack_from("<II", b, off); off += 8
    sites.append((pc, kind))
def counts(k):
    bb = open("%s/atomics/ckpt_%06d.bin" % (d, k), "rb").read()
    return [struct.unpack_from("<QQQ", bb, 24 + i * 24)[0]
            for i in range(n_sites)]
man = open(d + "/manifest.txt").read().splitlines()
cnt = [int(l.split()[0]) for l in man]
pcs = [int(l.split()[1], 16) for l in man]
n = len(cnt)
tot = [0] * n_sites
for k in range(1, n):
    c0 = counts(k - 1); c1 = counts(k)
    for i in range(n_sites):
        if sites[i][1] <= 3 and c1[i] > c0[i]:
            tot[i] += c1[i] - c0[i]
best = max(range(n_sites), key=lambda i: tot[i] if sites[i][1] <= 3 else -1)
if tot[best] < 1000000:
    sys.exit(2)
pc = sites[best][0]
# 计数仍在增长、且 pc 不在记录跳板页的检查点 (跳板页 pc 作为窗口终点
# 由 build 归一化到自旋站点, 但作为窗口起点会导致切片从采集跳板恢复)
hits = []
prev = [counts(k)[best] for k in range(n)]
for k in range(1, n):
    if prev[k] > prev[k - 1] and not any(
            pp <= pcs[k] < pp + 4096 for pp in tramp_pages):
        hits.append(k)
if len(hits) < 5:
    sys.exit(2)
from_k = hits[2]
to_k = hits[4]
if to_k - from_k < 1 or prev[to_k] <= prev[from_k]:
    sys.exit(2)
print(best, hex(pc), cnt[from_k], cnt[to_k], prev[from_k], prev[to_k],
      hex(pcs[to_k]))
EOF
)
case $? in
    0) ;;
    2) echo "FAIL: 未找到两端都在自旋内且 pc==站点 的检查点对 (重试/加密检查点)"; exit 1 ;;
    *) echo "FAIL: window selection error"; exit 1 ;;
esac
read -r SPIN_ID SPIN_PC FROM_C TO_C SPIN_FROM SPIN_TO TO_PC <<EOF
$WIN
EOF
T_SPIN_EST=$(( (SPIN_TO - SPIN_FROM) * 2 ))
echo "atomic: fused window pc=$SPIN_PC from=$FROM_C to=$TO_C " \
     "spin_accesses=$((SPIN_TO - SPIN_FROM)) T_spin_est=$T_SPIN_EST " \
     "to_pc=$TO_PC"

tf_build /dev/null "$TF_TMP/ss_slice.elf" --mode baremetal --bm-strict \
    --checkpoints "$TF_TMP/ss_r2" \
    --from-count "$FROM_C" --to-count "$TO_C" \
    --stack-reserve 67108864 > "$TF_TMP/ss_build.log" 2>&1 \
    || { echo "FAIL: build"; tail -8 "$TF_TMP/ss_build.log"; exit 1; }
grep -q "run-burn spin site" "$TF_TMP/ss_build.log" \
    && grep -q "fused-exit" "$TF_TMP/ss_build.log" \
    && grep -q "fused exit site .* removed" "$TF_TMP/ss_build.log" || {
    echo "FAIL: 构建未出现 run-burn 融合标记"
    grep -E "run-burn|fused|exit" "$TF_TMP/ss_build.log" | tail -5
    exit 1; }

timeout 120 strace -o "$TF_TMP/ss_slice.strace" \
    "$TF_TMP/ss_slice.elf" > /dev/null 2>&1
RC=$?
[ "$RC" = 0 ] || { echo "FAIL: slice rc=$RC (期望 0 干净退出)"; exit 1; }
AFTER=$(awk '/rt_sigreturn/{f=1; next} f' "$TF_TMP/ss_slice.strace")
if echo "$AFTER" | grep -E "openat|read\(|write\(|ioctl\(|mmap|brk|futex|clone"; then
    echo "FAIL: 目标阶段出现真实 syscall"; echo "$AFTER"; exit 1
fi
grep -q "exit_group(0)" "$TF_TMP/ss_slice.strace" \
    || { echo "FAIL: 无 exit_group(0)"; exit 1; }

timeout 120 perf stat -e instructions "$TF_TMP/ss_slice.elf" \
    > /dev/null 2> "$TF_TMP/ss.perf"
A=$(grep "instructions" "$TF_TMP/ss.perf" \
    | grep -oE "[0-9,]+" | head -1 | tr -d ",")
A=${A:-0}
[ "$A" -gt 0 ] || { echo "FAIL: 无指令数"; exit 1; }
MR=$((A * 100 / T_SPIN_EST))
echo "atomic: A=$A T_spin_est=$T_SPIN_EST multiplier=$(printf '%d.%02d' $((MR / 100)) $((MR % 100)))x"
if awk -v a=$A -v t=$T_SPIN_EST 'BEGIN{exit !(a*100 >= t*98 && a*100 <= t*105)}'; then
    tf_pass "atomic run-burn fused exit (rc=0, A/T_spin_est ∈ [0.98,1.05])"
else
    tf_fail "fused exit 倍率越界 (A/T_spin_est=$(printf '%d.%02d' $((MR / 100)) $((MR % 100)))x)"
fi
tf_finish
