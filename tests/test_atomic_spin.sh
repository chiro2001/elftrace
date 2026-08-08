#!/bin/bash
# aarch64: 多线程原子同步 (SPSC 有界队列 + 生产者自旋) strict 切片
#
# 两跑补偿流程:
#   Run 1 (校准): trace --atomic-replay → 侧车 + compensation.txt
#     (预估补偿指令比例 R_est 与触发放大系数 r = measured/orig)
#   Run 2 (正式): trace --atomic-replay --atomic-compensate <r1> →
#     检查点按原始指令数间隔触发, manifest 计数即原始计数
#   build: --from-count/--to-count 按原始计数选窗; 原子站点回放跳板
#     按"第几次读取"返回录制值 (自旋不再卡死); 窗口负载上限兜底退出
#   K 校准: 退出计数器 K 按 A/T 迭代, 使补偿指令比例 |A-T|/A ≤ 5%
#
# 断言:
#   1. 切片 rc=0 (不超时);
#   2. 目标阶段 (rt_sigreturn 后) 除 exit_group 外零 syscall;
#   3. 原子事件 > 0;
#   4. 补偿指令比例 ≤ 5%。
set -u
cd "$(dirname "$0")/.."
source tests/testlib.sh

if [ "$(uname -m)" != "aarch64" ]; then
    echo "SKIP: atomic SPSC 测试仅 aarch64 (--bm-strict + --atomic-replay)"
    exit 0
fi

tf_setup
tf_cleanup prog_spsc_spin
ELFTRACE="$TF_ELFTRACE"

echo "== [atomic] SPSC spin strict slice (two-run compensation) =="
gcc -O2 -g -pthread -o "$TF_TMP/prog_spsc_spin" tests/prog_spsc_spin.c \
    || exit 1

# ---------- Run 1: 校准 ----------
rm -rf "$TF_TMP/spsc_r1" "$TF_TMP/spsc_r2"
"$TF_TMP/prog_spsc_spin" 20000 8 10000 8000 2 \
    > "$TF_TMP/spsc_r1.out" 2>&1 &
PID=$!
sleep 0.3
timeout 300 "$ELFTRACE" trace "$PID" --every 50000000 \
    --out "$TF_TMP/spsc_r1" --atomic-replay \
    > "$TF_TMP/spsc_t1.log" 2>&1
wait $PID 2>/dev/null
[ -f "$TF_TMP/spsc_r1/atomics/compensation.txt" ] || {
    echo "FAIL: Run1 no compensation.txt"
    tail -5 "$TF_TMP/spsc_t1.log"
    exit 1
}
RN=$(awk '/^r_num/{print $2}' "$TF_TMP/spsc_r1/atomics/compensation.txt")
RD=$(awk '/^r_den/{print $2}' "$TF_TMP/spsc_r1/atomics/compensation.txt")
[ "${RN:-0}" -gt "${RD:-1}" ] || {
    echo "FAIL: Run1 bad ratio r_num=$RN r_den=$RD"; exit 1; }
echo "atomic: Run1 r=$RN/$RD"

# ---------- Run 2: 正式采集 (补偿触发) ----------
"$TF_TMP/prog_spsc_spin" 20000 8 10000 8000 2 \
    > "$TF_TMP/spsc_r2.out" 2>&1 &
PID=$!
sleep 0.3
timeout 300 "$ELFTRACE" trace "$PID" --every 50000000 \
    --out "$TF_TMP/spsc_r2" --atomic-replay \
    --atomic-compensate "$TF_TMP/spsc_r1/atomics/compensation.txt" \
    > "$TF_TMP/spsc_t2.log" 2>&1
wait $PID 2>/dev/null
NCK=$(wc -l < "$TF_TMP/spsc_r2/manifest.txt")
[ "$NCK" -ge 8 ] || { echo "FAIL: Run2 only $NCK checkpoints"; exit 1; }
[ -f "$TF_TMP/spsc_r2/atomics/events.bin" ] || {
    echo "FAIL: Run2 no events.bin"; exit 1; }

# ---------- 选窗: 有原子事件的中间窗口, 且退出点可计数 ----------
WIN=$(python3 - "$TF_TMP/spsc_r2" <<'EOF'
import struct, sys, os
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
    pc = u64(); insn = struct.unpack_from("<I", b, off)[0]
    off += 8
    sites.append(pc)
def ords(k):
    bb = open("%s/atomics/ckpt_%06d.bin" % (d, k), "rb").read()
    o = 24
    return [struct.unpack_from("<Q", bb, o + i * 24)[0] for i in range(n_sites)]
def states(k):
    bb = open("%s/atomics/ckpt_%06d.bin" % (d, k), "rb").read()
    o = 24
    return [(struct.unpack_from("<Q", bb, o + i * 24)[0],
             struct.unpack_from("<Q", bb, o + i * 24 + 8)[0],
             struct.unpack_from("<Q", bb, o + i * 24 + 16)[0])
            for i in range(n_sites)]
man = open(d + "/manifest.txt").read().splitlines()
cnt = [int(l.split()[0]) for l in man]
pcs = [int(l.split()[1], 16) for l in man]
total = cnt[-1]
ev = open(d + "/atomics/events.bin", "rb").read()
n_ev = struct.unpack_from("<Q", ev, 16)[0]
events = []
for i in range(n_ev):
    sid, ordv, addr, val = struct.unpack_from("<QQQQ", ev, 32 + i * 32)
    events.append((sid, ordv))
def site_events_between(sid, lo, hi):
    return any(e_s == sid and lo < e_o <= hi for (e_s, e_o) in events)
# 取中后段 (消费者活跃区), 要求有事件
for frac in (0.70, 0.75, 0.60, 0.80):
    lo_c = int(total * frac)
    from_k = next((k for k in range(len(cnt)) if cnt[k] >= lo_c), None)
    if from_k is None or from_k + 2 >= len(cnt):
        continue
    st = states(from_k)
    for to_k in range(from_k + 2, min(from_k + 5, len(cnt))):
        st2 = states(to_k)
        if pcs[to_k] in sites:
            continue
        if any(st2[i][0] > st[i][0] and
               site_events_between(i, st[i][0], st2[i][0])
               for i in range(n_sites)):
            print(cnt[from_k], cnt[to_k])
            sys.exit(0)
sys.exit(2)
EOF
)
case $? in
    0) ;;
    2) echo "FAIL: no suitable window with atomic events"; exit 1 ;;
    *) echo "FAIL: window selection error"; exit 1 ;;
esac
FROM_C=${WIN%% *}
TO_C=${WIN##* }
echo "atomic: window from-count=$FROM_C to-count=$TO_C"

# ---------- build + K 校准 (补偿指令比例 ≤ 5%) ----------
T=$((TO_C - FROM_C))
A0=0
K0=0
for iter in 1 2 3; do
    EXTRA=()
    [ "$K0" -gt 0 ] && EXTRA=(--bm-exit-count "$K0")
    tf_build /dev/null "$TF_TMP/spsc_slice.elf" --mode baremetal --bm-strict \
        --checkpoints "$TF_TMP/spsc_r2" \
        --from-count "$FROM_C" --to-count "$TO_C" \
        --stack-reserve 67108864 "${EXTRA[@]}" \
        > "$TF_TMP/spsc_build.log" 2>&1 || {
            echo "FAIL: build (iter $iter)"; tail -5 "$TF_TMP/spsc_build.log"; exit 1; }
    grep -q "count target insn" "$TF_TMP/spsc_build.log" || {
        echo "FAIL: exit not countable (iter $iter)"; tail -5 "$TF_TMP/spsc_build.log"; exit 1; }
    K=$(grep -oE "K=[0-9]+" "$TF_TMP/spsc_build.log" | head -1 | cut -d= -f2)
    [ -n "$K" ] || K=0
    timeout 120 perf stat -e instructions "$TF_TMP/spsc_slice.elf" \
        > /dev/null 2> "$TF_TMP/spsc.perf"
    RC=$?
    [ "$RC" = 0 ] || { echo "FAIL: slice rc=$RC (deadlock?)"; exit 1; }
    A=$(grep "instructions" "$TF_TMP/spsc.perf" \
        | grep -oE "[0-9,]+" | head -1 | tr -d ",")
    echo "atomic: iter $iter K=$K A=$A T=$T"
    A0=${A:-0}
    # 收敛: |A-T|/A <= 5%
    if [ "$A0" -gt 0 ]; then
        D=$((A0 > T ? A0 - T : T - A0))
        if [ $((D * 100 / A0)) -le 5 ]; then
            break
        fi
    fi
    if [ "$iter" -lt 3 ] && [ "$K" -gt 0 ] && [ "$A0" -gt 0 ]; then
        K0=$((K * T / A0))
        [ "$K0" -gt 0 ] || K0=1
    fi
done
[ "$A0" -gt 0 ] || { echo "FAIL: no A"; exit 1; }
D=$((A0 > T ? A0 - T : T - A0))
R=$((D * 100 / A0))
[ "$R" -le 5 ] || { echo "FAIL: compensation ratio $R% > 5%"; exit 1; }

# ---------- 目标阶段零 syscall ----------
timeout 120 strace -o "$TF_TMP/spsc_slice.strace" \
    "$TF_TMP/spsc_slice.elf" > /dev/null 2>&1
RC=$?
[ "$RC" = 0 ] || { echo "FAIL: strace slice rc=$RC"; exit 1; }
AFTER=$(awk '/rt_sigreturn/{f=1} f' "$TF_TMP/spsc_slice.strace")
if echo "$AFTER" | grep -E "openat|read\(|write\(|ioctl|mmap|brk|futex|clone"; then
    echo "FAIL: target-phase real syscalls"
    echo "$AFTER"
    exit 1
fi
grep -q "exit_group" "$TF_TMP/spsc_slice.strace" \
    || { echo "FAIL: no exit_group"; exit 1; }

NEV=$(python3 - "$TF_TMP/spsc_r2" <<'EOF'
import struct, sys
b = open(sys.argv[1] + "/atomics/events.bin", "rb").read()
print(struct.unpack_from("<Q", b, 16)[0])
EOF
)
[ "$NEV" -gt 0 ] || { echo "FAIL: no recorded atomic events"; exit 1; }

tf_pass "atomic SPSC two-run (rc=0, clean, ratio $R%, $NEV events)"
tf_finish
