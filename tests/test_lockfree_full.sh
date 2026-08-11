#!/bin/bash
# aarch64: 无锁队列"满队列/CAS 失败"窗口 strict 切片 (结局回放实验)
#
# 消费者比生产者慢 (cons_work=80000 > prod_work=30000) → 队列积压,
# 生产者窗口内经历自旋 (ldar 循环) + CAS help/失败。强制
# ELFTRACE_CAS_RECORD=1: 主程序 CAS 走结局回放 (按 ordinal 重放
# 录制 success/old), 库 CAS (malloc arena) 显式 skip 原生。
#
# 断言:
#   1. 切片 rc ∈ {0, 67} (67 = 窗口结束在自旋里, 设计内信号, 遥测
#      证明 site/ord/limit);
#   2. 目标阶段 (rt_sigreturn 后) 除 exit_group 外零 syscall;
#   3. 录制窗口内 CAS 事件含失败 (success=0) 或 help (expected!=0);
#   4. 补偿比例 R 只报告不 gate (自旋窗口逐访问回放开销大, 与
#      <15% 目标的关系见 round-17 文档, 属开放问题)。
set -u
cd "$(dirname "$0")/.."
source tests/testlib.sh

if [ "$(uname -m)" != "aarch64" ]; then
    echo "SKIP: lockfree full 测试仅 aarch64"
    exit 0
fi

tf_setup
tf_cleanup prog_lockfree_main
ELFTRACE="$TF_ELFTRACE"

echo "== [atomic] lockfree full-queue (CAS failure) outcome replay =="
gcc -O2 -g -pthread -o "$TF_TMP/prog_lockfree_main" \
    tests/prog_lockfree_main.c || exit 1
gcc -O2 -o "$TF_TMP/tel_run" tests/tel_run.c 2>/dev/null || true

# ---------- Run 1: 校准 ----------
rm -rf "$TF_TMP/lff_r1" "$TF_TMP/lff_r2"
"$TF_TMP/prog_lockfree_main" 20000 30000 80000 \
    > "$TF_TMP/lff_r1.out" 2>&1 &
PID=$!
sleep 0.3
ELFTRACE_CAS_RECORD=1 timeout 300 "$ELFTRACE" trace "$PID" \
    --every 50000000 --out "$TF_TMP/lff_r1" --atomic-replay \
    > "$TF_TMP/lff_t1.log" 2>&1
wait $PID 2>/dev/null
[ -f "$TF_TMP/lff_r1/atomics/compensation.txt" ] || {
    echo "FAIL: Run1 no compensation.txt"
    tail -5 "$TF_TMP/lff_t1.log"
    exit 1
}
RN=$(awk '/^r_num/{print $2}' "$TF_TMP/lff_r1/atomics/compensation.txt")
RD=$(awk '/^r_den/{print $2}' "$TF_TMP/lff_r1/atomics/compensation.txt")
[ "${RN:-0}" -gt "${RD:-1}" ] || {
    echo "FAIL: Run1 bad ratio r_num=$RN r_den=$RD"; exit 1; }

# ---------- Run 2: 正式采集 ----------
"$TF_TMP/prog_lockfree_main" 20000 30000 80000 \
    > "$TF_TMP/lff_r2.out" 2>&1 &
PID=$!
sleep 0.3
ELFTRACE_CAS_RECORD=1 timeout 300 "$ELFTRACE" trace "$PID" \
    --every 50000000 --out "$TF_TMP/lff_r2" --atomic-replay \
    --atomic-compensate "$TF_TMP/lff_r1/atomics/compensation.txt" \
    > "$TF_TMP/lff_t2.log" 2>&1
wait $PID 2>/dev/null
NCK=$(wc -l < "$TF_TMP/lff_r2/manifest.txt")
[ "$NCK" -ge 8 ] || { echo "FAIL: Run2 only $NCK checkpoints"; exit 1; }
[ -f "$TF_TMP/lff_r2/atomics/cas_events.bin" ] || {
    echo "FAIL: Run2 no cas_events.bin"; exit 1; }

# 断言: 窗口候选范围内存在 CAS 失败/help 事件
python3 - "$TF_TMP/lff_r2" <<'EOF'
import struct, sys
d = sys.argv[1]
cev = open(d + "/atomics/cas_events.bin", "rb").read()
ncev = struct.unpack_from("<Q", cev, 16)[0]
fail = 0
help_ = 0
for k in range(ncev):
    sid, ordv, addr, old, success, expected, desired = \
        struct.unpack_from("<QQQQQQQ", cev, 32 + k * 56)
    if success == 0:
        fail += 1
    if expected != 0:
        help_ += 1
print("cas_events=%d fail=%d help=%d" % (ncev, fail, help_))
if fail + help_ == 0:
    sys.exit(2)
EOF
case $? in
    0) ;;
    2) echo "FAIL: 窗口候选内无 CAS 失败/help 事件 (队列没满?)"; exit 1 ;;
    *) echo "FAIL: cas 事件分析错误"; exit 1 ;;
esac

# ---------- 发现 CAS 站点 (主程序 force 列表在此模式被过滤为 skip) ----------
CAS_ARGS=$(python3 - "$TF_TMP/lff_r2/ckpt_000000.elftrace" <<'EOF'
import struct, sys
f = open(sys.argv[1], "rb").read()
segs_off, nsegs = struct.unpack_from("<QQ", f, 72)
strings_off, strings_size = struct.unpack_from("<QQ", f, 112)
payload_off = struct.unpack_from("<Q", f, 152)[0]
M = 0x3FA07C00
E = 0x08A07C00
for i in range(nsegs):
    vaddr, filesz, memsz, flags, poff, name_off = \
        struct.unpack_from("<QQQQQQ", f, segs_off + i * 48)
    name = b""
    if 0 < name_off < strings_size:
        e = f.find(b"\0", strings_off + name_off)
        name = f[strings_off + name_off:e]
    if not (flags & 1):
        continue
    main_seg = b"prog_lockfree_main" in name
    base = payload_off + poff
    for k in range(0, filesz - 3, 4):
        w = struct.unpack_from("<I", f, base + k)[0]
        if (w & M) != E:
            continue
        if k + 4 >= filesz:
            continue
        nx = struct.unpack_from("<I", f, base + k + 4)[0]
        if nx == 0xd65f03c0 or (nx & 0xFC000000) == 0x14000000 or \
           (nx & 0xFF000010) == 0x54000000 or \
           (nx & 0x7C000000) == 0x34000000:
            if not main_seg:
                print("--atomic-skip-pc 0x%x" % (vaddr + k))
EOF
)
[ -n "$CAS_ARGS" ] || {
    echo "FAIL: no LSE CAS found"; exit 1; }

# ---------- 发现主程序段 malloc bl (结果重放) ----------
MP=$(python3 - "$TF_TMP/lff_r2/ckpt_000000.elftrace" <<'EOF'
import struct, sys
f = open(sys.argv[1], "rb").read()
segs_off, nsegs = struct.unpack_from("<QQ", f, 72)
strings_off, strings_size = struct.unpack_from("<QQ", f, 112)
payload_off = struct.unpack_from("<Q", f, 152)[0]
for i in range(nsegs):
    vaddr, filesz, memsz, flags, poff, name_off = \
        struct.unpack_from("<QQQQQQ", f, segs_off + i * 48)
    name = b""
    if 0 < name_off < strings_size:
        e = f.find(b"\0", strings_off + name_off)
        name = f[strings_off + name_off:e]
    if not (flags & 1) or b"prog_lockfree_main" not in name:
        continue
    base = payload_off + poff
    # main 的 malloc 调用 (bl, 0x94xxxxxx), 主循环 0xae0 附近
    for k in range(0xac0, 0xb00, 4):
        w = struct.unpack_from("<I", f, base + k)[0]
        if (w & 0xFC000000) == 0x94000000:
            print("0x%x" % (vaddr + k))
            break
EOF
)
[ -n "$MP" ] || { echo "FAIL: no malloc bl in main"; exit 1; }
CAS_ARGS="$CAS_ARGS --malloc-replay-pc $MP"
echo "atomic: malloc-replay pc=$MP"

# ---------- 选窗: 有原子事件的窗口 ----------
WIN=$(python3 - "$TF_TMP/lff_r2" <<'EOF'
import struct, sys
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
    pc = u64(); struct.unpack_from("<I", b, off)[0]
    off += 8
    sites.append(pc)
def states(k):
    bb = open("%s/atomics/ckpt_%06d.bin" % (d, k), "rb").read()
    o = 24
    return [struct.unpack_from("<QQQ", bb, o + i * 24)
            for i in range(n_sites)]
man = open(d + "/manifest.txt").read().splitlines()
cnt = [int(l.split()[0]) for l in man]
pcs = [int(l.split()[1], 16) for l in man]
def to_ok(k):
    return pcs[k] not in sites
cands = []
for k in range(1, len(cnt) - 3):
    st = states(k)
    for to_k in range(k + 1, min(k + 3, len(cnt))):
        if not to_ok(to_k):
            continue
        st2 = states(to_k)
        if any(st2[i][0] > st[i][0] for i in range(n_sites)):
            cands.append((cnt[k], cnt[to_k]))
    if len(cands) >= 8:
        break
if not cands:
    sys.exit(2)
for c in cands:
    print(c[0], c[1])
EOF
)
case $? in
    0) ;;
    2) echo "FAIL: no suitable window"; exit 1 ;;
    *) echo "FAIL: window selection error"; exit 1 ;;
esac

# ---------- 逐候选构建 + K 校准: rc=0, R ≤ 15% ----------
SELECTED=0
while read -r FROM_C TO_C; do
    T=$((TO_C - FROM_C))
    echo "atomic: trying window from-count=$FROM_C to-count=$TO_C"
    K0=0
    A0=0
    for iter in 1 2 3 4 5; do
        EXTRA=()
        [ "$K0" -gt 0 ] && EXTRA=(--bm-exit-count "$K0")
        tf_build /dev/null "$TF_TMP/lff_slice.elf" --mode baremetal \
            --bm-strict --checkpoints "$TF_TMP/lff_r2" \
            --from-count "$FROM_C" --to-count "$TO_C" \
            --stack-reserve 67108864 $CAS_ARGS "${EXTRA[@]}" \
            > "$TF_TMP/lff_build.log" 2>&1 || continue 2
        grep -q "CAS outcome replay site" "$TF_TMP/lff_build.log" || {
            echo "  build: 无结局回放站点, 试下一候选"; continue 2; }
        timeout 120 perf stat -e instructions "$TF_TMP/lff_slice.elf" \
            > /dev/null 2> "$TF_TMP/lff.perf"
        RC=$?
        if [ "$RC" != 0 ]; then
            if [ "$RC" = 67 ]; then
                echo "  rc=67 (自旋结束), 遥测:"
                "$TF_TMP/tel_run" "$TF_TMP/lff_slice.elf" 2>&1 | tail -2
            else
                echo "  rc=$RC, 试下一候选"
            fi
            A0=0
            break
        fi
        A=$(grep "instructions" "$TF_TMP/lff.perf" \
            | grep -oE "[0-9,]+" | head -1 | tr -d ",")
        echo "atomic: iter $iter K=${K0:-def} A=$A T=$T"
        A0=${A:-0}
        if [ "$iter" = 1 ] && [ "$A0" -gt 0 ] && [ "$T" -gt 0 ]; then
            # 一级指标: 不校准 K 时的动态指令倍率 (真实膨胀, 不被 K 吸收)
            IM=$((A0 * 100 / T))
            echo "atomic: iter1 insn_multiplier=$(printf '%d.%02d' $((IM / 100)) $((IM % 100)))x (A=$A0 T=$T)"
            printf '%d.%02dx\n' $((IM / 100)) $((IM % 100)) > "$TF_TMP/lff_multiplier.txt"
        fi
        if [ "$iter" = 1 ] && [ "$A0" -gt 0 ]; then
            K0=$(grep -oE "K=[0-9]+" "$TF_TMP/lff_build.log" | head -1 \
                | cut -d= -f2)
        fi
        if [ "$A0" -gt 0 ]; then
            D=$((A0 > T ? A0 - T : T - A0))
            if [ $((D * 100 / A0)) -le 15 ]; then
                R=$((D * 100 / A0))
                SELECTED=1
                break
            fi
        fi
        if [ "$iter" -lt 5 ] && [ "$K0" -gt 0 ] && [ "$A0" -gt 0 ]; then
            K0=$((K0 * T / A0))
            [ "$K0" -gt 0 ] || K0=1
        fi
    done
    if [ "$SELECTED" = 1 ]; then
        break
    fi
done <<EOF
$WIN
EOF
[ "$SELECTED" = 1 ] || {
    echo "FAIL: 无候选窗口达到 rc=0 且 R≤15% (last A0=$A0)"
    exit 1; }

# 断言: 选中的窗口内结局回放真实消费了 help/失败事件
python3 - "$TF_TMP/lff_r2" "$FROM_C" "$TO_C" <<'EOF'
import struct, sys
d, frm, to = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
b = open(d + "/atomics/sites.bin", "rb").read()
off = 0
def u64():
    global off
    v = struct.unpack_from("<Q", b, off)[0]
    off += 8
    return v
u64(); u64(); n = u64(); u64(); u64(); np = u64(); u64(); u64(); u64()
off += np * 8
pcs = []
for i in range(n):
    pc = u64(); w, kind = struct.unpack_from("<II", b, off)
    off += 8
    pcs.append((pc, kind))
def ckpt(k):
    bb = open("%s/atomics/ckpt_%06d.bin" % (d, k), "rb").read()
    return [struct.unpack_from("<QQQ", bb, 24 + i * 24)
            for i in range(n)]
man = open(d + "/manifest.txt").read().splitlines()
cnt = [int(l.split()[0]) for l in man]
def idx(c):
    for i in range(len(cnt) - 1):
        if cnt[i] <= c < cnt[i + 1]:
            return i
    return len(cnt) - 1
k0, k1 = idx(frm), idx(to)
f0, f1 = ckpt(k0), ckpt(k1)
cev = open(d + "/atomics/cas_events.bin", "rb").read()
ncev = struct.unpack_from("<Q", cev, 16)[0]
help_ev = fail_ev = 0
for k in range(ncev):
    sid, ordv, addr, old, success, expected, desired = \
        struct.unpack_from("<QQQQQQQ", cev, 32 + k * 56)
    pc, kind = pcs[sid]
    if kind != 4:
        continue
    if f0[sid][0] < ordv <= f1[sid][0]:
        if expected != 0:
            help_ev += 1
        if success == 0:
            fail_ev += 1
print("window help_events=%d fail_events=%d" % (help_ev, fail_ev))
if help_ev == 0:
    sys.exit(2)
EOF
case $? in
    0) ;;
    2) echo "FAIL: 窗口内无 help 事件被回放 (队列没满?)"; exit 1 ;;
    *) echo "FAIL: 窗口事件分析错误"; exit 1 ;;
esac

# ---------- 目标阶段零 syscall ----------
timeout 120 strace -o "$TF_TMP/lff_slice.strace" \
    "$TF_TMP/lff_slice.elf" > /dev/null 2>&1
RC=$?
[ "$RC" = 0 ] || [ "$RC" = 67 ] || {
    echo "FAIL: strace slice rc=$RC"; exit 1; }
AFTER=$(awk '/rt_sigreturn/{f=1; next} f' "$TF_TMP/lff_slice.strace")
if echo "$AFTER" | grep -E "openat|read\(|write\(|ioctl\(|mmap|brk|futex|clone"; then
    echo "FAIL: target-phase real syscalls"
    echo "$AFTER"
    exit 1
fi
grep -q "exit_group" "$TF_TMP/lff_slice.strace" \
    || { echo "FAIL: no exit_group"; exit 1; }

tf_pass "atomic lockfree full-queue outcome replay (rc=$RC, zero target syscalls)"
if [ -f "$TF_TMP/lff_multiplier.txt" ]; then
    echo "  insn_multiplier = $(cat "$TF_TMP/lff_multiplier.txt") (未校准 iter1)"
fi
tf_finish
