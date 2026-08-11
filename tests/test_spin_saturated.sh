#!/bin/bash
# aarch64: 纯自旋窗口 (队列 100% 满, 生产者全程自旋) 指令倍率验收
#
# 目的 (round-19 claude 评审 B4): R≈0% 是 K 校准收敛, 不是低开销证据。
# 一级指标 insn_multiplier = 不校准 K 时切片动态指令数 / 录制窗口指令数。
# 本测试选择"队列满、生产者全程自旋"的窗口, 断言 multiplier < 1.15。
#
# 当前状态: **预期红 (EXPECTED-RED)** —— run-burn 快路径 (RLE run 内
# 等长烧录, 每 run 只进跳板 2 次) 未实现, 逐访问值回放开销大。
# run-burn 落地后此脚本必须转绿, 然后加入 run_tests.sh 默认套件。
#
# 退出码: 0 = 达到 <1.15 目标; 1 = 未达到 (预期行为, 但脚本供 CI/手动
# 验收使用, 不加入默认套件)。
set -u
cd "$(dirname "$0")/.."
source tests/testlib.sh

if [ "$(uname -m)" != "aarch64" ]; then
    echo "SKIP: spin-saturated 测试仅 aarch64"
    exit 0
fi

tf_setup
tf_cleanup prog_lockfree_main
ELFTRACE="$TF_ELFTRACE"
GOAL=1.15

echo "== [atomic] spin-saturated window insn_multiplier (< $GOAL) =="
gcc -O2 -g -pthread -o "$TF_TMP/prog_lockfree_main" \
    tests/prog_lockfree_main.c || exit 1
gcc -O2 -o "$TF_TMP/tel_run" tests/tel_run.c 2>/dev/null || true

# 消费者极慢 (cons_work 大) + 生产者轻开销 (prod_work 小): 队列快速积压,
# 后期窗口生产者几乎全程自旋 (ldar 循环 + CAS help/失败)。
ITEMS=60000
PROD_WORK=5000
CONS_WORK=2000000

# ---------- Run 1: 校准 ----------
rm -rf "$TF_TMP/sp_r1" "$TF_TMP/sp_r2"
"$TF_TMP/prog_lockfree_main" "$ITEMS" "$PROD_WORK" "$CONS_WORK" \
    > "$TF_TMP/sp_r1.out" 2>&1 &
PID=$!
sleep 0.3
ELFTRACE_CAS_RECORD=1 timeout 600 "$ELFTRACE" trace "$PID" \
    --every 50000000 --out "$TF_TMP/sp_r1" --atomic-replay \
    > "$TF_TMP/sp_t1.log" 2>&1
wait $PID 2>/dev/null
[ -f "$TF_TMP/sp_r1/atomics/compensation.txt" ] || {
    echo "FAIL: Run1 no compensation.txt"
    tail -5 "$TF_TMP/sp_t1.log"
    exit 1
}

# ---------- Run 2: 正式采集 ----------
"$TF_TMP/prog_lockfree_main" "$ITEMS" "$PROD_WORK" "$CONS_WORK" \
    > "$TF_TMP/sp_r2.out" 2>&1 &
PID=$!
sleep 0.3
ELFTRACE_CAS_RECORD=1 timeout 600 "$ELFTRACE" trace "$PID" \
    --every 50000000 --out "$TF_TMP/sp_r2" --atomic-replay \
    --atomic-compensate "$TF_TMP/sp_r1/atomics/compensation.txt" \
    > "$TF_TMP/sp_t2.log" 2>&1
wait $PID 2>/dev/null
NCK=$(wc -l < "$TF_TMP/sp_r2/manifest.txt")
[ "$NCK" -ge 8 ] || { echo "FAIL: Run2 only $NCK checkpoints"; exit 1; }

# ---------- 发现 CAS 站点 + malloc bl (同 test_lockfree_full) ----------
CAS_ARGS=$(python3 - "$TF_TMP/sp_r2/ckpt_000000.elftrace" <<'EOF'
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
[ -n "$CAS_ARGS" ] || { echo "FAIL: no LSE CAS found"; exit 1; }

MP=$(python3 - "$TF_TMP/sp_r2/ckpt_000000.elftrace" <<'EOF'
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

# ---------- 选窗: 队列已满的自旋窗口 (help/失败事件密集, 靠后) ----------
WIN=$(python3 - "$TF_TMP/sp_r2" <<'EOF'
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
cev = open(d + "/atomics/cas_events.bin", "rb").read()
ncev = struct.unpack_from("<Q", cev, 16)[0]
ev = []
for k in range(ncev):
    ev.append(struct.unpack_from("<QQQQQQQ", cev, 32 + k * 56))
def help_between(frm, to):
    k0 = k1 = None
    for i in range(len(cnt) - 1):
        if cnt[i] <= frm < cnt[i + 1]:
            k0 = i
        if cnt[i] <= to < cnt[i + 1]:
            k1 = i
    if k0 is None or k1 is None:
        return 0
    f0, f1 = states(k0), states(k1)
    h = 0
    for (sid, ordv, addr, old, success, expected, desired) in ev:
        if f0[sid][0] < ordv <= f1[sid][0] and expected != 0:
            h += 1
    return h
cands = []
for k in range(2, len(cnt) - 3):
    for to_k in range(k + 1, min(k + 3, len(cnt))):
        if pcs[to_k] in sites:
            continue
        h = help_between(cnt[k], cnt[to_k])
        if h >= 2000:
            cands.append((h, cnt[k], cnt[to_k]))
if not cands:
    sys.exit(2)
cands.sort(reverse=True)
for h, f, t in cands[:8]:
    print(h, f, t)
EOF
)
case $? in
    0) ;;
    2) echo "FAIL: 无高密度 help 事件的自旋窗口 (队列没满?)"; exit 1 ;;
    *) echo "FAIL: window selection error"; exit 1 ;;
esac

# ---------- 逐候选构建 (不校准 K), 取 multiplier ----------
BEST=99999
while read -r HELP FROM_C TO_C; do
    T=$((TO_C - FROM_C))
    echo "atomic: spin window help=$HELP from=$FROM_C to=$TO_C (T=$T)"
    tf_build /dev/null "$TF_TMP/sp_slice.elf" --mode baremetal \
        --bm-strict --checkpoints "$TF_TMP/sp_r2" \
        --from-count "$FROM_C" --to-count "$TO_C" \
        --stack-reserve 67108864 $CAS_ARGS \
        > "$TF_TMP/sp_build.log" 2>&1 || continue
    grep -q "CAS outcome replay site" "$TF_TMP/sp_build.log" || continue
    timeout 120 perf stat -e instructions "$TF_TMP/sp_slice.elf" \
        > /dev/null 2> "$TF_TMP/sp.perf"
    RC=$?
    if [ "$RC" != 0 ] && [ "$RC" != 67 ]; then
        echo "  rc=$RC, 试下一候选"
        continue
    fi
    A=$(grep "instructions" "$TF_TMP/sp.perf" \
        | grep -oE "[0-9,]+" | head -1 | tr -d ",")
    A=${A:-0}
    if [ "$A" -gt 0 ] && [ "$T" -gt 0 ]; then
        IM=$((A * 100 / T))
        M=$((IM / 100)).$((IM % 100))
        echo "  rc=$RC A=$A T=$T insn_multiplier=$(printf '%d.%02d' $((IM / 100)) $((IM % 100)))x"
        if [ "$IM" -lt "$BEST" ]; then
            BEST=$IM
        fi
    fi
done <<EOF
$WIN
EOF

if [ "$BEST" = 99999 ]; then
    echo "FAIL: 无自旋窗口可构建运行"
    exit 1
fi
echo "best insn_multiplier=$(awk -v x=$BEST 'BEGIN{printf "%d.%02d", int(x/100), x%100}')x"

# ---------- 断言 < GOAL (当前预期红: run-burn 未实现) ----------
G=$(awk -v x=$GOAL 'BEGIN{printf "%d", x*100 + 0.5}')
if awk -v b=$BEST -v g=$G 'BEGIN{exit !(b < g)}'; then
    tf_pass "atomic spin-saturated insn_multiplier < $GOAL (rc=0)"
    tf_finish
    exit 0
fi

echo "EXPECTED-RED: insn_multiplier ≥ $GOAL — run-burn 快路径未实现"
echo "run-burn 落地后此脚本必须转绿并加入 run_tests.sh"
tf_fail "spin-saturated insn_multiplier < $GOAL"
exit 1
