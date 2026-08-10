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

# ---------- 逐候选构建: rc ∈ {0,67}, 遥测分诊 ----------
SELECTED=0
while read -r FROM_C TO_C; do
    echo "atomic: trying window from-count=$FROM_C to-count=$TO_C"
    tf_build /dev/null "$TF_TMP/lff_slice.elf" --mode baremetal \
        --bm-strict --checkpoints "$TF_TMP/lff_r2" \
        --from-count "$FROM_C" --to-count "$TO_C" \
        --stack-reserve 67108864 $CAS_ARGS \
        > "$TF_TMP/lff_build.log" 2>&1 || continue
    timeout 120 perf stat -e instructions "$TF_TMP/lff_slice.elf" \
        > /dev/null 2> "$TF_TMP/lff.perf"
    RC=$?
    if [ "$RC" = 0 ] || [ "$RC" = 67 ]; then
        if [ "$RC" = 67 ]; then
            echo "  rc=67 (自旋结束), 遥测:"
            "$TF_TMP/tel_run" "$TF_TMP/lff_slice.elf" 2>&1 | tail -2
        fi
        SELECTED=1
        break
    fi
    echo "  rc=$RC, 试下一候选"
done <<EOF
$WIN
EOF
[ "$SELECTED" = 1 ] || {
    echo "FAIL: 无候选窗口得到 rc∈{0,67}"
    exit 1; }

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
tf_finish
