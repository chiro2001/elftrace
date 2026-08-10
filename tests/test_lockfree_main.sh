#!/bin/bash
# aarch64: 无锁 MS 队列 (主线程=生产者) strict 切片
#
# 覆盖点: 真机 LSE casl CAS (glibc __aarch64_cas8_rel) + ldar 值回放。
# 采集时 casl 原生执行 (不入站点); 切片回放时检查点内存陈旧导致
# casl 失败 → 主循环空转 → 原子 ordinal 提前耗尽 (rc=67)。本测试验证
# LSE CAS 强制成功跳板: 无条件 str + Rs 保持期望值, 切片不再空转。
#
# 两跑补偿流程 (同 test_atomic_spin):
#   Run 1 (校准) → compensation.txt; Run 2 (正式, 补偿触发) →
#   build --from-count/--to-count 选窗; K 按 A/T 迭代使
#   补偿指令比例 |A-T|/A ≤ 5%。
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
    echo "SKIP: lockfree main 测试仅 aarch64 (--bm-strict + --atomic-replay)"
    exit 0
fi

tf_setup
tf_cleanup prog_lockfree_main
ELFTRACE="$TF_ELFTRACE"

echo "== [atomic] lockfree main-thread producer strict slice =="
gcc -O2 -g -pthread -o "$TF_TMP/prog_lockfree_main" \
    tests/prog_lockfree_main.c || exit 1
gcc -O2 -o "$TF_TMP/tel_run" tests/tel_run.c 2>/dev/null || true

# ---------- Run 1: 校准 ----------
rm -rf "$TF_TMP/lf_r1" "$TF_TMP/lf_r2"
"$TF_TMP/prog_lockfree_main" 20000 50000 40000 \
    > "$TF_TMP/lf_r1.out" 2>&1 &
PID=$!
sleep 0.3
timeout 300 "$ELFTRACE" trace "$PID" --every 50000000 \
    --out "$TF_TMP/lf_r1" --atomic-replay \
    > "$TF_TMP/lf_t1.log" 2>&1
wait $PID 2>/dev/null
[ -f "$TF_TMP/lf_r1/atomics/compensation.txt" ] || {
    echo "FAIL: Run1 no compensation.txt"
    tail -5 "$TF_TMP/lf_t1.log"
    exit 1
}
RN=$(awk '/^r_num/{print $2}' "$TF_TMP/lf_r1/atomics/compensation.txt")
RD=$(awk '/^r_den/{print $2}' "$TF_TMP/lf_r1/atomics/compensation.txt")
[ "${RN:-0}" -gt "${RD:-1}" ] || {
    echo "FAIL: Run1 bad ratio r_num=$RN r_den=$RD"; exit 1; }
echo "atomic: Run1 r=$RN/$RD"

# ---------- Run 2: 正式采集 (补偿触发) ----------
"$TF_TMP/prog_lockfree_main" 20000 50000 40000 \
    > "$TF_TMP/lf_r2.out" 2>&1 &
PID=$!
sleep 0.3
timeout 300 "$ELFTRACE" trace "$PID" --every 50000000 \
    --out "$TF_TMP/lf_r2" --atomic-replay \
    --atomic-compensate "$TF_TMP/lf_r1/atomics/compensation.txt" \
    > "$TF_TMP/lf_t2.log" 2>&1
wait $PID 2>/dev/null
NCK=$(wc -l < "$TF_TMP/lf_r2/manifest.txt")
[ "$NCK" -ge 8 ] || { echo "FAIL: Run2 only $NCK checkpoints"; exit 1; }
[ -f "$TF_TMP/lf_r2/atomics/events.bin" ] || {
    echo "FAIL: Run2 no events.bin"; exit 1; }

# ---------- 发现 LSE CAS 站点 ----------
# 采集端 CAS 结局录制默认关闭 (实验性); 生产路径按 PC 显式开启
# force-success, 只作用于主程序段里 real CAS (掩码 0x3FA07C00 +
# 下一条 ret 过滤, 排除数据/字面量池误报)。库 (libc 等) 的共享
# 有状态 CAS (malloc arena) 结局回放会因冻结态与录制态分歧而
# fail-closed, 实验路径显式 skip 让它们原生执行。
CAS_ARGS=$(python3 - "$TF_TMP/lf_r2/ckpt_000000.elftrace" <<'EOF'
import struct, sys
f = open(sys.argv[1], "rb").read()
segs_off, nsegs = struct.unpack_from("<QQ", f, 72)
strings_off, strings_size = struct.unpack_from("<QQ", f, 112)
payload_off = struct.unpack_from("<Q", f, 152)[0]
M = 0x3FA07C00
E = 0x08A07C00
pcs = []
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
            pcs.append((vaddr + k, main_seg))
for pc in pcs:
    if pc[1]:
        print("--atomic-force-cas-pc 0x%x" % pc[0])
    else:
        print("--atomic-skip-pc 0x%x" % pc[0])
EOF
)
[ -n "$CAS_ARGS" ] || {
    echo "FAIL: no LSE CAS found in main executable segment"
    exit 1; }
if [ -n "${ELFTRACE_CAS_RECORD:-}" ]; then
    # 实验: 库 CAS skip (原生), 主程序 CAS 走结局回放
    CAS_ARGS=$(echo "$CAS_ARGS" | grep -- --atomic-skip-pc)
else
    # 生产: 主程序 CAS force-success, 库 CAS 本就无事件不受影响
    CAS_ARGS=$(echo "$CAS_ARGS" | grep -- --atomic-force-cas-pc)
fi
[ -n "$CAS_ARGS" ] || {
    echo "FAIL: no usable CAS sites for this mode"
    exit 1; }
echo "atomic: force-cas sites: $(echo $CAS_ARGS | wc -w)"

# ---------- 选窗: 有原子事件且退出点可计数的窗口 ----------
WIN=$(python3 - "$TF_TMP/lf_r2" <<'EOF'
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
def ords(k):
    bb = open("%s/atomics/ckpt_%06d.bin" % (d, k), "rb").read()
    o = 24
    return [struct.unpack_from("<Q", bb, o + i * 24)[0]
            for i in range(n_sites)]
def states(k):
    bb = open("%s/atomics/ckpt_%06d.bin" % (d, k), "rb").read()
    o = 24
    return [struct.unpack_from("<QQQ", bb, o + i * 24)
            for i in range(n_sites)]
man = open(d + "/manifest.txt").read().splitlines()
cnt = [int(l.split()[0]) for l in man]
pcs = [int(l.split()[1], 16) for l in man]
ev = open(d + "/atomics/events.bin", "rb").read()
n_ev = struct.unpack_from("<Q", ev, 16)[0]
events = []
for i in range(n_ev):
    sid, ordv, addr, val = struct.unpack_from("<QQQQ", ev, 32 + i * 40)
    events.append((sid, ordv))
def site_events_between(sid, lo, hi):
    return any(e_s == sid and lo < e_o <= hi for (e_s, e_o) in events)
def to_ok(k):
    return pcs[k] not in sites
# 从后往前找: 靠后的窗口忙循环主导, 原子回放开销占比小; 跳过最后
# 3 个检查点 (程序收尾阶段 syscall 密集, 退出点不可计数)。
cands = []
for k in range(len(cnt) - 3, 0, -1):
    st = states(k)
    for to_k in range(k + 1, min(k + 5, len(cnt))):
        if not to_ok(to_k):
            continue
        st2 = states(to_k)
        if any(st2[i][0] > st[i][0] and
               site_events_between(i, st[i][0], st2[i][0])
               for i in range(n_sites)):
            cands.append((cnt[k], cnt[to_k]))
    if len(cands) >= 6:
        break
if not cands:
    sys.exit(2)
for c in cands:
    print(c[0], c[1])
EOF
)
case $? in
    0) ;;
    2) echo "FAIL: no suitable window with atomic events"; exit 1 ;;
    *) echo "FAIL: window selection error"; exit 1 ;;
esac

# ---------- 窗口 + K 校准 (补偿指令比例 ≤ 5%) ----------
SELECTED=0
R=999
while read -r FROM_C TO_C; do
    T=$((TO_C - FROM_C))
    echo "atomic: trying window from-count=$FROM_C to-count=$TO_C"
    K0=0
    A0=0
    for iter in 1 2 3 4 5; do
        EXTRA=()
        [ "$K0" -gt 0 ] && EXTRA=(--bm-exit-count "$K0")
        tf_build /dev/null "$TF_TMP/lf_slice.elf" --mode baremetal \
            --bm-strict --checkpoints "$TF_TMP/lf_r2" \
            --from-count "$FROM_C" --to-count "$TO_C" \
            --stack-reserve 67108864 $CAS_ARGS "${EXTRA[@]}" \
            > "$TF_TMP/lf_build.log" 2>&1 || continue 2
        grep -q "count target insn" "$TF_TMP/lf_build.log" || continue 2
        K=$(grep -oE "K=[0-9]+" "$TF_TMP/lf_build.log" | head -1 \
            | cut -d= -f2)
        [ -n "$K" ] || K=0
        timeout 120 perf stat -e instructions "$TF_TMP/lf_slice.elf" \
            > /dev/null 2> "$TF_TMP/lf.perf"
        RC=$?
        if [ "$RC" = 67 ]; then
            echo "atomic: window ends in spin (rc=67), try next candidate"
            [ -x "$TF_TMP/tel_run" ] && \
                "$TF_TMP/tel_run" "$TF_TMP/lf_slice.elf"
            A0=0
            break
        fi
        if [ "$RC" != 0 ]; then
            echo "FAIL: slice rc=$RC (deadlock?)"
            [ -x "$TF_TMP/tel_run" ] && \
                "$TF_TMP/tel_run" "$TF_TMP/lf_slice.elf"
            exit 1
        fi
        A=$(grep "instructions" "$TF_TMP/lf.perf" \
            | grep -oE "[0-9,]+" | head -1 | tr -d ",")
        echo "atomic: iter $iter K=$K A=$A T=$T"
        A0=${A:-0}
        if [ "$A0" -gt 0 ]; then
            D=$((A0 > T ? A0 - T : T - A0))
            if [ $((D * 100 / A0)) -le 5 ]; then
                R=$((D * 100 / A0))
                break
            fi
        fi
        if [ "$A0" -gt 0 ] && [ "$K" -gt 1000000 ] \
            && [ $((A0 * 10)) -lt "$T" ]; then
            echo "atomic: window early-exits via replay budget, skip"
            A0=0
            break
        fi
        if [ "$iter" -lt 5 ] && [ "$K" -gt 0 ] && [ "$A0" -gt 0 ]; then
            K0=$((K * T / A0))
            [ "$K0" -gt 0 ] || K0=1
        fi
    done
    if [ "$A0" -gt 0 ]; then
        D=$((A0 > T ? A0 - T : T - A0))
        R=$((D * 100 / A0))
        if [ "$R" -le 5 ]; then
            SELECTED=1
            break
        fi
    fi
done <<EOF
$WIN
EOF
[ "$SELECTED" = 1 ] || {
    echo "FAIL: no candidate window converges (last R=$R%)"
    tail -5 "$TF_TMP/lf_build.log"
    exit 1; }

# ---------- 目标阶段零 syscall ----------
timeout 120 strace -o "$TF_TMP/lf_slice.strace" \
    "$TF_TMP/lf_slice.elf" > /dev/null 2>&1
RC=$?
[ "$RC" = 0 ] || { echo "FAIL: strace slice rc=$RC"; exit 1; }
AFTER=$(awk '/rt_sigreturn/{f=1; next} f' "$TF_TMP/lf_slice.strace")
if echo "$AFTER" | grep -E "openat|read\(|write\(|ioctl\(|mmap|brk|futex|clone"; then
    echo "FAIL: target-phase real syscalls"
    echo "$AFTER"
    exit 1
fi
grep -q "exit_group" "$TF_TMP/lf_slice.strace" \
    || { echo "FAIL: no exit_group"; exit 1; }

NEV=$(python3 - "$TF_TMP/lf_r2" <<'EOF'
import struct, sys
b = open(sys.argv[1] + "/atomics/events.bin", "rb").read()
print(struct.unpack_from("<Q", b, 16)[0])
EOF
)
[ "$NEV" -gt 0 ] || { echo "FAIL: no recorded atomic events"; exit 1; }

if [ -n "${ELFTRACE_CAS_RECORD:-}" ]; then
    NCAS=$(grep -c "CAS outcome replay site" "$TF_TMP/lf_build.log")
else
    NCAS=$(grep -c "force-success LSE CAS" "$TF_TMP/lf_build.log")
fi
[ "$NCAS" -gt 0 ] || {
    echo "FAIL: no LSE CAS replay site"
    exit 1; }

tf_pass "atomic lockfree main (rc=0, clean, ratio $R%, $NEV events, $NCAS cas)"
tf_finish
