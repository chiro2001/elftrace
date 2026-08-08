#!/bin/bash
# aarch64: 多线程原子同步 (SPSC 有界队列 + 生产者自旋) strict 切片
#
# 复现死循环: 生产者满队列自旋读 head, 切片只恢复主线程, 消费者线程
# 不存在 → head 永不变化 → 永不退出。
#
# 方案 (原子读序号化回放):
#   trace --atomic-replay 把所有 ldar patch 成记录跳板, 记录
#   "第几次读取 + 地址 + 值" (游程压缩); build --bm-strict 把窗口内
#   有事件的站点替换成回放跳板, 按第几次访问返回录制值 (仍执行真实
#   acquire 屏障), 切片因此能越过自旋继续执行。
#
# 断言:
#   1. 切片 rc=0 (窗口结束正常退出, 不超时);
#   2. 目标阶段 (rt_sigreturn 后) 除 exit_group 外零 syscall;
#   3. 原子侧车存在且窗口内事件数 > 0。
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

echo "== [atomic] SPSC spin strict slice =="
gcc -O2 -g -pthread -o "$TF_TMP/prog_spsc_spin" tests/prog_spsc_spin.c \
    || exit 1

# 目标: 生产者每项 ~100k 指令, 消费者 ~80k, 消费者延迟 1s 启动制造
# "队列稳定满 + 生产者自旋" 窗口; 之后消费者追赶, 原子读值开始变化。
rm -rf "$TF_TMP/spsc_ckpts"
"$TF_TMP/prog_spsc_spin" 2000 8 10000 8000 1 \
    > "$TF_TMP/spsc_tr.out" 2>&1 &
PID=$!
sleep 0.2
timeout 300 "$ELFTRACE" trace "$PID" --every 50000000 \
    --out "$TF_TMP/spsc_ckpts" --atomic-replay \
    > "$TF_TMP/spsc_trace.log" 2>&1
wait $PID 2>/dev/null

[ -f "$TF_TMP/spsc_ckpts/atomics/events.bin" ] || {
    echo "FAIL: no atomics/events.bin"
    tail -20 "$TF_TMP/spsc_trace.log"
    exit 1
}
NCK=$(wc -l < "$TF_TMP/spsc_ckpts/manifest.txt")
[ "$NCK" -ge 8 ] || { echo "FAIL: only $NCK checkpoints"; exit 1; }

# 选窗口: from = 首个"某站点序号增长且窗口内该站点有实际事件"的检查点
# (消费者已启动并推进了队列), to 取后续检查点且其 pc 不是原子站点
# (避免退出点与回放站点冲突)。
WIN=$(python3 - "$TF_TMP/spsc_ckpts" <<'EOF'
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
off += n_pages * 8
sites = []
for i in range(n_sites):
    pc = u64()
    insn = struct.unpack_from("<I", b, off)[0]
    off += 4
    sites.append(pc)
def ords(k):
    bb = open("%s/atomics/ckpt_%06d.bin" % (d, k), "rb").read()
    o = 24
    return [struct.unpack_from("<Q", bb, o + i * 24)[0] for i in range(n_sites)]
n = len([f for f in os.listdir(d + "/atomics") if f.startswith("ckpt_")])
prev = ords(0)
ev = open(d + "/atomics/events.bin", "rb").read()
n_ev = struct.unpack_from("<Q", ev, 16)[0]
events = []
for i in range(n_ev):
    sid, ordv, addr, val = struct.unpack_from("<QQQQ", ev, 24 + i * 32)
    events.append((sid, ordv))
def site_events_between(sid, lo, hi):
    for (e_sid, e_ord) in events:
        if e_sid == sid and lo < e_ord <= hi:
            return True
    return False
from_k = None
for k in range(1, n - 1):
    cur = ords(k)
    nxt = ords(k + 1)
    if any(cur[i] > prev[i] and site_events_between(i, cur[i], nxt[i])
           for i in range(n_sites)):
        from_k = k
        break
    prev = cur
if from_k is None:
    sys.exit(2)
man = open(d + "/manifest.txt").read().splitlines()
pcs = [int(l.split()[1], 16) for l in man]
for to in range(from_k + 1, min(from_k + 6, len(pcs))):
    if pcs[to] not in sites:
        print(from_k, to)
        sys.exit(0)
sys.exit(3)
EOF
)
case $? in
    0) ;;
    2) echo "FAIL: no atomic progress between checkpoints"; exit 1 ;;
    3) echo "FAIL: no suitable --to (all coincide with atomic sites)"; exit 1 ;;
    *) echo "FAIL: window selection error"; exit 1 ;;
esac
FROM=${WIN%% *}
TO=${WIN##* }
echo "atomic: window from=$FROM to=$TO"

tf_build /dev/null "$TF_TMP/spsc_slice.elf" --mode baremetal --bm-strict \
    --checkpoints "$TF_TMP/spsc_ckpts" --from "$FROM" --to "$TO" \
    --stack-reserve 67108864 > "$TF_TMP/spsc_build.log" 2>&1 || {
    echo "FAIL: build"
    tail -20 "$TF_TMP/spsc_build.log"
    exit 1
}

timeout 60 strace -o "$TF_TMP/spsc_slice.strace" \
    "$TF_TMP/spsc_slice.elf" > /dev/null 2>&1
RC=$?
[ "$RC" = 0 ] || { echo "FAIL[1]: slice rc=$RC (deadlock?)"; exit 1; }

AFTER=$(awk '/rt_sigreturn/{f=1} f' "$TF_TMP/spsc_slice.strace")
if echo "$AFTER" | grep -E "openat|read\(|write\(|ioctl|mmap|brk|futex|clone"; then
    echo "FAIL[2]: target-phase real syscalls"
    echo "$AFTER"
    exit 1
fi
grep -q "exit_group" "$TF_TMP/spsc_slice.strace" \
    || { echo "FAIL[2]: no exit_group"; exit 1; }

NEV=$(python3 - "$TF_TMP/spsc_ckpts" <<'EOF'
import struct, sys
b = open(sys.argv[1] + "/atomics/events.bin", "rb").read()
print(struct.unpack_from("<Q", b, 16)[0])
EOF
)
[ "$NEV" -gt 0 ] || { echo "FAIL[3]: no recorded atomic events"; exit 1; }
echo "atomic: $NEV events recorded"

tf_pass "atomic SPSC spin (rc=0, clean target phase, $NEV events)"
tf_finish
