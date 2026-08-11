#!/bin/bash
# aarch64: 冷边界账本端到端 (--boundary-pc 全链路)
#
# 1. 编译 prog_alloc_n (round 循环 + malloc churn + usleep), 跑 1000 轮;
# 2. trace --alloc-replay --boundary-pc +0x8e8 --every 50M:
#    boundary pc 每命中记录 {count,alloc,sys,ord,pc} → boundaries.bin;
# 3. build --from 2 --to 3: 边界账本自动选 TO 后第一个边界为退出点
#    (K=序数差, T_exec=边界 count 差, alloc 事件表延伸到边界游标);
# 4. 断言: 切片 rc=0; strace 目标阶段仅 exit_group; perf stat 实际
#    指令数 ∈ [T_exec*0.95, T_exec*1.05]。
#
# +0x8e8 是 gcc -O2 (Ubuntu GCC 13) 下 prog_alloc_n round 循环头
# 的文件虚拟偏移, 已在该 aarch64 服务器验证; 布局变化时 objdump
# 校验会直接 FAIL。
set -u
cd "$(dirname "$0")/.."
source tests/testlib.sh

if [ "$(uname -m)" != "aarch64" ]; then
    echo "SKIP: boundary ledger e2e 仅 aarch64 (perf/ptrace)"
    exit 0
fi

tf_setup
tf_cleanup prog_alloc_n

ELFTRACE="$TF_ELFTRACE"
WORK="$TF_TMP/prog_alloc_n"
CKPT="$TF_TMP/bound_ckpts"
SLICE="$TF_TMP/bound_slice.elf"

gcc -O2 -o "$WORK" tests/prog_alloc_n.c || exit 1

# 校验 +0x8e8 仍是 main 的指令 (PIE 文件虚拟地址)
objdump -d "$WORK" 2>/dev/null | grep -qE "^\s+8e8:\s" \
    || { echo "FAIL: workload layout changed, boundary +0x8e8 invalid"; exit 1; }

rm -rf "$CKPT"
mkdir -p "$CKPT"
"$WORK" 1000 > "$TF_TMP/bound_work.out" 2>&1 &
PID=$!
tf_wait_marker bound_work READY 20 || { echo "FAIL: no READY"; exit 1; }

timeout 240 "$ELFTRACE" trace "$PID" --alloc-replay --boundary-pc +0x8e8 \
    --every 50000000 --out "$CKPT" > "$TF_TMP/bound_trace.log" 2>&1
TRC=$?
kill "$PID" 2>/dev/null
wait "$PID" 2>/dev/null
[ "$TRC" = 0 ] || { echo "FAIL: trace rc=$TRC"; exit 1; }

[ -f "$CKPT/boundaries.bin" ] \
    || { echo "FAIL: no boundaries.bin"; exit 1; }
NORD=$(( $(stat -c %s "$CKPT/boundaries.bin") / 40 ))
[ "$NORD" -ge 500 ] || { echo "FAIL: 边界记录太少 ($NORD)"; exit 1; }
NCK=$(wc -l < "$CKPT/manifest.txt")
[ "$NCK" -ge 4 ] || { echo "FAIL: 检查点不足 ($NCK)"; exit 1; }
echo "boundary e2e: records=$NORD checkpoints=$NCK"

tf_build /dev/null "$SLICE" --mode baremetal --bm-strict \
    --checkpoints "$CKPT" --from 2 --to 3 --stack-reserve 268435456 \
    > "$TF_TMP/bound_build.log" 2>&1 \
    || { echo "FAIL: build"; tail -5 "$TF_TMP/bound_build.log"; exit 1; }
grep -q "cold boundary exit pc=" "$TF_TMP/bound_build.log" \
    || { echo "FAIL: no cold boundary exit"; exit 1; }
T_EXEC=$(grep -oE "T_exec=[0-9]+" "$TF_TMP/bound_build.log" \
         | tail -1 | cut -d= -f2)
[ -n "$T_EXEC" ] || { echo "FAIL: no T_exec"; exit 1; }

timeout 60 strace -o "$TF_TMP/bound.strace" "$SLICE" > /dev/null 2>&1
RC=$?
[ "$RC" = 0 ] || { echo "FAIL: slice rc=$RC"; exit 1; }
AFTER=$(awk '/rt_sigreturn/{f=1; next} f' "$TF_TMP/bound.strace")
echo "$AFTER" | grep -E "openat|read\(|write\(|ioctl\(|mmap|brk|futex" \
    && { echo "FAIL: target-phase real syscalls"; echo "$AFTER"; exit 1; }

ACT=$(perf stat -e instructions "$SLICE" 2>&1 \
      | awk '/instructions:u/{print $1}' | tr -d ,)
[ -n "$ACT" ] || { echo "FAIL: no perf instruction count"; exit 1; }
LO=$(( T_EXEC * 95 / 100 ))
HI=$(( T_EXEC * 105 / 100 ))
[ "$ACT" -ge "$LO" ] && [ "$ACT" -le "$HI" ] \
    || { echo "FAIL: actual $ACT vs T_exec $T_EXEC (range $LO..$HI)"; exit 1; }

tf_pass "boundary ledger e2e (T_exec=$T_EXEC actual=$ACT)"
tf_finish
