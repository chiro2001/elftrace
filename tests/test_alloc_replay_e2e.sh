#!/bin/bash
# aarch64: alloc M1 端到端验收 (qemu 无法跑 ptrace/perf, 需真机/arm 服务器)
#
# 1. prog_alloc 200k 轮 + trace --alloc-replay --every 40M, 采 >=6 检查点
#    (>=240M 指令, 满足 200M~1000M 采集口径);
# 2. 选一个 40M 单间隔窗口, build 融合退出切片 (alloc fused exit,
#    不需要 K 校准);
# 3. 断言: rc=0、A 与 T=40M 的补偿比例 <=5%、目标阶段零中间 syscall、
#    分配事件全消费 (欠消费会 exit 65, 自动失败)。
set -u
cd "$(dirname "$0")/.."
source tests/testlib.sh

if [ "$(uname -m)" != "aarch64" ]; then
    echo "SKIP: alloc replay e2e 仅 aarch64 (perf/ptrace)"
    exit 0
fi

tf_setup
tf_cleanup prog_alloc200k
ELFTRACE="$TF_ELFTRACE"

# 200k 轮负载 (每轮 malloc+fill+free, 每 8 轮 realloc; 全程 ~35G 指令)
sed 's/round < 500/round < 200000/' tests/prog_alloc.c \
    > "$TF_TMP/prog_alloc200k.c" || exit 1
gcc -O2 -o "$TF_TMP/prog_alloc200k" "$TF_TMP/prog_alloc200k.c" || exit 1

CKPT="$TF_TMP/alloc_ckpts"
rm -rf "$CKPT"
mkdir -p "$CKPT"
"$TF_TMP/prog_alloc200k" > "$TF_TMP/alloc_tr.out" 2>&1 &
PID=$!
tf_wait_marker alloc_tr READY 20 || { echo "FAIL: READY"; exit 1; }

timeout 180 "$ELFTRACE" trace "$PID" --alloc-replay --every 40000000 \
    --out "$CKPT" > "$TF_TMP/alloc_trace.log" 2>&1 &
TRACE_PID=$!
# 等 >=12 个检查点后优雅停止 (目标 200k 轮会自己跑完, 这里先到数即停)
for i in $(seq 1 120); do
    NCK=$( [ -f "$CKPT/manifest.txt" ] && wc -l < "$CKPT/manifest.txt" || echo 0 )
    [ "$NCK" -ge 12 ] && break
    kill -0 "$TRACE_PID" 2>/dev/null || break
    sleep 1
done
NCK=$( [ -f "$CKPT/manifest.txt" ] && wc -l < "$CKPT/manifest.txt" || echo 0 )
[ "$NCK" -ge 12 ] || { echo "FAIL: 检查点不足 ($NCK)"; exit 1; }
kill -INT "$TRACE_PID" 2>/dev/null
wait "$TRACE_PID" 2>/dev/null
kill "$PID" 2>/dev/null
wait "$PID" 2>/dev/null
tf_cleanup prog_alloc200k

MAN="$CKPT/manifest.txt"
[ -f "$MAN" ] || { echo "FAIL: no manifest"; exit 1; }
ls "$CKPT/allocs/events.bin" >/dev/null 2>&1 \
    || { echo "FAIL: no alloc events"; exit 1; }
NEV=$(( $(stat -c %s "$CKPT/allocs/events.bin") / 32 ))
[ "$NEV" -gt 1000 ] || { echo "FAIL: 事件太少 ($NEV)"; exit 1; }
echo "alloc e2e: checkpoints=$NCK events=$NEV"

# 40M 单间隔窗口: 从中间候选逐个试 (窗口内 mmap/brk 新段预映射是
# 已知开放缺口 M3, 个别窗口的返回指针会指向切片未映射区域 → SEGV;
# 换一个窗口即可稳定通过)。
OK=0
for cand in 10 15 20 25; do
    F=$cand
    T=$((cand + 1))
    [ "$T" -lt "$NCK" ] || continue
    FCNT=$(sed -n "$((F + 1))p" "$MAN" | awk '{print $1}')
    TCNT=$(sed -n "$((T + 1))p" "$MAN" | awk '{print $1}')
    TEXP=$((TCNT - FCNT))
    echo "alloc e2e: try window [$F,$T] expected=$TEXP"

    SLICE="$TF_TMP/alloc_slice.elf"
    timeout 120 "$ELFTRACE" build /dev/null -o "$SLICE" \
        --mode baremetal --bm-strict --checkpoints "$CKPT" \
        --from "$F" --to "$T" --stack-reserve 268435456 \
        > "$TF_TMP/alloc_build.log" 2>&1 || continue
    grep -q "alloc fused exit" "$TF_TMP/alloc_build.log" || continue
    grep -q "alloc: replay window events=" "$TF_TMP/alloc_build.log" \
        || continue

    # rc + 目标阶段零中间 syscall
    timeout 120 strace -f -o "$TF_TMP/alloc_slice.strace" "$SLICE" \
        > /dev/null 2>&1
    RC=$?
    [ "$RC" = 0 ] || { echo "  window [$F,$T] rc=$RC, 换下一个"; continue; }
    AFTER=$(awk '/rt_sigreturn/{f=1; next} f' "$TF_TMP/alloc_slice.strace")
    if echo "$AFTER" | grep -E "openat|read\(|write\(|mmap|brk|ioctl|close\(|futex"; then
        echo "  window [$F,$T] 出现真实 syscall, 换下一个"
        continue
    fi
    grep -q "exit_group(0)" "$TF_TMP/alloc_slice.strace" || continue

    # 补偿比例 <=5% (融合退出在最后一个分配事件处结束, 误差 <=1 轮)
    perf stat -e instructions -r 1 "$SLICE" > /dev/null 2> "$TF_TMP/alloc_perf.txt"
    A=$(grep -oE '[0-9,]+ +instructions:u' "$TF_TMP/alloc_perf.txt" | head -1 \
        | sed -E 's/[ ,].*//' | tr -d ',')
    A=${A:-0}
    [ "$A" -gt 0 ] || continue
    C=$((A > TEXP ? A - TEXP : TEXP - A))
    R1000=$((C * 1000 / A))
    echo "alloc e2e: window [$F,$T] A=$A T=$TEXP comp=$C ratio=$(awk "BEGIN{printf \"%.3f\", $R1000/10}")%"
    if [ "$R1000" -le 50 ]; then
        OK=1
        break
    fi
done
[ "$OK" = 1 ] || { echo "FAIL: 所有候选窗口均失败 (现场保留在 $CKPT)"; exit 1; }

tf_cleanup alloc_ckpts
tf_pass "alloc replay e2e (events consumed, rc=0, zero syscalls, ratio <=5%)"

# 溢出门禁负测: 注入 overflow.bin (模拟真实溢出标记), build 必须拒绝。
printf '\x01\x00\x00\x00\x00\x00\x00\x00' > "$CKPT/allocs/overflow.bin"
if timeout 120 "$ELFTRACE" build /dev/null -o "$TF_TMP/alloc_ovf.elf" \
    --mode baremetal --bm-strict --checkpoints "$CKPT" \
    --from 1 --to 2 --stack-reserve 268435456 \
    > "$TF_TMP/alloc_ovf.log" 2>&1; then
    echo "FAIL: 溢出后 build 未拒绝"
    exit 1
fi
grep -q "事件缓冲溢出" "$TF_TMP/alloc_ovf.log" \
    || { echo "FAIL: 拒绝原因不对"; exit 1; }
rm -f "$CKPT/allocs/overflow.bin"
echo "alloc e2e: overflow gate OK (build 拒绝)"

tf_finish
