#!/bin/bash
# 测试: 指令区间切片指令数精度
#
# 1. trace 采集检查点, 验证采样点计数精确 (manifest 相邻 count 差 == N)
# 2. 组装多组不同指令数区间 (--from K --to M):
#    - 内部验证: stub perf 打印的 IPC 计数 vs 预期 (M-K)*N, 误差 < 1%
#    - 外部验证: perf stat 数切片用户态指令 vs 预期, 误差 < 1%
set -u
cd "$(dirname "$0")/.."
source tests/testlib.sh

tf_setup
tf_cleanup prog_interval slice_iv
N=200000000
PAIRS="1 4  2 6  3 7"
PROG="$TF_TMP/prog_interval"
CKPTS="$TF_TMP/ckpts_interval"

# 0. 编译测试程序 (STL + 纯计算, 运行时长 ~10s)
g++ -O2 -o "$PROG" tests/prog_cpp.cpp || { echo "FAIL: compile"; exit 1; }

# 1. trace 采集检查点
rm -rf "$CKPTS"
tf_run_bg "tr" "$PROG"
sleep 0.3
timeout 8 "$TF_ELFTRACE" trace "$TF_PID" --every "$N" --out "$CKPTS" \
    > /dev/null 2>&1
tf_cleanup prog_interval

[ -f "$CKPTS/manifest.txt" ] || { echo "FAIL: no manifest"; exit 1; }
NCKPT=$(wc -l < "$CKPTS/manifest.txt")
[ "$NCKPT" -ge 8 ] || { echo "FAIL: only $NCKPT checkpoints"; exit 1; }
echo "trace: $NCKPT checkpoints (every $N)"

# 2. manifest 采样点精度: 相邻 count 差必须 == N
awk '{print $1}' "$CKPTS/manifest.txt" | python3 -c "
import sys
prev = None
for line in sys.stdin:
    c = int(line)
    if prev is not None and c - prev != $N:
        print('FAIL: count jump %d -> %d' % (prev, c))
        sys.exit(1)
    prev = c
print('manifest counts exact (step %d)' % $N)
" || exit 1

# 3. 每组区间: 内部 + 外部指令数验证
FAILED=0
set -- $PAIRS
while [ $# -ge 2 ]; do
    K=$1; M=$2; shift 2
    EXP=$(( (M - K) * N ))
    SLICE="$TF_TMP/slice_iv_${K}_${M}.elf"

    tf_cleanup slice_iv
    tf_build /dev/null "$SLICE" --mode real \
        --checkpoints "$CKPTS" --from "$K" --to "$M" \
        || { echo "FAIL[$K-$M]: build"; FAILED=1; continue; }

    # 内部: stub perf 计数 (stdout 被 fd 恢复写回 tr.out, 偏移空洞含 NUL)
    : > "$TF_TMP/tr.out"
    timeout 90 "$SLICE" > /dev/null 2>&1
    tf_cleanup slice_iv
    CNT=$(tr -d '\0' < "$TF_TMP/tr.out" | grep "IPC:" | tail -1 \
           | grep -oE "[0-9]+")
    if [ -z "$CNT" ]; then
        echo "FAIL[$K-$M]: no IPC count"; FAILED=1
    else
        ERR=$(python3 -c "
e = abs(int('$CNT') - $EXP) / $EXP * 100
print('%.4f' % e)")
        OK=$(python3 -c "print(0 if abs(int('$CNT') - $EXP) / $EXP < 0.01 else 1)")
        echo "  [$K-$M] internal: cnt=$CNT expect=$EXP err=${ERR}% $([ $OK = 0 ] && echo OK || echo FAIL)"
        [ "$OK" = 0 ] || FAILED=1
    fi

    # 外部: perf stat 数切片用户态指令 (perf stat 干扰偶发导致 stub
    # perf 不触发时重试一次)
    : > "$TF_TMP/tr.out"
    perf stat -e instructions:u -- timeout 90 "$SLICE" \
        > /dev/null 2> "$TF_TMP/perf_iv.log"
    tf_cleanup slice_iv
    if ! tr -d '\0' < "$TF_TMP/tr.out" | grep -q "IPC:"; then
        sleep 0.5
        : > "$TF_TMP/tr.out"
        perf stat -e instructions:u -- timeout 90 "$SLICE" \
            > /dev/null 2> "$TF_TMP/perf_iv.log"
        tf_cleanup slice_iv
    fi
    PI=$(grep "instructions:u" "$TF_TMP/perf_iv.log" \
         | grep -oE "[0-9,]+" | tr -d "," | head -1)
    if [ -z "$PI" ]; then
        echo "FAIL[$K-$M]: perf stat failed"; FAILED=1
    else
        ERR=$(python3 -c "
e = abs(int('$PI') - $EXP) / $EXP * 100
print('%.4f' % e)")
        OK=$(python3 -c "print(0 if abs(int('$PI') - $EXP) / $EXP < 0.01 else 1)")
        echo "  [$K-$M] external: cnt=$PI expect=$EXP err=${ERR}% $([ $OK = 0 ] && echo OK || echo FAIL)"
        [ "$OK" = 0 ] || FAILED=1
    fi
done

tf_cleanup prog_interval slice_iv
[ "$FAILED" = 0 ] || exit 1
echo "PASS: interval instruction-count accuracy (internal + external < 1%)"
exit 0
