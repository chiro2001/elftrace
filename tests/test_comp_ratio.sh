#!/bin/bash
# aarch64 strict baremetal: 补偿指令比例指标
#
# 定义:
#   预期指令数 T  = manifest[to].count - manifest[from].count
#   实际指令数 A  = perf stat -e instructions 切片运行结果
#   补偿指令数 C  = |A - T|
#   补偿比例 R    = C / A, 要求 R <= 5%
#
# 实现: 先按默认 K 组装, perf 实测 A; 若 R 超标, 用 K <- K*T/A 迭代
# 校准 (A 与 K 近似线性), 最多 10 轮。
set -u
cd "$(dirname "$0")/.."
source tests/testlib.sh

if [ "$(uname -m)" != "aarch64" ]; then
    echo "SKIP: 补偿指令比例指标仅 aarch64 (--bm-strict)"
    exit 0
fi

tf_setup
tf_cleanup prog_calib
ELFTRACE="$TF_ELFTRACE"

gcc -O0 -g -o "$TF_TMP/prog_calib" tests/prog_calib.c || exit 1

rm -rf "$TF_TMP/calib_ckpts"
"$TF_TMP/prog_calib" > "$TF_TMP/calib_tr.out" 2>&1 &
PID=$!
tf_wait_marker calib_tr READY 20 || { echo "FAIL: READY"; exit 1; }
timeout 180 "$ELFTRACE" trace "$PID" --every 40000000 \
    --out "$TF_TMP/calib_ckpts" > /dev/null 2>&1
wait "$PID" 2>/dev/null
tf_cleanup prog_calib

MAN="$TF_TMP/calib_ckpts/manifest.txt"
[ -f "$MAN" ] || { echo "FAIL: no manifest"; exit 1; }
NCK=$(wc -l < "$MAN")
[ "$NCK" -ge 6 ] || { echo "FAIL: only $NCK checkpoints"; exit 1; }

FROM=$((NCK / 2 - 1))
TO=$((FROM + 1))
FROM_CNT=$(sed -n "$((FROM + 1))p" "$MAN" | awk '{print $1}')
TO_CNT=$(sed -n "$((TO + 1))p" "$MAN" | awk '{print $1}')
T=$((TO_CNT - FROM_CNT))
echo "comp-ratio: window [$FROM,$TO] expected=$T instructions"

SLICE="$TF_TMP/calib_slice.elf"
PERF="$TF_TMP/calib_perf.txt"
BUILD_LOG="$TF_TMP/calib_build.log"
K=0
PREV_K=0
OK=0

for iter in $(seq 1 10); do
    ARGS="--mode baremetal --bm-strict --checkpoints $TF_TMP/calib_ckpts \
          --from $FROM --to $TO --stack-reserve 67108864"
    if [ "$K" -gt 0 ]; then
        ARGS="$ARGS --bm-exit-count $K"
    fi
    "$ELFTRACE" build /dev/null -o "$SLICE" $ARGS > "$BUILD_LOG" 2>&1 \
        || { echo "FAIL[iter $iter]: build"; tail -10 "$BUILD_LOG"; exit 1; }
    if [ "$K" -eq 0 ]; then
        K=$(grep -oE 'K=[0-9]+' "$BUILD_LOG" | head -1 | cut -d= -f2)
        K=${K:-0}
        [ "$K" -gt 0 ] || { echo "FAIL: no loop counter in build"; exit 1; }
        echo "  default K=$K"
    fi

    perf stat -e instructions -r 1 "$SLICE" > /dev/null 2> "$PERF"
    A=$(grep -oE '[0-9,]+ +instructions:u' "$PERF" | head -1 \
        | sed -E 's/[ ,].*//' | tr -d ',')
    A=${A:-0}
    [ "$A" -gt 0 ] || { echo "FAIL[iter $iter]: perf instructions"; exit 1; }
    C=$((A > T ? A - T : T - A))
    R1000=0
    [ "$A" -gt 0 ] && R1000=$((C * 1000 / A))
    echo "  iter $iter: K=$K actual=$A expected=$T comp=$C ratio=$(awk "BEGIN{printf \"%.3f\", $R1000/10}")%"

    if [ "$R1000" -le 50 ]; then
        OK=1
        break
    fi
    PREV_K=$K
    K=$((K * T / A))
    [ "$K" -lt 1 ] && K=1
    [ "$K" = "$PREV_K" ] && { echo "FAIL: K converged but ratio ${R}%"; break; }
done

[ "$OK" = 1 ] || { echo "FAIL: 补偿指令比例无法收敛到 <=5%"; exit 1; }

# 目标阶段零 syscall (首个 rt_sigreturn 后只允许 exit_group)
timeout 60 strace -o "$TF_TMP/calib_slice.strace" "$SLICE" > /dev/null 2>&1
AFTER=$(awk '/rt_sigreturn/{f=1} f' "$TF_TMP/calib_slice.strace")
if echo "$AFTER" | grep -E "openat|read\(|write\(|mmap|brk|ioctl|close\("; then
    echo "FAIL: 目标阶段出现真实 syscall"
    echo "$AFTER" | head -5
    exit 1
fi
grep -q "exit_group" "$TF_TMP/calib_slice.strace" \
    || { echo "FAIL: 无 exit_group"; exit 1; }

echo "PASS: 补偿指令比例 $(awk "BEGIN{printf \"%.3f\", $R1000/10}")% (actual=$A expected=$T comp=$C)"
tf_pass "compensation instruction ratio ($(awk "BEGIN{printf \"%.3f\", $R1000/10}")% <= 5%)"
tf_finish
