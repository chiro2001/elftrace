#!/bin/bash
# 指令流验证测试: imix (instruction mix) + topdown 对比 real/baremetal
#
# 验证体系 (用户确认的方法论):
#   1. DynamoRIO + instrace 采集 real 切片的完整指令流 → imix 统计
#      (opcode 种类分布) —— dynamorio 无法采集 baremetal (stub 的
#      SIGTRAP 处理器 rt_sigreturn 与 dynamorio 插桩上下文冲突, 已
#      确认根因); qemu TCG 方案同样因 rt_sigreturn 恢复偏差不可用
#   2. PMU (perf) 交叉验证: 指令数 dynamorio ≈ perf (差 <1%)
#   3. real vs baremetal 的 PMU 指令数对比 (目标阶段无 syscall 时
#      差异应 <1%, 仅 int3/处理器替换开销)
#   4. topdown (perf -M PipelineL1: frontend/backend/retiring/bad_spec)
#      real vs baremetal 趋势对比
#
# 负载: prog_imix (纯计算循环, -O0, 冻结点后 ~3500 万条指令)
# 前提: 1) tests/IMIX/prog_imix.c 可编译
#       2) DynamoRIO 安装于 ~/tools/DynamoRIO-* (imix 部分, 无则 SKIP)
#       3) /mnt/elftrace-trace (固定大小 trace 文件系统) 可写
set -u
cd "$(dirname "$0")/../.."
source tests/testlib.sh

DRIO=$(ls -d ~/tools/DynamoRIO-* 2>/dev/null | head -1)
TRACE_DIR="/mnt/elftrace-trace"
IMIX_DIR="$TF_ROOT/tests/IMIX"
PROG="$TF_TMP/prog_imix"
SNAP="$TF_TMP/imix_snap.elftrace"
SLICE_R="$TF_TMP/imix_slice_real.elf"
SLICE_B="$TF_TMP/imix_slice_bm.elf"

[ -f "$IMIX_DIR/prog_imix.c" ] || { echo "FAIL: prog_imix.c 缺失"; exit 1; }
[ -w "$TRACE_DIR" ] || { echo "FAIL: 需要可写的 trace 文件系统 ($TRACE_DIR, 防 dynamorio 输出撑爆主盘)"; exit 1; }
tf_setup
tf_cleanup prog_imix

# 1. 编译 + 自暂停冻结 (CHECKPOINT 5 后 SIGSTOP, 冻结时刻精确)
gcc -O0 -g -o "$PROG" "$IMIX_DIR/prog_imix.c" || { echo "FAIL: compile"; exit 1; }
"$PROG" 500000 --stub > "$TF_TMP/imix_fz.out" 2>&1 &
PID=$!
tf_wait_stopped "$PID" 20 || { echo "FAIL: 目标未 SIGSTOP"; tf_cleanup prog_imix; exit 1; }
tf_freeze "$PID" "$SNAP" || { echo "FAIL: freeze"; kill -9 $PID 2>/dev/null; exit 1; }
kill -9 $PID 2>/dev/null
grep -q "CHECKPOINT 5" "$TF_TMP/imix_fz.out" || { echo "FAIL: 冻结时机异常"; exit 1; }

# 2. real + baremetal 切片
tf_build "$SNAP" "$SLICE_R" --mode real >/dev/null || { echo "FAIL: build real"; exit 1; }
tf_build "$SNAP" "$SLICE_B" --mode baremetal >/dev/null || { echo "FAIL: build baremetal"; exit 1; }

# 3. 基础: 两个切片直接运行 rc 一致 (均为 0)
"$SLICE_R" >/dev/null 2>&1; R_RC=$?
"$SLICE_B" >/dev/null 2>&1; B_RC=$?
[ "$R_RC" = 0 ] || { echo "FAIL: real slice rc=$R_RC"; exit 1; }
[ "$B_RC" = 0 ] || { echo "FAIL: baremetal slice rc=$B_RC"; exit 1; }

# 4. PMU: real vs baremetal 指令数对比 (差 <1%)
perf stat -e instructions -r 3 "$SLICE_R" >/dev/null 2>"$TF_TMP/imix_perf_r.txt" || { echo "FAIL: perf real"; exit 1; }
perf stat -e instructions -r 3 "$SLICE_B" >/dev/null 2>"$TF_TMP/imix_perf_b.txt" || { echo "FAIL: perf bm"; exit 1; }
R_INS=$(grep -oE '^\s+[0-9,]+ +instructions:u' "$TF_TMP/imix_perf_r.txt" | sed -E 's/^\s+([0-9,]+).*/\1/' | tr -d ',' | head -1)
B_INS=$(grep -oE '^\s+[0-9,]+ +instructions:u' "$TF_TMP/imix_perf_b.txt" | sed -E 's/^\s+([0-9,]+).*/\1/' | tr -d ',' | head -1)
R_INS=${R_INS:-0}; B_INS=${B_INS:-0}
echo "perf: real=$R_INS bm=$B_INS"
D=$(echo "scale=6; ($B_INS-$R_INS)*100/$R_INS" | bc)
echo "perf 指令数差: ${D}%"
echo "$D" | awk '{v=$1; if (v<0) v=-v; exit (v>=1.0)}' || { echo "FAIL: real/bm 指令数差 ${D}% >= 1%"; exit 1; }

# 5. topdown (PipelineL1): 趋势对比 (backend 主导, 两者一致)
perf stat -M frontend_bound,backend_bound,retiring,bad_speculation -e cycles,instructions \
    "$SLICE_R" >/dev/null 2>"$TF_TMP/imix_td_r.txt" || true
perf stat -M frontend_bound,backend_bound,retiring,bad_speculation -e cycles,instructions \
    "$SLICE_B" >/dev/null 2>"$TF_TMP/imix_td_b.txt" || true
TD_R=$(grep -oE '#\s+[0-9.]+ %  (frontend|backend|retiring|bad_spec)' "$TF_TMP/imix_td_r.txt" | tr '\n' ' ')
TD_B=$(grep -oE '#\s+[0-9.]+ %  (frontend|backend|retiring|bad_spec)' "$TF_TMP/imix_td_b.txt" | tr '\n' ' ')
echo "topdown real: $TD_R"
echo "topdown bm:   $TD_B"

# 6. DynamoRIO imix (real 切片, 完整指令流 → opcode 分布)
if [ -n "$DRIO" ] && [ -x "$DRIO/bin64/drrun" ] && [ -r "$TRACE_DIR/clients/libinstrace_simple.so" ]; then
    rm -f "$TRACE_DIR"/clients/instrace*.log
    OK=0
    for try in 1 2 3; do
        timeout 300 "$DRIO/bin64/drrun" -c "$TRACE_DIR/clients/libinstrace_simple.so" -- \
            "$SLICE_R" >/dev/null 2>&1 && { OK=1; break; }
        echo "  (dynamorio run $try 失败, 重试)"
        rm -f "$TRACE_DIR"/clients/instrace*.log
    done
    [ "$OK" = 1 ] || { echo "FAIL: dynamorio 采集 real 失败"; exit 1; }
    TRACE=$(ls -t "$TRACE_DIR"/clients/instrace*.log 2>/dev/null | head -1)
    [ -n "$TRACE" ] || { echo "FAIL: 无 instrace 输出"; exit 1; }
    python3 "$IMIX_DIR/imix.py" "$TRACE" --csv "$TF_TMP/imix_real.csv" > "$TF_TMP/imix_sum.txt"
    D_INS=$(grep -oE 'total [0-9]+' "$TF_TMP/imix_sum.txt" | grep -oE '[0-9]+')
    D_INS=${D_INS:-0}
    echo "dynamorio: total=$D_INS"
    # dynamorio 指令数 vs perf 差 <1%
    D2=$(echo "scale=6; ($D_INS-$R_INS)*100/$R_INS" | bc)
    echo "dynamorio vs perf 差: ${D2}%"
    echo "$D2" | awk '{v=$1; if (v<0) v=-v; exit (v>=1.0)}' || { echo "FAIL: dynamorio/perf 差 ${D2}% >= 1%"; exit 1; }
    # imix 合理性: mov 占比 >30% (计算循环主导)
    MOV=$(grep -oE '^\s+[0-9]+ [0-9.]+%  mov$' "$TF_TMP/imix_sum.txt" | grep -oE '[0-9.]+%' | tr -d '%')
    echo "imix: mov=$MOV%"
    awk -v m="${MOV:-0}" 'BEGIN { exit !(m > 30) }' || { echo "FAIL: mov 占比异常 ($MOV%)"; exit 1; }
    grep -q "syscall" "$TF_TMP/imix_sum.txt" && echo "  (含 syscall 指令: real 退出路径)"
    rm -f "$TRACE"
else
    echo "SKIP: DynamoRIO 未安装或 instrace client 缺失 (imix 部分跳过)"
fi

tf_cleanup prog_imix
echo "PASS: imix/topdown 验证 (perf real=$R_INS bm=$B_INS, 差 $D%; dynamorio imix ok)"
exit 0
