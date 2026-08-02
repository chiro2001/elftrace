#!/bin/bash
# GAP Benchmark Suite 切片测试 (真实世界图算法负载)
#
# 特点: 图数据大 (bfs -g 21 ~500MB 内存), 算法随机访问内存极多,
#       冻结/采集/恢复均为大镜像。gapbs 默认 OpenMP 多线程 (elftrace
#       单线程限制), 测试用 OMP_NUM_THREADS=1。测试流程注意:
#   - freeze 大内存目标给足超时 (~1.5GB 采集)
#   - 冻结时机: 图构建完成、进入 Trial 计算后 (等 "Trial Time" 输出)
#   - 切片恢复大镜像后继续计算, 输出/退出码与基准对比
#
# 前提: tests/GAP/setup.sh 已执行 (下载并构建 gapbs)
set -u
cd "$(dirname "$0")/../.."
source tests/testlib.sh

GAP="$TF_ROOT/tests/GAP/gapbs"
BFS="$GAP/bfs"
SCALE=21
SNAP="$TF_TMP/gap_snap.elftrace"
SLICE="$TF_TMP/gap_slice.elf"

[ -x "$BFS" ] || { echo "FAIL: 请先运行 tests/GAP/setup.sh 构建 gapbs"; exit 1; }
tf_setup
tf_cleanup bfs

# 1. 基准 (完整运行, 单线程)
timeout 90 env OMP_NUM_THREADS=1 "$BFS" -g $SCALE > "$TF_TMP/gap_ref.out" 2>&1
REF_RC=$?
[ "$REF_RC" = 0 ] || { echo "FAIL: ref rc=$REF_RC"; exit 1; }
grep -q "Graph has" "$TF_TMP/gap_ref.out" \
    || { echo "FAIL: ref 无 Graph 输出"; exit 1; }
echo "ref rc=0 $(grep 'Graph has' "$TF_TMP/gap_ref.out" | head -1)"

# 2. 冻结运行中: 等图构建完成 (RSS 变大 = 图已加载) 后冻结
tf_run_bg "gap" env OMP_NUM_THREADS=1 "$BFS" -g $SCALE
LOADED=0
for i in $(seq 1 300); do
    RSS=$(awk '/VmRSS/{print $2}' "/proc/$TF_PID/status" 2>/dev/null || echo 0)
    [ "$RSS" -gt 500000 ] && { LOADED=1; break; }
    kill -0 $TF_PID 2>/dev/null || break
    sleep 0.2
done
[ "$LOADED" = 1 ] || { echo "FAIL: 图未加载完成 (RSS 探测)"; tf_cleanup bfs; exit 1; }
sleep 0.3   # 进入 Trial 计算
kill -0 $TF_PID 2>/dev/null || { echo "FAIL: 目标已退出"; tf_cleanup bfs; exit 1; }
THR=$(awk '/^Threads/{print $2}' "/proc/$TF_PID/status" 2>/dev/null || echo 0)
[ "$THR" = 1 ] || { echo "FAIL: 目标线程数 $THR != 1 (OMP_NUM_THREADS=1 未生效)"; tf_cleanup bfs; exit 1; }

timeout 180 "$TF_ELFTRACE" freeze "$TF_PID" -o "$SNAP" >/dev/null 2>&1 \
    || { echo "FAIL: freeze (大镜像可能慢)"; tf_cleanup bfs; exit 1; }
kill -9 $TF_PID 2>/dev/null

# 3. 切片组装与运行
tf_build "$SNAP" "$SLICE" --mode real || { echo "FAIL: build"; exit 1; }
timeout 90 "$SLICE" > "$TF_TMP/gap_slice.out" 2>&1
S_RC=$?
[ "$S_RC" = "$REF_RC" ] || {
    echo "FAIL: slice rc=$S_RC != ref $REF_RC"
    tail -3 "$TF_TMP/gap_slice.out"
    exit 1
}
# 切片 stdout 被 fd 恢复写回 gap.out (目标原输出文件)
grep -q "Trial Time" "$TF_TMP/gap.out" \
    || { echo "FAIL: slice 未继续计算 (无 Trial Time)"; exit 1; }

# 4. 输出对比: 排除耗时行 (Generate/Build/Trial/Total Time), 对比其余
grep -vE "Time:" "$TF_TMP/gap_ref.out" > "$TF_TMP/gap_ref_f.out"
grep -vE "Time:" "$TF_TMP/gap.out" > "$TF_TMP/gap_slice_f.out"
if ! diff -q "$TF_TMP/gap_ref_f.out" "$TF_TMP/gap_slice_f.out" >/dev/null; then
    echo "FAIL: 输出不一致"
    diff "$TF_TMP/gap_ref_f.out" "$TF_TMP/gap_slice_f.out" | head -6
    exit 1
fi

tf_cleanup bfs
echo "PASS: GAP bfs -g $SCALE slice (rc=$S_RC, output consistent)"
exit 0
