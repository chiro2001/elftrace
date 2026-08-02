#!/bin/bash
# 压缩真实负载切片测试: zstd --ultra -22 等价压缩 (libzstd 单线程)
#
# 特点: enwik8.32m (32MB 维基百科文本, 经典压缩基准数据); 压缩进程
#       内存峰值 ~750MB (windowLog=27), 大量读写 (读输入/压缩状态/
#       写输出)。测试流程注意:
#   - 用 zstd_wrap (libzstd 单线程 API): zstd CLI 内部 ZSTDMT 线程池
#     即使 --single-thread 也保留 2 个 worker 线程 (实测 3 线程),
#     elftrace 单线程切片无法恢复 worker → 主线程 cond_wait 挂起/
#     状态错乱 abort。zstd CLI 无法通过环境变量/参数达成真正单线程,
#     故用官方 API 重写入口 (不改库代码), 压缩核心等价 --ultra -22
#   - 冻结时机: RSS 探测 (>400MB, 压缩中期)
#   - 输出对比: 压缩文件 .zst 的 sha256 必须一致 (确定性压缩)
#   - build 必须 --mode real
#
# 前提: tests/ZSTD/setup.sh 已执行 (下载 enwik8 + 编译 zstd_wrap)
set -u
cd "$(dirname "$0")/../.."
source tests/testlib.sh

ZDIR="$TF_ROOT/tests/ZSTD"
DATA="$ZDIR/data/enwik8.32m"
WRAP="$ZDIR/zstd_wrap"
REF_Z="$TF_TMP/enwik8_ref.zst"
SLC_Z="$TF_TMP/enwik8_slice.zst"
SNAP="$TF_TMP/zstd_snap.elftrace"
SLICE="$TF_TMP/zstd_slice.elf"

[ -f "$DATA" ] || { echo "FAIL: 请先运行 tests/ZSTD/setup.sh 下载数据"; exit 1; }
[ -x "$WRAP" ] || { echo "FAIL: 请先运行 tests/ZSTD/setup.sh 编译 zstd_wrap"; exit 1; }
tf_setup
tf_cleanup zstd_wrap

# 1. 基准: 完整压缩
rm -f "$REF_Z"
timeout 180 "$WRAP" "$DATA" "$REF_Z"
REF_RC=$?
[ "$REF_RC" = 0 ] && [ -f "$REF_Z" ] || { echo "FAIL: ref 压缩 rc=$REF_RC"; exit 1; }
REF_H=$(sha256sum "$REF_Z" | cut -d' ' -f1)
echo "ref rc=0 $(du -h "$REF_Z" | cut -f1) sha=$REF_H"

# 2. 冻结压缩中期: RSS > 400MB (峰值 ~750MB)
rm -f "$SLC_Z"
tf_run_bg "zstd" "$WRAP" "$DATA" "$SLC_Z"
LOADED=0
for i in $(seq 1 300); do
    RSS=$(awk '/VmRSS/{print $2}' "/proc/$TF_PID/status" 2>/dev/null || echo 0)
    [ "$RSS" -gt 400000 ] && { LOADED=1; break; }
    kill -0 $TF_PID 2>/dev/null || break
    sleep 0.1
done
[ "$LOADED" = 1 ] || { echo "FAIL: 压缩未达 RSS 阈值"; tf_cleanup zstd_wrap; exit 1; }
kill -0 $TF_PID 2>/dev/null || { echo "FAIL: 目标已退出"; tf_cleanup zstd_wrap; exit 1; }
THR=$(awk '/^Threads/{print $2}' "/proc/$TF_PID/status" 2>/dev/null || echo 0)
[ "$THR" = 1 ] || { echo "FAIL: 目标线程数 $THR != 1 (切片单线程限制)"; tf_cleanup zstd_wrap; exit 1; }

timeout 180 "$TF_ELFTRACE" freeze "$TF_PID" -o "$SNAP" >/dev/null 2>&1 \
    || { echo "FAIL: freeze"; tf_cleanup zstd_wrap; exit 1; }
kill -9 $TF_PID 2>/dev/null

# 3. 切片: 恢复压缩环境继续压缩到同一输出
tf_build "$SNAP" "$SLICE" --mode real || { echo "FAIL: build"; exit 1; }
timeout 180 "$SLICE" >/dev/null 2>&1
S_RC=$?
[ "$S_RC" = "$REF_RC" ] || { echo "FAIL: slice rc=$S_RC != ref $REF_RC"; exit 1; }
[ -f "$SLC_Z" ] || { echo "FAIL: 切片未产出 .zst"; exit 1; }
SLC_H=$(sha256sum "$SLC_Z" | cut -d' ' -f1)
[ "$SLC_H" = "$REF_H" ] || {
    echo "FAIL: .zst hash 不一致 ref=$REF_H slice=$SLC_H"
    exit 1
}

tf_cleanup zstd_wrap
echo "PASS: zstd -22 等价压缩 slice (rc=$S_RC, .zst sha=$SLC_H)"
exit 0
