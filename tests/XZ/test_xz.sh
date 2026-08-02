#!/bin/bash
# 压缩真实负载切片测试: xz -9e --lzma2=dict=256MiB -T1 (真实 CLI 工具)
#
# 特点: xz 是真实世界常用压缩工具; 单线程路径无 pthread (实测
#       Threads=1, 与 zstd CLI 的 ZSTDMT 线程池不同 — 配置即可达成
#       真正单线程); 256MiB 字典 → RSS ~540MB; 快照/切片 ~2.8GB
#       (超过单次 read/write 的 2GB 上限, 回归验证该修复)。测试
#       流程注意:
#   - 冻结时机: RSS 探测 (>300MB, 压缩中期)
#   - 冻结前断言 Threads==1 (配置生效与否的显式校验)
#   - 输出对比: 压缩文件 .xz 的 sha256 必须一致 (确定性压缩)
#   - build 必须 --mode real
#
# 前提: tests/XZ/setup.sh 已执行 (下载 enwik8 数据)
set -u
cd "$(dirname "$0")/../.."
source tests/testlib.sh

DATA="$TF_ROOT/tests/XZ/data/enwik8.32m"
REF_XZ="$TF_TMP/enwik8_ref.xz"
SLC_XZ="$TF_TMP/enwik8_slice.xz"
SNAP="$TF_TMP/xz_snap.elftrace"
SLICE="$TF_TMP/xz_slice.elf"

[ -f "$DATA" ] || { echo "FAIL: 请先运行 tests/XZ/setup.sh 下载数据"; exit 1; }
command -v xz >/dev/null || { echo "FAIL: 需要 xz"; exit 1; }
tf_setup
tf_cleanup xz

# 1. 基准: 完整压缩 (dict 256MiB, 单线程)
rm -f "$REF_XZ"
timeout 240 xz -9e --lzma2=dict=256MiB -T1 -f "$DATA" -c > "$REF_XZ" 2>/dev/null
REF_RC=$?
[ "$REF_RC" = 0 ] && [ -f "$REF_XZ" ] || { echo "FAIL: ref 压缩 rc=$REF_RC"; exit 1; }
REF_H=$(sha256sum "$REF_XZ" | cut -d' ' -f1)
echo "ref rc=0 $(du -h "$REF_XZ" | cut -f1) sha=$REF_H"

# 2. 冻结压缩中期: RSS > 300MB (峰值 ~540MB)
rm -f "$SLC_XZ"
xz -9e --lzma2=dict=256MiB -T1 -f "$DATA" -c > "$SLC_XZ" 2>/dev/null &
TF_PID=$!
LOADED=0
for i in $(seq 1 300); do
    RSS=$(awk '/VmRSS/{print $2}' "/proc/$TF_PID/status" 2>/dev/null || echo 0)
    [ "$RSS" -gt 300000 ] && { LOADED=1; break; }
    kill -0 $TF_PID 2>/dev/null || break
    sleep 0.05
done
[ "$LOADED" = 1 ] || { echo "FAIL: 压缩未达 RSS 阈值"; tf_cleanup xz; exit 1; }
kill -0 $TF_PID 2>/dev/null || { echo "FAIL: 目标已退出"; tf_cleanup xz; exit 1; }
THR=$(awk '/^Threads/{print $2}' "/proc/$TF_PID/status" 2>/dev/null || echo 0)
[ "$THR" = 1 ] || { echo "FAIL: 目标线程数 $THR != 1 (切片单线程限制)"; tf_cleanup xz; exit 1; }

timeout 300 "$TF_ELFTRACE" freeze "$TF_PID" -o "$SNAP" >/dev/null 2>&1 \
    || { echo "FAIL: freeze (2.8GB 大快照可能慢)"; tf_cleanup xz; exit 1; }
kill -9 $TF_PID 2>/dev/null
# 注: 不删除目标已写的部分输出文件 — fd 恢复按路径重开, 文件被外部
# 删除时重开失败 (输出会静默落回终端); 保留文件则切片续写偏移正确

# 3. 切片: 恢复压缩环境继续压缩到同一输出
tf_build "$SNAP" "$SLICE" --mode real >/dev/null 2>&1 || { echo "FAIL: build"; exit 1; }
timeout 300 "$SLICE" >/dev/null 2>&1
S_RC=$?
[ "$S_RC" = "$REF_RC" ] || { echo "FAIL: slice rc=$S_RC != ref $REF_RC"; exit 1; }
[ -f "$SLC_XZ" ] || { echo "FAIL: 切片未产出 .xz"; exit 1; }
SLC_H=$(sha256sum "$SLC_XZ" | cut -d' ' -f1)
[ "$SLC_H" = "$REF_H" ] || {
    echo "FAIL: .xz hash 不一致 ref=$REF_H slice=$SLC_H"
    exit 1
}

tf_cleanup xz
echo "PASS: xz -9e 大字典压缩 slice (rc=$S_RC, .xz sha=$SLC_H, 快照 $(du -h "$SNAP" | cut -f1))"
exit 0
