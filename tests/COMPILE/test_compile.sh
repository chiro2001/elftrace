#!/bin/bash
# 编译器真实负载切片测试: clang -O2 -g -c sqlite3.c (合并源文件 9.5MB)
#
# 特点: 编译器是真实世界最典型生产负载; 单翻译单元编译内存峰值
#       ~400MB (RSS), 中间表示与调度器读写极多。elftrace 单线程
#       限制: clang 编译单文件不 fork 子进程 (gcc 会 fork cc1, 故用
#       clang)。测试流程注意:
#   - 冻结时机: RSS 探测 (编译中期, >250MB 触发)
#   - 输出对比: 编译产物 .o 的 sha256 必须一致 (确定性编译)
#   - build 必须 --mode real (baremetal 默认, 编译器 syscall 密集
#     不受支持)
#
# 前提: tests/COMPILE/setup.sh 已执行 (下载 sqlite-amalgamation)
set -u
cd "$(dirname "$0")/../.."
source tests/testlib.sh

SRC="$TF_ROOT/tests/COMPILE/sqlite-src/sqlite3.c"
REF_O="$TF_TMP/sqlite3_ref.o"
SLC_O="$TF_TMP/sqlite3_slice.o"
SNAP="$TF_TMP/compile_snap.elftrace"
SLICE="$TF_TMP/compile_slice.elf"

[ -f "$SRC" ] || { echo "FAIL: 请先运行 tests/COMPILE/setup.sh 下载 sqlite3.c"; exit 1; }
command -v clang >/dev/null || { echo "FAIL: 需要 clang"; exit 1; }
tf_setup
tf_cleanup clang

# 1. 基准: 完整编译
rm -f "$REF_O"
timeout 120 clang -O2 -g -c "$SRC" -o "$REF_O" >/dev/null 2>&1
REF_RC=$?
[ "$REF_RC" = 0 ] && [ -f "$REF_O" ] || { echo "FAIL: ref 编译 rc=$REF_RC"; exit 1; }
REF_H=$(sha256sum "$REF_O" | cut -d' ' -f1)
echo "ref rc=0 $(du -h "$REF_O" | cut -f1) sha=$REF_H"

# 2. 冻结编译中期: RSS > 250MB (编译 ~13s, 峰值 ~410MB)
rm -f "$SLC_O"
tf_run_bg "clang" clang -O2 -g -c "$SRC" -o "$SLC_O"
LOADED=0
for i in $(seq 1 300); do
    RSS=$(awk '/VmRSS/{print $2}' "/proc/$TF_PID/status" 2>/dev/null || echo 0)
    [ "$RSS" -gt 250000 ] && { LOADED=1; break; }
    kill -0 $TF_PID 2>/dev/null || break
    sleep 0.1
done
[ "$LOADED" = 1 ] || { echo "FAIL: 编译未达 RSS 阈值"; tf_cleanup clang; exit 1; }
kill -0 $TF_PID 2>/dev/null || { echo "FAIL: 目标已退出"; tf_cleanup clang; exit 1; }
THR=$(awk '/^Threads/{print $2}' "/proc/$TF_PID/status" 2>/dev/null || echo 0)
[ "$THR" = 1 ] || { echo "FAIL: 目标线程数 $THR != 1 (切片单线程限制)"; tf_cleanup clang; exit 1; }

timeout 120 "$TF_ELFTRACE" freeze "$TF_PID" -o "$SNAP" >/dev/null 2>&1 \
    || { echo "FAIL: freeze"; tf_cleanup clang; exit 1; }
kill -9 $TF_PID 2>/dev/null

# 3. 切片: 恢复编译环境继续编译到同一输出
tf_build "$SNAP" "$SLICE" --mode real || { echo "FAIL: build"; exit 1; }
timeout 120 "$SLICE" >/dev/null 2>&1
S_RC=$?
[ "$S_RC" = "$REF_RC" ] || { echo "FAIL: slice rc=$S_RC != ref $REF_RC"; exit 1; }
[ -f "$SLC_O" ] || { echo "FAIL: 切片未产出 .o"; exit 1; }
SLC_H=$(sha256sum "$SLC_O" | cut -d' ' -f1)
[ "$SLC_H" = "$REF_H" ] || {
    echo "FAIL: .o hash 不一致 ref=$REF_H slice=$SLC_H"
    exit 1
}

tf_cleanup clang
echo "PASS: clang -O2 -g sqlite3.c slice (rc=$S_RC, .o sha=$SLC_H)"
exit 0
