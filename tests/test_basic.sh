#!/bin/bash
# 基础功能测试: 冻结一个运行中的循环程序, 组装为 ELF, 恢复执行并验证等价性。
#
# 验证方式:
#   1. 参考运行: 目标程序完整跑完, 记录输出与退出码 (基准)
#   2. 切片运行: 冻结在 CHECKPOINT 3 之后, 组装 (real 模式), 运行切片
#   3. 断言: 切片输出是基准输出的一个后缀 (从冻结点继续), 退出码一致
set -u
cd "$(dirname "$0")/.."
source tests/testlib.sh

tf_setup
tf_cleanup prog_simple
PROG="$TF_TMP/prog_simple"
SNAP="$TF_TMP/snap.elftrace"
SLICED="$TF_TMP/sliced.elf"
CP="CHECKPOINT 3"

gcc -O0 -g -o "$PROG" tests/prog_simple.c || { echo "FAIL: compile"; exit 1; }

# 1. 基准运行
"$PROG" > "$TF_TMP/ref.out" 2>&1
REF_RC=$?
echo "ref rc=$REF_RC last=$(tail -1 "$TF_TMP/ref.out")"

# 2. 切片: 后台运行目标, 等待 CHECKPOINT 3 出现后冻结
tf_run_bg "frozen" "$PROG"
tf_wait_marker "frozen" "$CP" || { echo "FAIL: checkpoint not reached"; tf_cleanup prog_simple; exit 1; }
sleep 0.3   # 确保已进入下一轮计算循环 (用户态)
tf_freeze "$TF_PID" "$SNAP" || { echo "FAIL: freeze"; tf_cleanup prog_simple; exit 1; }

# 3. 组装 + 运行切片
strace -o "$TF_TMP/tb.strace" "$TF_ELFTRACE" build "$SNAP" -o "$SLICED" --mode real || { echo "FAIL: build"; exit 1; }
tf_run_slice "$SLICED" 60
echo "sliced rc=$TF_SLICE_RC last=$(tail -1 "$TF_TMP/frozen.out")"

# 4. 断言
if [ "$TF_SLICE_RC" != "$REF_RC" ]; then
    echo "FAIL: exit code $TF_SLICE_RC != $REF_RC"
    echo "--- frozen.out ---"; cat "$TF_TMP/frozen.out"
    exit 1
fi
# 切片进程的 fd 1 指向冻结前打开的文件 (frozen.out), 恢复后继续写入原文件,
# 因此完整输出 (CHECKPOINT 0..9 + DONE) 应在 frozen.out 中, 且与基准一致。
if ! diff -q "$TF_TMP/frozen.out" "$TF_TMP/ref.out" >/dev/null; then
    echo "FAIL: frozen.out != ref.out"
    echo "--- frozen.out ---"; cat "$TF_TMP/frozen.out"
    echo "--- ref.out ---"; cat "$TF_TMP/ref.out"
    exit 1
fi

tf_cleanup prog_simple
tf_pass "basic feature (continue from freeze point, rc=$TF_SLICE_RC)"
tf_finish
