#!/bin/bash
# elftrace 测试汇总入口: 一键运行全部自动化测试
#
# 测试矩阵:
#   basic    基础功能1: 单线程循环程序冻结->切片->等价恢复 (real)
#   dbg      进阶功能2: 调试符号 (PIE bias/DWARF/gdb)
#   fd       进阶功能3: fd 重开 + 偏移续写
#   ipc      进阶功能4: perf 指令计数自动退出
#   cpp      进阶功能6/7: C++ 程序 real/baremetal/区间切片
#   fd_rw    测试2: 文件读写程序 (real/baremetal)
#   py       测试3: CPython 进程 (外部冻结/打桩自暂停/baremetal)
#   syscall  角落1: 冻结在 syscall 中 (in-flight 丢失告警 + 切片续跑)
#   stack    角落2: 深递归大栈 (冻结在最大深度; 下降途中冻结需栈生长)
#   bigmem   角落3: 128MB 匿名映射大 payload 切片
#   thread   角落5: 多线程进程 (语义未定义, 验证不崩溃/主线程一致)
#   append   角落6: O_APPEND 追加 fd 偏移语义
#   bareheap 角落9: baremetal brk 边界 (mock 拒绝) + real 模式 brk 恢复
#
# 需要 kernel.yama.ptrace_scope=0 (或目标允许被跟踪)。
set -u
cd "$(dirname "$0")/.."
ROOT=$(pwd)
LOG="$ROOT/tmp/test_run.log"
mkdir -p "$ROOT/tmp"

TESTS="basic dbg fd ipc cpp fd_rw py syscall stack bigmem thread append bareheap interval"
PASS=0
FAIL=0

# 清理残留测试进程 (避免干扰)
for p in prog_simple prog_fd prog_fd_rw prog_cpp python3 prog_syscall prog_stack prog_bigmem prog_thread prog_append prog_bareheap; do
    pgrep -x "$p" | xargs -r kill -9 2>/dev/null
done
sleep 0.3

echo "elftrace test suite ($(date '+%F %T'))"
echo "=========================================="
for t in $TESTS; do
    printf "%-8s " "[$t]"
    if timeout 600 "tests/test_$t.sh" > "$LOG" 2>&1; then
        LAST=$(grep -E "^PASS" "$LOG" | tail -1)
        echo "PASS  (${LAST#PASS: })"
        PASS=$((PASS + 1))
    else
        echo "FAIL"
        tail -5 "$LOG" | sed 's/^/       /'
        FAIL=$((FAIL + 1))
    fi
done
echo "=========================================="
echo "result: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
