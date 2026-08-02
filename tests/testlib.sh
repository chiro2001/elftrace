# tests/testlib.sh — 测试公共框架
#
# 用法: source "$(dirname "$0")/testlib.sh"  (在测试脚本 cd 到项目根后)
#
# 约定:
#   - 所有临时文件放 $TF_TMP (项目 tmp/ 目录)
#   - PASS/FAIL 统一输出; 测试脚本最终按 TF_FAIL 计数退出
#   - 清理残留进程用 tf_cleanup (pgrep -x 精确名, 禁止 -f 匹配自身)
set -u

TF_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF_TMP="$TF_ROOT/tmp"
TF_ELFTRACE="$TF_ROOT/build/elftrace"
TF_PASS=0
TF_FAIL=0

tf_setup() {
    mkdir -p "$TF_TMP"
}

tf_pass() { echo "PASS: $1"; TF_PASS=$((TF_PASS + 1)); }
tf_fail() { echo "FAIL: $1"; TF_FAIL=$((TF_FAIL + 1)); }

# 后台启动目标进程, 输出重定向到 $TF_TMP/$1.out, pid 存 TF_PID
tf_run_bg() {  # <输出名> <命令...>
    TF_OUT="$1"; shift
    "$@" > "$TF_TMP/$TF_OUT.out" 2>&1 &
    TF_PID=$!
}

# 等待输出文件出现 marker (默认 20s 超时)
tf_wait_marker() {  # <输出名> <pattern> [超时秒]
    local out="$1" pat="$2" t="${3:-20}"
    for _ in $(seq 1 $((t * 10))); do
        grep -q "$pat" "$TF_TMP/$out.out" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

# 等待进程进入 SIGSTOP 组停止 (State=T)
tf_wait_stopped() {  # <pid> [超时秒]
    local pid="$1" t="${2:-20}"
    for _ in $(seq 1 $((t * 10))); do
        local st
        st=$(awk '/^State/{print $2}' "/proc/$pid/status" 2>/dev/null)
        [ "$st" = "T" ] && return 0
        sleep 0.1
    done
    return 1
}

# 冻结目标到快照文件
tf_freeze() {  # <pid> <snap文件>
    "$TF_ELFTRACE" freeze "$1" -o "$2" >/dev/null 2>&1
}

# SIGCONT 放行原进程并等待其结束, 退出码存 TF_ORIG_RC
tf_orig_finish() {  # <pid>
    kill -CONT "$1" 2>/dev/null
    wait "$1" 2>/dev/null
    TF_ORIG_RC=$?
}

# 组装切片
tf_build() {  # <snap> <out.elf> [build 参数...]
    local snap="$1" out="$2"; shift 2
    "$TF_ELFTRACE" build "$snap" -o "$out" "$@" 2>&1
}

# 运行切片 (timeout 包裹), 退出码存 TF_SLICE_RC
tf_run_slice() {  # <elf> [timeout秒]
    local elf="$1" t="${2:-60}"
    timeout "$t" "$elf" > /dev/null 2>&1
    TF_SLICE_RC=$?
}

# 从输出文件取"本次运行新增的"最后一条 IPC 计数 (切片 stdout 被 fd
# 恢复写回目标原输出文件, 每次运行追加一行)
tf_ipc_count() {  # <输出名> -> 存 TF_IPC, 无则 -1
    local out="$1" n0=0 line cnt
    n0=$(wc -l < "$TF_TMP/$out.out" 2>/dev/null || echo 0)
    n0=$((n0 - 1)); [ $n0 -lt 0 ] && n0=0
    line=$(tail -n +$((n0 + 1)) "$TF_TMP/$out.out" 2>/dev/null \
           | tr -d '\0' | grep "IPC:" | tail -1)
    cnt=$(echo "$line" | grep -oE "[0-9]+" | head -1)
    TF_IPC=${cnt:--1}
}

# 清理残留测试进程 (pgrep -x 精确名)
tf_cleanup() {
    for p in "$@"; do
        pgrep -x "$p" | xargs -r kill -9 2>/dev/null
    done
}

# 测试收尾: 全部 PASS 则返回 0
tf_finish() {
    echo "result: $TF_PASS passed, $TF_FAIL failed"
    [ "$TF_FAIL" = 0 ]
}
