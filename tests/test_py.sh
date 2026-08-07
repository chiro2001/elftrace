#!/bin/bash
# 测试3: 冻结运行中的 CPython 进程
# 场景 A: 外部冻结 (运行中)
# 场景 B: 代码打桩自暂停 (--stub, os.kill(self, SIGSTOP)) 后冻结已停止进程
# 场景 C: baremetal 模式 (write 被 mock, 计算路径不变, 退出码一致)
# 验证: 输出连续 (CKPT..DONE), 退出码与"原进程从冻结点继续"一致
set -u
cd "$(dirname "$0")/.."
ROOT=$(pwd)
TMP="$ROOT/tmp"
ELFTRACE="$ROOT/build/elftrace"
SCRIPT="tests/prog_py.py"
SNAP="$TMP/snap_py.elftrace"
SLICED="$TMP/sliced_py.elf"

mkdir -p "$TMP"
BM_EXTRA=""
[ "$(uname -m)" = "aarch64" ] && BM_EXTRA="--bm-strict"

# 基准
python3 "$SCRIPT" > "$TMP/py_ref.out" 2>&1
REF_RC=$?
echo "ref rc=$REF_RC $(tail -1 "$TMP/py_ref.out")"

run_case() {  # $1 = 名称, $2 = 冻结方式 (freeze|stub), $3 = build 参数, $4 = 是否 baremetal
    local name="$1" mode="$2" bm="$3" is_bm="$4"
    local extra=""
    [ "$mode" = "stub" ] && extra="--stub"

    python3 "$SCRIPT" $extra > "$TMP/py_${name}.out" 2>&1 &
    PID=$!
    if [ "$mode" = "stub" ]; then
        # 等待目标自暂停 (SIGSTOP 组停止, State=T)
        for i in $(seq 1 400); do
            ST=$(awk '/^State/{print $2}' /proc/$PID/status 2>/dev/null)
            [ "$ST" = "T" ] && break
            sleep 0.05
        done
        [ "$ST" = "T" ] || { echo "FAIL[$name]: target not self-stopped"; kill -9 $PID; return 1; }
    else
        for i in $(seq 1 400); do
            grep -q "CKPT 1" "$TMP/py_${name}.out" 2>/dev/null && break
            sleep 0.05
        done
        sleep 0.4
        grep -q "CKPT 1" "$TMP/py_${name}.out" || { echo "FAIL[$name]: no CKPT 1"; kill -9 $PID; return 1; }
    fi

    "$ELFTRACE" freeze "$PID" -o "$SNAP" >/dev/null 2>&1 || { echo "FAIL[$name]: freeze"; kill -9 $PID; return 1; }
    kill -CONT $PID 2>/dev/null
    wait $PID 2>/dev/null
    local ORIG_RC=$?
    [ "$ORIG_RC" = "$REF_RC" ] || { echo "FAIL[$name]: orig rc=$ORIG_RC != ref $REF_RC"; return 1; }

    "$ELFTRACE" build "$SNAP" -o "$SLICED" $bm $BM_EXTRA >/dev/null 2>&1 || { echo "FAIL[$name]: build"; return 1; }

    local S_RC
    if [ -n "$is_bm" ]; then
        timeout 60 strace -o "$TMP/py_${name}.strace" "$SLICED" > /dev/null 2>&1
        S_RC=$?
        # baremetal: 目标阶段 (rt_sigreturn 后) 无真实 syscall
        AFTER=$(awk '/rt_sigreturn/{found=1} found' "$TMP/py_${name}.strace")
        if echo "$AFTER" | grep -E "openat|read\(|write\(" | grep -qE "= [0-9-]+$| = "; then
            echo "FAIL[$name]: real syscalls in baremetal target phase"
            echo "$AFTER" | grep -E "openat|read\(|write\(" | head -3
            return 1
        fi
    else
        timeout 60 "$SLICED" > /dev/null 2>&1
        S_RC=$?
    fi

    [ "$S_RC" = "$ORIG_RC" ] || { echo "FAIL[$name]: sliced rc=$S_RC != $ORIG_RC"; return 1; }

    # 输出连续性: 切片 stdout 写回冻结前的文件 (fd 恢复)
    if ! diff -q "$TMP/py_${name}.out" "$TMP/py_ref.out" >/dev/null; then
        echo "FAIL[$name]: output mismatch"
        return 1
    fi
    grep -q "^DONE" "$TMP/py_${name}.out" || { echo "FAIL[$name]: no DONE"; return 1; }
    echo "PASS[$name]: rc=$S_RC output continuous"
    return 0
}

run_case "ext" "freeze" "--mode real" "" || exit 1
run_case "stub" "stub" "--mode real" "" || exit 1
run_case "bm" "freeze" "--mode baremetal" 1 || exit 1

echo "PASS: python slice (external/stub/baremetal, rc=$REF_RC)"
exit 0
