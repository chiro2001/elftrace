#!/bin/bash
# 角落条件测试: 深递归 / 大栈 (12000 x 8KB = ~96MB 栈, payload ~100MB)
#
# 场景 A (冻结在最大深度, rsp 最深): 切片应完整展开栈帧, 输出/退出码与基准一致。
# 场景 B (冻结在下降途中, MID 标记后): 切片需继续向栈底生长 ~38MB ——
#   当前 elftrace stub 以 MAP_FIXED|ANON (无 MAP_GROWSDOWN) 恢复 [stack],
#   栈无法越过冻结时的边界生长, 预期 SIGSEGV (rc=139) —— 记录为待修复 bug,
#   本脚本对场景 B 保持 FAIL 状态。
set -u
cd "$(dirname "$0")/.."
ROOT=$(pwd)
TMP="$ROOT/tmp"
ELFTRACE="$ROOT/build/elftrace"
PROG="$TMP/prog_stack"

mkdir -p "$TMP"
gcc -O0 -o "$PROG" tests/prog_stack.c || exit 1

# 1. 基准 (~7s)
"$PROG" > "$TMP/stack_ref.out" 2>&1
REF_RC=$?
grep -q "^DONE" "$TMP/stack_ref.out" || { echo "FAIL: ref has no DONE"; exit 1; }
echo "ref rc=$REF_RC $(grep '^DONE' "$TMP/stack_ref.out")"

# ============ 场景 A: 冻结在最大深度 ============
run_scenario_a() {
    "$PROG" > "$TMP/stack_a.out" 2>&1 &
    local PID=$!
    for i in $(seq 1 400); do
        grep -q "^TOP" "$TMP/stack_a.out" 2>/dev/null && break
        sleep 0.05
    done
    grep -q "^TOP" "$TMP/stack_a.out" || { echo "FAIL[A]: TOP not seen"; kill -9 $PID; return 1; }

    "$ELFTRACE" freeze "$PID" -o "$TMP/snap_stack_a.elftrace" > "$TMP/stack_a_freeze.out" 2>&1 \
        || { echo "FAIL[A]: freeze"; kill -9 $PID; return 1; }
    kill -9 $PID 2>/dev/null; wait $PID 2>/dev/null
    PAYLOAD=$(grep -o "[0-9]* bytes payload" "$TMP/stack_a_freeze.out" | head -1)
    echo "[A] frozen at max depth ($PAYLOAD)"

    "$ELFTRACE" build "$TMP/snap_stack_a.elftrace" -o "$TMP/sliced_stack_a.elf" --mode real >/dev/null 2>&1 \
        || { echo "FAIL[A]: build"; return 1; }
    timeout 90 "$TMP/sliced_stack_a.elf" > /dev/null 2>&1
    local RC=$?
    [ "$RC" = "$REF_RC" ] || { echo "FAIL[A]: sliced rc=$RC != ref $REF_RC"; return 1; }
    diff -q "$TMP/stack_a.out" "$TMP/stack_ref.out" >/dev/null \
        || { echo "FAIL[A]: output mismatch"; diff "$TMP/stack_a.out" "$TMP/stack_ref.out" | head -5; return 1; }
    grep -q "^DONE" "$TMP/stack_a.out" || { echo "FAIL[A]: no DONE"; return 1; }
    echo "PASS[A]: deep stack restore at max depth (rc=$RC, output identical, $PAYLOAD)"
    return 0
}

# ============ 场景 B: 冻结在下降途中 (需栈生长) ============
run_scenario_b() {
    "$PROG" > "$TMP/stack_b.out" 2>&1 &
    local PID=$!
    for i in $(seq 1 300); do
        grep -q "^MID" "$TMP/stack_b.out" 2>/dev/null && break
        sleep 0.05
    done
    grep -q "^MID" "$TMP/stack_b.out" || { echo "FAIL[B]: MID not seen"; kill -9 $PID; return 1; }

    "$ELFTRACE" freeze "$PID" -o "$TMP/snap_stack_b.elftrace" > "$TMP/stack_b_freeze.out" 2>&1 \
        || { echo "FAIL[B]: freeze"; kill -9 $PID; return 1; }
    kill -9 $PID 2>/dev/null; wait $PID 2>/dev/null
    STACKSZ=$("$ELFTRACE" dump "$TMP/snap_stack_b.elftrace" | awk '/\[stack\]/{print $3}')
    echo "[B] frozen mid-descent ([stack]=$STACKSZ bytes, needs ~38MB growth)"

    "$ELFTRACE" build "$TMP/snap_stack_b.elftrace" -o "$TMP/sliced_stack_b.elf" --mode real >/dev/null 2>&1 \
        || { echo "FAIL[B]: build"; return 1; }
    timeout 60 "$TMP/sliced_stack_b.elf" > /dev/null 2>&1
    local RC=$?
    if [ "$RC" = "$REF_RC" ]; then
        echo "PASS[B]: stack growth below frozen rsp works (rc=$RC)"
        return 0
    fi
    echo "FAIL[B]: slice rc=$RC != ref $REF_RC — 栈恢复缺少 MAP_GROWSDOWN,"
    echo "       切片进程无法在冻结时栈边界之下生长 (深递归继续执行 → SIGSEGV);"
    echo "       期望 main agent 修复: stub 恢复 [stack] 段时加 MAP_GROWSDOWN"
    return 1
}

A=0; B=0
run_scenario_a && A=1
run_scenario_b && B=1

[ "$A" = 1 ] && [ "$B" = 1 ] && { echo "PASS: deep stack (scenarios A+B)"; exit 0; }
echo "FAIL: deep stack test (scenario A=$A, scenario B=$B)"
exit 1
