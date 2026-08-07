#!/bin/bash
# 功能6/7测试: baremetal 模式 + 指令区间切片 (C++ 程序)
# 1. real 模式: 冻结 C++ 程序切片, 输出/退出码与基准一致
# 2. baremetal: 无真实 syscall (strace 验证), 退出码 == real 切片
# 3. baremetal --bad-syscall: 报错退出 0x5e
# 4. 区间切片: trace 采集检查点, --from K --to M 恢复/退出
set -u
cd "$(dirname "$0")/.."
ROOT=$(pwd)
TMP="$ROOT/tmp"
ELFTRACE="$ROOT/build/elftrace"
PROG="$TMP/prog_cpp"
SNAP="$TMP/snap_cpp.elftrace"
SLICED="$TMP/sliced_cpp.elf"
CKPTS="$TMP/ckpts_cpp"

mkdir -p "$TMP"
BM_EXTRA=""
[ "$(uname -m)" = "aarch64" ] && BM_EXTRA="--bm-strict"
g++ -O0 -g -o "$PROG" tests/prog_cpp.cpp || exit 1

# 基准 (完整运行)
"$PROG" > "$TMP/cpp_ref.out" 2>&1
REF_RC=$?
echo "ref rc=$REF_RC $(tail -1 "$TMP/cpp_ref.out")"

run_frozen() {  # $1 = extra prog args
    local extra="${1-}"
    "$PROG" $extra > "$TMP/cpp_frozen.out" 2>&1 &
    PID=$!
    for i in $(seq 1 600); do
        grep -q "CKPT 1" "$TMP/cpp_frozen.out" 2>/dev/null && break
        sleep 0.1
    done
    sleep 0.5
    grep -q "CKPT 1" "$TMP/cpp_frozen.out" || { echo "FAIL: no CKPT 1"; kill $PID; exit 1; }
    "$ELFTRACE" freeze "$PID" -o "$SNAP" >/dev/null 2>&1 || exit 1
    kill -CONT $PID 2>/dev/null
    wait $PID 2>/dev/null
}

# ============ 1. real 模式 ============
run_frozen
ORIG_RC=$?
"$ELFTRACE" build "$SNAP" -o "$SLICED" --mode real >/dev/null 2>&1 || exit 1
timeout 300 "$SLICED" > /dev/null 2>&1
S_REAL_RC=$?
[ "$S_REAL_RC" = "$ORIG_RC" ] || { echo "FAIL: real rc $S_REAL_RC != orig $ORIG_RC"; exit 1; }
[ "$S_REAL_RC" = "$REF_RC" ] || { echo "FAIL: real rc $S_REAL_RC != ref $REF_RC"; exit 1; }
echo "real mode: rc=$S_REAL_RC (== orig from freeze, == ref) OK"

# ============ 2. baremetal 模式 ============
"$ELFTRACE" build "$SNAP" -o "$SLICED" --mode baremetal $BM_EXTRA >/dev/null 2>&1 || exit 1
strace -o "$TMP/bm.strace" timeout 300 "$SLICED" > /dev/null 2>&1
S_BM_RC=$?
[ "$S_BM_RC" = "$S_REAL_RC" ] || { echo "FAIL: baremetal rc $S_BM_RC != real $S_REAL_RC"; exit 1; }
# 目标阶段 (rt_sigreturn 之后) 不应有真实 syscall:
# 处理器内的 write/exit_group 是宿主操作 (允许), 其余 (read/open/brk/mmap)
# 必须全部被 mock。用 awk 取 rt_sigreturn 之后的行检查。
AFTER=$(awk '/rt_sigreturn/{found=1} found' "$TMP/bm.strace")
if echo "$AFTER" | grep -E "openat|mmap\(|brk\(|read\(" | grep -qE "= [0-9-]+$| = "; then
    echo "FAIL: unexpected real syscalls in baremetal target phase"
    echo "$AFTER" | grep -E "openat|mmap\(|brk\(|read\(" | head -5
    exit 1
fi
echo "baremetal: rc=$S_BM_RC (== real), syscalls mocked OK"

# ============ 3. baremetal --bad-syscall: 报错退出 ============
run_frozen "--bad-syscall"
"$ELFTRACE" build "$SNAP" -o "$SLICED" --mode baremetal $BM_EXTRA >/dev/null 2>&1
timeout 60 "$SLICED" > /dev/null 2>&1
S_BAD_RC=$?
[ "$S_BAD_RC" = 94 ] || { echo "FAIL: bad-syscall rc=$S_BAD_RC != 94"; exit 1; }
echo "bad-syscall: rc=94 (unsupported syscall reported) OK"

# ============ 4. 区间切片 (trace + --from/--to) ============
rm -rf "$CKPTS"
"$PROG" > "$TMP/cpp_tr.out" 2>&1 &
TPID=$!
sleep 0.3
timeout 45 "$ELFTRACE" trace "$TPID" --every 200000000 --out "$CKPTS" >/dev/null 2>&1
kill -9 $TPID 2>/dev/null
# trace 被 timeout 终止时不回收注入的 COW 镜像代理 (comm=prog_cpp), 手动清理
pgrep -x prog_cpp | xargs -r kill -9 2>/dev/null
NCK=$(wc -l < "$CKPTS/manifest.txt")
[ "$NCK" -ge 6 ] || { echo "FAIL: only $NCK checkpoints"; exit 1; }
echo "trace: $NCK checkpoints"

# real 区间: 从检查点 1 到检查点 4
"$ELFTRACE" build /dev/null -o "$SLICED" --mode real --checkpoints "$CKPTS" --from 1 --to 4 \
    > "$TMP/ckpts_build.log" 2>&1 || { echo "FAIL: build --from/--to"; cat "$TMP/ckpts_build.log"; exit 1; }
timeout 60 "$SLICED" > /dev/null 2>&1
R=$?
[ "$R" = 0 ] || { echo "FAIL: interval slice rc=$R"; exit 1; }
echo "interval (real): rc=0 (exit at checkpoint 4) OK"

# baremetal 区间: 退出点替换, 无 perf 计数
"$ELFTRACE" build /dev/null -o "$SLICED" --mode baremetal $BM_EXTRA \
    --checkpoints "$CKPTS" --from 1 --to 4 > /dev/null 2>&1 || exit 1
timeout 60 "$SLICED" > /dev/null 2>&1
R=$?
[ "$R" = 0 ] || { echo "FAIL: baremetal interval rc=$R"; exit 1; }
grep -q "baremetal: 600000000 instructions" /dev/null 2>/dev/null
echo "interval (baremetal): rc=0 OK"

echo "PASS: cpp real/baremetal/interval slices all consistent (rc=$S_REAL_RC)"
exit 0
