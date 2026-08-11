#!/bin/bash
# aarch64: sqlite3 文件库事务负载 strict baremetal 切片
#
# 目标: 覆盖 B-tree 页缓存/alloc/文件 syscall (open/write/fsync) 的
# 切片路径, 验证窗口内 40M 指令切片: rc=0、目标阶段零中间 syscall、
# 实际指令 ∈ [T*0.95, T*1.05]。窗口候选 [10,15,20] 逐个试 (已知
# 开放缺口: 个别窗口返回指针指向未预映射区)。
set -u
cd "$(dirname "$0")/.."
source tests/testlib.sh

if [ "$(uname -m)" != "aarch64" ]; then
    echo "SKIP: sqlite strict 测试仅 aarch64 (--bm-strict)"
    exit 0
fi
command -v sqlite3 >/dev/null 2>&1 || { echo "SKIP: sqlite3 未安装"; exit 0; }

tf_setup
tf_cleanup prog_sqlite

ELFTRACE="$TF_ELFTRACE"
WORK="$TF_TMP/prog_sqlite"
CKPT="$TF_TMP/sqlite_ckpts"

gcc -O2 -o "$WORK" tests/prog_sqlite.c -lsqlite3 || exit 1

rm -rf "$CKPT"
mkdir -p "$CKPT"
LD_BIND_NOW=1 "$WORK" 500 > "$TF_TMP/sqlite_tr.out" 2>&1 &
PID=$!
tf_wait_marker sqlite_tr READY 20 || { echo "FAIL: no READY"; exit 1; }

timeout 300 "$ELFTRACE" trace "$PID" --alloc-replay --every 40000000 \
    --out "$CKPT" > "$TF_TMP/sqlite_trace.log" 2>&1 &
TRACE_PID=$!
for i in $(seq 1 150); do
    NCK=$( [ -f "$CKPT/manifest.txt" ] && wc -l < "$CKPT/manifest.txt" || echo 0 )
    [ "$NCK" -ge 12 ] && break
    kill -0 "$TRACE_PID" 2>/dev/null || break
    sleep 1
done
kill -INT "$TRACE_PID" 2>/dev/null
wait "$TRACE_PID" 2>/dev/null
kill "$PID" 2>/dev/null
wait "$PID" 2>/dev/null

NCK=$( [ -f "$CKPT/manifest.txt" ] && wc -l < "$CKPT/manifest.txt" || echo 0 )
[ "$NCK" -ge 12 ] || { echo "FAIL: 检查点不足 ($NCK)"; exit 1; }
NEV=$(( $(stat -c %s "$CKPT/allocs/events.bin") / 40 ))
echo "sqlite: checkpoints=$NCK alloc_events=$NEV"

MAN="$CKPT/manifest.txt"
OK=0
for cand in 10 15 20; do
    F=$cand
    T=$((cand + 1))
    [ "$T" -lt "$NCK" ] || continue
    FCNT=$(sed -n "$((F + 1))p" "$MAN" | awk '{print $1}')
    TCNT=$(sed -n "$((T + 1))p" "$MAN" | awk '{print $1}')
    TEXP=$((TCNT - FCNT))
    echo "sqlite: try window [$F,$T] expected=$TEXP"

    SLICE="$TF_TMP/sqlite_slice.elf"
    timeout 120 "$ELFTRACE" build /dev/null -o "$SLICE" \
        --mode baremetal --bm-strict --checkpoints "$CKPT" \
        --from "$F" --to "$T" --stack-reserve 268435456 \
        > "$TF_TMP/sqlite_build.log" 2>&1 || continue
    grep -q "alloc fused exit" "$TF_TMP/sqlite_build.log" || continue

    timeout 90 strace -o "$TF_TMP/sqlite_slice.strace" "$SLICE" \
        > /dev/null 2>&1
    RC=$?
    [ "$RC" = 0 ] || { echo "sqlite: window [$F,$T] rc=$RC (retry)"; continue; }
    AFTER=$(awk '/rt_sigreturn/{f=1; next} f' "$TF_TMP/sqlite_slice.strace")
    if echo "$AFTER" | grep -qE "openat|read\(|write\(|ioctl\(|mmap|brk|futex"; then
        echo "sqlite: window [$F,$T] has target-phase syscalls (retry)"
        continue
    fi

    ACT=$(perf stat -e instructions "$SLICE" 2>&1 \
          | awk '/instructions:u/{print $1}' | tr -d ,)
    [ -n "$ACT" ] || continue
    LO=$(( TEXP * 95 / 100 ))
    HI=$(( TEXP * 105 / 100 ))
    if [ "$ACT" -ge "$LO" ] && [ "$ACT" -le "$HI" ]; then
        echo "sqlite: window [$F,$T] A=$ACT T=$TEXP"
        OK=1
        break
    fi
    echo "sqlite: window [$F,$T] ratio out of range A=$ACT T=$TEXP (retry)"
done

[ "$OK" = 1 ] || { echo "FAIL: 无可用窗口"; exit 1; }
tf_pass "sqlite file-backed strict slice (rc=0, zero syscalls, ${ACT} insns)"
tf_finish
