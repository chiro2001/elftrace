#!/bin/bash
# 进阶功能4测试: --ipc N 指令计数自动退出
# 冻结循环程序, 组装 --ipc N, 运行切片:
#   1. 应在目标程序自然结束前因 perf 溢出信号退出 (rc=0)
#   2. 输出 "IPC: <count> instructions" (经恢复后的 fd 1 写入冻结前文件)
#   3. count 应约为 N (含少量 handler/信号路径开销)
set -u
cd "$(dirname "$0")/.."
ROOT=$(pwd)
TMP="$ROOT/tmp"
ELFTRACE="$ROOT/build/elftrace"
PROG="$TMP/prog_simple"
SNAP="$TMP/snap_ipc.elftrace"
SLICED="$TMP/sliced_ipc.elf"
CP="CHECKPOINT 2"
IPC_N=8000000

mkdir -p "$TMP"
gcc -O0 -o "$PROG" tests/prog_simple.c || exit 1

"$PROG" > "$TMP/ipc_frozen.out" 2>&1 &
PID=$!
for i in $(seq 1 200); do
    grep -q "$CP" "$TMP/ipc_frozen.out" 2>/dev/null && break
    sleep 0.05
done
sleep 0.3
grep -q "$CP" "$TMP/ipc_frozen.out" || { echo "FAIL: checkpoint not reached"; kill $PID; exit 1; }
"$ELFTRACE" freeze "$PID" -o "$SNAP" || exit 1

"$ELFTRACE" build "$SNAP" -o "$SLICED" --mode real --ipc "$IPC_N" || exit 1

# 运行切片 (同步, 限制时间)
START=$(date +%s)
timeout 30 "$SLICED" > "$TMP/ipc_sliced.out" 2>&1
RC=$?
ELAPSED=$(($(date +%s) - START))
[ "$RC" = 0 ] || { echo "FAIL: rc=$RC (want 0, ipc exit)"; exit 1; }
[ "$ELAPSED" -lt 20 ] || { echo "FAIL: took ${ELAPSED}s (program should have run >20s)"; exit 1; }

# IPC 输出写入冻结前的 stdout 文件
grep -q "IPC: " "$TMP/ipc_frozen.out" || { echo "FAIL: no IPC line in $(cat $TMP/ipc_frozen.out)"; exit 1; }
COUNT=$(grep -oP 'IPC: \K[0-9]+' "$TMP/ipc_frozen.out" | head -1)
# 容差: 允许 0.5% 上浮 (信号路径/handler 开销)
[ -n "$COUNT" ] && [ "$COUNT" -ge "$IPC_N" ] && [ "$COUNT" -le $((IPC_N + IPC_N / 200)) ] \
    || { echo "FAIL: count $COUNT not ~ $IPC_N"; exit 1; }

echo "PASS: ipc auto-exit (rc=0, count=$COUNT ~ $IPC_N, ${ELAPSED}s)"
exit 0
