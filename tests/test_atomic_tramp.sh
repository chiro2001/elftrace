#!/bin/bash
# aarch64: 原子记录/回放跳板独立自测 (无 ptrace):
#   1. prog_atom_tramp: 记录跳板 + TLS 过滤 + 游程压缩事件
#      (辅助线程置位, 主线程自旋退出, 事件正确);
#   2. prog_atom_replay_tramp: 回放跳板按序号返回录制值
#      (无其他线程, 内存值不变也能在第 3 次读取后退出)。
set -u
cd "$(dirname "$0")/.."
source tests/testlib.sh

if [ "$(uname -m)" != "aarch64" ]; then
    echo "SKIP: atomic trampoline 自测仅 aarch64"
    exit 0
fi

tf_setup

echo "== [atomic] record trampoline =="
gcc -O2 -g -Iinclude -pthread -static -o "$TF_TMP/prog_atom_tramp" \
    tests/prog_atom_tramp.c src/atomic_a64.c src/a64.c || exit 1
timeout 30 "$TF_TMP/prog_atom_tramp" > "$TF_TMP/atom_tramp.out" 2>&1
RC=$?
[ "$RC" = 0 ] || { echo "FAIL: record trampoline rc=$RC"; tail -5 "$TF_TMP/atom_tramp.out"; exit 1; }
tf_pass "atomic record trampoline (TLS filter + run-length events)"

echo "== [atomic] replay trampoline =="
gcc -O2 -g -Iinclude -pthread -static -o "$TF_TMP/prog_atom_rep" \
    tests/prog_atom_replay_tramp.c src/atomic_a64.c src/a64.c || exit 1
timeout 30 "$TF_TMP/prog_atom_rep" > "$TF_TMP/atom_rep.out" 2>&1
RC=$?
[ "$RC" = 0 ] || { echo "FAIL: replay trampoline rc=$RC"; tail -5 "$TF_TMP/atom_rep.out"; exit 1; }
tf_pass "atomic replay trampoline (ordinal lookup, no other thread)"

tf_finish
