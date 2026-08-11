#!/bin/bash
# aarch64 alloc 结果重放跳板单测 (qemu-aarch64 可跑)
set -u
cd "$(dirname "$0")/.."
source tests/testlib.sh

tf_setup

if [ "$(uname -m)" = "aarch64" ]; then
    CC=gcc
    RUN=()
elif command -v aarch64-linux-gnu-gcc >/dev/null && \
     command -v qemu-aarch64 >/dev/null; then
    CC=aarch64-linux-gnu-gcc
    RUN=(qemu-aarch64)
else
    echo "SKIP: 无 aarch64 工具链/qemu"
    exit 0
fi

echo "== alloc replay trampoline unit test (qemu/native) =="
"$CC" -static -O2 -Iinclude -o "$TF_TMP/test_alloc_replay" \
    tests/test_alloc_replay.c src/alloc_build.c src/a64.c || exit 1

if ! "${RUN[@]}" "$TF_TMP/test_alloc_replay" ok; then
    echo "FAIL: alloc replay ok path (exit code != 0)"
    exit 1
fi

"${RUN[@]}" "$TF_TMP/test_alloc_replay" fuse
rc=$?
if [ "$rc" -ne 77 ]; then
    echo "FAIL: alloc replay fused exit (expected 77, got $rc)"
    exit 1
fi

"${RUN[@]}" "$TF_TMP/test_alloc_replay" overrun
rc=$?
if [ "$rc" -ne 9 ]; then
    echo "FAIL: alloc replay overrun (expected exit 9, got $rc)"
    exit 1
fi

"${RUN[@]}" "$TF_TMP/test_alloc_replay" mismatch
rc=$?
if [ "$rc" -ne 11 ]; then
    echo "FAIL: alloc replay mismatch (expected exit 11, got $rc)"
    exit 1
fi

"${RUN[@]}" "$TF_TMP/test_alloc_replay" argmis
rc=$?
if [ "$rc" -ne 12 ]; then
    echo "FAIL: alloc replay arg mismatch (expected exit 12, got $rc)"
    exit 1
fi

tf_pass "alloc replay (ok/fused/overrun/mismatch/argmis)"
tf_finish
