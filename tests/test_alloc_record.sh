#!/bin/bash
# aarch64 分配器记录跳板单测 (qemu-aarch64 可跑)
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

echo "== atomic alloc record trampoline unit test (qemu/native) =="
"$CC" -static -O2 -Iinclude -o "$TF_TMP/test_alloc_record" \
    tests/test_alloc_record.c src/alloc_trace.c src/a64.c \
    src/inject.c src/collect.c src/dwarf.c src/util.c || exit 1

if ! "${RUN[@]}" "$TF_TMP/test_alloc_record"; then
    echo "FAIL: alloc record logic (exit code != 0)"
    exit 1
fi

tf_pass "atomic alloc record (2 events, ret/caller correct, restore ok)"
tf_finish
