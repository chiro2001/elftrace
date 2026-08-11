#!/bin/bash
# aarch64 run-burn 融合退出逻辑单测 (本机 qemu-aarch64 可跑, 不依赖
# 远程硬件; 也可在 aarch64 主机原生跑)。
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

echo "== atomic burn fused-exit unit test (qemu/native) =="
"$CC" -static -O2 -Iinclude -o "$TF_TMP/test_burn_block" \
    tests/test_burn_block.c src/atomic_a64.c src/a64.c || exit 1

if ! "${RUN[@]}" "$TF_TMP/test_burn_block"; then
    echo "FAIL: burn fused-exit logic (exit code != 0)"
    exit 1
fi

tf_pass "atomic burn fused-exit (2 entries, clean exit, rc=0)"
tf_finish
