#!/bin/bash
# aarch64 原子指令编码判定单元测试 (纯静态, 任意架构可跑)。
set -u
cd "$(dirname "$0")/.."
source tests/testlib.sh

tf_setup

echo "== atomic encoding unit test =="
gcc -O2 -Iinclude -o "$TF_TMP/test_atomic_encoding" \
    tests/test_atomic_encoding.c src/atomic_a64.c src/a64.c \
    || exit 1
if ! "$TF_TMP/test_atomic_encoding"; then
    echo "FAIL: atomic encoding checks"
    exit 1
fi

tf_pass "atomic encoding unit (cas/casa/casl/casal + excl store/load)"
tf_finish
