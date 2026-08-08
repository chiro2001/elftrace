#!/bin/bash
# aarch64 真实场景负载 strict baremetal 测试:
#   C 负载: CRC32 文件校验 / RLE 压缩 / JSON 数字解析 / SHA-256 文件哈希
#           / 分配器压力 / AF_UNIX socketpair IPC / 目录遍历+stat
# 每个负载:
#   1. ref 完整运行 → rc/输出
#   2. trace 全程 (syscall 稀疏) → strict 全窗口切片 (从 0 到末尾):
#      切片跑到程序自然 exit_group, rc 必须 == ref (回放正确性)
#   3. strict 中间窗口切片: rc=0 (循环/计数退出) + 目标阶段零 syscall
# 断言: strace 目标阶段 (rt_sigreturn 后) 无任何真实 syscall。
set -u
cd "$(dirname "$0")/.."
source tests/testlib.sh

if [ "$(uname -m)" != "aarch64" ]; then
    echo "SKIP: realworld strict 测试仅 aarch64"
    exit 0
fi

tf_setup
ELFTRACE="$TF_ELFTRACE"
DATA="$TF_TMP/rw_data.bin"
JSON="$TF_TMP/rw_data.json"

# 生成测试数据 (32MB 伪随机 + 4MB JSON + 256 文件目录)
python3 - <<'EOF'
import os, random, shutil
r = random.Random(42)
with open("tmp/rw_data.bin", "wb") as f:
    f.write(bytes(r.randrange(256) for _ in range(32 << 20)))
with open("tmp/rw_data.json", "w") as f:
    f.write("{\"items\":[")
    for i in range(800000):
        if i:
            f.write(",")
        f.write("{\"id\":%d,\"v\":%d}" % (i, i * 31 % 1000000))
    f.write("]}")
d = "tmp/rw_dir"
shutil.rmtree(d, ignore_errors=True)
os.makedirs(d, exist_ok=True)
for i in range(64):
    with open(os.path.join(d, "f%03d" % i), "wb") as f:
        f.write(bytes(((i * 7 + j * 13) & 0xff)
                      for j in range(4096)))
EOF

# 通用 (C 负载): ref → trace → 全窗口 strict 切片 + 中间窗口 strict 切片
run_load() {
    local name=$1 prog=$2
    shift 2
    echo "== [realworld] $name =="
    "$prog" "$@" > "$TF_TMP/rw_${name}_ref.out" 2>&1
    local REF_RC=$?
    echo "  ref rc=$REF_RC $(tail -1 "$TF_TMP/rw_${name}_ref.out")"

    rm -rf "$TF_TMP/rw_${name}_ckpts"
    "$prog" "$@" > "$TF_TMP/rw_${name}_tr.out" 2>&1 &
    local PID=$!
    local every="${EVERY:-100000000}"
    for _ in $(seq 1 100); do
        grep -q READY "$TF_TMP/rw_${name}_tr.out" 2>/dev/null && break
        sleep 0.05
    done
    grep -q READY "$TF_TMP/rw_${name}_tr.out" \
        || { echo "  FAIL: READY not seen"; return 1; }
    timeout 600 "$ELFTRACE" trace "$PID" --every "$every" \
        --out "$TF_TMP/rw_${name}_ckpts" > /dev/null 2>&1
    wait $PID 2>/dev/null
    local NCK=$(wc -l < "$TF_TMP/rw_${name}_ckpts/manifest.txt")
    local NSYS=$(wc -l < "$TF_TMP/rw_${name}_ckpts/syscalls/syscall.map" 2>/dev/null)
    [ "$NCK" -ge 3 ] || { echo "  FAIL: only $NCK checkpoints"; return 1; }
    echo "  trace: $NCK ckpts, $NSYS syscalls"

    # 全窗口切片 (自然 exit_group 结束): rc 必须 == ref
    tf_build /dev/null "$TF_TMP/rw_${name}_full.elf" --mode baremetal \
        --bm-strict --checkpoints "$TF_TMP/rw_${name}_ckpts" --from 0 \
        --stack-reserve 67108864 > /dev/null 2>&1 || return 1
    timeout 120 strace -o "$TF_TMP/rw_${name}_full.strace" \
        "$TF_TMP/rw_${name}_full.elf" > /dev/null 2>&1
    local FR=$?
    [ "$FR" = "$REF_RC" ] || { echo "  FAIL: full rc=$FR != ref $REF_RC"; return 1; }
    local AFTER=$(awk '/rt_sigreturn/{f=1} f' "$TF_TMP/rw_${name}_full.strace")
    echo "$AFTER" | grep -E "read\(|write\(|openat|ioctl|mmap|brk|close\(" \
        && { echo "  FAIL: full-window real syscalls"; echo "$AFTER"; return 1; }
    echo "  PASS[full]: rc=$FR == ref, replay clean"

    # 中间窗口切片 (计数/循环退出): rc=0 + 零 syscall
    local TO=$((NCK / 2))
    tf_build /dev/null "$TF_TMP/rw_${name}_mid.elf" --mode baremetal \
        --bm-strict --checkpoints "$TF_TMP/rw_${name}_ckpts" \
        --from $((TO - 1)) --to $((TO + 1)) --stack-reserve 67108864 \
        > /dev/null 2>&1 || return 1
    timeout 120 strace -o "$TF_TMP/rw_${name}_mid.strace" \
        "$TF_TMP/rw_${name}_mid.elf" > /dev/null 2>&1
    local MR=$?
    [ "$MR" = 0 ] || { echo "  FAIL: mid rc=$MR"; return 1; }
    AFTER=$(awk '/rt_sigreturn/{f=1} f' "$TF_TMP/rw_${name}_mid.strace")
    echo "$AFTER" | grep -E "read\(|write\(|openat|ioctl|mmap|brk|close\(" \
        && { echo "  FAIL: mid-window real syscalls"; echo "$AFTER"; return 1; }
    echo "  PASS[mid]: rc=0, middle window clean"
    return 0
}

gcc -O0 -g -o "$TF_TMP/prog_crc32" tests/prog_crc32.c || exit 1
gcc -O0 -g -o "$TF_TMP/prog_lz" tests/prog_lz.c || exit 1
gcc -O0 -g -o "$TF_TMP/prog_json" tests/prog_json.c || exit 1
gcc -O0 -g -o "$TF_TMP/prog_sha256" tests/prog_sha256.c || exit 1
gcc -O0 -g -o "$TF_TMP/prog_alloc" tests/prog_alloc.c || exit 1
gcc -O0 -g -o "$TF_TMP/prog_sockpair" tests/prog_sockpair.c || exit 1
gcc -O0 -g -o "$TF_TMP/prog_dir" tests/prog_dir.c || exit 1
gcc -O0 -g -o "$TF_TMP/prog_qsort" tests/prog_qsort.c || exit 1
gcc -O0 -g -o "$TF_TMP/prog_base64" tests/prog_base64.c || exit 1

R=0
run_load crc32 "$TF_TMP/prog_crc32" "$DATA" || R=1
run_load lz "$TF_TMP/prog_lz" "$DATA" "$TF_TMP/rw_out.lz" || R=1
run_load json "$TF_TMP/prog_json" "$JSON" || R=1
run_load sha256 "$TF_TMP/prog_sha256" "$DATA" || R=1
run_load alloc "$TF_TMP/prog_alloc" || R=1
EVERY=20000000 run_load sock "$TF_TMP/prog_sockpair" || R=1
EVERY=10000000 run_load dir "$TF_TMP/prog_dir" "$TF_TMP/rw_dir" || R=1
run_load qsort "$TF_TMP/prog_qsort" || R=1
EVERY=50000000 run_load base64 "$TF_TMP/prog_base64" || R=1

tf_cleanup prog_crc32 prog_lz prog_json prog_sha256 prog_alloc \
    prog_sockpair prog_dir prog_qsort prog_base64
[ "$R" = 0 ] || { echo "FAIL: realworld 有失败"; exit 1; }
tf_pass "realworld strict (crc32/lz/json/sha256/alloc/sockpair/dir/qsort/base64)"
tf_finish
