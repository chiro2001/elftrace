#!/bin/bash
# baremetal 边界测试:
#   imm      — 可执行段内 0f 05 立即数误替换回归 (embed 值必须保持)
#              + 同 pc nanosleep 循环 (回放表游标顺序消费)
#   loopread — 同一 pc 的 read 循环, 每 read 一整页 dirty
#              (游标消费大量同 pc 记录 + dirty 回放 + fd 偏移续读)
#
# 每个负载: ref → trace 到退出 → real/bm 切片 → 断言 rc 一致 +
# baremetal 目标阶段无真实 syscall。
set -u
cd "$(dirname "$0")/.."

# aarch64: 该测试用 x86 内联汇编构造 0f 05 立即数回归场景, 在 aarch64
# 上无法编译 (svc 定长 4B 也不存在立即数误伤问题), 直接跳过。
if [ "$(uname -m)" = "aarch64" ]; then
    echo "SKIP: x86-specific baremetal edge test (aarch64)"
    exit 0
fi

source tests/testlib.sh

tf_setup
tf_cleanup prog_bm_imm prog_bm_loopread

compile() {
    local name=$1
    case "$name" in
        imm)     gcc -O0 -g -o "$TF_TMP/prog_bm_imm" tests/prog_bm_imm.c ;;
        loopread) gcc -O0 -g -o "$TF_TMP/prog_bm_loopread" \
                     tests/prog_bm_loopread.c ;;
        *) echo "FAIL: unknown load $name"; exit 1 ;;
    esac
}

# 生成确定性测试数据文件 (4MB, 4 字节/项可预测序列)
gen_data() {
    local f="$1"
    python3 - "$f" <<'EOF'
import sys
with open(sys.argv[1], "wb") as f:
    for i in range(1000000):
        f.write(bytes([(i*7+13) & 0xff, (i*3+1) & 0xff,
                       (i >> 8) & 0xff, (i >> 16) & 0xff]))
EOF
}

run_load() {
    local name=$1 extra_args=$2
    local PROG="$TF_TMP/prog_bm_$name"
    local CKPTS="$TF_TMP/bm_edge_${name}_ckpts"
    local F_DATA="$TF_TMP/bm_edge_${name}.bin"

    [ "$name" = loopread ] && gen_data "$F_DATA"

    # 1. ref
    timeout 180 "$PROG" $extra_args > /dev/null 2>&1
    local REF_RC=$?

    # 2. trace 到目标退出 (直接 & 启动, 不能用 timeout 包装)
    rm -rf "$CKPTS"
    "$PROG" $extra_args > /dev/null 2>&1 &
    local PID=$!
    [ "$name" = loopread ] && sleep 0.05 || sleep 0.2
    timeout 300 "$TF_ELFTRACE" trace "$PID" --every 200000000 \
        --out "$CKPTS" > "$TF_TMP/bm_edge_${name}_trace.log" 2>&1
    wait "$PID" 2>/dev/null
    tf_cleanup "$(basename "$PROG")"
    [ -f "$CKPTS/syscalls/syscall.map" ] || {
        echo "  FAIL[$name]: no syscall map"; return 1; }
    local NSYS
    NSYS=$(wc -l < "$CKPTS/syscalls/syscall.map")
    [ "$NSYS" -gt 5 ] || { echo "  FAIL[$name]: too few records ($NSYS)"; return 1; }

    # 3. real 切片
    "$TF_ELFTRACE" build "$CKPTS/ckpt_000000.elftrace" \
        -o "$TF_TMP/bm_edge_${name}_real.elf" --mode real \
        --checkpoints "$CKPTS" --from 0 >/dev/null 2>&1 \
        || { echo "  FAIL[$name]: build real"; return 1; }
    timeout 120 "$TF_TMP/bm_edge_${name}_real.elf" >/dev/null 2>&1
    local REAL_RC=$?

    # 4. baremetal 切片 (strace)
    "$TF_ELFTRACE" build "$CKPTS/ckpt_000000.elftrace" \
        -o "$TF_TMP/bm_edge_${name}_bm.elf" --mode baremetal \
        --checkpoints "$CKPTS" --from 0 >/dev/null 2>&1 \
        || { echo "  FAIL[$name]: build bm"; return 1; }
    timeout 120 strace -o "$TF_TMP/bm_edge_${name}_bm.strace" \
        "$TF_TMP/bm_edge_${name}_bm.elf" >/dev/null 2>&1
    local BM_RC=$?

    # 5. rc 一致性
    [ "$REAL_RC" = "$REF_RC" ] || {
        echo "  FAIL[$name]: real rc=$REAL_RC != ref $REF_RC"; return 1; }
    [ "$BM_RC" = "$REF_RC" ] || {
        echo "  FAIL[$name]: bm rc=$BM_RC != ref $REF_RC"; return 1; }
    # imm 的 rc 必须精确等于 15: 被 0f 05 误替换时是 204
    if [ "$name" = imm ] && [ "$REF_RC" != 15 ]; then
        echo "  FAIL[imm]: unexpected ref rc=$REF_RC (期望 15)"; return 1
    fi

    # 6. baremetal 目标阶段 (首个 rt_sigreturn 后) 无真实 syscall
    local LEAK
    LEAK=$(awk '
        /^rt_sigreturn/ { seen_rt = 1; in_handler = 0; next }
        !seen_rt { next }
        /^--- SIGTRAP/ { in_handler = 1; next }
        in_handler { next }
        /openat|read\(|write\(|mmap|brk|lseek|fstat|ioctl|clock_/ && /= [0-9-]+$/ {
            print; bad = 1
        }
        END { if (bad) exit 1 }
    ' "$TF_TMP/bm_edge_${name}_bm.strace")
    if [ -n "$LEAK" ]; then
        echo "  FAIL[$name]: real syscalls in bm target phase (handler 外)"
        echo "$LEAK" | head -3
        return 1
    fi

    echo "  [$name] ref=$REF_RC real=$REAL_RC bm=$BM_RC records=$NSYS ok"
    return 0
}

FAILED=0
for name in imm loopread; do
    compile "$name" || { echo "FAIL: compile $name"; FAILED=1; continue; }
    extra=""
    [ "$name" = loopread ] && extra="$TF_TMP/bm_edge_loopread.bin"
    run_load "$name" "$extra" || FAILED=1
done

tf_cleanup prog_bm_imm prog_bm_loopread
[ "$FAILED" = 0 ] || { echo "result: baremetal edge FAIL"; exit 1; }
echo "PASS: baremetal edge (imm 0f05 回归 + loopread 同 pc dirty 回放)"
exit 0
