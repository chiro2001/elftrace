#!/bin/bash
# aarch64 验证驱动: 交叉编译 → initramfs → qemu-system VM → 跑用例
#
# 环境变量:
#   QEMU_KERNEL   arm64 vmlinuz 路径 (默认 /tmp/arm64env/vmlinuz-virt)
#   BUSYBOX       static aarch64 busybox (默认 /tmp/arm64env/busybox-1.38.0/busybox)
#   BASH_A64      static aarch64 bash (默认 /tmp/arm64env/bash-5.2/bash)
#   VM_TIMEOUT    单次 VM 总超时秒 (默认 1200)
set -u
cd "$(dirname "$0")/../.."
ROOT=$(pwd)

CROSS=aarch64-linux-gnu-
QEMU_KERNEL=${QEMU_KERNEL:-/tmp/arm64env/vmlinuz-virt}
BUSYBOX=${BUSYBOX:-/tmp/arm64env/busybox-1.38.0/busybox}
BASH_A64=${BASH_A64:-/tmp/arm64env/bash-5.2/bash}
VM_TIMEOUT=${VM_TIMEOUT:-1200}

[ -f "$QEMU_KERNEL" ] || { echo "FAIL: 缺内核 $QEMU_KERNEL"; exit 1; }
[ -f "$BUSYBOX" ] || { echo "FAIL: 缺 busybox $BUSYBOX"; exit 1; }
command -v qemu-system-aarch64 >/dev/null || { echo "FAIL: 缺 qemu-system-aarch64"; exit 1; }
command -v ${CROSS}gcc >/dev/null || { echo "FAIL: 缺 aarch64 交叉工具链"; exit 1; }

WORK=$(mktemp -d /tmp/a64vm.XXXXXX)
trap 'echo "work: $WORK"; exit 1' INT

echo "== 交叉编译 elftrace =="
make ARCH=aarch64 BUILD="$WORK/build" LDFLAGS="-static" > /tmp/a64_build.log 2>&1 \
    || { echo "FAIL: 交叉编译 elftrace"; tail -5 /tmp/a64_build.log; exit 1; }

echo "== 交叉编译测试程序 =="
gcc_a64() { ${CROSS}gcc -static -O0 -g -o "$WORK/$2" "$1"; }
gcc_a64 tests/prog_simple.c prog_simple
gcc_a64 tests/prog_stack.c prog_stack
gcc_a64 tests/prog_fd_rw.c prog_fd_rw
gcc_a64 tests/prog_fd.c prog_fd
gcc_a64 tests/prog_bigmem.c prog_bigmem

echo "== 组装 initramfs =="
rm -rf "$WORK/initramfs"
mkdir -p "$WORK/initramfs"/{bin,dev,proc,sys,tmp}
cp "$BUSYBOX" "$WORK/initramfs/bin/busybox"
cp "$BASH_A64" "$WORK/initramfs/bin/bash"
cp "$WORK/build/elftrace" "$WORK/initramfs/bin/elftrace"
cp "$WORK"/prog_* "$WORK/initramfs/bin/"

cat > "$WORK/initramfs/init" <<'EOF'
#!/bin/busybox sh
/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
echo 0 > /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
echo 2 > /proc/sys/kernel/perf_event_paranoid 2>/dev/null

FAILED=0

# 通用用例: ref → (freeze|trace) → build → 切片 → rc/输出对比
run_case() {
    local name=$1 prog=$2 mode=$3
    local args=${ARGS:-}
    echo "=== $name ($mode) ==="
    $prog $args > "/ref_$name.out" 2>&1
    local REF=$?
    if [ "$mode" = replay ]; then
        # trace 到目标退出 (软件事件回退, 时间基检查点; 回放表照常)
        $prog $args > "/tr_$name.out" 2>&1 &
        local PID=$!
        for _ in $(seq 1 300); do
            grep -qE "${MARKER:-CHECKPOINT}" "/tr_$name.out" 2>/dev/null && break
            sleep 0.05
        done
        mkdir -p "/ckpts_$name"
        /bin/elftrace trace $PID --every 200000000 --out "/ckpts_$name" \
            > /dev/null 2>&1 || { echo "  FAIL[$name]: trace"; FAILED=1; return; }
        wait $PID 2>/dev/null
        /bin/elftrace build "/ckpts_$name/ckpt_000000.elftrace" \
            -o "/slice_$name.elf" --mode baremetal \
            --checkpoints "/ckpts_$name" --from 0 > /dev/null 2>&1 \
            || { echo "  FAIL[$name]: build"; FAILED=1; return; }
    else
        $prog $args > "/tr_$name.out" 2>&1 &
        local PID=$!
        for _ in $(seq 1 300); do
            grep -qE "${MARKER:-CHECKPOINT}" "/tr_$name.out" 2>/dev/null && break
            sleep 0.05
        done
        /bin/elftrace freeze $PID -o "/snap_$name.elftrace" > /dev/null 2>&1
        local FZ=$?
        kill -CONT $PID 2>/dev/null; wait $PID 2>/dev/null
        [ $FZ -eq 0 ] || { echo "  FAIL[$name]: freeze"; FAILED=1; return; }
        /bin/elftrace build "/snap_$name.elftrace" -o "/slice_$name.elf" \
            --mode "$mode" > /build_$name.log 2>&1 || {
                echo "  FAIL[$name]: build"; cat /build_$name.log | tail -3;
                FAILED=1; return; }
    fi
    timeout 180 "/slice_$name.elf" > "/slice_$name.out" 2>&1
    local RC=$?
    if [ "$RC" = "$REF" ]; then
        echo "  [$name] rc OK ($RC)"
    else
        echo "  FAIL[$name]: rc $RC != ref $REF"; FAILED=1
    fi
    # 输出: real 切片续写 tr (fd 恢复), 与 ref 全量对比
    if [ "$mode" = real ]; then
        diff -q "/ref_$name.out" "/tr_$name.out" > /dev/null 2>&1 \
            && echo "  [$name] output OK" || { echo "  FAIL[$name]: output"; FAILED=1; }
    fi
}

run_case simple /bin/prog_simple real
MARKER="MID|TOP" run_case stack /bin/prog_stack real
ARGS="/fd.out" MARKER="OPENED" run_case fd /bin/prog_fd real
MARKER="FILLED" run_case bigmem /bin/prog_bigmem real
run_case simple /bin/prog_simple baremetal
run_case simple /bin/prog_simple replay

# fd 内容断言 (AAABBB): 切片续写后文件应为完整内容
if [ "$(cat /fd.out 2>/dev/null)" = "AAABBB" ]; then
    echo "  [fd] content OK"
else
    echo "  FAIL[fd]: content [$(cat /fd.out 2>/dev/null)]"; FAILED=1
fi

echo "=== RESULT: $FAILED ==="
poweroff -f
EOF
chmod +x "$WORK/initramfs/init"

(cd "$WORK/initramfs" && find . | cpio -o -H newc 2>/dev/null | gzip) \
    > "$WORK/initramfs.cpio.gz"

echo "== 启动 VM =="
timeout "$VM_TIMEOUT" qemu-system-aarch64 -M virt -cpu cortex-a72 \
    -smp 4 -m 1024 -kernel "$QEMU_KERNEL" \
    -initrd "$WORK/initramfs.cpio.gz" \
    -append "console=ttyAMA0 panic=-1" -nographic > "$WORK/vm.log" 2>&1

grep -E "=== |rc OK|output OK|FAIL|RESULT" "$WORK/vm.log" | tail -20
R=$(grep -E "^=== RESULT:" "$WORK/vm.log" | tail -1 | grep -oE "[0-9]+")
if [ "${R:-1}" = "0" ]; then
    echo "PASS: aarch64 VM 测试全部通过 (日志: $WORK/vm.log)"
    exit 0
fi
echo "FAIL: aarch64 VM 测试有失败 (日志: $WORK/vm.log)"
exit 1
