#!/bin/bash
# 角落条件测试: 堆边界
#   baremetal: 冻结后 sbrk 被 brk mock 拒绝 -> rc=3 (程序走失败路径)
#   real: 冻结后 malloc 经 glibc mmap fallback 仍成功 -> rc=0 (与基准等价)
set -u
cd "$(dirname "$0")/.."
ROOT=$(pwd)
TMP="$ROOT/tmp"
ELFTRACE="$ROOT/build/elftrace"
PROG="$TMP/prog_bareheap"
SNAP="$TMP/snap_bareheap.elftrace"
SLICED="$TMP/sliced_bareheap.elf"

mkdir -p "$TMP"
gcc -O0 -o "$PROG" tests/prog_bareheap.c || exit 1

run_case() {  # $1 = 名称, $2 = prog 参数, $3 = build 参数, $4 = 期望 rc, $5 = 期望输出
    local name="$1" pargs="$2" bm="$3" want_rc="$4" want_out="$5"
    local frozen_out="$TMP/bareheap_${name}.out"

    "$PROG" $pargs > "$frozen_out" 2>&1 &
    local PID=$!
    for i in $(seq 1 200); do
        grep -q "ALLOC1" "$frozen_out" 2>/dev/null && break
        sleep 0.05
    done
    sleep 0.3
    grep -q "ALLOC1" "$frozen_out" || { echo "FAIL[$name]: ALLOC1 not seen"; kill -9 $PID; return 1; }

    "$ELFTRACE" freeze "$PID" -o "$SNAP" >/dev/null 2>&1 || { echo "FAIL[$name]: freeze"; kill -9 $PID; return 1; }
    kill -CONT $PID 2>/dev/null
    wait $PID 2>/dev/null
    local ORIG_RC=$?

    "$ELFTRACE" build "$SNAP" -o "$SLICED" --mode real $bm >/dev/null 2>&1 || { echo "FAIL[$name]: build"; return 1; }

    local S_RC
    if [ -n "$bm" ]; then
        timeout 30 strace -o "$TMP/bareheap_${name}.strace" "$SLICED" > /dev/null 2>&1
        S_RC=$?
        # 目标阶段 (rt_sigreturn 后) 不得出现真实 brk
        AFTER=$(awk '/rt_sigreturn/{found=1} found' "$TMP/bareheap_${name}.strace")
        if echo "$AFTER" | grep -E "brk\(" | grep -q "= 0x"; then
            echo "FAIL[$name]: real brk in baremetal target phase"
            return 1
        fi
    else
        timeout 30 "$SLICED" > /dev/null 2>&1
        S_RC=$?
    fi

    [ "$S_RC" = "$want_rc" ] || { echo "FAIL[$name]: rc=$S_RC != $want_rc (orig=$ORIG_RC)"; return 1; }
    if [ -n "$want_out" ]; then
        # 仅 real 模式检查输出 (baremetal 下 write 被 mock 丢弃)
        grep -q "$want_out" "$frozen_out" || { echo "FAIL[$name]: no '$want_out'"; return 1; }
    fi
    echo "PASS[$name]: rc=$S_RC ${want_out:+$want_out}"
    return 0
}

# 基准
"$PROG" > "$TMP/bareheap_ref.out" 2>&1
[ "$?" = 0 ] && grep -q "MALLOC OK" "$TMP/bareheap_ref.out" \
    || { echo "FAIL: ref"; exit 1; }
"$PROG" --sbrk > "$TMP/bareheap_ref_sbrk.out" 2>&1
[ "$?" = 0 ] && grep -q "SBRK OK" "$TMP/bareheap_ref_sbrk.out" \
    || { echo "FAIL: ref --sbrk"; exit 1; }
echo "ref: MALLOC OK / SBRK OK (both rc=0)"

run_case "real" "" "--mode real" 0 "MALLOC OK" || exit 1
run_case "bm" "--sbrk" "--mode baremetal" 3 "" || exit 1

echo "PASS: heap boundary (real malloc fallback + baremetal brk mock)"
exit 0
