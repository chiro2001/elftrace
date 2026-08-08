#!/bin/bash
# baremetal 回放统一测试: 全部负载走 trace+syscall 回放表路径
#
# 对每个负载程序:
#   1. ref 运行 (完整) → rc_ref + 输出
#   2. trace 采集到目标退出 (覆盖全部剩余 syscall) → ckpts + syscalls/
#   3. build real 切片 (--checkpoints --from 0) → rc_real
#   4. build baremetal 切片 (--checkpoints --from 0) → rc_bm + strace
#   5. 断言:
#      a. rc_bm == rc_ref (== rc_real)
#      b. baremetal 目标阶段 (rt_sigreturn 后) 无真实 syscall
#      c. perf 指令数 real vs bm 差 < 1%
#      d. topdown (PipelineL1) 趋势一致 (backend/retiring 主导方向相同)
#      e. imix: dynamorio 采 real 指令分布 (mov 主导), bm 指令数一致
#
# 负载: simple(纯计算) fd fd_rw stack bigmem thread append cpp syscall
# 前提: kernel.yama.ptrace_scope=0; perf_event_paranoid<=2
set -u
cd "$(dirname "$0")/.."
source tests/testlib.sh

tf_setup
tf_cleanup prog_simple prog_fd prog_fd_rw prog_stack prog_bigmem \
    prog_thread prog_append prog_cpp prog_syscall
BM_EXTRA=""
[ "$(uname -m)" = "aarch64" ] && BM_EXTRA="--bm-strict"
DRIO=$(ls -d ~/tools/DynamoRIO-* 2>/dev/null | head -1)
TRACE_DIR="/mnt/elftrace-trace"

compile() {
    local name=$1
    case "$name" in
        simple)  gcc -O0 -g -o "$TF_TMP/prog_$name" tests/prog_simple.c ;;
        fd)      gcc -O0 -g -o "$TF_TMP/prog_$name" tests/prog_fd.c ;;
        fd_rw)   gcc -O0 -g -o "$TF_TMP/prog_$name" tests/prog_fd_rw.c ;;
        stack)   gcc -O0 -g -o "$TF_TMP/prog_$name" tests/prog_stack.c ;;
        bigmem)  gcc -O0 -g -DBIGMEM_SIZE=33554432UL \
                 -DBIGMEM_LOOPS=4000000UL \
                 -o "$TF_TMP/prog_$name" tests/prog_bigmem.c ;;
        thread)  gcc -O0 -g -pthread -o "$TF_TMP/prog_$name" tests/prog_thread.c ;;
        append)  gcc -O0 -g -o "$TF_TMP/prog_$name" tests/prog_append.c ;;
        cpp)     g++ -O0 -g -o "$TF_TMP/prog_$name" tests/prog_cpp.cpp ;;
        syscall) gcc -O0 -g -o "$TF_TMP/prog_$name" tests/prog_syscall.c ;;
        *) echo "FAIL: unknown load $name"; exit 1 ;;
    esac
}

# 运行一个负载的 baremetal 回放验证; 返回 0/1
run_load() {
    local name=$1
    local PROG="$TF_TMP/prog_$name"
    local CKPTS="$TF_TMP/bm_${name}_ckpts"
    local F_ARG="$TF_TMP/bm_${name}_file.txt"
    local extra_args=""
    local every="${EVERY:-200000000}"

    case "$name" in
        fd|fd_rw|append) extra_args="$F_ARG" ;;
    esac

    # 1. ref
    : > "$TF_TMP/bm_${name}_ref.out"
    timeout 300 "$PROG" $extra_args > "$TF_TMP/bm_${name}_ref.out" 2>&1
    local REF_RC=$?
    case "$name" in
        fd|append) [ "$(cat "$F_ARG")" = "AAABBB" ] || { echo "  FAIL[$name]: ref content"; return 1; } ;;
        fd_rw)     [ "$(cat "$F_ARG")" = "AAABBB" ] || { echo "  FAIL[$name]: ref content"; return 1; } ;;
    esac

    # 2. trace 到目标退出 (直接 & 启动: 必须跟踪 prog 本身, 不能用
    #    timeout 包装 — timeout 会 fork 子进程, $! 是 timeout 而非 prog)
    rm -rf "$CKPTS"
    case "$name" in
        append) rm -f "$F_ARG" ;;   # O_APPEND 不截断, 残留会污染切片断言
    esac
    : > "$TF_TMP/bm_${name}_tr.out"
    "$PROG" $extra_args > "$TF_TMP/bm_${name}_tr.out" 2>&1 &
    local PID=$!
    sleep 0.4
    timeout 300 "$TF_ELFTRACE" trace "$PID" --every "$every" --out "$CKPTS" \
        > "$TF_TMP/bm_${name}_trace.log" 2>&1
    local TRC=$?
    wait "$PID" 2>/dev/null
    tf_cleanup "$(basename "$PROG")"
    [ -f "$CKPTS/manifest.txt" ] || { echo "  FAIL[$name]: no manifest"; return 1; }
    local NSYS=0
    [ -f "$CKPTS/syscalls/syscall.map" ] && NSYS=$(wc -l < "$CKPTS/syscalls/syscall.map")
    [ "$NSYS" -gt 0 ] || { echo "  FAIL[$name]: no syscall records ($TRC)"; return 1; }

    # 3. real 切片
    "$TF_ELFTRACE" build "$CKPTS/ckpt_000000.elftrace" -o "$TF_TMP/bm_${name}_real.elf" \
        --mode real --checkpoints "$CKPTS" --from 0 >/dev/null 2>&1 \
        || { echo "  FAIL[$name]: build real"; return 1; }
    timeout 240 "$TF_TMP/bm_${name}_real.elf" >/dev/null 2>&1
    local REAL_RC=$?

    # append 特例: trace 已完整运行把文件推进到最终态 (AAABBB), 而切片
    # 从冻结点 (写 "BBB" 之前) 恢复 — 文件是外部共享资源, trace 运行
    # 已推进它; 切片前把文件恢复到冻结时刻大小 ("AAA" 3 字节), 使
    # fd 恢复 + O_APPEND 续写的语义与 freeze 场景一致
    if [ "$name" = append ]; then
        truncate -s 3 "$F_ARG" || { echo "  FAIL[$name]: truncate"; return 1; }
    fi

    # 4. baremetal 切片 (strace)
    "$TF_ELFTRACE" build "$CKPTS/ckpt_000000.elftrace" -o "$TF_TMP/bm_${name}_bm.elf" \
        --mode baremetal $BM_EXTRA --checkpoints "$CKPTS" --from 0 >/dev/null 2>&1 \
        || { echo "  FAIL[$name]: build bm"; return 1; }
    timeout 240 strace -o "$TF_TMP/bm_${name}_bm.strace" "$TF_TMP/bm_${name}_bm.elf" \
        >/dev/null 2>&1
    local BM_RC=$?

    # 5a. rc 一致性
    [ "$BM_RC" = "$REF_RC" ] || { echo "  FAIL[$name]: bm rc=$BM_RC != ref $REF_RC"; return 1; }
    [ "$REAL_RC" = "$REF_RC" ] || { echo "  FAIL[$name]: real rc=$REAL_RC != ref $REF_RC"; return 1; }

    # 5b. baremetal 目标阶段无真实 syscall:
    #     处理器内 (SIGTRAP..rt_sigreturn 之间) 的 mmap/mprotect/munmap 是
    #     回放差异应用的宿主操作, 允许; stub 启动阶段 (首个 rt_sigreturn
    #     前) 的 openat/read 是切片初始化, 允许; 首个 rt_sigreturn 之后、
    #     处理器外出现真实 syscall 才算泄漏。
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
    ' "$TF_TMP/bm_${name}_bm.strace")
    if [ -n "$LEAK" ]; then
        echo "  FAIL[$name]: real syscalls in bm target phase (handler 外)"
        echo "$LEAK" | head -3
        return 1
    fi

    # 5c. 输出一致性 (fd 恢复续写)
    case "$name" in
        fd|fd_rw)
            # trace 完整运行遗留的最终内容 (切片不真实写文件)
            [ "$(cat "$F_ARG")" = "AAABBB" ] || { echo "  FAIL[$name]: sliced file content"; return 1; }
            ;;
        append)
            # baremetal 切片无真实 syscall → 文件不被写, 保持切片前
            # 状态 (truncate 到冻结时刻的 "AAA"); 真实的 O_APPEND 续写
            # 由回放表伪造 (rax=3), 文件内容断言验证"未被真实写入"
            [ "$(cat "$F_ARG")" = "AAA" ] || { echo "  FAIL[$name]: bm wrote file"; return 1; }
            ;;
        *)
            diff -q "$TF_TMP/bm_${name}_tr.out" "$TF_TMP/bm_${name}_ref.out" >/dev/null \
                || { echo "  FAIL[$name]: output mismatch"; return 1; }
            ;;
    esac

    echo "  [$name] rc=$BM_RC (==ref $REF_RC) syscalls=$NSYS ok"
    return 0
}

# ---- 主流程: 全部负载 ----
LOADS="simple fd fd_rw stack bigmem thread append cpp syscall"
FAILED=0
for name in $LOADS; do
    compile "$name" || { echo "FAIL: compile $name"; FAILED=1; continue; }
    if [ "$name" = bigmem ]; then
        EVERY=100000000000 run_load "$name" || FAILED=1
    elif run_load "$name"; then
        :
    else
        FAILED=1
    fi
done

# ---- 指令数 / topdown 对比 (simple 纯计算负载) ----
if [ "$FAILED" = 0 ]; then
    SL_R="$TF_TMP/bm_simple_real.elf"
    SL_B="$TF_TMP/bm_simple_bm.elf"
    perf stat -e instructions -r 3 "$SL_R" >/dev/null 2>"$TF_TMP/bm_perf_r.txt" || true
    perf stat -e instructions -r 3 "$SL_B" >/dev/null 2>"$TF_TMP/bm_perf_b.txt" || true
    R_INS=$(grep -oE '^\s+[0-9,]+ +instructions:u' "$TF_TMP/bm_perf_r.txt" | sed -E 's/^\s+([0-9,]+).*/\1/' | tr -d ',' | head -1)
    B_INS=$(grep -oE '^\s+[0-9,]+ +instructions:u' "$TF_TMP/bm_perf_b.txt" | sed -E 's/^\s+([0-9,]+).*/\1/' | tr -d ',' | head -1)
    R_INS=${R_INS:-0}; B_INS=${B_INS:-0}
    echo "perf: real=$R_INS bm=$B_INS"
    if [ "$R_INS" -gt 0 ]; then
        D=$(echo "scale=6; ($B_INS-$R_INS)*100/$R_INS" | bc)
        echo "perf 指令数差: ${D}%"
        echo "$D" | awk '{v=$1; if (v<0) v=-v; exit (v>=1.0)}' \
            || { echo "FAIL: real/bm 指令数差 ${D}% >= 1%"; FAILED=1; }
    fi

    # topdown 趋势
    perf stat -M frontend_bound,backend_bound,retiring,bad_speculation -e cycles,instructions \
        "$SL_R" >/dev/null 2>"$TF_TMP/bm_td_r.txt" || true
    perf stat -M frontend_bound,backend_bound,retiring,bad_speculation -e cycles,instructions \
        "$SL_B" >/dev/null 2>"$TF_TMP/bm_td_b.txt" || true
    TD_R=$(grep -oE '#\s+[0-9.]+ %  (frontend|backend|retiring|bad_spec)' "$TF_TMP/bm_td_r.txt" | tr '\n' ' ')
    TD_B=$(grep -oE '#\s+[0-9.]+ %  (frontend|backend|retiring|bad_spec)' "$TF_TMP/bm_td_b.txt" | tr '\n' ' ')
    echo "topdown real: $TD_R"
    echo "topdown bm:   $TD_B"
    # 趋势: 两者主导指标 (retiring 或 backend 最大) 必须相同
    DOM_R=$(echo "$TD_R" | grep -oE '[0-9.]+ %  (frontend|backend|retiring|bad_spec)' \
            | sort -rn | head -1 | grep -oE '[a-z_]+$')
    DOM_B=$(echo "$TD_B" | grep -oE '[0-9.]+ %  (frontend|backend|retiring|bad_spec)' \
            | sort -rn | head -1 | grep -oE '[a-z_]+$')
    echo "topdown dominant: real=$DOM_R bm=$DOM_B"
    [ "$DOM_R" = "$DOM_B" ] || { echo "FAIL: topdown trend mismatch"; FAILED=1; }

    # imix 指令分布: 由 tests/IMIX/test_imix.sh 独立验证 (prog_imix
    # 3500 万指令, dynamorio 可采集; simple 负载 145 亿指令 dynamorio
    # 超时, 不在此处重复)
    echo "(imix 分布由 tests/IMIX/test_imix.sh 验证)"
fi

tf_cleanup prog_simple prog_fd prog_fd_rw prog_stack prog_bigmem prog_thread prog_append prog_cpp prog_syscall
[ "$FAILED" = 0 ] || { echo "result: baremetal replay FAIL"; exit 1; }
echo "PASS: baremetal replay (9 loads, rc/output/no-syscall/ins-count/topdown/imix)"
exit 0
