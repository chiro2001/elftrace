/*
 * trace --atomic-replay 的 aarch64 原子记录上下文 (见 atomic_trace.c)。
 */
#ifndef ELFTRACE_ATOMIC_TRACE_H
#define ELFTRACE_ATOMIC_TRACE_H

#include <stdint.h>
#include <stddef.h>

struct atomic_trace_ctx;

/* 武装: 扫描目标 ldar 站点 → 注入缓冲区/记录页 → patch 站点。
 * 要求目标处于 ptrace-stop (INTERRUPT-stop), 结束后仍处于 stop。
 * regs 为目标当前寄存器 (恢复现场用)。返回 0 成功; 失败时保持目标
 * 未修改 (尽力), 调用方继续普通 trace。 */
int atomic_trace_arm(struct atomic_trace_ctx **ctx_out, pid_t pid,
                     const void *regs, const char *out,
                     uint64_t buf_size);

/* 检查点前调用: 若 pc 落在记录页内, 单步到记录跳板结束。
 * 返回 0 = 已离开记录页; -1 = 单步失败/超时 (调用方应放弃该检查点)。 */
int atomic_trace_step_out(struct atomic_trace_ctx *ctx);

/* 检查点后调用 (目标仍停止): 把各站点序号/最后值快照写入
 * <out>/atomics/ckpt_%06zu.bin, 并累积补偿数据 (measured 为当前 perf
 * 计数)。 */
int atomic_trace_ckpt(struct atomic_trace_ctx *ctx, size_t ckpt_no,
                      uint64_t measured);

/* 读取 Run 1 的 compensation.txt 触发放大系数 r = r_num/r_den */
int atomic_trace_load_compensation(const char *path, uint64_t *r_num,
                                   uint64_t *r_den);

/* 结束: 转储 events.bin, 恢复站点原指令, 解除缓冲区映射。
 * 要求目标处于运行或 ptrace-stop; 结束后保持 ptrace-stop (供 detach)。 */
int atomic_trace_finish(struct atomic_trace_ctx *ctx);

#endif
