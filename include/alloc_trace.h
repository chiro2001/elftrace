/*
 * elftrace 分配器调用捕获 (strict baremetal 的 malloc 结果重放, M1)
 *
 * 思路 (round-19/20 双模型评审): 在 libc malloc/calloc/realloc/free
 * 函数入口 patch 记录跳板 (非 PLT, 覆盖 libc 内部调用), 目标线程
 * (TPIDR_EL0 过滤) 记录 {kind, size, caller, ret} 到注入缓冲区;
 * 非目标线程只执行原函数。构建侧按同一入口 patch 回放跳板, 按序
 * 返回录制指针 (不执行真实分配器)。
 *
 * 事件 32B: {kind u32, pad u32, size u64, caller u64, ret u64}。
 * 缓冲区头 64B: magic/version/n_funcs/event_ptr/events_end/overflow/tls/
 * buf_size。
 */
#ifndef ELFTRACE_ALLOC_TRACE_H
#define ELFTRACE_ALLOC_TRACE_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/user.h>

/* 分配器函数编号 (kind) */
enum {
    ALLOC_MALLOC = 0,
    ALLOC_CALLOC = 1,
    ALLOC_REALLOC = 2,
    ALLOC_FREE = 3,
    ALLOC_NKIND = 4,
};

#define ALLOC_BUF_MAGIC   0x434F4C41ULL   /* "ALOC" */
#define ALLOC_BUF_VERSION 1
#define ALLOC_BUF_HDR_SIZE 64
#define ALLOC_EVENT_SIZE  32

/* 跳板块 (0x300B) */
#define ALLOC_BLOCK_SIZE 0x300

/* 记录跳板数据区偏移 */
#define ALLOC_TLS_OFF            0x200
#define ALLOC_EVENT_PTR_ADDR_OFF 0x208
#define ALLOC_EVENTS_END_ADDR_OFF 0x210
#define ALLOC_OVERFLOW_ADDR_OFF  0x218
#define ALLOC_ORIG_NEXT_OFF      0x220
#define ALLOC_RET_LABEL_OFF      0x228
#define ALLOC_KIND_OFF           0x230
#define ALLOC_DIAG_RET_OFF       0x250   /* 诊断: 最近返回值 */
#define ALLOC_DIAG_CNT_OFF       0x258   /* 诊断: 调用计数 */

struct alloc_trace_ctx;

/* 记录跳板生成器 (导出供单元测试) */
size_t alloc_record_block(uint8_t *out, uint64_t block_abs,
                          uint32_t saved_insn, uint64_t orig_pc,
                          uint64_t orig_next,
                          uint64_t tls, uint64_t hdr_event_ptr_addr,
                          uint64_t hdr_events_end_addr,
                          uint64_t hdr_overflow_addr, uint64_t kind);

/* 采集: 定位 libc 分配器入口并 arm 记录跳板 (目标需处于停止态)。
 * 成功返回 0, 写入侧车目录 <out>/allocs/。 */
int alloc_trace_arm(struct alloc_trace_ctx **ctx_out, pid_t pid,
                    const struct user_regs_struct *regs,
                    const char *out);

/* 检查点: 转储当前事件数到 <out>/allocs/ckpt_%06zu.bin */
int alloc_trace_ckpt(struct alloc_trace_ctx *ctx, size_t ckpt_no);

/* 结束: 恢复函数入口, 转储剩余事件, 释放。 */
int alloc_trace_finish(struct alloc_trace_ctx *ctx);

#endif
