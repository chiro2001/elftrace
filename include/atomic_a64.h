/*
 * aarch64 原子指令序号化记录/回放 (strict baremetal 多线程同步支持)
 *
 * 思路 (用户方案 B + 原子读序号化):
 *   - 采集侧 (trace --atomic-replay): 把目标线程可执行段中的 ldar
 *     指令 patch 成"记录跳板"。跳板执行原始 ldar (保留 acquire 语义),
 *     记录"第几次读取 + 地址 + 值"到注入缓冲区 (游程压缩: 值/地址
 *     不变不追加事件); 非目标线程 (按 TPIDR_EL0 过滤) 只执行原始
 *     ldar, 不记录。
 *   - 构建侧 (build --bm-strict): 窗口内有事件的站点替换为"回放跳板",
 *     按第几次访问返回录制值; 无事件的站点恢复原始 ldar。回放仍执行
 *     真实 acquire 屏障 (ldar 到原地址), 但返回值用录制值覆盖。
 *
 * 布局: 每站点一个 0x220 字节块 (入口 16B + 代码 + 数据区 @0x200),
 * 页内 16B 对齐。站点分支 b <入口> 与返回 b <站点+4> 都要求跳板页
 * 在站点 ±128MB 内 (build/trace 均按段就近分配页)。
 */
#ifndef ELFTRACE_ATOMIC_A64_H
#define ELFTRACE_ATOMIC_A64_H

#include <stdint.h>
#include <stddef.h>

/* ---- ldar/ldarb/ldarh 识别 ----
 * size 输出为加载宽度 (1/2/4/8 字节); rt/rn 为寄存器号 (31=sp)。 */
int a64_is_ldar(uint32_t w, int *size, unsigned *rt, unsigned *rn);

/* ---- 块/页布局 ---- */
#define A64_ATOM_BLOCK_SIZE  0x240   /* 每站点块 (代码 + 数据区@0x200..0x238) */
#define A64_ATOM_PAGE_SIZE   0x1000
#define A64_ATOM_BLOCKS_PER_PAGE  7   /* 7*0x240=0xFC0 */

/* 逐站点最小保存集 (生成器内部动态布局), 此处无固定偏移 */

/* ---- 记录跳板块 ----
 * 入口: stp x16,x17; ldar <原始指令>; [mov x17,x16 | nop]; ldr x16,
 * [pc,#8]; br x16; .quad block_abs; 代码@0x18 (保存全部寄存器+flags,
 * 值→x13, 地址→x12, TLS 过滤, 序号/游程事件追加, 恢复, b ret_addr)。
 * 数据区 @0x200: tls, site_id, state_abs, event_ptr_addr,
 * events_end_addr, overflow_addr, ret_addr。
 */
/* 各执行路径的额外指令数 (含站点处的 b):
 *   base   = 目标线程稳态负载 (ldar + 序号 + 比较, 不追加事件)
 *   append = 追加事件时的额外指令
 *   skip   = 非目标线程 (只执行 ldar + TLS 过滤后返回)
 * 用于采集侧补偿: perf 测量计数 = 原始计数 + Σ(ord×base + ev×append)。 */
struct a64_atom_counts {
    unsigned base, append, skip;
};

size_t a64_atomic_record_block(uint8_t *out, uint64_t block_abs,
                               uint32_t orig_insn, uint64_t tls,
                               uint64_t site_id, uint64_t state_abs,
                               uint64_t event_ptr_addr,
                               uint64_t events_end_addr,
                               uint64_t overflow_addr,
                               uint64_t ret_addr,
                               struct a64_atom_counts *counts);

/* ---- 回放跳板块 ----
 * 入口: stp x16,x17; nop; ldr x16,[pc,#8]; br x16; .quad block_abs。
 * 数据区 @0x200: ordinal, cursor, runs_abs, n_runs。
 * 回放: 序号递增 → 游标推进 (O(1) 均摊) → 命中运行段且地址一致 →
 * 执行真实 acquire 屏障 (ldar/ldaxr 到原地址, ldaxr 设置排他监视器
 * 使后续真实 stlxr 成功) 后返回录制值; 否则返回真实内存值。
 * rt/rn 与 ret_addr 直接编码进指令。
 */
size_t a64_atomic_replay_block(uint8_t *out, uint64_t block_abs,
                               uint64_t runs_abs, uint64_t n_runs,
                               int is64, unsigned rt, unsigned rn,
                               uint64_t ret_addr,
                               uint64_t load_limit, uint64_t exit_abs,
                               int exclusive);

/* 检测 ldar/ldarb/ldarh 与 ldaxr/ldaxrb/ldaxrh; *exclusive 输出
 * ldaxr 族标记 */
int a64_is_ldar_any(uint32_t w, int *size, unsigned *rt, unsigned *rn,
                    int *exclusive);

/* ---- 缓冲区头 (注入到目标地址空间, tracer 与跳板共享) ---- */
#define A64_ATB_MAGIC    0x41544F4DULL   /* "ATOM" */
#define A64_ATB_VERSION  1
#define A64_ATB_HDR_SIZE 72
#define A64_ATB_OFF_MAGIC       0
#define A64_ATB_OFF_VERSION     8
#define A64_ATB_OFF_N_SITES     16
#define A64_ATB_OFF_STATE_OFF   24   /* 状态区相对缓冲区的偏移 */
#define A64_ATB_OFF_EVENTS_OFF  32
#define A64_ATB_OFF_EVENT_PTR   40   /* 绝对地址 (下一条事件写入点) */
#define A64_ATB_OFF_EVENTS_END  48   /* 绝对地址 (事件区末尾) */
#define A64_ATB_OFF_OVERFLOW    56
#define A64_ATB_OFF_BUF_SIZE    64

/* 站点状态槽 (24B) */
#define A64_ATB_STATE_SIZE      24
#define A64_ATB_STATE_ORD       0
#define A64_ATB_STATE_LAST_VAL  8
#define A64_ATB_STATE_LAST_ADDR 16

/* 事件 (32B) */
#define A64_ATB_EVENT_SIZE      32

/* ---- 侧车文件魔数 (trace 输出 atomics/) ---- */
#define A64_AT_SITES_MAGIC  0x53495445ULL   /* "ETIS" */
#define A64_AT_EVENTS_MAGIC 0x56455441ULL   /* "ATEV" */
#define A64_AT_CKPT_MAGIC   0x4B435441ULL   /* "ATCK" */

#endif
