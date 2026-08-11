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

/* ---- 普通 load 地址描述 (值回放 MVP: 分配器等关键读站点) ----
 * mode 0: [Xn, #imm]   (ldr w/x 立即数偏移, imm 为未缩放字节偏移)
 * mode 1: [Xn, Xm{, lsl #shift}]  (寄存器偏移, 仅 LSL option)
 */
struct a64_ld_addr {
    int mode;
    unsigned rn, rm;
    int64_t imm;
    int shift;              /* mode 1: 0, 2 (w) 或 3 (x) */
    int ldr_kind;           /* 0=ldr w/x, 1=ldrb, 2=ldrh, 3=ldrsw,
                               4=ldrsb(w), 5=ldrsh(w) */
};

/* ---- 块/页布局 ---- */
#define A64_ATOM_BLOCK_SIZE  0x280   /* 每站点块 (代码 + 数据区@0x200..0x278;
                                        LSE CAS 记录块需要 last-tuple 槽) */
#define A64_ATOM_PAGE_SIZE   0x1000
#define A64_ATOM_BLOCKS_PER_PAGE  4   /* 4*0x280=0xA00 */

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

/* ---- 普通 load 记录跳板 ----
 * 与原子版不同: 入口不执行原指令 (地址依赖 rt/rm 时原指令会破坏
 * 基址), 改为先保存 {rt,rn,rm}, 从保存槽重建有效地址 → x12, 执行
 * ldr w/x x13,[x12], 再按 {值,地址} 游程记录。其余 (TLS 过滤/序号/
 * 事件/恢复) 与原子版一致。 */
size_t a64_load_record_block(uint8_t *out, uint64_t block_abs,
                             const struct a64_ld_addr *ad, int size,
                             unsigned rt, uint64_t tls,
                             uint64_t site_id, uint64_t state_abs,
                             uint64_t event_ptr_addr,
                             uint64_t events_end_addr,
                             uint64_t overflow_addr,
                             uint64_t ret_addr,
                             struct a64_atom_counts *counts,
                             int record_all);

/* ---- LSE CAS 记录跳板 (kind=4) ----
 * 入口保存 {rs,rt,rn}+scratch, 从槽重载后执行原始 cas/casa/casl/casal
 * (保留真实读改写语义), 捕获 old=Rs 与 success=(old==expected), 按
 * {addr,old,success,expected,desired} 五元组游程压缩追加到独立的
 * CAS 事件区 (56B/事件)。非目标线程只执行真实 CAS 不记录。 */
size_t a64_cas_record_block(uint8_t *out, uint64_t block_abs,
                            uint32_t orig_insn, uint64_t tls,
                            uint64_t site_id, uint64_t state_abs,
                            uint64_t cas_event_ptr_addr,
                            uint64_t cas_events_end_addr,
                            uint64_t cas_overflow_addr,
                            uint64_t ret_addr,
                            struct a64_atom_counts *counts);

/* ---- LSE CAS 结局回放跳板 ----
 * 按 ordinal 查 48B 运行段 {start,addr,old,success,expected,desired};
 * 按 ordinal 命中运行段: success=1 写 desired (切片自己的 Rt) 到
 * 录制 run.addr (对象身份跨站点校验暂缓: ldar 值回放带 +1 延迟,
 * 逐访问对齐会误报; 与 load 回放一致), Rs 一律装录制 old。
 * 超出窗口访问预算或 run.addr==0 → exit_abs 兜底。 */
size_t a64_cas_replay_block(uint8_t *out, uint64_t block_abs,
                            uint64_t runs_abs, uint64_t n_runs,
                            unsigned rs, unsigned rt, unsigned rn,
                            uint64_t ret_addr,
                            uint64_t load_limit, uint64_t exit_abs,
                            uint64_t tel_abs);

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
                               uint64_t tel_abs,
                               int kind,
                               const struct a64_ld_addr *ad);

/* run-burn 整 run 烧录回放块 (自旋循环):
 * 一次入口消费整个 busy run + 值变化访问, 内部按 guest 等长指令数
 * 烧录 (body_len = 循环体指令数), 消除逐访问值回放膨胀;
 * o == run.start 走逐访问路径, 末 run/预算越界走 limit_exit。 */
size_t a64_atomic_replay_burn_block(uint8_t *out, uint64_t block_abs,
                                    uint64_t runs_abs, uint64_t n_runs,
                                    int size, unsigned rt, unsigned rn,
                                    uint64_t ret_addr,
                                    uint64_t load_limit, uint64_t exit_abs,
                                    uint64_t tel_abs,
                                    int kind,
                                    const struct a64_ld_addr *ad,
                                    uint32_t body_len);

/* 单段常量站点的快速回放块: 窗口内值不变 (run_cnt==0, 仅合成首段)。
 * 不做游标推进/运行段查找/start 比较, 值直接内嵌; 保留命中计数+
 * 负载上限退出、地址校验 (失配回退真实读 + miss 计数) 与 ldar/ldaxr
 * 真实屏障 (排他监视器)。路径指令数约为通用块的 55-65%。 */
size_t a64_atomic_replay_block_fast(uint8_t *out, uint64_t block_abs,
                                    int size, unsigned rt, unsigned rn,
                                    const struct a64_ld_addr *ad,
                                    uint64_t ret_addr,
                                    uint64_t load_limit, uint64_t exit_abs,
                                    uint64_t tel_abs,
                                    int kind, uint64_t value, uint64_t addr);

/* 通用 load 检测: ldar 族 (kind=0), ldaxr 族 (kind=1),
 * 普通 ldr w/x 立即数 (kind=2), 普通 ldr w/x 寄存器偏移 (kind=3) */
int a64_is_load_any(uint32_t w, int *size, unsigned *rt, unsigned *rn,
                    int *kind);

/* 普通 ldr w/x 识别 (立即数/寄存器偏移), 输出地址描述。
 * kind 与 a64_is_load_any 一致 (2=立即数, 3=寄存器偏移)。 */
int a64_is_plain_load(uint32_t w, int *size, unsigned *rt, unsigned *rn,
                      int *kind, struct a64_ld_addr *ad);

/* 排他 store 检测: stxr/stlxr 族 (含 b/h/w/x)。size 0-3 (b/h/w/x),
 * rs=状态寄存器 (0=成功), rn=基址, rt=数据寄存器, acquire=1 为
 * stlxr 族。用于"强制成功"跳板: 把 stlxr 替换为无条件 str + rs=0,
 * 消除对排他监视器语义的依赖 (模拟器可能任何 store 清监视器 →
 * 真实 stlxr 永远失败 → LL/SC 循环死锁)。 */
int a64_is_excl_store(uint32_t w, int *size, unsigned *rs,
                      unsigned *rn, unsigned *rt, int *acquire);

/* 排他 load 检测: ldxr/ldaxr 族 (含 b/h/w/x)。size 0-3, rt=数据,
 * rn=基址, acquire=1 为 ldaxr 族。用于扫描"配对 stlxr" (覆盖未
 * 插桩的 ldxr: 无锁队列 CAS 用 ldxr+stlxr, ldxr 不在回放站点里)。 */
int a64_is_excl_load(uint32_t w, int *size, unsigned *rt,
                     unsigned *rn, int *acquire);

/* ---- LSE CAS 族 (cas/casa/casl/casal, 32/64 位) ----
 * 编码 (ARM ARM):
 *   [31:30] size (00=w, 11=x)
 *   [29:24] 001000 (bit27=1, bit22 不参与)
 *   [23:21] = 101 (CAS 族; bit22=L acquire 不参与)
 *   [20:16] Rs = 期望值 (CAS 成功后返回旧值)
 *   [15]    o0 (casl/casal 置位)
 *   [14:10] 11111
 *   [9:5]   Rn = 地址
 *   [4:0]   Rt = 新值
 * 匹配掩码: (w & 0x3FA07C00) == 0x08A07C00 —— 钉 bits[29:24]=001000/
 * bit23/bit21/bits[14:10]=11111, bit22 (L) 与 bit15 (o0) 不参与
 * (casa/casal 的 bit22=1)。**不可**再简化掩码: 0x08A07C00 会放行
 * 数据/字面量池误报 (0x3FE07C00 又漏 casa/casal)。实测编码:
 *   cas=0xc8a07c22 casl=0xc8a0fc22 casa=0xc8e07c22 casal=0xc8e0fc22
 *   (swpal=0xf8e08020 ldaddal=0xf8e00020 均被 bits14..10 排除)。 */
int a64_is_lse_cas(uint32_t w, unsigned *rs, unsigned *rt,
                   unsigned *rn);

/* 排他 store → 等宽无条件 str [Xn] (数据寄存器不变) */
uint32_t a64_excl_store_to_str(int size, unsigned rn, unsigned rt);

/* 生成排他 store 强制成功跳板 (0x20 字节):
 *   stp x16,x17,[sp,#-16]!
 *   str Xt,[Xn]        ; 无条件写入 (不依赖排他监视器)
 *   mov wRs,#0         ; 状态=成功
 *   ldp x16,x17,[sp],#16
 *   b ret_addr
 * 消除 LL/SC 对监视器语义的依赖 (模拟器可能任何 store 清监视器 →
 * stlxr 永远失败 → 循环死锁)。 */
size_t a64_excl_store_trampoline(uint8_t *out, uint64_t block_abs,
                                 uint32_t insn, uint64_t ret_addr);

/* 生成 LSE CAS 强制成功跳板 (0x20 字节):
 *   stp x16,x17,[sp,#-16]!
 *   ldr xT,[pc,#8]      ; T=16 或 17 (避开 Rt/Rn)
 *   str Xt,[Xn]         ; 无条件写入
 *   .quad ret_addr
 *   ldr 另一个,[sp,#N]; add sp,sp,#16; br xT
 * Rs 保持期望值 (CAS 成功语义)。Rt/Rn 同时占用 x16/x17 时返回 0。 */
size_t a64_lse_cas_trampoline(uint8_t *out, uint64_t block_abs,
                              uint32_t insn, uint64_t ret_addr);

/* 检测 ldar/ldarb/ldarh 与 ldaxr/ldaxrb/ldaxrh; *exclusive 输出
 * ldaxr 族标记 (兼容旧调用) */
int a64_is_ldar_any(uint32_t w, int *size, unsigned *rt, unsigned *rn,
                    int *exclusive);

/* ---- 缓冲区头 (注入到目标地址空间, tracer 与跳板共享) ---- */
#define A64_ATB_MAGIC    0x41544F4DULL   /* "ATOM" */
#define A64_ATB_VERSION  1
#define A64_ATB_HDR_SIZE 96
#define A64_ATB_OFF_MAGIC       0
#define A64_ATB_OFF_VERSION     8
#define A64_ATB_OFF_N_SITES     16
#define A64_ATB_OFF_STATE_OFF   24   /* 状态区相对缓冲区的偏移 */
#define A64_ATB_OFF_EVENTS_OFF  32
#define A64_ATB_OFF_EVENT_PTR   40   /* 绝对地址 (下一条事件写入点) */
#define A64_ATB_OFF_EVENTS_END  48   /* 绝对地址 (事件区末尾) */
#define A64_ATB_OFF_OVERFLOW    56
#define A64_ATB_OFF_BUF_SIZE    64
#define A64_ATB_OFF_CAS_EVENT_PTR 72  /* CAS 事件区 (56B/事件) */
#define A64_ATB_OFF_CAS_EVENTS_END 80
#define A64_ATB_OFF_CAS_OVERFLOW 88

/* 站点状态槽 (24B) */
#define A64_ATB_STATE_SIZE      24
#define A64_ATB_STATE_ORD       0
#define A64_ATB_STATE_LAST_VAL  8
#define A64_ATB_STATE_LAST_ADDR 16

/* 事件 (40B): {site_id, ord, addr, value, caller}
   caller 仅 record-all 诊断模式由普通 load 跳板填写 (原子跳板留空) */
#define A64_ATB_EVENT_SIZE      40

/* ---- 侧车文件魔数 (trace 输出 atomics/) ---- */
#define A64_AT_SITES_MAGIC  0x53495445ULL   /* "ETIS" */
#define A64_AT_EVENTS_MAGIC 0x56455441ULL   /* "ATEV" */
#define A64_AT_CAS_EVENTS_MAGIC 0x43564541ULL /* "AEVC" */
#define A64_AT_CKPT_MAGIC   0x4B435441ULL   /* "ATCK" */

#endif
