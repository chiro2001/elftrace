/*
 * aarch64 指令解码与编码工具 (strict baremetal 用)
 *
 * 用途:
 *   - 定位/生成 syscall 站点替换: svc #0 → b <trampoline>
 *   - 循环回边分析: 目标退出点在循环内时, patch 回边 → 跳板 counter
 * aarch64 指令定长 4B 小端。
 */
#ifndef ELFTRACE_A64_H
#define ELFTRACE_A64_H

#include <stdint.h>
#include <stddef.h>

uint32_t a64_insn(const uint8_t *p);

int a64_is_b(uint32_t w);        /* b #imm26 */
int a64_is_bl(uint32_t w);
int a64_is_bcond(uint32_t w);    /* b.cond #imm19 */
int a64_is_cbz(uint32_t w);
int a64_is_cbnz(uint32_t w);
int a64_is_tbz(uint32_t w);
int a64_is_tbnz(uint32_t w);
int a64_is_adr(uint32_t w);
int a64_is_adrp(uint32_t w);
int a64_is_ldr_literal(uint32_t w);
int a64_is_svc0(uint32_t w);     /* svc #0 = d4000001 */
int a64_is_br(uint32_t w);       /* br/blr/ret */

/* 分支目标 (pc 为指令地址); 非分支返回 0 */
uint64_t a64_branch_target(uint32_t w, uint64_t pc);
/* 向后分支 (target < pc) 则置 *target 并返回 1 */
int a64_backward_branch_target(uint32_t w, uint64_t pc, uint64_t *target);

/* 编码 */
uint32_t a64_encode_b(uint64_t from, uint64_t to);   /* b to (±128MB) */
uint32_t a64_ldr_x16_pc8(void);                      /* ldr x16, [pc, #8] */
uint32_t a64_br_x16(void);                           /* br x16 */
uint32_t a64_svc0(void);                             /* svc #0 */

/* 在段内容 code (seg_vaddr..seg_vaddr+filesz) 中查找包含 target_pc 的
 * 循环回边: 从 target_pc 向前扫描, 找最近的向后分支 (回边)。
 * 成功返回 1, *head = 循环头 (回边目标), *backedge = 回边指令地址。
 * 失败返回 0 (目标不在简单循环内)。 */
int a64_find_loop_backedge(const uint8_t *code, uint64_t seg_vaddr,
                           uint64_t seg_filesz, uint64_t target_pc,
                           uint64_t *head, uint64_t *backedge);

#endif
