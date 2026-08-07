#include "a64.h"
#include <string.h>

uint32_t a64_insn(const uint8_t *p)
{
    uint32_t w;
    memcpy(&w, p, 4);
    return w;
}

int a64_is_b(uint32_t w) { return (w & 0xFC000000U) == 0x14000000U; }
int a64_is_bl(uint32_t w) { return (w & 0xFC000000U) == 0x94000000U; }
int a64_is_bcond(uint32_t w)
{
    return (w & 0xFF000010U) == 0x54000000U;
}
int a64_is_cbz(uint32_t w) { return (w & 0x7F000000U) == 0x34000000U; }
int a64_is_cbnz(uint32_t w) { return (w & 0x7F000000U) == 0x35000000U; }
int a64_is_tbz(uint32_t w) { return (w & 0x7E000000U) == 0x36000000U; }
int a64_is_tbnz(uint32_t w) { return (w & 0x7E000000U) == 0x37000000U; }
int a64_is_adr(uint32_t w) { return (w & 0x9F000000U) == 0x10000000U; }
int a64_is_adrp(uint32_t w) { return (w & 0x9F000000U) == 0x90000000U; }
int a64_is_ldr_literal(uint32_t w)
{
    return (w & 0x3B000000U) == 0x18000000U;
}
int a64_is_svc0(uint32_t w) { return w == 0xD4000001U; }
int a64_is_br(uint32_t w)
{
    return (w & 0xFFFFFC1FU) == 0xD61F0000U;   /* br/blr/ret xn */
}

static int64_t sign_extend(uint64_t v, int bits)
{
    uint64_t m = 1ULL << (bits - 1);
    v &= (1ULL << bits) - 1;
    return (int64_t)((v ^ m) - m);
}

uint64_t a64_branch_target(uint32_t w, uint64_t pc)
{
    int64_t off;
    if (a64_is_b(w) || a64_is_bl(w))
        off = sign_extend(w & 0x03FFFFFFU, 26) << 2;
    else if (a64_is_bcond(w) || a64_is_cbz(w) || a64_is_cbnz(w))
        off = sign_extend((w >> 5) & 0x7FFFFU, 19) << 2;
    else if (a64_is_tbz(w) || a64_is_tbnz(w))
        off = sign_extend((w >> 5) & 0x3FFFU, 14) << 2;
    else if (a64_is_adr(w) || a64_is_adrp(w)) {
        int64_t imm = ((w >> 5) & 0x7FFFFU) | (((w >> 29) & 1U) << 20);
        imm = sign_extend((uint64_t)imm, 21);
        off = a64_is_adrp(w) ? (imm << 12) : imm;
    } else if (a64_is_ldr_literal(w)) {
        off = sign_extend((w >> 5) & 0x7FFFFU, 19) << 2;
    } else {
        return 0;
    }
    return (uint64_t)((int64_t)pc + off);
}

int a64_backward_branch_target(uint32_t w, uint64_t pc, uint64_t *target)
{
    uint64_t t = a64_branch_target(w, pc);
    if (!t || t >= pc)
        return 0;
    *target = t;
    return 1;
}

uint32_t a64_encode_b(uint64_t from, uint64_t to)
{
    int64_t off = (int64_t)(to - from);
    if ((off & 3) != 0 || off < (-1L << 25) || off > ((1L << 25) - 4))
        return 0;               /* 超出 ±128MB */
    return 0x14000000U | ((uint32_t)((off >> 2) & 0x03FFFFFFU));
}

uint32_t a64_ldr_x16_pc8(void) { return 0x58000050U; }
uint32_t a64_br_x16(void) { return 0xD61F0200U; }
uint32_t a64_svc0(void) { return 0xD4000001U; }

int a64_find_loop_backedge(const uint8_t *code, uint64_t seg_vaddr,
                           uint64_t seg_filesz, uint64_t target_pc,
                           uint64_t *head, uint64_t *backedge)
{
    if (target_pc < seg_vaddr ||
        target_pc - seg_vaddr + 4 > seg_filesz)
        return 0;
    uint64_t t_idx = (target_pc - seg_vaddr) / 4;
    uint64_t ninsn = seg_filesz / 4;
    uint64_t limit = 1 << 16;    /* 最多扫描 65536 条指令 */

    /* 1. 目标指令本身就是回边 (P == backedge) */
    {
        uint64_t pc = target_pc;
        uint32_t w = a64_insn(code + t_idx * 4);
        uint64_t t;
        if (a64_backward_branch_target(w, pc, &t) && t <= target_pc) {
            *head = t;
            *backedge = pc;
            return 1;
        }
    }
    /* 2. 向前: 目标在循环体内 (回边在目标之后) — 找最近的后向分支
       (回边), 其目标 H ≤ target_pc 即包含目标的循环头 */
    uint64_t idx = t_idx;
    limit = 1 << 16;
    while (idx + 1 < ninsn && limit--) {
        idx++;
        uint64_t pc = seg_vaddr + idx * 4;
        uint32_t w = a64_insn(code + idx * 4);
        uint64_t t;
        if (a64_backward_branch_target(w, pc, &t)) {
            if (t <= target_pc && t >= seg_vaddr) {
                *head = t;
                *backedge = pc;
                return 1;
            }
        }
    }
    return 0;
}
