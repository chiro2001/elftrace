/* alloc 结果重放跳板生成器 (M1 构建端) — 见 include/alloc_build.h */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "alloc_build.h"
#include "a64.h"

/* 小编码器 (构建侧跳板生成) */
static uint32_t b_movz(unsigned rd, unsigned imm16, unsigned hw)
{
    return 0xD2800000U | ((hw & 3) << 21) | ((imm16 & 0xffff) << 5) | rd;
}
static uint32_t b_movk(unsigned rd, unsigned imm16, unsigned hw)
{
    return 0xF2800000U | ((hw & 3) << 21) | ((imm16 & 0xffff) << 5) | rd;
}
static uint32_t b_ldr(unsigned rt, unsigned rn, unsigned imm)
{
    return 0xF9400000U | ((imm / 8) << 10) | (rn << 5) | rt;
}
static uint32_t b_str(unsigned rt, unsigned rn, unsigned imm)
{
    return 0xF9000000U | ((imm / 8) << 10) | (rn << 5) | rt;
}
static uint32_t b_addi(unsigned rd, unsigned rn, unsigned imm)
{
    return 0x91000000U | (imm << 10) | (rn << 5) | rd;
}
static uint32_t b_add_reg(unsigned rd, unsigned rn, unsigned rm, unsigned sh)
{
    return 0x8B000000U | (rm << 16) | ((sh & 7) << 10) | (rn << 5) | rd;
}
static uint32_t b_br(unsigned rn)
{
    return 0xD61F0000U | (rn << 5);
}

/* alloc 结果重放跳板 (每函数一块, 0x280B):
 * 消费全局事件流: 校验 kind → x0=录制 ret → 游标++。
 * 兜底: 超消费 (reason=9) / kind 失配 (reason=11) → 遥测 + bail。 */
size_t alloc_replay_block(uint8_t *out, uint64_t block_abs,
                          uint64_t cursor_addr, uint64_t total_addr,
                          uint64_t events_abs, uint32_t kind,
                          uint64_t tel_abs, uint64_t bail_abs,
                          uint64_t site_pc)
{
    uint8_t *p = out;
    memset(out, 0, 0x280);
    uint32_t w = 0xA9BF47F0U;
    memcpy(p, &w, 4); p += 4;              /* stp x16,x17,[sp,#-16]! */
    w = 0xA9BF53F3U;
    memcpy(p, &w, 4); p += 4;              /* stp x19,x20,[sp,#-16]! */
    w = 0xA9BF5BF5U;
    memcpy(p, &w, 4); p += 4;              /* stp x21,x22,[sp,#-16]! */
    w = 0xA9BF7FF7U;
    memcpy(p, &w, 4); p += 4;              /* stp x23,xzr,[sp,#-16]! */
    w = 0xD503201FU;
    memcpy(p, &w, 4); p += 4;              /* nop */
    w = 0x58000050U;
    memcpy(p, &w, 4); p += 4;              /* ldr x16,[pc,#8] */
    w = 0xD61F0200U;
    memcpy(p, &w, 4); p += 4;              /* br x16 */
    uint64_t v = block_abs + (uint64_t)(p - out) + 8;   /* 指向 sub 指令 */
    memcpy(p, &v, 8); p += 8;
    w = 0xD1000000U | (((uint32_t)(p - out)) << 10) | (16U << 5) | 16U;
    memcpy(p, &w, 4); p += 4;              /* sub x16,x16,#<sub_off> */
    w = b_ldr(17, 16, 0x200);
    memcpy(p, &w, 4); p += 4;              /* &cursor */
    w = b_ldr(18, 17, 0);
    memcpy(p, &w, 4); p += 4;              /* cursor */
    w = b_ldr(19, 16, 0x208);
    memcpy(p, &w, 4); p += 4;              /* &total */
    w = b_ldr(19, 19, 0);
    memcpy(p, &w, 4); p += 4;              /* total */
    w = 0xEB13025FU;
    memcpy(p, &w, 4); p += 4;              /* cmp x18,x19 */
    w = 0x54000063U;
    memcpy(p, &w, 4); p += 4;              /* b.lo +12 (跳过 8B 兜底) */
    uint8_t *ovr = p;                       /* movz x22,#9; b bail (8B) */
    p += 8;
    w = b_ldr(20, 16, 0x210);
    memcpy(p, &w, 4); p += 4;              /* events_abs */
    w = b_add_reg(21, 20, 18, 5);
    memcpy(p, &w, 4); p += 4;              /* x21 = x20 + x18<<5 */
    w = 0xB9400000U | (21U << 5) | 22U;
    memcpy(p, &w, 4); p += 4;              /* ldr w22,[x21] */
    w = 0xB9400000U | ((0x218U / 4) << 10) | (16U << 5) | 23U;
    memcpy(p, &w, 4); p += 4;              /* ldr w23,[x16,#0x218] */
    w = 0x6B1702DFU;
    memcpy(p, &w, 4); p += 4;              /* cmp w22,w23 */
    w = 0x54000060U;
    memcpy(p, &w, 4); p += 4;              /* b.eq +12 (跳过 8B 兜底) */
    uint8_t *mis = p;                       /* movz x22,#11; b bail (8B) */
    p += 8;
    w = b_ldr(0, 21, 24);
    memcpy(p, &w, 4); p += 4;              /* x0 = [event+24] ret */
    w = b_addi(18, 18, 1);
    memcpy(p, &w, 4); p += 4;              /* cursor++ */
    w = b_str(18, 17, 0);
    memcpy(p, &w, 4); p += 4;              /* [cursor]=cursor */
    w = 0xA8C17FF7U;
    memcpy(p, &w, 4); p += 4;              /* ldp x23,xzr,[sp],#16 */
    w = 0xA8C15BF5U;
    memcpy(p, &w, 4); p += 4;              /* ldp x21,x22,[sp],#16 */
    w = 0xA8C153F3U;
    memcpy(p, &w, 4); p += 4;              /* ldp x19,x20,[sp],#16 */
    w = 0xA8C147F0U;
    memcpy(p, &w, 4); p += 4;              /* ldp x16,x17,[sp],#16 */
    w = 0xD65F03C0U;
    memcpy(p, &w, 4); p += 4;              /* ret */

    /* 兜底: 遥测 + bail (共享; x22=reason, x18=cursor, x19=total) */
    uint8_t *bail = p;
    w = b_ldr(20, 16, 0x220);
    memcpy(p, &w, 4); p += 4;              /* tel_abs */
    w = b_movz(21, 0x4554, 0);
    memcpy(p, &w, 4); p += 4;
    w = b_movk(21, 0x4D4C, 1);
    memcpy(p, &w, 4); p += 4;              /* "TELM" */
    w = b_str(21, 20, 0);
    memcpy(p, &w, 4); p += 4;
    /* reason: overrun=9, mismatch=11 (由进入路径设 x22) */
    w = b_str(22, 20, 8);
    memcpy(p, &w, 4); p += 4;
    w = b_ldr(21, 16, 0x228);
    memcpy(p, &w, 4); p += 4;              /* site_pc */
    w = b_str(21, 20, 16);
    memcpy(p, &w, 4); p += 4;
    w = b_str(18, 20, 24);
    memcpy(p, &w, 4); p += 4;              /* ordinal = cursor */
    w = b_str(19, 20, 32);
    memcpy(p, &w, 4); p += 4;              /* limit = total */
    w = b_ldr(21, 16, 0x230);
    memcpy(p, &w, 4); p += 4;              /* bail_abs */
    w = b_br(21);
    memcpy(p, &w, 4); p += 4;

    /* 回填: overrun → movz x22,#9; b bail; mismatch → x22,#11; b bail */
    {
        uint32_t w9 = b_movz(22, 9, 0);
        uint32_t w11 = b_movz(22, 11, 0);
        uint32_t bw9 = a64_encode_b(block_abs + (uint64_t)(ovr + 4 - out),
                                    block_abs + (uint64_t)(bail - out));
        uint32_t bw11 = a64_encode_b(block_abs + (uint64_t)(mis + 4 - out),
                                     block_abs + (uint64_t)(bail - out));
        if (!bw9 || !bw11)
            return 0;
        memcpy(ovr, &w9, 4);
        memcpy(ovr + 4, &bw9, 4);
        memcpy(mis, &w11, 4);
        memcpy(mis + 4, &bw11, 4);
    }

    v = cursor_addr; memcpy(out + 0x200, &v, 8);
    v = total_addr;  memcpy(out + 0x208, &v, 8);
    v = events_abs;  memcpy(out + 0x210, &v, 8);
    v = kind;        memcpy(out + 0x218, &v, 8);
    v = tel_abs;     memcpy(out + 0x220, &v, 8);
    v = site_pc;     memcpy(out + 0x228, &v, 8);
    v = bail_abs;    memcpy(out + 0x230, &v, 8);
    return 0x280;
}
