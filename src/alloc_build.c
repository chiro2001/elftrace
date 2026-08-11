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
                          uint64_t site_pc, uint64_t exit_abs,
                          uint64_t copy_len_abs)
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
    w = 0x8B120E95U;
    memcpy(p, &w, 4); p += 4;              /* x21 = x20 + x18<<3 */
    w = 0x8B1216B5U;
    memcpy(p, &w, 4); p += 4;              /* x21 += x18<<5 (40B/事件) */
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
    w = b_ldr(23, 21, 8);
    memcpy(p, &w, 4); p += 4;              /* x23 = [event+8] 录制参数 */
    w = 0xEB17001FU;
    memcpy(p, &w, 4); p += 4;              /* cmp x0,x24 (调用参数一致) */
    w = 0x54000060U;
    memcpy(p, &w, 4); p += 4;              /* b.eq +12 (跳过 8B 兜底) */
    uint8_t *argmis = p;                    /* movz x22,#12; b bail (8B) */
    p += 8;
    w = 0xAA0003E2U;
    memcpy(p, &w, 4); p += 4;              /* mov x2,x0 (old_ptr 暂存,
                                               realloc 搬运用) */
    /* calloc 清零: x0=nmemb, x1=elem_size (调用参数仍有效),
       x23=录制 nmemb (arg 校验后空闲, 已保存/恢复)。
       x23 = nmemb*elem_size; 超 256MB → reason=13 bail。
       所有分支偏移用指针回填, 不手算。 */
    w = 0x9B017C17U;
    memcpy(p, &w, 4); p += 4;              /* mul x23,x0,x1 */
    w = 0x91001EF7U;
    memcpy(p, &w, 4); p += 4;              /* add x23,x23,#7 (8B 对齐) */
    w = 0x927DF2F7U;
    memcpy(p, &w, 4); p += 4;              /* and x23,x23,#~7 */
    w = 0x710006DFU;
    memcpy(p, &w, 4); p += 4;              /* cmp w22,#1 (kind==calloc) */
    uint8_t *bne1 = p;                      /* b.ne → ldr x0 (占位) */
    p += 4;
    w = b_movz(5, 0x1000, 1);
    memcpy(p, &w, 4); p += 4;              /* mov x5,#0x10000000 (256MB) */
    w = 0xEB0502FFU;
    memcpy(p, &w, 4); p += 4;              /* cmp x23,x5 */
    uint8_t *bhi = p;                       /* b.hi → big (占位) */
    p += 4;
    uint8_t *bskp = p;                      /* b → ldr x0 (占位) */
    p += 4;
    uint8_t *big = p;                       /* movz x22,#13; b bail (8B) */
    p += 8;
    uint8_t *after = p;
    w = b_ldr(0, 21, 24);
    memcpy(p, &w, 4); p += 4;              /* x0 = [event+24] ret */
    /* 零化循环: [x0, x0+x23) (仅 calloc 且 ret!=0 且 size!=0) */
    w = 0x710006DFU;
    memcpy(p, &w, 4); p += 4;              /* cmp w22,#1 */
    uint8_t *bne2 = p;                      /* b.ne → cursor++ (占位) */
    p += 4;
    uint8_t *cbz0 = p;                      /* cbz x0 → cursor++ (占位) */
    p += 4;
    uint8_t *cbzz = p;                      /* cbz x23 → cursor++ (占位) */
    p += 4;
    w = 0xAA0003E3U;
    memcpy(p, &w, 4); p += 4;              /* mov x3,x0 */
    w = 0xAA1703E4U;
    memcpy(p, &w, 4); p += 4;              /* mov x4,x23 */
    uint8_t *zloop = p;
    w = 0xF800847FU;
    memcpy(p, &w, 4); p += 4;              /* str xzr,[x3],#8 */
    w = 0xD1002084U;
    memcpy(p, &w, 4); p += 4;              /* sub x4,x4,#8 */
    w = 0xB5000000U | (((uint32_t)((zloop - p) / 4) & 0x7FFFF)
                       << 5) | 4U;
    memcpy(p, &w, 4); p += 4;              /* cbnz x4,zloop */
    uint8_t *zero_end = p;
    /* realloc 搬运: kind==2 且 ret!=old 且 copy_len>0 时
       memcpy(ret, old, copy_len) — 录制侧真实 realloc 的搬运在切片里
       被跳过, 补上既保证内容正确也恢复指令工作量 (A/T 对齐)。 */
    w = 0x71000ADFU;
    memcpy(p, &w, 4); p += 4;              /* cmp w22,#2 */
    uint8_t *bne3 = p;                      /* b.ne → cursor++ (占位) */
    p += 4;
    w = 0xF9412205U;
    memcpy(p, &w, 4); p += 4;              /* ldr x5,[x16,#0x240] */
    w = 0x8B120CA5U;
    memcpy(p, &w, 4); p += 4;              /* add x5,x5,x18,lsl#3 */
    w = b_ldr(5, 5, 0);
    memcpy(p, &w, 4); p += 4;              /* ldr x5,[x5] copy_len */
    w = 0x91001CA5U;
    memcpy(p, &w, 4); p += 4;              /* add x5,x5,#7 */
    w = 0x927DF0A5U;
    memcpy(p, &w, 4); p += 4;              /* and x5,x5,#~7 (8B 对齐) */
    uint8_t *cbz5 = p;                      /* cbz x5 → cursor++ (占位) */
    p += 4;
    uint8_t *cbz0b = p;                     /* cbz x0 → cursor++ (占位) */
    p += 4;
    w = 0xEB02001FU;
    memcpy(p, &w, 4); p += 4;              /* cmp x0,x2 (ret==old?) */
    uint8_t *beq = p;                       /* b.eq → cursor++ (占位) */
    p += 4;
    w = 0xAA0203E3U;
    memcpy(p, &w, 4); p += 4;              /* mov x3,x2 (src) */
    w = 0xAA0003E4U;
    memcpy(p, &w, 4); p += 4;              /* mov x4,x0 (dst) */
    uint8_t *cploop = p;
    w = 0xF8408466U;
    memcpy(p, &w, 4); p += 4;              /* ldr x6,[x3],#8 */
    w = 0xF8008486U;
    memcpy(p, &w, 4); p += 4;              /* str x6,[x4],#8 */
    w = 0xD10020A5U;
    memcpy(p, &w, 4); p += 4;              /* sub x5,x5,#8 */
    w = 0xB5000000U | (((uint32_t)((cploop - p) / 4) & 0x7FFFF) << 5) |
        5U;                                 /* cbnz x5,cploop */
    memcpy(p, &w, 4); p += 4;
    uint8_t *cp_end = p;
    /* 回填 realloc 搬运段分支 */
    {
        uint32_t b3 = 0x54000000U |
                      (((uint32_t)((cp_end - bne3) / 4) & 0x7FFFF) << 5) |
                      1U;
        memcpy(bne3, &b3, 4);
        uint32_t c5 = 0xB4000000U |
                      (((uint32_t)((cp_end - cbz5) / 4) & 0x7FFFF) << 5) |
                      5U;
        memcpy(cbz5, &c5, 4);
        uint32_t c0 = 0xB4000000U |
                      (((uint32_t)((cp_end - cbz0b) / 4) & 0x7FFFF) << 5);
        memcpy(cbz0b, &c0, 4);
        uint32_t be = 0x54000000U |
                      (((uint32_t)((cp_end - beq) / 4) & 0x7FFFF) << 5);
        memcpy(beq, &be, 4);
    }
    /* 回填: bne1→after, bhi→big, bskp→after,
       bne2→zero_end, cbz0→zero_end, cbzz→zero_end */
    {
        uint32_t b1 = 0x54000000U |
                      (((uint32_t)((after - bne1) / 4) & 0x7FFFF) << 5) |
                      1U;                   /* b.ne */
        memcpy(bne1, &b1, 4);
        uint32_t bh = 0x54000000U |
                      (((uint32_t)((big - bhi) / 4) & 0x7FFFF) << 5) |
                      8U;                   /* b.hi */
        memcpy(bhi, &bh, 4);
        uint32_t bs = 0x14000000U |
                      (((uint32_t)((after - bskp) / 4) & 0x3FFFFFF));
        memcpy(bskp, &bs, 4);
        uint32_t b2 = 0x54000000U |
                      (((uint32_t)((zero_end - bne2) / 4) & 0x7FFFF) << 5) |
                      1U;                   /* b.ne */
        memcpy(bne2, &b2, 4);
        uint32_t c0 = 0xB4000000U |
                      (((uint32_t)((zero_end - cbz0) / 4) & 0x7FFFF) << 5);
        memcpy(cbz0, &c0, 4);
        uint32_t cz = 0xB4000000U |
                      (((uint32_t)((zero_end - cbzz) / 4) & 0x7FFFF) << 5) |
                      23U;
        memcpy(cbzz, &cz, 4);
    }
    w = b_addi(18, 18, 1);
    memcpy(p, &w, 4); p += 4;              /* cursor++ */
    w = b_str(18, 17, 0);
    memcpy(p, &w, 4); p += 4;              /* [cursor]=cursor */
    /* 融合退出: cursor==total (窗口最后一个分配事件消费完) →
       br exit_abs; 不返回调用者, 切片在最后一个分配调用处干净结束。
       exit_abs==0 时禁用 (逐事件返回, 靠 TO 站点/循环计数退出)。 */
    w = b_ldr(20, 16, 0x238);
    memcpy(p, &w, 4); p += 4;              /* exit_abs */
    uint8_t *fused_cbz = p;
    w = 0xB4000000U | (20U << 5);           /* cbz x20 (占位, 回填) */
    memcpy(p, &w, 4); p += 4;
    w = 0xEB13025FU;
    memcpy(p, &w, 4); p += 4;              /* cmp x18,x19 */
    uint8_t *fused_bne = p;
    w = 0x54000000U | 1U;                   /* b.ne (占位, 回填) */
    memcpy(p, &w, 4); p += 4;
    w = 0xD61F0280U;
    memcpy(p, &w, 4); p += 4;              /* br x20 */
    uint8_t *restore = p;
    {
        uint32_t cbz = 0xB4000000U |
                       (((uint32_t)((restore - fused_cbz) / 4) &
                         0x7FFFF) << 5) | 20U;
        memcpy(fused_cbz, &cbz, 4);
        uint32_t bne = 0x54000000U |
                       (((uint32_t)((restore - fused_bne) / 4) &
                         0x7FFFF) << 5) | 1U;
        memcpy(fused_bne, &bne, 4);
    }
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
        uint32_t w12 = b_movz(22, 12, 0);
        uint32_t w13 = b_movz(22, 13, 0);
        uint32_t bw9 = a64_encode_b(block_abs + (uint64_t)(ovr + 4 - out),
                                    block_abs + (uint64_t)(bail - out));
        uint32_t bw11 = a64_encode_b(block_abs + (uint64_t)(mis + 4 - out),
                                     block_abs + (uint64_t)(bail - out));
        uint32_t bw12 = a64_encode_b(block_abs + (uint64_t)(argmis + 4 - out),
                                     block_abs + (uint64_t)(bail - out));
        uint32_t bw13 = a64_encode_b(block_abs + (uint64_t)(big + 4 - out),
                                     block_abs + (uint64_t)(bail - out));
        if (!bw9 || !bw11 || !bw12 || !bw13)
            return 0;
        memcpy(ovr, &w9, 4);
        memcpy(ovr + 4, &bw9, 4);
        memcpy(mis, &w11, 4);
        memcpy(mis + 4, &bw11, 4);
        memcpy(argmis, &w12, 4);
        memcpy(argmis + 4, &bw12, 4);
        memcpy(big, &w13, 4);
        memcpy(big + 4, &bw13, 4);
    }

    v = cursor_addr; memcpy(out + 0x200, &v, 8);
    v = total_addr;  memcpy(out + 0x208, &v, 8);
    v = events_abs;  memcpy(out + 0x210, &v, 8);
    v = kind;        memcpy(out + 0x218, &v, 8);
    v = tel_abs;     memcpy(out + 0x220, &v, 8);
    v = site_pc;     memcpy(out + 0x228, &v, 8);
    v = bail_abs;    memcpy(out + 0x230, &v, 8);
    v = exit_abs;    memcpy(out + 0x238, &v, 8);
    v = copy_len_abs; memcpy(out + 0x240, &v, 8);
    return 0x280;
}
