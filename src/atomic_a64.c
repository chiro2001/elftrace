/*
 * aarch64 原子指令记录/回放跳板生成器。
 *
 * 编码均来自真实汇编 (objdump 验证): stp/ldp 带 sp 前/后变址,
 * mrs/msr nzcv, ldar, mov, ldr literal, br, b, cmp, ccmp, b.cond,
 * madd (mul), ldr/str [xN,#imm]。
 */
#include "atomic_a64.h"
#include "a64.h"

#include <string.h>

/* ---- 小端 32 位编码器 ---- */
static void put32(uint8_t **p, uint32_t w)
{
    memcpy(*p, &w, 4);
    *p += 4;
}

static void put64(uint8_t **p, uint64_t v)
{
    memcpy(*p, &v, 8);
    *p += 8;
}

/* ---- 固定指令编码 ---- */
#define INSN_NOP        0xD503201FU
#define INSN_MRS_X15_NZCV 0xD53B420FU
#define INSN_MSR_NZCV_X15 0xD51B420FU
#define INSN_MRS_X14_TPIDR 0xD53BD04EU
#define INSN_LDAR_X29_X27 0xC8DFFF7DU
#define INSN_LDAR_W29_X27 0x88DFFF7DU
#define INSN_BR_X16     0xD61F0200U

/* stp xA,xB,[sp,#-16]! / ldp xA,xB,[sp],#16, 按保存顺序索引 */
static const uint32_t stp_pre_tab[] = {
    0xA9BF07E0U, 0xA9BF0FE2U, 0xA9BF17E4U, 0xA9BF1FE6U,
    0xA9BF27E8U, 0xA9BF2FEAU, 0xA9BF37ECU, 0xA9BF3FEEU,
    0xA9BF4FF2U, 0xA9BF57F4U, 0xA9BF5FF6U, 0xA9BF67F8U,
    0xA9BF6FFAU, 0xA9BF77FCU, 0xA9BF7FFEU,
};
static const uint32_t ldp_post_tab[] = {
    0xA8C107E0U, 0xA8C10FE2U, 0xA8C117E4U, 0xA8C11FE6U,
    0xA8C127E8U, 0xA8C12FEAU, 0xA8C137ECU, 0xA8C13FEEU,
    0xA8C14FF2U, 0xA8C157F4U, 0xA8C15FF6U, 0xA8C167F8U,
    0xA8C16FFAU, 0xA8C177FCU, 0xA8C17FFEU,
};
static const uint32_t stp_flags = 0xA9BF7FEFU;  /* stp x15,xzr */
static const uint32_t ldp_flags = 0xA8C17FEFU;  /* ldp x15,xzr */

/* ldr/str xT,[xN,#imm] (imm/8 <= 4095) */
static uint32_t ldr_x_imm(unsigned base, unsigned rt, unsigned imm)
{
    return 0xF9400000U | ((imm / 8) << 10) | (base << 5) | rt;
}
static uint32_t str_x_imm(unsigned base, unsigned rt, unsigned imm)
{
    return 0xF9000000U | ((imm / 8) << 10) | (base << 5) | rt;
}
static uint32_t ldr_x16_imm(unsigned rt, unsigned imm)
{
    return ldr_x_imm(16, rt, imm);
}
static uint32_t str_x16_imm(unsigned rt, unsigned imm)
{
    return str_x_imm(16, rt, imm);
}

static uint32_t mov_x(unsigned rd, unsigned rm)
{
    return 0xAA0003E0U | (rm << 16) | rd;
}
static uint32_t add_x(unsigned rd, unsigned rn, unsigned imm)
{
    return 0x91000000U | (imm << 10) | (rn << 5) | rd;
}
static uint32_t add_xr(unsigned rd, unsigned rn, unsigned rm)
{
    return 0x8B000000U | (rm << 16) | (rn << 5) | rd;
}
static uint32_t cmp_x(unsigned rn, unsigned rm)
{
    return 0xEB00001FU | (rm << 16) | (rn << 5);
}
static uint32_t ccmp_eq(unsigned rn, unsigned rm)
{
    return 0xFA400000U | (rm << 16) | (rn << 5);
}
static uint32_t movz_x(unsigned rd, unsigned imm16, unsigned hw)
{
    return 0xD2800000U | ((hw & 3) << 21) | ((imm16 & 0xffff) << 5) | rd;
}
static uint32_t ldr_lit(unsigned rt, int32_t off)
{
    return 0x58000000U | (((uint32_t)(off / 4) & 0x7FFFF) << 5) | rt;
}
static uint32_t bcond(int32_t off, unsigned cond)
{
    return 0x54000000U | (((uint32_t)(off / 4) & 0x7FFFF) << 5) |
           (cond & 0xF);
}
static uint32_t mul_x(unsigned rd, unsigned rn, unsigned rm)
{
    /* madd xd,xn,xm,xzr */
    return 0x9B007C00U | (rm << 16) | (rn << 5) | rd;
}

/* ---- 保存/恢复序列 (入口的 x16/x17 已由入口 stp 保存) ---- */
static void emit_save(uint8_t **p)
{
    for (size_t i = 0; i < sizeof(stp_pre_tab) / sizeof(stp_pre_tab[0]); i++)
        put32(p, stp_pre_tab[i]);
    put32(p, INSN_MRS_X15_NZCV);
    put32(p, stp_flags);
}

static void emit_restore(uint8_t **p)
{
    put32(p, ldp_flags);
    put32(p, INSN_MSR_NZCV_X15);
    for (size_t i = sizeof(ldp_post_tab) / sizeof(ldp_post_tab[0]);
         i > 0; i--)
        put32(p, ldp_post_tab[i - 1]);
    put32(p, 0xA8C147F0U);      /* ldp x16,x17,[sp],#16 (入口保存) */
}

int a64_is_ldar(uint32_t w, int *size, unsigned *rt, unsigned *rn)
{
    /* 保留除 size(bit30)/Rn/Rt 外的全部定式位 */
    uint32_t base = w & 0xBFDFFC00U;
    if (base != 0x08DFFC00U && base != 0x88DFFC00U)
        return 0;               /* 仅 ldar/ldarb/ldarh (w/x 两种) */
    if (base == 0x08DFFC00U)
        *size = (w & 0x40000000U) ? 2 : 1;      /* ldarh / ldarb */
    else
        *size = (w & 0x40000000U) ? 8 : 4;      /* ldar x / ldar w */
    *rt = w & 0x1FU;
    *rn = (w >> 5) & 0x1FU;
    return 1;
}

/* 按加载宽度生成 ldar/ldarb/ldarh 指令 (回放屏障用) */
static uint32_t a64_ldar_insn(int size, unsigned rn, unsigned rt)
{
    uint32_t base = size == 1 ? 0x08DFFC00U :
                    size == 2 ? 0x48DFFC00U :
                    size == 4 ? 0x88DFFC00U : 0xC8DFFC00U;
    return base | (rn << 5) | rt;
}

int a64_atom_reg_save_off(unsigned reg)
{
    if (reg <= 15)
        return (reg & 1) ? (int)(256 - reg * 8) : (int)(240 - reg * 8);
    if (reg == 30)
        return 16;
    if (reg >= 18 && reg <= 29)
        return (reg & 1) ? (int)(272 - reg * 8) : (int)(256 - reg * 8);
    if (reg == 16)
        return 256;
    if (reg == 17)
        return 264;
    return -1;
}

/* ---- 记录跳板 ---- */
#define REC_TLS_OFF           0x200
#define REC_SITE_ID_OFF       0x208
#define REC_STATE_ABS_OFF     0x210
#define REC_EVENT_PTR_ADDR_OFF 0x218
#define REC_EVENTS_END_ADDR_OFF 0x220
#define REC_OVERFLOW_ADDR_OFF 0x228
#define REC_RET_ADDR_OFF      0x230

size_t a64_atomic_record_block(uint8_t *out, uint64_t block_abs,
                               uint32_t orig_insn, uint64_t tls,
                               uint64_t site_id, uint64_t state_abs,
                               uint64_t event_ptr_addr,
                               uint64_t events_end_addr,
                               uint64_t overflow_addr,
                               uint64_t ret_addr,
                               struct a64_atom_counts *counts)
{
    uint8_t *p = out;
    unsigned rt, rn;
    int size;
    if (!a64_is_ldar(orig_insn, &size, &rt, &rn))
        return 0;
    if (rt == 31)
        return 0;               /* 写入 xzr: 罕见, 跳过 */

    memset(out, 0, A64_ATOM_BLOCK_SIZE);

    /* 入口 (5 指令 + 8B 字面量 = 0x1C 字节, 代码从 0x1C 开始) */
    put32(&p, 0xA9BF47F0U);     /* stp x16,x17,[sp,#-16]! */
    put32(&p, orig_insn);       /* 原始 ldar (语义完全保留) */
    if (rt == 16)
        put32(&p, mov_x(17, 16));   /* 保存 ldar 结果 (x16 即将被覆盖) */
    else
        put32(&p, INSN_NOP);
    put32(&p, ldr_lit(16, 8));  /* ldr x16,[pc,#8] */
    put32(&p, INSN_BR_X16);
    put64(&p, block_abs + 0x1C);    /* 记录入口 5 指令, 代码在 +0x1C */
    /* p == out + 0x1C (sub) */

    /* 入口 br 过来时 x16 = 代码地址 (block+0x1C); 数据区偏移按块基算,
       先减回去 */
    put32(&p, 0xD1007210U);     /* sub x16, x16, #0x1c (入口 5 指令) */
    emit_save(&p);

    /* 值 → x13 */
    if (rt == 13) {
        /* 已在 x13 */
    } else if (rt == 16) {
        put32(&p, mov_x(13, 17));   /* 入口已把值移到 x17 */
    } else if (rt == 12) {
        put32(&p, mov_x(13, 12));   /* 先保存值, 地址拷贝会覆盖 x12 */
    } else {
        put32(&p, mov_x(13, rt));
    }
    /* 地址 → x12 */
    if (rn == 12) {
        /* 已在 x12 */
    } else if (rn == 13) {
        put32(&p, mov_x(12, 13));
    } else if (rn == 31) {
        put32(&p, add_x(12, 31, A64_ATOM_SAVE_SIZE));
    } else if (rn == 16) {
        put32(&p, ldr_x_imm(31, 12, 256));  /* 入口已覆盖 x16, 从栈取回 */
    } else if (rn == 17) {
        put32(&p, ldr_x_imm(31, 12, 264));
    } else {
        put32(&p, mov_x(12, rn));
    }

    /* TLS 过滤: 非目标线程只执行原始 ldar, 不记录 */
    put32(&p, INSN_MRS_X14_TPIDR);
    put32(&p, ldr_x16_imm(15, REC_TLS_OFF));
    put32(&p, cmp_x(14, 15));
    uint8_t *tls_bne = p;
    put32(&p, bcond(0, 1));     /* b.ne done (占位, 尾部回填) */

    /* 序号 = ++state.ordinal */
    put32(&p, ldr_x16_imm(17, REC_STATE_ABS_OFF));  /* x17 = state_abs */
    put32(&p, ldr_x_imm(17, 19, 0));                /* ordinal */
    put32(&p, add_x(19, 19, 1));
    put32(&p, str_x_imm(17, 19, 0));

    /* 值/地址变化才追加事件 (游程压缩) */
    put32(&p, ldr_x_imm(17, 20, 8));    /* last_val */
    put32(&p, ldr_x_imm(17, 21, 16));   /* last_addr */
    put32(&p, cmp_x(20, 13));
    put32(&p, ccmp_eq(21, 12));
    uint8_t *same_b = p;
    put32(&p, bcond(0, 0));     /* b.eq done (占位) */
    put32(&p, str_x_imm(17, 13, 8));    /* last_val = value */
    put32(&p, str_x_imm(17, 12, 16));   /* last_addr = addr */

    /* 追加事件 {site_id, ordinal, addr, value} */
    put32(&p, ldr_x16_imm(18, REC_EVENT_PTR_ADDR_OFF)); /* &hdr.event_ptr */
    put32(&p, ldr_x_imm(18, 21, 0));    /* event_ptr */
    put32(&p, add_x(22, 21, A64_ATB_EVENT_SIZE));
    put32(&p, ldr_x16_imm(23, REC_EVENTS_END_ADDR_OFF)); /* &hdr.events_end */
    put32(&p, ldr_x_imm(23, 23, 0));    /* events_end */
    put32(&p, cmp_x(22, 23));
    uint8_t *ovf_b = p;
    put32(&p, bcond(0, 8));     /* b.hi overflow (占位) */
    put32(&p, ldr_x16_imm(20, REC_SITE_ID_OFF));
    put32(&p, str_x_imm(21, 20, 0));    /* [event+0] = site_id */
    put32(&p, str_x_imm(21, 19, 8));    /* [event+8] = ordinal */
    put32(&p, str_x_imm(21, 12, 16));   /* [event+16] = addr */
    put32(&p, str_x_imm(21, 13, 24));   /* [event+24] = value */
    put32(&p, str_x_imm(18, 22, 0));    /* hdr.event_ptr = event+32 */
    uint8_t *skip_b = p;
    put32(&p, 0x14000000U);     /* b done (占位, 无条件) */
    put32(&p, ldr_x16_imm(20, REC_OVERFLOW_ADDR_OFF)); /* &hdr.overflow */
    put32(&p, movz_x(21, 1, 0));
    put32(&p, str_x_imm(20, 21, 0));    /* hdr.overflow = 1 */

    /* done: 把 ldar 的加载值写回 Rt 的保存槽 (ldar 语义: Rt = 加载值;
       保存区是 ldar 执行前的快照; 所有提前跳转路径都经过这里),
       然后恢复现场 + 跳回站点下一条 */
    {
        int rt_off = a64_atom_reg_save_off(rt);
        if (rt_off < 0)
            return 0;
        uint8_t *done = p;
        put32(&p, str_x_imm(31, 13, (unsigned)rt_off));
        emit_restore(&p);

        /* 回填条件分支 */
        int32_t d1 = (int32_t)(done - tls_bne);
        int32_t d2 = (int32_t)(done - same_b);
        int32_t d3 = (int32_t)((skip_b + 4) - ovf_b);
        uint32_t w4 = a64_encode_b(block_abs + (uint64_t)(skip_b - out),
                                   block_abs + (uint64_t)(done - out));
        uint32_t w;
        w = bcond(d1, 1);   memcpy(tls_bne, &w, 4);
        w = bcond(d2, 0);   memcpy(same_b, &w, 4);
        w = bcond(d3, 8);   memcpy(ovf_b, &w, 4);
        memcpy(skip_b, &w4, 4);
    }
    uint64_t b_off = (uint64_t)(p - out);
    put32(&p, a64_encode_b(block_abs + b_off, ret_addr));

    /* 路径指令数: 代码区 = 稳态 + 追加路径(14) + 溢出路径(3);
       追加/溢出只在不稳态执行。跳过路径不做 ordinal(3)+compare(5),
       但 value/addr 拷贝在 TLS 检查之前, 两路径都有。 */
    if (counts) {
        size_t code_n = (size_t)(p - out) / 4;
        unsigned steady = (unsigned)code_n - 14 - 3;
        counts->base = steady + 1;          /* +1 = 站点处 b */
        counts->append = 14;
        counts->skip = steady - 8 + 1;
    }

    /* 数据区 */
    uint64_t v = tls;           memcpy(out + REC_TLS_OFF, &v, 8);
    v = site_id;                memcpy(out + REC_SITE_ID_OFF, &v, 8);
    v = state_abs;              memcpy(out + REC_STATE_ABS_OFF, &v, 8);
    v = event_ptr_addr;         memcpy(out + REC_EVENT_PTR_ADDR_OFF, &v, 8);
    v = events_end_addr;        memcpy(out + REC_EVENTS_END_ADDR_OFF, &v, 8);
    v = overflow_addr;          memcpy(out + REC_OVERFLOW_ADDR_OFF, &v, 8);
    v = ret_addr;               memcpy(out + REC_RET_ADDR_OFF, &v, 8);

    return A64_ATOM_BLOCK_SIZE;
}

/* ---- 回放跳板 ---- */
#define REP_ORD_OFF   0x200
#define REP_CURSOR_OFF 0x208
#define REP_RUNS_ABS_OFF 0x210
#define REP_NRUNS_OFF 0x218
#define REP_LOAD_LIMIT_OFF 0x220
#define REP_EXIT_ABS_OFF 0x228

size_t a64_atomic_replay_block(uint8_t *out, uint64_t block_abs,
                               uint64_t runs_abs, uint64_t n_runs,
                               int size, unsigned rt, unsigned rn,
                               uint64_t ret_addr,
                               uint64_t load_limit, uint64_t exit_abs)
{
    uint8_t *p = out;
    int rt_off = a64_atom_reg_save_off(rt);
    if (rt_off < 0 || rt == 31)
        return 0;
    int rn_off = rn == 31 ? -1 : a64_atom_reg_save_off(rn);
    if (rn != 31 && rn_off < 0)
        return 0;

    memset(out, 0, A64_ATOM_BLOCK_SIZE);

    /* 入口 (5 指令 + 8B 字面量 = 0x1C 字节) */
    put32(&p, 0xA9BF47F0U);     /* stp x16,x17 */
    put32(&p, INSN_NOP);
    put32(&p, ldr_lit(16, 8));
    put32(&p, INSN_BR_X16);
    put64(&p, block_abs + 0x18);    /* 回放入口 4 指令, 代码在 +0x18 */
    /* p == out + 0x18 (sub) */

    put32(&p, 0xD1006210U);     /* sub x16, x16, #0x18 (入口 4 指令) */
    emit_save(&p);

    /* 序号 = ++ordinal */
    put32(&p, ldr_x16_imm(19, REP_ORD_OFF));
    put32(&p, add_x(19, 19, 1));
    put32(&p, str_x16_imm(19, REP_ORD_OFF));
    /* 窗口负载上限: 序号超过窗口内该站点负载预算 → 直接退出。
       窗口结束在自旋里时, 忙循环的退出计数器永远到不了, 必须由
       回放跳板兜底 exit (exit_abs=0 时禁用, 独立自测用)。 */
    uint8_t *lim_b = NULL;
    if (exit_abs) {
        put32(&p, ldr_x16_imm(17, REP_LOAD_LIMIT_OFF));
        put32(&p, cmp_x(19, 17));
        lim_b = p;
        put32(&p, bcond(0, 8));     /* b.hi limit_exit (占位) */
    }

    /* 游标推进: while (cursor+1 < n_runs &&
     *          runs[cursor+1].start <= ordinal) cursor++; */
    put32(&p, ldr_x16_imm(20, REP_CURSOR_OFF));
    put32(&p, ldr_x16_imm(21, REP_NRUNS_OFF));
    put32(&p, ldr_x16_imm(22, REP_RUNS_ABS_OFF));
    uint8_t *loop_top = p;
    put32(&p, add_x(23, 20, 1));
    put32(&p, cmp_x(23, 21));
    uint8_t *hs_b = p;
    put32(&p, bcond(0, 2));     /* b.hs have_run (占位) */
    put32(&p, movz_x(24, 24, 0));       /* x24 = 24 (运行段条目大小) */
    put32(&p, mul_x(24, 23, 24));       /* x24 = (cursor+1)*24 */
    put32(&p, add_xr(24, 24, 22));      /* next run base */
    put32(&p, ldr_x_imm(24, 25, 0));    /* next.start */
    put32(&p, cmp_x(25, 19));
    uint8_t *hi_b = p;
    put32(&p, bcond(0, 8));     /* b.hi have_run (占位) */
    put32(&p, mov_x(20, 23));
    put32(&p, bcond((int32_t)(loop_top - p), 14)); /* b.al loop */
    uint8_t *have = p;
    put32(&p, str_x16_imm(20, REP_CURSOR_OFF));
    /* 当前运行段基址 */
    put32(&p, movz_x(24, 24, 0));
    put32(&p, mul_x(24, 20, 24));       /* cursor*24 */
    put32(&p, add_xr(24, 24, 22));
    put32(&p, ldr_x_imm(24, 25, 0));    /* run.start */
    put32(&p, cmp_x(25, 19));
    uint8_t *lo_b = p;
    put32(&p, bcond(0, 8));     /* b.hi use_real: run.start > ordinal
                                   才回退真实读; 游标已定位的运行段
                                   值持续到下一个事件 (曾用 b.lo,
                                   序号越过运行段起点后误回退真实值) */
    /* 地址校验: 实际地址 == 运行段地址? */
    if (rn == 31)
        put32(&p, add_x(27, 31, A64_ATOM_SAVE_SIZE));
    else
        put32(&p, ldr_x_imm(31, 27, (unsigned)rn_off));
    put32(&p, ldr_x_imm(24, 28, 8));    /* run.addr */
    put32(&p, cmp_x(27, 28));
    uint8_t *ne_b = p;
    put32(&p, bcond(0, 1));     /* b.ne use_real (占位) */
    put32(&p, ldr_x_imm(24, 23, 16));   /* run.value */
    /* 真实 acquire 屏障: 对原地址执行 ldar (值丢弃), 保证排序语义 */
    put32(&p, a64_ldar_insn(size, 27, 29));
    uint8_t *set_jmp = p;
    put32(&p, 0x14000000U);     /* b set (占位, 无条件) */
    uint8_t *use_real = p;
    if (rn == 31)
        put32(&p, add_x(27, 31, A64_ATOM_SAVE_SIZE));
    else
        put32(&p, ldr_x_imm(31, 27, (unsigned)rn_off));
    put32(&p, a64_ldar_insn(size, 27, 13));
    put32(&p, mov_x(23, 13));           /* 真实值 → x23 (set 统一写槽) */
    uint8_t *set = p;
    /* 把最终值写入 Rt 的保存槽 (恢复时弹出) */
    put32(&p, str_x_imm(31, 23, (unsigned)rt_off));
    emit_restore(&p);
    uint64_t b_off = (uint64_t)(p - out);
    put32(&p, a64_encode_b(block_abs + b_off, ret_addr));
    uint8_t *limit_exit = NULL;
    if (exit_abs) {
        limit_exit = p;
        put32(&p, ldr_x16_imm(16, REP_EXIT_ABS_OFF));
        put32(&p, INSN_BR_X16);
    }

    /* 回填 */
    {
        int32_t d1 = (int32_t)(have - hs_b);
        int32_t d2 = (int32_t)(have - hi_b);
        int32_t d3 = (int32_t)(use_real - lo_b);
        int32_t d4 = (int32_t)(use_real - ne_b);
        uint32_t w5 = a64_encode_b(block_abs + (uint64_t)(set_jmp - out),
                                   block_abs + (uint64_t)(set - out));
        uint32_t w;
        w = bcond(d1, 2);   memcpy(hs_b, &w, 4);
        w = bcond(d2, 8);   memcpy(hi_b, &w, 4);
        w = bcond(d3, 8);   memcpy(lo_b, &w, 4);
        w = bcond(d4, 1);   memcpy(ne_b, &w, 4);
        memcpy(set_jmp, &w5, 4);
        if (lim_b) {
            uint32_t w6 = bcond((int32_t)(limit_exit - lim_b), 8);
            memcpy(lim_b, &w6, 4);
        }
    }

    {
        uint64_t v = 0;         memcpy(out + REP_ORD_OFF, &v, 8);
        v = 0;                  memcpy(out + REP_CURSOR_OFF, &v, 8);
        v = runs_abs;           memcpy(out + REP_RUNS_ABS_OFF, &v, 8);
        v = n_runs;             memcpy(out + REP_NRUNS_OFF, &v, 8);
        v = load_limit;         memcpy(out + REP_LOAD_LIMIT_OFF, &v, 8);
        v = exit_abs;           memcpy(out + REP_EXIT_ABS_OFF, &v, 8);
    }

    return A64_ATOM_BLOCK_SIZE;
}
