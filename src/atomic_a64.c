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

/* ---- 逐站点最小保存集 ----
 * 跳板只保存自己会破坏的寄存器: 基础 scratch 集 + 站点 Rt/Rn (保证
 * 加载值经槽写回、地址经槽取回, rt==rn 时地址仍可恢复)。保存/恢复
 * 指令数从 35 降到 ~11-15, 栈流量从 272B 降到 ~112-144B。
 */
struct save_plan {
    uint32_t stp[16];
    uint32_t ldp[16];
    int off[32];                /* reg → 最终 sp 偏移; -1 = 未保存 */
    int n_pairs;
    int save_size;              /* 含 flags 的总字节 */
};

static uint32_t stp_pre_64(unsigned rt1, unsigned rt2, unsigned rn)
{
    return 0xA9800000U | (0x7EU << 15) | (rt2 << 10) | (rn << 5) | rt1;
}
static uint32_t ldp_post_64(unsigned rt1, unsigned rt2, unsigned rn)
{
    return 0xA8C00000U | (0x02U << 15) | (rt2 << 10) | (rn << 5) | rt1;
}

static void plan_save(struct save_plan *pl, const unsigned *base,
                      size_t n_base, unsigned rt, unsigned rn)
{
    unsigned regs[32];
    size_t n = 0;
    memset(pl, 0, sizeof(*pl));
    for (int i = 0; i < 32; i++)
        pl->off[i] = -1;
    for (size_t i = 0; i < n_base; i++) {
        unsigned r = base[i];
        int dup = 0;
        for (size_t j = 0; j < n; j++)
            if (regs[j] == r)
                dup = 1;
        if (!dup && r < 31)
            regs[n++] = r;
    }
    if (rt < 31) {
        int dup = 0;
        for (size_t j = 0; j < n; j++)
            if (regs[j] == rt)
                dup = 1;
        if (!dup)
            regs[n++] = rt;
    }
    if (rn < 31) {
        int dup = 0;
        for (size_t j = 0; j < n; j++)
            if (regs[j] == rn)
                dup = 1;
        if (!dup)
            regs[n++] = rn;
    }
    /* 升序 */
    for (size_t i = 1; i < n; i++)
        for (size_t j = i; j > 0 && regs[j - 1] > regs[j]; j--) {
            unsigned t = regs[j - 1];
            regs[j - 1] = regs[j];
            regs[j] = t;
        }
    /* 入口 (16,17) 最先推 (最高地址); 其余两两成对, 单数补 xzr */
    unsigned rest[32];
    size_t nr = 0;
    int has16 = 0, has17 = 0;
    for (size_t i = 0; i < n; i++) {
        if (regs[i] == 16 && !has16) { has16 = 1; continue; }
        if (regs[i] == 17 && !has17) { has17 = 1; continue; }
        rest[nr++] = regs[i];
    }
    if (nr & 1)
        rest[nr++] = 31;        /* xzr 占位 */
    pl->n_pairs = (int)(nr / 2);        /* 仅体内对; 入口对由入口代码推入 */
    pl->save_size = (pl->n_pairs + 2) * 16;   /* 入口对 + 体内对 + flags */
    /* 入口对占据 [save_size-16, save_size); 体内对 b 占据
       [save_size-(b+2)*16, save_size-(b+1)*16) */
    pl->off[16] = pl->save_size - 16;
    pl->off[17] = pl->save_size - 8;
    size_t k = 0;
    for (size_t i = 0; i + 1 < nr; i += 2, k++) {
        unsigned a = rest[i], b = rest[i + 1];
        pl->stp[k] = stp_pre_64(a, b, 31);
        pl->off[a] = pl->save_size - (int)(k + 2) * 16;
        pl->off[b] = pl->off[a] + 8;
    }
    for (int i = 0; i < pl->n_pairs; i++) {
        uint32_t w = pl->stp[pl->n_pairs - 1 - i];
        unsigned rt2 = (w >> 10) & 0x1F, rt1 = w & 0x1F;
        pl->ldp[i] = ldp_post_64(rt1, rt2, 31);
    }
}

static void emit_plan_save(uint8_t **p, const struct save_plan *pl)
{
    for (int i = 0; i < pl->n_pairs; i++)
        put32(p, pl->stp[i]);
    put32(p, INSN_MRS_X15_NZCV);
    put32(p, stp_flags);
}

static void emit_plan_restore(uint8_t **p, const struct save_plan *pl)
{
    put32(p, ldp_flags);
    put32(p, INSN_MSR_NZCV_X15);
    for (int i = 0; i < pl->n_pairs; i++)
        put32(p, pl->ldp[i]);
    put32(p, 0xA8C147F0U);      /* ldp x16,x17,[sp],#16 (入口对) */
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

/* 检测 ldar/ldarb/ldarh 或 ldaxr/ldaxrb/ldaxrh (读-获取/排他读)。
 * ldaxr 需与后续真实 stlxr/stxr 配对: 回放跳板必须执行真实 ldaxr
 * 设置排他监视器, 否则切片里的 stlxr 永远失败 → 自旋死循环。
 * *exclusive 输出 1 表示 ldaxr 族。 */
int a64_is_ldar_any(uint32_t w, int *size, unsigned *rt, unsigned *rn,
                    int *exclusive)
{
    uint32_t base = w & 0xBFDFFC00U;
    int ex = 0;
    if (base == 0x08DFFC00U || base == 0x88DFFC00U) {
        /* ldar 族 */
    } else if (base == 0x085FFC00U || base == 0x885FFC00U) {
        ex = 1;                 /* ldaxr 族 */
    } else {
        return 0;
    }
    if (exclusive)
        *exclusive = ex;
    if (base == 0x08DFFC00U || base == 0x085FFC00U)
        *size = (w & 0x40000000U) ? 2 : 1;      /* h / b */
    else
        *size = (w & 0x40000000U) ? 8 : 4;      /* x / w */
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

/* 按加载宽度生成 ldaxr/ldaxrb/ldaxrh (回放屏障 + 排他监视器) */
static uint32_t a64_ldaxr_insn(int size, unsigned rn, unsigned rt)
{
    uint32_t base = size == 1 ? 0x085FFC00U :
                    size == 2 ? 0x485FFC00U :
                    size == 4 ? 0x885FFC00U : 0xC85FFC00U;
    return base | (rn << 5) | rt;
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
    int exclusive;
    if (!a64_is_ldar_any(orig_insn, &size, &rt, &rn, &exclusive))
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
    unsigned base_rec[] = {12, 13, 14, 15, 16, 17, 18, 19,
                           20, 21, 22, 23};
    struct save_plan pl;
    plan_save(&pl, base_rec, sizeof(base_rec) / sizeof(base_rec[0]),
              rt, rn);
    emit_plan_save(&p, &pl);

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
    /* 地址 → x12 (逐站点保存计划: rn 必在保存槽内, rt==rn 时地址
       也能从槽恢复) */
    if (rn == 31)
        put32(&p, add_x(12, 31, (unsigned)pl.save_size));
    else
        put32(&p, ldr_x_imm(31, 12, (unsigned)pl.off[rn]));

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
        int rt_off = pl.off[rt];
        if (rt_off < 0)
            return 0;
        uint8_t *done = p;
        put32(&p, str_x_imm(31, 13, (unsigned)rt_off));
        emit_plan_restore(&p, &pl);

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
                               uint64_t load_limit, uint64_t exit_abs,
                               int exclusive)
{
    uint8_t *p = out;
    unsigned base_rep[] = {16, 17, 18, 19, 20, 21, 22, 23,
                           24, 25, 26, 27, 28, 29};
    struct save_plan pl;
    plan_save(&pl, base_rep, sizeof(base_rep) / sizeof(base_rep[0]),
              rt, rn);
    int rt_off = pl.off[rt];
    if (rt_off < 0 || rt == 31)
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
    emit_plan_save(&p, &pl);

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
        put32(&p, add_x(27, 31, (unsigned)pl.save_size));
    else
        put32(&p, ldr_x_imm(31, 27, (unsigned)pl.off[rn]));
    put32(&p, ldr_x_imm(24, 28, 8));    /* run.addr */
    put32(&p, cmp_x(27, 28));
    uint8_t *ne_b = p;
    put32(&p, bcond(0, 1));     /* b.ne use_real (占位) */
    put32(&p, ldr_x_imm(24, 23, 16));   /* run.value */
    /* 真实 acquire 屏障: 对原地址执行 ldar/ldaxr (值丢弃), 保证排序
       语义; ldaxr 额外设置排他监视器, 使后续真实 stlxr/stxr 成功
       (否则切片里的锁获取自旋永远失败) */
    put32(&p, exclusive ? a64_ldaxr_insn(size, 27, 29)
                        : a64_ldar_insn(size, 27, 29));
    uint8_t *set_jmp = p;
    put32(&p, 0x14000000U);     /* b set (占位, 无条件) */
    uint8_t *use_real = p;
    if (rn == 31)
        put32(&p, add_x(27, 31, (unsigned)pl.save_size));
    else
        put32(&p, ldr_x_imm(31, 27, (unsigned)pl.off[rn]));
    /* 真实值: 用保存集内的 x29 做加载 (x13 不在最小保存集, 不能破坏) */
    put32(&p, exclusive ? a64_ldaxr_insn(size, 27, 29)
                        : a64_ldar_insn(size, 27, 29));
    put32(&p, mov_x(23, 29));           /* 真实值 → x23 (set 统一写槽) */
    uint8_t *set = p;
    /* 把最终值写入 Rt 的保存槽 (恢复时弹出) */
    put32(&p, str_x_imm(31, 23, (unsigned)rt_off));
    emit_plan_restore(&p, &pl);
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
