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
static uint32_t add_xr_lsl(unsigned rd, unsigned rn, unsigned rm,
                           unsigned shift)
{
    return 0x8B000000U | ((shift & 7) << 10) | (rm << 16) |
           (rn << 5) | rd;
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
static uint32_t movk_x(unsigned rd, unsigned imm16, unsigned hw)
{
    return 0xF2800000U | ((hw & 3) << 21) | ((imm16 & 0xffff) << 5) | rd;
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
static uint32_t sub_xr(unsigned rd, unsigned rn, unsigned rm)
{
    /* sub xd, xn, xm (shifted register, shift=0) */
    return 0xCB000000U | (rm << 16) | (rn << 5) | rd;
}
static uint32_t sub_x_imm(unsigned rd, unsigned rn, unsigned imm)
{
    return 0xD1000000U | ((imm & 0xfff) << 10) | (rn << 5) | rd;
}
static uint32_t cbnz_x(int32_t off, unsigned rt)
{
    /* cbnz xrt, #off (64 位计数器) */
    return 0xB5000000U | (((uint32_t)(off / 4) & 0x7FFFF) << 5) | rt;
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
                      size_t n_base, unsigned rt, unsigned rn,
                      unsigned rm)
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
    if (rm < 31) {
        int dup = 0;
        for (size_t j = 0; j < n; j++)
            if (regs[j] == rm)
                dup = 1;
        if (!dup)
            regs[n++] = rm;
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
    } else if (base == 0x085F7C00U || base == 0x885F7C00U) {
        ex = 1;                 /* ldxr 族 (无 acquire, 与 ldaxr 同
                                   回放路径: 屏障用 ldaxr 更严格,
                                   语义无害) */
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

/* 通用 load 检测: ldar 族 (kind=0), ldaxr 族 (kind=1, 需排他监视器),
 * 普通 ldr w/x 立即数偏移 (kind=2, 多线程自旋标志位场景)。
 * 普通 ldr 只在这里做候选判定, 是否真是自旋站点由扫描器的
 * "load 值直接决定回边" 模式确认 (见 atomic_scan)。 */
int a64_is_load_any(uint32_t w, int *size, unsigned *rt, unsigned *rn,
                    int *kind)
{
    int ex = 0;
    uint32_t base = w & 0xBFDFFC00U;
    if (base == 0x08DFFC00U || base == 0x88DFFC00U) {
        /* ldar 族 */
    } else if (base == 0x085FFC00U || base == 0x885FFC00U) {
        ex = 1;                 /* ldaxr 族 */
    } else if (base == 0x085F7C00U || base == 0x885F7C00U) {
        ex = 1;                 /* ldxr 族 (无 acquire) */
    } else {
        uint32_t lbase = w & 0xFFC00000U;
        if (lbase == 0xB9400000U || lbase == 0xF9400000U) {
            /* 普通 ldr w/x, [xN, #imm] (自旋候选) */
            if (kind)
                *kind = 2;
            *size = lbase == 0xF9400000U ? 8 : 4;
            *rt = w & 0x1FU;
            *rn = (w >> 5) & 0x1FU;
            return 1;
        }
        return 0;
    }
    if (kind)
        *kind = ex;
    if (base == 0x08DFFC00U || base == 0x085FFC00U)
        *size = (w & 0x40000000U) ? 2 : 1;      /* h / b */
    else
        *size = (w & 0x40000000U) ? 8 : 4;      /* x / w */
    *rt = w & 0x1FU;
    *rn = (w >> 5) & 0x1FU;
    return 1;
}

/* 普通 ldr w/x: 立即数偏移 (kind=2) 或寄存器偏移 LSL (kind=3) */
int a64_is_plain_load(uint32_t w, int *size, unsigned *rt, unsigned *rn,
                      int *kind, struct a64_ld_addr *ad)
{
    /* 立即数形式: 按编码基区分 ldr w/x, ldrb, ldrh, ldrsw, ldrsb, ldrsh */
    static const struct {
        uint32_t base;          /* & 0xFFC00000 */
        int ldr_kind;
        int s;                  /* 加载宽度 */
        int shift;              /* imm 缩放 */
    } imm_forms[] = {
        {0xF9400000U, 0, 8, 3},
        {0xB9400000U, 0, 4, 2},
        {0x39400000U, 1, 1, 0},
        {0x79400000U, 2, 2, 1},
        {0xB9800000U, 3, 8, 2},
        {0x39C00000U, 4, 1, 0},   /* ldrsb w (零扩展进 w) */
        {0x79C00000U, 5, 2, 1},   /* ldrsh w */
    };
    for (size_t i = 0; i < sizeof(imm_forms) / sizeof(imm_forms[0]); i++) {
        if ((w & 0xFFC00000U) == imm_forms[i].base) {
            if (size) *size = imm_forms[i].s;
            if (rt) *rt = w & 0x1FU;
            if (rn) *rn = (w >> 5) & 0x1FU;
            if (kind) *kind = 2;
            if (ad) {
                ad->mode = 0;
                ad->rn = (w >> 5) & 0x1FU;
                ad->rm = 0;
                ad->imm = (int64_t)((w >> 10) & 0xFFFU) <<
                          imm_forms[i].shift;
                ad->shift = 0;
                ad->ldr_kind = imm_forms[i].ldr_kind;
            }
            return 1;
        }
    }
    /* 寄存器偏移 (option=011 LSL): ldr/ldrb/ldrh/ldrsb/ldrsh/ldrsw */
    static const struct {
        uint32_t base;          /* & 0xFFE0E000 */
        int ldr_kind;
        int s;
        int shift;              /* S=1 时的移位 */
    } reg_forms[] = {
        {0xF8606000U, 0, 8, 3},
        {0xB8606000U, 0, 4, 2},
        {0x38606000U, 1, 1, 0},
        {0x78606000U, 2, 2, 1},
        {0xB8A06000U, 3, 8, 2},
        {0x38E06000U, 4, 1, 0},
        {0x78E06000U, 5, 2, 1},
        /* SXTW (option=110): free_list 等按索引取指针
           (S 位在掩码外, shift 由 S 位决定) */
        {0xF860C000U, 0, 8, 3},
        {0xB860C000U, 0, 4, 2},
        {0xB8A0C000U, 3, 8, 2},
    };
    for (size_t i = 0; i < sizeof(reg_forms) / sizeof(reg_forms[0]); i++) {
        if ((w & 0xFFE0E000U) == reg_forms[i].base) {
            if (size) *size = reg_forms[i].s;
            if (rt) *rt = w & 0x1FU;
            if (rn) *rn = (w >> 5) & 0x1FU;
            if (kind) *kind = 3;
            if (ad) {
                ad->mode = 1;
                ad->rn = (w >> 5) & 0x1FU;
                ad->rm = (w >> 16) & 0x1FU;
                ad->imm = 0;
                ad->shift = (w & 0x1000U) ? reg_forms[i].shift : 0;
                ad->ldr_kind = reg_forms[i].ldr_kind;
            }
            return 1;
        }
    }
    return 0;
}

/* stxr/stlxr 族编码 (ARM ARM):
 *   size 00=stxrb/stlxrb, 01=stxrh/stlxrh, 10=stxr w/stlxr w,
 *        11=stxr x/stlxr x
 *   [31:26] = 000010 (0x08 after masking bits 31-26)
 *   [15:12] = 0111 (stxr) 或 1111 (stlxr, bit15=release)
 *   [23:21] = 000? (独占标志)
 */
int a64_is_excl_store(uint32_t w, int *size, unsigned *rs,
                      unsigned *rn, unsigned *rt, int *acquire)
{
    uint32_t m = w & 0x3F00FC00U;
    if (m != 0x0800FC00U && m != 0x08007C00U)
        return 0;
    /* bits[22:21] 判别: stxr/stlxr=00; ldxr/ldar=10 (load);
       LSE CAS (cas/casa/casl/casal) = 01/11 (bit21=1) */
    if (((w >> 21) & 3U) != 0)
        return 0;
    if (size)
        *size = (int)((w >> 30) & 3U);
    if (rs)
        *rs = (w >> 16) & 0x1FU;
    if (rn)
        *rn = (w >> 5) & 0x1FU;
    if (rt)
        *rt = w & 0x1FU;
    if (acquire)
        *acquire = (m == 0x0800FC00U) ? 1 : 0;
    return 1;
}

int a64_is_excl_load(uint32_t w, int *size, unsigned *rt,
                     unsigned *rn, int *acquire)
{
    uint32_t m = w & 0x3F00FC00U;   /* 含 bit15: LDXR(0)/LDAXR(1) 可辨 */
    if (m != 0x0800FC00U && m != 0x08007C00U)
        return 0;
    if (!((w >> 22) & 1U))
        return 0;               /* stxr/stlxr (store) */
    if ((w >> 21) & 1U)
        return 0;               /* bit21=1: LSE CAS 族, 不是排他 load */
    if (size)
        *size = (int)((w >> 30) & 3U);
    if (rt)
        *rt = w & 0x1FU;
    if (rn)
        *rn = (w >> 5) & 0x1FU;
    if (acquire)
        *acquire = (m == 0x0800FC00U) ? 1 : 0;
    return 1;
}

int a64_is_lse_cas(uint32_t w, unsigned *rs, unsigned *rt,
                   unsigned *rn)
{
    if ((w & 0x3FA07C00U) != 0x08A07C00U)
        return 0;
    if (((w >> 30) & 3U) < 2)
        return 0;               /* CASB/CASH (size 00/01): 不支持, 原生 */
    if (rs)
        *rs = (w >> 16) & 0x1FU;
    if (rt)
        *rt = w & 0x1FU;
    if (rn)
        *rn = (w >> 5) & 0x1FU;
    return 1;
}

uint32_t a64_excl_store_to_str(int size, unsigned rn, unsigned rt)
{
    static const uint32_t bases[4] = {
        0x39000000U,    /* strb */
        0x79000000U,    /* strh */
        0xB9000000U,    /* str w */
        0xF9000000U,    /* str x */
    };
    return bases[size & 3] | (rn << 5) | rt;
}

size_t a64_excl_store_trampoline(uint8_t *out, uint64_t block_abs,
                                 uint32_t insn, uint64_t ret_addr)
{
    int size;
    unsigned rs, rn, rt;
    int acq;
    if (!a64_is_excl_store(insn, &size, &rs, &rn, &rt, &acq))
        return 0;
    memset(out, 0, 0x20);
    uint8_t *p = out;
    put32(&p, 0xA9BF47F0U);            /* stp x16,x17,[sp,#-16]! */
    put32(&p, a64_excl_store_to_str(size, rn, rt));
    put32(&p, rs < 31 ? (0x52800000U | (rs << 5)) : INSN_NOP);
    put32(&p, 0xA8C147F0U);            /* ldp x16,x17,[sp],#16 */
    uint64_t b_off = (uint64_t)(p - out);
    put32(&p, a64_encode_b(block_abs + b_off, ret_addr));
    return 0x20;
}

/* LSE CAS 强制成功跳板: 无条件 str <Rt>,[<Rn>], Rs 保持期望值不动
 * (CAS 成功时 Rs 返回旧值 == 期望值, 调用方看到"成功")。 */
size_t a64_lse_cas_trampoline(uint8_t *out, uint64_t block_abs,
                              uint32_t insn, uint64_t ret_addr)
{
    unsigned rs, rt, rn;
    if (!a64_is_lse_cas(insn, &rs, &rt, &rn))
        return 0;
    int size = (int)((insn >> 30) & 3U);
    uint32_t str_insn = a64_excl_store_to_str(size, rn, rt);
    memset(out, 0, 0x20);
    uint8_t *p = out;
    /* 与 stlxr 强制成功跳板同构: 无条件 str + 保持 Rs (期望值)。
       ret_addr 与跳板同段 (±128MB), 直接用 b, 无需字面量。 */
    put32(&p, 0xA9BF47F0U);         /* stp x16,x17,[sp,#-16]! */
    put32(&p, str_insn);            /* str <Rt>,[<Rn>] */
    put32(&p, 0xA8C147F0U);         /* ldp x16,x17,[sp],#16 */
    uint64_t b_off = (uint64_t)(p - out);
    put32(&p, a64_encode_b(block_abs + b_off, ret_addr));
    (void)rs;
    return 0x20;
}

/* 按加载宽度生成 ldar/ldarb/ldarh 指令 (回放屏障用) */
static uint32_t a64_ldar_insn(int size, unsigned rn, unsigned rt)
{
    uint32_t base = size == 1 ? 0x08DFFC00U :
                    size == 2 ? 0x48DFFC00U :
                    size == 4 ? 0x88DFFC00U : 0xC8DFFC00U;
    return base | (rn << 5) | rt;
}

/* 按加载宽度生成普通 ldr 指令 (自旋回放屏障用, 无排他监视器) */
static uint32_t a64_ldr_insn(int size, unsigned rn, unsigned rt)
{
    uint32_t base = size == 1 ? 0x39400000U :
                    size == 2 ? 0x79400000U :
                    size == 4 ? 0xB9400000U : 0xF9400000U;
    return base | (rn << 5) | rt;
}

/* 按 ldr_kind 生成值加载指令 (记录/回放屏障共用) */
static uint32_t a64_ldval_insn(int ldr_kind, int size,
                               unsigned rn, unsigned rt)
{
    uint32_t base = ldr_kind == 1 ? 0x39400000U :
                    ldr_kind == 2 ? 0x79400000U :
                    ldr_kind == 3 ? 0xB9800000U :
                    ldr_kind == 4 ? 0x39C00000U :
                    ldr_kind == 5 ? 0x79C00000U :
                    (0xF9400000U);
    if (ldr_kind == 0)
        return a64_ldr_insn(size, rn, rt);
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
#define REC_RECORD_ALL_OFF    0x238   /* 诊断: 全量记录 (不游程压缩) */

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
    uint8_t *done = NULL;
    unsigned rt, rn;
    int size;
    int kind;
    if (!a64_is_load_any(orig_insn, &size, &rt, &rn, &kind))
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
              rt, rn, 31);
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
        done = p;
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

    /* 实际执行路径指令数 (从生成期标签统计, 不依赖 code_n):
       steady = [入口..b.eq] + [done..b ret], 减入口字面量 2 槽;
       skip   = [入口..TLS b.ne] + [done..b ret] (不做 ordinal+compare);
       追加路径实测 16 条 (last_* 更新 2 + 事件写入 12 + 跳 done 2)。 */
    if (counts) {
        size_t head = (size_t)(same_b - out) / 4 + 1 - 2;
        size_t tail = (size_t)(p - done) / 4;
        counts->base = (unsigned)(head + tail) + 1;  /* +1 = 站点处 b */
        counts->append = 16;
        counts->skip = (unsigned)((size_t)(tls_bne - out) / 4 + 1 - 2 +
                                  tail);
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

size_t a64_load_record_block(uint8_t *out, uint64_t block_abs,
                             const struct a64_ld_addr *ad, int size,
                             unsigned rt, uint64_t tls,
                             uint64_t site_id, uint64_t state_abs,
                             uint64_t event_ptr_addr,
                             uint64_t events_end_addr,
                             uint64_t overflow_addr,
                             uint64_t ret_addr,
                             struct a64_atom_counts *counts,
                             int record_all)
{
    uint8_t *p = out;
    uint8_t *done = NULL;
    unsigned rn;

    if (!ad || rt == 31)
        return 0;
    rn = ad->rn;
    if (ad->mode == 1 && ad->rm == rt && ad->rm == rn)
        return 0;               /* 地址完全依赖被破坏的 rt: 不支持 */

    memset(out, 0, A64_ATOM_BLOCK_SIZE);

    /* 入口 (4 指令 + 8B 字面量 = 0x18 字节, 代码从 0x18 开始) */
    put32(&p, 0xA9BF47F0U);     /* stp x16,x17,[sp,#-16]! */
    put32(&p, INSN_NOP);
    put32(&p, ldr_lit(16, 8));
    put32(&p, INSN_BR_X16);
    put64(&p, block_abs + 0x18);
    /* p == out + 0x18 */

    put32(&p, 0xD1006210U);     /* sub x16, x16, #0x18 */
    unsigned base_rec[] = {12, 13, 14, 15, 16, 17, 18, 19,
                           20, 21, 22, 23};
    struct save_plan pl;
    plan_save(&pl, base_rec, sizeof(base_rec) / sizeof(base_rec[0]),
              rt, rn, ad->mode == 1 ? ad->rm : 31);
    emit_plan_save(&p, &pl);

    /* 重建有效地址 → x12 */
    if (rn == 31)
        put32(&p, add_x(12, 31, (unsigned)pl.save_size));
    else
        put32(&p, ldr_x_imm(31, 12, (unsigned)pl.off[rn]));
    if (ad->mode == 0) {
        if (ad->imm != 0)
            put32(&p, add_x(12, 12, (unsigned)ad->imm));
    } else {
        if (ad->rm < 31)
            put32(&p, ldr_x_imm(31, 13, (unsigned)pl.off[ad->rm]));
        else
            put32(&p, movz_x(13, 0, 0));
        put32(&p, add_xr_lsl(12, 12, 13, (unsigned)ad->shift));
    }
    /* 执行原 load (值 → x13; 窄读零/符号扩展按 ldr_kind) */
    put32(&p, a64_ldval_insn(ad->ldr_kind, size, 12, 13));

    /* TLS 过滤: 非目标线程只执行原始 load, 不记录 */
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

    uint8_t *same_b = NULL;
    if (!record_all) {
        /* 值/地址变化才追加事件 (游程压缩) */
        put32(&p, ldr_x_imm(17, 20, 8));    /* last_val */
        put32(&p, ldr_x_imm(17, 21, 16));   /* last_addr */
        put32(&p, cmp_x(20, 13));
        put32(&p, ccmp_eq(21, 12));
        same_b = p;
        put32(&p, bcond(0, 0));     /* b.eq done (占位) */
    }
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
    if (record_all)
        put32(&p, str_x_imm(21, 30, 32));   /* [event+32] = caller */
    put32(&p, str_x_imm(18, 22, 0));    /* hdr.event_ptr = event+32 */
    uint8_t *skip_b = p;
    put32(&p, 0x14000000U);     /* b done (占位, 无条件) */
    put32(&p, ldr_x16_imm(20, REC_OVERFLOW_ADDR_OFF)); /* &hdr.overflow */
    put32(&p, movz_x(21, 1, 0));
    put32(&p, str_x_imm(20, 21, 0));    /* hdr.overflow = 1 */

    /* done: 把加载值写回 Rt 的保存槽, 恢复现场 + 跳回站点下一条 */
    {
        int rt_off = pl.off[rt];
        if (rt_off < 0)
            return 0;
        done = p;
        put32(&p, str_x_imm(31, 13, (unsigned)rt_off));
        emit_plan_restore(&p, &pl);

        /* 回填条件分支 */
        int32_t d1 = (int32_t)(done - tls_bne);
        int32_t d2 = same_b ? (int32_t)(done - same_b) : 0;
        int32_t d3 = (int32_t)((skip_b + 4) - ovf_b);
        uint32_t w4 = a64_encode_b(block_abs + (uint64_t)(skip_b - out),
                                   block_abs + (uint64_t)(done - out));
        uint32_t w;
        w = bcond(d1, 1);   memcpy(tls_bne, &w, 4);
        if (same_b) {
            w = bcond(d2, 0);
            memcpy(same_b, &w, 4);
        }
        w = bcond(d3, 8);   memcpy(ovf_b, &w, 4);
        memcpy(skip_b, &w4, 4);
    }
    uint64_t b_off = (uint64_t)(p - out);
    put32(&p, a64_encode_b(block_abs + b_off, ret_addr));

    /* 实际执行路径指令数 (同原子版口径):
       record_all 时每次访问都走追加路径, append 已含在 base 内。 */
    if (counts) {
        const uint8_t *h = same_b ? same_b : skip_b;
        size_t head = (size_t)(h - out) / 4 + 1 - 2;
        size_t tail = (size_t)(p - done) / 4;
        counts->base = (unsigned)(head + tail) + 1;  /* +1 = 站点处 b */
        counts->append = record_all ? 0 : 16;
        counts->skip = (unsigned)((size_t)(tls_bne - out) / 4 + 1 - 2 +
                                  tail);
    }

    /* 数据区 */
    uint64_t v = tls;           memcpy(out + REC_TLS_OFF, &v, 8);
    v = site_id;                memcpy(out + REC_SITE_ID_OFF, &v, 8);
    v = state_abs;              memcpy(out + REC_STATE_ABS_OFF, &v, 8);
    v = event_ptr_addr;         memcpy(out + REC_EVENT_PTR_ADDR_OFF, &v, 8);
    v = events_end_addr;        memcpy(out + REC_EVENTS_END_ADDR_OFF, &v, 8);
    v = overflow_addr;          memcpy(out + REC_OVERFLOW_ADDR_OFF, &v, 8);
    v = ret_addr;               memcpy(out + REC_RET_ADDR_OFF, &v, 8);
    v = record_all ? 1 : 0;     memcpy(out + REC_RECORD_ALL_OFF, &v, 8);

    return A64_ATOM_BLOCK_SIZE;
}

/* ---- LSE CAS 记录跳板 ----
 * 数据区 (0x200..0x278):
 *   tls, site_id, state_abs, cas_event_ptr_addr, cas_events_end_addr,
 *   cas_overflow_addr, ret_addr (0x200..0x238);
 *   last_old/last_addr/last_success/last_expected/last_desired
 *   (0x238..0x260, 游程压缩比较用)。
 * 事件 (56B): {site_id, ordinal, addr, old, success, expected, desired}。
 */
#define CASREC_TLS_OFF           0x200
#define CASREC_SITE_ID_OFF       0x208
#define CASREC_STATE_ABS_OFF     0x210
#define CASREC_EVENT_PTR_ADDR_OFF 0x218
#define CASREC_EVENTS_END_ADDR_OFF 0x220
#define CASREC_OVERFLOW_ADDR_OFF 0x228
#define CASREC_RET_ADDR_OFF      0x230
#define CASREC_LAST_OFF          0x238

size_t a64_cas_record_block(uint8_t *out, uint64_t block_abs,
                            uint32_t orig_insn, uint64_t tls,
                            uint64_t site_id, uint64_t state_abs,
                            uint64_t cas_event_ptr_addr,
                            uint64_t cas_events_end_addr,
                            uint64_t cas_overflow_addr,
                            uint64_t ret_addr,
                            struct a64_atom_counts *counts)
{
    unsigned rs, rt, rn;
    if (!a64_is_lse_cas(orig_insn, &rs, &rt, &rn))
        return 0;
    /* rs/rt/rn 占用 x16/x17 (块基址/入口暂存) 或 x31 (sp/xzr):
       不支持, 站点保持原指令 (采集原生执行, 切片无结局回放)。 */
    if (rs == 16 || rs == 17 || rs == 31 ||
        rt == 16 || rt == 17 || rt == 31 ||
        rn == 16 || rn == 17 || rn == 31)
        return 0;

    memset(out, 0, A64_ATOM_BLOCK_SIZE);
    uint8_t *p = out;
    uint8_t *done = NULL;

    /* 入口 (4 指令 + 8B 字面量 = 0x18 字节, 代码从 0x18 开始) */
    put32(&p, 0xA9BF47F0U);     /* stp x16,x17,[sp,#-16]! */
    put32(&p, INSN_NOP);
    put32(&p, ldr_lit(16, 8));
    put32(&p, INSN_BR_X16);
    put64(&p, block_abs + 0x18);
    /* p == out + 0x18 */

    put32(&p, 0xD1006210U);     /* sub x16, x16, #0x18 */
    unsigned base_rec[] = {12, 13, 14, 15, 16, 17, 18, 19,
                           20, 21, 22, 23, 24, 25};
    struct save_plan pl;
    plan_save(&pl, base_rec, sizeof(base_rec) / sizeof(base_rec[0]),
              rt, rn, rs);
    emit_plan_save(&p, &pl);

    /* 从保存槽重载 rs/rt/rn (plan_save 可能已破坏原寄存器) */
    put32(&p, ldr_x_imm(31, rs, (unsigned)pl.off[rs]));
    put32(&p, ldr_x_imm(31, rt, (unsigned)pl.off[rt]));
    put32(&p, ldr_x_imm(31, rn, (unsigned)pl.off[rn]));
    /* 执行原始 CAS (真实读改写, Rs 返回旧值) */
    put32(&p, orig_insn);
    /* old → x13, addr → x12 */
    if (rs != 13)
        put32(&p, mov_x(13, rs));
    if (rn != 12)
        put32(&p, mov_x(12, rn));

    /* TLS 过滤: 非目标线程只执行真实 CAS, 不记录 */
    put32(&p, INSN_MRS_X14_TPIDR);
    put32(&p, ldr_x16_imm(15, CASREC_TLS_OFF));
    put32(&p, cmp_x(14, 15));
    uint8_t *tls_bne = p;
    put32(&p, bcond(0, 1));     /* b.ne done (占位) */

    /* 序号 = ++state.ordinal */
    put32(&p, ldr_x16_imm(17, CASREC_STATE_ABS_OFF));
    put32(&p, ldr_x_imm(17, 19, 0));
    put32(&p, add_x(19, 19, 1));
    put32(&p, str_x_imm(17, 19, 0));

    /* success = (old == expected) → x21; expected → x20 (槽内旧值) */
    put32(&p, ldr_x_imm(31, 20, (unsigned)pl.off[rs]));
    put32(&p, cmp_x(13, 20));
    put32(&p, 0x9A9F17F5U);     /* cset x21, eq */
    /* desired → x22 */
    put32(&p, ldr_x_imm(31, 22, (unsigned)pl.off[rt]));

    /* 五元组游程压缩: (old,addr,success,expected,desired) 全同 → 不追加 */
    put32(&p, ldr_x16_imm(23, CASREC_LAST_OFF + 0));
    put32(&p, cmp_x(13, 23));
    put32(&p, ldr_x16_imm(23, CASREC_LAST_OFF + 8));
    put32(&p, ccmp_eq(12, 23));
    put32(&p, ldr_x16_imm(23, CASREC_LAST_OFF + 16));
    put32(&p, ccmp_eq(21, 23));
    put32(&p, ldr_x16_imm(23, CASREC_LAST_OFF + 24));
    put32(&p, ccmp_eq(20, 23));
    put32(&p, ldr_x16_imm(23, CASREC_LAST_OFF + 32));
    put32(&p, ccmp_eq(22, 23));
    uint8_t *same_b = p;
    put32(&p, bcond(0, 0));     /* b.eq done (占位) */
    put32(&p, str_x16_imm(13, CASREC_LAST_OFF + 0));
    put32(&p, str_x16_imm(12, CASREC_LAST_OFF + 8));
    put32(&p, str_x16_imm(21, CASREC_LAST_OFF + 16));
    put32(&p, str_x16_imm(20, CASREC_LAST_OFF + 24));
    put32(&p, str_x16_imm(22, CASREC_LAST_OFF + 32));

    /* 追加事件 {site_id, ordinal, addr, old, success, expected, desired} */
    put32(&p, ldr_x16_imm(18, CASREC_EVENT_PTR_ADDR_OFF));
    put32(&p, ldr_x_imm(18, 24, 0));    /* cas_event_ptr */
    put32(&p, add_x(25, 24, 56));
    put32(&p, ldr_x16_imm(23, CASREC_EVENTS_END_ADDR_OFF));
    put32(&p, ldr_x_imm(23, 23, 0));
    put32(&p, cmp_x(25, 23));
    uint8_t *ovf_b = p;
    put32(&p, bcond(0, 8));     /* b.hi overflow (占位) */
    put32(&p, ldr_x16_imm(20, CASREC_SITE_ID_OFF));
    put32(&p, str_x_imm(24, 20, 0));    /* site_id */
    put32(&p, str_x_imm(24, 19, 8));    /* ordinal */
    put32(&p, str_x_imm(24, 12, 16));   /* addr */
    put32(&p, str_x_imm(24, 13, 24));   /* old */
    put32(&p, str_x_imm(24, 21, 32));   /* success */
    put32(&p, ldr_x_imm(31, 20, (unsigned)pl.off[rs]));
    put32(&p, str_x_imm(24, 20, 40));   /* expected */
    put32(&p, str_x_imm(24, 22, 48));   /* desired */
    put32(&p, str_x_imm(18, 25, 0));    /* hdr.cas_event_ptr = event+56 */
    uint8_t *skip_b = p;
    put32(&p, 0x14000000U);     /* b done (占位) */
    put32(&p, ldr_x16_imm(20, CASREC_OVERFLOW_ADDR_OFF));
    put32(&p, movz_x(21, 1, 0));
    put32(&p, str_x_imm(20, 21, 0));

    /* done: CAS 结果 (old) 写回 Rs 保存槽, 恢复现场, 跳回站点下一条 */
    {
        int rs_off = pl.off[rs];
        if (rs_off < 0)
            return 0;
        done = p;
        put32(&p, str_x_imm(31, 13, (unsigned)rs_off));
        emit_plan_restore(&p, &pl);

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

    /* 实际执行路径指令数: steady = [入口..b.eq] + [done..b ret] 减
       入口字面量 2 槽; 追加路径实测 23 条 (五元组 last_* 5 + 事件
       写入 16 + 跳 done 2)。 */
    if (counts) {
        size_t head = (size_t)(same_b - out) / 4 + 1 - 2;
        size_t tail = (size_t)(p - done) / 4;
        counts->base = (unsigned)(head + tail) + 1;  /* +1 = 站点处 b */
        counts->append = 23;
        counts->skip = (unsigned)((size_t)(tls_bne - out) / 4 + 1 - 2 +
                                  tail);
    }

    uint64_t v = tls;           memcpy(out + CASREC_TLS_OFF, &v, 8);
    v = site_id;                memcpy(out + CASREC_SITE_ID_OFF, &v, 8);
    v = state_abs;              memcpy(out + CASREC_STATE_ABS_OFF, &v, 8);
    v = cas_event_ptr_addr;     memcpy(out + CASREC_EVENT_PTR_ADDR_OFF, &v, 8);
    v = cas_events_end_addr;    memcpy(out + CASREC_EVENTS_END_ADDR_OFF, &v, 8);
    v = cas_overflow_addr;      memcpy(out + CASREC_OVERFLOW_ADDR_OFF, &v, 8);
    v = ret_addr;               memcpy(out + CASREC_RET_ADDR_OFF, &v, 8);

    return A64_ATOM_BLOCK_SIZE;
}

/* ---- LSE CAS 结局回放跳板 ----
 * 运行段 48B: {start, addr, old, success, expected, desired}。
 * 数据区: ord/cursor/runs_abs/n_runs/load_limit/exit_abs (0x200..0x230)。
 */
#define CASREP_ORD_OFF      0x200
#define CASREP_CURSOR_OFF   0x208
#define CASREP_RUNS_ABS_OFF 0x210
#define CASREP_NRUNS_OFF    0x218
#define CASREP_LOAD_LIMIT_OFF 0x220
#define CASREP_EXIT_ABS_OFF 0x228
#define CASREP_SITE_PC_OFF 0x238

/* 遥测写入 (limit_exit 路径): 进入时 x16=块基址, 退出后 x16=exit_abs。
 * 破坏 x14/x15。site_pc 从块数据 site_pc_off 读。 */
static void emit_replay_tel(uint8_t **pp, uint64_t tel_abs,
                            unsigned site_pc_off)
{
    uint8_t *p = *pp;
    put32(&p, mov_x(15, 16));               /* x15 = block base */
    uint64_t t = tel_abs;
    put32(&p, movz_x(16, (uint32_t)t & 0xffff, 0));
    put32(&p, movk_x(16, ((uint32_t)t >> 16) & 0xffff, 1));
    put32(&p, movk_x(16, ((uint64_t)t >> 32) & 0xffff, 2));
    put32(&p, movk_x(16, ((uint64_t)t >> 48) & 0xffff, 3));
    put32(&p, movz_x(14, 0x4554, 0));       /* "TELM" LE */
    put32(&p, movk_x(14, 0x4D4C, 1));
    put32(&p, str_x_imm(16, 14, 0));        /* magic */
    put32(&p, mov_x(14, 22));               /* reason = x22 (调用方设) */
    put32(&p, str_x_imm(16, 14, 8));
    put32(&p, ldr_x_imm(15, 14, site_pc_off));
    put32(&p, str_x_imm(16, 14, 16));       /* site_pc */
    put32(&p, str_x_imm(16, 19, 24));       /* ordinal */
    put32(&p, str_x_imm(16, 17, 32));       /* limit */
    put32(&p, str_x_imm(16, 30, 40));       /* caller */
    put32(&p, ldr_x_imm(15, 16, 0x228));    /* exit_abs */
    put32(&p, INSN_BR_X16);
    *pp = p;
}

size_t a64_cas_replay_block(uint8_t *out, uint64_t block_abs,
                            uint64_t runs_abs, uint64_t n_runs,
                            unsigned rs, unsigned rt, unsigned rn,
                            uint64_t ret_addr,
                            uint64_t load_limit, uint64_t exit_abs,
                            uint64_t tel_abs)
{
    if (rs == 31 || rt == 31 || rn == 31)
        return 0;

    memset(out, 0, A64_ATOM_BLOCK_SIZE);
    uint8_t *p = out;

    /* 入口 (4 指令 + 8B 字面量 = 0x18) */
    put32(&p, 0xA9BF47F0U);
    put32(&p, INSN_NOP);
    put32(&p, ldr_lit(16, 8));
    put32(&p, INSN_BR_X16);
    put64(&p, block_abs + 0x18);

    put32(&p, 0xD1006210U);     /* sub x16, x16, #0x18 */
    unsigned base_rep[] = {16, 17, 18, 19, 20, 21, 22, 23,
                           24, 25, 26, 27, 28, 29};
    struct save_plan pl;
    plan_save(&pl, base_rep, sizeof(base_rep) / sizeof(base_rep[0]),
              rt, rn, rs);
    emit_plan_save(&p, &pl);

    /* 序号 = ++ordinal; 超窗口预算 → exit_abs */
    put32(&p, ldr_x16_imm(19, CASREP_ORD_OFF));
    put32(&p, add_x(19, 19, 1));
    put32(&p, str_x16_imm(19, CASREP_ORD_OFF));
    put32(&p, ldr_x16_imm(17, CASREP_LOAD_LIMIT_OFF));
    put32(&p, cmp_x(19, 17));
    uint8_t *lim_b = p;
    put32(&p, movz_x(22, 1, 0));    /* reason=1: ordinal 预算 */
    put32(&p, bcond(0, 8));     /* b.hi limit_exit (占位) */

    /* 游标推进: while (cursor+1 < n_runs && runs[cursor+1].start <= ord) */
    put32(&p, ldr_x16_imm(20, CASREP_CURSOR_OFF));
    put32(&p, ldr_x16_imm(21, CASREP_NRUNS_OFF));
    put32(&p, ldr_x16_imm(22, CASREP_RUNS_ABS_OFF));
    uint8_t *loop_top = p;
    put32(&p, add_x(23, 20, 1));
    put32(&p, cmp_x(23, 21));
    uint8_t *hs_b = p;
    put32(&p, bcond(0, 2));     /* b.hs have (占位) */
    put32(&p, movz_x(24, 48, 0));
    put32(&p, mul_x(24, 23, 24));
    put32(&p, add_xr(24, 24, 22));
    put32(&p, ldr_x_imm(24, 25, 0));    /* next.start */
    put32(&p, cmp_x(25, 19));
    uint8_t *hi_b = p;
    put32(&p, bcond(0, 8));     /* b.hi have (占位) */
    put32(&p, mov_x(20, 23));
    put32(&p, bcond((int32_t)(loop_top - p), 14));
    uint8_t *have = p;
    put32(&p, str_x16_imm(20, CASREP_CURSOR_OFF));
    put32(&p, movz_x(24, 48, 0));
    put32(&p, mul_x(24, 20, 24));
    put32(&p, add_xr(24, 24, 22));      /* run base → x24 */

    /* 期望值校验: 当前 Rs == run.expected (恒定的站点才回放, 该值
       无 +1 延迟问题; 若切片路径分歧 (如走到 help CAS) → fail-closed) */
    put32(&p, ldr_x_imm(31, 27, (unsigned)pl.off[rs]));
    put32(&p, ldr_x_imm(24, 28, 32));   /* run.expected */
    put32(&p, cmp_x(27, 28));
    uint8_t *exp_ne = p;
    put32(&p, movz_x(22, 3, 0));    /* reason=3: expected 失配 */
    put32(&p, bcond(0, 1));     /* b.ne limit_exit (占位) */
    /* 纯结局回放: 不做任何内存写入! 写入目标在切片冻结堆里可能是
       空闲 chunk (消费者缺席, 其 +8 是 tcache/free-list 指针), 覆盖
       即腐蚀堆 → malloc #4 崩溃。主线程控制流完全由 ldar 值回放 +
       CAS 结果 (Rs=old) 驱动, 不需要真实写队列。 */
    put32(&p, ldr_x_imm(24, 23, 16));   /* Rs 值 = run.old */

    /* set: 把最终 Rs 值写入保存槽, 恢复现场, 跳回 */
    {
        int rs_off = pl.off[rs];
        if (rs_off < 0)
            return 0;
        uint8_t *set = p;
        put32(&p, str_x_imm(31, 23, (unsigned)rs_off));
        emit_plan_restore(&p, &pl);
        uint64_t b_off = (uint64_t)(p - out);
        put32(&p, a64_encode_b(block_abs + b_off, ret_addr));

        /* limit_exit: 兜底退出 (预算耗尽或校验失败) */
        uint8_t *limit_exit = p;
        if (tel_abs) {
            emit_replay_tel(&p, tel_abs, CASREP_SITE_PC_OFF);
        } else {
            put32(&p, ldr_x16_imm(16, CASREP_EXIT_ABS_OFF));
            put32(&p, INSN_BR_X16);
        }

        int32_t d1 = (int32_t)(have - hs_b);
        int32_t d2 = (int32_t)(have - hi_b);
        int32_t d8 = (int32_t)(limit_exit - exp_ne);
        uint32_t w;
        w = bcond(d1, 2);   memcpy(hs_b, &w, 4);
        w = bcond(d2, 8);   memcpy(hi_b, &w, 4);
        w = bcond(d8, 1);   memcpy(exp_ne, &w, 4);
        if (lim_b) {
            uint32_t w6 = bcond((int32_t)(limit_exit - lim_b), 8);
            memcpy(lim_b, &w6, 4);
        }
    }

    uint64_t v = 0;         memcpy(out + CASREP_ORD_OFF, &v, 8);
    v = 0;                  memcpy(out + CASREP_CURSOR_OFF, &v, 8);
    v = runs_abs;           memcpy(out + CASREP_RUNS_ABS_OFF, &v, 8);
    v = n_runs;             memcpy(out + CASREP_NRUNS_OFF, &v, 8);
    v = load_limit;         memcpy(out + CASREP_LOAD_LIMIT_OFF, &v, 8);
    v = exit_abs;           memcpy(out + CASREP_EXIT_ABS_OFF, &v, 8);
    v = ret_addr - 4;       memcpy(out + CASREP_SITE_PC_OFF, &v, 8);

    return A64_ATOM_BLOCK_SIZE;
}

/* ---- 回放跳板 ---- */
#define REP_ORD_OFF   0x200
#define REP_CURSOR_OFF 0x208
#define REP_RUNS_ABS_OFF 0x210
#define REP_NRUNS_OFF 0x218
#define REP_LOAD_LIMIT_OFF 0x220
#define REP_EXIT_ABS_OFF 0x228
#define REP_MISS_OFF 0x230      /* 普通 load: 回退真实读计数 (诊断) */
#define REP_SITE_PC_OFF 0x238   /* 站点 pc (遥测) */

size_t a64_atomic_replay_block(uint8_t *out, uint64_t block_abs,
                               uint64_t runs_abs, uint64_t n_runs,
                               int size, unsigned rt, unsigned rn,
                               uint64_t ret_addr,
                               uint64_t load_limit, uint64_t exit_abs,
                               uint64_t tel_abs,
                               int kind,
                               const struct a64_ld_addr *ad)
{
    uint8_t *p = out;
    unsigned base_rep[] = {16, 17, 18, 19, 20, 21, 22, 23,
                           24, 25, 26, 27, 28, 29};
    struct save_plan pl;
    plan_save(&pl, base_rep, sizeof(base_rep) / sizeof(base_rep[0]),
              rt, rn, ad ? (ad->mode == 1 ? ad->rm : 31) : 31);
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
    /* 有效地址重建 (屏障真实 load 需要, 即使单段常量回放也要保留) */
    if (rn == 31)
        put32(&p, add_x(27, 31, (unsigned)pl.save_size));
    else
        put32(&p, ldr_x_imm(31, 27, (unsigned)pl.off[rn]));
    if (ad && ad->mode == 0) {
        if (ad->imm != 0)
            put32(&p, add_x(27, 27, (unsigned)ad->imm));
    } else if (ad && ad->mode == 1) {
        if (ad->rm < 31)
            put32(&p, ldr_x_imm(31, 28, (unsigned)pl.off[ad->rm]));
        else
            put32(&p, movz_x(28, 0, 0));
        put32(&p, add_xr_lsl(27, 27, 28, (unsigned)ad->shift));
    }
    /* 地址校验: 实际地址 == 运行段地址 (任何段数都校验 —— 地址失配
       是最早的对象身份分歧信号, 不允许因单段常量就放宽)。 */
    put32(&p, ldr_x_imm(24, 28, 8));    /* run.addr */
    put32(&p, cmp_x(27, 28));
    uint8_t *ne_b = p;
    put32(&p, bcond(0, 1));     /* b.ne use_real (占位) */
    put32(&p, ldr_x_imm(24, 23, 16));   /* run.value */
    /* 真实屏障: 对原地址执行 ldar/ldaxr/普通 load (值丢弃), 保证排序语义;
       ldaxr 额外设置排他监视器, 使后续真实 stlxr/stxr 成功 (锁获取);
       普通 ldr 自旋站点用普通 ldr 即可 */
    put32(&p, ad ? a64_ldval_insn(ad->ldr_kind, size, 27, 29)
                 : kind == 1 ? a64_ldaxr_insn(size, 27, 29)
                             : kind == 2 ? a64_ldr_insn(size, 27, 29)
                                         : a64_ldar_insn(size, 27, 29));
    uint8_t *set_jmp = p;
    put32(&p, 0x14000000U);     /* b set (占位, 无条件) */
    uint8_t *use_real = p;
    /* 诊断: 普通 load 回退到真实读时计数 (值回放 miss) */
    if (ad) {
        put32(&p, ldr_x16_imm(18, REP_MISS_OFF));
        put32(&p, add_x(18, 18, 1));
        put32(&p, str_x16_imm(18, REP_MISS_OFF));
    }
    if (rn == 31)
        put32(&p, add_x(27, 31, (unsigned)pl.save_size));
    else
        put32(&p, ldr_x_imm(31, 27, (unsigned)pl.off[rn]));
    if (ad && ad->mode == 0) {
        if (ad->imm != 0)
            put32(&p, add_x(27, 27, (unsigned)ad->imm));
    } else if (ad && ad->mode == 1) {
        if (ad->rm < 31)
            put32(&p, ldr_x_imm(31, 28, (unsigned)pl.off[ad->rm]));
        else
            put32(&p, movz_x(28, 0, 0));
        put32(&p, add_xr_lsl(27, 27, 28, (unsigned)ad->shift));
    }
    /* 真实值: 用保存集内的 x29 做加载 (x13 不在最小保存集, 不能破坏) */
    put32(&p, ad ? a64_ldval_insn(ad->ldr_kind, size, 27, 29)
                 : kind == 1 ? a64_ldaxr_insn(size, 27, 29)
                             : kind == 2 ? a64_ldr_insn(size, 27, 29)
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
        put32(&p, movz_x(22, 1, 0));    /* reason=1: ordinal 预算 */
        if (tel_abs) {
            emit_replay_tel(&p, tel_abs, REP_SITE_PC_OFF);
        } else {
            put32(&p, ldr_x16_imm(16, REP_EXIT_ABS_OFF));
            put32(&p, INSN_BR_X16);
        }
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
        w = bcond(d4, 1);
        memcpy(ne_b, &w, 4);
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
        v = 0;                  memcpy(out + REP_MISS_OFF, &v, 8);
        v = ret_addr - 4;       memcpy(out + REP_SITE_PC_OFF, &v, 8);
    }

    return A64_ATOM_BLOCK_SIZE;
}

/* ---- run-burn 整 run 烧录回放块 ----
 * 适用: 精确自旋循环 (site load; cmp/tst rt; b.cond → site), body_len =
 * 循环体指令数 (当前检测只接受 3)。一次入口消费整个 busy run + 值变化
 * 访问, 内部按 guest 等长指令数烧录, 使切片动态指令数 ≈ 录制指令数,
 * 避免逐访问值回放 ~10× 膨胀。
 *
 * 语义 (单入口, 与逐访问块共用 runs 表):
 *   - 入口 ordinal 落在 run 中段 (o > run.start) 才烧录;
 *   - iter_busy = next.start - o (有下一 run) 或 limit - o + 1 (末 run);
 *   - 烧录 iter_busy × body_len 条 (busy 访问全部在跳板内复现);
 *   - 有下一 run: ordinal = next.start + 1 (变化访问已消费), cursor+1,
 *     返回下一 run 值; 程序 cmp+b.cond 执行一次, 与录制中变化访问的
 *     走向一致 (b.cond 不跳 → 循环退出; 跳 → 下一 run 从 next.start+1
 *     继续消费);
 *   - 末 run: 烧到 load_limit 后 limit_exit (reason=1, 窗口结束在自旋);
 *   - o == run.start (run 首访问): 逐访问路径 —— 该访问可能是值变化后
 *     的首次访问, 程序可能据此退出, 不能整 run 烧录;
 *   - 地址失配/run 未覆盖 → 真实读回退 + miss 计数。
 * 每 run 边界固定开销 ~50 条, 长自旋 run 下指令倍率 → 1。
 */
#define BURN_BODY_LEN_OFF 0x240

size_t a64_atomic_replay_burn_block(uint8_t *out, uint64_t block_abs,
                                    uint64_t runs_abs, uint64_t n_runs,
                                    int size, unsigned rt, unsigned rn,
                                    uint64_t ret_addr,
                                    uint64_t load_limit, uint64_t exit_abs,
                                    uint64_t tel_abs,
                                    int kind,
                                    const struct a64_ld_addr *ad,
                                    uint32_t body_len)
{
    uint8_t *p = out;
    unsigned base_rep[] = {16, 17, 18, 19, 20, 21, 22, 23,
                           24, 25, 26, 27, 28, 29};
    struct save_plan pl;
    plan_save(&pl, base_rep, sizeof(base_rep) / sizeof(base_rep[0]),
              rt, rn, ad ? (ad->mode == 1 ? ad->rm : 31) : 31);
    int rt_off = pl.off[rt];
    if (rt_off < 0 || rt == 31 || body_len < 2 || !exit_abs)
        return 0;

    memset(out, 0, A64_ATOM_BLOCK_SIZE);

    /* 入口 (5 指令 + 8B 字面量 = 0x1C 字节) */
    put32(&p, 0xA9BF47F0U);     /* stp x16,x17,[sp,#-16]! */
    put32(&p, INSN_NOP);
    put32(&p, ldr_lit(16, 8));
    put32(&p, INSN_BR_X16);
    put64(&p, block_abs + 0x18);
    put32(&p, 0xD1006210U);     /* sub x16, x16, #0x18 */
    emit_plan_save(&p, &pl);

    /* 序号 = ++ordinal (x19) */
    put32(&p, ldr_x16_imm(19, REP_ORD_OFF));
    put32(&p, add_x(19, 19, 1));
    put32(&p, str_x16_imm(19, REP_ORD_OFF));
    uint8_t *lim_b = NULL;
    put32(&p, ldr_x16_imm(17, REP_LOAD_LIMIT_OFF));
    put32(&p, cmp_x(19, 17));
    lim_b = p;
    put32(&p, bcond(0, 8));     /* b.hi limit_exit (占位) */

    /* 游标推进 (与逐访问块同逻辑): 光标指到 start <= ordinal 的 run */
    put32(&p, ldr_x16_imm(20, REP_CURSOR_OFF));
    put32(&p, ldr_x16_imm(21, REP_NRUNS_OFF));
    put32(&p, ldr_x16_imm(22, REP_RUNS_ABS_OFF));
    uint8_t *loop_top = p;
    put32(&p, add_x(23, 20, 1));
    put32(&p, cmp_x(23, 21));
    uint8_t *hs_b = p;
    put32(&p, bcond(0, 2));     /* b.hs have (占位) */
    put32(&p, movz_x(24, 24, 0));
    put32(&p, mul_x(24, 23, 24));
    put32(&p, add_xr(24, 24, 22));
    put32(&p, ldr_x_imm(24, 25, 0));    /* next.start */
    put32(&p, cmp_x(25, 19));
    uint8_t *hi_b = p;
    put32(&p, bcond(0, 8));     /* b.hi have (占位) */
    put32(&p, mov_x(20, 23));
    put32(&p, bcond((int32_t)(loop_top - p), 14));  /* b.al loop */
    uint8_t *have = p;
    put32(&p, str_x16_imm(20, REP_CURSOR_OFF));
    put32(&p, movz_x(24, 24, 0));
    put32(&p, mul_x(24, 20, 24));
    put32(&p, add_xr(24, 24, 22));
    put32(&p, ldr_x_imm(24, 25, 0));    /* run.start */
    put32(&p, cmp_x(25, 19));
    uint8_t *lo_b = p;
    put32(&p, bcond(0, 8));     /* b.hi use_real (占位) */

    /* 有效地址 → x27 */
    if (rn == 31)
        put32(&p, add_x(27, 31, (unsigned)pl.save_size));
    else
        put32(&p, ldr_x_imm(31, 27, (unsigned)pl.off[rn]));
    if (ad && ad->mode == 0) {
        if (ad->imm != 0)
            put32(&p, add_x(27, 27, (unsigned)ad->imm));
    } else if (ad && ad->mode == 1) {
        if (ad->rm < 31)
            put32(&p, ldr_x_imm(31, 28, (unsigned)pl.off[ad->rm]));
        else
            put32(&p, movz_x(28, 0, 0));
        put32(&p, add_xr_lsl(27, 27, 28, (unsigned)ad->shift));
    }
    /* 地址校验: 失配 = 对象身份分歧信号, 回退真实读 */
    put32(&p, ldr_x_imm(24, 28, 8));    /* run.addr */
    put32(&p, cmp_x(27, 28));
    uint8_t *ne_b = p;
    put32(&p, bcond(0, 1));     /* b.ne use_real (占位) */
    /* run 首访问 (ordinal == run.start): 逐访问路径 */
    put32(&p, cmp_x(25, 19));
    uint8_t *eq_b = p;
    put32(&p, bcond(0, 0));     /* b.eq per_access (占位) */

    /* ---- 烧录路径: 有下一 run ---- */
    put32(&p, add_x(23, 20, 1));
    put32(&p, cmp_x(23, 21));
    uint8_t *last_b = p;
    put32(&p, bcond(0, 8));     /* b.hs burn_last (占位) */
    put32(&p, movz_x(24, 24, 0));
    put32(&p, mul_x(24, 23, 24));
    put32(&p, add_xr(24, 24, 22));
    put32(&p, ldr_x_imm(24, 25, 0));    /* next.start */
    /* 下一 run 地址必须与本次一致 (单 load 循环地址不变; 失配安全回退) */
    put32(&p, ldr_x_imm(24, 28, 8));    /* next.addr */
    put32(&p, cmp_x(27, 28));
    uint8_t *na_b = p;
    put32(&p, bcond(0, 1));     /* b.ne per_access (占位) */
    /* 下一 run 起点越过窗口预算 (合成末 run) → 按末 run 烧到 limit */
    put32(&p, ldr_x16_imm(17, REP_LOAD_LIMIT_OFF));
    put32(&p, add_x(28, 17, 1));
    put32(&p, cmp_x(25, 28));
    uint8_t *cap_b = p;
    put32(&p, bcond(0, 8));     /* b.hi burn_last (占位) */
    put32(&p, sub_xr(26, 25, 19));      /* iter_busy = next.start - o */
    uint8_t *burn_loop = p;
    for (uint32_t i = 0; i + 2 < body_len; i++)
        put32(&p, INSN_NOP);
    put32(&p, sub_x_imm(26, 26, 1));
    put32(&p, cbnz_x((int32_t)(burn_loop - p), 26));
    /* 变化访问已消费: ordinal = next.start + 1, cursor+1, 值=下一 run */
    put32(&p, add_x(19, 25, 1));
    put32(&p, str_x16_imm(19, REP_ORD_OFF));
    put32(&p, add_x(20, 20, 1));
    put32(&p, str_x16_imm(20, REP_CURSOR_OFF));
    put32(&p, movz_x(24, 24, 0));
    put32(&p, mul_x(24, 20, 24));
    put32(&p, add_xr(24, 24, 22));
    put32(&p, ldr_x_imm(24, 23, 16));   /* 下一 run.value */
    /* 真实屏障 load (acquire/排他监视器语义) */
    put32(&p, ad ? a64_ldval_insn(ad->ldr_kind, size, 27, 29)
                 : kind == 1 ? a64_ldaxr_insn(size, 27, 29)
                             : kind == 2 ? a64_ldr_insn(size, 27, 29)
                                         : a64_ldar_insn(size, 27, 29));
    uint8_t *set_jmp = p;
    put32(&p, 0x14000000U);     /* b set (占位) */

    /* ---- 末 run 烧录: 烧到 load_limit 后 limit_exit ---- */
    uint8_t *burn_last = p;
    put32(&p, ldr_x16_imm(17, REP_LOAD_LIMIT_OFF));
    put32(&p, sub_xr(26, 17, 19));
    put32(&p, add_x(26, 26, 1));        /* accesses = limit - o + 1 */
    uint8_t *burn_loop_last = p;
    for (uint32_t i = 0; i + 2 < body_len; i++)
        put32(&p, INSN_NOP);
    put32(&p, sub_x_imm(26, 26, 1));
    put32(&p, cbnz_x((int32_t)(burn_loop_last - p), 26));
    put32(&p, add_x(19, 17, 1));
    put32(&p, str_x16_imm(19, REP_ORD_OFF));
    uint8_t *last_exit_jmp = p;
    put32(&p, 0x14000000U);     /* b limit_exit (占位) */

    /* ---- 逐访问路径 (run 首访问) ---- */
    uint8_t *per_access = p;
    put32(&p, ad ? a64_ldval_insn(ad->ldr_kind, size, 27, 29)
                 : kind == 1 ? a64_ldaxr_insn(size, 27, 29)
                             : kind == 2 ? a64_ldr_insn(size, 27, 29)
                                         : a64_ldar_insn(size, 27, 29));
    put32(&p, ldr_x_imm(24, 23, 16));   /* run.value */
    uint8_t *set_jmp2 = p;
    put32(&p, 0x14000000U);     /* b set (占位) */

    /* ---- 真实读回退 ---- */
    uint8_t *use_real = p;
    put32(&p, ldr_x16_imm(18, REP_MISS_OFF));
    put32(&p, add_x(18, 18, 1));
    put32(&p, str_x16_imm(18, REP_MISS_OFF));
    if (rn == 31)
        put32(&p, add_x(27, 31, (unsigned)pl.save_size));
    else
        put32(&p, ldr_x_imm(31, 27, (unsigned)pl.off[rn]));
    if (ad && ad->mode == 0) {
        if (ad->imm != 0)
            put32(&p, add_x(27, 27, (unsigned)ad->imm));
    } else if (ad && ad->mode == 1) {
        if (ad->rm < 31)
            put32(&p, ldr_x_imm(31, 28, (unsigned)pl.off[ad->rm]));
        else
            put32(&p, movz_x(28, 0, 0));
        put32(&p, add_xr_lsl(27, 27, 28, (unsigned)ad->shift));
    }
    put32(&p, ad ? a64_ldval_insn(ad->ldr_kind, size, 27, 29)
                 : kind == 1 ? a64_ldaxr_insn(size, 27, 29)
                             : kind == 2 ? a64_ldr_insn(size, 27, 29)
                                         : a64_ldar_insn(size, 27, 29));
    put32(&p, mov_x(23, 29));

    /* ---- set: 写 Rt 保存槽, 恢复, 返回 ---- */
    uint8_t *set = p;
    put32(&p, str_x_imm(31, 23, (unsigned)rt_off));
    emit_plan_restore(&p, &pl);
    uint64_t b_off = (uint64_t)(p - out);
    put32(&p, a64_encode_b(block_abs + b_off, ret_addr));

    /* ---- limit_exit (reason=1: ordinal 预算) ---- */
    uint8_t *limit_exit = p;
    put32(&p, movz_x(22, 1, 0));
    if (tel_abs) {
        emit_replay_tel(&p, tel_abs, REP_SITE_PC_OFF);
    } else {
        put32(&p, ldr_x16_imm(16, REP_EXIT_ABS_OFF));
        put32(&p, INSN_BR_X16);
    }

    /* 回填 */
    {
        int32_t d1 = (int32_t)(have - hs_b);
        int32_t d2 = (int32_t)(have - hi_b);
        int32_t d3 = (int32_t)(use_real - lo_b);
        int32_t d4 = (int32_t)(use_real - ne_b);
        int32_t d5 = (int32_t)(per_access - eq_b);
        int32_t d6 = (int32_t)(burn_last - last_b);
        int32_t d7 = (int32_t)(burn_last - cap_b);
        int32_t d8 = (int32_t)(per_access - na_b);
        uint32_t w7 = a64_encode_b(block_abs + (uint64_t)(set_jmp - out),
                                   block_abs + (uint64_t)(set - out));
        uint32_t w8 = a64_encode_b(block_abs + (uint64_t)(set_jmp2 - out),
                                   block_abs + (uint64_t)(set - out));
        uint32_t w;
        w = bcond(d1, 2);   memcpy(hs_b, &w, 4);
        w = bcond(d2, 8);   memcpy(hi_b, &w, 4);
        w = bcond(d3, 8);   memcpy(lo_b, &w, 4);
        w = bcond(d4, 1);   memcpy(ne_b, &w, 4);
        w = bcond(d5, 0);   memcpy(eq_b, &w, 4);
        w = bcond(d6, 8);   memcpy(last_b, &w, 4);
        w = bcond(d7, 8);   memcpy(cap_b, &w, 4);
        w = bcond(d8, 1);   memcpy(na_b, &w, 4);
        memcpy(set_jmp, &w7, 4);
        memcpy(set_jmp2, &w8, 4);
        {
            uint32_t w9 = a64_encode_b(
                block_abs + (uint64_t)(last_exit_jmp - out),
                block_abs + (uint64_t)(limit_exit - out));
            memcpy(last_exit_jmp, &w9, 4);
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
        v = 0;                  memcpy(out + REP_MISS_OFF, &v, 8);
        v = ret_addr - 4;       memcpy(out + REP_SITE_PC_OFF, &v, 8);
        v = body_len;           memcpy(out + BURN_BODY_LEN_OFF, &v, 8);
    }

    return A64_ATOM_BLOCK_SIZE;
}

/* ---- 单段常量站点快速回放块 ---- */
#define FAST_HITS_OFF   0x200
#define FAST_LIMIT_OFF  0x208
#define FAST_EXIT_OFF   0x210
#define FAST_VALUE_OFF  0x218
#define FAST_ADDR_OFF   0x220
#define FAST_MISS_OFF   0x228
#define FAST_SITE_PC_OFF 0x238

size_t a64_atomic_replay_block_fast(uint8_t *out, uint64_t block_abs,
                                    int size, unsigned rt, unsigned rn,
                                    const struct a64_ld_addr *ad,
                                    uint64_t ret_addr,
                                    uint64_t load_limit, uint64_t exit_abs,
                                    uint64_t tel_abs,
                                    int kind, uint64_t value, uint64_t addr)
{
    if (rt == 31)
        return 0;
    /* 最小保存集: 本块破坏 x12(地址)/x13(值/rm)/x18(计数)/x19(上限)/
       x29(屏障 load) + rt/rn[/rm]。单条 ldr 语义要求除 Rt 外全保留
       (目标代码可能在 x12-x19 中跨 load 持有状态)。 */
    unsigned base_rep[] = {12, 13, 18, 19, 29};
    struct save_plan pl;
    plan_save(&pl, base_rep, sizeof(base_rep) / sizeof(base_rep[0]),
              rt, rn,
              ad ? (ad->mode == 1 ? ad->rm : 31) : 31);
    int rt_off = pl.off[rt];
    if (rt_off < 0)
        return 0;

    memset(out, 0, A64_ATOM_BLOCK_SIZE);
    uint8_t *p = out;
    /* 入口 (4 指令 + 8B 字面量 = 0x18 字节) */
    put32(&p, 0xA9BF47F0U);     /* stp x16,x17,[sp,#-16]! */
    put32(&p, INSN_NOP);
    put32(&p, ldr_lit(16, 8));
    put32(&p, INSN_BR_X16);
    put64(&p, block_abs + 0x18);
    put32(&p, 0xD1006210U);     /* sub x16, x16, #0x18 */
    emit_plan_save(&p, &pl);

    /* 命中计数 + 窗口负载上限 (exit_abs=0 时禁用, 独立自测用) */
    uint8_t *lim_b = NULL;
    if (exit_abs && load_limit) {
        put32(&p, ldr_x16_imm(18, FAST_HITS_OFF));
        put32(&p, add_x(18, 18, 1));
        put32(&p, str_x16_imm(18, FAST_HITS_OFF));
        put32(&p, ldr_x16_imm(19, FAST_LIMIT_OFF));
        put32(&p, cmp_x(18, 19));
        lim_b = p;
        put32(&p, bcond(0, 8));     /* b.hi limit_exit (占位) */
    }

    /* 有效地址重建 → x12 */
    if (rn == 31)
        put32(&p, add_x(12, 31, (unsigned)pl.save_size));
    else
        put32(&p, ldr_x_imm(31, 12, (unsigned)pl.off[rn]));
    if (ad && ad->mode == 0) {
        if (ad->imm != 0)
            put32(&p, add_x(12, 12, (unsigned)ad->imm));
    } else if (ad && ad->mode == 1) {
        if (ad->rm < 31)
            put32(&p, ldr_x_imm(31, 13, (unsigned)pl.off[ad->rm]));
        else
            put32(&p, movz_x(13, 0, 0));
        put32(&p, add_xr_lsl(12, 12, 13, (unsigned)ad->shift));
    }
    /* 地址校验: 失配 = 对象身份分歧信号, 回退真实读 + miss 计数 */
    put32(&p, ldr_x16_imm(13, FAST_ADDR_OFF));
    put32(&p, cmp_x(12, 13));
    uint8_t *ne_b = p;
    put32(&p, bcond(0, 1));     /* b.ne use_real (占位) */
    /* 常量值 → x13 */
    put32(&p, ldr_x16_imm(13, FAST_VALUE_OFF));
    uint8_t *set_jmp = p;
    put32(&p, 0x14000000U);     /* b set (占位) */
    uint8_t *use_real = p;
    put32(&p, ldr_x16_imm(18, FAST_MISS_OFF));
    put32(&p, add_x(18, 18, 1));
    put32(&p, str_x16_imm(18, FAST_MISS_OFF));
    /* 真实屏障 load: ldar/ldaxr 必须执行 (排序/排他监视器);
       普通 ldr 无顺序要求, 但保持与原指令一致的访存副作用 */
    put32(&p, ad ? a64_ldval_insn(ad->ldr_kind, size, 12, 29)
                 : kind == 1 ? a64_ldaxr_insn(size, 12, 29)
                             : kind == 2 ? a64_ldr_insn(size, 12, 29)
                                         : a64_ldar_insn(size, 12, 29));
    put32(&p, mov_x(13, 29));
    uint8_t *set = p;
    /* 最终值写入 Rt 保存槽 */
    put32(&p, str_x_imm(31, 13, (unsigned)rt_off));
    emit_plan_restore(&p, &pl);
    uint64_t b_off = (uint64_t)(p - out);
    put32(&p, a64_encode_b(block_abs + b_off, ret_addr));
    uint8_t *limit_exit = NULL;
    if (exit_abs && load_limit) {
        limit_exit = p;
        put32(&p, movz_x(22, 1, 0));    /* reason=1: ordinal 预算 */
        if (tel_abs) {
            emit_replay_tel(&p, tel_abs, FAST_SITE_PC_OFF);
        } else {
            put32(&p, ldr_x16_imm(16, FAST_EXIT_OFF));
            put32(&p, INSN_BR_X16);
        }
    }

    /* 回填 */
    {
        int32_t d1 = (int32_t)(use_real - ne_b);
        uint32_t w5 = a64_encode_b(block_abs + (uint64_t)(set_jmp - out),
                                   block_abs + (uint64_t)(set - out));
        uint32_t w;
        w = bcond(d1, 1);   memcpy(ne_b, &w, 4);
        memcpy(set_jmp, &w5, 4);
        if (lim_b) {
            uint32_t w6 = bcond((int32_t)(limit_exit - lim_b), 8);
            memcpy(lim_b, &w6, 4);
        }
    }

    {
        uint64_t v = 0;     memcpy(out + FAST_HITS_OFF, &v, 8);
        v = load_limit;     memcpy(out + FAST_LIMIT_OFF, &v, 8);
        v = exit_abs;       memcpy(out + FAST_EXIT_OFF, &v, 8);
        v = value;          memcpy(out + FAST_VALUE_OFF, &v, 8);
        v = addr;           memcpy(out + FAST_ADDR_OFF, &v, 8);
        v = 0;              memcpy(out + FAST_MISS_OFF, &v, 8);
        v = ret_addr - 4;   memcpy(out + FAST_SITE_PC_OFF, &v, 8);
    }
    return A64_ATOM_BLOCK_SIZE;
}
