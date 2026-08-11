/*
 * 分配器调用捕获 (strict baremetal malloc 结果重放 M1)
 *
 * 在 libc malloc/calloc/realloc/free 入口 patch `b <记录跳板>`:
 *   - 目标线程 (TPIDR_EL0 == 采集目标 TLS): 记录 {kind,size,caller,ret}
 *     到注入缓冲区, 然后执行原函数 (原入口首条指令内联), 返回时把
 *     x0 (返回值) 写回事件;
 *   - 非目标线程: 只执行原函数 (入口指令内联 + 跳 func+4), 不记录。
 *
 * 跳板栈纪律: 入口 stp(E-16) → base 槽(E-32) → caller x30(E-48) →
 * size(E-64) → event(E-80); 原函数在内联首指令后运行, 其 epilogue
 * 恢复 sp 到 E-80 后 ret 到 ret_label, 按序弹出并 ret 回调用者。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <elf.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/resource.h>

#include "util.h"
#include "arch.h"
#include "collect.h"
#include "a64.h"
#include "alloc_trace.h"

#if defined(__aarch64__)

#define put32(p, w) do { uint32_t _w = (w); memcpy((p), &_w, 4); \
                         (p) += 4; } while (0)

extern int inject_run_snippet(pid_t pid,
                              const struct user_regs_struct *regs,
                              const uint32_t *code, size_t ninsn,
                              uint64_t *ret0);
extern int inject_syscall(pid_t pid,
                          const struct user_regs_struct *regs,
                          uint64_t nr, uint64_t a0, uint64_t a1,
                          uint64_t a2, uint64_t a3, uint64_t a4,
                          uint64_t a5, uint64_t *ret);

struct alloc_func {
    uint64_t pc;                /* libc 内运行时地址 */
    uint32_t first_insn;        /* 入口首条指令 (恢复/内联用) */
    uint64_t page;              /* 跳板页 */
    uint32_t page_off;
    int kind;
};

struct alloc_trace_ctx {
    pid_t pid;
    char out[512];
    int armed;
    struct user_regs_struct regs;
    uint64_t tls;
    uint64_t abuf_addr;
    uint64_t abuf_size;
    struct alloc_func funcs[ALLOC_NKIND];
    size_t n_funcs;
    uint64_t *pages;
    size_t n_pages;
    uint64_t dump_event_ptr;    /* 已转储事件游标 (绝对地址) */
    uint64_t total_events;
    uint64_t *ckpt_events;      /* 每检查点累计事件数 */
    size_t n_ckpts;
};

uint64_t alloc_trace_abuf_addr(const struct alloc_trace_ctx *ctx)
{
    return ctx ? ctx->abuf_addr : 0;
}

static int alloc_events_dump(struct alloc_trace_ctx *ctx);

/* 增量转储 alloc 事件 (边界命中时调用): 目标可能随后退出 (pan
   1000 在 1000 次命中后自然结束), 收尾转储会因目标死亡静默失败,
   events.bin 缺尾部事件 → build slack 被 clamp → 切片超消费。 */
int alloc_trace_events_dump(struct alloc_trace_ctx *ctx)
{
    if (!ctx || !ctx->armed)
        return 0;
    return alloc_events_dump(ctx);
}

/* ---- 注入缓冲区 tmem 读写 (与 atomic_trace 同款) ---- */
static int atmem_rw(pid_t pid, int wr, uint64_t addr, void *buf, size_t len)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, wr ? O_RDWR : O_RDONLY);
    if (fd < 0)
        return -1;
    ssize_t n = wr ? pwrite(fd, buf, len, (off_t)addr)
                   : pread(fd, buf, len, (off_t)addr);
    close(fd);
    return n == (ssize_t)len ? 0 : -1;
}

/* ---- maps 解析: 找 libc 可执行段 ---- */
static int find_libc_exec(pid_t pid, uint64_t *start_out, uint64_t *end_out,
                          char *path, size_t pathsz)
{
    char mp[64];
    snprintf(mp, sizeof(mp), "/proc/%d/maps", pid);
    FILE *f = fopen(mp, "r");
    if (!f)
        return -1;
    char line[512];
    int rc = -1;
    while (fgets(line, sizeof(line), f)) {
        uint64_t s, e;
        char perms[8], rest[512];
        if (sscanf(line, "%llx-%llx %7s %*llx %*x:%*x %*llu %511[^\n]",
                   (unsigned long long *)&s,
                   (unsigned long long *)&e, perms, rest) != 4)
            continue;
        if (perms[0] != 'r' || perms[2] != 'x')
            continue;
        if (!strstr(rest, "libc"))
            continue;
        *start_out = s;
        *end_out = e;
        snprintf(path, pathsz, "%s", rest);
        rc = 0;
        break;
    }
    fclose(f);
    return rc;
}

/* ---- libc ELF dynsym: 找 malloc/calloc/realloc/free ----
 * lstart = libc 可执行段运行时起始; load_bias = lstart - PT_LOAD[0].p_vaddr。 */
static int libc_symbols(const char *path, uint64_t lstart,
                        uint64_t syms[ALLOC_NKIND])
{
    static const char *names[ALLOC_NKIND] = {
        "malloc", "calloc", "realloc", "free",
    };
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    Elf64_Ehdr eh;
    if (read(fd, &eh, sizeof(eh)) != sizeof(eh) ||
        memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0) {
        close(fd);
        return -1;
    }
    uint64_t bias = lstart;
    Elf64_Phdr ph;
    if (eh.e_phnum > 0 &&
        pread(fd, &ph, sizeof(ph), (off_t)eh.e_phoff) == sizeof(ph) &&
        ph.p_type == PT_LOAD)
        bias = lstart - ph.p_vaddr;
    for (int i = 0; i < ALLOC_NKIND; i++)
        syms[i] = 0;
    for (int i = 0; i < eh.e_shnum; i++) {
        Elf64_Shdr sh;
        off_t off = (off_t)eh.e_shoff + (off_t)i * eh.e_shentsize;
        if (pread(fd, &sh, sizeof(sh), off) != sizeof(sh))
            continue;
        if (sh.sh_type != SHT_DYNSYM)
            continue;
        Elf64_Shdr strsh;
        off_t stroff = (off_t)eh.e_shoff +
                       (off_t)sh.sh_link * eh.e_shentsize;
        if (pread(fd, &strsh, sizeof(strsh), stroff) != sizeof(strsh))
            continue;
        size_t n = sh.sh_size / sh.sh_entsize;
        for (size_t k = 0; k < n; k++) {
            Elf64_Sym sy;
            if (pread(fd, &sy, sizeof(sy),
                      (off_t)sh.sh_offset + (off_t)k * sh.sh_entsize)
                != sizeof(sy))
                continue;
            if (ELF64_ST_TYPE(sy.st_info) != STT_FUNC || !sy.st_value)
                continue;
            char nm[64];
            ssize_t r = pread(fd, nm, sizeof(nm) - 1,
                              (off_t)strsh.sh_offset + sy.st_name);
            if (r <= 0)
                continue;
            nm[r] = 0;
            for (int f = 0; f < ALLOC_NKIND; f++) {
                if (!syms[f] && strcmp(nm, names[f]) == 0)
                    syms[f] = bias + sy.st_value;
            }
        }
    }
    close(fd);
    return (syms[0] && syms[1] && syms[2] && syms[3]) ? 0 : -1;
}

/* ---- a64 编码小工具 ---- */
static uint32_t amovz(unsigned rd, unsigned imm16, unsigned hw)
{
    return 0xD2800000U | ((imm16 & 0xffff) << 5) | rd;
}
static uint32_t amovk(unsigned rd, unsigned imm16, unsigned hw)
{
    return 0xF2800000U | ((hw & 3) << 21) |
           ((imm16 & 0xffff) << 5) | rd;
}
static uint32_t aldr_lit(unsigned rt, int32_t off)
{
    return 0x58000000U | (((uint32_t)(off / 4) & 0x7FFFF) << 5) | rt;
}
static uint32_t abr(unsigned rn)
{
    return 0xD61F0000U | (rn << 5);
}
static uint32_t acmp(unsigned rn, unsigned rm)
{
    return 0xEB00001FU | (rm << 16) | (rn << 5);
}
static uint32_t abcond(int32_t off, unsigned cond)
{
    return 0x54000000U | (((uint32_t)(off / 4) & 0x7FFFF) << 5) |
           (cond & 0xF);
}
static uint32_t aadd(unsigned rd, unsigned rn, unsigned imm)
{
    return 0x91000000U | ((imm & 0xfff) << 10) | (rn << 5) | rd;
}
static uint32_t astr(unsigned rt, unsigned rn, unsigned imm)
{
    return 0xF9000000U | (((imm >> 3) & 0xfff) << 10) |
           (rn << 5) | rt;
}
static uint32_t aldr(unsigned rt, unsigned rn, unsigned imm)
{
    return 0xF9400000U | (((imm >> 3) & 0xfff) << 10) |
           (rn << 5) | rt;
}
static uint32_t aldr_w(unsigned rt, unsigned rn, unsigned imm)
{
    return 0xB9400000U | (((imm >> 2) & 0xfff) << 10) |
           (rn << 5) | rt;
}
static uint32_t astr_w(unsigned rt, unsigned rn, unsigned imm)
{
    return 0xB9000000U | (((imm >> 2) & 0xfff) << 10) |
           (rn << 5) | rt;
}
static uint32_t acbnz(unsigned rt, int32_t off)
{
    return 0x35000000U | (((uint32_t)(off / 4) & 0x7FFFF) << 5) | rt;
}
static uint32_t ab_uncond(int32_t off)
{
    return 0x14000000U | (((uint32_t)(off / 4)) & 0x3FFFFFF);
}
static uint32_t amov(unsigned rd, unsigned rm)
{
    return 0xAA0003E0U | (rm << 16) | rd;
}
static uint32_t amovz_imm(unsigned rd, uint64_t v)
{
    uint32_t w = amovz(rd, (uint32_t)v & 0xffff, 0);
    return w;
}

/* 地址装载: xd = imm64 (movz+movk×3) */
static void aemit_addr(uint8_t **pp, unsigned rd, uint64_t v)
{
    uint8_t *p = *pp;
    uint32_t w = amovz(rd, (uint32_t)v & 0xffff, 0);
    memcpy(p, &w, 4); p += 4;
    for (int h = 1; h < 4; h++) {
        w = amovk(rd, (uint32_t)(v >> (16 * h)) & 0xffff, (unsigned)h);
        memcpy(p, &w, 4); p += 4;
    }
    *pp = p;
}

/* 分支重定位: 原指令在 orig_pc 处的分支改写到 new_pc 处执行,
 * 目标保持原始绝对目标。返回 0 = 不可重定位。 */
static uint32_t areloc_branch(uint32_t w, uint64_t orig_pc,
                              uint64_t new_pc)
{
    uint64_t target = a64_branch_target(w, orig_pc);
    if (!target)
        return 0;
    int64_t d = (int64_t)(target - new_pc);
    if (a64_is_cbz(w) || a64_is_cbnz(w)) {
        if (d < -(1 << 20) || d >= (1 << 20))
            return 0;
        return (w & 0xFF00001FU) |
               (((uint32_t)(d >> 2) & 0x7FFFFU) << 5);
    }
    if (a64_is_bcond(w)) {
        if (d < -(1 << 20) || d >= (1 << 20))
            return 0;
        return (w & 0xFF000010U) |
               (((uint32_t)(d >> 2) & 0x7FFFFU) << 5);
    }
    if (a64_is_b(w) || a64_is_bl(w)) {
        if (d < -(1 << 25) || d >= (1 << 25))
            return 0;
        return (w & 0xFC000000U) |
               ((uint32_t)(d >> 2) & 0x3FFFFFFU);
    }
    return 0;
}

/* 内联原函数首条指令 (分支则重定位到本槽) */
static int emit_saved_insn(uint8_t **pp, uint32_t saved,
                           uint64_t orig_pc, uint64_t slot_pc)
{
    uint8_t *p = *pp;
    uint32_t w = saved;
    if (a64_is_cbz(w) || a64_is_cbnz(w) || a64_is_bcond(w) ||
        a64_is_b(w) || a64_is_bl(w)) {
        w = areloc_branch(w, orig_pc, slot_pc);
        if (!w) {
            /* 直接重定位超范围 (跳板页可能离 libc 入口 >1MB):
               逆条件跳过 + ldr x15,[pc,#8] + br x15 + .quad 目标,
               支持任意距离 (x15 caller-saved)。 */
            uint64_t target = a64_branch_target(saved, orig_pc);
            if (!target)
                return -1;
            uint32_t inv;
            if (a64_is_cbz(saved))
                inv = 0xB5000000U | (saved & 0x1F);   /* cbnz xt */
            else if (a64_is_cbnz(saved))
                inv = 0xB4000000U | (saved & 0x1F);   /* cbz xt */
            else if (a64_is_bcond(saved))
                inv = 0x54000000U | ((saved & 0xF) ^ 1);
            else
                return -1;
            uint8_t *skip = p + 20;   /* 跳过 ldr+br+.quad, 落到 func+4 */
            inv |= (((uint32_t)((skip - p) / 4) & 0x7FFFF) << 5);
            memcpy(p, &inv, 4);
            p += 4;
            uint32_t ldr = 0x58000000U | (2U << 5) | 15U;
            memcpy(p, &ldr, 4);
            p += 4;
            uint32_t br = 0xD61F0000U | (15U << 5);
            memcpy(p, &br, 4);
            p += 4;
            memcpy(p, &target, 8);
            p += 8;
            *pp = p;
            return 0;
        }
    }
    memcpy(p, &w, 4);
    p += 4;
    *pp = p;
    return 0;
}

/* 生成单个分配器函数的记录跳板 (0x300B)
 *
 * 栈纪律 (sp 从调用者入口 E 起):
 *   E-16  entry stp x16,x17;  E-32 base 槽;  E-48 caller x30 槽;
 *   E-64 size 槽;  E-80 x19,x20;  E-96 x21;  E-112 event 槽。
 * 跳板作为 callee 的一部分, 必须像真实分配器一样保留 x19-x28
 * (本跳板破坏 x19/x20/x21, 一并保存)。
 * 原函数首条指令内联执行; 其 epilogue 恢复 sp 到 E-80 (target) 或
 * E (non-target/overflow) 后 ret:
 *   - target: ret → ret_label (x30 被我们设为 ret_label), 写回返回值,
 *     按序弹栈, ret 调用者;
 *   - non-target/overflow: ret → 原调用者 (x30 未动)。 */
size_t alloc_record_block(uint8_t *out, uint64_t block_abs,
                          uint32_t saved_insn,
                          uint64_t orig_pc,
                          uint64_t orig_next,
                          uint64_t tls,
                          uint64_t hdr_event_ptr_addr,
                          uint64_t hdr_events_end_addr,
                          uint64_t hdr_overflow_addr,
                          uint64_t kind)
{
    uint8_t *p = out;
    memset(out, 0, ALLOC_BLOCK_SIZE);

    /* 入口 (5 指令 + 8B 字面量); 之后 sp=E-16, x16=block base */
    put32(p, 0xA9BF47F0U);      /* stp x16,x17,[sp,#-16]! */
    put32(p, 0xD503201FU);      /* nop */
    put32(p, aldr_lit(16, 8));
    put32(p, abr(16));
    uint64_t v = block_abs + 0x18;
    memcpy(p, &v, 8); p += 8;
    put32(p, 0xD1006210U);      /* sub x16,x16,#0x18 */
    put32(p, 0xD10043FFU);      /* sub sp,sp,#16 (base 槽, E-32) */
    put32(p, astr(16, 31, 0));  /* str x16,[sp] */
    put32(p, 0xD53BD04EU);      /* mrs x14,tpidr_el0 */
    put32(p, aldr(15, 16, ALLOC_TLS_OFF));
    put32(p, acmp(14, 15));
    uint8_t *tls_bne = p;
    put32(p, abcond(0, 1));     /* b.ne non_target (占位) */

    /* target: 记录 {kind,size,caller}, 执行原函数, ret_label 写回 */
    put32(p, 0xD10043FFU);      /* sub sp,sp,#16 (caller x30 槽, E-48) */
    put32(p, astr(30, 31, 0));  /* str x30,[sp] */
    put32(p, 0xD10043FFU);      /* sub sp,sp,#16 (size 槽, E-64) */
    put32(p, astr(0, 31, 0));   /* str x0,[sp] */
    put32(p, 0xA9BF53F3U);      /* stp x19,x20,[sp,#-16]! (E-80) */
    put32(p, 0xD10043FFU);      /* sub sp,sp,#16 (x21 槽, E-96) */
    put32(p, astr(21, 31, 0));  /* str x21,[sp] */
    put32(p, aldr(17, 16, ALLOC_EVENT_PTR_ADDR_OFF));
    put32(p, aldr(18, 17, 0));  /* event_ptr */
    put32(p, aldr(19, 16, ALLOC_EVENTS_END_ADDR_OFF));
    put32(p, aldr(19, 19, 0));  /* events_end */
    put32(p, aadd(20, 18, ALLOC_EVENT_SIZE));
    put32(p, acmp(20, 19));
    uint8_t *ovf_b = p;
    put32(p, abcond(0, 8));     /* b.hi overflow (占位) */
    /* reserve/commit: 槽 pad 字段 0=COMMITTED/空闲, 1=RESERVED (在途)。
       入口 pad==1 → 外层分配器调用在途 (嵌套调用) → 原生执行不记录。 */
    put32(p, aldr_w(20, 18, 4));    /* ldr w20,[x18,#4] pad */
    uint8_t *nested_b = p;
    put32(p, acbnz(20, 0));         /* cbnz w20,nested (占位) */
    put32(p, amovz(20, 1, 0));      /* mov w20,#1 */
    put32(p, astr_w(20, 18, 4));    /* str w20,[x18,#4] RESERVED */
    /* 诊断: 调用计数++ (仅记录型调用; 溢出/嵌套不计) */
    put32(p, aldr(15, 16, ALLOC_DIAG_CNT_OFF));
    put32(p, aadd(15, 15, 1));
    put32(p, astr(15, 16, ALLOC_DIAG_CNT_OFF));
    put32(p, aldr(21, 16, ALLOC_KIND_OFF));
    put32(p, astr(21, 18, 0));
    put32(p, aldr(21, 31, 32)); /* size (E-64, sp=E-96) */
    put32(p, astr(21, 18, 8));
    put32(p, aldr(21, 31, 48)); /* caller x30 (E-48, sp=E-96) */
    put32(p, astr(21, 18, 16));
    put32(p, astr(31, 18, 24)); /* ret = 0 (xzr) */
    put32(p, astr(1, 18, 32));  /* extra = x1 (calloc elem / realloc 新大小) */
    put32(p, 0xD10043FFU);      /* sub sp,sp,#16 (event 槽, E-112) */
    put32(p, astr(18, 31, 0));  /* str event,[sp] */
    put32(p, aldr(30, 16, ALLOC_RET_LABEL_OFF));
    /* 原函数会访问其栈帧上方的溢出区 (glibc sp+偏移), 与跳板保存槽
       冲突 (曾把 caller x30 槽写坏 → 返回地址变事件地址 → SIGBUS)。
       压 0x800 缓冲垫隔离; event 槽在原函数 sp 上方 0x800 处,
       远离常见 [sp+0x200..0x280] 溢出访问。 */
    put32(p, 0xD12003FFU);      /* sub sp,sp,#0x800 (缓冲垫加大:
                                   原函数会访问帧上方溢出区, 0x200 曾被
                                   踩穿破坏保存槽 → event_ptr 提交错乱) */
    if (emit_saved_insn(&p, saved_insn, orig_pc,
                        block_abs + (uint64_t)(p - out)) < 0)
        return 0;               /* 不可重定位 */
    put32(p, aldr(18, 16, ALLOC_ORIG_NEXT_OFF));
    put32(p, abr(18));

    /* overflow (sp=E-96): 置标志 → unwind 原生执行 */
    uint8_t *overflow = p;
    put32(p, aldr(18, 16, ALLOC_ORIG_NEXT_OFF));
    put32(p, aldr(14, 16, ALLOC_OVERFLOW_ADDR_OFF));
    put32(p, amovz_imm(15, 1));
    put32(p, astr(15, 14, 0));
    uint8_t *ovf_b2 = p;
    put32(p, ab_uncond(0));     /* b unwind (占位) */

    /* nested (sp=E-96): 嵌套分配器调用, 原生执行不记录 */
    uint8_t *nested = p;
    put32(p, aldr(18, 16, ALLOC_ORIG_NEXT_OFF));
    uint8_t *nst_b = p;
    put32(p, ab_uncond(0));     /* b unwind (占位) */

    /* unwind (sp=E-96): 弹栈到 E, 执行原函数 */
    uint8_t *unwind = p;
    put32(p, 0xF94003F5U);      /* ldr x21,[sp] (E-96) */
    put32(p, aadd(31, 31, 16)); /* pop x21 (E-80) */
    put32(p, 0xA8C153F3U);      /* ldp x19,x20,[sp],#16 (E-64) */
    put32(p, aadd(31, 31, 16)); /* pop size (E-48) */
    put32(p, 0xA8C17FFEU);      /* ldp x30,xzr,[sp],#16 (caller, E-32) */
    put32(p, aadd(31, 31, 16)); /* pop base 槽 (E-16) */
    put32(p, 0xA8C147F0U);      /* ldp x16,x17,[sp],#16 (entry, E) */
    if (emit_saved_insn(&p, saved_insn, orig_pc,
                        block_abs + (uint64_t)(p - out)) < 0)
        return 0;
    put32(p, abr(18));

    /* non_target (sp=E-32): 弹 base+entry, 原生执行 */
    uint8_t *non_target = p;
    put32(p, aldr(18, 16, ALLOC_ORIG_NEXT_OFF));
    put32(p, aadd(31, 31, 16)); /* pop base 槽 (E-16) */
    put32(p, 0xA8C147F0U);      /* ldp x16,x17,[sp],#16 (E) */
    if (emit_saved_insn(&p, saved_insn, orig_pc,
                        block_abs + (uint64_t)(p - out)) < 0)
        return 0;
    put32(p, abr(18));

    /* ret_label (sp=E-912): 提交事件 (ret + pad=0 + event_ptr 前进),
       弹栈到 E, ret 调用者。x16 可能已被原函数破坏, 先从 base 槽恢复。 */
    uint8_t *ret_label = p;
    put32(p, 0x912003FFU);      /* add sp,sp,#0x800 (弹回缓冲垫) */
    put32(p, aldr(16, 31, 80)); /* ldr x16,[sp,#80] (base 槽 E-32) */
    put32(p, astr(0, 16, ALLOC_DIAG_RET_OFF));  /* 诊断: 最近返回值 */
    put32(p, aldr(18, 31, 0));  /* event (E-112) */
    put32(p, astr(0, 18, 24));  /* ret */
    put32(p, astr_w(31, 18, 4));/* pad = 0 (COMMITTED) */
    put32(p, aldr(17, 16, ALLOC_EVENT_PTR_ADDR_OFF));
    put32(p, aadd(20, 18, ALLOC_EVENT_SIZE));
    put32(p, astr(20, 17, 0));  /* hdr.event_ptr = event+40 (commit) */
    put32(p, aadd(31, 31, 16)); /* pop event (E-96) */
    put32(p, 0xF94003F5U);      /* ldr x21,[sp] (E-96) */
    put32(p, aadd(31, 31, 16)); /* pop x21 (E-80) */
    put32(p, 0xA8C153F3U);      /* ldp x19,x20,[sp],#16 (E-64) */
    put32(p, aadd(31, 31, 16)); /* pop size (E-48) */
    put32(p, 0xA8C17FFEU);      /* ldp x30,xzr,[sp],#16 (caller, E-32) */
    put32(p, aadd(31, 31, 16)); /* pop base 槽 (E-16) */
    put32(p, 0xA8C147F0U);      /* ldp x16,x17,[sp],#16 (E) */
    put32(p, 0xD65F03C0U);      /* ret */

    /* 回填 */
    {
        int32_t d1 = (int32_t)(non_target - tls_bne);
        int32_t d2 = (int32_t)(overflow - ovf_b);
        int32_t d3 = (int32_t)(nested - nested_b);
        int32_t d4 = (int32_t)(unwind - ovf_b2);
        int32_t d5 = (int32_t)(unwind - nst_b);
        uint32_t w = abcond(d1, 1);
        memcpy(tls_bne, &w, 4);
        w = abcond(d2, 8);
        memcpy(ovf_b, &w, 4);
        w = acbnz(20, d3);
        memcpy(nested_b, &w, 4);
        w = ab_uncond(d4);
        memcpy(ovf_b2, &w, 4);
        w = ab_uncond(d5);
        memcpy(nst_b, &w, 4);
    }

    /* 数据区 */
    v = tls;                memcpy(out + ALLOC_TLS_OFF, &v, 8);
    v = hdr_event_ptr_addr; memcpy(out + ALLOC_EVENT_PTR_ADDR_OFF, &v, 8);
    v = hdr_events_end_addr;
    memcpy(out + ALLOC_EVENTS_END_ADDR_OFF, &v, 8);
    v = hdr_overflow_addr; memcpy(out + ALLOC_OVERFLOW_ADDR_OFF, &v, 8);
    v = orig_next;          memcpy(out + ALLOC_ORIG_NEXT_OFF, &v, 8);
    v = block_abs + (uint64_t)(ret_label - out);
    memcpy(out + ALLOC_RET_LABEL_OFF, &v, 8);
    v = kind;               memcpy(out + ALLOC_KIND_OFF, &v, 8);

    return ALLOC_BLOCK_SIZE;
}

/* ---- 就近找空闲 gap (解析 maps) ---- */
static uint64_t alloc_find_gap(pid_t pid, uint64_t near, uint64_t size)
{
    struct amap { uint64_t s, e; };
    struct amap maps[1024];
    size_t n = 0;
    char mp[64];
    snprintf(mp, sizeof(mp), "/proc/%d/maps", pid);
    FILE *f = fopen(mp, "r");
    if (!f)
        return 0;
    char line[512];
    while (n < 1024 && fgets(line, sizeof(line), f)) {
        uint64_t s, e;
        if (sscanf(line, "%llx-%llx",
                   (unsigned long long *)&s,
                   (unsigned long long *)&e) == 2) {
            maps[n].s = s;
            maps[n].e = e;
            n++;
        }
    }
    fclose(f);
    uint64_t lo = 0;
    for (size_t i = 0; i < n; i++) {
        if (maps[i].s <= near && near < maps[i].e) {
            lo = maps[i].e;
            break;
        }
    }
    if (!lo)
        lo = near;
    /* 向后找 (最多 16MB); 再向前找 */
    for (uint64_t d = 0x1000; d <= 0x1000000; d += 0x1000) {
        uint64_t a = (lo + d + 0xfff) & ~0xfffULL;
        int ok = 1;
        for (size_t i = 0; i < n; i++) {
            if (a < maps[i].e && a + size > maps[i].s) {
                ok = 0;
                break;
            }
        }
        if (ok)
            return a;
    }
    for (uint64_t d = 0x1000; d <= 0x1000000; d += 0x1000) {
        uint64_t a = near > d + size ? near - d - size : 0;
        if (!a)
            break;
        a &= ~0xfffULL;
        int ok = 1;
        for (size_t i = 0; i < n; i++) {
            if (a < maps[i].e && a + size > maps[i].s) {
                ok = 0;
                break;
            }
        }
        if (ok)
            return a;
    }
    return 0;
}

/* 目标内 icache/dcache 刷新 (patch 函数入口 + 跳板页后必须执行;
   /proc/pid/mem 写代码页不保证指令缓存一致, 曾导致目标执行旧指令
   随机崩溃) */
static int alloc_flush_ranges(pid_t pid,
                              const struct user_regs_struct *regs,
                              uint64_t list_abs, uint64_t n_ranges)
{
    uint32_t code[64];
    size_t n = 0;
    size_t cbz_off = 0, inner_off = 0, bne_off = 0, loop_off = 0,
           b_off = 0, done_off = 0;
    uint64_t v = list_abs;
    code[n++] = 0xD2800000U | ((uint32_t)(v & 0xffff) << 5) | 16U;
    if (v & 0xFFFF0000ULL)
        code[n++] = 0xF2800000U | (1U << 21) |
                    ((uint32_t)((v >> 16) & 0xffff) << 5) | 16U;
    if (v & 0xFFFFFFFF0000ULL)
        code[n++] = 0xF2800000U | (2U << 21) |
                    ((uint32_t)((v >> 32) & 0xffff) << 5) | 16U;
    if (v & 0xFFFFFFFFFFFF0000ULL)
        code[n++] = 0xF2800000U | (3U << 21) |
                    ((uint32_t)((v >> 48) & 0xffff) << 5) | 16U;
    code[n++] = 0xF9400213U;             /* ldr x19,[x16] */
    code[n++] = 0x91002210U;             /* add x20,x16,#8 */
    loop_off = n;
    cbz_off = n;
    code[n++] = 0xB4000000U | 19U;
    code[n++] = 0xF9400295U;             /* ldr x21,[x20] */
    code[n++] = 0xF9408296U;             /* ldr x22,[x20,#16] */
    code[n++] = 0xCB1502D7U;             /* sub x23,x22,x21 */
    code[n++] = 0x9100FEF7U;             /* add x23,x23,#63 */
    code[n++] = 0xD346FEF7U;             /* lsr x23,x23,#6 */
    inner_off = n;
    code[n++] = 0xD50B7B35U;             /* dc cvau,x21 */
    code[n++] = 0xD50B7535U;             /* ic ivau,x21 */
    code[n++] = 0x910102B5U;             /* add x21,x21,#64 */
    bne_off = n;
    code[n++] = 0x54000001U;
    code[n++] = 0x91010294U;             /* add x20,x20,#16 */
    code[n++] = 0xD1000673U;             /* sub x19,x19,#1 */
    b_off = n;
    code[n++] = 0x14000000U;
    done_off = n;
    code[n++] = 0xD5033B9FU;             /* dsb ish */
    code[n++] = 0xD5033FDFU;             /* isb */
    code[n++] = 0xD4200000U;             /* brk #0 */
    code[cbz_off] = 0xB4000000U |
        (((uint32_t)(done_off - cbz_off) & 0x7FFFF) << 5) | 19U;
    code[bne_off] = 0x54000001U |
        (((uint32_t)(inner_off - bne_off) & 0x7FFFF) << 5);
    code[b_off] = a64_encode_b((uint64_t)b_off * 4,
                               (uint64_t)loop_off * 4);
    (void)n_ranges;
    return inject_run_snippet(pid, regs, code, n, NULL);
}

/* ---- 事件增量转储: events.bin + 游标推进 ---- */
static int alloc_events_dump(struct alloc_trace_ctx *ctx)
{
    char path[600];
    snprintf(path, sizeof(path), "%s/allocs/events.bin", ctx->out);
    uint64_t event_ptr = 0;
    if (atmem_rw(ctx->pid, 0, ctx->abuf_addr + 24, &event_ptr, 8) < 0)
        return -1;
    uint64_t base = ctx->abuf_addr + ALLOC_BUF_HDR_SIZE;
    if (ctx->dump_event_ptr == 0)
        ctx->dump_event_ptr = base;
    if (event_ptr < ctx->dump_event_ptr)
        event_ptr = ctx->dump_event_ptr;
    uint64_t n_new = (event_ptr - ctx->dump_event_ptr) / ALLOC_EVENT_SIZE;
    uint64_t total = ctx->total_events;
    FILE *f = fopen(path, "a+b");
    if (!f) {
        fprintf(stderr, "alloc: dump fopen %s failed (errno %d)\n",
                path, errno);
        return -1;
    }
    if (n_new) {
        uint8_t *ev = xmalloc(n_new * ALLOC_EVENT_SIZE);
        if (atmem_rw(ctx->pid, 0, ctx->dump_event_ptr, ev,
                     n_new * ALLOC_EVENT_SIZE) == 0) {
            fwrite(ev, 1, n_new * ALLOC_EVENT_SIZE, f);
            ctx->dump_event_ptr += n_new * ALLOC_EVENT_SIZE;
            total += n_new;
        } else {
            char mpath[64];
            snprintf(mpath, sizeof(mpath), "/proc/%d/mem", ctx->pid);
            int mfd = open(mpath, O_RDONLY);
            ssize_t got = -1;
            int err = 0, err_open = 0;
            if (mfd < 0)
                err_open = errno;
            if (mfd >= 0) {
                errno = 0;
                got = pread(mfd, ev, n_new * ALLOC_EVENT_SIZE,
                            (off_t)ctx->dump_event_ptr);
                err = errno;
                uint64_t one = 0;
                ssize_t g1 = pread(mfd, &one, 1,
                                   (off_t)ctx->dump_event_ptr - 4096);
                int e1 = errno;
                ssize_t g2 = pread(mfd, &one, 1,
                                   (off_t)ctx->dump_event_ptr);
                int e2 = errno;
                fprintf(stderr,
                        "alloc: dump FAIL detail open_errno=%d "
                        "pread=%zd/%d one_at_-4k=%zd/%d one_at=%zd/%d\n",
                        err_open, got, err, g1, e1, g2, e2);
                close(mfd);
            }
            if (mfd < 0) {
                struct rlimit rl;
                getrlimit(RLIMIT_NOFILE, &rl);
                fprintf(stderr,
                        "alloc: dump read FAIL addr=%#llx len=%zu "
                        "open_errno=%d rlim={%lu,%lu}\n",
                        (unsigned long long)ctx->dump_event_ptr,
                        n_new * ALLOC_EVENT_SIZE, err_open,
                        (unsigned long)rl.rlim_cur,
                        (unsigned long)rl.rlim_max);
            }
        }
        free(ev);
    }
    fclose(f);
    ctx->total_events = total;
    return 0;
}

int alloc_trace_ckpt(struct alloc_trace_ctx *ctx, size_t ckpt_no)
{
    if (!ctx || !ctx->armed)
        return 0;
    alloc_events_dump(ctx);
    /* 诊断: 每 50 个检查点读一次各块调用计数 (定位 TLS 过滤/记录路径) */
    if (ckpt_no % 50 == 1) {
        for (size_t i = 0; i < ctx->n_funcs; i++) {
            uint64_t blk = ctx->funcs[i].page + ctx->funcs[i].page_off;
            uint64_t cnt = 0, ret = 0;
            if (atmem_rw(ctx->pid, 0, blk + ALLOC_DIAG_CNT_OFF,
                         &cnt, 8) == 0)
                atmem_rw(ctx->pid, 0, blk + ALLOC_DIAG_RET_OFF,
                         &ret, 8);
            fprintf(stderr,
                    "alloc: ckpt %zu func[%zu] kind=%d calls=%llu "
                    "last_ret=%#llx\n",
                    ckpt_no, i, ctx->funcs[i].kind,
                    (unsigned long long)cnt,
                    (unsigned long long)ret);
        }
        uint64_t ep = 0, ee = 0, ovf = 0, next_pad = 0;
        if (atmem_rw(ctx->pid, 0, ctx->abuf_addr + 24, &ep, 8) == 0 &&
            atmem_rw(ctx->pid, 0, ctx->abuf_addr + 32, &ee, 8) == 0 &&
            atmem_rw(ctx->pid, 0, ctx->abuf_addr + 40, &ovf, 8) == 0)
            atmem_rw(ctx->pid, 0, ep, &next_pad, 4);
        if (ep)
            fprintf(stderr,
                    "alloc: ckpt %zu event_ptr=%llu events_end=%llu "
                    "overflow=%llu next_pad=%llu\n",
                    ckpt_no, (unsigned long long)ep,
                    (unsigned long long)ee, (unsigned long long)ovf,
                    (unsigned long long)next_pad);
    }
    char path[600];
    snprintf(path, sizeof(path), "%s/allocs/ckpt_%06zu.bin",
             ctx->out, ckpt_no);
    FILE *f = fopen(path, "wb");
    if (f) {
        uint64_t v = ctx->total_events;
        fwrite(&v, 1, 8, f);
        fclose(f);
    }
    ctx->ckpt_events = xrealloc(ctx->ckpt_events,
                                (ctx->n_ckpts + 1) * sizeof(uint64_t));
    ctx->ckpt_events[ctx->n_ckpts++] = ctx->total_events;
    return 0;
}

int alloc_trace_finish(struct alloc_trace_ctx *ctx)
{
    if (!ctx)
        return 0;
    fprintf(stderr, "alloc: finish total_events=%llu armed=%d\n",
            (unsigned long long)(ctx ? ctx->total_events : 0),
            ctx ? ctx->armed : 0);
    if (ctx->armed) {
        /* 环溢出标记: 事件缓冲满后记录停止, 事件流不完整。
           build 必须拒绝装配覆盖丢失事件的窗口。 */
        uint64_t ovf = 0;
        if (atmem_rw(ctx->pid, 0, ctx->abuf_addr + 40, &ovf, 8) == 0 &&
            ovf) {
            char op[600];
            snprintf(op, sizeof(op), "%s/allocs/overflow.bin", ctx->out);
            FILE *of = fopen(op, "wb");
            if (of) {
                fwrite(&ovf, 1, 8, of);
                fclose(of);
            }
            fprintf(stderr,
                    "alloc: EVENT BUFFER OVERFLOW (8MB, %llu events) — "
                    "事件流不完整\n",
                    (unsigned long long)ctx->total_events);
        }
        for (size_t i = 0; i < ctx->n_funcs; i++) {
            uint64_t blk = ctx->funcs[i].page + ctx->funcs[i].page_off;
            uint64_t ret = 0, cnt = 0;
            atmem_rw(ctx->pid, 0, blk + ALLOC_DIAG_RET_OFF, &ret, 8);
            atmem_rw(ctx->pid, 0, blk + ALLOC_DIAG_CNT_OFF, &cnt, 8);
            fprintf(stderr,
                    "alloc: func[%zu] kind=%d pc=%#llx calls=%llu "
                    "last_ret=%#llx\n",
                    i, ctx->funcs[i].kind,
                    (unsigned long long)ctx->funcs[i].pc,
                    (unsigned long long)cnt,
                    (unsigned long long)ret);
        }
        if (alloc_events_dump(ctx) < 0)
            warn("alloc: finish event dump failed (target likely exited); "
                 "events.bin may be incomplete");
        /* 恢复函数入口原指令 (目标随后被 trace 终止) */
        for (size_t i = 0; i < ctx->n_funcs; i++)
            atmem_rw(ctx->pid, 1, ctx->funcs[i].pc,
                     &ctx->funcs[i].first_insn, 4);
        inject_syscall(ctx->pid, &ctx->regs, 215 /* SYS_munmap */,
                       ctx->abuf_addr, ctx->abuf_size, 0, 0, 0, 0, NULL);
        for (size_t i = 0; i < ctx->n_pages; i++)
            inject_syscall(ctx->pid, &ctx->regs, 215,
                           ctx->pages[i], 0x1000, 0, 0, 0, 0, NULL);
        collect_exclude_clear();
        ctx->armed = 0;
    }
    free(ctx->pages);
    free(ctx->ckpt_events);
    free(ctx);
    return 0;
}

int alloc_trace_arm(struct alloc_trace_ctx **ctx_out, pid_t pid,
                    const struct user_regs_struct *regs,
                    const char *out)
{
    struct alloc_trace_ctx *ctx = xcalloc(1, sizeof(*ctx));
    ctx->pid = pid;
    snprintf(ctx->out, sizeof(ctx->out), "%s", out);
    ctx->regs = *regs;
    ctx->tls = collect_get_tls();
    if (!ctx->tls) {
        warn("alloc: cannot read target TLS");
        free(ctx);
        return -1;
    }

    uint64_t lstart, lend;
    char path[512];
    if (find_libc_exec(pid, &lstart, &lend, path, sizeof(path)) < 0) {
        warn("alloc: libc exec segment not found");
        free(ctx);
        return -1;
    }
    uint64_t syms[ALLOC_NKIND];
    if (libc_symbols(path, lstart, syms) < 0) {
        warn("alloc: libc allocator symbols not found (%s)", path);
        free(ctx);
        return -1;
    }
    fprintf(stderr,
            "alloc: libc exec %#llx-%#llx path=%s syms "
            "malloc=%#llx calloc=%#llx realloc=%#llx free=%#llx\n",
            (unsigned long long)lstart, (unsigned long long)lend, path,
            (unsigned long long)syms[0], (unsigned long long)syms[1],
            (unsigned long long)syms[2], (unsigned long long)syms[3]);

    for (int k = 0; k < ALLOC_NKIND; k++) {
        const char *fm = getenv("ELFTRACE_ALLOC_KIND");
        if (fm && strchr(fm, '0' + k) == NULL)
            continue;           /* 诊断: 只拦截指定 kind */
        uint32_t w = 0;
        if (atmem_rw(pid, 0, syms[k], &w, 4) < 0) {
            warn("alloc: cannot read entry %#llx",
                 (unsigned long long)syms[k]);
            free(ctx);
            return -1;
        }
        /* 入口首条指令须可内联/重定位: b.cond/cbz/cbnz/b/bl 由生成器
           重定位到跳板; 拒绝 tbz/tbnz/adr/adrp/ldr 字面量/svc/br/ret */
        if (a64_is_tbz(w) || a64_is_tbnz(w) || a64_is_adr(w) ||
            a64_is_adrp(w) || a64_is_ldr_literal(w) ||
            a64_is_svc0(w) || a64_is_br(w)) {
            warn("alloc: entry %#llx first insn %08x not relocatable",
                 (unsigned long long)syms[k], w);
            free(ctx);
            return -1;
        }
        ctx->funcs[k].pc = syms[k];
        ctx->funcs[k].first_insn = w;
        ctx->funcs[k].kind = k;
        ctx->n_funcs++;
    }

    /* mmap 事件缓冲区 (默认 8MB; ELFTRACE_ALLOC_BUF_SIZE 可调, 测试
       溢出门禁用) */
    uint64_t buf_size = 8 << 20;
    const char *bs = getenv("ELFTRACE_ALLOC_BUF_SIZE");
    if (bs && *bs)
        buf_size = strtoull(bs, NULL, 0);
    uint64_t ret = 0;
    if (inject_syscall(pid, regs, 222 /* SYS_mmap */, 0, buf_size,
                       7 /* RWX */, 0x22 /* PRIVATE|ANON */, -1, 0,
                       &ret) < 0 || !ret) {
        warn("alloc: cannot mmap event buffer");
        free(ctx);
        return -1;
    }
    ctx->abuf_addr = ret;
    ctx->abuf_size = buf_size;
    collect_exclude_add(ret, buf_size);

    /* 写头 */
    {
        uint8_t hdr[ALLOC_BUF_HDR_SIZE];
        memset(hdr, 0, sizeof(hdr));
        uint64_t v = ALLOC_BUF_MAGIC;
        memcpy(hdr + 0, &v, 8);
        v = ALLOC_BUF_VERSION;
        memcpy(hdr + 8, &v, 8);
        v = ctx->n_funcs;
        memcpy(hdr + 16, &v, 8);
        v = ret + ALLOC_BUF_HDR_SIZE;
        memcpy(hdr + 24, &v, 8);    /* event_ptr */
        v = ret + buf_size;
        memcpy(hdr + 32, &v, 8);    /* events_end */
        v = 0;
        memcpy(hdr + 40, &v, 8);    /* overflow */
        v = ctx->tls;
        memcpy(hdr + 48, &v, 8);
        v = buf_size;
        memcpy(hdr + 56, &v, 8);
        if (atmem_rw(pid, 1, ret, hdr, sizeof(hdr)) < 0) {
            warn("alloc: cannot write header");
            inject_syscall(pid, regs, 215, ret, buf_size, 0, 0, 0, 0,
                           NULL);
            free(ctx);
            return -1;
        }
    }

    /* 跳板页 (就近 libc) */
    size_t need = ((ctx->n_funcs * ALLOC_BLOCK_SIZE + 0xfff) & ~0xfffULL);
    uint64_t taddr = alloc_find_gap(pid, lend, need);
    if (!taddr) {
        warn("alloc: no gap near libc");
        inject_syscall(pid, regs, 215, ret, buf_size, 0, 0, 0, 0, NULL);
        free(ctx);
        return -1;
    }
    if (inject_syscall(pid, regs, 222, taddr, need, 7, 0x32, -1, 0,
                       &ret) < 0 || ret != taddr) {
        warn("alloc: cannot mmap trampoline page");
        inject_syscall(pid, regs, 215, ctx->abuf_addr, buf_size, 0, 0,
                       0, 0, NULL);
        free(ctx);
        return -1;
    }
    collect_exclude_add(taddr, need);
    ctx->pages = xcalloc(need / 4096, sizeof(uint64_t));
    for (size_t i = 0; i < need / 4096; i++)
        ctx->pages[ctx->n_pages++] = taddr + i * 4096;

    size_t o = 0;
    for (size_t i = 0; i < ctx->n_funcs; i++) {
        uint64_t block_abs = taddr + o;
        uint8_t blk[ALLOC_BLOCK_SIZE];
        size_t n = alloc_record_block(
            blk, block_abs, ctx->funcs[i].first_insn,
            ctx->funcs[i].pc,
            ctx->funcs[i].pc + 4, ctx->tls,
            ctx->abuf_addr + 24, ctx->abuf_addr + 32,
            ctx->abuf_addr + 40, ctx->funcs[i].kind);
        if (!n) {
            warn("alloc: block gen failed for %#llx (kind %d)",
                 (unsigned long long)ctx->funcs[i].pc,
                 ctx->funcs[i].kind);
            free(ctx);
            return -1;
        }
        if (atmem_rw(pid, 1, block_abs, blk, n) < 0) {
            warn("alloc: cannot write block for %#llx",
                 (unsigned long long)ctx->funcs[i].pc);
            continue;
        }
        ctx->funcs[i].page = taddr;
        ctx->funcs[i].page_off = (uint32_t)o;
        uint32_t bw = a64_encode_b(ctx->funcs[i].pc, block_abs);
        if (atmem_rw(pid, 1, ctx->funcs[i].pc, &bw, 4) < 0) {
            warn("alloc: cannot patch %#llx",
                 (unsigned long long)ctx->funcs[i].pc);
            continue;
        }
        o += ALLOC_BLOCK_SIZE;
    }

    /* icache/dcache 刷新: patch 的函数入口页 + 跳板页 */
    {
        size_t n_ranges = ctx->n_funcs + ctx->n_pages;
        size_t list_bytes = 8 + n_ranges * 16;
        uint8_t *lst = xcalloc(1, list_bytes);
        uint8_t *lp = lst;
        uint64_t v = n_ranges;
        memcpy(lp, &v, 8);
        lp += 8;
        for (size_t i = 0; i < ctx->n_funcs; i++) {
            v = ctx->funcs[i].pc & ~0xfffULL;
            memcpy(lp, &v, 8);
            lp += 8;
            v = (ctx->funcs[i].pc & ~0xfffULL) + 4096;
            memcpy(lp, &v, 8);
            lp += 8;
        }
        for (size_t i = 0; i < ctx->n_pages; i++) {
            v = ctx->pages[i];
            memcpy(lp, &v, 8);
            lp += 8;
            v = ctx->pages[i] + 4096;
            memcpy(lp, &v, 8);
            lp += 8;
        }
        uint64_t list_abs = ctx->abuf_addr + ctx->abuf_size - 4096;
        if (atmem_rw(pid, 1, list_abs, lst, list_bytes) == 0 &&
            !getenv("ELFTRACE_ALLOC_NOFLUSH"))
            alloc_flush_ranges(pid, regs, list_abs, n_ranges);
        free(lst);
    }

    /* 侧车目录 */
    char dir[600];
    snprintf(dir, sizeof(dir), "%s/allocs", out);
    mkdir(dir, 0755);
    char fp[700];
    snprintf(fp, sizeof(fp), "%s/funcs.bin", dir);
    FILE *f = fopen(fp, "wb");
    if (f) {
        for (size_t i = 0; i < ctx->n_funcs; i++) {
            fwrite(&ctx->funcs[i].pc, 1, 8, f);
            fwrite(&ctx->funcs[i].first_insn, 1, 4, f);
            uint32_t k = (uint32_t)ctx->funcs[i].kind;
            fwrite(&k, 1, 4, f);
        }
        fclose(f);
    }
    fprintf(stderr,
            "alloc: armed malloc=%#llx calloc=%#llx realloc=%#llx "
            "free=%#llx (buf %#llx+%llu, tramp %#llx)\n",
            (unsigned long long)syms[0], (unsigned long long)syms[1],
            (unsigned long long)syms[2], (unsigned long long)syms[3],
            (unsigned long long)ctx->abuf_addr,
            (unsigned long long)buf_size,
            (unsigned long long)taddr);
    ctx->armed = 1;
    *ctx_out = ctx;
    return 0;
}

#endif /* __aarch64__ */
