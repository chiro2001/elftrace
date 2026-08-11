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
static int find_libc_exec(uint64_t *start_out, uint64_t *end_out,
                          char *path, size_t pathsz)
{
    FILE *f = fopen("/proc/self/../self/maps", "r");
    if (!f)
        f = fopen("/proc/self/maps", "r");
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
    put32(p, aldr(21, 16, ALLOC_KIND_OFF));
    put32(p, astr(21, 18, 0));
    put32(p, aldr(21, 31, 32)); /* size (E-64, sp=E-96) */
    put32(p, astr(21, 18, 8));
    put32(p, aldr(21, 31, 48)); /* caller x30 (E-48, sp=E-96) */
    put32(p, astr(21, 18, 16));
    put32(p, astr(31, 18, 24)); /* ret = 0 (xzr) */
    put32(p, astr(20, 17, 0));  /* hdr.event_ptr = event+32 */
    put32(p, 0xD10043FFU);      /* sub sp,sp,#16 (event 槽, E-112) */
    put32(p, astr(18, 31, 0));  /* str event,[sp] */
    put32(p, aldr(30, 16, ALLOC_RET_LABEL_OFF));
    memcpy(p, &saved_insn, 4);  /* 原函数首条指令 */
    p += 4;
    put32(p, aldr(18, 16, ALLOC_ORIG_NEXT_OFF));
    put32(p, abr(18));

    /* overflow (sp=E-96): 置标志, 弹栈到 E, 原生执行 */
    uint8_t *overflow = p;
    put32(p, aldr(18, 16, ALLOC_ORIG_NEXT_OFF));
    put32(p, aldr(14, 16, ALLOC_OVERFLOW_ADDR_OFF));
    put32(p, amovz_imm(15, 1));
    put32(p, astr(15, 14, 0));
    put32(p, 0xF94003F5U);      /* ldr x21,[sp] (E-96) */
    put32(p, aadd(31, 31, 16)); /* pop x21 (E-80) */
    put32(p, 0xA8C153F3U);      /* ldp x19,x20,[sp],#16 (E-64) */
    put32(p, aadd(31, 31, 16)); /* pop size (E-48) */
    put32(p, 0xA8C17FFEU);      /* ldp x30,xzr,[sp],#16 (caller, E-32) */
    put32(p, aadd(31, 31, 16)); /* pop base 槽 (E-16) */
    put32(p, 0xA8C147F0U);      /* ldp x16,x17,[sp],#16 (entry, E) */
    memcpy(p, &saved_insn, 4);
    p += 4;
    put32(p, abr(18));

    /* non_target (sp=E-32): 弹 base+entry, 原生执行 */
    uint8_t *non_target = p;
    put32(p, aldr(18, 16, ALLOC_ORIG_NEXT_OFF));
    put32(p, aadd(31, 31, 16)); /* pop base 槽 (E-16) */
    put32(p, 0xA8C147F0U);      /* ldp x16,x17,[sp],#16 (E) */
    memcpy(p, &saved_insn, 4);
    p += 4;
    put32(p, abr(18));

    /* ret_label (sp=E-112): 写回 ret, 弹栈到 E, ret 调用者 */
    uint8_t *ret_label = p;
    put32(p, aldr(18, 31, 0));  /* event (E-112) */
    put32(p, astr(0, 18, 24));  /* ret */
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
        uint32_t w = abcond(d1, 1);
        memcpy(tls_bne, &w, 4);
        w = abcond(d2, 8);
        memcpy(ovf_b, &w, 4);
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
static uint64_t alloc_find_gap(uint64_t near, uint64_t size)
{
    struct amap { uint64_t s, e; };
    struct amap maps[1024];
    size_t n = 0;
    FILE *f = fopen("/proc/self/maps", "r");
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
    if (!f)
        return -1;
    if (n_new) {
        uint8_t *ev = xmalloc(n_new * ALLOC_EVENT_SIZE);
        if (atmem_rw(ctx->pid, 0, ctx->dump_event_ptr, ev,
                     n_new * ALLOC_EVENT_SIZE) == 0) {
            fwrite(ev, 1, n_new * ALLOC_EVENT_SIZE, f);
            ctx->dump_event_ptr += n_new * ALLOC_EVENT_SIZE;
            total += n_new;
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
    if (ctx->armed) {
        alloc_events_dump(ctx);
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
    if (find_libc_exec(&lstart, &lend, path, sizeof(path)) < 0) {
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

    for (int k = 0; k < ALLOC_NKIND; k++) {
        uint32_t w = 0;
        if (atmem_rw(pid, 0, syms[k], &w, 4) < 0) {
            warn("alloc: cannot read entry %#llx",
                 (unsigned long long)syms[k]);
            free(ctx);
            return -1;
        }
        /* 入口首条指令须可内联: 拒绝分支/PC 相对/svc */
        if (a64_is_b(w) || a64_is_bl(w) || a64_is_bcond(w) ||
            a64_is_cbz(w) || a64_is_cbnz(w) || a64_is_tbz(w) ||
            a64_is_tbnz(w) || a64_is_adr(w) || a64_is_adrp(w) ||
            a64_is_ldr_literal(w) || a64_is_svc0(w) || a64_is_br(w)) {
            warn("alloc: entry %#llx first insn %08x not inlineable",
                 (unsigned long long)syms[k], w);
            free(ctx);
            return -1;
        }
        ctx->funcs[k].pc = syms[k];
        ctx->funcs[k].first_insn = w;
        ctx->funcs[k].kind = k;
        ctx->n_funcs++;
    }

    /* mmap 事件缓冲区 (8MB) */
    uint64_t buf_size = 8 << 20;
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
    uint64_t taddr = alloc_find_gap(lend, need);
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
            ctx->funcs[i].pc + 4, ctx->tls,
            ctx->abuf_addr + 24, ctx->abuf_addr + 32,
            ctx->abuf_addr + 40, ctx->funcs[i].kind);
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
