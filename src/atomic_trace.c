/*
 * aarch64 原子记录 (trace --atomic-replay)
 *
 * 流程:
 *   1. 扫描目标可执行段中的 ldar 站点 (排除 vdso/vvar);
 *   2. 注入一块匿名缓冲区 (默认 64MB, 事件游程压缩) + 每段就近一组
 *      RWX 记录页 (每站点 0x220B 记录跳板);
 *   3. 把站点指令 patch 成 b <记录跳板入口>;
 *   4. 检查点时把各站点状态 (序号/最后值/地址) 快照到
 *      <out>/atomics/ckpt_*.bin; 结束时把事件流转储到 events.bin;
 *   5. 结束恢复原指令并 munmap 缓冲区 (记录页保留, 避免其他线程
 *      正在执行时被解映射崩溃; 进程退出时由内核回收)。
 *
 * 缓冲区/记录页通过 collect_exclude_* 排除在检查点快照之外。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

extern void inject_flush_icache(pid_t pid,
                                const struct user_regs_struct *regs,
                                unsigned long page, size_t len);
#include <errno.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <elf.h>

#include "elftrace.h"
#include "collect.h"
#include "arch.h"
#include "a64.h"
#include "atomic_a64.h"
#include "atomic_trace.h"
#include "util.h"

#if defined(__aarch64__)

/* 记录站点 */
struct asite {
    uint64_t pc;
    uint32_t orig_insn;
    int kind;                   /* 0=ldar 族, 2/3=普通 ldr, 4=LSE CAS */
    size_t seg;                 /* 所属可执行段索引 */
    uint64_t page;              /* 记录页地址 */
    uint32_t page_off;          /* 块偏移 */
};

/* CAS 扫描误报过滤: 候选指令的下一条必须是 ret 或分支 (真实 CAS
 * 站点位于代码里, 后面常跟 ret/b.cond/cbz; 数据/字面量池的下一条
 * 是随机值)。仅用于 CAS 候选, 不用于 ldar/ldxr (它们掩码更紧)。 */
static int a64_is_ret_or_branch(uint32_t w)
{
    if (w == 0xD65F03C0U)               /* ret */
        return 1;
    if ((w & 0xFC000000U) == 0x14000000U)   /* b / bl */
        return 1;
    if ((w & 0xFF000010U) == 0x54000000U)   /* b.cond */
        return 1;
    if ((w & 0x7C000000U) == 0x34000000U)   /* cbz/cbnz/tbz/tbnz */
        return 1;
    if ((w & 0xFFFFFC1FU) == 0xD61F0000U)   /* br/blr (含 ret) */
        return 1;
    return 0;
}

struct atomic_trace_ctx {
    pid_t pid;
    char out[512];
    int armed;
    struct user_regs_struct regs;   /* 最后一次 snippet 前的现场 */
    uint64_t tls;
    uint64_t abuf_addr;
    uint64_t abuf_size;
    struct asite *sites;
    size_t n_sites;
    uint64_t *pages;            /* 记录页地址 */
    size_t n_pages;
    uint64_t dump_event_ptr;    /* 已转储事件游标 (绝对地址) */
    uint64_t total_events;      /* 已转储事件数 (补偿模型) */
    uint64_t cas_dump_ptr;      /* 已转储 CAS 事件游标 */
    uint64_t total_cas_events;
    unsigned base_insns, append_insns;
    int record_all;             /* 诊断: 全量记录普通 load 访问 */
    /* 补偿: 每检查点 {measured, overhead, orig} */
    uint64_t *ckpt_measured;
    uint64_t *ckpt_overhead;
    uint64_t *ckpt_orig;
    size_t n_ckpts;
    uint64_t r_num, r_den;      /* 膨胀系数 r = r_num/r_den (触发缩放) */
};

int inject_run_snippet(pid_t pid, const struct user_regs_struct *regs,
                       const uint32_t *code, size_t ninsn, uint64_t *ret0);
int inject_syscall(pid_t pid, const struct user_regs_struct *regs,
                   uint64_t nr, uint64_t a0, uint64_t a1, uint64_t a2,
                   uint64_t a3, uint64_t a4, uint64_t a5, uint64_t *ret);

#define SYS_mmap       222
#define SYS_munmap     215

static int atomic_events_append(struct atomic_trace_ctx *ctx);

/* ---- /proc/pid/mem 读写 ---- */
static int tmem_rw(pid_t pid, int wr, uint64_t addr, void *buf, size_t len)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, wr ? O_RDWR : O_RDONLY);
    if (fd < 0)
        return -1;
    ssize_t n = wr ? pwrite(fd, buf, len, (off_t)addr)
                   : pread(fd, buf, len, (off_t)addr);
    if (n != (ssize_t)len)
        fprintf(stderr, "atomic: tmem_rw %s @ %#llx len %zu -> %zd "
                "(errno %d %s)\n",
                wr ? "write" : "read", (unsigned long long)addr, len, n,
                errno, strerror(errno));
    close(fd);
    return n == (ssize_t)len ? 0 : -1;
}

/* ---- maps 解析 ---- */
struct seginfo {
    uint64_t start, end;
    int exec;
    char name[256];
};

static int read_maps(pid_t pid, struct seginfo **out, size_t *n_out)
{
    char path[64];
    char line[1024];
    FILE *f;
    struct seginfo *v = NULL;
    size_t n = 0, cap = 0;

    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    f = fopen(path, "r");
    if (!f)
        return -1;
    while (fgets(line, sizeof(line), f)) {
        unsigned long long s, e;
        char perms[8], name[256] = "";
        if (sscanf(line, "%llx-%llx %7s %*s %*s %*s %255[^\n]", &s, &e,
                   perms, name) < 3)
            continue;
        if (n == cap) {
            cap = cap ? cap * 2 : 64;
            v = xrealloc(v, cap * sizeof(*v));
        }
        memset(&v[n], 0, sizeof(v[n]));
        v[n].start = s;
        v[n].end = e;
        v[n].exec = perms[2] == 'x';
        if (name[0] == ' ')
            memmove(name, name + 1, strlen(name));
        snprintf(v[n].name, sizeof(v[n].name), "%s", name);
        n++;
    }
    fclose(f);
    *out = v;
    *n_out = n;
    return 0;
}

/* 在 near 附近 (128MB 内) 找 size 字节空闲区间 */
static uint64_t atomic_find_gap(pid_t pid, uint64_t near, uint64_t size)
{
    struct seginfo *maps = NULL;
    size_t nmaps = 0;
    if (read_maps(pid, &maps, &nmaps) < 0)
        return 0;
    uint64_t cur = (near + 0xfff) & ~0xfffULL;
    uint64_t lim = near + (128UL << 20);
    uint64_t found = 0;
    while (cur + size <= lim) {
        uint64_t end = cur + size;
        int busy = 0;
        for (size_t i = 0; i < nmaps; i++) {
            if (cur < maps[i].end && end > maps[i].start) {
                cur = (maps[i].end + 0xfff) & ~0xfffULL;
                busy = 1;
                break;
            }
        }
        if (!busy) {
            found = cur;
            break;
        }
    }
    free(maps);
    return found;
}

/* 普通 ldr 自旋站点判定: 纯自旋循环 —
   load 后 1-3 条指令内, 加载值直接决定一个回跳 (cbz/cbnz/tbz/tbnz,
   或 cmp wRt,#0 + 条件分支); 回跳目标必须是 load 本身或前 1 条指令
   (该指令须为 dmb/dsb/nop 屏障); load 与分支之间只允许屏障。
   排除字符串/哈希等普通循环 (曾扫出 5000+ 误报拖垮目标)。 */
static int is_spin_ldr(const uint8_t *buf, size_t got, uint64_t off,
                       unsigned rt, uint64_t ldr_pc)
{
    /* 屏障类指令 (dmb/dsb/nop) */
    #define SPIN_BARRIER(w) \
        ((w) == 0xD503201FU || (w) == 0xD5033BBFU || \
         (w) == 0xD50339BFU || (w) == 0xD5033ABFU || \
         (w) == 0xD5033B9FU)
    uint64_t t = 0;
    for (int step = 1; step <= 3; step++) {
        uint64_t o = off + step * 4;
        if (o + 4 > got)
            return 0;
        uint32_t w;
        memcpy(&w, buf + o, 4);
        if (SPIN_BARRIER(w))
            continue;
        uint64_t pc = ldr_pc + step * 4;
        if ((a64_is_cbz(w) || a64_is_cbnz(w)) && (w & 0x1FU) == rt) {
            t = a64_branch_target(w, pc);
            break;
        }
        if ((a64_is_tbz(w) || a64_is_tbnz(w)) && (w & 0x1FU) == rt) {
            t = a64_branch_target(w, pc);
            break;
        }
        /* cmp wRt, #0; 下一指令条件分支回跳 */
        if ((w & 0xFF000000U) == 0x71000000U &&
            (w & 0x1FU) == 0x1FU &&
            (w & 0x003FFC00U) == 0 &&
            ((w >> 5) & 0x1FU) == rt) {
            uint64_t o2 = o + 4;
            if (o2 + 4 > got)
                return 0;
            uint32_t w2;
            memcpy(&w2, buf + o2, 4);
            if (a64_is_bcond(w2)) {
                t = a64_branch_target(w2, pc + 4);
                break;
            }
            return 0;
        }
        return 0;               /* 其他指令: 非自旋模式 */
    }
    if (!t || t > ldr_pc || t < ldr_pc - 4)
        return 0;               /* 回跳目标必须是 load 本身或前 1 条 */
    if (t == ldr_pc - 4) {
        /* 循环头前一条必须是屏障, 保证循环体只有 load */
        if (off < 4)
            return 0;
        uint32_t hw;
        memcpy(&hw, buf + off - 4, 4);
        if (!SPIN_BARRIER(hw))
            return 0;
    }
    return 1;
    #undef SPIN_BARRIER
}

/* 扫描目标可执行段中的原子/自旋 load 站点 */
static int atomic_scan(pid_t pid, struct asite **out, size_t *n_out,
                       struct seginfo **segs_out, size_t *nsegs_out,
                       const char *value_sites)
{
    struct seginfo *maps = NULL;
    size_t nmaps = 0;
    struct asite *sites = NULL;
    size_t n = 0, cap = 0;
    int mfd = -1;
    char path[64];

    if (read_maps(pid, &maps, &nmaps) < 0)
        return -1;
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    mfd = open(path, O_RDONLY);
    if (mfd < 0) {
        free(maps);
        return -1;
    }
    for (size_t i = 0; i < nmaps; i++) {
        struct seginfo *sg = &maps[i];
        if (!sg->exec)
            continue;
        if (strstr(sg->name, "vdso") || strstr(sg->name, "vvar") ||
            strstr(sg->name, "vsyscall"))
            continue;
        uint64_t size = sg->end - sg->start;
        if (size == 0 || size > (512UL << 20))
            continue;
        uint8_t *buf = xmalloc(size);
        ssize_t got = pread(mfd, buf, size, (off_t)sg->start);
        if (got < 0) {
            free(buf);
            continue;
        }
        for (uint64_t off = 0; off + 4 <= (uint64_t)got; off += 4) {
            uint32_t w;
            memcpy(&w, buf + off, 4);
            int size;
            unsigned rt, rn;
            int kind;
            /* LSE CAS 结局录制: 默认关闭 (实验性)。开启后采集端会
               patch cas/casa/casl/casal 记录结局; 但当前观测到开启后
               冻结堆状态不再自洽 (切片 malloc 数次后崩溃/挂死, 机制
               未明), 生产路径用构建侧 --atomic-force-cas-pc 兜底。 */
            if (a64_is_lse_cas(w, NULL, NULL, NULL) &&
                getenv("ELFTRACE_CAS_RECORD")) {
                /* 误报过滤: 数据/字面量池里随机字也会匹配 CAS 编码
                   (13 个固定位), patch 会破坏 literal load → 目标崩溃。
                   要求下一条是 ret/分支 (真实 cas8_* 家族全是
                   cas*; ret)。 */
                uint32_t wnext;
                if (off + 8 > (uint64_t)got)
                    continue;
                memcpy(&wnext, buf + off + 4, 4);
                if (!a64_is_ret_or_branch(wnext))
                    continue;
                if (n == cap) {
                    cap = cap ? cap * 2 : 64;
                    sites = xrealloc(sites, cap * sizeof(*sites));
                }
                sites[n].pc = sg->start + off;
                sites[n].orig_insn = w;
                sites[n].kind = 4;
                sites[n].seg = i;
                n++;
                continue;
            }
            if (!a64_is_load_any(w, &size, &rt, &rn, &kind))
                continue;
            if (rt == 31)
                continue;       /* 目标 xzr: 罕见, 跳过 */
            if (kind == 2 &&
                !is_spin_ldr(buf, (size_t)got, off, rt, sg->start + off))
                continue;       /* 普通 ldr 但非自旋模式: 跳过 */
            if (n == cap) {
                cap = cap ? cap * 2 : 64;
                sites = xrealloc(sites, cap * sizeof(*sites));
            }
            sites[n].pc = sg->start + off;
            sites[n].orig_insn = w;
            sites[n].kind = kind;
            sites[n].seg = i;
            n++;
        }
        free(buf);
    }
    /* 值回放白名单: 每行 "pc insn" (hex)。验证 pc 在可执行段内且
       指令字匹配, 防止库版本/PIE 偏移变化后静默 patch 错站点。 */
    if (value_sites) {
        FILE *vf = fopen(value_sites, "r");
        if (!vf)
            die("cannot open value-replay sites %s", value_sites);
        char line[256];
        while (fgets(line, sizeof(line), vf)) {
            uint64_t pc = 0;
            uint32_t insn = 0;
            if (sscanf(line, "%llx %x", (unsigned long long *)&pc,
                       &insn) != 2)
                continue;
            int found = -1;
            for (size_t k = 0; k < nmaps; k++) {
                if (maps[k].exec &&
                    pc >= maps[k].start && pc + 4 <= maps[k].end) {
                    found = (int)k;
                    break;
                }
            }
            if (found < 0) {
                warn("value-replay site %#llx not in executable segment",
                     (unsigned long long)pc);
                continue;
            }
            int size;
            unsigned rt, rn;
            int kind = -1;
            struct a64_ld_addr ad;
            if (!a64_is_plain_load(insn, &size, &rt, &rn, &kind, &ad)) {
                warn("value-replay site %#llx: not plain ldr w/x (%#x)",
                     (unsigned long long)pc, insn);
                continue;
            }
            /* 验证目标内存中的指令字 */
            uint32_t real = 0;
            ssize_t got = pread(mfd, &real, 4, (off_t)pc);
            if (got != 4 || real != insn) {
                warn("value-replay site %#llx insn mismatch "
                     "(%#x vs %#x)", (unsigned long long)pc, real, insn);
                continue;
            }
            if (n == cap) {
                cap = cap ? cap * 2 : 64;
                sites = xrealloc(sites, cap * sizeof(*sites));
            }
            sites[n].pc = pc;
            sites[n].orig_insn = insn;
            sites[n].kind = kind;
            sites[n].seg = (size_t)found;
            n++;
        }
        fclose(vf);
    }
    close(mfd);
    *out = sites;
    *n_out = n;
    *segs_out = maps;
    *nsegs_out = nmaps;
    return 0;
}

static void write_u64(uint8_t **p, uint64_t v)
{
    memcpy(*p, &v, 8);
    *p += 8;
}

/* ---- 目标内 icache/dcache 刷新 ----
 * /proc/pid/mem 写代码页后内核不保证指令缓存一致 (真机 A53 实测部分
 * 生效), 让目标自己执行 dc cvau / ic ivau / dsb ish / isb。
 * ranges: {start,end} 对, 放在事件缓冲区最后一页 (临时, 事件不会
 * 写到这里之前)。目标必须处于 ptrace-stop。 */
static int atomic_flush_ranges(pid_t pid,
                               const struct user_regs_struct *regs,
                               uint64_t list_abs, uint64_t n_ranges)
{
    uint32_t code[64];
    size_t n = 0;
    size_t cbz_off = 0, bne_off = 0, inner_off = 0, loop_off = 0,
           b_off = 0, done_off = 0;

    /* movz/movk x16 = list_abs */
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
    code[n++] = 0xF9400213U;             /* ldr x19,[x16] = n_ranges */
    code[n++] = 0x91002210U;             /* add x20,x16,#8 */
    loop_off = n;
    cbz_off = n;
    code[n++] = 0xB4000000U | 19U;       /* cbz x19,done (占位) */
    code[n++] = 0xF9400295U;             /* ldr x21,[x20] = start */
    code[n++] = 0xF9408296U;             /* ldr x22,[x20,#16] = end */
    code[n++] = 0xCB1502D7U;             /* sub x23,x22,x21 */
    code[n++] = 0x9100FEF7U;             /* add x23,x23,#63 */
    code[n++] = 0xD346FEF7U;             /* lsr x23,x23,#6 */
    inner_off = n;
    code[n++] = 0xD50B7B35U;             /* dc cvau,x21 */
    code[n++] = 0xD50B7535U;             /* ic ivau,x21 */
    code[n++] = 0x910102B5U;             /* add x21,x21,#64 */
    bne_off = n;
    code[n++] = 0x54000001U;             /* b.ne inner (占位) */
    code[n++] = 0x91010294U;             /* add x20,x20,#16 */
    code[n++] = 0xD1000673U;             /* sub x19,x19,#1 */
    b_off = n;
    code[n++] = 0x14000000U;             /* b loop (占位) */
    done_off = n;
    code[n++] = 0xD5033B9FU;             /* dsb ish */
    code[n++] = 0xD5033FDFU;             /* isb */
    code[n++] = 0xD4200000U;             /* brk #0 */

    /* 回填: cbz → done; b.ne → inner; b → loop */
    code[cbz_off] = 0xB4000000U |
        (((uint32_t)(done_off - cbz_off) & 0x7FFFF) << 5) | 19U;
    code[bne_off] = 0x54000001U |
        (((uint32_t)(inner_off - bne_off) & 0x7FFFF) << 5);
    code[b_off] = a64_encode_b((uint64_t)b_off * 4, (uint64_t)loop_off * 4);
    (void)n_ranges;
    return inject_run_snippet(pid, regs, code, n, NULL);
}

int atomic_trace_arm(struct atomic_trace_ctx **ctx_out, pid_t pid,
                     const void *regs, const char *out, uint64_t buf_size,
                     const char *value_sites, int record_all)
{
    struct atomic_trace_ctx *ctx = xcalloc(1, sizeof(*ctx));
    struct asite *sites = NULL;
    size_t n_sites = 0;
    struct seginfo *maps = NULL;
    size_t nmaps = 0;
    uint64_t ret = 0;

    if (!buf_size)
        buf_size = 64UL << 20;
    snprintf(ctx->out, sizeof(ctx->out), "%s", out);
    ctx->pid = pid;
    ctx->regs = *(const struct user_regs_struct *)regs;
    ctx->tls = collect_get_tls();
    ctx->record_all = record_all;
    if (!ctx->tls) {
        warn("atomic: no TPIDR_EL0 for target, atomic replay disabled");
        free(ctx);
        return -1;
    }
    if (atomic_scan(pid, &sites, &n_sites, &maps, &nmaps,
                    value_sites) < 0) {
        warn("atomic: cannot scan target memory");
        free(ctx);
        return -1;
    }
    if (!n_sites) {
        fprintf(stderr, "atomic: no ldar sites found, disabled\n");
        free(sites);
        free(maps);
        free(ctx);
        return -1;
    }
    ctx->sites = sites;
    ctx->n_sites = n_sites;

    /* 1. 注入事件缓冲区 (内核选址) */
    if (inject_syscall(pid, &ctx->regs, SYS_mmap, 0, buf_size,
                       3 /* RW */, 0x22 /* PRIVATE|ANON */, -1, 0,
                       &ret) < 0 ||
        ret == (uint64_t)-1) {
        warn("atomic: cannot mmap event buffer in target");
        goto fail;
    }
    ctx->abuf_addr = ret;
    ctx->abuf_size = buf_size;
    collect_exclude_add(ctx->abuf_addr, buf_size);

    /* 2. 初始化缓冲区头 */
    {
        uint8_t hdr[A64_ATB_HDR_SIZE];
        memset(hdr, 0, sizeof(hdr));
        uint8_t *p = hdr;
        uint64_t state_off = A64_ATB_HDR_SIZE;
        uint64_t events_off = state_off + n_sites * A64_ATB_STATE_SIZE;
        uint64_t cas_base = ctx->abuf_addr + buf_size / 2;
        write_u64(&p, A64_ATB_MAGIC);
        write_u64(&p, A64_ATB_VERSION);
        write_u64(&p, n_sites);
        write_u64(&p, state_off);
        write_u64(&p, events_off);
        write_u64(&p, ctx->abuf_addr + events_off);
        write_u64(&p, cas_base);            /* 前半: load 事件区 */
        write_u64(&p, 0);
        write_u64(&p, buf_size);
        write_u64(&p, cas_base);            /* 后半: CAS 事件区 */
        write_u64(&p, ctx->abuf_addr + buf_size);
        write_u64(&p, 0);
        if (tmem_rw(pid, 1, ctx->abuf_addr, hdr, sizeof(hdr)) < 0) {
            warn("atomic: cannot init event buffer @ %#llx",
                 (unsigned long long)ctx->abuf_addr);
            fprintf(stderr,
                    "atomic: buf mmap ret=%#llx size=%llu (target %d)\n",
                    (unsigned long long)ctx->abuf_addr,
                    (unsigned long long)buf_size, pid);
            goto fail;
        }
    }

    /* 3. 按段就近注入记录页并生成跳板 */
    ctx->pages = xcalloc(n_sites, sizeof(uint64_t));
    for (size_t gi = 0; gi < nmaps; gi++) {
        if (!maps[gi].exec)
            continue;
        size_t cnt = 0;
        for (size_t i = 0; i < n_sites; i++)
            if (sites[i].seg == gi)
                cnt++;
        if (!cnt)
            continue;
        uint64_t need = ((cnt * A64_ATOM_BLOCK_SIZE + 0xfff) &
                         ~0xfffULL);
        uint64_t taddr = atomic_find_gap(pid, maps[gi].end, need);
        if (!taddr)
            taddr = atomic_find_gap(pid,
                                    maps[gi].start > need
                                        ? maps[gi].start - need : 0,
                                    need);
        if (!taddr) {
            warn("atomic: no trampoline gap near %#llx, %zu sites "
                 "unpatched", (unsigned long long)maps[gi].start, cnt);
            continue;
        }
        if (inject_syscall(pid, &ctx->regs, SYS_mmap, taddr, need,
                           7 /* RWX */, 0x32 /* PRIVATE|ANON|FIXED */,
                           -1, 0, &ret) < 0 || ret != taddr) {
            warn("atomic: cannot mmap trampoline page at %#llx",
                 (unsigned long long)taddr);
            continue;
        }
        collect_exclude_add(taddr, need);
        for (size_t pg = 0; pg < need / 4096; pg++)
            ctx->pages[ctx->n_pages++] = taddr + pg * 4096;

        size_t o = 0;
        for (size_t i = 0; i < n_sites; i++) {
            if (sites[i].seg != gi)
                continue;
            uint64_t page = taddr + (o / 4096) * 4096;
            uint32_t poff = (o % 4096);
            uint64_t block_abs = page + poff;
            uint64_t state_abs = ctx->abuf_addr + A64_ATB_HDR_SIZE +
                                 i * A64_ATB_STATE_SIZE;
            uint8_t blk[A64_ATOM_BLOCK_SIZE];
            struct a64_atom_counts cnt;
            size_t bl;
            if (sites[i].kind == 2 || sites[i].kind == 3) {
                int size;
                unsigned rt, rn;
                int kind;
                struct a64_ld_addr ad;
                if (!a64_is_plain_load(sites[i].orig_insn, &size, &rt,
                                       &rn, &kind, &ad))
                    continue;
                bl = a64_load_record_block(
                    blk, block_abs, &ad, size, rt, ctx->tls, i,
                    state_abs, ctx->abuf_addr + A64_ATB_OFF_EVENT_PTR,
                    ctx->abuf_addr + A64_ATB_OFF_EVENTS_END,
                    ctx->abuf_addr + A64_ATB_OFF_OVERFLOW,
                    sites[i].pc + 4, &cnt, ctx->record_all);
            } else if (sites[i].kind == 4) {
                bl = a64_cas_record_block(
                    blk, block_abs, sites[i].orig_insn, ctx->tls, i,
                    state_abs,
                    ctx->abuf_addr + A64_ATB_OFF_CAS_EVENT_PTR,
                    ctx->abuf_addr + A64_ATB_OFF_CAS_EVENTS_END,
                    ctx->abuf_addr + A64_ATB_OFF_CAS_OVERFLOW,
                    sites[i].pc + 4, &cnt);
            } else {
                bl = a64_atomic_record_block(
                    blk, block_abs, sites[i].orig_insn, ctx->tls, i,
                    state_abs, ctx->abuf_addr + A64_ATB_OFF_EVENT_PTR,
                    ctx->abuf_addr + A64_ATB_OFF_EVENTS_END,
                    ctx->abuf_addr + A64_ATB_OFF_OVERFLOW,
                    sites[i].pc + 4, &cnt);
            }
            if (!bl) {
                warn("atomic: cannot generate block for %#llx",
                     (unsigned long long)sites[i].pc);
                continue;
            }
            if (i == 0) {
                ctx->base_insns = cnt.base;
                ctx->append_insns = cnt.append;
            }
            if (tmem_rw(pid, 1, block_abs, blk, sizeof(blk)) < 0) {
                warn("atomic: cannot write block at %#llx",
                     (unsigned long long)block_abs);
                continue;
            }
            sites[i].page = page;
            sites[i].page_off = poff;
            o += A64_ATOM_BLOCK_SIZE;
        }
    }

    /* 4. patch 站点 → b <入口> */
    size_t patched = 0;
    for (size_t i = 0; i < n_sites; i++) {
        if (!sites[i].page)
            continue;
        uint32_t w = a64_encode_b(sites[i].pc,
                                  sites[i].page + sites[i].page_off);
        if (!w) {
            warn("atomic: cannot encode branch at %#llx",
                 (unsigned long long)sites[i].pc);
            continue;
        }
        if (tmem_rw(pid, 1, sites[i].pc, &w, 4) < 0) {
            warn("atomic: cannot patch %#llx",
                 (unsigned long long)sites[i].pc);
            continue;
        }
        patched++;
    }
    if (!patched) {
        warn("atomic: no sites patched, disabled");
        goto fail;
    }
    fprintf(stderr, "atomic: armed %zu/%zu ldar sites, buffer %#llx "
            "(%llu MB), %zu pages\n", patched, n_sites,
            (unsigned long long)ctx->abuf_addr,
            (unsigned long long)(buf_size >> 20), ctx->n_pages);

    /* 4.5 目标内 icache/dcache 刷新 (站点 patch 与跳板页生效;
       /proc/pid/mem 写代码页后内核不保证指令缓存一致) */
    {
        size_t n_ranges = patched + ctx->n_pages;
        size_t list_bytes = 8 + n_ranges * 16;
        uint8_t *lst = xcalloc(1, list_bytes);
        uint8_t *lp = lst;
        write_u64(&lp, n_ranges);
        for (size_t i = 0; i < n_sites; i++) {
            if (!sites[i].page)
                continue;
            write_u64(&lp, sites[i].pc & ~0xfffULL);
            write_u64(&lp, (sites[i].pc & ~0xfffULL) + 4096);
        }
        for (size_t i = 0; i < ctx->n_pages; i++) {
            write_u64(&lp, ctx->pages[i]);
            write_u64(&lp, ctx->pages[i] + 4096);
        }
        uint64_t list_abs = ctx->abuf_addr + ctx->abuf_size - 4096;
        if (tmem_rw(pid, 1, list_abs, lst, list_bytes) == 0)
            atomic_flush_ranges(pid, &ctx->regs, list_abs, n_ranges);
        free(lst);
    }

    ctx->armed = 1;
    *ctx_out = ctx;

    /* 5. 侧车文件: sites.bin + ckpt_000000.bin */
    {
        char dir[512];
        snprintf(dir, sizeof(dir), "%s/atomics", ctx->out);
        mkdir(dir, 0755);
        char path[600];
        snprintf(path, sizeof(path), "%s/sites.bin", dir);
        uint8_t *sb = xmalloc(72 + ctx->n_pages * 8 +
                              ctx->n_sites * 16);
        uint8_t *p = sb;
        write_u64(&p, A64_AT_SITES_MAGIC);
        write_u64(&p, 1);
        write_u64(&p, ctx->n_sites);
        write_u64(&p, ctx->abuf_addr);
        write_u64(&p, ctx->abuf_size);
        write_u64(&p, ctx->n_pages);
        write_u64(&p, ctx->base_insns);
        write_u64(&p, ctx->append_insns);
        write_u64(&p, 0);               /* skip 计数暂不用 */
        for (size_t i = 0; i < ctx->n_pages; i++)
            write_u64(&p, ctx->pages[i]);
        for (size_t i = 0; i < ctx->n_sites; i++) {
            write_u64(&p, ctx->sites[i].pc);
            memcpy(p, &ctx->sites[i].orig_insn, 4);
            memcpy(p + 4, &ctx->sites[i].kind, 4);
            p += 8;                 /* 4B orig + 4B pad: 每条 16B */
        }
        FILE *f = fopen(path, "wb");
        if (f) {
            fwrite(sb, 1, (size_t)(p - sb), f);
            fclose(f);
        } else {
            warn("atomic: cannot write %s", path);
        }
        free(sb);
        atomic_trace_ckpt(ctx, 0, 0);   /* 基线行: measured 由后续检查点填 */
    }

    free(maps);
    return 0;
fail:
    /* 尽力恢复: 还原已 patch 的站点, 解除排除区 */
    for (size_t i = 0; i < n_sites; i++) {
        if (!sites[i].page)
            continue;
        tmem_rw(pid, 1, sites[i].pc, &sites[i].orig_insn, 4);
    }
    if (ctx->abuf_addr)
        inject_syscall(pid, &ctx->regs, SYS_munmap, ctx->abuf_addr,
                       ctx->abuf_size, 0, 0, 0, 0, &ret);
    collect_exclude_clear();
    free(ctx->pages);
    free(sites);
    free(maps);
    free(ctx);
    return -1;
}

int atomic_trace_step_out(struct atomic_trace_ctx *ctx)
{
    if (!ctx || !ctx->armed)
        return 0;
    struct user_regs_struct r;
    struct iovec io = {.iov_base = &r, .iov_len = sizeof(r)};
    for (int i = 0; i < 1024; i++) {
        if (ptrace(PTRACE_GETREGSET, ctx->pid, (void *)NT_PRSTATUS,
                   &io) < 0)
            return -1;
        int inside = 0;
        for (size_t k = 0; k < ctx->n_pages; k++) {
            if (REG_PC(r) >= ctx->pages[k] &&
                REG_PC(r) < ctx->pages[k] + 4096) {
                inside = 1;
                break;
            }
        }
        if (!inside)
            return 0;
        if (ptrace(PTRACE_SINGLESTEP, ctx->pid, 0, 0) < 0)
            return -1;
        int st;
        if (waitpid(ctx->pid, &st, 0) < 0 || !WIFSTOPPED(st))
            return -1;
    }
    return -1;
}

int atomic_trace_ckpt(struct atomic_trace_ctx *ctx, size_t ckpt_no,
                      uint64_t measured)
{
    if (!ctx || !ctx->armed)
        return 0;
    size_t state_size = ctx->n_sites * A64_ATB_STATE_SIZE;
    uint8_t *state = xmalloc(state_size);
    if (tmem_rw(ctx->pid, 0, ctx->abuf_addr + A64_ATB_HDR_SIZE,
                state, state_size) < 0) {
        free(state);
        return -1;
    }
    char path[600];
    snprintf(path, sizeof(path), "%s/atomics/ckpt_%06zu.bin",
             ctx->out, ckpt_no);
    uint8_t *sb = xmalloc(24 + state_size);
    uint8_t *p = sb;
    write_u64(&p, A64_AT_CKPT_MAGIC);
    write_u64(&p, 1);
    write_u64(&p, ctx->n_sites);
    memcpy(p, state, state_size);
    FILE *f = fopen(path, "wb");
    int rc = 0;
    if (f) {
        fwrite(sb, 1, 24 + state_size, f);
        fclose(f);
    } else {
        rc = -1;
    }
    free(sb);
    atomic_events_append(ctx);      /* 先补齐事件数, 再统计补偿 */
    /* 补偿: overhead = Σ ord×base + 事件数×append; orig = measured −
       overhead */
    if (ctx->n_ckpts < 1024 * 1024) {
        uint64_t overhead = 0;
        for (size_t i = 0; i < ctx->n_sites; i++) {
            uint64_t ord;
            memcpy(&ord, state + i * A64_ATB_STATE_SIZE, 8);
            overhead += ord * ctx->base_insns;
        }
        overhead += ctx->total_events * ctx->append_insns;
        uint64_t orig = measured > overhead ? measured - overhead : measured;
        ctx->ckpt_measured = xrealloc(ctx->ckpt_measured,
                                      (ctx->n_ckpts + 1) * sizeof(uint64_t));
        ctx->ckpt_overhead = xrealloc(ctx->ckpt_overhead,
                                      (ctx->n_ckpts + 1) * sizeof(uint64_t));
        ctx->ckpt_orig = xrealloc(ctx->ckpt_orig,
                                  (ctx->n_ckpts + 1) * sizeof(uint64_t));
        ctx->ckpt_measured[ctx->n_ckpts] = measured;
        ctx->ckpt_overhead[ctx->n_ckpts] = overhead;
        ctx->ckpt_orig[ctx->n_ckpts] = orig;
        ctx->n_ckpts++;
    }
    free(state);
    return rc;
}

/* 增量转储事件: 把 [dump_event_ptr, event_ptr) 追加到 events.bin
 * (目标可能在任何时候退出, 不能只靠 finish 读缓冲区)。 */
struct evfile_hdr {
    uint64_t magic, version, n_events, bytes;
};

static int atomic_events_append(struct atomic_trace_ctx *ctx)
{
    char path[600];
    snprintf(path, sizeof(path), "%s/atomics/events.bin", ctx->out);
    uint64_t event_ptr = 0, events_base = 0, overflow = 0;
    if (tmem_rw(ctx->pid, 0, ctx->abuf_addr + A64_ATB_OFF_EVENT_PTR,
                &event_ptr, 8) < 0)
        return -1;
    tmem_rw(ctx->pid, 0, ctx->abuf_addr + A64_ATB_OFF_OVERFLOW,
            &overflow, 8);
    events_base = ctx->abuf_addr + A64_ATB_HDR_SIZE +
                  ctx->n_sites * A64_ATB_STATE_SIZE;
    if (ctx->dump_event_ptr == 0)
        ctx->dump_event_ptr = events_base;
    if (event_ptr < ctx->dump_event_ptr)
        event_ptr = ctx->dump_event_ptr;    /* 目标重启等异常: 防回退 */
    uint64_t n_new = (event_ptr - ctx->dump_event_ptr) / A64_ATB_EVENT_SIZE;

    uint64_t total = 0;
    FILE *f = fopen(path, "r+b");
    if (!f) {
        f = fopen(path, "wb");
        if (!f)
            return -1;
        struct evfile_hdr hdr = {A64_AT_EVENTS_MAGIC, 1, 0, 0};
        fwrite(&hdr, sizeof(hdr), 1, f);
    } else {
        struct evfile_hdr hdr;
        if (fread(&hdr, sizeof(hdr), 1, f) == 1 &&
            hdr.magic == A64_AT_EVENTS_MAGIC && hdr.version == 1)
            total = hdr.n_events;
    }
    if (n_new) {
        uint8_t *ev = xmalloc(n_new * A64_ATB_EVENT_SIZE);
        if (tmem_rw(ctx->pid, 0, ctx->dump_event_ptr, ev,
                    n_new * A64_ATB_EVENT_SIZE) == 0) {
            fseek(f, 0, SEEK_END);
            fwrite(ev, 1, n_new * A64_ATB_EVENT_SIZE, f);
            ctx->dump_event_ptr += n_new * A64_ATB_EVENT_SIZE;
            total += n_new;
        }
        free(ev);
    }
    /* 更新头: n_events */
    {
        struct evfile_hdr hdr = {A64_AT_EVENTS_MAGIC, 1, total,
                                 total * A64_ATB_EVENT_SIZE};
        fseek(f, 0, SEEK_SET);
        fwrite(&hdr, sizeof(hdr), 1, f);
    }
    fclose(f);
    ctx->total_events = total;
    if (overflow)
        fprintf(stderr, "atomic: event buffer overflow flag set\n");

    /* CAS 事件区 (56B/事件) → cas_events.bin */
    {
        char cpath[600];
        snprintf(cpath, sizeof(cpath), "%s/atomics/cas_events.bin",
                 ctx->out);
        uint64_t cas_ptr = 0, cas_overflow = 0;
        uint64_t cas_base = ctx->abuf_addr + ctx->abuf_size / 2;
        if (tmem_rw(ctx->pid, 0,
                    ctx->abuf_addr + A64_ATB_OFF_CAS_EVENT_PTR,
                    &cas_ptr, 8) < 0)
            return 0;
        tmem_rw(ctx->pid, 0,
                ctx->abuf_addr + A64_ATB_OFF_CAS_OVERFLOW,
                &cas_overflow, 8);
        if (ctx->cas_dump_ptr == 0)
            ctx->cas_dump_ptr = cas_base;
        if (cas_ptr < ctx->cas_dump_ptr)
            cas_ptr = ctx->cas_dump_ptr;
        uint64_t n_cas = (cas_ptr - ctx->cas_dump_ptr) / 56;
        uint64_t ctotal = 0;
        FILE *cf = fopen(cpath, "r+b");
        if (!cf) {
            cf = fopen(cpath, "wb");
            if (!cf)
                return 0;
            struct evfile_hdr hdr = {A64_AT_CAS_EVENTS_MAGIC, 1, 0, 0};
            fwrite(&hdr, sizeof(hdr), 1, cf);
        } else {
            struct evfile_hdr hdr;
            if (fread(&hdr, sizeof(hdr), 1, cf) == 1 &&
                hdr.magic == A64_AT_CAS_EVENTS_MAGIC && hdr.version == 1)
                ctotal = hdr.n_events;
        }
        if (n_cas) {
            uint8_t *cev = xmalloc(n_cas * 56);
            if (tmem_rw(ctx->pid, 0, ctx->cas_dump_ptr, cev,
                        n_cas * 56) == 0) {
                fseek(cf, 0, SEEK_END);
                fwrite(cev, 1, n_cas * 56, cf);
                ctx->cas_dump_ptr += n_cas * 56;
                ctotal += n_cas;
            }
            free(cev);
        }
        {
            struct evfile_hdr hdr = {A64_AT_CAS_EVENTS_MAGIC, 1, ctotal,
                                     ctotal * 56};
            fseek(cf, 0, SEEK_SET);
            fwrite(&hdr, sizeof(hdr), 1, cf);
        }
        fclose(cf);
        ctx->total_cas_events = ctotal;
        if (cas_overflow)
            fprintf(stderr, "atomic: CAS event buffer overflow flag set\n");
    }
    return 0;
}

/* 读取 Run 1 的 compensation.txt (r_num/r_den) */
int atomic_trace_load_compensation(const char *path, uint64_t *r_num,
                                   uint64_t *r_den)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    char line[256];
    uint64_t num = 0, den = 0;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "r_num %llu", (unsigned long long *)&num) == 1)
            continue;
        if (sscanf(line, "r_den %llu", (unsigned long long *)&den) == 1)
            continue;
    }
    fclose(f);
    if (!num || !den || num < den)
        return -1;
    *r_num = num;
    *r_den = den;
    return 0;
}

/* 写出补偿结果 (Run 1 产物): r = 最后检查点的 measured/orig */
static void atomic_write_compensation(struct atomic_trace_ctx *ctx)
{
    if (!ctx->n_ckpts)
        return;
    char path[600];
    snprintf(path, sizeof(path), "%s/atomics/compensation.txt", ctx->out);
    FILE *f = fopen(path, "w");
    if (!f)
        return;
    uint64_t m = ctx->ckpt_measured[ctx->n_ckpts - 1];
    uint64_t o = ctx->ckpt_orig[ctx->n_ckpts - 1];
    fprintf(f, "# elftrace atomic compensation v1\n");
    fprintf(f, "r_num %llu\n", (unsigned long long)m);
    fprintf(f, "r_den %llu\n", (unsigned long long)o);
    fprintf(f, "base_insns %u\n", ctx->base_insns);
    fprintf(f, "append_insns %u\n", ctx->append_insns);
    fprintf(f, "# idx measured overhead orig\n");
    for (size_t i = 0; i < ctx->n_ckpts; i++) {
        fprintf(f, "%zu %llu %llu %llu\n", i,
                (unsigned long long)ctx->ckpt_measured[i],
                (unsigned long long)ctx->ckpt_overhead[i],
                (unsigned long long)ctx->ckpt_orig[i]);
    }
    fclose(f);
    fprintf(stderr, "atomic: compensation r=%llu/%llu (R_est=%.2f%%), "
            "%zu checkpoints\n",
            (unsigned long long)m, (unsigned long long)o,
            o ? 100.0 * (double)(m - o) / (double)m : 0.0, ctx->n_ckpts);
}

/* 结束: INTERRUPT 停止 → 转储事件 → 恢复站点 → munmap 缓冲区 */
int atomic_trace_finish(struct atomic_trace_ctx *ctx)
{
    if (!ctx || !ctx->armed)
        return 0;
    pid_t pid = ctx->pid;

    atomic_write_compensation(ctx);

    /* 停止目标 (处理 syscall-stop 后再 INTERRUPT) */
    int stopped = 0;
    for (int i = 0; i < 16; i++) {
        if (ptrace(PTRACE_INTERRUPT, pid, 0, 0) < 0) {
            if (errno == ESRCH)
                return 0;
            /* 可能已处于 ptrace-stop: 验证后继续 */
            struct user_regs_struct rr;
            struct iovec io = {.iov_base = &rr, .iov_len = sizeof(rr)};
            if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS,
                       &io) == 0) {
                stopped = 1;
                break;
            }
            break;
        }
        int st;
        int got = 0;
        for (int w = 0; w < 25000; w++) {
            pid_t wr = waitpid(pid, &st, WNOHANG);
            if (wr == pid) {
                got = 1;
                break;
            }
            if (wr < 0)
                break;
            usleep(200);
        }
        if (!got || !WIFSTOPPED(st))
            break;
        if (WSTOPSIG(st) == (SIGTRAP | 0x80)) {
            ptrace(PTRACE_SYSCALL, pid, 0, 0);
            continue;
        }
        if (WSTOPSIG(st) == SIGTRAP) {
            stopped = 1;
            break;
        }
        ptrace(PTRACE_SYSCALL, pid, 0, WSTOPSIG(st));
    }
    if (!stopped)
        return -1;
    if (kill(pid, 0) < 0 && errno == ESRCH)
        return 0;
    atomic_trace_step_out(ctx);

    /* 转储剩余事件 (增量文件已含各检查点前的事件) */
    atomic_events_append(ctx);

    /* 恢复站点原指令 */
    for (size_t i = 0; i < ctx->n_sites; i++) {
        if (ctx->sites[i].page)
            tmem_rw(pid, 1, ctx->sites[i].pc,
                    &ctx->sites[i].orig_insn, 4);
    }
    /* 刷新站点范围的 I-cache: 只恢复数据不失效缓存, 目标会继续执行
       缓存的跳转指令 (跳到已恢复/已解映射的跳板) → SIGSEGV。 */
    {
        uint64_t lo = ~0ULL, hi = 0;
        for (size_t i = 0; i < ctx->n_sites; i++) {
            uint64_t pc = ctx->sites[i].pc;
            if (pc < lo)
                lo = pc;
            if (pc > hi)
                hi = pc;
        }
        if (hi >= lo)
            inject_flush_icache(pid, &ctx->regs, lo & ~0x3fULL,
                                (size_t)(hi - lo) + 0x80);
    }
    /* 解除缓冲区 (记录页保留: 其他线程可能正在执行, 解映射会崩) */
    {
        uint64_t ret = 0;
        inject_syscall(pid, &ctx->regs, SYS_munmap, ctx->abuf_addr,
                       ctx->abuf_size, 0, 0, 0, 0, &ret);
    }
    collect_exclude_clear();
    return 0;
}

#else /* !__aarch64__ */

int atomic_trace_arm(struct atomic_trace_ctx **ctx_out, pid_t pid,
                     const void *regs, const char *out, uint64_t buf_size,
                     const char *value_sites, int record_all)
{
    (void)ctx_out; (void)pid; (void)regs; (void)out; (void)buf_size;
    (void)value_sites;
    (void)record_all;
    return -1;
}
int atomic_trace_step_out(struct atomic_trace_ctx *ctx)
{
    (void)ctx;
    return 0;
}
int atomic_trace_ckpt(struct atomic_trace_ctx *ctx, size_t ckpt_no,
                      uint64_t measured)
{
    (void)ctx; (void)ckpt_no; (void)measured;
    return 0;
}
int atomic_trace_finish(struct atomic_trace_ctx *ctx)
{
    (void)ctx;
    return 0;
}

#endif
