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
    size_t seg;                 /* 所属可执行段索引 */
    uint64_t page;              /* 记录页地址 */
    uint32_t page_off;          /* 块偏移 */
};

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
};

int inject_run_snippet(pid_t pid, const struct user_regs_struct *regs,
                       const uint32_t *code, size_t ninsn, uint64_t *ret0);
int inject_syscall(pid_t pid, const struct user_regs_struct *regs,
                   uint64_t nr, uint64_t a0, uint64_t a1, uint64_t a2,
                   uint64_t a3, uint64_t a4, uint64_t a5, uint64_t *ret);

#define SYS_mmap       222
#define SYS_munmap     215

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

/* 扫描目标可执行段中的 ldar 站点 */
static int atomic_scan(pid_t pid, struct asite **out, size_t *n_out,
                       struct seginfo **segs_out, size_t *nsegs_out)
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
            int is64;
            unsigned rt, rn;
            if (!a64_is_ldar(w, &is64, &rt, &rn))
                continue;
            if (rt == 31)
                continue;       /* 目标 xzr: 罕见, 跳过 */
            if (n == cap) {
                cap = cap ? cap * 2 : 64;
                sites = xrealloc(sites, cap * sizeof(*sites));
            }
            sites[n].pc = sg->start + off;
            sites[n].orig_insn = w;
            sites[n].seg = i;
            n++;
        }
        free(buf);
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

int atomic_trace_arm(struct atomic_trace_ctx **ctx_out, pid_t pid,
                     const void *regs, const char *out, uint64_t buf_size)
{
    struct atomic_trace_ctx *ctx = xcalloc(1, sizeof(*ctx));
    struct asite *sites = NULL;
    size_t n_sites = 0;
    struct seginfo *maps = NULL;
    size_t nmaps = 0;
    int rc = -1;
    uint64_t ret = 0;

    if (!buf_size)
        buf_size = 64UL << 20;
    snprintf(ctx->out, sizeof(ctx->out), "%s", out);
    ctx->pid = pid;
    ctx->regs = *(const struct user_regs_struct *)regs;
    ctx->tls = collect_get_tls();
    if (!ctx->tls) {
        warn("atomic: no TPIDR_EL0 for target, atomic replay disabled");
        free(ctx);
        return -1;
    }
    if (atomic_scan(pid, &sites, &n_sites, &maps, &nmaps) < 0) {
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
        write_u64(&p, A64_ATB_MAGIC);
        write_u64(&p, A64_ATB_VERSION);
        write_u64(&p, n_sites);
        write_u64(&p, state_off);
        write_u64(&p, events_off);
        write_u64(&p, ctx->abuf_addr + events_off);
        write_u64(&p, ctx->abuf_addr + buf_size);
        write_u64(&p, 0);
        write_u64(&p, buf_size);
        if (tmem_rw(pid, 1, ctx->abuf_addr, hdr, sizeof(hdr)) < 0) {
            warn("atomic: cannot init event buffer");
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
            size_t bl = a64_atomic_record_block(
                blk, block_abs, sites[i].orig_insn, ctx->tls, i,
                state_abs, ctx->abuf_addr + A64_ATB_OFF_EVENT_PTR,
                ctx->abuf_addr + A64_ATB_OFF_EVENTS_END,
                ctx->abuf_addr + A64_ATB_OFF_OVERFLOW,
                sites[i].pc + 4);
            if (!bl) {
                warn("atomic: cannot generate block for %#llx",
                     (unsigned long long)sites[i].pc);
                continue;
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

    ctx->armed = 1;
    *ctx_out = ctx;

    /* 5. 侧车文件: sites.bin + ckpt_000000.bin */
    {
        char dir[512];
        snprintf(dir, sizeof(dir), "%s/atomics", ctx->out);
        mkdir(dir, 0755);
        char path[600];
        snprintf(path, sizeof(path), "%s/sites.bin", dir);
        uint8_t *sb = xmalloc(32 + ctx->n_pages * 8 +
                              ctx->n_sites * 16);
        uint8_t *p = sb;
        write_u64(&p, A64_AT_SITES_MAGIC);
        write_u64(&p, 1);
        write_u64(&p, ctx->n_sites);
        write_u64(&p, ctx->abuf_addr);
        write_u64(&p, ctx->abuf_size);
        write_u64(&p, ctx->n_pages);
        for (size_t i = 0; i < ctx->n_pages; i++)
            write_u64(&p, ctx->pages[i]);
        for (size_t i = 0; i < ctx->n_sites; i++) {
            write_u64(&p, ctx->sites[i].pc);
            memcpy(p, &ctx->sites[i].orig_insn, 4);
            p += 4;                 /* 无 pad: 每条 16B */
        }
        FILE *f = fopen(path, "wb");
        if (f) {
            fwrite(sb, 1, (size_t)(p - sb), f);
            fclose(f);
        } else {
            warn("atomic: cannot write %s", path);
        }
        free(sb);
        atomic_trace_ckpt(ctx, 0);
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

int atomic_trace_ckpt(struct atomic_trace_ctx *ctx, size_t ckpt_no)
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
    free(state);
    return rc;
}

/* 结束: INTERRUPT 停止 → 转储事件 → 恢复站点 → munmap 缓冲区 */
int atomic_trace_finish(struct atomic_trace_ctx *ctx)
{
    if (!ctx || !ctx->armed)
        return 0;
    pid_t pid = ctx->pid;

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
        if (waitpid(pid, &st, 0) < 0 || !WIFSTOPPED(st))
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

    /* 转储事件 */
    {
        uint64_t event_ptr = 0, overflow = 0;
        tmem_rw(pid, 0, ctx->abuf_addr + A64_ATB_OFF_EVENT_PTR,
                &event_ptr, 8);
        tmem_rw(pid, 0, ctx->abuf_addr + A64_ATB_OFF_OVERFLOW,
                &overflow, 8);
        uint64_t events_base = ctx->abuf_addr + A64_ATB_HDR_SIZE +
                               ctx->n_sites * A64_ATB_STATE_SIZE;
        uint64_t n_ev = event_ptr > events_base
                            ? (event_ptr - events_base) / A64_ATB_EVENT_SIZE
                            : 0;
        char path[600];
        snprintf(path, sizeof(path), "%s/atomics/events.bin", ctx->out);
        uint8_t *eb = xmalloc(24 + n_ev * A64_ATB_EVENT_SIZE);
        uint8_t *p = eb;
        write_u64(&p, A64_AT_EVENTS_MAGIC);
        write_u64(&p, 1);
        write_u64(&p, n_ev);
        write_u64(&p, n_ev * A64_ATB_EVENT_SIZE);
        if (n_ev &&
            tmem_rw(pid, 0, events_base, p, n_ev * A64_ATB_EVENT_SIZE) < 0)
            warn("atomic: cannot read event buffer");
        FILE *f = fopen(path, "wb");
        if (f) {
            fwrite(eb, 1, 24 + n_ev * A64_ATB_EVENT_SIZE, f);
            fclose(f);
        } else {
            warn("atomic: cannot write %s", path);
        }
        free(eb);
        fprintf(stderr, "atomic: dumped %llu events%s\n",
                (unsigned long long)n_ev,
                overflow ? " (BUFFER OVERFLOW)" : "");
    }

    /* 恢复站点原指令 */
    for (size_t i = 0; i < ctx->n_sites; i++) {
        if (ctx->sites[i].page)
            tmem_rw(pid, 1, ctx->sites[i].pc,
                    &ctx->sites[i].orig_insn, 4);
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
                     const void *regs, const char *out, uint64_t buf_size)
{
    (void)ctx_out; (void)pid; (void)regs; (void)out; (void)buf_size;
    return -1;
}
int atomic_trace_step_out(struct atomic_trace_ctx *ctx)
{
    (void)ctx;
    return 0;
}
int atomic_trace_ckpt(struct atomic_trace_ctx *ctx, size_t ckpt_no)
{
    (void)ctx; (void)ckpt_no;
    return 0;
}
int atomic_trace_finish(struct atomic_trace_ctx *ctx)
{
    (void)ctx;
    return 0;
}

#endif
