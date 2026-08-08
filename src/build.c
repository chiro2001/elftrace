/*
 * elftrace build: ELF 组装器
 *
 * 读取 .elftrace, 生成一个可执行 ELF (ET_EXEC, x86_64):
 *   - 将恢复 stub blob (RWX) 放入目标进程地址空间的一个空闲 gap
 *   - 在 blob 的 desc 中填入目标 rip / seg 表 / fd 表 / fpu 大小等
 *   - 段内容 (payload) 与 fd 表/字符串作为数据追加在 blob 之后
 *   - 从 aux 记录重建调试节 (.debug_*, .symtab, .strtab), 使 gdb 可用
 * 加载并执行生成的 ELF 时, stub 恢复内存/寄存器/fd 后跳转到目标 rip。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <elf.h>
#include <sys/stat.h>

#include "elftrace.h"
#include "elftrace_stub.h"
#include "collect.h"
#include "bundle.h"
#include "util.h"
#include "disasm.h"
#include "arch.h"
#include "a64.h"
#include "atomic_a64.h"

/* ---- 生成的 stub blob (按目标架构选择) ---- */
extern const unsigned char stub_blob_x86_64[];
extern const unsigned int stub_blob_x86_64_len;
#if defined(__aarch64__)
extern const unsigned char stub_blob_aarch64[];
extern const unsigned int stub_blob_aarch64_len;
#endif


/* ---- 可扩展缓冲 (同 freeze) ---- */
struct buf {
    uint8_t *data;
    size_t size;
    size_t cap;
};

static void buf_init(struct buf *b)
{
    memset(b, 0, sizeof(*b));
}

static void buf_reserve(struct buf *b, size_t extra)
{
    if (b->size + extra > b->cap) {
        size_t ncap = b->cap ? b->cap * 2 : 65536;
        while (ncap < b->size + extra)
            ncap *= 2;
        b->data = xrealloc(b->data, ncap);
        b->cap = ncap;
    }
}

static void buf_append(struct buf *b, const void *data, size_t size)
{
    buf_reserve(b, size);
    memcpy(b->data + b->size, data, size);
    b->size += size;
}

static void buf_zero(struct buf *b, size_t size)
{
    uint8_t z[512];
    size_t chunk = sizeof(z);

    while (size) {
        size_t n = size < chunk ? size : chunk;
        memset(z, 0, n);
        buf_append(b, z, n);
        size -= n;
    }
}

/* ---- .elftrace 读取 ---- */
struct snap {
    elftrace_hdr h;
    uint8_t *file;              /* 整个文件映像 */
    size_t file_size;
    uint64_t fpu_size;
    uint64_t ipc_period;
};

static const char *sn_str(const struct snap *s, uint64_t off)
{
    if (off >= s->h.strings_size)
        return "";
    return (const char *)s->file + s->h.strings_off + off;
}

/* 回放记录 (build_main 解析 syscall.map 后的内存形态) */
struct rec_tmp {
    uint64_t pc, sysno, rax;
    uint64_t n_unmap, n_newseg, n_dirty;
    struct buf unmap, newseg, dirty;
};

/* strict 模式下的额外 PT_LOAD (由 ELF 组装段发射) */
struct strict_pload {
    uint64_t vaddr;
    uint64_t filesz;
    uint64_t memsz;
    uint64_t flags;             /* PF_* */
    uint64_t file_off;          /* 由组装段回填 */
    const uint8_t *data;        /* filesz>0 时的文件数据 (NULL=纯 BSS) */
};

#if defined(__aarch64__)
/* ===================== strict baremetal (ELF loader 型) =====================
 *
 * 目标: 切片运行期除开始 execve / 结束 exit_group 外无任何 syscall。
 * 方案:
 *   - 全部内存 (初始段 + 切片窗口内未来 newseg + 栈预留 + 跳板页)
 *     用 PT_LOAD 由 ELF loader 建立, stub 不再 mmap/mprotect。
 *   - 目标代码中的 svc #0 定点替换为 b <跳板>; 跳板 ldr x16+br 到
 *     blob 内的站点块, comp 引擎保存现场 → 应用回放差异 (纯访存) →
 *     伪造 x0 → 恢复现场 (仅 x16 被约定破坏) → 回到 svc 下一条。
 *   - 退出点: 唯一路径 → 指令替换为 b <exit 跳板>; 循环内 → patch
 *     回边 → b <loop 跳板>, 跳板 counter 决定何时退出。
 *   - 结束 = 真实 exit_group (允许)。
 */

struct strict_site {
    uint64_t pc;                /* 被 patch 的指令地址 */
    int kind;                   /* 0=syscall 1=exit 2=loop 3=count 4=atomic */
    uint64_t head;              /* loop: 循环头 */
    uint64_t tramp_addr;        /* 跳板入口 */
    uint64_t block_addr;        /* 站点块/循环描述块 (blob 绝对地址) */
    int rec_id;                 /* syscall: 回放记录号 (-1=mock) */
    size_t ab_id;               /* atomic: 原子站点索引 */
    uint64_t ab_run_off;        /* atomic: 运行表在 blob 内的偏移 */
};

/* ---- trace --atomic-replay 侧车 (atomics/) ---- */
struct ab_site {
    uint64_t pc;
    uint32_t orig_insn;
    uint64_t from_ord, to_ord;  /* 窗口内序号边界 */
};
struct ab_run {
    uint64_t start;             /* 窗口内起始序号 (1-based) */
    uint64_t addr, value;
};
struct atomic_build {
    int have;
    struct ab_site *sites;
    size_t n_sites;
    struct ab_run *runs;
    size_t n_runs;
    size_t *run_off;            /* 站点 i 的 runs 起始索引 */
    size_t *run_cnt;
};

static uint64_t rd_u64(const uint8_t **p)
{
    uint64_t v;
    memcpy(*p, &v, 8);
    *p += 8;
    return v;
}

/* 读取 <dir>/atomics/ 侧车; 成功置 ab->have=1。窗口 = [from,to]。 */
static void atomic_load(const char *dir, long from, long to,
                        struct atomic_build *ab)
{
    char path[PATH_MAX];
    uint8_t *buf = NULL;
    size_t sz = 0;
    uint64_t n_sites = 0;

    memset(ab, 0, sizeof(*ab));
    snprintf(path, sizeof(path), "%s/atomics/sites.bin", dir);
    {
        FILE *f = fopen(path, "rb");
        if (!f)
            return;
        fseek(f, 0, SEEK_END);
        sz = (size_t)ftell(f);
        fseek(f, 0, SEEK_SET);
        buf = xmalloc(sz ? sz : 1);
        if (fread(buf, 1, sz, f) != sz) {
            fclose(f);
            free(buf);
            return;
        }
        fclose(f);
    }
    const uint8_t *p = buf;
    const uint8_t *end = buf + sz;
    if (end - p < 40 || rd_u64(&p) != A64_AT_SITES_MAGIC)
        goto bad;
    if (rd_u64(&p) != 1)
        goto bad;
    n_sites = rd_u64(&p);
    uint64_t buf_addr = rd_u64(&p);
    uint64_t buf_size = rd_u64(&p);
    uint64_t n_pages = rd_u64(&p);
    (void)buf_addr; (void)buf_size;
    if (n_sites > 100000 || n_pages > 100000)
        goto bad;
    if (end - p < n_pages * 8 + n_sites * 16)
        goto bad;
    p += n_pages * 8;
    ab->sites = xcalloc(n_sites, sizeof(*ab->sites));
    ab->n_sites = n_sites;
    for (size_t i = 0; i < n_sites; i++) {
        ab->sites[i].pc = rd_u64(&p);
        memcpy(&ab->sites[i].orig_insn, p, 4);
        p += 4;
    }
    free(buf);

    /* 窗口边界: 从 ckpt 快照读每站点 ordinal */
    {
        char ck[PATH_MAX];
        snprintf(ck, sizeof(ck), "%s/atomics/ckpt_%06ld.bin", dir, from);
        FILE *f = fopen(ck, "rb");
        if (!f) {
            warn("atomic: missing %s", ck);
            goto bad2;
        }
        uint8_t hdr[24];
        if (fread(hdr, 1, 24, f) != 24) {
            fclose(f);
            goto bad2;
        }
        const uint8_t *hp = hdr;
        if (rd_u64(&hp) != A64_AT_CKPT_MAGIC || rd_u64(&hp) != 1) {
            fclose(f);
            goto bad2;
        }
        uint64_t ns = rd_u64(&hp);
        if (ns != n_sites) {
            fclose(f);
            goto bad2;
        }
        uint8_t *st = xmalloc(n_sites * 24);
        if (fread(st, 1, n_sites * 24, f) != n_sites * 24) {
            fclose(f);
            free(st);
            goto bad2;
        }
        fclose(f);
        for (size_t i = 0; i < n_sites; i++) {
            const uint8_t *q = st + i * 24;
            ab->sites[i].from_ord = rd_u64(&q);
        }
        free(st);

        snprintf(ck, sizeof(ck), "%s/atomics/ckpt_%06ld.bin", dir, to);
        f = fopen(ck, "rb");
        if (!f) {
            warn("atomic: missing %s", ck);
            goto bad2;
        }
        if (fread(hdr, 1, 24, f) != 24) {
            fclose(f);
            goto bad2;
        }
        hp = hdr;
        if (rd_u64(&hp) != A64_AT_CKPT_MAGIC || rd_u64(&hp) != 1 ||
            rd_u64(&hp) != n_sites) {
            fclose(f);
            goto bad2;
        }
        st = xmalloc(n_sites * 24);
        if (fread(st, 1, n_sites * 24, f) != n_sites * 24) {
            fclose(f);
            free(st);
            goto bad2;
        }
        fclose(f);
        for (size_t i = 0; i < n_sites; i++) {
            const uint8_t *q = st + i * 24;
            ab->sites[i].to_ord = rd_u64(&q);
        }
        free(st);
    }

    /* 事件 → 每站点运行段 (窗口内) */
    snprintf(path, sizeof(path), "%s/atomics/events.bin", dir);
    {
        FILE *f = fopen(path, "rb");
        if (f) {
            fseek(f, 0, SEEK_END);
            long esz = ftell(f);
            fseek(f, 0, SEEK_SET);
            uint8_t *eb = xmalloc(esz > 0 ? (size_t)esz : 1);
            if (fread(eb, 1, (size_t)esz, f) == (size_t)esz) {
                const uint8_t *ep = eb;
                const uint8_t *ee = eb + esz;
                if (ee - ep >= 24 && rd_u64(&ep) == A64_AT_EVENTS_MAGIC &&
                    rd_u64(&ep) == 1) {
                    uint64_t n_ev = rd_u64(&ep);
                    if (ee - ep >= (long)(n_ev * 32)) {
                        ab->runs = xmalloc((n_ev ? n_ev : 1) *
                                           sizeof(*ab->runs));
                        size_t nr = 0;
                        for (uint64_t k = 0; k < n_ev; k++) {
                            uint64_t site_id = rd_u64(&ep);
                            uint64_t ord = rd_u64(&ep);
                            uint64_t addr = rd_u64(&ep);
                            uint64_t value = rd_u64(&ep);
                            if (site_id >= n_sites)
                                continue;
                            if (ord <= ab->sites[site_id].from_ord ||
                                ord > ab->sites[site_id].to_ord)
                                continue;
                            ab->runs[nr].start = ord -
                                                 ab->sites[site_id].from_ord;
                            ab->runs[nr].addr = addr;
                            ab->runs[nr].value = value;
                            nr++;
                        }
                        ab->n_runs = nr;
                    }
                }
            }
            free(eb);
            fclose(f);
        }
    }
    /* 事件 → 每站点运行段 (窗口内, 全局有序 → 每站点单调) */
    {
        ab->run_off = xcalloc(n_sites ? n_sites : 1, sizeof(size_t));
        ab->run_cnt = xcalloc(n_sites ? n_sites : 1, sizeof(size_t));
        /* 先统计每站点窗口事件数 (事件全局有序, 站点内单调) */
        snprintf(path, sizeof(path), "%s/atomics/events.bin", dir);
        FILE *f = fopen(path, "rb");
        if (!f)
            goto no_runs;
        {
            fseek(f, 0, SEEK_END);
            long esz = ftell(f);
            fseek(f, 0, SEEK_SET);
            uint8_t *eb = xmalloc(esz > 0 ? (size_t)esz : 1);
            if (fread(eb, 1, (size_t)esz, f) == (size_t)esz) {
                const uint8_t *ep = eb;
                const uint8_t *ee = eb + esz;
                if (ee - ep >= 24 && rd_u64(&ep) == A64_AT_EVENTS_MAGIC &&
                    rd_u64(&ep) == 1) {
                    uint64_t n_ev = rd_u64(&ep);
                    size_t total = 0;
                    for (uint64_t k = 0; k < n_ev && ee - ep >= 32; k++) {
                        uint64_t site_id = rd_u64(&ep);
                        uint64_t ord = rd_u64(&ep);
                        rd_u64(&ep);            /* addr */
                        rd_u64(&ep);            /* value */
                        if (site_id >= n_sites)
                            continue;
                        if (ord <= ab->sites[site_id].from_ord ||
                            ord > ab->sites[site_id].to_ord)
                            continue;
                        ab->run_cnt[site_id]++;
                        total++;
                    }
                    size_t acc = 0;
                    for (size_t i = 0; i < n_sites; i++) {
                        ab->run_off[i] = acc;
                        acc += ab->run_cnt[i];
                    }
                    ab->runs = xmalloc((total ? total : 1) *
                                       sizeof(*ab->runs));
                    ab->n_runs = total;
                    /* 第二遍填内容 (位置由 run_off + 已计数偏移) */
                    size_t *filled = xcalloc(n_sites ? n_sites : 1,
                                             sizeof(size_t));
                    ep = eb + 24;
                    for (uint64_t k = 0; k < n_ev && ee - ep >= 32; k++) {
                        uint64_t site_id = rd_u64(&ep);
                        uint64_t ord = rd_u64(&ep);
                        uint64_t addr = rd_u64(&ep);
                        uint64_t value = rd_u64(&ep);
                        if (site_id >= n_sites)
                            continue;
                        if (ord <= ab->sites[site_id].from_ord ||
                            ord > ab->sites[site_id].to_ord)
                            continue;
                        size_t o = ab->run_off[site_id] + filled[site_id]++;
                        ab->runs[o].start = ord -
                                            ab->sites[site_id].from_ord;
                        ab->runs[o].addr = addr;
                        ab->runs[o].value = value;
                    }
                    free(filled);
                }
            }
            free(eb);
        }
        fclose(f);
    }

    if (ab->n_runs == 0)
        fprintf(stderr, "atomic: %zu sites, no window events "
                "(replay not applied)\n", (size_t)n_sites);
    else
        fprintf(stderr, "atomic: %zu sites, %zu window run segments\n",
                (size_t)n_sites, ab->n_runs);
    ab->have = 1;
    return;
no_runs:
    if (ab->n_runs == 0)
        fprintf(stderr, "atomic: no events.bin, replay not applied\n");
    ab->have = 1;
    return;
bad:
    free(buf);
bad2:
    free(ab->sites);
    memset(ab, 0, sizeof(*ab));
}

static void spload_add(struct strict_pload **pl, size_t *n, size_t *cap,
                       uint64_t vaddr, uint64_t memsz, uint64_t flags)
{
    if (!memsz)
        return;
    if (*n == *cap) {
        *cap = *cap ? *cap * 2 : 16;
        *pl = xrealloc(*pl, *cap * sizeof(**pl));
    }
    struct strict_pload *p = &(*pl)[(*n)++];
    memset(p, 0, sizeof(*p));
    p->vaddr = vaddr;
    p->memsz = memsz;
    p->flags = flags;
}

/* 区间 [vaddr, vaddr+memsz) 是否已被初始段或已有 pload 覆盖 */
static int range_covered(const elftrace_seg *segs, size_t nsegs,
                         const struct strict_pload *pl, size_t npl,
                         uint64_t vaddr, uint64_t memsz)
{
    uint64_t end = vaddr + memsz;
    for (size_t i = 0; i < nsegs; i++) {
        uint64_t se = segs[i].vaddr + segs[i].memsz;
        if (vaddr >= segs[i].vaddr && end <= se)
            return 1;
    }
    for (size_t i = 0; i < npl; i++) {
        uint64_t pe = pl[i].vaddr + pl[i].memsz;
        if (vaddr >= pl[i].vaddr && end <= pe)
            return 1;
    }
    return 0;
}

/* 在 [near, near+128MB) 中找一个能容纳 size 的空闲页对齐区间 */
static uint64_t find_gap_near(const elftrace_seg *segs, size_t nsegs,
                              const struct strict_pload *pl, size_t npl,
                              uint64_t near, uint64_t size)
{
    uint64_t cur = (near + 0xfff) & ~0xfffULL;
    uint64_t lim = near + (128UL << 20);
    while (cur + size <= lim) {
        uint64_t end = cur + size;
        int busy = 0;
        for (size_t i = 0; i < nsegs; i++) {
            if (cur < segs[i].vaddr + segs[i].memsz &&
                end > segs[i].vaddr) {
                busy = 1;
                cur = (segs[i].vaddr + segs[i].memsz + 0xfff) & ~0xfffULL;
                break;
            }
        }
        if (busy)
            continue;
        for (size_t i = 0; i < npl; i++) {
            if (cur < pl[i].vaddr + pl[i].memsz && end > pl[i].vaddr) {
                busy = 1;
                cur = (pl[i].vaddr + pl[i].memsz + 0xfff) & ~0xfffULL;
                break;
            }
        }
        if (!busy)
            return cur;
    }
    return 0;
}

/* aarch64: svc 前 128 条指令内是否出现 syscall 号装载定式
 * (movz/movk x8/x16/w8/w16, #imm)。真实 syscall 的装载点可能离 svc
 * 很远: musl 的共享 trampoline 可达 74 条 (先装号再 b 到公共路径,
 * 公共路径里还有 EINTR 重试直通 svc); vDSO 使用 w8 变体。可执行段里的
 * 0xd4000001 可能是数据表/跳转表内容 (libstdc++ 大量出现), 数据表中
 * 前后没有 syscall 号装载, 因此该检查可避免误伤。 */
static int a64_mov_x8_before(const uint8_t *code, uint64_t filesz,
                             uint64_t off)
{
    for (int k = 1; k <= 128; k++) {
        if (off < (uint64_t)k * 4)
            break;
        uint32_t w = a64_insn(code + off - (uint64_t)k * 4);
        switch (w & 0xFFE0001FU) {
        case 0xD2800008U:   /* movz x8, #imm */
        case 0xF2800008U:   /* movk x8, #imm */
        case 0x52800008U:   /* movz w8, #imm */
        case 0x72800008U:   /* movk w8, #imm */
        case 0xD2800010U:   /* movz x16, #imm */
        case 0xF2800010U:   /* movk x16, #imm */
        case 0x52800010U:   /* movz w16, #imm */
        case 0x72800010U:   /* movk w16, #imm */
            return 1;
        }
    }
    return 0;
}

/* 若段内容以 ELF64 头开始 (file-backed 映射), 提取其中 PF_X 的
 * PT_LOAD 文件范围, 供 mock 扫描只扫真正的可执行代码。返回范围数;
 * 非 ELF/无法解析返回 0 (调用方回退全段扫描)。 */
static int a64_seg_exec_ranges(const uint8_t *p, uint64_t filesz,
                               uint64_t ranges[][2], int max)
{
    if (filesz < 64 || memcmp(p, "\177ELF", 4) != 0)
        return 0;
    uint16_t machine, phentsize, phnum;
    uint64_t phoff;
    memcpy(&machine, p + 18, 2);
    memcpy(&phoff, p + 32, 8);
    memcpy(&phentsize, p + 54, 2);
    memcpy(&phnum, p + 56, 2);
    if (machine != 183 /* EM_AARCH64 */ || phentsize < 56 || !phnum)
        return 0;
    if (phoff + (uint64_t)phnum * phentsize > filesz)
        return 0;
    int n = 0;
    for (uint16_t i = 0; i < phnum && n < max; i++) {
        const uint8_t *ph = p + phoff + (uint64_t)i * phentsize;
        uint32_t type, flags;
        uint64_t offset, p_filesz;
        memcpy(&type, ph, 4);
        memcpy(&flags, ph + 4, 4);
        memcpy(&offset, ph + 8, 8);
        memcpy(&p_filesz, ph + 32, 8);
        if (type != 1 /* PT_LOAD */ || !(flags & 1) /* PF_X */ ||
            !p_filesz)
            continue;
        uint64_t a = offset;
        uint64_t b = offset + p_filesz;
        if (b > filesz)
            b = filesz;
        if (a < b) {
            ranges[n][0] = a;
            ranges[n][1] = b;
            n++;
        }
    }
    return n;
}

static int a64_in_exec_ranges(const uint64_t ranges[][2], int nr,
                              uint64_t off)
{
    for (int i = 0; i < nr; i++)
        if (off >= ranges[i][0] && off < ranges[i][1])
            return 1;
    return 0;
}

/* strict 模式构建: 收集站点 → 生成跳板/站点块 → patch 指令 →
 * 计算额外 PT_LOAD (跳板页/未来 newseg/栈预留)。
 * 返回 0 成功; 写 *pl_out / *npl_out。 */
static int build_strict_aarch64(const struct snap *s, struct buf *blob,
                                uint64_t base, uint64_t blob_total,
                                uint64_t payload_off,
                                const elftrace_seg *segs,
                                struct rec_tmp *recs, size_t nrecs,
                                int have_map,
                                const struct atomic_build *ab,
                                uint64_t exit_override,
                                const uint64_t *ckpt_pcs, size_t nckpt_pcs,
                                uint64_t count_from, uint64_t count_to,
                                uint64_t exit_count_override,
                                uint64_t stack_reserve,
                                uint64_t replay_off,
                                uint64_t heap_end,
                                struct strict_pload **pl_out,
                                size_t *npl_out, uint64_t *replay_abs)
{
    size_t nsegs = s->h.nsegs;
    struct strict_site *sites = NULL;
    size_t nsites = 0, sites_cap = 0;
    struct strict_pload *pl = NULL;
    size_t npl = 0, pl_cap = 0;
    uint64_t exit_abs = base + STUB_STRICT_EXIT_OFF;
    uint64_t comp_abs = base + STUB_STRICT_COMP_OFF;
    uint64_t loop_abs = base + STUB_STRICT_LOOP_OFF;
    uint64_t count_abs = base + STUB_STRICT_COUNT_OFF;
    uint64_t rabs = base + replay_off;

    /* 1. syscall 站点: 来自回放记录 (权威); 无记录时扫描 mock */
    for (size_t k = 0; k < nrecs; k++) {
        uint64_t site = recs[k].pc;
        int found = 0;
        /* 常规记录: pc = entry-stop ip = svc+4 */
        if (site >= 4) {
            const uint8_t *q = NULL;
            for (size_t i = 0; i < nsegs; i++) {
                if (site - 4 >= segs[i].vaddr &&
                    site - 4 < segs[i].vaddr + segs[i].filesz) {
                    q = blob->data + payload_off +
                        segs[i].payload_off + (site - 4 - segs[i].vaddr);
                    break;
                }
            }
            if (q && a64_is_svc0(a64_insn(q))) {
                site -= 4;
                found = 1;
            }
        }
        if (!found) {
            const uint8_t *q = NULL;
            for (size_t i = 0; i < nsegs; i++) {
                if (site >= segs[i].vaddr &&
                    site < segs[i].vaddr + segs[i].filesz) {
                    q = blob->data + payload_off +
                        segs[i].payload_off + (site - segs[i].vaddr);
                    break;
                }
            }
            if (q && a64_is_svc0(a64_insn(q)))
                found = 1;
        }
        if (!found)
            continue;           /* 站点不可定位: 丢弃 */
        /* 回放表 rec.pc 统一为 svc 地址 (3.5b 的定点替换在 strict 模式
           被跳过, 表里还是 entry-stop ip = svc+4; 引擎按站点 pc 匹配) */
        {
            uint8_t *recp = blob->data + replay_off + 8 + (size_t)k * 80;
            memcpy(recp, &site, 8);
        }
        /* exit/exit_group 保持真实 (切片结束的合法 syscall) */
        if (recs[k].sysno == 93 || recs[k].sysno == 94)
            continue;
        /* 同一 pc 的多条记录 (libc 共享 trampoline): 只建一个站点,
           游标从首个记录索引开始顺序消费 (与 legacy 回放表游标一致) */
        int dup = 0;
        for (size_t j = 0; j < nsites; j++) {
            if (sites[j].kind == 0 && sites[j].pc == site) {
                dup = 1;
                break;
            }
        }
        if (dup)
            continue;
        if (nsites == sites_cap) {
            sites_cap = sites_cap ? sites_cap * 2 : 32;
            sites = xrealloc(sites, sites_cap * sizeof(*sites));
        }
        struct strict_site *st = &sites[nsites++];
        memset(st, 0, sizeof(*st));
        st->pc = site;
        st->kind = 0;
        st->rec_id = (int)k;
    }
    if (!have_map) {
        /* freeze 快照 (无 trace 回放数据): 全段扫描 svc → mock 站点 */
        size_t scanned = 0;
        for (size_t i = 0; i < nsegs; i++) {
            if (!(segs[i].flags & ET_SEG_X))
                continue;
            const uint8_t *basep = blob->data + payload_off +
                                   segs[i].payload_off;
            uint64_t exec_ranges[8][2];
            int nr = a64_seg_exec_ranges(basep, segs[i].filesz,
                                         exec_ranges, 8);
            for (uint64_t j = 0; j + 4 <= segs[i].filesz; j += 4) {
                if (!a64_is_svc0(a64_insn(basep + j)))
                    continue;
                if (nr && !a64_in_exec_ranges(exec_ranges, nr, j))
                    continue;   /* 段内非可执行部分 (如 ELF 头/RW 数据) */
                if (!a64_mov_x8_before(basep, segs[i].filesz, j))
                    continue;   /* 数据表误报, 跳过 */
                if (nsites == sites_cap) {
                    sites_cap = sites_cap ? sites_cap * 2 : 32;
                    sites = xrealloc(sites, sites_cap * sizeof(*sites));
                }
                struct strict_site *st = &sites[nsites++];
                memset(st, 0, sizeof(*st));
                st->pc = segs[i].vaddr + j;
                st->kind = 0;
                st->rec_id = -1;
                scanned++;
            }
        }
        if (scanned)
            warn("strict: no replay map, %zu svc sites patched as mock "
                 "(scan)", scanned);
    }

    /* 2. 退出点: 唯一路径埋 exit; 循环内 patch 回边 */
    if (exit_override) {
        int seg_idx = -1;
        for (size_t i = 0; i < nsegs; i++) {
            if (exit_override >= segs[i].vaddr &&
                exit_override < segs[i].vaddr + segs[i].filesz) {
                seg_idx = (int)i;
                break;
            }
        }
        if (seg_idx < 0)
            die("exit point %#llx not in any captured segment",
                (unsigned long long)exit_override);
        uint64_t head = 0, backedge = 0;
        const uint8_t *code = blob->data + payload_off +
                              segs[seg_idx].payload_off;
        /* vDSO/vvar 是内核映射的共享代码, 内部有大量低地址相对引用,
           a64_find_loop_backedge 会把无关的向后 b/bl 误判成巨型循环
           (ioctl 检查点落在 clock_gettime 时曾把 libc 到 vdso 的
           范围当成循环体, 计数退出永不触发)。vDSO 内不套用循环分析,
           直接在目标指令埋唯一路径 exit。 */
        const char *seg_name = sn_str(s, segs[seg_idx].name_off);
        int in_vdso = strstr(seg_name, "vdso") != NULL ||
                      strstr(seg_name, "vvar") != NULL;
        int in_loop = 0;
        if (!in_vdso)
            in_loop = a64_find_loop_backedge(code, segs[seg_idx].vaddr,
                                             segs[seg_idx].filesz,
                                             exit_override, &head,
                                             &backedge);
        /* 循环判定增强: 目标 PC 或回边在窗口检查点中出现 >= 2 次
           才认为是"重复路径" (仅跑一次则直接埋 exit) */
        int repeated = 0;
        if (in_loop) {
            size_t hits = 0;
            for (size_t i = 0; i < nckpt_pcs; i++) {
                if (ckpt_pcs[i] == exit_override ||
                    ckpt_pcs[i] == backedge ||
                    (ckpt_pcs[i] >= head && ckpt_pcs[i] <= backedge))
                    hits++;
            }
            if (hits >= 2)
                repeated = 1;
        }
        if (nsites == sites_cap) {
            sites_cap = sites_cap ? sites_cap * 2 : 32;
            sites = xrealloc(sites, sites_cap * sizeof(*sites));
        }
        struct strict_site *st = &sites[nsites++];
        memset(st, 0, sizeof(*st));
        if (in_loop && repeated) {
            st->head = head;
            /* K ≈ 窗口内该循环执行的迭代次数 */
            uint64_t body_len = (backedge + 4 - head) / 4;
            uint64_t total = count_to > count_from
                                 ? count_to - count_from : 1;
            size_t inloop = 0;
            for (size_t i = 0; i < nckpt_pcs; i++) {
                if (ckpt_pcs[i] >= head && ckpt_pcs[i] <= backedge)
                    inloop++;
            }
            uint64_t frac = nckpt_pcs ? inloop * 100 / nckpt_pcs : 100;
            uint64_t iters = total * frac / 100 / (body_len ? body_len : 1);
            if (iters < 1)
                iters = 1;
            /* 保守八等分: perf 指令计数与静态 body_len 的换算并不精确
               (body 内 bl 调用的被调函数、条件分支提前退出等都会让
               实际 P 命中数远小于估算), 宁可提前退出 (仍在窗口内,
               rc=0) 也不能让 counter 越过目标窗口跑到自然 exit, 否则
               窗口外的 syscall 会真实泄漏。 */
            iters /= 8;
            if (iters < 1)
                iters = 1;
            if (exit_count_override)
                iters = exit_count_override;
            st->rec_id = (int)iters;    /* 复用字段存迭代数 */
            /* 回边无条件 (do-while): patch 回边 → 跳板 counter;
               回边条件 (while): 必须保留循环自身退出语义, 改为在
               目标指令 P 上计数 (执行原指令后继续), 否则强制迭代
               会破坏 j<n 之类条件导致越界。 */
            uint32_t back_w = a64_insn(code + (backedge - segs[seg_idx].vaddr));
            uint32_t exit_w = a64_insn(code +
                                (exit_override - segs[seg_idx].vaddr));
            int exit_pc_rel = a64_is_adr(exit_w) || a64_is_adrp(exit_w) ||
                              a64_is_ldr_literal(exit_w) || a64_is_b(exit_w) ||
                              a64_is_bl(exit_w) || a64_is_bcond(exit_w) ||
                              a64_is_cbz(exit_w) || a64_is_cbnz(exit_w) ||
                              a64_is_tbz(exit_w) || a64_is_tbnz(exit_w);
            if (a64_is_b(back_w)) {
                st->pc = backedge;
                st->kind = 2;
                fprintf(stderr, "strict: exit in do-while loop "
                        "[%#llx,%#llx] @%#llx K=%llu (patch backedge)\n",
                        (unsigned long long)head,
                        (unsigned long long)backedge,
                        (unsigned long long)exit_override,
                        (unsigned long long)iters);
            } else if (!exit_pc_rel) {
                st->pc = exit_override;
                st->kind = 3;
                fprintf(stderr, "strict: exit in while loop "
                        "[%#llx,%#llx] @%#llx K=%llu (count target insn)\n",
                        (unsigned long long)head,
                        (unsigned long long)backedge,
                        (unsigned long long)exit_override,
                        (unsigned long long)iters);
            } else {
                st->pc = exit_override;
                st->kind = 1;
                warn("strict: exit target is PC-relative in conditional "
                     "loop; using first-hit exit (window approximate)");
            }
        } else {
            st->pc = exit_override;
            st->kind = 1;
            fprintf(stderr, "strict: exit at unique path %#llx\n",
                    (unsigned long long)exit_override);
        }
    }

    /* 2.6 原子回放站点 (trace --atomic-replay):
       - 所有 ldar 站点恢复原始指令 (快照里是记录跳板分支);
       - 窗口内有事件的站点建回放跳板 (kind 4), 无事件的不 patch
         (原指令真实执行, 内存值与录制一致)。 */
    if (ab && ab->have && ab->n_sites) {
        for (size_t i = 0; i < ab->n_sites; i++) {
            uint8_t *q = NULL;
            for (size_t k = 0; k < nsegs; k++) {
                if (ab->sites[i].pc >= segs[k].vaddr &&
                    ab->sites[i].pc < segs[k].vaddr + segs[k].filesz) {
                    q = blob->data + payload_off + segs[k].payload_off +
                        (ab->sites[i].pc - segs[k].vaddr);
                    break;
                }
            }
            if (!q) {
                warn("atomic: site %#llx not in payload, skipped",
                     (unsigned long long)ab->sites[i].pc);
                continue;
            }
            /* 还原原始 ldar (记录跳板分支 → 原指令) */
            memcpy(q, &ab->sites[i].orig_insn, 4);
            if (!ab->run_cnt[i])
                continue;
            if (exit_override == ab->sites[i].pc)
                die("atomic: exit point %#llx coincides with atomic "
                    "replay site; choose a different --to checkpoint",
                    (unsigned long long)ab->sites[i].pc);
            if (nsites == sites_cap) {
                sites_cap = sites_cap ? sites_cap * 2 : 32;
                sites = xrealloc(sites, sites_cap * sizeof(*sites));
            }
            struct strict_site *st = &sites[nsites++];
            memset(st, 0, sizeof(*st));
            st->pc = ab->sites[i].pc;
            st->kind = 4;
            st->ab_id = i;
        }
    }

    if (!nsites) {
        *pl_out = NULL;
        *npl_out = 0;
        free(sites);
        return 0;
    }

    /* 3. 预映射未来 newseg (回放记录中的新段, 补偿代码直接写入) */
    for (size_t k = 0; k < nrecs; k++) {
        const uint8_t *nd = recs[k].newseg.data;
        size_t off = 0;
        for (uint64_t j = 0; j < recs[k].n_newseg; j++) {
            uint64_t vaddr, filesz, memsz;
            memcpy(&vaddr, nd + off, 8);
            memcpy(&filesz, nd + off + 8, 8);
            memcpy(&memsz, nd + off + 16, 8);
            off += 32 + filesz;
            if (!range_covered(segs, nsegs, pl, npl, vaddr, memsz))
                spload_add(&pl, &npl, &pl_cap, vaddr, memsz,
                           PF_R | PF_W | PF_X);
        }
    }

    /* 4. 栈预留 (零填充, 在 [stack] 下方; 只取空闲区间, 避免与
       libc 等已有段重叠 — 预留过大时内核会先映射预留再被段覆盖,
       find_gap_near 会把整个预留区间视为占用导致跳板无处安放) */
    if (stack_reserve) {
        uint64_t sv = 0;
        for (size_t i = 0; i < nsegs; i++) {
            const char *nm = sn_str(s, segs[i].name_off);
            if (strstr(nm, "[stack]")) {
                sv = segs[i].vaddr;
                break;
            }
        }
        if (sv && sv >= stack_reserve) {
            /* 找栈下方最高段, 预留区从 max(sv-reserve, 该段尾) 开始 */
            uint64_t below = 0x10000;
            for (size_t i = 0; i < nsegs; i++) {
                uint64_t e = segs[i].vaddr + segs[i].memsz;
                if (e <= sv && e > below)
                    below = e;
            }
            uint64_t start = sv > stack_reserve ? sv - stack_reserve : 0;
            if (start < below)
                start = below;
            if (start < sv && sv - start >= (1UL << 20)) {
                if (!range_covered(segs, nsegs, pl, npl,
                                   start, sv - start))
                    spload_add(&pl, &npl, &pl_cap, start, sv - start,
                               PF_R | PF_W);
            }
            fprintf(stderr, "strict: stack reserve %llu MB below %#llx\n",
                    (unsigned long long)((sv - start) >> 20),
                    (unsigned long long)sv);
        }
    }

    /* 5. 站点块 (syscall: 304B; loop 回边: 24B; 计数退出: 40B) */
    *replay_abs = rabs;
    /* blob 当前尺寸可能非 16B 对齐 (payload 大小不定), 站点块内嵌
       可执行指令 (计数退出 [16]/[32] 等) 必须对齐, 先补齐 */
    if (blob->size & 15)
        buf_zero(blob, 16 - (blob->size & 15));
    for (size_t i = 0; i < nsites; i++) {
        struct strict_site *st = &sites[i];
        if (st->kind == 0) {
            st->block_addr = base + blob->size;
            buf_zero(blob, 304);   /* 24B 头 + 31×8 保存槽 + brk/tid/游标 */
        } else if (st->kind == 2) {
            st->block_addr = base + blob->size;
            buf_zero(blob, 24);
        } else if (st->kind == 3) {
            st->block_addr = base + blob->size;
            buf_zero(blob, 40);
        } else if (st->kind == 4) {
            /* 原子回放块在跳板页内生成 (见 6.5), blob 不占 */
            continue;
        }
        if (blob->size & 15)      /* 每块 16B 对齐 (内嵌指令) */
            buf_zero(blob, 16 - (blob->size & 15));
    }
    /* 填站点块内容 */
    for (size_t i = 0; i < nsites; i++) {
        struct strict_site *st = &sites[i];
        if (st->kind == 0) {
            uint8_t *b = blob->data + (st->block_addr - base);
            uint64_t v;
            v = st->pc;             memcpy(b + 0, &v, 8);
            v = st->pc + 4;             memcpy(b + 8, &v, 8);
            v = replay_off ? rabs : 0;  memcpy(b + 16, &v, 8);
            v = heap_end;               memcpy(b + 272, &v, 8);
            v = s->h.task_tid;          memcpy(b + 280, &v, 8);
            v = (uint64_t)(st->rec_id >= 0 ? st->rec_id : 0);
            memcpy(b + 288, &v, 8);     /* 游标初始 = 首个记录索引 */
        } else if (st->kind == 2) {
            uint8_t *b = blob->data + (st->block_addr - base);
            uint64_t v;
            v = (uint64_t)st->rec_id;   memcpy(b + 0, &v, 8);
            v = st->head;               memcpy(b + 8, &v, 8);
            memcpy(b + 16, &exit_abs, 8);
        } else if (st->kind == 3) {
            uint8_t *b = blob->data + (st->block_addr - base);
            uint64_t v;
            uint32_t w;
            v = (uint64_t)st->rec_id;   memcpy(b + 0, &v, 8);  /* counter */
            memcpy(b + 8, &exit_abs, 8);
            /* 原始指令 (执行于 blob, 随后跳回 P+4; 仅限非 PC 相对) */
            for (size_t k = 0; k < nsegs; k++) {
                if (exit_override >= segs[k].vaddr &&
                    exit_override < segs[k].vaddr + segs[k].filesz) {
                    const uint8_t *q = blob->data + payload_off +
                        segs[k].payload_off +
                        (exit_override - segs[k].vaddr);
                    memcpy(b + 16, q, 4);
                    break;
                }
            }
            w = 0x58000070U;    /* ldr x16, [pc, #12] → ret_addr */
            memcpy(b + 20, &w, 4);
            w = 0xD61F0200U;    /* br x16 */
            memcpy(b + 24, &w, 4);
            w = 0xD503201FU;    /* nop */
            memcpy(b + 28, &w, 4);
            v = st->pc + 4;     /* ret_addr */
            memcpy(b + 32, &v, 8);
        } else if (st->kind == 4) {
            continue;
        }
    }

    /* 5.5 原子回放运行表 (每站点连续 24B 段) */
    if (ab && ab->have) {
        for (size_t i = 0; i < nsites; i++) {
            struct strict_site *st = &sites[i];
            if (st->kind != 4)
                continue;
            if (blob->size & 7)
                buf_zero(blob, 8 - (blob->size & 7));
            st->ab_run_off = blob->size;
            size_t o = ab->run_off[st->ab_id];
            size_t cnt = ab->run_cnt[st->ab_id];
            for (size_t k = 0; k < cnt; k++) {
                struct ab_run *r = &ab->runs[o + k];
                buf_append(blob, &r->start, 8);
                buf_append(blob, &r->addr, 8);
                buf_append(blob, &r->value, 8);
            }
        }
    }

    /* 6. 跳板页: 按可执行段分组, 每段一个 16B/站点 的页 */
    for (size_t gi = 0; gi < nsegs; gi++) {
        size_t cnt = 0;
        for (size_t i = 0; i < nsites; i++) {
            if (sites[i].kind != 4 &&
                sites[i].pc >= segs[gi].vaddr &&
                sites[i].pc < segs[gi].vaddr + segs[gi].filesz)
                cnt++;
        }
        if (!cnt)
            continue;
        uint64_t need = ((cnt * 32 + 0xfff) & ~0xfffULL);
        uint64_t taddr = find_gap_near(segs, nsegs, pl, npl,
                                       segs[gi].vaddr + segs[gi].filesz,
                                       need);
        if (!taddr)
            taddr = find_gap_near(segs, nsegs, pl, npl,
                                  segs[gi].vaddr > need
                                      ? segs[gi].vaddr - need : 0,
                                  need);
        if (!taddr)
            die("strict: cannot place trampoline page near %#llx "
                "(code too dense / >128MB away)",
                (unsigned long long)segs[gi].vaddr);
        spload_add(&pl, &npl, &pl_cap, taddr, need, PF_R | PF_W | PF_X);
        uint8_t *page = xcalloc(1, need);
        size_t o = 0;
        for (size_t i = 0; i < nsites; i++) {
            struct strict_site *st = &sites[i];
            if (st->kind == 4 ||
                st->pc < segs[gi].vaddr ||
                st->pc >= segs[gi].vaddr + segs[gi].filesz)
                continue;
            st->tramp_addr = taddr + o;
            /* 32B 条目: ldr x16,[pc,#16]; ldr x17,[pc,#20]; br x17; nop;
               .quad data_block; .quad handler_code */
            uint32_t w;
            w = 0x58000090U;        /* ldr x16, [pc, #16] */
            memcpy(page + o, &w, 4);
            w = 0x580000B1U;        /* ldr x17, [pc, #20] (第二个 literal) */
            memcpy(page + o + 4, &w, 4);
            w = 0xD61F0220U;        /* br x17 */
            memcpy(page + o + 8, &w, 4);
            w = 0xD503201FU;        /* nop */
            memcpy(page + o + 12, &w, 4);
            uint64_t block = st->block_addr;
            uint64_t code = comp_abs;
            if (st->kind == 1) {
                block = exit_abs;   /* exit: 两槽都指向退出代码 */
                code = exit_abs;
            } else if (st->kind == 2) {
                code = loop_abs;
            } else if (st->kind == 3) {
                code = count_abs;
            }
            memcpy(page + o + 16, &block, 8);
            memcpy(page + o + 24, &code, 8);
            o += 32;
        }
        /* 记录页面数据供组装段发射 */
        for (size_t i = 0; i < npl; i++) {
            if (pl[i].vaddr == taddr) {
                pl[i].filesz = need;
                pl[i].data = page;
                break;
            }
        }
    }

    /* 6.5 原子回放跳板页: 每段就近一组页, 每站点 0x220B 块 */
    if (ab && ab->have) {
        for (size_t gi = 0; gi < nsegs; gi++) {
            size_t cnt = 0;
            for (size_t i = 0; i < nsites; i++) {
                if (sites[i].kind == 4 &&
                    sites[i].pc >= segs[gi].vaddr &&
                    sites[i].pc < segs[gi].vaddr + segs[gi].filesz)
                    cnt++;
            }
            if (!cnt)
                continue;
            uint64_t need = ((cnt * A64_ATOM_BLOCK_SIZE + 0xfff) &
                             ~0xfffULL);
            uint64_t taddr = find_gap_near(segs, nsegs, pl, npl,
                                           segs[gi].vaddr + segs[gi].filesz,
                                           need);
            if (!taddr)
                taddr = find_gap_near(segs, nsegs, pl, npl,
                                      segs[gi].vaddr > need
                                          ? segs[gi].vaddr - need : 0,
                                      need);
            if (!taddr)
                die("strict: cannot place atomic trampoline page near "
                    "%#llx", (unsigned long long)segs[gi].vaddr);
            spload_add(&pl, &npl, &pl_cap, taddr, need,
                       PF_R | PF_W | PF_X);
            uint8_t *page = xcalloc(1, need);
            size_t o = 0;
            for (size_t i = 0; i < nsites; i++) {
                struct strict_site *st = &sites[i];
                if (st->kind != 4 ||
                    st->pc < segs[gi].vaddr ||
                    st->pc >= segs[gi].vaddr + segs[gi].filesz)
                    continue;
                st->tramp_addr = taddr + o;
                st->block_addr = taddr + o;
                uint64_t runs_abs = base + st->ab_run_off;
                int is64;
                unsigned rt, rn;
                if (!a64_is_ldar(ab->sites[st->ab_id].orig_insn,
                                 &is64, &rt, &rn))
                    die("atomic: bad orig insn at %#llx",
                        (unsigned long long)st->pc);
                size_t bl = a64_atomic_replay_block(
                    page + o, taddr + o, runs_abs,
                    ab->run_cnt[st->ab_id], is64, rt, rn, st->pc + 4);
                if (!bl)
                    die("atomic: cannot generate replay block at %#llx",
                        (unsigned long long)st->pc);
                o += A64_ATOM_BLOCK_SIZE;
            }
            for (size_t i = 0; i < npl; i++) {
                if (pl[i].vaddr == taddr) {
                    pl[i].filesz = need;
                    pl[i].data = page;
                    break;
                }
            }
        }
    }

    /* 7. patch 目标代码: svc/回边/退出指令 → b <跳板> */
    for (size_t i = 0; i < nsites; i++) {
        struct strict_site *st = &sites[i];
        uint8_t *p = NULL;
        for (size_t k = 0; k < nsegs; k++) {
            if (st->pc >= segs[k].vaddr &&
                st->pc < segs[k].vaddr + segs[k].filesz) {
                p = blob->data + payload_off +
                    segs[k].payload_off + (st->pc - segs[k].vaddr);
                break;
            }
        }
        if (!p) {
            warn("strict: site %#llx not in payload, skipped",
                 (unsigned long long)st->pc);
            continue;
        }
        uint32_t w = a64_encode_b(st->pc, st->tramp_addr);
        if (!w)
            die("strict: cannot encode branch from %#llx to %#llx "
                "(>128MB)",
                (unsigned long long)st->pc,
                (unsigned long long)st->tramp_addr);
        memcpy(p, &w, 4);
    }

    *pl_out = pl;
    *npl_out = npl;
    free(sites);
    return 0;
}
#endif /* __aarch64__ */

/* 找出放置 blob 的空闲 gap */
static uint64_t pick_base(const struct snap *s, uint64_t blob_size)
{
    const uint64_t VA_MIN = 0x10000;
    const uint64_t VA_CAP = 0x7fe00000000ULL;   /* 初始栈可能出现的区域之上 */
    elftrace_seg *segs;
    uint64_t prev_end = VA_MIN;
    uint64_t base = 0;

    segs = xmalloc(s->h.nsegs * sizeof(elftrace_seg));
    memcpy(segs, s->file + s->h.segs_off, s->h.nsegs * sizeof(elftrace_seg));

    /* 按 vaddr 排序 (防御性) */
    for (size_t i = 0; i < s->h.nsegs; i++)
        for (size_t j = i + 1; j < s->h.nsegs; j++)
            if (segs[j].vaddr < segs[i].vaddr) {
                elftrace_seg t = segs[i];
                segs[i] = segs[j];
                segs[j] = t;
            }

    for (size_t i = 0; i < s->h.nsegs; i++) {
        uint64_t gap_start = prev_end;
        uint64_t gap_end = segs[i].vaddr;
        if (gap_end >= gap_start && gap_end - gap_start >= blob_size &&
            gap_start + blob_size <= VA_CAP) {
            base = gap_start;
            break;
        }
        uint64_t end = segs[i].vaddr + segs[i].memsz;
        prev_end = (end + 0xfff) & ~0xfffULL;
    }
    if (!base) {
        if (prev_end + blob_size <= VA_CAP)
            base = prev_end;
    }
    if (!base)
        die("no gap in target address space can hold %llu-byte restore blob "
            "(target memory too dense)", (unsigned long long)blob_size);
    return base;
}

/* 在 blob 映像中打补丁 */
static void blob_patch_u64(uint8_t *blob, uint64_t off, uint64_t val)
{
    memcpy(blob + off, &val, 8);
}

/* 应用差异文件到合成快照 (增量检查点重建) */
static void apply_diff(struct collect_snapshot *sn, const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        die("cannot open diff %s", path);
    struct stat st;
    if (fstat(fd, &st) < 0)
        die("fstat %s", path);
    uint8_t *f = xmalloc(st.st_size);
    { size_t roff = 0; while (roff < (size_t)st.st_size) {
        ssize_t r = read(fd, (char *)f + roff, (size_t)st.st_size - roff);
        if (r < 0) { close(fd); die("short read %s", path); }
        roff += (size_t)r;
    } }
    close(fd);

    elftrace_diff_hdr h;
    memcpy(&h, f, sizeof(h));
    if (h.magic != ELFTRACE_DIFF_MAGIC) {
        free(f);
        return;
    }
    size_t off = sizeof(h) + h.state_size;

    /* 状态区: regs | xstate_size+xstate | sigmask | nfds+fds表+路径 */
    if (h.state_size) {
        size_t so = sizeof(h);
        if (h.state_size >= sizeof(sn->regs))
            memcpy(&sn->regs, f + so, sizeof(sn->regs));
        so += sizeof(sn->regs);
        if (so + 8 <= sizeof(h) + h.state_size) {
            uint64_t xs;
            memcpy(&xs, f + so, 8);
            so += 8;
            if (xs) {
                free(sn->xstate);
                sn->xstate = xmalloc(xs);
                memcpy(sn->xstate, f + so, xs);
                sn->xstate_size = xs;
                so += xs;
            }
        }
        if (so + 8 <= sizeof(h) + h.state_size) {
            memcpy(sn->sigmask, f + so, sizeof(sn->sigmask));
            so += sizeof(sn->sigmask);
        }
        if (so + 8 <= sizeof(h) + h.state_size) {
            uint64_t nfds;
            memcpy(&nfds, f + so, 8);
            so += 8;
            for (size_t i = 0; i < sn->nfds; i++)
                free(sn->fds[i].path);
            free(sn->fds);
            sn->fds = NULL;
            sn->nfds = 0;
            if (nfds) {
                sn->fds = xcalloc(nfds, sizeof(struct cfdinfo));
                for (size_t i = 0; i < nfds; i++) {
                    elftrace_fd e;
                    memcpy(&e, f + so, sizeof(e));
                    so += sizeof(e);
                    sn->fds[i].fd = e.fd;
                    sn->fds[i].flags = e.flags;
                    sn->fds[i].mode = e.mode;
                    sn->fds[i].pos = e.pos;
                    if (e.path_len) {
                        sn->fds[i].path = xstrdup((const char *)(f + so));
                        so += e.path_len;
                    }
                }
                sn->nfds = nfds;
            }
        }
    }

    /* 1. unmap: 删除段 (同步移除 payload 内容与 payload_offs) */
    for (uint64_t k = 0; k < h.n_unmap; k++) {
        uint64_t vaddr;
        memcpy(&vaddr, f + off, 8);
        off += 8;
        for (size_t i = 0; i < sn->nsegs; i++) {
            if (sn->segs[i].vaddr == vaddr) {
                size_t boff = sn->payload_offs[i];
                size_t blen = sn->segs[i].filesz;
                memmove(sn->payload.data + boff,
                        sn->payload.data + boff + blen,
                        sn->payload.size - boff - blen);
                sn->payload.size -= blen;
                free(sn->segs[i].name);
                memmove(&sn->segs[i], &sn->segs[i + 1],
                        (sn->nsegs - i - 1) * sizeof(struct cseg));
                memmove(&sn->payload_offs[i], &sn->payload_offs[i + 1],
                        (sn->nsegs - i - 1) * sizeof(uint64_t));
                sn->nsegs--;
                for (size_t j = i; j < sn->nsegs; j++)
                    sn->payload_offs[j] -= blen;
                break;
            }
        }
    }

    /* 2. newseg: 追加段 (内容进 payload) */
    for (uint64_t k = 0; k < h.n_newseg; k++) {
        elftrace_diff_seg e;
        memcpy(&e, f + off, sizeof(e));
        off += sizeof(e);
        sn->segs = xrealloc(sn->segs, (sn->nsegs + 1) * sizeof(struct cseg));
        sn->payload_offs = xrealloc(sn->payload_offs,
                                    (sn->nsegs + 1) * sizeof(uint64_t));
        struct cseg *c = &sn->segs[sn->nsegs];
        memset(c, 0, sizeof(*c));
        c->vaddr = e.vaddr;
        c->filesz = e.filesz;
        c->memsz = e.memsz;
        c->flags = e.flags;
        c->name = NULL;
        sn->payload_offs[sn->nsegs] = sn->payload.size;
        sn->nsegs++;
        cbuf_append(&sn->payload, f + off, e.filesz);
        off += e.filesz;
    }

    /* 3. dirty: 覆盖页内容 (用 payload_offs 定位) */
    for (uint64_t k = 0; k < h.n_dirty; k++) {
        uint64_t vaddr;
        memcpy(&vaddr, f + off, 8);
        off += 8;
        const uint8_t *data = f + off;
        off += 4096;
        size_t si = (size_t)-1;
        for (size_t i = 0; i < sn->nsegs; i++) {
            if (vaddr >= sn->segs[i].vaddr &&
                vaddr < sn->segs[i].vaddr + sn->segs[i].memsz) {
                si = i;
                break;
            }
        }
        if (si == (size_t)-1)
            continue;
        uint64_t rel = vaddr - sn->segs[si].vaddr;
        size_t avail = sn->segs[si].filesz > rel
                           ? sn->segs[si].filesz - rel : 0;
        size_t n = avail < 4096 ? avail : 4096;
        if (n)
            memcpy(sn->payload.data + sn->payload_offs[si] + rel, data, n);
    }
    free(f);
}

int build_main(int argc, char **argv)
{
    const char *in = NULL;
    const char *out = "sliced.elf";
    uint64_t ipc_period = 0;
    uint64_t breakpoint = 0;    /* 注入 int3 的地址 (0 = 无) */
    int mode_baremetal = 1;   /* 默认 baremetal */
    int bm_strict = 0;        /* aarch64: ELF loader 型无 syscall baremetal */
    uint64_t stack_reserve = 0;  /* strict: [stack] 下方预留字节 */
    const char *ckpts = NULL;   /* trace 检查点目录 */
    long from_ckpt = -1, to_ckpt = -1;
    struct snap s = {0};
    int fd;
    struct buf blob;            /* 最终 blob (stub + 追加数据) */
    uint64_t base;
    struct buf file;            /* 输出 ELF 文件 */
    elftrace_seg *segs;
    elftrace_fd *fds;


    uint64_t segs_off, fds_off, strings_off, payload_off;
    uint64_t blob_total;
    uint64_t exit_override = 0; /* baremetal 退出点地址 (0 = 无) */
    uint64_t heap_end = 0;      /* 冻结时堆尾 (brk 恢复/baremetal 模拟) */
    uint64_t replay_off = 0;    /* baremetal syscall 回放表 (blob 相对) */
    uint64_t replay_size = 0;
    uint64_t stack_vaddr = 0;   /* [stack] 段 vaddr (MAP_GROWSDOWN) */
    uint64_t exit_count_override = 0; /* --bm-exit-count: 覆盖循环 K */
    /* strict 循环判定用: 窗口内检查点 PC 与计数 */
    uint64_t *ckpt_pcs = NULL;
    size_t nckpt_pcs = 0;
    uint64_t ckpt_count0 = 0, ckpt_count_to = 0;
    struct strict_pload *sploads = NULL;
    size_t n_sploads = 0;
    uint64_t strict_replay_abs = 0;
#if defined(__aarch64__)
    struct atomic_build ab;
    memset(&ab, 0, sizeof(ab));
#endif

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            out = argv[++i];
        } else if (strcmp(argv[i], "--ipc") == 0 && i + 1 < argc) {
            ipc_period = strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--breakpoint") == 0 && i + 1 < argc) {
            breakpoint = strtoull(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            if (strcmp(argv[++i], "real") == 0)
                mode_baremetal = 0;
            else if (strcmp(argv[i], "baremetal") == 0)
                mode_baremetal = 1;
            else
                die("--mode must be real or baremetal");
        } else if (strcmp(argv[i], "--bm-strict") == 0) {
            bm_strict = 1;
        } else if (strcmp(argv[i], "--bm-exit-count") == 0 &&
                   i + 1 < argc) {
            exit_count_override = strtoull(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "--stack-reserve") == 0 &&
                   i + 1 < argc) {
            stack_reserve = strtoull(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "--checkpoints") == 0 && i + 1 < argc) {
            ckpts = argv[++i];
            /* bundle 单文件: 解包到临时目录 */
            if (bundle_is_bundle(ckpts)) {
                char tmpdir[] = "/tmp/elftrace_bundle_XXXXXX";
                if (!mkdtemp(tmpdir))
                    die("mkdtemp");
                bundle_extract(ckpts, tmpdir);
                ckpts = xstrdup(tmpdir);
            }
        } else if (strcmp(argv[i], "--from") == 0 && i + 1 < argc) {
            from_ckpt = strtol(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--to") == 0 && i + 1 < argc) {
            to_ckpt = strtol(argv[++i], NULL, 10);
        } else if (argv[i][0] != '-') {
            in = argv[i];
        } else {
            die("usage: elftrace build <file.elftrace> [-o out.elf] "
                "[--mode real|baremetal] [--ipc N] [--checkpoints DIR] "
                "[--from K] [--to M] [--breakpoint ADDR] "
                "[--bm-strict] [--bm-exit-count N] [--stack-reserve N]");
        }
    }
    if (!in)
        die("usage: elftrace build <file.elftrace> [-o out.elf] "
            "[--mode real|baremetal] [--ipc N] [--checkpoints DIR] "
            "[--from K] [--to M] [--breakpoint ADDR] "
            "[--bm-strict] [--bm-exit-count N] [--stack-reserve N]");
#if !defined(__aarch64__)
    if (bm_strict)
        die("--bm-strict is only supported on aarch64 builds");
#endif
    if (bm_strict && !mode_baremetal)
        die("--bm-strict requires --mode baremetal");
    if (stack_reserve && !bm_strict)
        die("--stack-reserve requires --bm-strict");
    if (bm_strict && stack_reserve == 0)
        stack_reserve = 256UL << 20;   /* 默认预留 256MB (100M 指令切片) */

    /* --from/--to: 用 trace 检查点替代基础镜像并确定退出点 */
    uint64_t syscall_start = 0, syscall_end = UINT64_MAX;
    uint64_t resume_pc = 0;   /* 切片恢复点 pc (丢弃悬空记录用) */
    if (ckpts) {
        char path[PATH_MAX];
        FILE *f;
        uint64_t count0 = 0, ip0 = 0;
        uint64_t count_to = 0, ip_to = 0;
        long idx = 0, found_from = -1;
        size_t ckpt_cap = 0;

        if (from_ckpt < 0)
            from_ckpt = 0;
        snprintf(path, sizeof(path), "%s/manifest.txt", ckpts);
        f = fopen(path, "r");
        if (!f)
            die("cannot open %s", path);
        char line[1024];
        while (fgets(line, sizeof(line), f)) {
            uint64_t cnt, ip, nsys = 0;
            char file[PATH_MAX];
            int nf = sscanf(line, "%llu 0x%llx %511s %llu", &cnt, &ip,
                            file, &nsys);
            if (nf < 3)
                continue;
            if (nckpt_pcs == ckpt_cap) {
                ckpt_cap = ckpt_cap ? ckpt_cap * 2 : 64;
                ckpt_pcs = xrealloc(ckpt_pcs, ckpt_cap * sizeof(*ckpt_pcs));
            }
            ckpt_pcs[nckpt_pcs++] = ip;
            if (idx == from_ckpt) {
                snprintf(path, sizeof(path), "%s/%s", ckpts, file);
                in = xstrdup(path);
                found_from = idx;
                count0 = cnt;
                ip0 = ip;
                resume_pc = ip;
                if (nf >= 4)
                    syscall_start = nsys; /* 回放表起始 (K 前的不消费) */
            }
            if (to_ckpt >= 0 && idx == to_ckpt) {
                count_to = cnt;
                ip_to = ip;
                if (nf >= 4)
                    syscall_end = nsys;  /* 回放表终止 */
            }
            idx++;
        }
        fclose(f);
        /* 仅保留窗口内检查点 PC (循环判定用) */
        {
            size_t keep = 0;
            for (size_t i = 0; i < nckpt_pcs; i++) {
                if ((long)i >= from_ckpt &&
                    (to_ckpt < 0 || (long)i <= to_ckpt))
                    ckpt_pcs[keep++] = ckpt_pcs[i];
            }
            nckpt_pcs = keep;
        }
        if (found_from < 0)
            die("checkpoint %ld not found in %s", from_ckpt, path);
        if (to_ckpt >= 0 && idx <= to_ckpt)
            die("checkpoint %ld not found (have %ld)", to_ckpt, idx);
        fprintf(stderr, "build: base = checkpoint %ld (count %llu, pc %#llx)\n",
                found_from, (unsigned long long)count0,
                (unsigned long long)ip0);
        ckpt_count0 = count0;
        ckpt_count_to = count_to;
        if (to_ckpt < 0)
            ckpt_count_to = UINT64_MAX;   /* 无 --to: 窗口延伸到末尾 */

        /* 增量检查点: 从 base (ckpt_000000 完整) 应用 1..from_ckpt 差异链,
           合成完整快照到临时文件。仅当检查点 1 是 diff 格式时启用;
           旧版完整格式目录直接以 from 检查点文件为 in。 */
        int use_diff = 0;
        if (found_from > 0) {
            char c1[PATH_MAX];
            snprintf(c1, sizeof(c1), "%s/ckpt_000001.elftrace", ckpts);
            int fd1 = open(c1, O_RDONLY);
            if (fd1 >= 0) {
                uint32_t mg;
                if (read(fd1, &mg, 4) == 4)
                    use_diff = (mg == ELFTRACE_DIFF_MAGIC);
                close(fd1);
            }
        }
        if (use_diff) {
            struct collect_snapshot syn = {0};
            {
                char bp[PATH_MAX];
                snprintf(bp, sizeof(bp), "%s/ckpt_000000.elftrace", ckpts);
                if (access(bp, R_OK) != 0)
                    die("incremental checkpoints need %s (full base)", bp);
                collect_snapshot_load(bp, &syn);
            }
            {
                char mp[PATH_MAX];
                snprintf(mp, sizeof(mp), "%s/manifest.txt", ckpts);
                FILE *df = fopen(mp, "r");
                if (!df)
                    die("cannot open %s", mp);
                long idx2 = 0;
                while (fgets(line, sizeof(line), df)) {
                    uint64_t cnt, ip;
                    char file[PATH_MAX];
                    if (sscanf(line, "%llu 0x%llx %511s", &cnt, &ip, file)
                        != 3)
                        continue;
                    if (idx2 >= 1 && idx2 <= found_from) {
                        char dp[PATH_MAX];
                        snprintf(dp, sizeof(dp), "%s/%s", ckpts, file);
                        apply_diff(&syn, dp);
                    }
                    if (idx2 >= found_from)
                        break;
                    idx2++;
                }
                fclose(df);
            }
            char tmp[PATH_MAX];
            snprintf(tmp, sizeof(tmp), "%s/.synth_%ld.elftrace", ckpts,
                     found_from);
            collect_write(&syn, tmp);
            free(in);
            in = xstrdup(tmp);
            for (size_t k = 0; k < syn.nsegs; k++)
                free(syn.segs[k].name);
            free(syn.segs);
            free(syn.payload_offs);
            free(syn.payload.data);
            for (size_t k = 0; k < syn.nfds; k++)
                free(syn.fds[k].path);
            free(syn.fds);
            free(syn.xstate);
        }

        if (to_ckpt >= 0) {
            if (mode_baremetal) {
                /* 退出地址 = 检查点 to 的 pc (替换该处指令);
                   strict 模式退出由跳板/循环 counter 完成, 不装 perf IPC */
                exit_override = ip_to;
                if (!bm_strict && ipc_period == 0)
                    ipc_period = count_to - count0;
            } else {
                /* real: 用 perf 计数 (ipc_period = 区间指令数) */
                if (ipc_period == 0)
                    ipc_period = count_to - count0;
                else
                    warn("--ipc overridden by --to (%llu instructions)",
                         (unsigned long long)(count_to - count0));
            }
            fprintf(stderr, "build: exit at checkpoint %ld (count %llu)\n",
                    to_ckpt, (unsigned long long)count_to);
        }
    }
    /* baremetal 的 --ipc: 需要检查点来确定第 N 条指令的地址 */
    if (mode_baremetal && ipc_period && !exit_override) {
        die("baremetal --ipc N requires --checkpoints DIR (to locate the "
            "N-th instruction); use --to M or --checkpoints instead");
    }
    if (mode_baremetal && !ipc_period && !exit_override) {
        warn("baremetal without exit point: slice will run until the "
             "target exits or hits an unsupported syscall");
    }
    s.ipc_period = ipc_period;

    /* 1. 读入 .elftrace */
    fd = open(in, O_RDONLY);
    if (fd < 0)
        die("cannot open %s", in);
    s.file_size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    s.file = xmalloc(s.file_size);
    { size_t roff = 0; while (roff < s.file_size) {
        ssize_t r = read(fd, (char *)s.file + roff, s.file_size - roff);
        if (r < 0)
            die("short read on %s", in);
        roff += (size_t)r;
    } }
    close(fd);

    memcpy(&s.h, s.file, sizeof(s.h));
    if (s.h.magic != ELFTRACE_MAGIC)
        die("%s: not an elftrace file (magic %#x)", in, s.h.magic);
    if (s.h.version != ELFTRACE_VERSION)
        die("%s: unsupported version %u", in, s.h.version);
    if (s.h.arch != ELFTRACE_ARCH_X86_64 &&
        s.h.arch != ELFTRACE_ARCH_AARCH64)
        die("%s: unsupported architecture %u", in, s.h.arch);
#if defined(__aarch64__)
    if (s.h.arch != ELFTRACE_ARCH_AARCH64)
        die("%s: build on aarch64 requires aarch64 snapshot (arch %u)",
            in, s.h.arch);
#else
    if (s.h.arch != ELFTRACE_ARCH_X86_64)
        die("%s: build on x86_64 requires x86_64 snapshot (arch %u)",
            in, s.h.arch);
#endif

    /* 2. 构造 blob: 固定区 + segs 表 + fds 表 + 字符串 + payload */
    buf_init(&blob);
#if defined(__aarch64__)
    const unsigned char *stub = stub_blob_aarch64;
    const unsigned int stub_len = stub_blob_aarch64_len;
#else
    const unsigned char *stub = stub_blob_x86_64;
    const unsigned int stub_len = stub_blob_x86_64_len;
#endif
    buf_append(&blob, stub, stub_len);
    /* 固定区不足则补齐 (stub_blob 可能略大于/略小于 STUB_FIXED_SIZE:
       .org 保证 >= STUB_FIXED_SIZE, ld 可能在尾部追加少量对齐填充) */
    if (blob.size < STUB_FIXED_SIZE)
        buf_zero(&blob, STUB_FIXED_SIZE - blob.size);
    if (blob.size > STUB_FIXED_SIZE)
        fprintf(stderr, "build: note: stub blob %u bytes exceeds fixed area "
                "%#x by %u (padding)\n", stub_len, STUB_FIXED_SIZE,
                (unsigned)(blob.size - STUB_FIXED_SIZE));

    segs_off = blob.size;
    fds_off = segs_off + s.h.nsegs * sizeof(elftrace_seg);
    strings_off = fds_off + s.h.nfds * sizeof(elftrace_fd);
    payload_off = strings_off + s.h.strings_size;

    /* segs 表 (payload_off 转为 blob 相对) */
    segs = (elftrace_seg *)(s.file + s.h.segs_off);
    for (size_t i = 0; i < s.h.nsegs; i++) {
        elftrace_seg e = segs[i];
        e.payload_off += payload_off;
        buf_append(&blob, &e, sizeof(e));
    }

    /* fds 表 + 字符串 */
    fds = (elftrace_fd *)(s.file + s.h.fds_off);
    for (size_t i = 0; i < s.h.nfds; i++) {
        elftrace_fd e = fds[i];
        if (e.path_len) {
            const char *p = sn_str(&s, e.path_off);
            e.path_off += strings_off;
            e.path_len = strlen(p) + 1;
        }
        buf_append(&blob, &e, sizeof(e));
    }
    buf_append(&blob, s.file + s.h.strings_off, s.h.strings_size);

    /* payload: 段内容 */
    if (blob.size != payload_off)
        die("internal: blob layout mismatch (%zu != %llu)", blob.size,
            (unsigned long long)payload_off);
    for (size_t i = 0; i < s.h.nsegs; i++) {
        const uint8_t *p = s.file + s.h.payload_off + segs[i].payload_off;
        buf_append(&blob, p, segs[i].filesz);
    }

    blob_total = blob.size;

    /* 3. 选 base */
    base = pick_base(&s, blob_total);
    fprintf(stderr, "build: blob %llu bytes at base %#llx\n",
            (unsigned long long)blob_total, (unsigned long long)base);

    /* 3.5 baremetal: 段表加载后确定 brk 边界与退出地址的 blob 位置
       (strict 模式由 build_strict 统一处理, 跳过 brk 替换) */
    if (mode_baremetal && !bm_strict) {
        if (exit_override) {
            int hit = 0;
            for (size_t i = 0; i < s.h.nsegs; i++) {
                if (exit_override >= segs[i].vaddr &&
                    exit_override < segs[i].vaddr + segs[i].filesz) {
                    size_t off = payload_off + segs[i].payload_off +
                                 (exit_override - segs[i].vaddr);
                    arch_patch_syscall(blob.data + off); /* int3/brk */
                    hit = 1;
                    break;
                }
            }
            if (!hit)
                die("exit point %#llx not in any captured segment",
                    (unsigned long long)exit_override);
        }
        fprintf(stderr, "build: baremetal mode (brk_base=%#llx%s)\n",
                (unsigned long long)heap_end,
                exit_override ? ", exit at " : "");
        if (exit_override)
            fprintf(stderr, "        exit addr %#llx (int3)\n",
                    (unsigned long long)exit_override);
    }

    /* 3.5a baremetal: 解析 syscall 回放记录 (--checkpoints
       DIR/syscalls/syscall.map → 内存中的 recs)。只保留切片区间
       [syscall_start, syscall_end) 内的记录。记录 pc 修正放到 int3
       替换之后 (见 3.5b)。 */
    replay_off = 0;
    replay_size = 0;
    struct rec_tmp *recs = NULL;
    size_t nrecs = 0, rec_cap = 0;
    int have_map = 0;         /* 找到 syscall.map (有回放数据) */
    if (mode_baremetal && ckpts) {
        char mappath[PATH_MAX];
        snprintf(mappath, sizeof(mappath), "%s/syscalls/syscall.map", ckpts);
        FILE *mf = fopen(mappath, "r");
        if (mf) {
            have_map = 1;
            size_t map_idx = 0;   /* 记录在 syscall.map 中的行号 */
            char line[1024];
            while (fgets(line, sizeof line, mf)) {
                char fname[256];
                char f4[32] = "", f5[32] = "";
                uint64_t pc, sysno, rec_count = UINT64_MAX;
                int nf = sscanf(line, "%llx %llu %255s %31s %31s",
                                &pc, &sysno, fname, f4, f5);
                if (nf < 3)
                    continue;
                int interrupted = 0;
                if (nf >= 4) {
                    if (strcmp(f4, "I") == 0) {
                        interrupted = 1;   /* 旧格式: 4 字段被打断标记 */
                        if (nf >= 5)
                            rec_count = strtoull(f5, NULL, 10);
                    } else {
                        rec_count = strtoull(f4, NULL, 10);
                    }
                }
                /* 只保留切片区间内的记录:
                   - 新格式 (map 第 5 字段 = 捕获时 perf 计数): 按
                     [count_from, count_to) 过滤 — manifest 的 nsys 字段
                     滞后不可靠 (perf 溢出与 syscall-stop 异步处理,
                     窗口内 syscall 会被误删)。
                   - 旧格式: 按 manifest nsys 索引过滤 (兼容) */
                if (rec_count != UINT64_MAX) {
                    if (rec_count < ckpt_count0 ||
                        rec_count >= ckpt_count_to) {
                        map_idx++;
                        continue;
                    }
                } else {
                    if (map_idx < syscall_start ||
                        map_idx >= syscall_end) {
                        map_idx++;
                        continue;
                    }
                }
                map_idx++;
                /* 悬空的被打断 syscall 记录 (map 第 4 字段 "I"):
                   检查点 INTERRUPT 打断的在途 syscall, 记录在检查点之后
                   补记; 切片从该检查点恢复时 pc 在 syscall 指令之后
                   (resume_pc == rec.pc+2), 不会重执行它。若保留, 记录
                   会错误消费下一条同 pc 的 syscall (libc 共享
                   trampoline 场景, 曾致 read 被回放成已完成的
                   nanosleep 而返回 EOF)。 */
                if (interrupted &&
                    pc + ARCH_SYSCALL_LEN == resume_pc) {
                    fprintf(stderr, "build: drop dangling interrupted "
                            "syscall rec (pc %#llx, resume pc %#llx)\n",
                            (unsigned long long)pc,
                            (unsigned long long)resume_pc);
                    continue;
                }
                char path[PATH_MAX];
                snprintf(path, sizeof(path), "%s/syscalls/%s", ckpts, fname);
                int dfd = open(path, O_RDONLY);
                if (dfd < 0)
                    die("cannot open syscall diff %s", path);
                struct stat dst;
                if (fstat(dfd, &dst) < 0)
                    die("fstat %s", path);
                uint8_t *f = xmalloc(dst.st_size);
                { size_t roff = 0; while (roff < (size_t)dst.st_size) {
                    ssize_t r = read(dfd, (char *)f + roff,
                                     (size_t)dst.st_size - roff);
                    if (r < 0) { close(dfd); die("read %s", path); }
                    roff += (size_t)r;
                } }
                close(dfd);
                elftrace_diff_hdr h;
                memcpy(&h, f, sizeof(h));
                if (h.magic != ELFTRACE_DIFF_MAGIC) {
                    free(f);
                    continue;
                }
                size_t off = sizeof(h) + h.state_size;
                if (nrecs == rec_cap) {
                    rec_cap = rec_cap ? rec_cap * 2 : 8;
                    recs = xrealloc(recs, rec_cap * sizeof(*recs));
                    memset(recs + nrecs, 0, (rec_cap - nrecs) *
                           sizeof(*recs));
                }
                struct rec_tmp *r = &recs[nrecs];
                buf_init(&r->unmap);
                buf_init(&r->newseg);
                buf_init(&r->dirty);
                r->pc = pc;
                r->sysno = sysno;
                if (h.state_size >= 0x60)
                    memcpy(&r->rax, f + sizeof(h) + ARCH_REGS_RET_OFF, 8);
                r->n_unmap = h.n_unmap;
                r->n_newseg = h.n_newseg;
                r->n_dirty = h.n_dirty;
                for (uint64_t k = 0; k < h.n_unmap; k++) {
                    buf_append(&r->unmap, f + off, 8);
                    off += 8;
                }
                for (uint64_t k = 0; k < h.n_newseg; k++) {
                    elftrace_diff_seg e;
                    memcpy(&e, f + off, sizeof(e));
                    off += sizeof(e);
                    buf_append(&r->newseg, &e.vaddr, 32);
                    buf_append(&r->newseg, f + off, e.filesz);
                    off += e.filesz;
                }
                for (uint64_t k = 0; k < h.n_dirty; k++) {
                    buf_append(&r->dirty, f + off, 8);
                    off += 8;
                    buf_append(&r->dirty, f + off, 4096);
                    off += 4096;
                }
                free(f);
                nrecs++;
            }
            fclose(mf);
            if (nrecs)
                fprintf(stderr, "build: %zu syscall records in window "
                        "[%llu,%llu)\n",
                        nrecs, (unsigned long long)syscall_start,
                        (unsigned long long)syscall_end);
        }
    }

    /* 3.5b baremetal: syscall 指令 → 断点替换
       (kernel entry-stop 的 ip 是 syscall 指令的下一条; x86_64 0f05
       长 2 → int3; aarch64 svc #0 (d4000001) 长 4 → brk #0 (d4200000),
       断点打在 pc-ARCH_SYSCALL_LEN。trace 被打断的 syscall 记录 pc
       已修正为 syscall 地址本身, 检查 blob[pc] 即可)。 */
    if (mode_baremetal && !bm_strict) {
        if (nrecs) {
            /* 回放路径: 只替换 trace 记录过的 syscall 指令。
               这是权威的 syscall 地址表, 不做全段字节扫描 —
               直接扫描 0f 05 会误伤指令立即数/操作数中的同字节序列
               (例如 movabs $0x50f → 48 b8 0f 05 ...), 静默改变切片
               行为 (曾致 embed 值从 0x50f 变 0x90cc)。 */
            size_t replaced = 0, dropped = 0;
            for (size_t k = 0; k < nrecs; k++) {
                uint64_t pc = recs[k].pc;
                /* 常规记录: pc = entry-stop ip = syscall+len */
                if (pc >= ARCH_SYSCALL_LEN) {
                    uint8_t *s2 = NULL;
                    for (size_t i = 0; i < s.h.nsegs; i++) {
                        if (pc - ARCH_SYSCALL_LEN >= segs[i].vaddr &&
                            pc - ARCH_SYSCALL_LEN <
                                segs[i].vaddr + segs[i].filesz) {
                            s2 = blob.data + payload_off +
                                 segs[i].payload_off +
                                 (pc - ARCH_SYSCALL_LEN - segs[i].vaddr);
                            break;
                        }
                    }
                    if (s2 && arch_is_syscall(s2, 4)) {
                        arch_patch_syscall(s2);
                        recs[k].pc = pc - ARCH_SYSCALL_LEN;
                        replaced++;
                        continue;
                    }
                    if (s2 && arch_is_breakpoint(s2, 4)) {
                        /* 已被替换 (退出点 int3 重叠/重复记录) */
                        recs[k].pc = pc - ARCH_SYSCALL_LEN;
                        continue;
                    }
                }
                /* 已修正记录 (trace 被打断的 syscall): pc 即 syscall */
                {
                    uint8_t *q = NULL;
                    for (size_t i = 0; i < s.h.nsegs; i++) {
                        if (pc >= segs[i].vaddr &&
                            pc < segs[i].vaddr + segs[i].filesz) {
                            q = blob.data + payload_off +
                                segs[i].payload_off + (pc - segs[i].vaddr);
                            break;
                        }
                    }
                    if (q && arch_is_syscall(q, 4)) {
                        arch_patch_syscall(q);
                        replaced++;
                        continue;
                    }
                    if (q && arch_is_breakpoint(q, 4))
                        continue;   /* 已替换 */
                }
                warn("baremetal: syscall rec @ %#llx has no breakpoint "
                     "site, "
                     "record unused", (unsigned long long)pc);
                dropped++;
            }
            fprintf(stderr, "        %zu syscall instructions replaced by "
                    "int3 (replay), %zu dropped\n", replaced, dropped);
        } else if (!have_map) {
            /* 旧 mock 路径 (freeze 快照, 无 trace 回放表):
               x86_64: 先用指令长度解码器从段起点顺序扫描, 只替换
               "完整解码为 2 字节 0F 05 指令"的地址 (指令边界, 不误伤
               立即数); 遇到无法解码的位置 (段内嵌数据表等) 后, 剩余
               部分退回模式扫描。
               aarch64: 定长 4 字节指令, 直接在 4 字节边界扫描 svc #0
               (d4000001) → brk #0, 无解码器需求。 */
            size_t replaced = 0;
            for (size_t i = 0; i < s.h.nsegs; i++) {
                if (!(segs[i].flags & ET_SEG_X))
                    continue;
                size_t base = payload_off + segs[i].payload_off;
#if defined(__x86_64__)
                size_t off = 0;
                while (off + 1 < segs[i].filesz) {
                    if (x86_is_syscall(blob.data + base + off,
                                       segs[i].filesz - off)) {
                        arch_patch_syscall(blob.data + base + off);
                        replaced++;
                        off += 2;
                        continue;
                    }
                    int l = x86_len(blob.data + base + off,
                                    segs[i].filesz - off);
                    if (l <= 0)
                        break;  /* 数据区: 退回模式扫描 */
                    off += (size_t)l;
                }
                for (uint64_t j = 0; j + 1 < segs[i].filesz; j++) {
                    if (j >= off &&
                        blob.data[base + j] == 0x0f &&
                        blob.data[base + j + 1] == 0x05) {
                        arch_patch_syscall(blob.data + base + j);
                        replaced++;
                    }
                }
#else
                uint64_t exec_ranges[8][2];
                int nr = a64_seg_exec_ranges(blob.data + base,
                                             segs[i].filesz,
                                             exec_ranges, 8);
                for (uint64_t j = 0; j + 4 <= segs[i].filesz; j += 4) {
                    if (arch_is_syscall(blob.data + base + j, 4)) {
                        if (nr &&
                            !a64_in_exec_ranges(exec_ranges, nr, j))
                            continue;
                        if (!a64_mov_x8_before(blob.data + base,
                                               segs[i].filesz, j))
                            continue;   /* 数据表误报 */
                        arch_patch_syscall(blob.data + base + j);
                        replaced++;
                    }
                }
#endif
            }
            warn("baremetal without syscall replay data (freeze snapshot "
                 "or bundle without syscalls/): pattern-based replacement "
                 "may corrupt immediates containing 0f 05; prefer "
                 "--checkpoints for authoritative replacement");
            fprintf(stderr, "        %zu syscall instructions replaced by "
                    "int3 (mock scan)\n", replaced);
        }
        /* 有回放 map 但窗口内无记录: 切片区间内没有 syscall, 无需替换 */
    }

    /* 3.6 baremetal: syscall 回放表 → 嵌入 blob 追加区。
       回放表布局 (偏移相对 replay 区起点):
         +0   n_recs (u64)
         rec × n (80B): {pc, sysno, rax, n_unmap, unmap_off,
                         n_newseg, newseg_off, n_dirty, dirty_off, pad}
         数据区:
           unmap:  {vaddr} × n_unmap
           newseg: {vaddr,filesz,memsz,flags}(32B) + data(filesz) × n_newseg
           dirty:  {vaddr} + data(4096) × n_dirty
       stub 处理器: 触发 int3 的 pc 匹配记录 → 应用差异 (unmap/mmap+
       拷贝/mprotect + dirty 页覆盖) + 恢复 rax (B 的 syscall 返回值);
       游标顺序消费 (单线程执行顺序 == 记录顺序)。 */
    if (nrecs) {
        /* pass 2: 布局 — rec 表连续 (80B/条), 数据区统一在后 */
        struct buf replay;
        buf_init(&replay);
        if (blob.size & 7)
            buf_zero(&blob, 8 - (blob.size & 7)); /* 8B 对齐 */
        buf_zero(&replay, 8);                    /* n_recs */
        uint64_t *rec_off = xmalloc(nrecs * 8);
        for (size_t i = 0; i < nrecs; i++) {
            rec_off[i] = replay.size;
            buf_zero(&replay, 80);
        }
        uint64_t *unmap_off = xmalloc(nrecs * 8);
        uint64_t *newseg_off = xmalloc(nrecs * 8);
        uint64_t *dirty_off = xmalloc(nrecs * 8);
        for (size_t i = 0; i < nrecs; i++) {
            unmap_off[i] = replay.size;
            buf_append(&replay, recs[i].unmap.data, recs[i].unmap.size);
        }
        for (size_t i = 0; i < nrecs; i++) {
            newseg_off[i] = replay.size;
            buf_append(&replay, recs[i].newseg.data, recs[i].newseg.size);
        }
        for (size_t i = 0; i < nrecs; i++) {
            dirty_off[i] = replay.size;
            buf_append(&replay, recs[i].dirty.data, recs[i].dirty.size);
        }
        memcpy(replay.data, &nrecs, 8);
        for (size_t i = 0; i < nrecs; i++) {
            uint8_t *rc = replay.data + rec_off[i];
            uint64_t v;
            v = recs[i].pc;      memcpy(rc + 0, &v, 8);
            v = recs[i].sysno;   memcpy(rc + 8, &v, 8);
            v = recs[i].rax;     memcpy(rc + 16, &v, 8);
            v = recs[i].n_unmap; memcpy(rc + 24, &v, 8);
            v = unmap_off[i];    memcpy(rc + 32, &v, 8);
            v = recs[i].n_newseg; memcpy(rc + 40, &v, 8);
            v = newseg_off[i];   memcpy(rc + 48, &v, 8);
            v = recs[i].n_dirty; memcpy(rc + 56, &v, 8);
            v = dirty_off[i];    memcpy(rc + 64, &v, 8);
        }
        replay_off = blob.size;
        buf_append(&blob, replay.data, replay.size);
        replay_size = replay.size;
        blob_total = blob.size;
        fprintf(stderr, "build: %llu syscall replay records "
                "(%llu bytes)\n",
                (unsigned long long)nrecs,
                (unsigned long long)replay_size);
        free(rec_off);
        free(unmap_off);
        free(newseg_off);
        free(dirty_off);
    }
    /* 3.6 堆尾/栈段定位 (real 与 baremetal 共用)
       取第一个 [heap] 段: 真实 brk 区域 (mmap 的大块匿名段也可能被
       内核标为 [heap], 但真实 brk 指针是第一个) */
    for (size_t i = 0; i < s.h.nsegs; i++) {
        const char *nm = sn_str(&s, segs[i].name_off);
        if (segs[i].flags & ET_SEG_W) {
            if (!heap_end && strcmp(nm, "[heap]") == 0)
                heap_end = segs[i].vaddr + segs[i].memsz;
        }
        if (strstr(nm, "[stack]"))
            stack_vaddr = segs[i].vaddr;
    }

    /* 3.7 strict baremetal (aarch64): ELF loader 全内存 + 分支补偿 */
#if defined(__aarch64__)
    if (mode_baremetal && bm_strict) {
        if (ckpts && to_ckpt >= 0)
            atomic_load(ckpts, from_ckpt, to_ckpt, &ab);
        if (build_strict_aarch64(&s, &blob, base, blob_total, payload_off,
                                 segs,
                                 recs, nrecs, have_map, &ab, exit_override,
                                 ckpt_pcs, nckpt_pcs,
                                 ckpt_count0, ckpt_count_to,
                                 exit_count_override,
                                 stack_reserve, replay_off,
                                 heap_end,
                                 &sploads, &n_sploads,
                                 &strict_replay_abs) != 0)
            die("strict baremetal build failed");
        blob_total = blob.size;
        fprintf(stderr, "build: strict baremetal: %zu extra PT_LOADs\n",
                n_sploads);
    }
#endif
#if defined(__aarch64__)
    free(ab.sites);
    free(ab.runs);
    free(ab.run_off);
    free(ab.run_cnt);
#endif
    for (size_t i = 0; i < nrecs; i++) {
        free(recs[i].unmap.data);
        free(recs[i].newseg.data);
        free(recs[i].dirty.data);
    }
    free(recs);

    /* 4. 补丁 desc */
    if (memcmp(blob.data + RST_DESC_MAGIC, &(uint64_t){RST_DESC_MAGIC_VAL},
               8) != 0) {
        fprintf(stderr, "desc bytes: %02x %02x %02x %02x %02x %02x %02x %02x\n",
                blob.data[0], blob.data[1], blob.data[2], blob.data[3],
                blob.data[4], blob.data[5], blob.data[6], blob.data[7]);
        die("stub blob magic mismatch (stub/header mismatch?)");
    }
    uint64_t desc_flags = 0;
    if (s.h.nfds)
        desc_flags |= RST_FLAG_RESTORE_FDS;
    if (ipc_period)
        desc_flags |= RST_FLAG_IPC;
    blob_patch_u64(blob.data, RST_DESC_FLAGS, desc_flags);
    blob_patch_u64(blob.data, RST_DESC_TARGET_RIP, s.h.entry_pc);
    blob_patch_u64(blob.data, RST_DESC_N_SEGS, s.h.nsegs);
    blob_patch_u64(blob.data, RST_DESC_SEGS_OFF, segs_off);
    blob_patch_u64(blob.data, RST_DESC_N_FDS, s.h.nfds);
    blob_patch_u64(blob.data, RST_DESC_FDS_OFF, fds_off);
    blob_patch_u64(blob.data, RST_DESC_FPU_SIZE, s.h.fpu_size);
    blob_patch_u64(blob.data, RST_DESC_IPC_PERIOD, ipc_period);
    blob_patch_u64(blob.data, RST_DESC_IPC_FD, (uint64_t)-1);
    blob_patch_u64(blob.data, RST_DESC_MODE, mode_baremetal ? 1 : 0);
    blob_patch_u64(blob.data, RST_DESC_EXIT_ADDR, exit_override);
    blob_patch_u64(blob.data, RST_DESC_BRK_BASE, heap_end);
    blob_patch_u64(blob.data, RST_DESC_TARGET_TID, s.h.task_tid);
    blob_patch_u64(blob.data, RST_DESC_STACK_VADDR, stack_vaddr);
    blob_patch_u64(blob.data, RST_DESC_RLIM_STACK_CUR, s.h.rlim_stack_cur);
    blob_patch_u64(blob.data, RST_DESC_RLIM_STACK_MAX, s.h.rlim_stack_max);
    blob_patch_u64(blob.data, RST_DESC_TLS, s.h.tls);
    blob_patch_u64(blob.data, RST_DESC_BM_STYLE, bm_strict ? 1 : 0);
    blob_patch_u64(blob.data, RST_DESC_REPLAY_OFF, replay_off);
    blob_patch_u64(blob.data, RST_DESC_REPLAY_SIZE, replay_size);
    blob_patch_u64(blob.data, RST_DESC_REPLAY_CUR, 0);

    /* 可选: 在目标地址注入 int3 (gdb 无法在 stub 恢复前插入断点,
       此法在构建期直接修改内存映像, 恢复时自动生效) */
    if (breakpoint) {
        int hit = 0;
        for (size_t i = 0; i < s.h.nsegs; i++) {
            if (breakpoint >= segs[i].vaddr &&
                breakpoint < segs[i].vaddr + segs[i].filesz) {
                size_t off = payload_off + segs[i].payload_off +
                             (breakpoint - segs[i].vaddr);
                arch_patch_syscall(blob.data + off);
                hit = 1;
                break;
            }
        }
        if (!hit)
            die("breakpoint %#llx not in any captured segment",
                (unsigned long long)breakpoint);
        fprintf(stderr, "build: int3 injected at %#llx\n",
                (unsigned long long)breakpoint);
    }

    /* FPU 状态拷贝到 blob 固定区 */
    memcpy(blob.data + STUB_FPU_OFF, s.file + s.h.fpu_off, s.h.fpu_size);
    /* 信号掩码 */
    memcpy(blob.data + STUB_SIGMASK_OFF, s.file + s.h.sigmask_off, 8);
    /* 寄存器 */
    memcpy(blob.data + STUB_REGS_OFF, s.file + s.h.regs_off, s.h.regs_size);

    /* 5. 组装 ELF */
    buf_init(&file);
    Elf64_Ehdr eh;
    Elf64_Phdr *ph;
    Elf64_Shdr *sh;
    int nsh;
    int symtab_idx = -1, strtab_idx = -1;
    int strict_elf = 0;
#if defined(__aarch64__)
    strict_elf = (mode_baremetal && bm_strict);
#endif

    /* 节规划: 0=null, 1=.rst, 2..2+naux-1=aux(调试节), 2+naux=.shstrtab */
    nsh = 3 + s.h.aux_n;
    sh = xcalloc(nsh, sizeof(Elf64_Shdr));

    /* shstrtab 内容 */
    struct buf shstr;
    buf_init(&shstr);
    size_t name_rst, name_shstr;
    buf_append(&shstr, "\0", 1);
    name_rst = shstr.size;
    buf_append(&shstr, ".rst\0", 5);
    name_shstr = shstr.size;
    buf_append(&shstr, ".shstrtab\0", 10);

    /* ---- 布局:
       [0x000] ehdr (64)
       [0x040] phdr xN
       [0x1000] blob (blob_total)
       [之后]   strict: 各内存段/跳板页内容 (页对齐)
       [之后]   aux 节数据 (调试节内容)
       [之后]   shstrtab 数据
       [e_shoff] 节头表
    */
    uint64_t blob_file_off = 0x1000;
    uint64_t data_off = (blob_file_off + blob_total + 0xfff) & ~0xfffULL;
    uint64_t aux_data_off = data_off;

    /* strict: 排序后的附加 PT_LOAD (初始段 + strict ploads) */
    struct strict_emit {
        uint64_t vaddr, filesz, memsz;
        const uint8_t *data;
        int is_seg;
        size_t idx;
    } *sem = NULL;
    size_t n_sem = 0;
    if (strict_elf) {
        n_sem = s.h.nsegs + n_sploads;
        sem = xcalloc(n_sem, sizeof(*sem));
        for (size_t i = 0; i < s.h.nsegs; i++) {
            sem[i].vaddr = segs[i].vaddr;
            sem[i].filesz = segs[i].filesz;
            sem[i].memsz = segs[i].memsz;
            /* 必须用 blob 内的副本: syscall/退出点已在 blob payload 中
               patch (b <跳板>), 快照文件里是原始指令 */
            sem[i].data = blob.data + payload_off + segs[i].payload_off;
            sem[i].is_seg = 1;
            sem[i].idx = i;
        }
        for (size_t i = 0; i < n_sploads; i++) {
            sem[s.h.nsegs + i].vaddr = sploads[i].vaddr;
            sem[s.h.nsegs + i].filesz = sploads[i].filesz;
            sem[s.h.nsegs + i].memsz = sploads[i].memsz;
            sem[s.h.nsegs + i].data = sploads[i].data;
            sem[s.h.nsegs + i].is_seg = 0;
            sem[s.h.nsegs + i].idx = i;
        }
        /* 按 vaddr 稳定排序 (同 vaddr 保持追加顺序, 后者覆盖前者) */
        for (size_t i = 1; i < n_sem; i++) {
            struct strict_emit t = sem[i];
            size_t j = i;
            while (j > 0 && sem[j - 1].vaddr > t.vaddr) {
                sem[j] = sem[j - 1];
                j--;
            }
            sem[j] = t;
        }
    }
    size_t nload = 2 + (strict_elf ? n_sem : 0);
    ph = xcalloc(nload, sizeof(*ph));
    size_t nload_used = 0;
    ph[nload_used++] = (Elf64_Phdr){
        .p_type = PT_LOAD,
        .p_flags = PF_R | PF_W | PF_X,
        .p_offset = blob_file_off,
        .p_vaddr = base,
        .p_paddr = base,
        .p_filesz = blob_total,
        .p_memsz = blob_total,
        .p_align = 0x1000,
    };
    for (size_t i = 0; i < n_sem; i++) {
        Elf64_Phdr *p = &ph[nload_used++];
        p->p_type = PT_LOAD;
        p->p_flags = PF_R | PF_W | PF_X;   /* strict: 统一 RWX, 补偿直接写 */
        p->p_vaddr = sem[i].vaddr;
        p->p_paddr = sem[i].vaddr;
        p->p_filesz = sem[i].filesz;
        p->p_memsz = sem[i].memsz;
        p->p_align = 0x1000;
        if (sem[i].filesz) {
            p->p_offset = data_off;
            data_off = (data_off + sem[i].filesz + 0xfff) & ~0xfffULL;
        } else {
            p->p_offset = data_off;   /* 纯 BSS: 无文件数据 */
        }
    }
    ph[nload_used++].p_type = PT_GNU_STACK;
    ph[nload - 1].p_flags = PF_R | PF_W;
    ph[nload - 1].p_align = 0x10;
    if (nload_used != nload)
        die("internal: phdr count mismatch");
    aux_data_off = data_off;
    for (size_t i = 0; i < s.h.aux_n; i++) {
        elftrace_aux *a = (elftrace_aux *)(s.file + s.h.aux_off) + i;
        size_t si = 2 + i;
        size_t so = shstr.size;
        const char *nm = sn_str(&s, a->name_off);
        buf_append(&shstr, nm, strlen(nm) + 1);

        sh[si].sh_name = so;
        sh[si].sh_type = a->type;
        sh[si].sh_flags = a->flags;
        sh[si].sh_addr = a->addr;
        sh[si].sh_offset = (aux_data_off + 7) & ~7ULL;
        sh[si].sh_size = a->size;
        sh[si].sh_addralign = a->align;
        sh[si].sh_entsize = a->entsize;
        sh[si].sh_link = a->link;
        sh[si].sh_info = a->info;
        if (a->type == SHT_SYMTAB)
            symtab_idx = si;
        if (a->type == SHT_STRTAB)
            strtab_idx = si;
        aux_data_off = sh[si].sh_offset + sh[si].sh_size;
    }

    /* .symtab 的 sh_link 指向新 .strtab 索引 */
    if (symtab_idx >= 0 && strtab_idx >= 0)
        sh[symtab_idx].sh_link = strtab_idx;

    /* .rst 节 */
    sh[0] = (Elf64_Shdr){0};
    sh[1].sh_name = name_rst;
    sh[1].sh_type = SHT_PROGBITS;
    sh[1].sh_flags = SHF_ALLOC | SHF_WRITE | SHF_EXECINSTR;
    sh[1].sh_addr = base;
    sh[1].sh_offset = blob_file_off;
    sh[1].sh_size = blob_total;
    sh[1].sh_addralign = 0x1000;

    /* .shstrtab 节 */
    uint64_t shstr_off = (aux_data_off + 7) & ~7ULL;
    sh[2 + s.h.aux_n].sh_name = name_shstr;
    sh[2 + s.h.aux_n].sh_type = SHT_STRTAB;
    sh[2 + s.h.aux_n].sh_offset = shstr_off;
    sh[2 + s.h.aux_n].sh_size = shstr.size;
    sh[2 + s.h.aux_n].sh_addralign = 1;

    memset(&eh, 0, sizeof(eh));
    memcpy(eh.e_ident, ELFMAG, 4);
    eh.e_ident[EI_CLASS] = ELFCLASS64;
    eh.e_ident[EI_DATA] = ELFDATA2LSB;
    eh.e_ident[EI_VERSION] = EV_CURRENT;
    eh.e_type = ET_EXEC;
    eh.e_machine = s.h.arch == ELFTRACE_ARCH_AARCH64 ? EM_AARCH64
                                                     : EM_X86_64;
    eh.e_version = EV_CURRENT;
    eh.e_entry = base + STUB_ENTRY_OFF;
    eh.e_phoff = 64;
    eh.e_shoff = (shstr_off + shstr.size + 7) & ~7ULL;
    eh.e_flags = 0;
    eh.e_ehsize = 64;
    eh.e_phentsize = sizeof(Elf64_Phdr);
    eh.e_phnum = (uint16_t)nload;
    eh.e_shentsize = sizeof(Elf64_Shdr);
    eh.e_shnum = nsh;
    eh.e_shstrndx = 2 + s.h.aux_n;

    buf_append(&file, &eh, sizeof(eh));
    buf_append(&file, ph, nload * sizeof(*ph));
    buf_zero(&file, blob_file_off - file.size);
    buf_append(&file, blob.data, blob_total);
    /* strict: 各内存段/跳板页内容 (按 phdr 顺序发射) */
    for (size_t i = 0; i < n_sem; i++) {
        if (!sem[i].filesz)
            continue;
        buf_zero(&file, ph[1 + i].p_offset - file.size);
        buf_append(&file, sem[i].data, sem[i].filesz);
    }
    /* aux 数据 */
    for (size_t i = 0; i < s.h.aux_n; i++) {
        elftrace_aux *a = (elftrace_aux *)(s.file + s.h.aux_off) + i;
        buf_zero(&file, sh[2 + i].sh_offset - file.size);
        buf_append(&file, s.file + s.h.payload_off + a->payload_off, a->size);
    }
    /* shstrtab 数据 */
    buf_zero(&file, shstr_off - file.size);
    buf_append(&file, shstr.data, shstr.size);
    /* 节头表 */
    buf_zero(&file, eh.e_shoff - file.size);
    for (int i = 0; i < nsh; i++)
        buf_append(&file, &sh[i], sizeof(sh[i]));

    fd = open(out, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd < 0)
        die("cannot create %s", out);
    size_t woff = 0;
    while (woff < file.size) {
        ssize_t n = write(fd, file.data + woff, file.size - woff);
        if (n < 0)
            die("write %s: %s", out, strerror(errno));
        woff += (size_t)n;
    }
    close(fd);

    fprintf(stderr, "build: %s written (entry %#llx, %zu sections)\n", out,
            (unsigned long long)eh.e_entry, (size_t)nsh);
    return 0;
}
