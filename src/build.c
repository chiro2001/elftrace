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

/* ---- 生成的 stub blob ---- */
extern const unsigned char stub_blob_x86_64[];
extern const unsigned int stub_blob_x86_64_len;

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
                "[--from K] [--to M] [--breakpoint ADDR]");
        }
    }
    if (!in)
        die("usage: elftrace build <file.elftrace> [-o out.elf] "
            "[--mode real|baremetal] [--ipc N] [--checkpoints DIR] "
            "[--from K] [--to M] [--breakpoint ADDR]");

    /* --from/--to: 用 trace 检查点替代基础镜像并确定退出点 */
    uint64_t syscall_start = 0, syscall_end = UINT64_MAX;
    uint64_t resume_pc = 0;   /* 切片恢复点 pc (丢弃悬空记录用) */
    if (ckpts) {
        char path[PATH_MAX];
        FILE *f;
        uint64_t count0 = 0, ip0 = 0;
        uint64_t count_to = 0, ip_to = 0;
        long idx = 0, found_from = -1;

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
        if (found_from < 0)
            die("checkpoint %ld not found in %s", from_ckpt, path);
        if (to_ckpt >= 0 && idx <= to_ckpt)
            die("checkpoint %ld not found (have %ld)", to_ckpt, idx);
        fprintf(stderr, "build: base = checkpoint %ld (count %llu, pc %#llx)\n",
                found_from, (unsigned long long)count0,
                (unsigned long long)ip0);

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
                /* 退出地址 = 检查点 to 的 pc (替换该处指令) */
                exit_override = ip_to;
                if (ipc_period == 0)
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
    if (s.h.arch != ELFTRACE_ARCH_X86_64)
        die("%s: architecture %u not yet supported (x86_64 only)", in,
            s.h.arch);

    /* 2. 构造 blob: 固定区 + segs 表 + fds 表 + 字符串 + payload */
    buf_init(&blob);
    buf_append(&blob, stub_blob_x86_64, stub_blob_x86_64_len);
    /* 固定区不足则补齐 (stub_blob 可能略大于/略小于 STUB_FIXED_SIZE:
       .org 保证 >= STUB_FIXED_SIZE, ld 可能在尾部追加少量对齐填充) */
    if (blob.size < STUB_FIXED_SIZE)
        buf_zero(&blob, STUB_FIXED_SIZE - blob.size);
    if (blob.size > STUB_FIXED_SIZE)
        fprintf(stderr, "build: note: stub blob %u bytes exceeds fixed area "
                "%#x by %u (padding)\n", stub_blob_x86_64_len, STUB_FIXED_SIZE,
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

    /* 3.5 baremetal: 段表加载后确定 brk 边界与退出地址的 blob 位置 */
    if (mode_baremetal) {
        if (exit_override) {
            int hit = 0;
            for (size_t i = 0; i < s.h.nsegs; i++) {
                if (exit_override >= segs[i].vaddr &&
                    exit_override < segs[i].vaddr + segs[i].filesz) {
                    size_t off = payload_off + segs[i].payload_off +
                                 (exit_override - segs[i].vaddr);
                    blob.data[off] = 0xcc;      /* int3 */
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
    struct rec_tmp {
        uint64_t pc, sysno, rax;
        uint64_t n_unmap, n_newseg, n_dirty;
        struct buf unmap, newseg, dirty;
    } *recs = NULL;
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
                char tag[8] = "";
                uint64_t pc, sysno;
                if (sscanf(line, "%llx %llu %255s %7s", &pc, &sysno,
                           fname, tag) < 3)
                    continue;
                /* 只保留切片区间 [syscall_start, syscall_end) 内的记录:
                   切片从检查点 from 恢复, from 之前的 syscall 不执行 */
                if (map_idx < syscall_start ||
                    map_idx >= syscall_end) {
                    map_idx++;
                    continue;
                }
                map_idx++;
                /* 悬空的被打断 syscall 记录 (map 第 4 字段 "I"):
                   检查点 INTERRUPT 打断的在途 syscall, 记录在检查点之后
                   补记; 切片从该检查点恢复时 pc 在 syscall 指令之后
                   (resume_pc == rec.pc+2), 不会重执行它。若保留, 记录
                   会错误消费下一条同 pc 的 syscall (libc 共享
                   trampoline 场景, 曾致 read 被回放成已完成的
                   nanosleep 而返回 EOF)。 */
                if (tag[0] == 'I' && pc + 2 == resume_pc) {
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
                    memcpy(&r->rax, f + sizeof(h) + 0x50, 8); /* regs.rax */
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

    /* 3.5b baremetal: syscall 指令 → int3 替换
       (kernel entry-stop 的 ip 是 syscall 指令的下一条; x86_64 0f05
       长 2, int3 打在 pc-2。trace 被打断的 syscall 记录 pc 已修正为
       syscall 地址本身, 检查 blob[pc] 即可)。 */
    if (mode_baremetal) {
        if (nrecs) {
            /* 回放路径: 只替换 trace 记录过的 syscall 指令。
               这是权威的 syscall 地址表, 不做全段字节扫描 —
               直接扫描 0f 05 会误伤指令立即数/操作数中的同字节序列
               (例如 movabs $0x50f → 48 b8 0f 05 ...), 静默改变切片
               行为 (曾致 embed 值从 0x50f 变 0x90cc)。 */
            size_t replaced = 0, dropped = 0;
            for (size_t k = 0; k < nrecs; k++) {
                uint64_t pc = recs[k].pc;
                /* 常规记录: pc = entry-stop ip = syscall+2 */
                if (pc >= 2) {
                    uint8_t *s2 = NULL;
                    for (size_t i = 0; i < s.h.nsegs; i++) {
                        if (pc - 2 >= segs[i].vaddr &&
                            pc - 2 < segs[i].vaddr + segs[i].filesz) {
                            s2 = blob.data + payload_off +
                                 segs[i].payload_off + (pc - 2 -
                                                        segs[i].vaddr);
                            break;
                        }
                    }
                    if (s2 && s2[0] == 0x0f && s2[1] == 0x05) {
                        s2[0] = 0xcc;
                        s2[1] = 0x90;
                        recs[k].pc = pc - 2;
                        replaced++;
                        continue;
                    }
                    if (s2 && s2[0] == 0xcc) {
                        /* 已被替换 (退出点 int3 重叠/重复记录) */
                        recs[k].pc = pc - 2;
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
                    if (q && q[0] == 0x0f && q[1] == 0x05) {
                        q[0] = 0xcc;
                        q[1] = 0x90;
                        replaced++;
                        continue;
                    }
                    if (q && q[0] == 0xcc)
                        continue;   /* 已替换 */
                }
                warn("baremetal: syscall rec @ %#llx has no int3 site, "
                     "record unused", (unsigned long long)pc);
                dropped++;
            }
            fprintf(stderr, "        %zu syscall instructions replaced by "
                    "int3 (replay), %zu dropped\n", replaced, dropped);
        } else if (!have_map) {
            /* 旧 mock 路径 (freeze 快照, 无 trace 回放表):
               先用 x86-64 长度解码器从段起点顺序扫描 — 只把"完整解码
               为 2 字节 0F 05 指令"的地址替换 (指令边界, 不误伤立即数);
               遇到无法解码的位置 (段内嵌数据表等) 后, 剩余部分退回
               模式扫描 (0f 05 → cc 90, 已知局限: 可能破坏该区域内指令
               立即数, 仅作为无 trace 数据时的兜底)。 */
            size_t replaced = 0;
            for (size_t i = 0; i < s.h.nsegs; i++) {
                if (!(segs[i].flags & ET_SEG_X))
                    continue;
                size_t base = payload_off + segs[i].payload_off;
                size_t off = 0;
                while (off + 1 < segs[i].filesz) {
                    if (blob.data[base + off] == 0x0f &&
                        blob.data[base + off + 1] == 0x05 &&
                        x86_is_syscall(blob.data + base + off,
                                       segs[i].filesz - off)) {
                        blob.data[base + off] = 0xcc;
                        blob.data[base + off + 1] = 0x90;
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
                        blob.data[base + j] = 0xcc;
                        blob.data[base + j + 1] = 0x90;
                        replaced++;
                    }
                }
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
    for (size_t i = 0; i < nrecs; i++) {
        free(recs[i].unmap.data);
        free(recs[i].newseg.data);
        free(recs[i].dirty.data);
    }
    free(recs);

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
                blob.data[off] = 0xcc;
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
    Elf64_Phdr ph[2];
    Elf64_Shdr *sh;
    int nsh;
    int symtab_idx = -1, strtab_idx = -1;

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
       [0x040] phdr x2 (112)  -> 0xC0
       [0x1000] blob (blob_total)
       [shoff]  aux 节数据 (调试节内容)
       [之后]   shstrtab 数据
       [e_shoff] 节头表
    */
    uint64_t blob_file_off = 0x1000;
    uint64_t shoff = (blob_file_off + blob_total + 7) & ~7ULL;
    uint64_t aux_data_off = shoff;
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
    eh.e_machine = EM_X86_64;
    eh.e_version = EV_CURRENT;
    eh.e_entry = base + STUB_ENTRY_OFF;
    eh.e_phoff = 64;
    eh.e_shoff = (shstr_off + shstr.size + 7) & ~7ULL;
    eh.e_flags = 0;
    eh.e_ehsize = 64;
    eh.e_phentsize = sizeof(Elf64_Phdr);
    eh.e_phnum = 2;
    eh.e_shentsize = sizeof(Elf64_Shdr);
    eh.e_shnum = nsh;
    eh.e_shstrndx = 2 + s.h.aux_n;

    memset(&ph, 0, sizeof(ph));
    ph[0].p_type = PT_LOAD;
    ph[0].p_flags = PF_R | PF_W | PF_X;
    ph[0].p_offset = blob_file_off;
    ph[0].p_vaddr = base;
    ph[0].p_paddr = base;
    ph[0].p_filesz = blob_total;
    ph[0].p_memsz = blob_total;
    ph[0].p_align = 0x1000;
    ph[1].p_type = PT_GNU_STACK;
    ph[1].p_flags = PF_R | PF_W;
    ph[1].p_align = 0x10;

    buf_append(&file, &eh, sizeof(eh));
    buf_append(&file, &ph, sizeof(ph));
    buf_zero(&file, blob_file_off - file.size);
    buf_append(&file, blob.data, blob_total);
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
