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
#include <elf.h>

#include "elftrace.h"
#include "elftrace_stub.h"
#include "util.h"

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

int build_main(int argc, char **argv)
{
    const char *in = NULL;
    const char *out = "sliced.elf";
    uint64_t ipc_period = 0;
    uint64_t breakpoint = 0;    /* 注入 int3 的地址 (0 = 无) */
    struct snap s = {0};
    int fd;
    struct buf blob;            /* 最终 blob (stub + 追加数据) */
    uint64_t base;
    struct buf file;            /* 输出 ELF 文件 */
    elftrace_seg *segs;
    elftrace_fd *fds;


    uint64_t segs_off, fds_off, strings_off, payload_off;
    uint64_t blob_total;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            out = argv[++i];
        } else if (strcmp(argv[i], "--ipc") == 0 && i + 1 < argc) {
            ipc_period = strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--breakpoint") == 0 && i + 1 < argc) {
            breakpoint = strtoull(argv[++i], NULL, 0);
        } else if (argv[i][0] != '-') {
            in = argv[i];
        } else {
            die("usage: elftrace build <file.elftrace> [-o out.elf] "
                "[--ipc N] [--breakpoint ADDR]");
        }
    }
    if (!in)
        die("usage: elftrace build <file.elftrace> [-o out.elf] "
            "[--ipc N] [--breakpoint ADDR]");
    s.ipc_period = ipc_period;

    /* 1. 读入 .elftrace */
    fd = open(in, O_RDONLY);
    if (fd < 0)
        die("cannot open %s", in);
    s.file_size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    s.file = xmalloc(s.file_size);
    if (read(fd, s.file, s.file_size) != (ssize_t)s.file_size)
        die("short read on %s", in);
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
    if (write(fd, file.data, file.size) != (ssize_t)file.size)
        die("short write to %s", out);
    close(fd);

    fprintf(stderr, "build: %s written (entry %#llx, %zu sections)\n", out,
            (unsigned long long)eh.e_entry, (size_t)nsh);
    return 0;
}
