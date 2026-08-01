/*
 * elftrace freeze: 数据采集器
 *
 * 冻结指定进程 (ptrace seize + interrupt, 保持其停止), 采集:
 *   - 通用寄存器 (PTRACE_GETREGS, x86_64 struct user_regs_struct == pt_regs)
 *   - FPU/xstate (PTRACE_GETREGSET NT_X86_XSTATE, XSAVE 非压缩格式)
 *   - 信号掩码 (PTRACE_GETSIGMASK, 内核 sigset_t 8 字节)
 *   - 内存段 (/proc/<pid>/maps + /proc/<pid>/mem), 跳过 vdso/vvar/vsyscall
 *   - fd 列表 (/proc/<pid>/fd + fdinfo): 仅支持常规文件 (按路径重开恢复)
 *   - 主可执行文件的调试节 (aux): .debug_*, .symtab, .strtab
 * 结果写入 .elftrace 中间文件, 供 build 组装 ELF。
 *
 * 采集完成后 PTRACE_DETACH: 由于使用 SEIZE+INTERRUPT, 目标进程保持冻结。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <elf.h>

#include "elftrace.h"
#include "util.h"

/* ---- 可扩展缓冲 ---- */
struct buf {
    uint8_t *data;
    size_t size;
    size_t cap;
};

static void buf_init(struct buf *b)
{
    b->data = NULL;
    b->size = 0;
    b->cap = 0;
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

/* ---- 采集到的进程状态 ---- */
struct seg {
    uint64_t vaddr;
    uint64_t filesz;        /* 采集到的字节数 */
    uint64_t memsz;
    uint64_t flags;         /* PF_* */
    char *name;             /* maps 路径名, 可为 NULL */
};

struct fdinfo {
    uint64_t fd;
    uint64_t flags;         /* O_* */
    uint64_t mode;
    uint64_t pos;
    char *path;             /* NULL = 不支持的类型 */
};

struct auxent {
    char *name;
    uint64_t addr;
    uint64_t size;
    uint64_t type;
    uint64_t flags;
    uint64_t align;
    uint64_t entsize;
    uint64_t link;
    uint64_t info;
    uint8_t *data;          /* 内容 (从原 ELF 拷贝) */
};

struct snapshot {
    pid_t pid;
    uint32_t arch;              /* ELFTRACE_ARCH_* */
    struct user_regs_struct regs;
    uint8_t *xstate;
    size_t xstate_size;
    uint8_t sigmask[8];
    int in_syscall;

    struct seg *segs;
    size_t nsegs;
    uint64_t *payload_offs;     /* 每段在 payload 中的偏移 */
    struct buf payload;         /* 段内容顺序拼接 */

    struct fdinfo *fds;
    size_t nfds;

    char *exe_path;
    uint64_t exe_bias;          /* PIE 加载偏置 */

    struct auxent *aux;
    size_t naux;
};

static int is_supported_fd_path(const char *path)
{
    return strncmp(path, "socket:", 7) != 0 &&
           strncmp(path, "pipe:", 5) != 0 &&
           strncmp(path, "anon_inode:", 11) != 0;
}

/* ---- /proc/<pid>/fdinfo 解析: pos 和 flags ---- */
static void parse_fdinfo(pid_t pid, struct fdinfo *fi)
{
    char path[64];
    char buf[512];
    int fd = open(path, O_RDONLY);
    ssize_t n;

    snprintf(path, sizeof(path), "/proc/%d/fdinfo/%llu", pid,
             (unsigned long long)fi->fd);
    fd = open(path, O_RDONLY);
    if (fd < 0)
        return;
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return;
    buf[n] = 0;

    char *p = buf;
    while (p && *p) {
        char *eol = strchr(p, '\n');
        if (!eol)
            eol = p + strlen(p);
        if (strncmp(p, "pos:\t", 5) == 0)
            fi->pos = strtoull(p + 5, NULL, 10);
        else if (strncmp(p, "flags:\t", 7) == 0)
            fi->flags = strtoull(p + 7, NULL, 8);   /* fdinfo flags 是八进制 */
        p = *eol ? eol + 1 : NULL;
    }
}

/* ---- 采集 fd ---- */
static void collect_fds(struct snapshot *sn)
{
    char path[64];
    char link[PATH_MAX];
    struct dirent *de;
    DIR *d;
    int cap = 16;

    snprintf(path, sizeof(path), "/proc/%d/fd", sn->pid);
    d = opendir(path);
    if (!d)
        return;

    sn->fds = xcalloc(cap, sizeof(struct fdinfo));
    while ((de = readdir(d))) {
        struct fdinfo fi = {0};
        struct stat st;

        if (de->d_name[0] == '.')
            continue;
        fi.fd = strtoull(de->d_name, NULL, 10);

        snprintf(path, sizeof(path), "/proc/%d/fd/%s", sn->pid, de->d_name);
        ssize_t n = readlink(path, link, sizeof(link) - 1);
        if (n < 0)
            continue;
        link[n] = 0;
        if (stat(link, &st) == 0)
            fi.mode = st.st_mode & 07777;
        if (!is_supported_fd_path(link)) {
            fi.path = NULL;         /* pipe/socket/anon: 暂不支持 */
        } else {
            fi.path = xstrdup(link);
        }
        parse_fdinfo(sn->pid, &fi);

        if (sn->nfds == (size_t)cap) {
            cap *= 2;
            sn->fds = xrealloc(sn->fds, cap * sizeof(struct fdinfo));
        }
        sn->fds[sn->nfds++] = fi;
    }
    closedir(d);
}

/* ---- 采集内存段 ---- */
static void collect_segments(struct snapshot *sn)
{
    char path[64];
    char line[1024];
    FILE *f;
    int cap = 32;

    snprintf(path, sizeof(path), "/proc/%d/maps", sn->pid);
    f = fopen(path, "r");
    if (!f)
        die("cannot open %s", path);

    sn->segs = xcalloc(cap, sizeof(struct seg));
    while (fgets(line, sizeof(line), f)) {
        unsigned long long start, end;
        char perms[8], name[512];
        int n;

        n = sscanf(line, "%llx-%llx %7s %*s %*s %*s %511[^\n]", &start, &end,
                   perms, name);
        if (n < 3)
            continue;
        if (n == 4 && name[0] == ' ')
            memmove(name, name + 1, strlen(name));  /* 去掉路径前导空格 */

        /* 跳过内核管理区域 */
        if (strstr(name, "[vdso]") || strstr(name, "[vvar") ||
            strstr(name, "[vsyscall]") || strstr(name, "[sigpage]"))
            continue;
        /* 跳过无权限区域 */
        if (perms[0] == '-' && perms[1] == '-' && perms[2] == '-')
            continue;

        struct seg s = {0};
        s.vaddr = start;
        s.memsz = end - start;
        s.flags = 0;
        if (perms[0] == 'r') s.flags |= PF_R;
        if (perms[1] == 'w') s.flags |= PF_W;
        if (perms[2] == 'x') s.flags |= PF_X;
        s.name = (n && name[0]) ? xstrdup(name) : NULL;

        if (sn->nsegs == (size_t)cap) {
            cap *= 2;
            sn->segs = xrealloc(sn->segs, cap * sizeof(struct seg));
        }
        sn->segs[sn->nsegs++] = s;
    }
    fclose(f);
}

/* 从 /proc/<pid>/mem 读取一段内存, 返回实际读取字节数 (页粒度, 失败截断) */
static size_t read_mem(pid_t pid, uint64_t vaddr, uint64_t size,
                       uint8_t *out, int warn_on_partial)
{
    char path[64];
    size_t got = 0;
    int fd;

    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    fd = open(path, O_RDONLY);
    if (fd < 0)
        die("cannot open %s", path);

    while (got < size) {
        ssize_t n = pread(fd, out + got, size - got, vaddr + got);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (n == 0)
            break;
        got += n;
    }
    close(fd);
    if (warn_on_partial && got < size)
        warn("segment %#llx read %zu of %llu bytes",
             (unsigned long long)vaddr, got, (unsigned long long)size);
    return got;
}

/* ---- 提取主可执行文件的调试节 + 分配节 ---- */
int dwarf_patch_bias(uint8_t *data, size_t size, const char *name,
                     uint64_t bias, const uint8_t *abbrev, size_t abbrev_size);

static void collect_aux(struct snapshot *sn)
{
    int fd;
    Elf64_Ehdr eh;
    Elf64_Shdr *sh = NULL;
    Elf64_Shdr shstr_sh;
    char *shstr = NULL;
    uint8_t *debug_abbrev = NULL;
    size_t debug_abbrev_size = 0;
    int cap = 8;
    uint64_t file_base = 0;     /* 文件中第一个 PT_LOAD 的 p_vaddr */
    uint64_t runtime_base = 0;  /* exe 在目标进程中的基址 */
    int nph;

    if (!sn->exe_path)
        return;
    fd = open(sn->exe_path, O_RDONLY);
    if (fd < 0) {
        warn("cannot open exe %s for debug sections: %s",
             sn->exe_path, strerror(errno));
        return;
    }
    if (read(fd, &eh, sizeof(eh)) != sizeof(eh) ||
        memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 ||
        eh.e_ident[EI_CLASS] != ELFCLASS64) {
        close(fd);
        return;
    }
    if (eh.e_shoff == 0 || eh.e_shnum == 0) {
        close(fd);
        return;
    }

    /* 计算 PIE 加载偏置: runtime 基址 (最低 exe 映射) - 文件第一个 LOAD p_vaddr */
    nph = eh.e_phnum;
    for (int i = 0; i < nph; i++) {
        Elf64_Phdr ph;
        if (pread(fd, &ph, sizeof(ph), eh.e_phoff + i * sizeof(ph)) !=
            sizeof(ph))
            break;
        if (ph.p_type == PT_LOAD) {
            file_base = ph.p_vaddr;
            break;
        }
    }
    for (size_t i = 0; i < sn->nsegs; i++) {
        if (sn->segs[i].name &&
            strcmp(sn->segs[i].name, sn->exe_path) == 0 &&
            (!runtime_base || sn->segs[i].vaddr < runtime_base))
            runtime_base = sn->segs[i].vaddr;
    }
    if (runtime_base)
        sn->exe_bias = runtime_base - file_base;
    else
        sn->exe_bias = 0;
    fprintf(stderr, "aux: exe=%s file_base=%#llx runtime_base=%#llx bias=%#llx\n",
            sn->exe_path, (unsigned long long)file_base,
            (unsigned long long)runtime_base, (unsigned long long)sn->exe_bias);

    sh = xcalloc(eh.e_shnum, sizeof(Elf64_Shdr));
    if (pread(fd, sh, sizeof(Elf64_Shdr) * eh.e_shnum, eh.e_shoff) !=
        (ssize_t)(sizeof(Elf64_Shdr) * eh.e_shnum)) {
        close(fd);
        free(sh);
        return;
    }

    sn->aux = xcalloc(cap, sizeof(struct auxent));

    /* 预读 .debug_abbrev (供 .debug_info 解析) */
    for (int i = 0; i < eh.e_shnum; i++) {
        const char *name;
        if (i == eh.e_shstrndx)
            continue;
        if (pread(fd, &shstr_sh, sizeof(shstr_sh), eh.e_shoff +
                  eh.e_shstrndx * sizeof(Elf64_Shdr)) != sizeof(shstr_sh))
            break;
        shstr = xrealloc(shstr, shstr_sh.sh_size);
        if (pread(fd, shstr, shstr_sh.sh_size, shstr_sh.sh_offset) !=
            (ssize_t)shstr_sh.sh_size)
            break;
        if (sh[i].sh_name >= shstr_sh.sh_size)
            continue;
        name = shstr + sh[i].sh_name;
        if (strcmp(name, ".debug_abbrev") == 0 && sh[i].sh_size) {
            debug_abbrev = xmalloc(sh[i].sh_size);
            if (pread(fd, debug_abbrev, sh[i].sh_size, sh[i].sh_offset) ==
                (ssize_t)sh[i].sh_size)
                debug_abbrev_size = sh[i].sh_size;
            break;
        }
    }

    for (int i = 0; i < eh.e_shnum; i++) {
        const char *name;
        int keep = 0;

        if (i == eh.e_shstrndx)
            continue;
        if (pread(fd, &shstr_sh, sizeof(shstr_sh), eh.e_shoff +
                  eh.e_shstrndx * sizeof(Elf64_Shdr)) != sizeof(shstr_sh))
            break;
        shstr = xrealloc(shstr, shstr_sh.sh_size);
        if (pread(fd, shstr, shstr_sh.sh_size, shstr_sh.sh_offset) !=
            (ssize_t)shstr_sh.sh_size)
            break;
        if (sh[i].sh_name >= shstr_sh.sh_size)
            continue;
        name = shstr + sh[i].sh_name;

        if (strncmp(name, ".debug", 6) == 0 || strcmp(name, ".symtab") == 0 ||
            strcmp(name, ".strtab") == 0 || strcmp(name, ".comment") == 0)
            keep = 1;
        /* 运行时分配节: 供 gdb 对齐地址。跳过动态链接器相关节
           (切片是静态的, 这些节只会让 gdb 困惑) */
        if (sh[i].sh_flags & SHF_ALLOC) {
            if (strncmp(name, ".note", 5) == 0 ||
                strncmp(name, ".gnu", 4) == 0 ||
                strncmp(name, ".rel", 4) == 0 ||
                strncmp(name, ".dyn", 4) == 0 ||
                strncmp(name, ".tdata", 6) == 0 ||
                strncmp(name, ".tbss", 5) == 0 ||
                strcmp(name, ".interp") == 0 || strcmp(name, ".plt") == 0 ||
                strcmp(name, ".plt.got") == 0 || strcmp(name, ".plt.sec") == 0 ||
                strcmp(name, ".got") == 0 || strcmp(name, ".got.plt") == 0 ||
                strcmp(name, ".dynamic") == 0)
                keep = 0;
            else
                keep = 1;
        }

        if (!keep)
            continue;

        struct auxent a = {0};
        a.name = xstrdup(name);
        a.addr = sh[i].sh_addr + sn->exe_bias;
        a.size = sh[i].sh_size;
        a.type = sh[i].sh_type;
        a.flags = sh[i].sh_flags;
        a.align = sh[i].sh_addralign;
        a.entsize = sh[i].sh_entsize;
        /* 仅 SYMTAB 节需要 sh_link (指向 .strtab, 组装时重映射);
           其余节在原文件中的 link 索引在新 ELF 中无效, 清零 */
        a.link = (sh[i].sh_type == SHT_SYMTAB) ? sh[i].sh_link : 0;
        a.info = sh[i].sh_info;
        a.data = xmalloc(a.size ? a.size : 1);
        if (a.size && sh[i].sh_type != SHT_NOBITS &&
            pread(fd, a.data, a.size, sh[i].sh_offset) != (ssize_t)a.size) {
            warn("short read on section %s", name);
            free(a.data);
            free(a.name);
            continue;
        }
        if (sh[i].sh_type == SHT_NOBITS)
            memset(a.data, 0, a.size);
        /* DWARF 地址偏置修补 (PIE) */
        if (strncmp(name, ".debug", 6) == 0)
            dwarf_patch_bias(a.data, a.size, name, sn->exe_bias,
                             debug_abbrev, debug_abbrev_size);
        /* symtab: 已定义符号地址加 bias */
        if (sh[i].sh_type == SHT_SYMTAB && sn->exe_bias) {
            for (uint64_t s = 0; s + sizeof(Elf64_Sym) <= a.size;
                 s += sizeof(Elf64_Sym)) {
                Elf64_Sym *sym = (Elf64_Sym *)(a.data + s);
                if (sym->st_shndx != SHN_UNDEF && sym->st_shndx != SHN_ABS &&
                    sym->st_shndx != SHN_COMMON)
                    sym->st_value += sn->exe_bias;
            }
        }
        if (sn->naux == (size_t)cap) {
            cap *= 2;
            sn->aux = xrealloc(sn->aux, cap * sizeof(struct auxent));
        }
        sn->aux[sn->naux++] = a;
    }
    close(fd);
    free(sh);
    free(shstr);
    free(debug_abbrev);
}

/* ---- 判断目标是否处于系统调用中 (rip-2 为 syscall 指令) ---- */
static void detect_in_syscall(struct snapshot *sn)
{
    uint8_t insn[2];

    if (sn->regs.orig_rax == (unsigned long)-1)
        return;
    if (sn->regs.rip < 2)
        return;
    if (read_mem(sn->pid, sn->regs.rip - 2, 2, insn, 0) != 2)
        return;
    if (insn[0] == 0x0f && insn[1] == 0x05) {
        sn->in_syscall = 1;
        warn("tracee %d frozen inside syscall %ld; in-flight syscall "
             "will be lost in the slice", sn->pid, (long)sn->regs.orig_rax);
    }
}

/* ---- 写出 .elftrace ---- */
static void write_snapshot(const struct snapshot *sn, const char *out)
{
    struct buf sb;              /* strings 区 */
    struct buf file;
    struct buf payload;
    elftrace_hdr h = {0};
    uint64_t off;
    uint64_t *seg_name_off, *fd_path_off, *aux_name_off;
    uint64_t *aux_payload_off;

    buf_init(&sb);
    buf_init(&file);
    buf_init(&payload);

    seg_name_off = xcalloc(sn->nsegs, sizeof(uint64_t));
    fd_path_off = xcalloc(sn->nfds, sizeof(uint64_t));
    aux_name_off = xcalloc(sn->naux, sizeof(uint64_t));
    aux_payload_off = xcalloc(sn->naux, sizeof(uint64_t));

    /* 1. 构造字符串区 */
    buf_append(&sb, "", 1);     /* 0 号偏移保留为空串 */
    for (size_t i = 0; i < sn->nsegs; i++) {
        if (sn->segs[i].name) {
            seg_name_off[i] = sb.size;
            buf_append(&sb, sn->segs[i].name, strlen(sn->segs[i].name) + 1);
        }
    }
    for (size_t i = 0; i < sn->nfds; i++) {
        if (sn->fds[i].path) {
            fd_path_off[i] = sb.size;
            buf_append(&sb, sn->fds[i].path, strlen(sn->fds[i].path) + 1);
        }
    }
    if (sn->exe_path) {
        h.exe_off = sb.size;
        buf_append(&sb, sn->exe_path, strlen(sn->exe_path) + 1);
    }
    for (size_t i = 0; i < sn->naux; i++) {
        aux_name_off[i] = sb.size;
        buf_append(&sb, sn->aux[i].name, strlen(sn->aux[i].name) + 1);
    }

    /* 2. 构造 payload: 先段内容 (采集时已入 sn->payload), 后 aux 内容 */
    buf_append(&payload, sn->payload.data, sn->payload.size);
    for (size_t i = 0; i < sn->naux; i++) {
        aux_payload_off[i] = payload.size;
        buf_append(&payload, sn->aux[i].data, sn->aux[i].size);
    }

    /* 3. 偏移规划 */
    h.magic = ELFTRACE_MAGIC;
    h.version = ELFTRACE_VERSION;
    h.arch = sn->arch;
    h.flags = ELFTRACE_FLAG_NONE;
    h.entry_pc = sn->regs.rip;
    h.task_tid = sn->pid;
    h.exe_bias = sn->exe_bias;

    off = sizeof(elftrace_hdr);
    h.regs_off = off;
    h.regs_size = sizeof(struct user_regs_struct);
    off += h.regs_size;

    h.fpu_off = off;
    h.fpu_size = sn->xstate_size;
    off += h.fpu_size;

    h.sigmask_off = off;
    off += sizeof(sn->sigmask);

    h.segs_off = off;
    h.nsegs = sn->nsegs;
    off += h.nsegs * sizeof(elftrace_seg);

    h.fds_off = off;
    h.nfds = sn->nfds;
    off += h.nfds * sizeof(elftrace_fd);

    h.strings_off = off;
    h.strings_size = sb.size;
    off += h.strings_size;

    h.aux_off = off;
    h.aux_n = sn->naux;
    off += h.aux_n * sizeof(elftrace_aux);

    h.payload_off = off;
    h.payload_size = payload.size;

    /* 4. 顺序写入 */
    buf_append(&file, &h, sizeof(h));
    buf_append(&file, &sn->regs, sizeof(sn->regs));
    buf_append(&file, sn->xstate, sn->xstate_size);
    buf_append(&file, sn->sigmask, sizeof(sn->sigmask));

    for (size_t i = 0; i < sn->nsegs; i++) {
        elftrace_seg e = {0};
        e.vaddr = sn->segs[i].vaddr;
        e.filesz = sn->segs[i].filesz;
        e.memsz = sn->segs[i].memsz;
        e.flags = sn->segs[i].flags;
        e.payload_off = sn->payload_offs[i];
        e.name_off = seg_name_off[i];
        buf_append(&file, &e, sizeof(e));
    }

    for (size_t i = 0; i < sn->nfds; i++) {
        elftrace_fd e = {0};
        e.fd = sn->fds[i].fd;
        e.flags = sn->fds[i].flags;
        e.mode = sn->fds[i].mode;
        e.pos = sn->fds[i].pos;
        e.path_len = sn->fds[i].path ? strlen(sn->fds[i].path) + 1 : 0;
        e.path_off = fd_path_off[i];
        buf_append(&file, &e, sizeof(e));
    }

    buf_append(&file, sb.data, sb.size);

    for (size_t i = 0; i < sn->naux; i++) {
        elftrace_aux e = {0};
        e.name_off = aux_name_off[i];
        e.addr = sn->aux[i].addr;
        e.payload_off = aux_payload_off[i];
        e.size = sn->aux[i].size;
        e.type = sn->aux[i].type;
        e.flags = sn->aux[i].flags;
        e.align = sn->aux[i].align;
        e.entsize = sn->aux[i].entsize;
        e.link = sn->aux[i].link;
        e.info = sn->aux[i].info;
        buf_append(&file, &e, sizeof(e));
    }

    buf_append(&file, payload.data, payload.size);

    int fd = open(out, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        die("cannot create %s", out);
    size_t n = write(fd, file.data, file.size);
    if (n != file.size)
        die("short write to %s", out);
    close(fd);

    fprintf(stderr, "freeze: %zu segments, %zu fds, %zu aux sections, "
            "%llu bytes payload -> %s\n", sn->nsegs, sn->nfds, sn->naux,
            (unsigned long long)payload.size, out);

    free(seg_name_off);
    free(fd_path_off);
    free(aux_name_off);
    free(aux_payload_off);
}

int freeze_main(int argc, char **argv)
{
    const char *out = "snapshot.elftrace";
    pid_t pid = 0;
    int st;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            out = argv[++i];
        } else if (argv[i][0] >= '0' && argv[i][0] <= '9') {
            pid = atoi(argv[i]);
        } else {
            die("usage: elftrace freeze <pid> [-o out.elftrace]");
        }
    }
    if (pid == 0)
        die("usage: elftrace freeze <pid> [-o out.elftrace]");

    struct snapshot sn = {.pid = pid};
    struct iovec iov;
    char path[64];

    /* 0. 架构识别: 读目标 exe 的 ELF 头 */
    {
        snprintf(path, sizeof(path), "/proc/%d/exe", pid);
        int exe_fd = open(path, O_RDONLY);
        if (exe_fd >= 0) {
            Elf64_Ehdr eh;
            if (read(exe_fd, &eh, sizeof(eh)) == sizeof(eh) &&
                memcmp(eh.e_ident, ELFMAG, SELFMAG) == 0) {
                switch (eh.e_machine) {
                case EM_X86_64:
                    sn.arch = ELFTRACE_ARCH_X86_64;
                    break;
                case EM_AARCH64:
                    sn.arch = ELFTRACE_ARCH_AARCH64;
                    break;
                default:
                    die("unsupported target machine %u", eh.e_machine);
                }
            }
            close(exe_fd);
        }
        if (!sn.arch)
            die("cannot determine target architecture");
    }

    /* 1. 冻结: SEIZE + INTERRUPT */
    if (ptrace(PTRACE_SEIZE, pid, 0, 0) < 0)
        die("ptrace(SEIZE) on %d", pid);
    if (ptrace(PTRACE_INTERRUPT, pid, 0, 0) < 0)
        die("ptrace(INTERRUPT) on %d", pid);
    if (waitpid(pid, &st, 0) < 0)
        die("waitpid(%d)", pid);
    if (!WIFSTOPPED(st)) {
        ptrace(PTRACE_DETACH, pid, 0, 0);
        die("tracee %d did not stop (status %#x)", pid, st);
    }

    /* 2. 寄存器: 用可移植的 PTRACE_GETREGSET NT_PRSTATUS
       (x86_64: 返回 user_regs_struct 布局; aarch64: user_pt_regs) */
    {
        struct iovec rv = {.iov_base = &sn.regs, .iov_len = sizeof(sn.regs)};
        if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &rv) < 0) {
            /* 旧式路径 (x86_64 备用) */
            if (ptrace(PTRACE_GETREGS, pid, 0, &sn.regs) < 0)
                die("ptrace(GETREGS) on %d", pid);
        }
    }

    /* 3. FPU 状态: 按架构选择 regset (x86_64: NT_X86_XSTATE;
       aarch64: NT_FPREGSET) */
    sn.xstate = xcalloc(1, 8192);
    iov.iov_base = sn.xstate;
    iov.iov_len = 8192;
    {
        int nt = (sn.arch == ELFTRACE_ARCH_AARCH64) ? NT_FPREGSET
                                                    : NT_X86_XSTATE;
        if (ptrace(PTRACE_GETREGSET, pid, (void *)(long)nt, &iov) < 0) {
            warn("no FPU regset (nt=%d), collecting legacy fpregs", nt);
            iov.iov_len = 512;
        }
    }
    sn.xstate_size = iov.iov_len;
    if (sn.xstate_size > 4096) {
        /* sigframe fpstate 区域容量为 4096, 超出部分截断 (AMX 等极端情况) */
        warn("fpu state size %zu exceeds stub capacity 4096, truncated",
             sn.xstate_size);
        sn.xstate_size = 4096;
    }

    /* 4. 信号掩码 (内核 sigset, 8 字节) */
    iov.iov_base = sn.sigmask;
    iov.iov_len = sizeof(sn.sigmask);
    if (ptrace(PTRACE_GETSIGMASK, pid, sizeof(sn.sigmask), &iov) < 0)
        die("ptrace(GETSIGMASK) on %d", pid);

    /* 5. 内存段 */
    collect_segments(&sn);
    sn.payload_offs = xcalloc(sn.nsegs, sizeof(uint64_t));
    for (size_t i = 0; i < sn.nsegs; i++) {
        uint8_t *tmp = xmalloc(sn.segs[i].memsz ? sn.segs[i].memsz : 1);
        sn.segs[i].filesz = read_mem(pid, sn.segs[i].vaddr,
                                     sn.segs[i].memsz, tmp, 1);
        sn.payload_offs[i] = sn.payload.size;
        buf_append(&sn.payload, tmp, sn.segs[i].filesz);
        free(tmp);
    }

    /* 6. fd */
    collect_fds(&sn);

    /* 7. exe + 架构识别 + 调试节 */
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    char exe[PATH_MAX];
    ssize_t exe_len = readlink(path, exe, sizeof(exe) - 1);
    if (exe_len > 0) {
        exe[exe_len] = 0;
        sn.exe_path = xstrdup(exe);
    }
    collect_aux(&sn);

    /* 8. 系统调用检测 */
    detect_in_syscall(&sn);

    /* 9. 写出 */
    write_snapshot(&sn, out);

    /* 10. 分离 (SEIZE+INTERRUPT 语义: 分离后目标保持停止) */
    ptrace(PTRACE_DETACH, pid, 0, 0);
    fprintf(stderr, "freeze: %d detached and left frozen\n", pid);
    return 0;
}
