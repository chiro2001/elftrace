/*
 * elftrace 采集器 (freeze/trace 共用)
 *
 * 采集指定进程的完整用户态状态:
 *   - 通用寄存器 (GETREGSET NT_PRSTATUS, x86_64 布局 == user_regs_struct)
 *   - FPU/xstate (NT_X86_XSTATE, XSAVE 非压缩格式)
 *   - 信号掩码 (PTRACE_GETSIGMASK, 内核 sigset_t 8 字节)
 *   - 内存段 (/proc/<pid>/maps + mem), 跳过 vdso/vvar/vsyscall
 *   - fd 列表 (仅常规文件, 按路径重开恢复)
 *   - 主可执行文件的调试节/分配节 (aux) + PIE 加载偏置
 *
 * freeze 命令: 冻结后采集, 分离并保持停止;
 * trace 命令: 每 N 条指令冻结采集一次 (检查点)。
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
#include "collect.h"
#include "util.h"

/* ---- 可扩展缓冲 ---- */
void cbuf_init(struct cbuf *b)
{
    b->data = NULL;
    b->size = 0;
    b->cap = 0;
}

static void cbuf_reserve(struct cbuf *b, size_t extra)
{
    if (b->size + extra > b->cap) {
        size_t ncap = b->cap ? b->cap * 2 : 65536;
        while (ncap < b->size + extra)
            ncap *= 2;
        b->data = xrealloc(b->data, ncap);
        b->cap = ncap;
    }
}

void cbuf_append(struct cbuf *b, const void *data, size_t size)
{
    cbuf_reserve(b, size);
    memcpy(b->data + b->size, data, size);
    b->size += size;
}

static int is_supported_fd_path(const char *path)
{
    return strncmp(path, "socket:", 7) != 0 &&
           strncmp(path, "pipe:", 5) != 0 &&
           strncmp(path, "anon_inode:", 11) != 0;
}

/* ---- /proc/<pid>/fdinfo 解析: pos 和 flags ---- */
static void parse_fdinfo(pid_t pid, struct cfdinfo *fi)
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
static void collect_fds(struct collect_snapshot *sn)
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

    sn->fds = xcalloc(cap, sizeof(struct cfdinfo));
    while ((de = readdir(d))) {
        struct cfdinfo fi = {0};
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
            sn->fds = xrealloc(sn->fds, cap * sizeof(struct cfdinfo));
        }
        sn->fds[sn->nfds++] = fi;
    }
    closedir(d);
}

/* ---- 采集内存段 ---- */
void collect_segments(struct collect_snapshot *sn)
{
    char path[64];
    char line[1024];
    FILE *f;
    int cap = 32;

    snprintf(path, sizeof(path), "/proc/%d/maps", sn->pid);
    f = fopen(path, "r");
    if (!f)
        die("cannot open %s", path);

    sn->segs = xcalloc(cap, sizeof(struct cseg));
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

        struct cseg s = {0};
        s.vaddr = start;
        s.memsz = end - start;
        s.flags = 0;
        if (perms[0] == 'r') s.flags |= PF_R;
        if (perms[1] == 'w') s.flags |= PF_W;
        if (perms[2] == 'x') s.flags |= PF_X;
        s.name = (n && name[0]) ? xstrdup(name) : NULL;

        if (sn->nsegs == (size_t)cap) {
            cap *= 2;
            sn->segs = xrealloc(sn->segs, cap * sizeof(struct cseg));
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

static void collect_aux(struct collect_snapshot *sn)
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

    sh = xcalloc(eh.e_shnum, sizeof(Elf64_Shdr));
    if (pread(fd, sh, sizeof(Elf64_Shdr) * eh.e_shnum, eh.e_shoff) !=
        (ssize_t)(sizeof(Elf64_Shdr) * eh.e_shnum)) {
        close(fd);
        free(sh);
        return;
    }

    sn->aux = xcalloc(cap, sizeof(struct caux));

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

        struct caux a = {0};
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
            sn->aux = xrealloc(sn->aux, cap * sizeof(struct caux));
        }
        sn->aux[sn->naux++] = a;
    }
    close(fd);
    free(sh);
    free(shstr);
    free(debug_abbrev);
}

/* ---- 判断目标是否处于系统调用中 (rip-2 为 syscall 指令) ---- */
static void detect_in_syscall(struct collect_snapshot *sn)
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
void collect_write(const struct collect_snapshot *sn, const char *out)
{
    struct cbuf sb;              /* strings 区 */
    struct cbuf file;
    struct cbuf payload;
    elftrace_hdr h = {0};
    uint64_t off;
    uint64_t *seg_name_off, *fd_path_off, *aux_name_off;
    uint64_t *aux_payload_off;

    cbuf_init(&sb);
    cbuf_init(&file);
    cbuf_init(&payload);

    seg_name_off = xcalloc(sn->nsegs, sizeof(uint64_t));
    fd_path_off = xcalloc(sn->nfds, sizeof(uint64_t));
    aux_name_off = xcalloc(sn->naux, sizeof(uint64_t));
    aux_payload_off = xcalloc(sn->naux, sizeof(uint64_t));

    /* 1. 构造字符串区 */
    cbuf_append(&sb, "", 1);     /* 0 号偏移保留为空串 */
    for (size_t i = 0; i < sn->nsegs; i++) {
        if (sn->segs[i].name) {
            seg_name_off[i] = sb.size;
            cbuf_append(&sb, sn->segs[i].name, strlen(sn->segs[i].name) + 1);
        }
    }
    for (size_t i = 0; i < sn->nfds; i++) {
        if (sn->fds[i].path) {
            fd_path_off[i] = sb.size;
            cbuf_append(&sb, sn->fds[i].path, strlen(sn->fds[i].path) + 1);
        }
    }
    if (sn->exe_path) {
        h.exe_off = sb.size;
        cbuf_append(&sb, sn->exe_path, strlen(sn->exe_path) + 1);
    }
    for (size_t i = 0; i < sn->naux; i++) {
        aux_name_off[i] = sb.size;
        cbuf_append(&sb, sn->aux[i].name, strlen(sn->aux[i].name) + 1);
    }

    /* 2. 构造 payload: 先段内容 (采集时已入 sn->payload), 后 aux 内容 */
    cbuf_append(&payload, sn->payload.data, sn->payload.size);
    for (size_t i = 0; i < sn->naux; i++) {
        aux_payload_off[i] = payload.size;
        cbuf_append(&payload, sn->aux[i].data, sn->aux[i].size);
    }

    /* 3. 偏移规划 */
    h.magic = ELFTRACE_MAGIC;
    h.version = ELFTRACE_VERSION;
    h.arch = sn->arch;
    h.flags = ELFTRACE_FLAG_NONE;
    h.entry_pc = sn->regs.rip;
    h.task_tid = sn->pid;
    h.exe_bias = sn->exe_bias;
    h.rlim_stack_cur = sn->rlim_stack_cur;
    h.rlim_stack_max = sn->rlim_stack_max;

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
    cbuf_append(&file, &h, sizeof(h));
    cbuf_append(&file, &sn->regs, sizeof(sn->regs));
    cbuf_append(&file, sn->xstate, sn->xstate_size);
    cbuf_append(&file, sn->sigmask, sizeof(sn->sigmask));

    for (size_t i = 0; i < sn->nsegs; i++) {
        elftrace_seg e = {0};
        e.vaddr = sn->segs[i].vaddr;
        e.filesz = sn->segs[i].filesz;
        e.memsz = sn->segs[i].memsz;
        e.flags = sn->segs[i].flags;
        e.payload_off = sn->payload_offs[i];
        e.name_off = seg_name_off[i];
        cbuf_append(&file, &e, sizeof(e));
    }

    for (size_t i = 0; i < sn->nfds; i++) {
        elftrace_fd e = {0};
        e.fd = sn->fds[i].fd;
        e.flags = sn->fds[i].flags;
        e.mode = sn->fds[i].mode;
        e.pos = sn->fds[i].pos;
        e.path_len = sn->fds[i].path ? strlen(sn->fds[i].path) + 1 : 0;
        e.path_off = fd_path_off[i];
        cbuf_append(&file, &e, sizeof(e));
    }

    cbuf_append(&file, sb.data, sb.size);

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
        cbuf_append(&file, &e, sizeof(e));
    }

    cbuf_append(&file, payload.data, payload.size);

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

/* ---- 公开接口 ---- */

int collect_freeze(pid_t pid)
{
    int st;

    if (ptrace(PTRACE_SEIZE, pid, 0, 0) < 0)
        return -1;
    if (ptrace(PTRACE_INTERRUPT, pid, 0, 0) < 0)
        return -1;
    if (waitpid(pid, &st, 0) < 0)
        return -1;
    if (!WIFSTOPPED(st)) {
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return -1;
    }
    return 0;
}

void collect_state_light(pid_t pid, struct collect_snapshot *sn)
{
    struct iovec iov;
    char path[64];

    /* 架构识别: 读目标 exe 的 ELF 头 */
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    int exe_fd = open(path, O_RDONLY);
    if (exe_fd >= 0) {
        Elf64_Ehdr eh;
        if (read(exe_fd, &eh, sizeof(eh)) == sizeof(eh) &&
            memcmp(eh.e_ident, ELFMAG, SELFMAG) == 0) {
            switch (eh.e_machine) {
            case EM_X86_64:
                sn->arch = ELFTRACE_ARCH_X86_64;
                break;
            case EM_AARCH64:
                sn->arch = ELFTRACE_ARCH_AARCH64;
                break;
            default:
                die("unsupported target machine %u", eh.e_machine);
            }
        }
        close(exe_fd);
    }
    if (!sn->arch)
        die("cannot determine target architecture");

    /* 寄存器: 可移植 GETREGSET NT_PRSTATUS */
    {
        struct iovec rv = {.iov_base = &sn->regs, .iov_len = sizeof(sn->regs)};
        if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &rv) < 0) {
            if (ptrace(PTRACE_GETREGS, pid, 0, &sn->regs) < 0)
                die("ptrace(GETREGS) on %d", pid);
        }
    }

    /* FPU: 按架构选择 regset */
    sn->xstate = xcalloc(1, 8192);
    iov.iov_base = sn->xstate;
    iov.iov_len = 8192;
    {
        int nt = (sn->arch == ELFTRACE_ARCH_AARCH64) ? NT_FPREGSET
                                                     : NT_X86_XSTATE;
        if (ptrace(PTRACE_GETREGSET, pid, (void *)(long)nt, &iov) < 0) {
            warn("no FPU regset (nt=%d), collecting legacy fpregs", nt);
            iov.iov_len = 512;
        }
    }
    sn->xstate_size = iov.iov_len;
    if (sn->xstate_size > 4096) {
        warn("fpu state size %zu exceeds stub capacity 4096, truncated",
             sn->xstate_size);
        sn->xstate_size = 4096;
    }

    /* 信号掩码 (内核 sigset, 8 字节) */
    iov.iov_base = sn->sigmask;
    iov.iov_len = sizeof(sn->sigmask);
    if (ptrace(PTRACE_GETSIGMASK, pid, sizeof(sn->sigmask), &iov) < 0)
        die("ptrace(GETSIGMASK) on %d", pid);

    /* 内存段 (仅解析 maps, 不读取) */
    collect_segments(sn);

    /* fd */
    collect_fds(sn);

    /* exe + 架构识别 + 调试节 */
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    char exe[PATH_MAX];
    ssize_t exe_len = readlink(path, exe, sizeof(exe) - 1);
    if (exe_len > 0) {
        exe[exe_len] = 0;
        sn->exe_path = xstrdup(exe);
    }
    collect_aux(sn);

    /* 系统调用检测 */
    detect_in_syscall(sn);

    /* RLIMIT_STACK (切片进程恢复栈增长限制) */
    sn->rlim_stack_cur = sn->rlim_stack_max = 0;
    snprintf(path, sizeof(path), "/proc/%d/limits", pid);
    FILE *lf = fopen(path, "r");
    if (lf) {
        char line[256];
        while (fgets(line, sizeof(line), lf)) {
            if (strncmp(line, "Max stack size", 14) == 0) {
                unsigned long long cur, max;
                if (sscanf(line + 14, "%llu %llu", &cur, &max) == 2) {
                    sn->rlim_stack_cur = cur;
                    sn->rlim_stack_max = (max == ~0ULL) ? 0 : max;
                }
                break;
            }
        }
        fclose(lf);
    }
}

void collect_memory(pid_t pid, struct collect_snapshot *sn)
{
    sn->payload_offs = xcalloc(sn->nsegs, sizeof(uint64_t));
    for (size_t i = 0; i < sn->nsegs; i++) {
        uint8_t *tmp = xmalloc(sn->segs[i].memsz ? sn->segs[i].memsz : 1);
        sn->segs[i].filesz = read_mem(pid, sn->segs[i].vaddr,
                                      sn->segs[i].memsz, tmp, 1);
        sn->payload_offs[i] = sn->payload.size;
        cbuf_append(&sn->payload, tmp, sn->segs[i].filesz);
        free(tmp);
    }
}

void collect_state(pid_t pid, struct collect_snapshot *sn)
{
    collect_state_light(pid, sn);
    collect_memory(pid, sn);
}

int collect_interrupt(pid_t pid)
{
    int st;

    if (ptrace(PTRACE_INTERRUPT, pid, 0, 0) < 0)
        return -1;
    if (waitpid(pid, &st, 0) < 0)
        return -1;
    if (!WIFSTOPPED(st))
        return -1;
    return 0;
}

void collect_detach_run(pid_t pid)
{
    ptrace(PTRACE_DETACH, pid, 0, 0);
}

void collect_detach_frozen(pid_t pid)
{
    /* SEIZE+INTERRUPT 后 detach 会唤醒 tracee, 先 SIGSTOP 使其进入
       组停止 (T 状态), 之后可用 SIGCONT 解除 */
    kill(pid, SIGSTOP);
    ptrace(PTRACE_DETACH, pid, 0, 0);
}

void collect_resume(pid_t pid)
{
    ptrace(PTRACE_CONT, pid, 0, 0);
}

void collect_free(struct collect_snapshot *sn)
{
    for (size_t i = 0; i < sn->nsegs; i++)
        free(sn->segs[i].name);
    free(sn->segs);
    free(sn->payload_offs);
    for (size_t i = 0; i < sn->nfds; i++)
        free(sn->fds[i].path);
    free(sn->fds);
    free(sn->exe_path);
    for (size_t i = 0; i < sn->naux; i++) {
        free(sn->aux[i].name);
        free(sn->aux[i].data);
    }
    free(sn->aux);
    free(sn->payload.data);
    free(sn->xstate);
    memset(sn, 0, sizeof(*sn));
}
