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
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <elf.h>

#include "elftrace.h"
#include "collect.h"
#include "util.h"
#include "arch.h"

/* aarch64: collect_freeze 用 jit 读到的 TPIDR_EL0 (NT_ARM_TLS 可能陈旧) */
static unsigned long g_tls;

/* ---- 采集排除区 (trace 原子记录注入页) ---- */
#define EXCL_MAX 64
static struct {
    uint64_t vaddr, size;
} g_excl[EXCL_MAX];
static size_t g_n_excl;

void collect_exclude_clear(void)
{
    g_n_excl = 0;
}

int collect_exclude_add(uint64_t vaddr, uint64_t size)
{
    if (g_n_excl >= EXCL_MAX || !size)
        return -1;
    g_excl[g_n_excl].vaddr = vaddr;
    g_excl[g_n_excl].size = size;
    g_n_excl++;
    return 0;
}

static int collect_excluded(uint64_t vaddr, uint64_t size)
{
    uint64_t end = vaddr + size;
    for (size_t i = 0; i < g_n_excl; i++) {
        if (vaddr >= g_excl[i].vaddr &&
            end <= g_excl[i].vaddr + g_excl[i].size)
            return 1;
    }
    return 0;
}

/* 发射一个采集段 (供 collect_segments 分割排除区时复用) */
static void seg_emit(struct collect_snapshot *sn, int *cap,
                     uint64_t vaddr, uint64_t memsz, uint64_t flags,
                     const char *name)
{
    if (sn->nsegs == (size_t)*cap) {
        *cap *= 2;
        sn->segs = xrealloc(sn->segs, *cap * sizeof(struct cseg));
    }
    struct cseg s = {0};
    s.vaddr = vaddr;
    s.memsz = memsz;
    s.flags = flags;
    s.name = name ? xstrdup(name) : NULL;
    sn->segs[sn->nsegs++] = s;
}

int collect_excluded_range(uint64_t vaddr, uint64_t size)
{
    return collect_excluded(vaddr, size);
}

#if defined(__aarch64__)
/* 让目标自己执行 `mrs x0, tpidr_el0; brk #0x1234` 读 HW TPIDR_EL0
 * (内核 NT_ARM_TLS regset 读 thread.uw.tp_value, 只在上下文切换时
 * 同步, 从未被换出的目标读到 exec 后的陈旧 0)。目标执行后恢复
 * 寄存器与页字节, 停在 brk 的 SIGTRAP-stop (可继续采集)。
 * 结果存 g_tls。要求目标处于 ptrace-stop。 */
void collect_tls_jit(pid_t pid)
{
    int st;
    uint32_t snippet[2] = {0xd53bd040, 0xd420048d};
    unsigned long scratch = 0;
    char mp[64];

    if (g_tls)
        return;
    snprintf(mp, sizeof(mp), "/proc/%d/maps", pid);
    FILE *mf = fopen(mp, "r");
    if (mf) {
        char line[256];
        while (fgets(line, sizeof line, mf)) {
            unsigned long long s, e;
            char perms[8];
            if (sscanf(line, "%llx-%llx %7s", &s, &e, perms) == 3 &&
                perms[0] == 'r' && perms[2] == 'x' &&
                !collect_excluded(s, e - s)) {
                scratch = (unsigned long)s;
                break;
            }
        }
        fclose(mf);
    }
    if (!scratch)
        return;
    unsigned long backup = ptrace(PTRACE_PEEKDATA, pid, scratch, 0);
    ptrace(PTRACE_POKEDATA, pid, scratch,
           (unsigned long)snippet[0] |
               ((unsigned long)snippet[1] << 32));
    struct user_regs_struct r, saved;
    struct iovec io = {.iov_base = &r, .iov_len = sizeof(r)};
    if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &io) == 0) {
        saved = r;
        r.pc = scratch;
        r.regs[30] = scratch;
        ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &io);
        ptrace(PTRACE_CONT, pid, 0, 0);
        if (waitpid(pid, &st, 0) > 0 && WIFSTOPPED(st)) {
            /* 目标原本被 SIGSTOP 组停: CONT 后重新进入组停, jit 片段
               没执行; 用 SIGCONT 放行一次再等 SIGTRAP (brk) */
            if (WSTOPSIG(st) == SIGSTOP) {
                ptrace(PTRACE_CONT, pid, 0, SIGCONT);
                waitpid(pid, &st, 0);
            }
            struct user_regs_struct r2;
            struct iovec io2 = {.iov_base = &r2, .iov_len = sizeof(r2)};
            if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS,
                       &io2) == 0)
                g_tls = r2.regs[0];
            io.iov_base = &saved;
            ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &io);
        }
    }
    ptrace(PTRACE_POKEDATA, pid, scratch, backup);
}

uint64_t collect_get_tls(void)
{
    return g_tls;
}
#endif

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

        /* 跳过内核管理区域 (vdso/vvar 需采集: libc 缓存其函数指针,
           切片进程 vdso ASLR 位置不同, 不恢复则调用必崩;
           vsyscall/sigpage 为固定内核页, 不采集) */
        if (strstr(name, "[vsyscall]") || strstr(name, "[sigpage]"))
            continue;
        /* 跳过无权限区域 */
        if (perms[0] == '-' && perms[1] == '-' && perms[2] == '-')
            continue;
        /* 采集排除区 (原子记录注入页): 完全落入排除区的整段跳过;
           部分重叠的按排除区分割, 只保留非排除子段。内核可能把注入
           缓冲与目标段合并成一个 VMA (如 [heap] 66MB = 线程栈/arena
           + 64MB 环形缓冲), 不分割会把环形缓冲整段录进 diff。 */
        uint64_t seg_flags = 0;
        if (perms[0] == 'r') seg_flags |= PF_R;
        if (perms[1] == 'w') seg_flags |= PF_W;
        if (perms[2] == 'x') seg_flags |= PF_X;
        const char *sname = (n && name[0]) ? name : NULL;
        uint64_t seg_start = start, seg_end = end;
        for (size_t ei = 0; ei < g_n_excl && seg_start < seg_end; ei++) {
            uint64_t xs = g_excl[ei].vaddr;
            uint64_t xe = xs + g_excl[ei].size;
            if (xe <= seg_start || xs >= seg_end)
                continue;
            if (xs > seg_start)
                seg_emit(sn, &cap, seg_start, xs - seg_start, seg_flags,
                         sname);
            seg_start = xe;
        }
        if (seg_start < seg_end)
            seg_emit(sn, &cap, seg_start, seg_end - seg_start, seg_flags,
                     sname);
    }
    fclose(f);
}

/* 从 /proc/<pid>/mem 读取一段内存, 返回实际读取字节数 (页粒度, 失败截断) */
static size_t read_mem_dbg(pid_t pid, uint64_t vaddr, uint64_t size,
                           uint8_t *out, int warn_on_partial, const char *tag)
{
    char path[64];
    size_t got = 0;
    int fd;

    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        char st[128];
        snprintf(st, sizeof(st), "/proc/%d/stat", pid);
        FILE *sf = fopen(st, "r");
        if (sf) {
            char sb[256];
            size_t sn2 = fread(sb, 1, sizeof(sb) - 1, sf);
            sb[sn2] = 0;
            fprintf(stderr, "  agent %d state: %s\n", pid, sb);
            fclose(sf);
        } else {
            fprintf(stderr, "  agent %d: /proc/%d/stat 不可读\n", pid, pid);
        }
        die("cannot open %s", path);
    }

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
    if (warn_on_partial && got < size) {
        warn("segment %#llx read %zu of %llu bytes (from pid %d, tag %s)",
             (unsigned long long)vaddr, got, (unsigned long long)size, pid,
             tag);
        char mp[64];
        snprintf(mp, sizeof(mp), "/proc/%d/maps", pid);
        FILE *mf = fopen(mp, "r");
        if (mf) {
            char ml[512];
            while (fgets(ml, sizeof(ml), mf)) {
                unsigned long long ms, me;
                if (sscanf(ml, "%llx-%llx", &ms, &me) == 2 &&
                    vaddr >= ms && vaddr < me)
                    fprintf(stderr, "  proc map: %s", ml);
            }
            fclose(mf);
        }
    }
    return got;
}

static size_t read_mem(pid_t pid, uint64_t vaddr, uint64_t size,
                       uint8_t *out, int warn_on_partial)
{
    return read_mem_dbg(pid, vaddr, size, out, warn_on_partial, "normal");
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

/* ---- 采集环境信息 (meta 区, trace 多检查点复用) ---- */

static void meta_append(char *buf, size_t *off, size_t cap, const char *kv)
{
    size_t n = strlen(kv);
    if (*off + n < cap) {
        memcpy(buf + *off, kv, n);
        *off += n;
    }
}

static void meta_from_file(char *buf, size_t *off, size_t cap,
                           const char *key, const char *path, int take_last)
{
    char line[512];
    FILE *f = fopen(path, "r");
    if (!f) {
        char tmp[64];
        snprintf(tmp, sizeof(tmp), "key=%s unavailable\n", key);
        meta_append(buf, off, cap, tmp);
        return;
    }
    char *last = NULL;
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = 0;
        last = xstrdup(line);
    }
    fclose(f);
    char tmp[640];
    snprintf(tmp, sizeof(tmp), "%s=%s\n", key, last ? last : "unknown");
    meta_append(buf, off, cap, tmp);
    free(last);
}

static void meta_from_cmd(char *buf, size_t *off, size_t cap,
                          const char *key, const char *cmd, int first_line)
{
    char line[1024];
    FILE *p = popen(cmd, "r");
    if (!p) {
        char tmp[64];
        snprintf(tmp, sizeof(tmp), "key=%s unavailable\n", key);
        meta_append(buf, off, cap, tmp);
        return;
    }
    int n = 0;
    while (fgets(line, sizeof(line), p)) {
        line[strcspn(line, "\n")] = 0;
        char tmp[1100];
        snprintf(tmp, sizeof(tmp), "%s=%s\n", key, line);
        meta_append(buf, off, cap, tmp);
        n++;
        if (first_line)
            break;
    }
    pclose(p);
}

/* 采集一次 (static 缓存), 返回指向 NUL 结尾的 key=value 文本块 */
const char *collect_meta(size_t *out_size)
{
    static char meta[16384];
    static size_t meta_size = 0;
    static int done = 0;
    size_t off = 0;
    char tmp[128];
    char line[1024];
    FILE *f;

    if (done) {
        *out_size = meta_size;
        return meta;
    }

    /* 1. ISA / 内核 */
    meta_from_cmd(meta, &off, sizeof(meta), "isa", "uname -m", 1);
    meta_from_cmd(meta, &off, sizeof(meta), "kernel", "uname -srm", 1);
    meta_from_cmd(meta, &off, sizeof(meta), "hostname", "hostname", 1);

    /* 2. OS 信息 */
    f = fopen("/etc/os-release", "r");
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            line[strcspn(line, "\n")] = 0;
            if (strncmp(line, "PRETTY_NAME=", 12) == 0) {
                char *v = line + 12;
                size_t vl = strlen(v);
                if (vl >= 2 && v[0] == '"' && v[vl - 1] == '"') {
                    v[vl - 1] = 0;
                    v++;
                }
                char tmp2[1100];
                snprintf(tmp2, sizeof(tmp2), "os=%s\n", v);
                meta_append(meta, &off, sizeof(meta), tmp2);
            } else if (strncmp(line, "VERSION_ID=", 11) == 0) {
                char tmp2[1100];
                snprintf(tmp2, sizeof(tmp2), "os_version=%s\n", line + 11);
                meta_append(meta, &off, sizeof(meta), tmp2);
            }
        }
        fclose(f);
    }

    /* 3. libc 版本 */
    meta_from_cmd(meta, &off, sizeof(meta), "libc", "ldd --version 2>&1 | head -1", 0);

    /* 4. CPU 概要 (lscpu 关键字段, LC_ALL=C 强制英文输出) */
    f = popen("LC_ALL=C lscpu", "r");
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            line[strcspn(line, "\n")] = 0;
            if (strncmp(line, "Architecture:", 13) == 0 ||
                strncmp(line, "Model name:", 11) == 0 ||
                strncmp(line, "CPU(s):", 7) == 0 ||
                strncmp(line, "CPU op-mode(s):", 15) == 0 ||
                strncmp(line, "Virtualization:", 15) == 0) {
                char tmp2[1100];
                snprintf(tmp2, sizeof(tmp2), "cpu_%s\n", line);
                meta_append(meta, &off, sizeof(meta), tmp2);
            }
        }
        pclose(f);
    }

    /* 5. NUMA 拓扑 (/sys, 无需 numactl) */
    meta_from_file(meta, &off, sizeof(meta), "numa_nodes",
                   "/sys/devices/system/node/possible", 1);
    DIR *nd = opendir("/sys/devices/system/node");
    int nn = 0;
    if (nd) {
        struct dirent *de;
        while ((de = readdir(nd)))
            if (strncmp(de->d_name, "node", 4) == 0)
                nn++;
        closedir(nd);
    }
    snprintf(tmp, sizeof(tmp), "numa_node_count=%d\n", nn);
    meta_append(meta, &off, sizeof(meta), tmp);

    /* 6. dmidecode (需 root, 失败记录状态) */
    meta_from_cmd(meta, &off, sizeof(meta), "dmidecode",
                  "dmidecode -t system 2>&1 | head -6", 0);

    /* 7. IP 列表 (getifaddrs, 无外部命令依赖) */
    {
        struct ifaddrs *ifa, *p;
        if (getifaddrs(&ifa) != 0) {
            meta_append(meta, &off, sizeof(meta), "ip=unavailable\n");
        } else {
            int nip = 0;
            for (p = ifa; p; p = p->ifa_next) {
                if (!p->ifa_addr || (p->ifa_flags & IFF_LOOPBACK))
                    continue;
                void *sa = NULL;
                if (p->ifa_addr->sa_family == AF_INET)
                    sa = &((struct sockaddr_in *)p->ifa_addr)->sin_addr;
                else if (p->ifa_addr->sa_family == AF_INET6)
                    sa = &((struct sockaddr_in6 *)p->ifa_addr)->sin6_addr;
                else
                    continue;
                char straddr[INET6_ADDRSTRLEN] = {0};
                inet_ntop(p->ifa_addr->sa_family, sa, straddr,
                          sizeof(straddr));
                char tmp2[300];
                snprintf(tmp2, sizeof(tmp2), "ip_%s=%s\n", p->ifa_name,
                         straddr);
                meta_append(meta, &off, sizeof(meta), tmp2);
                nip++;
            }
            if (!nip)
                meta_append(meta, &off, sizeof(meta), "ip=none\n");
            freeifaddrs(ifa);
        }
    }

    meta[off] = 0;
    meta_size = off;
    done = 1;
    *out_size = meta_size;
    return meta;
}

/* ---- 判断目标是否处于系统调用中 (pc-4/2 为 syscall 指令) ---- */
static void detect_in_syscall(struct collect_snapshot *sn)
{
    uint8_t insn[ARCH_SYSCALL_LEN];

    if (REG_SYSCALL_NR(sn->regs) == (unsigned long)-1)
        return;
    if (REG_PC(sn->regs) < ARCH_SYSCALL_LEN)
        return;
#if defined(__aarch64__)
    /* aarch64 syscall entry-stop 的 pc 指向 svc 指令本身
       (与 x86 的 rip=下一条不同) */
    if (read_mem(sn->pid, REG_PC(sn->regs), ARCH_SYSCALL_LEN, insn, 0)
        != ARCH_SYSCALL_LEN)
        return;
    if (arch_is_syscall(insn, sizeof insn)) {
        sn->in_syscall = 1;
        warn("tracee %d frozen inside syscall %ld; in-flight syscall "
             "will be lost in the slice", sn->pid,
             (long)REG_SYSCALL_NR(sn->regs));
    }
#else
    if (read_mem(sn->pid, REG_PC(sn->regs) - ARCH_SYSCALL_LEN,
                 ARCH_SYSCALL_LEN, insn, 0) != ARCH_SYSCALL_LEN)
        return;
    if (arch_is_syscall(insn, sizeof insn)) {
        sn->in_syscall = 1;
        warn("tracee %d frozen inside syscall %ld; in-flight syscall "
             "will be lost in the slice", sn->pid,
             (long)REG_SYSCALL_NR(sn->regs));
    }
#endif
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
    h.entry_pc = REG_PC(sn->regs);
    h.task_tid = sn->pid;
    h.exe_bias = sn->exe_bias;
    h.rlim_stack_cur = sn->rlim_stack_cur;
    h.rlim_stack_max = sn->rlim_stack_max;
    h.tls = sn->tls;

    off = sizeof(elftrace_hdr);
    if (sn->meta && sn->meta_size) {
        h.meta_off = off;
        h.meta_size = sn->meta_size + 1;   /* 含结尾 NUL, 与写入一致 */
        off += sn->meta_size + 1;
    } else {
        h.meta_off = 0;
        h.meta_size = 0;
    }

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
    if (sn->meta && sn->meta_size)
        cbuf_append(&file, sn->meta, sn->meta_size + 1);
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
    /* 单次 write() 有 MAX_RW_COUNT (2GB-4096) 上限, 大快照 (>2GB)
       必须分块写, 否则截断 */
    size_t woff = 0;
    while (woff < file.size) {
        ssize_t n = write(fd, file.data + woff, file.size - woff);
        if (n < 0)
            die("write %s: %s", out, strerror(errno));
        woff += (size_t)n;
    }
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
#if defined(__aarch64__)
    collect_tls_jit(pid);
#endif
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
#if defined(__x86_64__)
            /* aarch64 无 PTRACE_GETREGS, 只有 GETREGSET */
            if (ptrace(PTRACE_GETREGS, pid, 0, &sn->regs) < 0)
                die("ptrace(GETREGS) on %d", pid);
#else
            die("ptrace(GETREGSET NT_PRSTATUS) on %d", pid);
#endif
        }
    }
    /* ptrace 停止机制 (尤其 PTRACE_SYSCALL) 可能残留单步/陷阱位
       (x86: eflags TF; aarch64: pstate SS): 内核用单步在 syscall
       边界停止, INTERRUPT-stop 时仍置位。切片恢复后目标每条指令
       触发单步 SIGTRAP (风暴), baremetal 处理器误判为 syscall 触发。
       目标正常运行时不含这些位, 清除是正确语义。 */
    REG_CLEAR_TRAPS(sn->regs);

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

#if defined(__aarch64__)
    /* TPIDR_EL0: 用户态不可读, 用 PTRACE_GETREGSET NT_ARM_TLS (0x409)
       采集; stub 恢复时 jit msr tpidr_el0 (用户态唯一写入口) */
    {
        struct iovec tv = {.iov_base = &sn->tls, .iov_len = sizeof(sn->tls)};
        if (ptrace(PTRACE_GETREGSET, pid, (void *)0x409, &tv) < 0)
            sn->tls = 0;
        if (sn->tls == 0)
            sn->tls = g_tls;      /* collect_freeze 的 jit 采集值 */
    }
#endif

    /* 环境信息 (meta, static 缓存只采一次) */
    sn->meta = collect_meta(&sn->meta_size);

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

/* 深拷贝轻量状态 (regs/xstate/sigmask/fds/段表, 不含内存 payload)。
   延迟 dump 模式: 在线检查点只保存此副本, 离线阶段补内存。 */
void collect_snapshot_copy_light(struct collect_snapshot *dst,
                                 const struct collect_snapshot *src)
{
    memset(dst, 0, sizeof(*dst));
    dst->arch = src->arch;
    dst->pid = src->pid;
    dst->regs = src->regs;
    if (src->xstate_size) {
        dst->xstate = xmalloc(src->xstate_size);
        memcpy(dst->xstate, src->xstate, src->xstate_size);
        dst->xstate_size = src->xstate_size;
    }
    memcpy(dst->sigmask, src->sigmask, sizeof(dst->sigmask));
    dst->nsegs = src->nsegs;
    if (src->nsegs) {
        dst->segs = xcalloc(src->nsegs, sizeof(struct cseg));
        for (size_t i = 0; i < src->nsegs; i++) {
            dst->segs[i] = src->segs[i];
            if (src->segs[i].name)
                dst->segs[i].name = xstrdup(src->segs[i].name);
        }
        if (src->payload_offs) {
            dst->payload_offs = xmalloc(src->nsegs * sizeof(uint64_t));
            memcpy(dst->payload_offs, src->payload_offs,
                   src->nsegs * sizeof(uint64_t));
        }
    }
    dst->nfds = src->nfds;
    if (src->nfds) {
        dst->fds = xcalloc(src->nfds, sizeof(struct cfdinfo));
        for (size_t i = 0; i < src->nfds; i++) {
            dst->fds[i] = src->fds[i];
            if (src->fds[i].path)
                dst->fds[i].path = xstrdup(src->fds[i].path);
        }
    }
    if (src->exe_path)
        dst->exe_path = xstrdup(src->exe_path);
    dst->exe_bias = src->exe_bias;
    dst->rlim_stack_cur = src->rlim_stack_cur;
    dst->rlim_stack_max = src->rlim_stack_max;
    dst->tls = src->tls;
    dst->meta = src->meta;          /* static, 不拷贝 */
    dst->meta_size = src->meta_size;
    if (src->naux) {
        dst->aux = xcalloc(src->naux, sizeof(struct caux));
        for (size_t i = 0; i < src->naux; i++) {
            dst->aux[i] = src->aux[i];
            if (src->aux[i].name)
                dst->aux[i].name = xstrdup(src->aux[i].name);
            if (src->aux[i].size) {
                dst->aux[i].data = xmalloc(src->aux[i].size);
                memcpy(dst->aux[i].data, src->aux[i].data,
                       src->aux[i].size);
            }
        }
        dst->naux = src->naux;
    }
}

/* 深拷贝段表 + payload (增量检查点的 last 镜像用) */
void collect_snapshot_copy_last(struct collect_snapshot *dst,
                                const struct collect_snapshot *src)
{
    dst->nsegs = src->nsegs;
    dst->segs = xcalloc(src->nsegs ? src->nsegs : 1, sizeof(struct cseg));
    for (size_t i = 0; i < src->nsegs; i++) {
        dst->segs[i] = src->segs[i];
        if (src->segs[i].name)
            dst->segs[i].name = xstrdup(src->segs[i].name);
    }
    if (src->nsegs) {
        dst->payload_offs = xmalloc(src->nsegs * sizeof(uint64_t));
        memcpy(dst->payload_offs, src->payload_offs,
               src->nsegs * sizeof(uint64_t));
    }
    cbuf_init(&dst->payload);
    cbuf_append(&dst->payload, src->payload.data, src->payload.size);
}

/* 释放 collect_snapshot_copy_light 产生的副本 */
void collect_snapshot_free_light(struct collect_snapshot *sn)
{
    for (size_t i = 0; i < sn->nsegs; i++)
        free(sn->segs[i].name);
    free(sn->segs);
    for (size_t i = 0; i < sn->nfds; i++)
        free(sn->fds[i].path);
    free(sn->fds);
    free(sn->exe_path);
    for (size_t i = 0; i < sn->naux; i++) {
        free(sn->aux[i].name);
        free(sn->aux[i].data);
    }
    free(sn->aux);
    free(sn->xstate);
    free(sn->payload.data);
    memset(sn, 0, sizeof(*sn));
}

void collect_snapshot_free_last(struct collect_snapshot *sn)
{
    for (size_t i = 0; i < sn->nsegs; i++)
        free(sn->segs[i].name);
    free(sn->segs);
    free(sn->payload_offs);
    free(sn->payload.data);
    sn->segs = NULL;
    sn->nsegs = 0;
    sn->payload_offs = NULL;
    sn->payload.data = NULL;
    sn->payload.size = sn->payload.cap = 0;
}

/* 从 .elftrace 文件构造 collect_snapshot (段表 + payload, build 合成用) */
void collect_snapshot_load(const char *path, struct collect_snapshot *sn)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        die("cannot open %s", path);
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

    elftrace_hdr h;
    memcpy(&h, f, sizeof(h));
    if (h.magic != ELFTRACE_MAGIC || h.version != ELFTRACE_VERSION)
        die("%s: not a v%d elftrace file", path, ELFTRACE_VERSION);

    sn->arch = h.arch;
    sn->pid = h.task_tid;
    sn->nsegs = h.nsegs;
    sn->segs = xcalloc(h.nsegs ? h.nsegs : 1, sizeof(struct cseg));
    if (h.nsegs)
        sn->payload_offs = xmalloc(h.nsegs * sizeof(uint64_t));
    for (size_t i = 0; i < h.nsegs; i++) {
        elftrace_seg e;
        memcpy(&e, f + h.segs_off + i * sizeof(e), sizeof(e));
        struct cseg *c = &sn->segs[i];
        c->vaddr = e.vaddr;
        c->filesz = e.filesz;
        c->memsz = e.memsz;
        c->flags = e.flags;
        c->name = NULL;
        if (e.name_off) {
            const char *nm = (const char *)(f + h.strings_off + e.name_off);
            c->name = xstrdup(nm);
        }
        sn->payload_offs[i] = sn->payload.size;
        uint8_t *tmp = xmalloc(e.filesz ? e.filesz : 1);
        memcpy(tmp, f + h.payload_off + e.payload_off, e.filesz);
        cbuf_append(&sn->payload, tmp, e.filesz);
        free(tmp);
    }
    /* 状态: regs/xstate/sigmask/fds (aux 用 base 的调试节, 不常变) */
    if (h.regs_off && h.regs_size <= sizeof(sn->regs))
        memcpy(&sn->regs, f + h.regs_off, h.regs_size);
    if (h.fpu_off && h.fpu_size) {
        sn->xstate = xmalloc(h.fpu_size);
        memcpy(sn->xstate, f + h.fpu_off, h.fpu_size);
        sn->xstate_size = h.fpu_size;
    }
    memcpy(sn->sigmask, f + h.sigmask_off, sizeof(sn->sigmask));
    /* 状态字段 (增量合成必须保留, 否则区间切片丢 TLS/rlimit/exe) */
    sn->tls = h.tls;
    sn->rlim_stack_cur = h.rlim_stack_cur;
    sn->rlim_stack_max = h.rlim_stack_max;
    sn->exe_bias = h.exe_bias;
    if (h.exe_off) {
        sn->exe_path = xstrdup((const char *)(f + h.strings_off +
                                              h.exe_off));
    }
    if (h.aux_n) {
        sn->aux = xcalloc(h.aux_n, sizeof(struct caux));
        for (size_t i = 0; i < h.aux_n; i++) {
            elftrace_aux e;
            memcpy(&e, f + h.aux_off + i * sizeof(e), sizeof(e));
            sn->aux[i].addr = e.addr;
            sn->aux[i].size = e.size;
            sn->aux[i].type = e.type;
            sn->aux[i].flags = e.flags;
            sn->aux[i].align = e.align;
            sn->aux[i].entsize = e.entsize;
            sn->aux[i].link = e.link;
            sn->aux[i].info = e.info;
            if (e.name_off)
                sn->aux[i].name = xstrdup((const char *)
                                          (f + h.strings_off + e.name_off));
            sn->aux[i].data = xmalloc(e.size ? e.size : 1);
            memcpy(sn->aux[i].data, f + h.payload_off + e.payload_off,
                   e.size);
        }
        sn->naux = h.aux_n;
    }
    if (h.nfds) {
        sn->fds = xcalloc(h.nfds, sizeof(struct cfdinfo));
        for (size_t i = 0; i < h.nfds; i++) {
            elftrace_fd e;
            memcpy(&e, f + h.fds_off + i * sizeof(e), sizeof(e));
            sn->fds[i].fd = e.fd;
            sn->fds[i].flags = e.flags;
            sn->fds[i].mode = e.mode;
            sn->fds[i].pos = e.pos;
            if (e.path_len) {
                sn->fds[i].path =
                    xstrdup((const char *)(f + h.strings_off + e.path_off));
            }
        }
        sn->nfds = h.nfds;
    }
    free(f);
}

/* 对比 last 与 sn, 写差异文件 (增量检查点) */
void collect_write_diff(const struct collect_snapshot *last,
                        const struct collect_snapshot *sn, const char *out)
{
    struct cbuf file = {0};
    struct cbuf state = {0};
    struct cbuf tmpbuf = {0};
    elftrace_diff_hdr h = {0};
    uint64_t n_unmap = 0, n_newseg = 0, n_dirty = 0;
    uint64_t *unmaps = NULL;
    uint64_t *dirty_addrs = NULL;
    struct cbuf dirty_data = {0};
    struct cbuf newseg_data = {0};

    /* 第一次扫描: unmap (last 有, sn 无) + newseg (sn 有, last 无) */
    for (size_t i = 0; i < last->nsegs; i++) {
        int found = 0;
        for (size_t j = 0; j < sn->nsegs; j++) {
            if (sn->segs[j].vaddr == last->segs[i].vaddr) {
                found = 1;
                break;
            }
        }
        if (!found)
            n_unmap++;
    }
    if (n_unmap)
        unmaps = xcalloc(n_unmap, sizeof(uint64_t));
    n_unmap = 0;
    for (size_t i = 0; i < last->nsegs; i++) {
        int found = 0;
        for (size_t j = 0; j < sn->nsegs; j++) {
            if (sn->segs[j].vaddr == last->segs[i].vaddr) {
                found = 1;
                break;
            }
        }
        if (!found)
            unmaps[n_unmap++] = last->segs[i].vaddr;
    }

    /* 第二遍: newseg + dirty (用 payload_offs 精确定位) */
    for (size_t i = 0; i < last->nsegs; i++) {
        /* 找 sn 中同 vaddr 段 */
        const struct cseg *m = NULL;
        size_t m_idx = 0;
        for (size_t j = 0; j < sn->nsegs; j++) {
            if (sn->segs[j].vaddr == last->segs[i].vaddr) {
                m = &sn->segs[j];
                m_idx = j;
                break;
            }
        }
        if (!m)
            continue;           /* unmap 段 */
        const uint8_t *lp = last->payload.data + last->payload_offs[i];
        const uint8_t *sp = sn->payload.data + sn->payload_offs[m_idx];
        size_t llen = last->segs[i].filesz;
        size_t slen = m->filesz;
        size_t common = llen < slen ? llen : slen;
        uint64_t pg = 0;
        while (pg + 4096 <= common) {
            if (memcmp(lp + pg, sp + pg, 4096) != 0) {
                dirty_addrs = xrealloc(dirty_addrs,
                                       (n_dirty + 1) * sizeof(uint64_t));
                dirty_addrs[n_dirty++] = last->segs[i].vaddr + pg;
                cbuf_append(&dirty_data, sp + pg, 4096);
            }
            pg += 4096;
        }
        /* 尾部残页 (不足 4096) 或内容变化 */
        if (common > pg) {
            size_t tail = common - pg;
            if (tail < 4096)
                tail = 4096;
            if (slen > llen ||
                memcmp(lp + pg, sp + pg, common - pg) != 0) {
                dirty_addrs = xrealloc(dirty_addrs,
                                       (n_dirty + 1) * sizeof(uint64_t));
                dirty_addrs[n_dirty++] = last->segs[i].vaddr + pg;
                cbuf_append(&dirty_data, sp + pg, tail);
            }
        }
        /* sn 比 last 长的部分: 全部 dirty */
        for (uint64_t extra = common; extra + 4096 <= slen; extra += 4096) {
            dirty_addrs = xrealloc(dirty_addrs,
                                   (n_dirty + 1) * sizeof(uint64_t));
            dirty_addrs[n_dirty++] = m->vaddr + extra;
            cbuf_append(&dirty_data, sp + extra, 4096);
        }
        if (slen > common && (slen - common) < 4096) {
            size_t tail = slen - common;
            if (tail < 4096)
                tail = 4096;
            dirty_addrs = xrealloc(dirty_addrs,
                                   (n_dirty + 1) * sizeof(uint64_t));
            dirty_addrs[n_dirty++] = m->vaddr + common;
            cbuf_append(&dirty_data, sp + common, tail);
        }
    }

    /* newseg: sn 中 last 没有的段 (内容全量) */
    for (size_t j = 0; j < sn->nsegs; j++) {
        int found = 0;
        for (size_t i = 0; i < last->nsegs; i++) {
            if (sn->segs[j].vaddr == last->segs[i].vaddr) {
                found = 1;
                break;
            }
        }
        if (!found) {
            n_newseg++;
            elftrace_diff_seg e = {0};
            e.vaddr = sn->segs[j].vaddr;
            e.filesz = sn->segs[j].filesz;
            e.memsz = sn->segs[j].memsz;
            e.flags = sn->segs[j].flags;
            cbuf_append(&newseg_data, &e, sizeof(e));
            cbuf_append(&newseg_data,
                        sn->payload.data + sn->payload_offs[j], e.filesz);
        }
    }

    /* 状态区: regs | xstate_size+xstate | sigmask | nfds + fds表 + 路径 */
    cbuf_append(&state, &sn->regs, sizeof(sn->regs));
    cbuf_append(&state, &sn->xstate_size, sizeof(sn->xstate_size));
    if (sn->xstate_size)
        cbuf_append(&state, sn->xstate, sn->xstate_size);
    cbuf_append(&state, sn->sigmask, sizeof(sn->sigmask));
    cbuf_append(&state, &sn->nfds, sizeof(sn->nfds));
    for (size_t i = 0; i < sn->nfds; i++) {
        elftrace_fd e = {0};
        e.fd = sn->fds[i].fd;
        e.flags = sn->fds[i].flags;
        e.mode = sn->fds[i].mode;
        e.pos = sn->fds[i].pos;
        e.path_len = sn->fds[i].path ? strlen(sn->fds[i].path) + 1 : 0;
        e.path_off = state.size;   /* 路径紧跟 fd 表后 */
        cbuf_append(&state, &e, sizeof(e));
        if (sn->fds[i].path)
            cbuf_append(&state, sn->fds[i].path, e.path_len);
    }

    /* 写文件: hdr | 状态区 | unmaps | newseg 区 | dirty 页区 */
    h.magic = ELFTRACE_DIFF_MAGIC;
    h.version = ELFTRACE_DIFF_VERSION;
    h.state_size = state.size;
    h.n_unmap = n_unmap;
    h.n_newseg = n_newseg;
    h.n_dirty = n_dirty;
    cbuf_init(&file);
    cbuf_append(&file, &h, sizeof(h));
    cbuf_append(&file, state.data, state.size);
    if (n_unmap)
        cbuf_append(&file, unmaps, n_unmap * sizeof(uint64_t));
    cbuf_append(&file, newseg_data.data, newseg_data.size);
    for (uint64_t k = 0; k < n_dirty; k++) {
        cbuf_append(&file, &dirty_addrs[k], sizeof(uint64_t));
        cbuf_append(&file, dirty_data.data + k * 4096, 4096);
    }

    int fd = open(out, O_WRONLY | O_CREAT | O_TRUNC, 0644);
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

    fprintf(stderr, "diff: %llu unmap, %llu newseg, %llu dirty pages -> %s "
            "(%llu bytes)\n",
            (unsigned long long)n_unmap, (unsigned long long)n_newseg,
            (unsigned long long)n_dirty, out,
            (unsigned long long)file.size);

    free(unmaps);
    free(dirty_addrs);
    free(file.data);
    free(state.data);
    free(tmpbuf.data);
    free(newseg_data.data);
    free(dirty_data.data);
}

void collect_memory(pid_t pid, struct collect_snapshot *sn)
{
    sn->payload_offs = xcalloc(sn->nsegs, sizeof(uint64_t));
    for (size_t i = 0; i < sn->nsegs; i++) {
        uint8_t *tmp = xmalloc(sn->segs[i].memsz ? sn->segs[i].memsz : 1);
        sn->segs[i].filesz = read_mem_dbg(pid, sn->segs[i].vaddr,
                                          sn->segs[i].memsz, tmp, 1, "agent");
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
