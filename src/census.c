/*
 * elftrace census: 陈旧读普查器 (实验室 pass)
 *
 * 把切片里含回放 granule 的页面 mprotect(PROT_NONE), 目标代码读页
 * 时触发 SIGSEGV; 由 ptrace 记录 {pc, page}, 然后解保护 + 单步 +
 * 重新保护。stub 回放引擎自己的写 (pc 落在 blob strict 区) 静默放行。
 *
 * 输出: 每行 "pc page" (十六进制)。build --read-set 消费它, 只保留
 * 主线程实际读过的页面的 granule (读集过滤)。
 *
 * 用法: elftrace-census <slice.elf> <pages.list>
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <elf.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include "arch.h"

static uint64_t blob_vaddr, blob_size;
static uint64_t blob_file_off;
static uint64_t strict_lo, strict_hi;   /* stub 回放引擎代码范围 */

static int parse_elf(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    Elf64_Ehdr eh;
    if (read(fd, &eh, sizeof(eh)) != sizeof(eh)) {
        close(fd);
        return -1;
    }
    for (int i = 0; i < eh.e_phnum; i++) {
        Elf64_Phdr ph;
        if (pread(fd, &ph, sizeof(ph),
                  eh.e_phoff + i * eh.e_phentsize) != sizeof(ph))
            continue;
        if (ph.p_type != PT_LOAD)
            continue;
        if (ph.p_filesz > blob_size) {
            blob_vaddr = ph.p_vaddr;
            blob_size = ph.p_filesz;
            blob_file_off = ph.p_offset;
        }
    }
    close(fd);
    if (!blob_size)
        return -1;
    /* strict 回放引擎位于 blob 固定区末尾 0x1000 (见 elftrace_stub.h) */
    strict_lo = blob_vaddr + 0xF000;
    strict_hi = blob_vaddr + 0x10000;
    return 0;
}

static long do_ptrace(enum __ptrace_request req, pid_t pid, void *a, void *b)
{
    errno = 0;
    long r = ptrace(req, pid, a, b);
    if (r < 0 && errno != 0 && errno != ESRCH)
        fprintf(stderr, "census: ptrace %d failed: %s\n", req,
                strerror(errno));
    return r;
}

/* 在目标内执行 syscall 片段 (svc #0; brk #0), 返回 x0 */
static long inject_syscall(pid_t pid, struct user_regs_struct *regs,
                           long nr, long a0, long a1, long a2, long a3)
{
#if defined(__aarch64__)
    /* 找当前 PC 页 (RWX) 写片段 */
    char maps[256], line[1024];
    snprintf(maps, sizeof maps, "/proc/%d/maps", pid);
    FILE *f = fopen(maps, "r");
    unsigned long page = 0;
    if (f) {
        while (fgets(line, sizeof line, f)) {
            unsigned long s, e;
            char perms[8];
            if (sscanf(line, "%lx-%lx %7s", &s, &e, perms) == 3 &&
                perms[0] == 'r' && perms[2] == 'x' &&
                REG_PC(*regs) >= s && REG_PC(*regs) < e) {
                page = (unsigned long)REG_PC(*regs) & ~0xfffUL;
                break;
            }
        }
        fclose(f);
    }
    if (!page)
        return -1;
    /* 两条指令打包进一个 8B 字 (LE: 低 4B=svc #0, 高 4B=brk #0) */
    uint64_t code = 0xd4200000ULL << 32 | 0xd4000001ULL;
    long backup = do_ptrace(PTRACE_PEEKDATA, pid, (void *)page, 0);
    /* POKEDATA 第 4 参是数据字本身, 不是指针 */
    do_ptrace(PTRACE_POKEDATA, pid, (void *)page,
              (void *)(uintptr_t)code);
    long verify = do_ptrace(PTRACE_PEEKDATA, pid, (void *)page, 0);
    if (verify != (long)code) {
        fprintf(stderr, "census: POKEDATA verify fail at %#lx\n", page);
    }
    struct user_regs_struct r = *regs, saved = *regs;
    r.regs[8] = nr;
    r.regs[0] = a0;
    r.regs[1] = a1;
    r.regs[2] = a2;
    r.regs[3] = a3;
    REG_SET_PC(r, page);
    struct iovec io = {.iov_base = &r, .iov_len = sizeof(r)};
    long ret = -1;
    do_ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &io);
    do_ptrace(PTRACE_CONT, pid, 0, 0);
    int st;
    waitpid(pid, &st, 0);
    if (WIFSTOPPED(st) && WSTOPSIG(st) == SIGSTOP) {
        do_ptrace(PTRACE_CONT, pid, 0, (void *)SIGCONT);
        waitpid(pid, &st, 0);
    }
    if (WIFSTOPPED(st) && WSTOPSIG(st) == SIGTRAP) {
        struct user_regs_struct r2;
        struct iovec io2 = {.iov_base = &r2, .iov_len = sizeof(r2)};
        if (do_ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &io2) == 0)
            ret = r2.regs[0];
    }
    io.iov_base = &saved;
    do_ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &io);
    do_ptrace(PTRACE_POKEDATA, pid, (void *)page, (void *)backup);
    return ret;
#else
    (void)pid; (void)regs; (void)nr; (void)a0; (void)a1; (void)a2; (void)a3;
    return -1;
#endif
}

int main(int argc, char **argv)
{
#if defined(__aarch64__)
    if (argc < 3) {
        fprintf(stderr, "usage: %s <slice.elf> <pages.list>\n", argv[0]);
        return 2;
    }
    if (parse_elf(argv[1]) < 0) {
        fprintf(stderr, "census: cannot parse %s\n", argv[1]);
        return 2;
    }
    /* 读页面清单 */
    uint64_t *pages = NULL;
    size_t npages = 0, cap = 0;
    FILE *pf = fopen(argv[2], "r");
    if (!pf) {
        fprintf(stderr, "census: cannot open %s\n", argv[2]);
        return 2;
    }
    char line[128];
    while (fgets(line, sizeof line, pf)) {
        unsigned long long v;
        if (sscanf(line, "%llx", &v) != 1)
            continue;
        if (npages == cap) {
            cap = cap ? cap * 2 : 64;
            pages = realloc(pages, cap * sizeof(*pages));
        }
        pages[npages++] = v;
    }
    fclose(pf);

    pid_t pid = fork();
    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        execl(argv[1], argv[1], (char *)NULL);
        _exit(127);
    }
    int st;
    waitpid(pid, &st, 0);           /* exec-stop */
    do_ptrace(PTRACE_SETOPTIONS, pid, 0,
              (void *)(PTRACE_O_TRACEEXIT | PTRACE_O_EXITKILL));

    struct user_regs_struct regs;
    struct iovec io = {.iov_base = &regs, .iov_len = sizeof(regs)};
    do_ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &io);

    /* 恢复期防护: 在目标入口 PC 放软断点, 恢复完成 (stub 跳到目标)
       后再 mprotect, 避免恢复写对受保护页逐写逐故障 (极慢且可能
       死锁)。入口 PC 存于 blob 描述符 RST_DESC_TARGET_RIP (+0x18)。 */
    uint64_t target_rip = 0;
    {
        int fd = open(argv[1], O_RDONLY);
        if (fd >= 0) {
            uint8_t d[0x20];
            if (pread(fd, d, sizeof(d),
                      (off_t)(blob_file_off + 0x18)) == sizeof(d))
                target_rip = *(uint64_t *)d;
            close(fd);
        }
    }
    if (target_rip) {
        long saved = do_ptrace(PTRACE_PEEKDATA, pid, (void *)target_rip, 0);
        do_ptrace(PTRACE_POKEDATA, pid, (void *)target_rip,
                  (void *)(uintptr_t)0xD4200000ULL);   /* brk #0 */
        do_ptrace(PTRACE_CONT, pid, 0, 0);
        int st;
        waitpid(pid, &st, 0);
        int at_entry = 0;
        if (WIFSTOPPED(st) && WSTOPSIG(st) == SIGTRAP) {
            struct user_regs_struct r2;
            struct iovec io2 = {.iov_base = &r2, .iov_len = sizeof(r2)};
            if (do_ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS,
                          &io2) == 0 &&
                REG_PC(r2) == target_rip)
                at_entry = 1;
        }
        /* 无论如何先还原 brk (若未停在入口, 后续循环会放行到崩溃) */
        do_ptrace(PTRACE_POKEDATA, pid, (void *)target_rip,
                  (void *)saved);
        if (at_entry) {
            fprintf(stderr, "census: recovery done at %#llx, arming\n",
                    (unsigned long long)target_rip);
        } else {
            uint64_t t = target_rip;
            target_rip = 0;
            fprintf(stderr, "census: target entry %#llx not reached, "
                    "arming anyway\n", (unsigned long long)t);
            /* 已还原 brk; 目标可能已崩, 由主循环处理 */
        }
    }

    for (size_t i = 0; i < npages; i++) {
        long mr = inject_syscall(pid, &regs, 226 /* mprotect */, pages[i],
                                 4096, 0 /* PROT_NONE */, 0);
        if (mr != 0)
            fprintf(stderr, "census: mprotect(%#llx) = %ld\n",
                    (unsigned long long)pages[i], mr);
    }

    unsigned long long reads = 0, writes = 0;
    unsigned char *seen = calloc(npages, 1);
    unsigned long last_pc = 0;
    int same_pc = 0;
    for (;;) {
        do_ptrace(PTRACE_CONT, pid, 0, 0);
        waitpid(pid, &st, 0);
        if (!WIFSTOPPED(st))
            break;
        int sig = WSTOPSIG(st);
        if (sig == (SIGTRAP | 0x80))
            continue;
        if (sig != SIGSEGV) {
            same_pc = 0;
            continue;               /* 其他信号: 放行 */
        }
        siginfo_t si;
        unsigned long addr = 0;
        if (do_ptrace(PTRACE_GETSIGINFO, pid, 0, &si) == 0)
            addr = (unsigned long)si.si_addr;
        do_ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &io);
        unsigned long pc = REG_PC(regs);
        if (pc == last_pc)
            same_pc++;
        else
            same_pc = 0;
        last_pc = pc;
        /* 非普查页重复同 pc 故障 = 目标自身真实崩溃 (NULL deref /
           代码访问等): 放行会无限循环, 终止普查。 */
        unsigned long pg = addr & ~0xfffUL;
        int in_list = 0;
        for (size_t k = 0; k < npages; k++)
            if (pages[k] == pg)
                in_list = 1;
        if (same_pc >= 3 && !in_list) {
            fprintf(stderr, "census: target crashed at pc %#lx "
                    "(addr %#lx), stop\n", pc, addr);
            break;
        }
        if (!addr)
            continue;
        unsigned long page = addr & ~0xfffUL;
        /* 找到对应页索引 */
        size_t pi = 0;
        for (; pi < npages; pi++)
            if (pages[pi] == page)
                break;
        if (pi == npages)
            continue;               /* 非普查页: 直接重执行 */
        if (pc >= strict_lo && pc < strict_hi) {
            /* 回放写: 解保护 + 单步重执行 + 重新保护 (保持页受保护,
               之后的目标读仍会 fault 并记录) */
            writes++;
            inject_syscall(pid, &regs, 226, page, 4096, 3 /* RW */, 0);
            do_ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
            waitpid(pid, &st, 0);
            inject_syscall(pid, &regs, 226, page, 4096, 0 /* NONE */, 0);
            continue;
        }
        if (!seen[pi]) {
            seen[pi] = 1;
            printf("%lx %lx\n", pc, page);
            reads++;
            /* 解保护并保持: 该页后续访问不再 fault (快模式) */
            inject_syscall(pid, &regs, 226, page, 4096, 3 /* RW */, 0);
        }
    }
    free(seen);
    fprintf(stderr, "census: %llu reads, %llu replay writes\n",
            reads, writes);
    return 0;
#else
    (void)argc; (void)argv;
    fprintf(stderr, "census: only supported on aarch64\n");
    return 2;
#endif
}
