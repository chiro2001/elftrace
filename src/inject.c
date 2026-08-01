/*
 * elftrace 注入器: 在冻结的目标进程中执行一次 fork (COW 检查点)
 *
 * 两阶段注入 (compel 式):
 *   - stage1 (写在目标"冷"代码页, 执行后恢复原字节):
 *       mmap 一块专用 RWX 页, 把 stage2 拷贝过去, 跳转执行
 *   - stage2 (专用页, 无污染):
 *       fork; 父进程恢复全部 GPR、跳回原 rip;
 *       子进程 (镜像代理) 置就绪标志后自旋
 *       (专用页保留在目标地址空间, 每检查点 ~4KB 匿名页, 可接受)
 *
 * 收益: 目标停顿仅 ~100ns (注入代码执行), 之后完全不受影响; 内存
 * 快照由采集器从自旋的代理进程读取 (fork 时刻 COW 共享页, 稳定)。
 *
 * 阶段页选择: 目标 exe 的 r-x 段最后一页 (远离 rip 与执行流); 注入
 * 完成后立即恢复原字节 (窗口内目标不会执行该页)。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <signal.h>

#include "util.h"

#define STAGE2_SIZE 512        /* stage2 代码 + 数据 */
#define STAGE1_SIZE 128

/* stage2 数据区 (紧随代码) */
#define D2_OFF    256
#define D2_RIP    0
#define D2_FLAG   8
#define D2_PHASE  16

/* 找注入页: 某代码段的"冷"最后一页 (远离 rip 与执行流) */
static unsigned long find_stage1_page(pid_t pid, unsigned long rip)
{
    char path[64];
    char line[512];
    FILE *f;
    unsigned long candidates[16];
    int ncand = 0;
    unsigned long fallback = 0;

    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    f = fopen(path, "r");
    if (!f)
        return 0;
    while (fgets(line, sizeof(line), f) && ncand < 16) {
        unsigned long long s, e;
        char perms[8];
        char name[256] = "";
        if (sscanf(line, "%llx-%llx %7s %*s %*s %*s %255[^\n]", &s, &e,
                   perms, name) < 3)
            continue;
        if (perms[2] != 'x' || perms[0] != 'r')
            continue;
        if (name[0] == ' ') {
            memmove(name, name + 1, strlen(name));
            if (strstr(name, "vdso") || strstr(name, "vsyscall") ||
                strstr(name, "vvar"))
                continue;
        }
        unsigned long page = ((unsigned long)e - 4096) & ~0xfffUL;
        if (page < s)
            continue;
        if (rip >= page && rip < page + 4096)
            continue;           /* 与 rip 同页 */
        candidates[ncand++] = page;
        if (!fallback)
            fallback = page;
    }
    fclose(f);
    /* 优先 exe 的冷页 (最低地址的候选) */
    unsigned long best = 0;
    for (int i = 0; i < ncand; i++)
        if (!best || candidates[i] < best)
            best = candidates[i];
    return best ? best : fallback;
}

/* 找可写页 (rw- 匿名), 供就绪标志 */
static unsigned long find_flag_page(pid_t pid)
{
    char path[64];
    char line[512];
    FILE *f;

    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    f = fopen(path, "r");
    if (!f)
        return 0;
    while (fgets(line, sizeof(line), f)) {
        unsigned long long s, e;
        char perms[8];
        char name[256] = "";
        if (sscanf(line, "%llx-%llx %7s %*s %*s %*s %255[^\n]", &s, &e,
                   perms, name) < 3)
            continue;
        if (perms[0] != 'r' || perms[1] != 'w')
            continue;
        if (name[0] == ' ') {
            memmove(name, name + 1, strlen(name));
            if (strcmp(name, "[heap]") == 0) {
                fclose(f);
                return (unsigned long)s;
            }
        }
        if (name[0] == '\0') {
            fclose(f);
            return (unsigned long)s;
        }
    }
    fclose(f);
    return 0;
}

static void emit_movabs(unsigned char **pp, unsigned char rex,
                        unsigned char op, uint64_t val)
{
    unsigned char *p = *pp;
    *p++ = rex;
    *p++ = op;
    memcpy(p, &val, 8);
    *pp = p + 8;
}

/*
 * 构造 stage2 (在专用页执行):
 *   lea rax,[rip+0]; and rax,-4096        ; 专用页地址
 *   mov rdi,rax; mov rsi,4096; mov rax,11; syscall   ; munmap 自清理
 *   mov rax,57; syscall                    ; fork
 *   test rax,rax; jz child
 *   [恢复 16 GPR] jmp [rip+0] + orig_rip
 *   child: phase=0xAA; flag=1; spin
 */
void build_stage2(unsigned char *buf, const struct user_regs_struct *r,
                         unsigned long rip, unsigned long flag_addr)
{
    unsigned char *p = buf;
    unsigned char *d = buf + D2_OFF;
    uint64_t v;
    struct { unsigned char rex, op; uint64_t val; } gpr[16] = {
        {0x48, 0xb8, 0}, {0x48, 0xbb, 0}, {0x48, 0xb9, 0},
        {0x48, 0xba, 0}, {0x48, 0xbe, 0}, {0x48, 0xbf, 0},
        {0x48, 0xbd, 0}, {0x48, 0xbc, 0},
        {0x49, 0xb8, 0}, {0x49, 0xb9, 0}, {0x49, 0xba, 0},
        {0x49, 0xbb, 0}, {0x49, 0xbc, 0}, {0x49, 0xbd, 0},
        {0x49, 0xbe, 0}, {0x49, 0xbf, 0},
    };
    uint64_t vals[16] = {r->rax, r->rbx, r->rcx, r->rdx, r->rsi, r->rdi,
                         r->rbp, r->rsp, r->r8, r->r9, r->r10, r->r11,
                         r->r12, r->r13, r->r14, r->r15};

    /* mov rax,57; syscall; test; jz rel32 (child 在末尾) */
    *p++ = 0x48; *p++ = 0xc7; *p++ = 0xc0;
    v = 57; memcpy(p, &v, 4); p += 4;
    *p++ = 0x0f; *p++ = 0x05;
    *p++ = 0x48; *p++ = 0x85; *p++ = 0xc0;
    *p++ = 0x0f; *p++ = 0x84;
    *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;

    /* 恢复 GPR */
    for (int i = 0; i < 16; i++)
        emit_movabs(&p, gpr[i].rex, gpr[i].op, vals[i]);

    /* jmp [rip+0] + orig_rip */
    *p++ = 0xff; *p++ = 0x25;
    *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0;
    memcpy(p, &rip, 8); p += 8;

    /* child: phase=0xAA -> flag=1 -> spin */
    {
        unsigned char *child = p;
        *p++ = 0x48; *p++ = 0xc7; *p++ = 0xc0;
        v = 0xaa; memcpy(p, &v, 4); p += 4;
        emit_movabs(&p, 0x48, 0xbb, flag_addr + 8);
        *p++ = 0x48; *p++ = 0x89; *p++ = 0x03;
        *p++ = 0x48; *p++ = 0xc7; *p++ = 0xc0;
        v = 1; memcpy(p, &v, 4); p += 4;
        emit_movabs(&p, 0x48, 0xbb, flag_addr);
        *p++ = 0x48; *p++ = 0x89; *p++ = 0x03;
        *p++ = 0xeb; *p++ = 0xfe;
        int32_t disp = (int32_t)(child - (buf + 12 + 6));
        /* jz 指令在 buf[12..17], disp 在 buf[14..17] */
        memcpy(buf + 14, &disp, 4);
    }

    memset(d, 0, 32);
    *(uint64_t *)(d + D2_RIP) = rip;
    *(uint64_t *)(d + D2_FLAG) = 0;
    *(uint64_t *)(d + D2_PHASE) = 0;
}

/*
 * 构造 stage1 (写在目标冷代码页):
 *   mov rax,9; xor rdi,rdi; mov rsi,4096; mov rdx,7; mov r10,0x22;
 *   mov r8,-1; xor r9,r9; syscall          ; mmap RWX 匿名
 *   mov rdi,rax; lea rsi,[rip+disp]; mov rcx,512; rep movsb
 *   jmp rax
 */
void build_stage1(unsigned char *buf, const unsigned char *stage2,
                         size_t stage2_len)
{
    unsigned char *p = buf;
    uint64_t v;
    int32_t disp;

    *p++ = 0x48; *p++ = 0xc7; *p++ = 0xc0;
    v = 9; memcpy(p, &v, 4); p += 4;         /* mmap */
    *p++ = 0x48; *p++ = 0x31; *p++ = 0xff;   /* xor rdi,rdi */
    *p++ = 0x48; *p++ = 0xc7; *p++ = 0xc6;
    v = 4096; memcpy(p, &v, 4); p += 4;
    *p++ = 0x48; *p++ = 0xc7; *p++ = 0xc2;
    v = 7; memcpy(p, &v, 4); p += 4;
    *p++ = 0x49; *p++ = 0xc7; *p++ = 0xc2;
    v = 0x22; memcpy(p, &v, 4); p += 4;
    *p++ = 0x49; *p++ = 0xc7; *p++ = 0xc0;
    v = -1; memcpy(p, &v, 4); p += 4;
    *p++ = 0x4d; *p++ = 0x31; *p++ = 0xc9;   /* xor r9,r9 */
    *p++ = 0x0f; *p++ = 0x05;
    /* mov rdi, rax */
    *p++ = 0x48; *p++ = 0x89; *p++ = 0xc7;
    /* lea rsi, [rip+disp] -> stage2 副本 (紧跟本代码) */
    *p++ = 0x48; *p++ = 0x8d; *p++ = 0x35;
    disp = (int32_t)((buf + STAGE1_SIZE) - (p + 4));
    memcpy(p, &disp, 4); p += 4;
    /* mov rcx, len; rep movsb */
    *p++ = 0x48; *p++ = 0xc7; *p++ = 0xc1;
    v = stage2_len; memcpy(p, &v, 4); p += 4;
    *p++ = 0xf3; *p++ = 0xa4;
    /* jmp rax */
    *p++ = 0xff; *p++ = 0xe0;

    /* stage2 副本紧跟其后 (由调用方拷贝) */
    memcpy(buf + STAGE1_SIZE, stage2, stage2_len);
}

int inject_fork(pid_t pid, const struct user_regs_struct *regs, pid_t *child)
{
    unsigned long page1 = find_stage1_page(pid, regs->rip);
    unsigned long flag_page = find_flag_page(pid);
    unsigned char stage2[STAGE2_SIZE];
    unsigned char stage1[STAGE1_SIZE + STAGE2_SIZE];
    unsigned char backup[STAGE1_SIZE];
    unsigned long flag_addr;
    int got = 0;

    if (!page1 || !flag_page)
        return -1;

    flag_addr = flag_page + D2_OFF + D2_FLAG;
    memset(stage2, 0, sizeof(stage2));
    build_stage2(stage2, regs, regs->rip, flag_addr);
    build_stage1(stage1, stage2, STAGE2_SIZE);

    for (int i = 0; i < STAGE1_SIZE; i++)
        backup[i] = ptrace(PTRACE_PEEKDATA, pid, page1 + i, 0) & 0xff;

    /* 写入 stage1 代码 + stage2 副本 (页内偏移 0x80 起) */
    for (int i = 0; i < STAGE1_SIZE + STAGE2_SIZE; i += 8) {
        unsigned long w = 0;
        memcpy(&w, stage1 + i, 8);
        if (ptrace(PTRACE_POKEDATA, pid, page1 + i, w) < 0)
            goto fail;
    }

    {
        struct user_regs_struct nr = *regs;
        nr.rip = page1;
        if (ptrace(PTRACE_SETREGS, pid, 0, &nr) < 0)
            goto fail;
    }
    if (ptrace(PTRACE_CONT, pid, 0, 0) < 0)
        goto fail;

    for (int i = 0; i < 500; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/task/%d/children", pid, pid);
        FILE *f = fopen(path, "r");
        if (f) {
            int c;
            if (fscanf(f, "%d", &c) == 1) {
                char mpath[64];
                snprintf(mpath, sizeof(mpath), "/proc/%d/mem", c);
                int mfd = open(mpath, O_RDONLY);
                if (mfd >= 0) {
                    unsigned long v = 0;
                    ssize_t nr = pread(mfd, &v, 8, flag_addr);
                    if (nr == 8 && v == 1) {
                        close(mfd);
                        fclose(f);
                        *child = c;
                        got = 1;
                        break;
                    }
                    close(mfd);
                }
            }
            fclose(f);
        }
        usleep(1000);
    }

    if (!got)
        return -1;

    for (int i = 0; i < STAGE1_SIZE; i += 8) {
        unsigned long w = 0;
        memcpy(&w, backup + i, 8);
        ptrace(PTRACE_POKEDATA, pid, page1 + i, w);
    }
    return 0;
fail:
    for (int i = 0; i < STAGE1_SIZE; i += 8) {
        unsigned long w = 0;
        memcpy(&w, backup + i, 8);
        ptrace(PTRACE_POKEDATA, pid, page1 + i, w);
    }
    return -1;
}
