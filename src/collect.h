#ifndef ELFTRACE_COLLECT_H
#define ELFTRACE_COLLECT_H

#include <stdint.h>
#include <stddef.h>
#include <sys/user.h>

/* 可扩展缓冲 */
struct cbuf {
    uint8_t *data;
    size_t size;
    size_t cap;
};

void cbuf_init(struct cbuf *b);
void cbuf_append(struct cbuf *b, const void *data, size_t size);

struct cseg {
    uint64_t vaddr;
    uint64_t filesz;
    uint64_t memsz;
    uint64_t flags;
    char *name;
};

struct cfdinfo {
    uint64_t fd;
    uint64_t flags;
    uint64_t mode;
    uint64_t pos;
    char *path;
};

struct caux {
    char *name;
    uint64_t addr;
    uint64_t size;
    uint64_t type;
    uint64_t flags;
    uint64_t align;
    uint64_t entsize;
    uint64_t link;
    uint64_t info;
    uint8_t *data;
};

/* 一次进程状态采集的完整结果 */
struct collect_snapshot {
    pid_t pid;
    uint32_t arch;              /* ELFTRACE_ARCH_* */
    struct user_regs_struct regs;
    uint8_t *xstate;
    size_t xstate_size;
    uint8_t sigmask[8];
    int in_syscall;

    struct cseg *segs;
    size_t nsegs;
    uint64_t *payload_offs;
    struct cbuf payload;

    struct cfdinfo *fds;
    size_t nfds;

    char *exe_path;
    uint64_t exe_bias;

    struct caux *aux;
    size_t naux;
};

/* 冻结: SEIZE + INTERRUPT + waitpid, 返回 0 成功 (tracee 处于 ptrace-stop) */
int collect_freeze(pid_t pid);
/* 仅 INTERRUPT (要求已 SEIZE): 用于 trace 的连续检查点 */
int collect_interrupt(pid_t pid);
/* 解除跟踪 (detach, tracee 恢复运行) */
void collect_detach_run(pid_t pid);
/* 采集全部状态 (要求 tracee 已冻结) */
void collect_state(pid_t pid, struct collect_snapshot *sn);
/* 采集轻量状态 (寄存器/掩码/xstate/fds/段表, 不含内存) */
void collect_state_light(pid_t pid, struct collect_snapshot *sn);
void collect_segments(struct collect_snapshot *sn);
/* 采集内存段内容 (从指定进程读, 通常为 COW 代理) */
void collect_memory(pid_t pid, struct collect_snapshot *sn);
/* 写出 .elftrace */
void collect_write(const struct collect_snapshot *sn, const char *out);
/* 分离并保持冻结 (SIGSTOP + detach), 之后 SIGCONT 可唤醒 */
void collect_detach_frozen(pid_t pid);
/* 恢复运行 (PTRACE_CONT, 用于 trace) */
void collect_resume(pid_t pid);
/* 释放 */
void collect_free(struct collect_snapshot *sn);

#endif /* ELFTRACE_COLLECT_H */
