/*
 * elftrace trace: 指令计数检查点采集器 (功能 7 的采集端)
 *
 * 用 perf 指令计数事件 (perf_event_open 绑定目标进程) 每隔 N 条指令
 * 冻结目标, 采集一个完整检查点 (.elftrace), 并记录 (指令计数, 冻结
 * 时 PC) 到 manifest。生成的文件可被 build --checkpoints/--from/--to
 * 用作区间切片的基础镜像与退出点。
 *
 * 计数从 trace 启动时刻起算 (相对计数); 检查点粒度 = N 条指令,
 * "第 xn 条指令" 对齐到最近检查点 (误差 < N)。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <linux/ptrace.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stddef.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <limits.h>

#include "elftrace.h"
#include "collect.h"
#include "util.h"
#include "arch.h"

int inject_fork(pid_t pid, const struct user_regs_struct *regs, pid_t *child,
                uint64_t *inj_page);

#define TRACE_DEFAULT_EVERY 100000000ULL   /* 每 1e8 条指令一个检查点 */

static volatile sig_atomic_t g_stop = 0;
static void on_sig(int s) { (void)s; g_stop = 1; }
#define RING_PAGES 5                        /* (1 + 2^k) 页 */

struct trace_ctx {
    pid_t pid;
    uint64_t every;
    const char *out;
    int perf_fd;
    struct perf_event_mmap_page *meta;
    uint8_t *ring;
    size_t ring_size;
    uint64_t count;             /* 已记录的指令计数 */
    size_t ckpt_no;
    size_t cow_ok, cow_fail;
    pid_t *cow_children;
    size_t n_cow_children;
    struct collect_snapshot last;   /* 上一检查点的段表+内容 (增量对比) */
    int have_last;
    /* 延迟 dump: 在线只保存代理 pid + 轻量状态, 目标阶段结束后按序 dump */
    struct ckpt_entry {
        pid_t agent;
        struct collect_snapshot light;
    } *entries;
    size_t n_entries;
    /* syscall 前后检查点 (PTRACE_SYSCALL 捕获) */
    uint64_t inj_page;              /* 注入专用页地址 (放行判断) */
    struct syscall_rec {
        uint64_t pc;                /* syscall 指令地址 */
        uint64_t sysno;
        uint64_t count;             /* 捕获时的 perf 指令计数 (窗口过滤用) */
        int interrupted;            /* INTERRUPT 打断的在途 syscall (A=近似) */
        struct collect_snapshot light_a;  /* 入口状态 + 内存基线 */
        struct collect_snapshot light_b;  /* 返回状态 + 内存 */
    } *syscalls;
    size_t n_syscalls;
    struct collect_snapshot pend_light;  /* 待定 syscall 入口状态 */
    pid_t pend_agent;
    uint64_t pend_pc, pend_sysno;
    int have_pending;
};

/* 读 perf 累计计数 (syscall 记录定位用; ring sample 可能滞后) */
static uint64_t perf_count_now(struct trace_ctx *tc)
{
    uint64_t v = 0;
    if (tc->perf_fd >= 0)
        read(tc->perf_fd, &v, sizeof(v));
    return v;
}

static void perf_open(struct trace_ctx *tc)
{
    struct perf_event_attr attr;
    long page = sysconf(_SC_PAGESIZE);
    void *map;

    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_HARDWARE;
    attr.size = sizeof(attr);
    attr.config = PERF_COUNT_HW_INSTRUCTIONS;
    attr.sample_period = tc->every;
    attr.sample_type = PERF_SAMPLE_IP;
    attr.disabled = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    attr.wakeup_events = 1;

    tc->perf_fd = syscall(__NR_perf_event_open, &attr, tc->pid, -1, -1, 0);
    if (tc->perf_fd < 0) {
        /* qemu TCG / 无 PMU 环境: 回退软件事件 (task-clock, 时间基
           检查点)。指令数不再精确 (interval/IPC 断言会偏移), 但
           PTRACE_SYSCALL 回放表照常采集。 */
        warn("perf hardware instructions unavailable (%s), falling back "
             "to task-clock (time-based checkpoints)", strerror(errno));
        attr.type = PERF_TYPE_SOFTWARE;
        attr.config = PERF_COUNT_SW_TASK_CLOCK;
        attr.sample_period = 1000000000;   /* 1s 一个检查点 */
        attr.sample_freq = 0;
        tc->perf_fd = syscall(__NR_perf_event_open, &attr, tc->pid,
                              -1, -1, 0);
    }
    if (tc->perf_fd < 0)
        die("perf_event_open on %d (need perf_event_paranoid <= 2)", tc->pid);

    tc->ring_size = RING_PAGES * page;
    map = mmap(NULL, tc->ring_size, PROT_READ | PROT_WRITE, MAP_SHARED,
               tc->perf_fd, 0);
    if (map == MAP_FAILED)
        die("mmap perf ring");
    tc->meta = map;
    tc->ring = (uint8_t *)map + tc->meta->data_offset;
}

/* 消费 ring 中的一个 sample, 返回其 IP; 无数据返回 0 */
static uint64_t perf_next_sample(struct trace_ctx *tc)
{
    struct perf_event_mmap_page *m = tc->meta;
    uint64_t head, tail;
    size_t data_size = tc->meta->data_size;

    head = __atomic_load_n(&m->data_head, __ATOMIC_ACQUIRE);
    tail = __atomic_load_n(&m->data_tail, __ATOMIC_RELAXED);
    if (head == tail)
        return 0;

    struct perf_event_header *h =
        (struct perf_event_header *)(tc->ring + (tail % data_size));
    if (h->type == PERF_RECORD_SAMPLE && h->size >= 16) {
        uint64_t ip;
        size_t off = (tail + 8) % data_size;    /* ip 紧跟 header */
        memcpy(&ip, tc->ring + off, 8);
        __atomic_store_n(&m->data_tail, tail + h->size, __ATOMIC_RELEASE);
        return ip;
    }
    /* 其他记录类型: 跳过 */
    if (h->size > 0 && h->size <= data_size) {
        __atomic_store_n(&m->data_tail, tail + h->size, __ATOMIC_RELEASE);
    }
    return 0;
}

/* syscall 入口/返回停止处理 (PTRACE_SYSCALL 模式)
 * entry: 记录待定 + 注入入口代理 A (临时 diff 基线)
 * exit:  注入返回代理 B, 完成记录 {pc, A, B}
 * 注入专用页内的 syscall (mmap/fork) 直接放行 */
static void handle_syscall_stop(struct trace_ctx *tc, int is_entry,
                                int sysno, uint64_t rip)
{
    if (tc->inj_page && rip >= tc->inj_page && rip < tc->inj_page + 4096) {
        ptrace(PTRACE_SYSCALL, tc->pid, 0, 0);   /* 注入代码的 syscall */
        return;
    }
    if (is_entry) {
        if (tc->have_pending) {
            /* 捕获窗口竞态 (INTERRUPT 冻结在 syscall 中, 恢复后重复):
               跳过, 不中断采集 */
            fprintf(stderr, "trace: syscall entry while pending @ %#llx "
                    "(skipped)\n", (unsigned long long)rip);
            ptrace(PTRACE_SYSCALL, tc->pid, 0, 0);
            return;
        }
        struct collect_snapshot sn = {.pid = tc->pid};
        collect_state_light(tc->pid, &sn);
        /* 入口基线: 目标在 syscall-stop (本来就停), 直接读内存 */
        collect_memory(tc->pid, &sn);
        tc->pend_pc = rip;
        tc->pend_sysno = sysno;
        collect_snapshot_copy_light(&tc->pend_light, &sn);
        cbuf_append(&tc->pend_light.payload, sn.payload.data,
                    sn.payload.size);
        tc->have_pending = 1;
        collect_free(&sn);
    } else {
        if (!tc->have_pending) {
            /* INTERRUPT 打断进行中的 syscall: entry-stop 在捕获窗口前
               (trace 开始前已在 syscall 中 / 被 INTERRUPT 打断)。
               补记: A = 上检查点快照 (近似: 打断时刻状态不可得),
               B = 当前 (syscall 已完成, buffer 被写/rax=返回值)。
               切片从检查点恢复后重做该 syscall (int3) 时命中。 */
            struct collect_snapshot b = {.pid = tc->pid};
            collect_state_light(tc->pid, &b);
            collect_memory(tc->pid, &b);
            tc->syscalls = xrealloc(tc->syscalls,
                                    (tc->n_syscalls + 1) *
                                    sizeof(*tc->syscalls));
            struct syscall_rec *r = &tc->syscalls[tc->n_syscalls++];
            r->pc = rip - ARCH_SYSCALL_LEN;  /* syscall 指令 */
            r->sysno = 0;       /* EXIT-stop 无 syscall 号 */
            r->count = perf_count_now(tc);
            r->interrupted = 1;
            if (tc->have_last) {
                collect_snapshot_copy_light(&r->light_a, &tc->last);
                cbuf_append(&r->light_a.payload, tc->last.payload.data,
                            tc->last.payload.size);
            }
            collect_snapshot_copy_light(&r->light_b, &b);
            cbuf_append(&r->light_b.payload, b.payload.data, b.payload.size);
            collect_free(&b);
            fprintf(stderr, "trace: interrupted syscall @ %#llx "
                    "(A=last ckpt, rec %zu)\n",
                    (unsigned long long)r->pc, tc->n_syscalls - 1);
            ptrace(PTRACE_SYSCALL, tc->pid, 0, 0);
            return;
        }
        struct collect_snapshot sn = {.pid = tc->pid};
        collect_state_light(tc->pid, &sn);
        /* 返回状态: 同样直接读目标内存 (无代理, 无 dumpable/注入交互) */
        collect_memory(tc->pid, &sn);
        tc->syscalls = xrealloc(tc->syscalls,
                                (tc->n_syscalls + 1) *
                                sizeof(*tc->syscalls));
        struct syscall_rec *r = &tc->syscalls[tc->n_syscalls++];
        r->pc = tc->pend_pc;
        r->sysno = tc->pend_sysno;
        r->count = perf_count_now(tc);
        collect_snapshot_copy_light(&r->light_b, &sn);
        cbuf_append(&r->light_b.payload, sn.payload.data, sn.payload.size);
        /* A 基线 (入口状态+内存) 移入记录 */
        r->light_a = tc->pend_light;
        memset(&tc->pend_light, 0, sizeof(tc->pend_light));
        tc->have_pending = 0;
        collect_free(&sn);
        fprintf(stderr, "trace: syscall %llu @ %#llx (rec %zu)\n",
                (unsigned long long)r->sysno,
                (unsigned long long)r->pc, tc->n_syscalls - 1);
    }
    ptrace(PTRACE_SYSCALL, tc->pid, 0, 0);
}

/* 冻结目标: INTERRUPT 循环直到拿到 INTERRUPT-stop;
 * 若目标在 syscall-stop (挂起未处理) 先按 syscall 逻辑处理再重新冻结 */
static int collect_interrupt_sc(struct trace_ctx *tc)
{
    pid_t pid = tc->pid;
    for (int i = 0; i < 16; i++) {
        if (ptrace(PTRACE_INTERRUPT, pid, 0, 0) < 0)
            return -1;
        int st;
        if (waitpid(pid, &st, 0) < 0)
            return -1;
        if (!WIFSTOPPED(st))
            return -1;
        int si = WSTOPSIG(st);
        if (si == (SIGTRAP | 0x80)) {
            struct ptrace_syscall_info psi;
            memset(&psi, 0, sizeof(psi));
            long n = ptrace(PTRACE_GET_SYSCALL_INFO, pid, sizeof(psi), &psi);
            if (n <= 0)
                die("trace: PTRACE_GET_SYSCALL_INFO failed");
            fprintf(stderr, "dbg: interrupt-sc syscall op=%d\n",
                    (int)psi.op);
            if (psi.op == PTRACE_SYSCALL_INFO_ENTRY) {
                handle_syscall_stop(tc, 1, psi.entry.nr,
                                    psi.instruction_pointer);
            } else if (psi.op == PTRACE_SYSCALL_INFO_EXIT &&
                       !tc->have_pending) {
                /* INTERRUPT 打断进行中的 syscall: 恢复后先产生
                   EXIT-stop (无对应 entry)。补记该记录 —
                   A = 上检查点快照 (近似: 打断时刻状态不可得),
                   B = 当前 (syscall 已完成, buffer 被写/rax=返回值)。
                   切片从检查点恢复后重做该 syscall (int3) 时命中。 */
                struct collect_snapshot b = {.pid = pid};
                collect_state_light(pid, &b);
                collect_memory(pid, &b);
                tc->syscalls = xrealloc(tc->syscalls,
                                        (tc->n_syscalls + 1) *
                                        sizeof(*tc->syscalls));
                struct syscall_rec *r = &tc->syscalls[tc->n_syscalls++];
                r->pc = psi.instruction_pointer - ARCH_SYSCALL_LEN;
                r->sysno = 0;   /* EXIT-stop 无 syscall 号 */
                r->count = perf_count_now(tc);
                r->interrupted = 1;
                if (tc->have_last) {
                    collect_snapshot_copy_light(&r->light_a, &tc->last);
                    cbuf_append(&r->light_a.payload,
                                tc->last.payload.data,
                                tc->last.payload.size);
                }
                collect_snapshot_copy_light(&r->light_b, &b);
                cbuf_append(&r->light_b.payload, b.payload.data,
                            b.payload.size);
                collect_free(&b);
                fprintf(stderr, "trace: interrupted syscall @ %#llx "
                        "(A=last ckpt)\n",
                        (unsigned long long)r->pc);
            } else {
                handle_syscall_stop(tc, 0, 0, psi.instruction_pointer);
            }
            continue;           /* 重新 INTERRUPT */
        }
        if (si == SIGTRAP)
            return 0;           /* INTERRUPT-stop */
        ptrace(PTRACE_SYSCALL, pid, 0, 0);   /* 其他信号: 放行再冻结 */
        continue;
    }
    return -1;
}

/* already_stopped: tracee 已处于 ptrace-stop (初始停止或刚 INTERRUPT 完) */
static void ckpt_take(struct trace_ctx *tc, int already_stopped)
{
    char path[PATH_MAX];
    char manifest[PATH_MAX];
    struct collect_snapshot sn = {.pid = tc->pid};
    FILE *f;
    pid_t child = -1;

    if (!already_stopped && collect_interrupt_sc(tc) < 0)
        return;                 /* tracee 已退出 */

#if defined(__aarch64__)
    /* TPIDR_EL0: NT_ARM_TLS 可能陈旧, 用 jit 读 HW 值 (首次) */
    collect_tls_jit(tc->pid);
#endif

    /* 轻量采集 (冻结 ~us): 寄存器/掩码/xstate/fds/段表 */
    collect_state_light(tc->pid, &sn);
    if (tc->inj_page && REG_PC(sn.regs) >= tc->inj_page &&
        REG_PC(sn.regs) < tc->inj_page + 4096) {
        /* 冻结在注入代码中: 检查点无效, 放弃 (目标恢复运行) */
        ptrace(PTRACE_SYSCALL, tc->pid, 0, 0);
        collect_free(&sn);
        return;
    }

    /* aarch64: 检查点捕获到在途 syscall (INTERRUPT 打断) 时, 恢复 pc
       在 svc+4 (EXIT 态), 切片会跳过该 syscall 但内存未生效; 把 pc
       调回 svc 使切片重执行它, 由回放记录应用内存变化并返回完整结果。 */
#if defined(__aarch64__)
    if (tc->n_syscalls > 0) {
        struct syscall_rec *lastr = &tc->syscalls[tc->n_syscalls - 1];
        if (lastr->interrupted &&
            lastr->pc + ARCH_SYSCALL_LEN == REG_PC(sn.regs)) {
            REG_SET_PC(sn.regs, lastr->pc);
        }
    }
#endif

    /* 冻结期间直接读全量内存并即时写检查点 (diff 链) */
    collect_memory(tc->pid, &sn);
    /* 无上一检查点时的在途记录: A 基线 = 当前检查点状态 (内存未生效,
       与 B 的 diff 即 syscall 的内存变化) */
    if (tc->n_syscalls > 0) {
        struct syscall_rec *lastr = &tc->syscalls[tc->n_syscalls - 1];
        if (lastr->interrupted && lastr->light_a.payload.size == 0) {
            collect_snapshot_copy_light(&lastr->light_a, &sn);
            cbuf_append(&lastr->light_a.payload, sn.payload.data,
                        sn.payload.size);
        }
    }
    snprintf(path, sizeof(path), "%s/ckpt_%06zu.elftrace", tc->out,
             tc->ckpt_no);
    if (tc->ckpt_no == 0) {
        collect_write(&sn, path);
        collect_snapshot_copy_last(&tc->last, &sn);
        tc->have_last = 1;
    } else {
        collect_write_diff(&tc->last, &sn, path);
        collect_snapshot_free_last(&tc->last);
        collect_snapshot_copy_last(&tc->last, &sn);
    }
    ptrace(PTRACE_SYSCALL, tc->pid, 0, 0);   /* 保持 syscall 捕获模式 */

    snprintf(manifest, sizeof(manifest), "%s/manifest.txt", tc->out);
    f = fopen(manifest, "a");
    if (f) {
        /* 记录文件名 (相对目录), 供 build --checkpoints 拼接 */
        snprintf(path, sizeof(path), "%s/ckpt_%06zu.elftrace", tc->out,
                 tc->ckpt_no);
        const char *base = strrchr(path, '/');
        base = base ? base + 1 : path;
        /* 第 4 字段: 该检查点时刻已捕获的 syscall 记录数 —
           build --from/--to 据此裁剪回放表 (切片从检查点 K 恢复,
           只消费 K 之后的 syscall 记录) */
        fprintf(f, "%llu 0x%llx %s %zu\n",
                (unsigned long long)tc->count,
                (unsigned long long)REG_PC(sn.regs), base,
                tc->n_syscalls);
        fclose(f);
    }
    fprintf(stderr, "trace: ckpt %zu @ count %llu pc %#llx\n", tc->ckpt_no,
            (unsigned long long)tc->count, (unsigned long long)REG_PC(sn.regs));

    collect_free(&sn);
    if (tc->ckpt_no > 0 && tc->ckpt_no % 5 == 0)
        fprintf(stderr, "trace: %zu checkpoints (cow ok %zu, fail %zu)\n",
                tc->ckpt_no, tc->cow_ok, tc->cow_fail);
    tc->ckpt_no++;
    tc->count += tc->every;
}

int trace_main(int argc, char **argv)
{
    struct trace_ctx tc = {0};
    pid_t pid = 0;

    tc.every = TRACE_DEFAULT_EVERY;
    tc.out = "./ckpts";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--every") == 0 && i + 1 < argc) {
            tc.every = strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
            tc.out = argv[++i];
        } else if (argv[i][0] >= '0' && argv[i][0] <= '9') {
            pid = atoi(argv[i]);
        } else {
            die("usage: elftrace trace <pid> [--every N] [--out DIR]");
        }
    }
    if (pid == 0)
        die("usage: elftrace trace <pid> [--every N] [--out DIR]");
    tc.pid = pid;

    if (mkdir(tc.out, 0755) < 0 && errno != EEXIST)
        die("mkdir %s", tc.out);

    perf_open(&tc);
    if (ioctl(tc.perf_fd, PERF_EVENT_IOC_ENABLE, 0) < 0)
        die("perf enable");

    /* SIGTERM/SIGINT: 优雅退出 (先离线 dump 再退出) */
    signal(SIGTERM, on_sig);
    signal(SIGINT, on_sig);

    /* 全程保持 SEIZE 关系; 每个检查点只 INTERRUPT */
    if (ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_TRACESYSGOOD) < 0)
        die("ptrace(SEIZE) on %d", pid);
    if (ptrace(PTRACE_INTERRUPT, pid, 0, 0) < 0)
        die("ptrace(INTERRUPT) on %d", pid);
    {
        int st;
        if (waitpid(pid, &st, 0) < 0 || !WIFSTOPPED(st))
            die("wait for initial stop of %d", pid);
    }

    /* 初始检查点 (count 0, 已处于初始停止) */
    ckpt_take(&tc, 1);

    /* 目标恢复运行, 用 PTRACE_SYSCALL 模式 (每次 syscall 入口/返回停止) */
    ptrace(PTRACE_SYSCALL, pid, 0, 0);

    /* 主循环: 事件驱动 (syscall-stop 分派 + perf 溢出检查点) */
    /* 主循环: WNOHANG 处理挂起 stop (syscall-stop) + poll 等 perf 溢出 */
    for (;;) {
        /* 1. 处理挂起的 ptrace-stop (syscall 入口/返回, 信号等) */
        for (int ns = 0; ns < 256; ns++) {
            if (g_stop)
                break;
            int wst;
            pid_t wr = waitpid(pid, &wst, WNOHANG);
            if (wr != pid)
                break;
            if (WIFEXITED(wst) || WIFSIGNALED(wst))
                goto main_done;
            if (!WIFSTOPPED(wst))
                continue;
            int si = WSTOPSIG(wst);
            if (si == (SIGTRAP | 0x80)) {
                struct ptrace_syscall_info psi;
                memset(&psi, 0, sizeof(psi));
                long n = ptrace(PTRACE_GET_SYSCALL_INFO, pid,
                                sizeof(psi), &psi);
                if (n <= 0)
                    die("trace: PTRACE_GET_SYSCALL_INFO failed");
                if (psi.op == PTRACE_SYSCALL_INFO_ENTRY)
                    handle_syscall_stop(&tc, 1, psi.entry.nr,
                                        psi.instruction_pointer);
                else if (psi.op == PTRACE_SYSCALL_INFO_EXIT)
                    handle_syscall_stop(&tc, 0, 0,
                                        psi.instruction_pointer);
                else
                    ptrace(PTRACE_SYSCALL, pid, 0, 0);
            } else if (si == SIGTRAP) {
                ptrace(PTRACE_SYSCALL, pid, 0, 0);
            } else {
                fprintf(stderr, "trace: target signal %d (delivered)\n",
                        si);
                ptrace(PTRACE_SYSCALL, pid, 0, si);
            }
        }

        /* 2. perf 溢出 → 常规检查点 */
        {
            struct pollfd pfd = {.fd = tc.perf_fd, .events = POLLIN};
            int r = poll(&pfd, 1, 100);
            if (r > 0 && (pfd.revents & POLLIN)) {
                uint64_t ip;
                while ((ip = perf_next_sample(&tc)) != 0)
                    ckpt_take(&tc, 0);
                if (kill(pid, 0) == 0)
                    ptrace(PTRACE_SYSCALL, pid, 0, 0);
            }
            /* 兜底: aarch64 上 ptrace 频繁 syscall-stop 可能干扰 ring
               sample 写入 (首样本后 head 不再前进), 直接读计数器值判断
               是否越过下一检查点阈值。read 返回累计计数, 无样本时
               依然可靠。 */
            {
                uint64_t val = 0;
                if (read(tc.perf_fd, &val, sizeof(val)) == sizeof(val) &&
                    val >= tc.count + tc.every) {
                    uint64_t ip;
                    while ((ip = perf_next_sample(&tc)) != 0) {}
                    ckpt_take(&tc, 0);
                    if (kill(pid, 0) == 0)
                        ptrace(PTRACE_SYSCALL, pid, 0, 0);
                }
            }
        }

        if (g_stop)
            break;              /* SIGTERM: 优雅退出进入离线 dump */

        if (kill(pid, 0) < 0 && errno == ESRCH)
            break;
    }
main_done:

    if (kill(pid, 0) == 0)
        collect_detach_run(pid);   /* 目标已退出则无需 detach */
    close(tc.perf_fd);

    /* 离线 dump 阶段: 目标阶段已结束, 按检查点顺序从代理读内存,
       先检查代理存活情况 */
    {
        int nalive = 0, nzombie = 0;
        for (size_t k = 0; k < tc.n_entries; k++) {
            pid_t a = tc.entries[k].agent;
            char sp[64];
            snprintf(sp, sizeof(sp), "/proc/%d/stat", a);
            FILE *sf = fopen(sp, "r");
            if (!sf) {
                nzombie++;
                fprintf(stderr, "dump: agent %d (ckpt %zu) gone\n", a, k);
                continue;
            }
            char sb[256];
            size_t sn2 = fread(sb, 1, sizeof(sb) - 1, sf);
            sb[sn2] = 0;
            fclose(sf);
            char *p = strrchr(sb, ')');
            if (p && p[1] == ' ' && p[2] == 'Z')
                nzombie++;
            else
                nalive++;
        }
        fprintf(stderr, "dump: agents alive=%d zombie/gone=%d\n",
                nalive, nzombie);
    }

    /* 检查点 0 写完整快照, 后续与上一检查点对比写 diff (需按序);
       dump 完的代理立即回收 */
    for (size_t k = 0; k < tc.n_entries; k++) {
        struct ckpt_entry *e = &tc.entries[k];
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/ckpt_%06zu.elftrace", tc.out, k);
        collect_memory(e->agent, &e->light);
        if (k == 0) {
            collect_write(&e->light, path);
            collect_snapshot_copy_last(&tc.last, &e->light);
            tc.have_last = 1;
        } else {
            collect_write_diff(&tc.last, &e->light, path);
            collect_snapshot_free_last(&tc.last);
            collect_snapshot_copy_last(&tc.last, &e->light);
        }
        kill(e->agent, SIGKILL);
        e->agent = -1;
        collect_snapshot_free_light(&e->light);
    }
    if (tc.have_last)
        collect_snapshot_free_last(&tc.last);

    /* 离线 syscall 检查点: 对比入口/返回代理 → B-A diff
       (syscalls/ 子目录, 仅记录差异, 不参与切片起点/终点选择) */
    if (tc.n_syscalls) {
        char sdir[PATH_MAX];
        snprintf(sdir, sizeof(sdir), "%s/syscalls", tc.out);
        mkdir(sdir, 0755);
        char mp[PATH_MAX];
        snprintf(mp, sizeof(mp), "%s/syscall.map", sdir);
        FILE *mf = fopen(mp, "w");
        if (!mf)
            die("cannot create %s", mp);
        for (size_t k = 0; k < tc.n_syscalls; k++) {
            struct syscall_rec *r = &tc.syscalls[k];
            char path[PATH_MAX];
            snprintf(path, sizeof(path), "%s/sys_%06zu.elftrace", sdir, k);
            collect_write_diff(&r->light_a, &r->light_b, path);
            fprintf(mf, "%#llx %llu sys_%06zu.elftrace%s %llu\n",
                    (unsigned long long)r->pc,
                    (unsigned long long)r->sysno, k,
                    r->interrupted ? " I" : "",
                    (unsigned long long)r->count);
            collect_snapshot_free_light(&r->light_a);
            collect_snapshot_free_light(&r->light_b);
        }
        fclose(mf);
    }

    fprintf(stderr, "trace: done, %zu checkpoints (cow %zu/%zu, %zu agents), "
            "%zu syscalls in %s\n", tc.ckpt_no, tc.cow_ok,
            tc.cow_ok + tc.cow_fail, tc.n_entries, tc.n_syscalls, tc.out);
    return 0;
}
