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

int inject_fork(pid_t pid, const struct user_regs_struct *regs, pid_t *child);

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
};

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

/* already_stopped: tracee 已处于 ptrace-stop (初始停止或刚 INTERRUPT 完) */
static void ckpt_take(struct trace_ctx *tc, int already_stopped)
{
    char path[PATH_MAX];
    char manifest[PATH_MAX];
    struct collect_snapshot sn = {.pid = tc->pid};
    FILE *f;
    pid_t child = -1;

    if (!already_stopped && collect_interrupt(tc->pid) < 0)
        return;                 /* tracee 已退出 */

    /* 轻量采集 (冻结 ~us): 寄存器/掩码/xstate/fds/段表 */
    collect_state_light(tc->pid, &sn);

    /* COW 注入: 目标 fork 镜像代理后立即恢复运行 */
    if (inject_fork(tc->pid, &sn.regs, &child) == 0) {
        tc->cow_ok++;
        /* 延迟 dump: 在线只保存代理 pid + 轻量状态 (目标零重负载);
           代理 pause 阻塞保持快照, 目标阶段结束后统一按序 dump */
        tc->entries = xrealloc(tc->entries,
                               (tc->n_entries + 1) *
                               sizeof(*tc->entries));
        struct ckpt_entry *e = &tc->entries[tc->n_entries++];
        e->agent = child;
        collect_snapshot_copy_light(&e->light, &sn);
        child = -1;
    } else {
        tc->cow_fail++;
        /* 回退: 冻结期间读全量内存并即时写检查点 (tracee 已在 ptrace-stop) */
        collect_memory(tc->pid, &sn);
        collect_resume(tc->pid);
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
    }

    snprintf(manifest, sizeof(manifest), "%s/manifest.txt", tc->out);
    f = fopen(manifest, "a");
    if (f) {
        /* 记录文件名 (相对目录), 供 build --checkpoints 拼接 */
        snprintf(path, sizeof(path), "%s/ckpt_%06zu.elftrace", tc->out,
                 tc->ckpt_no);
        const char *base = strrchr(path, '/');
        base = base ? base + 1 : path;
        fprintf(f, "%llu 0x%llx %s\n",
                (unsigned long long)tc->count,
                (unsigned long long)sn.regs.rip, base);
        fclose(f);
    }
    fprintf(stderr, "trace: ckpt %zu @ count %llu pc %#llx\n", tc->ckpt_no,
            (unsigned long long)tc->count, (unsigned long long)sn.regs.rip);

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
    if (ptrace(PTRACE_SEIZE, pid, 0, 0) < 0)
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

    /* 主循环: 等待溢出 */
    for (;;) {
        struct pollfd pfd = {.fd = tc.perf_fd, .events = POLLIN};
        int r = poll(&pfd, 1, 1000);

        if (r > 0 && (pfd.revents & POLLIN)) {
            uint64_t ip;
            while ((ip = perf_next_sample(&tc)) != 0)
                ckpt_take(&tc, 0);
        } else if (r < 0 && errno != EINTR) {
            die("poll");
        } else if (r == 0) {
            uint64_t cnt = 0;
            read(tc.perf_fd, &cnt, 8);
            fprintf(stderr, "dbg: timeout cnt=%llu head=%llu\n",
                    (unsigned long long)cnt,
                    (unsigned long long)tc.meta->data_head);
        }
        if (g_stop)
            break;              /* SIGTERM: 优雅退出进入离线 dump */

        /* tracee 是否还活着 (含僵尸: ptrace 目标被 SIGKILL 后变僵尸,
           kill(pid,0) 不报 ESRCH, 需 waitpid WNOHANG reap 检测) */
        {
            int wst;
            pid_t wr = waitpid(pid, &wst, WNOHANG);
            if (wr == pid)
                break;          /* 目标已退出 */
        }
        if (kill(pid, 0) < 0 && errno == ESRCH)
            break;
    }

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
    fprintf(stderr, "trace: done, %zu checkpoints (cow %zu/%zu, %zu agents) "
            "in %s\n", tc.ckpt_no, tc.cow_ok, tc.cow_ok + tc.cow_fail,
            tc.n_entries, tc.out);
    return 0;
}
