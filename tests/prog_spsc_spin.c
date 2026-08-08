/* 复现: 多线程 aarch64 原子同步导致切片死循环。
 *
 * 场景:
 *   - 主线程 = 生产者, 消费者为 pthread;
 *   - 有界 SPSC 队列 (容量 cap), 满时生产者用原子 load 自旋等待;
 *   - 生产者每项 busy ~100k 条指令, 消费者每项 busy ~80k 条指令;
 *   - 消费者启动前 sleep(3), 制造"队列稳定满 + 生产者自旋"窗口。
 *
 * 复现步骤:
 *   1. 正常运行: 程序最终完成 (消费者 3s 后开始消费);
 *   2. 后台运行并等待 STABLE_FULL 输出;
 *   3. elftrace freeze <pid> -o snap.elftrace;
 *   4. elftrace build snap.elftrace -o slice.elf --mode real;
 *   5. timeout 10 ./slice.elf  → 应卡死 (生产者自旋, 消费者线程未恢复)。
 *
 * 用法: prog_spsc_spin [items] [cap] [prod_work] [cons_work] [delay_s]
 */
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_CAP 4096

typedef struct {
    int slots[MAX_CAP];
    _Atomic unsigned head;
    _Atomic unsigned tail;
    unsigned cap;
} spsc;

static volatile uint64_t sink;
static volatile unsigned long g_spins;

static uint64_t busy(uint64_t x, int n)
{
    for (int i = 0; i < n; i++)
        x = x * 6364136223846793005ULL + 1442695040888963407ULL;
    sink = x;
    return x;
}

static void spsc_init(spsc *q, unsigned cap)
{
    if (cap > MAX_CAP)
        cap = MAX_CAP;
    q->cap = cap;
    atomic_init(&q->head, 0);
    atomic_init(&q->tail, 0);
}

static void spsc_push(spsc *q, int v)
{
    for (;;) {
        unsigned t = atomic_load_explicit(&q->tail, memory_order_relaxed);
        unsigned h = atomic_load_explicit(&q->head, memory_order_acquire);
        if (t - h < q->cap) {
            q->slots[t % q->cap] = v;
            atomic_store_explicit(&q->tail, t + 1, memory_order_release);
            return;
        }
        g_spins++;
    }
}

static int spsc_pop(spsc *q, int *out)
{
    for (;;) {
        unsigned h = atomic_load_explicit(&q->head, memory_order_relaxed);
        unsigned t = atomic_load_explicit(&q->tail, memory_order_acquire);
        if (h != t) {
            *out = q->slots[h % q->cap];
            atomic_store_explicit(&q->head, h + 1, memory_order_release);
            return 1;
        }
    }
}

typedef struct {
    spsc *q;
    int items;
    int work;
    int delay_s;
    int rc;
} consumer_arg;

static void *consumer_main(void *arg)
{
    consumer_arg *ca = arg;
    sleep(ca->delay_s);
    uint64_t x = 0x1234;
    for (int i = 0; i < ca->items; i++) {
        int v;
        while (!spsc_pop(ca->q, &v)) {
        }
        if (v != i) {
            ca->rc = 1;
            return NULL;
        }
        x = busy(x, ca->work);
    }
    ca->rc = 0;
    return NULL;
}

int main(int argc, char **argv)
{
    int items = argc > 1 ? atoi(argv[1]) : 200000;
    unsigned cap = argc > 2 ? (unsigned)atoi(argv[2]) : 8;
    int prod_work = argc > 3 ? atoi(argv[3]) : 10000;   /* ~100k insn */
    int cons_work = argc > 4 ? atoi(argv[4]) : 8000;    /* ~80k insn */
    int delay_s = argc > 5 ? atoi(argv[5]) : 3;

    spsc q;
    spsc_init(&q, cap);

    printf("READY items=%d cap=%u prod=%d cons=%d delay=%d\n",
           items, cap, prod_work, cons_work, delay_s);
    fflush(stdout);

    consumer_arg ca = {.q = &q, .items = items,
                       .work = cons_work, .delay_s = delay_s, .rc = -1};
    pthread_t ct;
    pthread_create(&ct, NULL, consumer_main, &ca);

    uint64_t x = 0x5678;
    for (int i = 0; i < items; i++) {
        x = busy(x, prod_work);
        spsc_push(&q, i);
        if (i == (int)cap - 1) {
            printf("STABLE_FULL\n");
            fflush(stdout);
        }
    }
    pthread_join(ct, NULL);
    printf("DONE spins=%lu rc=%d\n", g_spins, ca.rc);
    return ca.rc != 0 ? 1 : 0;
}
