/* aarch64 原子指令验证: 一生产者一消费者无锁队列 (MS queue, CAS)。
 *
 * 目的:
 *   1. 确认 postmarketOS aarch64 手机支持 ldaxr/stlxr (LL/SC);
 *   2. 反汇编观察编译器为无锁队列生成的原子指令。
 *
 * 编译:
 *   gcc -O2 -pthread -o prog_lockfree_queue tests/prog_lockfree_queue.c
 * 反汇编:
 *   objdump -d prog_lockfree_queue | grep -E "ldaxr|stlxr|ldxr|stxr"
 *
 * postmarketOS 真机 (Cortex-A53, CPU part 0xd03) 实测:
 *   - ldaxr/stlxr 直接内联执行 OK;
 *   - SPSC 队列 100 万条 OK;
 *   - /proc/cpuinfo 无 LSE (atomics) 特性, __aarch64_have_lse_atomics=0,
 *     运行路径走 LL/SC 回退 (ldxr/stlxr / ldaxr/stxr), 不走 casa/casl。
 */
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct node {
    int val;
    _Atomic(struct node *) next;
} node;

typedef struct {
    _Atomic(node *) head;
    _Atomic(node *) tail;
} queue;

static void q_init(queue *q)
{
    node *dummy = calloc(1, sizeof(*dummy));
    if (!dummy)
        exit(2);
    atomic_init(&dummy->next, NULL);
    atomic_init(&q->head, dummy);
    atomic_init(&q->tail, dummy);
}

static void q_push(queue *q, int v)
{
    node *n = malloc(sizeof(*n));
    if (!n)
        exit(2);
    n->val = v;
    atomic_init(&n->next, NULL);
    for (;;) {
        node *t = atomic_load_explicit(&q->tail, memory_order_acquire);
        node *next = atomic_load_explicit(&t->next, memory_order_acquire);
        if (t != atomic_load_explicit(&q->tail, memory_order_acquire))
            continue;
        if (next == NULL) {
            node *expected = NULL;
            if (atomic_compare_exchange_strong_explicit(
                    &t->next, &expected, n,
                    memory_order_release, memory_order_relaxed)) {
                atomic_store_explicit(&q->tail, n, memory_order_release);
                return;
            }
        } else {
            node *expected = t;
            atomic_compare_exchange_strong_explicit(
                &q->tail, &expected, next,
                memory_order_release, memory_order_relaxed);
        }
    }
}

static int q_pop(queue *q, int *out)
{
    for (;;) {
        node *h = atomic_load_explicit(&q->head, memory_order_acquire);
        node *t = atomic_load_explicit(&q->tail, memory_order_acquire);
        node *next = atomic_load_explicit(&h->next, memory_order_acquire);
        if (h != atomic_load_explicit(&q->head, memory_order_acquire))
            continue;
        if (h == t) {
            if (next == NULL)
                return 0;
            node *expected = t;
            atomic_compare_exchange_strong_explicit(
                &q->tail, &expected, next,
                memory_order_release, memory_order_relaxed);
        } else {
            node *expected = h;
            if (atomic_compare_exchange_strong_explicit(
                    &q->head, &expected, next,
                    memory_order_acquire, memory_order_relaxed)) {
                *out = next->val;
                free(h);
                return 1;
            }
        }
    }
}

/* 直接执行 ldaxr/stlxr, 证明 CPU/内核支持 LL/SC 原子指令。 */
static int test_ldaxr_stlxr(void)
{
    static volatile uint64_t v = 0;
    uint64_t old;
    uint32_t status;
    v = 0;
    asm volatile(
        "1: ldaxr %0, [%2]\n"
        "   stlxr %w1, %3, [%2]\n"
        "   cbnz %w1, 1b\n"
        : "=&r"(old), "=&r"(status)
        : "r"(&v), "r"(42ULL)
        : "memory");
    return v == 42 ? 0 : 1;
}

#define N 1000000

static queue g_q;
static int g_producer_rc, g_consumer_rc;

static void *producer(void *arg)
{
    (void)arg;
    for (int i = 0; i < N; i++)
        q_push(&g_q, i);
    return NULL;
}

static void *consumer(void *arg)
{
    (void)arg;
    int got = 0;
    for (;;) {
        int v;
        if (q_pop(&g_q, &v)) {
            if (v != got) {
                g_consumer_rc = 1;
                return NULL;
            }
            got++;
            if (got == N)
                break;
        }
    }
    g_consumer_rc = 0;
    return NULL;
}

int main(void)
{
    if (test_ldaxr_stlxr() != 0) {
        printf("LDAXR/STLXR FAIL\n");
        return 1;
    }
    printf("LDAXR/STLXR OK\n");

    q_init(&g_q);
    pthread_t pt, ct;
    pthread_create(&pt, NULL, producer, NULL);
    pthread_create(&ct, NULL, consumer, NULL);
    pthread_join(pt, NULL);
    pthread_join(ct, NULL);
    if (g_consumer_rc != 0) {
        printf("QUEUE MISMATCH\n");
        return 1;
    }
    printf("SPSC queue OK (%d items)\n", N);
    return 0;
}
