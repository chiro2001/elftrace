/* 无锁队列切片负载: 主线程=生产者 (MS queue CAS: ldaxr/stlxr),
 * 消费者线程在 trace 前创建。
 *
 * 与 prog_lockfree_queue.c 的区别: 生产者跑在主线程 (切片目标),
 * 消费者为预创建 pthread。主线程的 q_push 每项执行多次
 * ldaxr/stlxr CAS (无 LSE 时), 验证 strict 切片的 stlxr 强制成功
 * 跳板 (模拟器排他监视器语义无关化)。
 *
 * 用法: prog_lockfree_main [items] [prod_work] [cons_work]
 */
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

typedef struct node {
    int val;
    _Atomic(struct node *) next;
} node;

typedef struct {
    _Atomic(node *) head;
    _Atomic(node *) tail;
} queue;

static volatile uint64_t sink;

static uint64_t busy(uint64_t x, int n)
{
    for (int i = 0; i < n; i++)
        x = x * 6364136223846793005ULL + 1442695040888963407ULL;
    sink = x;
    return x;
}

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
                    memory_order_release, memory_order_relaxed))
                return;
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

typedef struct {
    queue *q;
    int items;
    int cons_work;
    int rc;
} cons_arg;

static void *consumer(void *arg)
{
    cons_arg *ca = arg;
    int got = 0;
    uint64_t cs = 0;
    for (;;) {
        int v;
        if (q_pop(ca->q, &v)) {
            if (v != got) {
                ca->rc = 1;
                return NULL;
            }
            got++;
            cs = busy(cs ^ (uint64_t)v, ca->cons_work);
            if (got == ca->items)
                break;
        }
    }
    ca->rc = 0;
    return NULL;
}

int main(int argc, char **argv)
{
    int items = argc > 1 ? atoi(argv[1]) : 20000;
    int pw = argc > 2 ? atoi(argv[2]) : 50000;
    int cw = argc > 3 ? atoi(argv[3]) : 40000;
    queue q;
    q_init(&q);
    cons_arg ca = {&q, items, cw, 0};
    pthread_t ct;
    if (pthread_create(&ct, NULL, consumer, &ca) != 0)
        return 2;
    sleep(2);                       /* 消费者先进入等待 */
    uint64_t x = 1;
    for (int i = 0; i < items; i++) {
        q_push(&q, i);
        x = busy(x ^ (uint64_t)i, pw);
    }
    pthread_join(ct, NULL);
    printf("DONE items=%d consumer_rc=%d checksum=%llu\n",
           items, ca.rc,
           (unsigned long long)(x ^ sink));
    return ca.rc;
}
