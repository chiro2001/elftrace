/* 预创建线程池: 主线程=生产者, N 个消费者线程在窗口开始前已创建。
 *
 * 场景:
 *   - 有界环形队列 (容量 cap) + pthread_mutex + 两个 condvar;
 *   - 队列满时生产者 cond_wait(not_full), 空时消费者
 *     cond_wait(not_empty) — 同步点全部走 futex syscall;
 *   - 生产者每项 busy ~50k 条指令, 每个消费者每项 busy ~40k 条指令;
 *   - 线程在 trace 前创建 (无 clone3), 验证"线程已稳定"窗口的
 *     futex/condvar 经边界 diff + 原子回放后主线程能继续 (支持层
 *     负载, 与 HTTP 每请求 clone 的限制层区分)。
 *
 * 用法: prog_threadpool [items] [cap] [nthreads] [prod_work] [cons_work]
 */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_CAP 4096
static volatile uint64_t sink;

static uint64_t busy(uint64_t x, int n)
{
    for (int i = 0; i < n; i++)
        x = x * 6364136223846793005ULL + 1442695040888963407ULL;
    sink = x;
    return x;
}

typedef struct {
    pthread_mutex_t m;
    pthread_cond_t not_full, not_empty;
    int slots[MAX_CAP];
    unsigned head, tail, count, cap;
    uint64_t checksum;
    int done;
    int cons_work;
} queue;

static void q_init(queue *q, unsigned cap, int cons_work)
{
    if (cap > MAX_CAP)
        cap = MAX_CAP;
    pthread_mutex_init(&q->m, NULL);
    pthread_cond_init(&q->not_full, NULL);
    pthread_cond_init(&q->not_empty, NULL);
    q->cap = cap;
    q->head = q->tail = q->count = 0;
    q->checksum = 0;
    q->done = 0;
    q->cons_work = cons_work;
}

static void *consumer(void *arg)
{
    queue *q = arg;
    uint64_t cs = 0;
    for (;;) {
        pthread_mutex_lock(&q->m);
        while (q->count == 0 && !q->done)
            pthread_cond_wait(&q->not_empty, &q->m);
        if (q->count == 0 && q->done) {
            pthread_mutex_unlock(&q->m);
            break;
        }
        int v = q->slots[q->head % q->cap];
        q->head++;
        q->count--;
        pthread_cond_signal(&q->not_full);
        pthread_mutex_unlock(&q->m);
        cs = busy(cs ^ (uint64_t)v, q->cons_work);
        q->checksum = cs;   /* 竞态可接受: 主线程 join 后才读 */
    }
    return NULL;
}

int main(int argc, char **argv)
{
    int items = argc > 1 ? atoi(argv[1]) : 20000;
    unsigned cap = argc > 2 ? (unsigned)atoi(argv[2]) : 16;
    int nthr = argc > 3 ? atoi(argv[3]) : 4;
    int pw = argc > 4 ? atoi(argv[4]) : 50000;
    int cw = argc > 5 ? atoi(argv[5]) : 40000;
    queue q;
    q_init(&q, cap, cw);
    pthread_t *th = calloc(nthr, sizeof(*th));
    if (!th)
        return 2;
    for (int i = 0; i < nthr; i++) {
        if (pthread_create(&th[i], NULL, consumer, &q) != 0)
            return 2;
    }
    sleep(2);                       /* 让消费者进入 cond_wait */
    uint64_t x = 1;
    for (int i = 0; i < items; i++) {
        pthread_mutex_lock(&q.m);
        while (q.count == q.cap)
            pthread_cond_wait(&q.not_full, &q.m);
        q.slots[q.tail % q.cap] = i;
        q.tail++;
        q.count++;
        pthread_cond_signal(&q.not_empty);
        pthread_mutex_unlock(&q.m);
        x = busy(x ^ (uint64_t)i, pw);
    }
    pthread_mutex_lock(&q.m);
    q.done = 1;
    pthread_cond_broadcast(&q.not_empty);
    pthread_mutex_unlock(&q.m);
    for (int i = 0; i < nthr; i++)
        pthread_join(th[i], NULL);
    free(th);
    printf("DONE items=%d checksum=%llu\n", items,
           (unsigned long long)(x ^ q.checksum));
    return 0;
}
