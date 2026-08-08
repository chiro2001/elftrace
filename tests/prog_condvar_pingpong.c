/* 紧密乒乓: 生产者(主线程)与消费者通过 mutex+condvar 高频交接。
 *
 * 场景:
 *   - 主线程 = 生产者, 消费者为 pthread;
 *   - 有界环形队列 (容量 cap) + pthread_mutex + 两个 condvar;
 *   - 队列满时生产者 cond_wait(not_full), 空时消费者
 *     cond_wait(not_empty) — 同步点全部走 futex syscall;
 *   - 生产者每项 busy ~50k 条指令, 消费者每项 busy ~40k 条指令;
 *   - 消费者启动前 sleep(2), 制造"队列满 + 生产者阻塞"窗口。
 *
 * 切片意义: 验证 futex/condvar 协议经 syscall 边界 diff + 原子回放
 * (mutex 的 ldaxr/stlxr) 后, 主线程的 cond_wait 循环能观察到消费者
 * 推进 (队列腾出空间) 而继续, 不卡死。
 *
 * 用法: prog_condvar_pingpong [items] [cap] [prod_work] [cons_work]
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
} queue;

static void q_init(queue *q, unsigned cap)
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
        cs = busy(cs ^ (uint64_t)v, 40000);
        q->checksum = cs;
    }
    return NULL;
}

int main(int argc, char **argv)
{
    int items = argc > 1 ? atoi(argv[1]) : 20000;
    unsigned cap = argc > 2 ? (unsigned)atoi(argv[2]) : 8;
    int pw = argc > 3 ? atoi(argv[3]) : 50000;
    queue q;
    q_init(&q, cap);
    pthread_t th;
    if (pthread_create(&th, NULL, consumer, &q) != 0)
        return 2;
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
    pthread_join(th, NULL);
    printf("DONE items=%d checksum=%llu\n", items,
           (unsigned long long)(x ^ q.checksum));
    return 0;
}
