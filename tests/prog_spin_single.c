/* 单 load 自旋负载 (run-burn 原型验证)
 *
 * 主线程 (切片目标) 在 worker 置位前全程自旋:
 *   while (atomic_load_explicit(&gate, acquire) == 0) {}
 * 编译为单 load 循环 (ldar; cbz → site), 是 run-burn 整 run 烧录的
 * 适用形态 (q_push 的多 load 自旋循环不是, 见 round-19 评审)。
 *
 * 用法: prog_spin_single [delay_us] [work]
 *   delay_us: worker 置位前等待微秒数 (自旋时长, 默认 1000000)
 *   work: 置位后 busy 循环迭代数 (默认 3000000), 提供窗口后段
 */
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static _Atomic int gate;
static volatile uint64_t sink;

static void *worker(void *arg)
{
    long d = *(const long *)arg;
    usleep((useconds_t)d);
    atomic_store_explicit(&gate, 1, memory_order_release);
    return NULL;
}

int main(int argc, char **argv)
{
    long delay_us = argc > 1 ? atol(argv[1]) : 1000000;
    int work = argc > 2 ? atoi(argv[2]) : 3000000;
    pthread_t t;
    if (pthread_create(&t, NULL, worker, &delay_us) != 0)
        return 2;
    uint64_t x = 1;
    while (atomic_load_explicit(&gate, memory_order_acquire) == 0) { }
    for (int i = 0; i < work; i++)
        x = x * 6364136223846793005ULL + 1442695040888963407ULL +
            (uint64_t)i;
    sink = x;
    pthread_join(t, NULL);
    printf("DONE checksum=%llu\n", (unsigned long long)x);
    return 0;
}
