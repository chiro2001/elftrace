/*
 * 多线程测试目标: 主线程 + 无限 worker 线程 (独立计算, 不参与主线程结果)。
 *
 * elftrace 只冻结/恢复主线程 (多线程语义未定义)。本测试验证:
 *   - freeze/build/运行切片不崩溃 (至少行为可预期)
 *   - 主线程输出与退出码与基准一致 (worker 副作用丢失可接受)
 */
#include <stdio.h>
#include <pthread.h>

static void *worker(void *arg)
{
    volatile unsigned long w = 0;
    for (;;)
        for (unsigned long i = 0; i < 100000000UL; i++)
            w += i;
    return NULL;
}

int main(void)
{
    pthread_t t;
    if (pthread_create(&t, NULL, worker, NULL) != 0)
        return 2;

    unsigned long x = 0;
    for (int i = 0; i < 10; i++) {
        for (unsigned long j = 0; j < 300000000UL; j++)
            x += 1;
        printf("CHECKPOINT %d x=%lu\n", i, x);
        fflush(stdout);
    }
    printf("DONE x=%lu\n", x);
    return (int)(x % 255);
}
