/* 原子 acquire 语义边界 (已知限制) 固化测试。
 *
 * 场景: 辅助线程先写 payload ("NEW") 再 release 递增 seq; 主线程
 * (被切片线程) 用 acquire 自旋读 seq, 读到 >=1 后读取 payload。
 *
 * 切片行为: 回放跳板按录制序号返回 seq=1, 但辅助线程写入的 payload
 * 在切片里是冻结值 ("OLD") —— acquire 值与它保护的数据脱钩, 程序
 * 不死锁但会读到陈旧数据。退出码: data==NEW → 7, 否则 0。
 * test_atomic_boundary.sh 断言 ref rc=7 而切片 rc=0, 固化这个边界
 * (等价于 xfail: 期望的行为是"已知错误")。
 */
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct sh {
    _Atomic unsigned seq;
    char data[64];
};

static void *writer_main(void *arg)
{
    struct sh *s = arg;
    usleep(2000000);            /* 让 trace 在写 payload 之前冻结 */
    memcpy(s->data, "NEW", 4);
    atomic_store_explicit(&s->seq, 1, memory_order_release);
    printf("WROTE\n");
    fflush(stdout);
    return NULL;
}

int main(void)
{
    static struct sh s;
    memcpy(s.data, "OLD", 4);
    atomic_init(&s.seq, 0);
    pthread_t wt;
    pthread_create(&wt, NULL, writer_main, &s);

    printf("READY\n");
    fflush(stdout);
    volatile uint64_t acc = 0;
    for (;;) {
        unsigned v = atomic_load_explicit(&s.seq, memory_order_acquire);
        if (v >= 1)
            break;
        /* 忙循环: 让采集检查点落在普通指令上 (自旋太短时检查点全在
           PC 相对指令/原子站点, 退出点不可计数) */
        for (int j = 0; j < 2000; j++)
            acc += (uint64_t)j;
    }
    if (acc == 0xdeadbeef)
        printf("unreachable\n");
    printf("DATA=%s\n", s.data);
    return strcmp(s.data, "NEW") == 0 ? 7 : 0;
}
