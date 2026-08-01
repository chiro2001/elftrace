/*
 * 基础测试目标: 单线程, 无文件, 纯计算循环 + 周期打印。
 * 运行约 10 秒, 每个 check 点打印一行; 冻结后再恢复应继续后续输出。
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static volatile unsigned long counter;

int main(int argc, char **argv)
{
    unsigned long x = 0;

    if (argc > 1)
        x = strtoul(argv[1], NULL, 0);
    for (int i = 0; i < 10; i++) {
        for (unsigned long j = 0; j < 300000000UL; j++) {
            x += 1;
            counter = x;
        }
        printf("CHECKPOINT %d x=%lu\n", i, counter);
        fflush(stdout);
    }
    printf("DONE x=%lu\n", counter);
    return (int)(counter % 255);
}
