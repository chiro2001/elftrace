/* prog_imix.c — imix 验证用负载
 *
 * 轻量计算循环, 用于 DynamoRIO 指令流 (imix) 与 topdown 对比测试。
 * --stub: 打印 CHECKPOINT 5 后 SIGSTOP 自暂停 (freeze 采集已停止进程,
 *         冻结时刻精确, 无探测竞态)。冻结点后剩余 4 个检查点
 *         (iters=500000, -O0: ~700 万条/检查点 ≈ 2800 万条,
 *         instrace text trace ~550MB, 适合固定大小 trace 文件系统)。
 * 注: kill/getpid 在 baremetal mock 表内 (getpid→target_tid, kill→0),
 *     切片恢复后不再触发 SIGSTOP。
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    uint64_t iters = argc > 1 ? strtoull(argv[1], 0, 10) : 500000;
    int stub = argc > 2 && strcmp(argv[2], "--stub") == 0;
    uint64_t s = 1;
    for (int c = 0; c < 10; c++) {
        printf("CHECKPOINT %d\n", c);
        fflush(stdout);
        if (stub && c == 5)
            kill(getpid(), SIGSTOP);
        for (uint64_t i = 0; i < iters; i++) {
            s = s * 6364136223846793005ULL + 1442695040888963407ULL;
            if ((i & 0x3ff) == 0)
                s ^= (s >> 33);
        }
    }
    printf("DONE %llu\n", (unsigned long long)s);
    return 0;
}
