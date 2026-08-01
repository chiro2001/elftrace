/*
 * 堆边界测试目标。
 *
 * --sbrk 模式 (baremetal 测试): 冻结前 malloc(4MB), 冻结后 sbrk(64KB)。
 *   baremetal: brk mock 拒绝超出冻结时堆边界的移动, sbrk 返回 -1,
 *   程序走失败路径 "SBRK FAILED", rc=3 (预期)
 *
 * 默认模式 (real 测试): 冻结前 malloc(4MB), 冻结后 malloc(4MB)。
 *   real: 冻结后新分配走 glibc mmap fallback (brk 路径受切片进程
 *   内核 brk 与恢复的 glibc __curbrk 不一致限制), 分配成功 rc=0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    int use_sbrk = (argc > 1 && strcmp(argv[1], "--sbrk") == 0);

    if (!malloc(4UL << 20))
        return 2;
    printf("ALLOC1\n");
    fflush(stdout);

    volatile unsigned long x = 0;
    for (unsigned long i = 0; i < 2000000000UL; i++)
        x += i;                     /* 冻结点 */

    if (use_sbrk) {
        if (sbrk(64 * 1024) == (void *)-1) {
            printf("SBRK FAILED\n");
            fflush(stdout);
            return 3;
        }
        printf("SBRK OK\n");
        fflush(stdout);
    } else {
        if (!malloc(4UL << 20)) {
            printf("MALLOC FAILED\n");
            fflush(stdout);
            return 3;
        }
        printf("MALLOC OK\n");
        fflush(stdout);
    }
    return 0;
}
