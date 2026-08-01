/*
 * 深递归/大栈测试目标: 12000 层 x 8KB 栈帧 ≈ 96MB 栈。
 *
 * - "MID" 在下降途中 depth=5000 处打印 (此时 rsp 已深约 40MB);
 * - "TOP" 在最大深度打印, 随后 busy loop 约 2 秒 (冻结位点 A);
 * - 冻结位点 B: MID 之后立即冻结 (切片需继续向栈底生长约 38MB)。
 *
 * 恢复后应展开全部栈帧, DONE 输出与退出码与基准一致。
 */
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>

#define FRAME 8192
#define DEPTH 12000
#define MID   5000

static unsigned long sink;

__attribute__((noinline)) static unsigned long deep(unsigned long x, int depth)
{
    unsigned char pad[FRAME];
    if (depth <= 0) {
        printf("TOP\n");
        fflush(stdout);
        for (unsigned long i = 0; i < 1500000000UL; i++)
            x += (i * 2654435761UL) & 0xff;
        return x;
    }
    if (depth == MID) {
        printf("MID\n");
        fflush(stdout);
    }
    for (unsigned long i = 0; i < 400000; i++)
        x += (i * 2654435761UL) & 0xff;
    memset(pad, depth & 0xff, sizeof(pad));
    sink += pad[0];
    return deep(x + 1, depth - 1);
}

int main(void)
{
    struct rlimit rl = { 512UL << 20, 512UL << 20 };
    setrlimit(RLIMIT_STACK, &rl);
    unsigned long x = deep(0, DEPTH);
    printf("DONE x=%lu sink=%lu\n", x, sink);
    return (int)(x % 255);
}
