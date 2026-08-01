/*
 * 大内存测试目标: 128MB 匿名映射 (PRNG 填充 + 随机访问校验)。
 *
 * 冻结时快照 payload ≈ 130MB; 恢复后:
 *   - 映射内容完整 (最终 checksum 与基准一致)
 *   - 计算循环从冻结点继续, 输出/退出码与基准一致
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>

#define SIZE (128UL << 20)
#define MASK (SIZE - 1)

static uint64_t rng = 0x123456789abcdef0;
static uint8_t *mem;

static unsigned long checksum(void)
{
    unsigned long s = 0;
    for (unsigned long i = 0; i < SIZE; i++)
        s = (s + mem[i]) * 31;
    return s;
}

int main(void)
{
    mem = mmap(NULL, SIZE, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANON, -1, 0);
    if (mem == MAP_FAILED) {
        perror("mmap");
        return 2;
    }
    unsigned long r = 0x12345678;
    for (unsigned long i = 0; i < SIZE; i++) {
        r = (r * 1103515245 + 12345) & 0x7fffffff;
        mem[i] = (uint8_t)(r >> 16);
    }
    printf("FILLED\n");
    fflush(stdout);

    unsigned long x = 0;
    for (int c = 0; c < 8; c++) {
        printf("CKPT %d\n", c);
        fflush(stdout);
        for (unsigned long j = 0; j < 64000000UL; j++) {
            rng = rng * 6364136223846793005ULL + 1442695040888963407ULL;
            x += mem[(rng >> 36) & MASK];
        }
    }
    printf("DONE cksum=%lu x=%lu\n", checksum(), x);
    return (int)(x % 255);
}
