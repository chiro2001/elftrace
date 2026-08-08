/* 真实场景负载: 内存分配器压力 (malloc/free/realloc churn)。
 * 混合小对象与 mmap 级大块, 写入并校验模式, 模拟真实应用堆行为;
 * rc = 校验和 % 255。 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t x = 0x9e3779b97f4a7c15ULL;

static uint64_t rnd(void)
{
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    return x;
}

int main(void)
{
    printf("READY\n");
    fflush(stdout);
    uint64_t sum = 0;
    size_t peak = 0;
    for (int round = 0; round < 500; round++) {
        size_t sz = 64 + (size_t)(rnd() % 2048);
        if ((round % 64) == 0)
            sz = 1U << 20;          /* 触发 mmap 级分配 */
        unsigned char *p = malloc(sz);
        if (!p)
            return 3;
        for (size_t i = 0; i < sz; i++)
            p[i] = (unsigned char)(i * 31 + round);
        if (round % 8 == 0) {
            size_t nsz = sz + 64 + (size_t)(rnd() % 512);
            unsigned char *q = realloc(p, nsz);
            if (!q)
                return 3;
            p = q;
            sz = nsz;
            for (size_t i = 0; i < sz; i++)
                p[i] = (unsigned char)(i * 31 + round);
        }
        for (size_t i = 0; i < sz; i += 17)
            sum += p[i];
        if (sz > peak)
            peak = sz;
        free(p);
    }
    printf("ALLOC sum=%llu peak=%zu\n",
           (unsigned long long)sum, peak);
    return (int)(sum % 255);
}
