/* 真实负载: 200 万整数快速排序 (递归 qsort + 堆分配 + 校验和)。
 * 确定性: 固定种子 LCG 生成数据; 输出 READY/DONE 供 trace/断言。 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static uint64_t rng = 0x123456789abcdef0ULL;
static uint64_t next_rand(void)
{
    rng = rng * 6364136223846793005ULL + 1442695040888963407ULL;
    return rng;
}

static int cmp_int(const void *a, const void *b)
{
    int x = *(const int *)a, y = *(const int *)b;
    return (x > y) - (x < y);
}

int main(void)
{
    enum { N = 2000000 };
    int *a = malloc(sizeof(int) * N);
    if (!a)
        return 2;
    for (int i = 0; i < N; i++)
        a[i] = (int)(next_rand() & 0x7fffffff);
    printf("READY\n");
    fflush(stdout);

    qsort(a, N, sizeof(int), cmp_int);

    uint64_t sum = 0;
    for (int i = 0; i < N; i++) {
        if (i && a[i] < a[i - 1]) {
            printf("UNSORTED\n");
            return 3;
        }
        sum = sum * 31 + (unsigned)a[i];
    }
    printf("DONE sum=%llu\n", (unsigned long long)sum);
    free(a);
    return 0;
}
