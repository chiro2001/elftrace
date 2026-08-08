/* 补偿指令比例指标负载: 纯计算双循环, 总量约 600M 条指令。
 * 供 test_comp_ratio.sh 用 trace 采集中间 40M 窗口, 再校准 strict
 * 切片的循环退出计数, 使实际执行指令数 ≈ 预期窗口指令数。 */
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

static volatile uint64_t sink;

int main(void)
{
    uint64_t x = 0x12345678;
    printf("READY\n");
    fflush(stdout);
    sleep(2);   /* 给外部 tracer 足够时间 attach */
    for (int c = 0; c < 20; c++) {
        for (uint64_t j = 0; j < 2000000UL; j++) {
            x = x * 31 + 1;
            sink = x;
        }
        printf("CKPT %d\n", c);
        fflush(stdout);
    }
    printf("DONE %llu\n", (unsigned long long)x);
    return (int)(x % 255);
}
