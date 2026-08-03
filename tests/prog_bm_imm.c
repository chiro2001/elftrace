/* baremetal 边界: 可执行段内 0f 05 字节序列的立即数不能被误替换。
 *
 * movabs $0x50f 编码为 48 b8 0f 05 00 ... — 曾经的模式扫描 (PF_X 段内
 * 直接找 0f 05 → cc 90) 会把这里的立即数误替换, 静默把值从 0x50f 变成
 * 0x90cc, 切片行为被悄悄改变。
 *
 * 回归断言: embed() 必须返回 0x50f (成功 rc = 15 = 0x50f & 0xff);
 * 被误替换时 embed() 返回 0x90cc → rc = 204。
 *
 * 循环内穿插 nanosleep: 检查点可能落在 syscall 中 (在途 syscall 记录 +
 * 同 pc 多次), 覆盖回放表游标顺序消费。
 */
#include <stdint.h>
#include <time.h>

static uint64_t embed(void)
{
    uint64_t v;
    asm volatile("movabs $0x050f, %%rax\n\tmovq %%rax, %0" : "=r"(v) :: "rax");
    return v;
}

int main(void)
{
    struct timespec ts = {.tv_sec = 0, .tv_nsec = 10000000};
    for (int i = 0; i < 100; i++) {
        for (int j = 0; j < 500000; j++) {
            if (embed() != 0x50fULL)
                return 204;         /* 被误替换 */
        }
        nanosleep(&ts, 0);
    }
    return 15;
}
