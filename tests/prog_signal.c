/*
 * 信号处理测试目标: 安装 SIGUSR1 处理器, 循环等待信号。
 * 用于验证切片进程的信号投递与帧构建是否正常。
 */
#include <stdio.h>
#include <signal.h>
#include <unistd.h>

static volatile int got;

static void handler(int sig)
{
    got++;
    write(1, "HANDLED\n", 8);
}

int main(void)
{
    signal(SIGUSR1, handler);
    write(1, "READY\n", 6);
    volatile unsigned long x = 0;
    for (;;) {
        for (unsigned long i = 0; i < 300000000UL; i++)
            x += i;
        if (got) {
            printf("GOT %d\n", got);
            return 0;
        }
    }
}
