/*
 * 实验参考: 信号处理测试目标 (安装 SIGUSR1 处理器)。
 * 用于调研切片进程的信号投递; sigactions 恢复尚未实现,
 * 切片中信号处理器为默认动作; 无对应自动化测试。
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
