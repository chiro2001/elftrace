/*
 * 冻结在 syscall 中 (nanosleep) 的测试目标。
 *
 * 场景: 进程阻塞在 sleep(2) (内核态); freeze 会检测到 in-flight syscall
 * 并告警; 切片从 syscall 指令重新执行该 sleep, 后续输出与基准一致。
 */
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    for (int i = 0; i < 5; i++) {
        printf("SLEEP %d\n", i);
        fflush(stdout);
        sleep(1);
        printf("WAKE %d\n", i);
        fflush(stdout);
    }
    printf("DONE\n");
    return 0;
}
