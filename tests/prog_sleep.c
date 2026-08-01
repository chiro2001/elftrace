/*
 * 实验参考: 睡眠程序 (用于验证 freeze 对阻塞在 syscall 中的
 * 进程的检测与采集; 无对应自动化测试)。
 */
#include <stdio.h>
#include <unistd.h>
int main(void){ printf("SLEEPING\n"); fflush(stdout); for(;;) sleep(1); }
