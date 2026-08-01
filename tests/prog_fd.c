/*
 * fd 语义测试目标: 打开文件, 写入, 冻结后继续写入并验证文件偏移/内容。
 *
 * 流程:
 *   1. 打开 out.txt (w+), 写入 "AAA"
 *   2. 忙循环 (冻结点, 期间 fd 1 与 out.txt fd 保持打开)
 *   3. 写入 "BBB", 关闭, 退出
 * 切片进程应通过重开的 fd 在原文件偏移处继续写 "BBB", 文件内容为 "AAABBB"。
 */
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    int fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open");
        return 2;
    }
    write(fd, "AAA", 3);
    write(1, "OPENED\n", 7);
    fsync(fd);

    volatile unsigned long x = 0;
    for (unsigned long i = 0; i < 2000000000UL; i++)
        x += i;                     /* 冻结点: 此处约 2 秒 */

    write(fd, "BBB", 3);
    close(fd);
    write(1, "CLOSED\n", 7);
    return 0;
}
