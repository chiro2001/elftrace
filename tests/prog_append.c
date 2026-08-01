/*
 * O_APPEND 语义测试目标: 以 O_APPEND 打开文件, 写 "AAA" 后冻结,
 * 恢复后 lseek(0) 再写 "BBB" —— 若 O_APPEND 标志被恢复, "BBB"
 * 应落在文件末尾 (AAABBB); 若标志丢失, "BBB" 会覆盖开头 (BBB)。
 */
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    int fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0644);
    if (fd < 0) {
        perror("open");
        return 2;
    }
    write(fd, "AAA", 3);
    write(1, "OPENED\n", 7);
    fsync(fd);

    volatile unsigned long x = 0;
    for (unsigned long i = 0; i < 1000000000UL; i++)
        x += i;                     /* 冻结点 */

    lseek(fd, 0, SEEK_SET);         /* 偏移回 0; O_APPEND 下写仍在末尾 */
    write(1, "SEEKED\n", 7);
    write(fd, "BBB", 3);
    close(fd);
    write(1, "CLOSED\n", 7);
    return 0;
}
