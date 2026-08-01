/*
 * 文件读写测试目标: 单线程, 打开文件 -> 写 -> 读回验证 -> 计算循环
 * (冻结点) -> 续写 -> 读回全量验证 -> 退出。
 *
 * 验证点:
 *   - 切片恢复后 fd 偏移正确 (续写 "BBB" 落在 "AAA" 之后)
 *   - 读回内容与基准一致 (AAABBB), 退出码一致
 */
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

static int verify_file(const char *path, const char *expect)
{
    char buf[64];
    int fd = open(path, O_RDONLY);
    ssize_t n;

    if (fd < 0)
        return 1;
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n != (ssize_t)strlen(expect) ||
        memcmp(buf, expect, n) != 0)
        return 1;
    return 0;
}

int main(int argc, char **argv)
{
    const char *path = argv[1];
    char rbuf[4] = {0};
    int fd;

    fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return 2;

    /* 1. 写 "AAA" */
    if (write(fd, "AAA", 3) != 3)
        return 3;

    /* 2. 读回验证 (lseek 到 0) */
    if (lseek(fd, 0, SEEK_SET) < 0 || read(fd, rbuf, 3) != 3 ||
        memcmp(rbuf, "AAA", 3) != 0)
        return 4;
    if (lseek(fd, 3, SEEK_SET) < 0)
        return 5;
    write(1, "STAGE1\n", 7);

    /* 3. 计算循环 (冻结点: 此处约 2 秒) */
    volatile unsigned long x = 0;
    for (unsigned long i = 0; i < 2000000000UL; i++)
        x += i;

    /* 4. 续写 "BBB" (应在偏移 3) */
    if (write(fd, "BBB", 3) != 3)
        return 6;
    write(1, "STAGE2\n", 7);

    /* 5. 全量读回验证 */
    if (verify_file(path, "AAABBB") != 0)
        return 7;
    close(fd);

    /* 6. 再验证一次 (模拟程序后续仍在使用该文件) */
    if (verify_file(path, "AAABBB") != 0)
        return 8;

    write(1, "DONE\n", 5);
    return 0;
}
