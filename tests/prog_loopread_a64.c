/* aarch64 strict baremetal 回放测试负载:
 * 循环 read 同一 fd (每次 4KB), 期间 syscall 散布在整个 trace 窗口,
 * dirty 页每次变化; 结束后校验累计和并退出。
 * 用于验证 strict 模式 (ELF loader + 分支补偿) 的 syscall 回放表路径。 */
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char buf[4096];

int main(int argc, char **argv)
{
    int fd;
    if (argc < 2)
        return 2;
    fd = open(argv[1], O_RDONLY);
    if (fd < 0)
        return 2;
    unsigned long long sum = 0;
    int rounds = argc > 2 ? atoi(argv[2]) : 20000;
    for (int i = 0; i < rounds; i++) {
        int n = read(fd, buf, sizeof(buf));
        if (n <= 0) {
            lseek(fd, 0, SEEK_SET);
            n = read(fd, buf, sizeof(buf));
            if (n <= 0)
                break;
        }
        for (int j = 0; j < n; j++)
            sum += buf[j];
    }
    close(fd);
    printf("SUM %llu\n", sum);
    return (int)(sum % 255);
}
