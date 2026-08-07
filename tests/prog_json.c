/* 真实场景负载: 简单 JSON 数字解析 (状态机, 跳过字符串/对象/数组,
 * 累加所有数值), 分块读取。rc = sum%255, 切片后必须与基准一致。 */
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    if (argc < 2)
        return 2;
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0)
        return 2;
    printf("READY\n");
    fflush(stdout);
    static unsigned char buf[4 << 20];
    unsigned long long sum = 0;
    int in_str = 0, in_num = 0;
    unsigned long long num = 0;
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        for (ssize_t i = 0; i < n; i++) {
            unsigned char c = buf[i];
            if (in_str) {
                if (c == '"')
                    in_str = 0;
                continue;
            }
            if (c == '"') {
                in_str = 1;
                continue;
            }
            if (c >= '0' && c <= '9') {
                num = num * 10 + (c - '0');
                in_num = 1;
            } else if (in_num) {
                sum += num;
                num = 0;
                in_num = 0;
            }
        }
    }
    close(fd);
    printf("JSON sum %llu\n", sum);
    return (int)(sum % 255);
}
