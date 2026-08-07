/* 真实场景负载: 对文件分块 (4MB) 计算 CRC32 (IEEE)。
 * syscall 稀疏 (大块 read), trace/strict 切片后 rc = crc%255
 * 必须与基准一致, 证明窗口内 read/dirty 回放正确。 */
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

static unsigned long crc32_table[256];

static void init_table(void)
{
    for (unsigned i = 0; i < 256; i++) {
        unsigned long c = i;
        for (int k = 0; k < 8; k++)
            c = (c & 1) ? 0xEDB88320UL ^ (c >> 1) : c >> 1;
        crc32_table[i] = c;
    }
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return 2;
    init_table();
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0)
        return 2;
    printf("READY\n");
    fflush(stdout);
    static unsigned char buf[4 << 20];
    unsigned long crc = 0xFFFFFFFFUL;
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        for (ssize_t i = 0; i < n; i++)
            crc = crc32_table[(crc ^ buf[i]) & 0xff] ^ (crc >> 8);
    }
    close(fd);
    crc ^= 0xFFFFFFFFUL;
    printf("CRC32 %08lx\n", crc);
    return (int)(crc % 255);
}
