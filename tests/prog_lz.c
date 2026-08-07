/* 真实场景负载: 简单 LZ/RLE 压缩器 (确定性)。
 * 分块读取输入, 游程编码 + 字面量, 输出压缩字节流;
 * rc = (压缩输出大小 + 输入 CRC) % 255, 切片后必须与基准一致。 */
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    if (argc < 3)
        return 2;
    int in = open(argv[1], O_RDONLY);
    int out = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (in < 0 || out < 0)
        return 2;
    printf("READY\n");
    fflush(stdout);
    static unsigned char buf[4 << 20];
    static unsigned char enc[4 << 20];
    unsigned long crc = 0xFFFFFFFFUL;
    size_t total_out = 0;
    ssize_t n;
    while ((n = read(in, buf, sizeof(buf))) > 0) {
        for (ssize_t i = 0; i < n; i++)
            crc = ((crc >> 8) ^ buf[i]) * 0x01000193UL;
        size_t e = 0, i = 0;
        while (i < (size_t)n) {
            size_t run = 1;
            while (i + run < (size_t)n && buf[i + run] == buf[i] &&
                   run < 255)
                run++;
            if (run >= 3) {
                enc[e++] = 0;       /* RLE 标记 */
                enc[e++] = (unsigned char)run;
                enc[e++] = buf[i];
                i += run;
            } else {
                enc[e++] = buf[i++];
            }
        }
        if (write(out, enc, e) != (ssize_t)e)
            return 3;
        total_out += e;
    }
    close(in);
    close(out);
    crc ^= 0xFFFFFFFFUL;
    printf("LZ out=%zu crc=%08lx\n", total_out, crc);
    return (int)((total_out + crc) % 255);
}
