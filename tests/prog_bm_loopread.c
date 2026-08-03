/* baremetal 边界: 同一 pc 的 read 循环 + 每次 read 填一整页。
 *
 * 覆盖:
 *   - 回放表游标按顺序消费大量同 pc 记录 (单线程执行顺序 == 记录顺序)
 *   - 每条 read 记录携带 dirty 页 (读入的缓冲页), 回放把数据写回
 *   - fd 恢复 + 从冻结偏移继续读
 *
 * 断言: 从冻结 fd 偏移继续读满全部块, 校验和与 ref 一致 (rc 敏感)。
 * 用主程序内联 syscall (唯一 pc) 而不是 libc read wrapper: libc 的
 * syscall trampoline 与 nanosleep 共享同一 pc, 在途 syscall 被内核
 * 重启时记录序列与切片执行序列发散, 纯 pc 匹配会误配; 主程序内
 * syscall 唯一, 游标扫描可跳过无关记录收敛到正确记录。
 */
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define NCHUNK 120
#define CHUNK  4096

static inline ssize_t myread(int fd, void *buf, size_t len)
{
    long r;
    asm volatile("mov $0, %%rax\n\t"
                 "syscall\n\t"
                 "mov %%rax, %0"
                 : "=r"(r)
                 : "D"(fd), "S"(buf), "d"(len)
                 : "rcx", "r11", "memory");
    return (ssize_t)r;
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return 99;
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0)
        return 98;
    uint8_t *buf = malloc(NCHUNK * CHUNK);
    if (!buf)
        return 97;
    struct timespec ts = {.tv_sec = 0, .tv_nsec = 2000000}; /* 2ms */
    uint64_t acc = 0;
    for (int i = 0; i < NCHUNK; i++) {
        ssize_t n = myread(fd, buf + (size_t)i * CHUNK, CHUNK);
        if (n != CHUNK)
            return 96 - i;      /* 读不满 → 失败路径, rc 区分位置 */
        acc = acc * 31 + buf[(size_t)i * CHUNK] + buf[(size_t)i * CHUNK + 1];
        nanosleep(&ts, 0);
    }
    printf("acc=%llu\n", (unsigned long long)acc);
    return (int)(acc % 251);
}
