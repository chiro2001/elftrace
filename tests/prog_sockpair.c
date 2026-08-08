/* 真实场景负载: AF_UNIX socketpair 数据报 IPC。
 * 发送 64 个 1KB 数据报并全部读回, 校验内容; 覆盖
 * socket/sendto/recvfrom/close 等 syscall 在 strict 切片中的回放。 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void)
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0)
        return 2;
    printf("READY\n");
    fflush(stdout);
    static unsigned char msg[1024];
    static unsigned char rcv[1024];
    uint64_t sum = 0;
    for (int i = 0; i < 64; i++) {
        for (size_t j = 0; j < sizeof(msg); j++)
            msg[j] = (unsigned char)(i * 31 + j * 7 + 1);
        ssize_t w = send(sv[0], msg, sizeof(msg), 0);
        if (w != (ssize_t)sizeof(msg))
            return 3;
        ssize_t r = recv(sv[1], rcv, sizeof(rcv), 0);
        if (r != (ssize_t)sizeof(rcv))
            return 3;
        for (size_t j = 0; j < sizeof(rcv); j++) {
            if (rcv[j] != (unsigned char)(i * 31 + j * 7 + 1))
                return 4;
            for (int k = 0; k < 2048; k++)
                sum += rcv[j] + (unsigned)k;
        }
    }
    close(sv[0]);
    close(sv[1]);
    printf("SOCK sum=%llu\n", (unsigned long long)sum);
    return (int)(sum % 255);
}
