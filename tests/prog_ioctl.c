/* aarch64 strict baremetal ioctl 设备操作负载:
 * 打开字符设备 (/dev/null, 可指定), 循环内反复 ioctl (FIONREAD),
 * 中间夹计算负载, 证明设备操作也能被 trace+严格切片精确回放
 * (窗口内 ioctl 全部走回放表, 不产生真实 syscall)。 */
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>

int main(int argc, char **argv)
{
    int rounds = argc > 1 ? atoi(argv[1]) : 200;
    const char *dev = argc > 2 ? argv[2] : "/dev/null";
    int every = argc > 3 ? atoi(argv[3]) : 10;  /* 每 N 轮一次 ioctl */
    int fd = open(dev, O_RDWR);
    if (fd < 0)
        return 2;
    unsigned long long sum = 0;
    int ioctl_ok = 0, ioctl_eno = 0;
    for (int i = 0; i < rounds; i++) {
        for (int j = 0; j < 100000; j++)
            sum += (unsigned)j;
        if (i % every == 0) {
            int n = 0;
            int r = ioctl(fd, FIONREAD, &n);
            if (r == 0)
                ioctl_ok++;
            else if (errno == ENOTTY)
                ioctl_eno++;
            else
                return 3;
        }
    }
    printf("SUM %llu IOCTL_OK %d ENOTTY %d\n", sum, ioctl_ok, ioctl_eno);
    close(fd);
    return (int)(sum % 255);
}
