/* 真实场景负载: 目录遍历 + stat (opendir/readdir/stat/closedir)。
 * 对目录下所有非隐藏条目做 stat, 累计 st_size 与 d_ino;
 * rc = 总和 % 255。 */
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc < 2)
        return 2;
    DIR *d = opendir(argv[1]);
    if (!d)
        return 2;
    printf("READY\n");
    fflush(stdout);
    sleep(2);   /* 给外部 tracer 足够时间 attach (本负载 syscall 密集) */
    struct dirent *e;
    uint64_t sum = 0;
    unsigned count = 0;
    for (int pass = 0; pass < 4; pass++) {
        rewinddir(d);
        while ((e = readdir(d)) != NULL) {
            if (e->d_name[0] == '.')
                continue;
            char path[4096];
            if (snprintf(path, sizeof(path), "%s/%s",
                         argv[1], e->d_name) >= (int)sizeof(path))
                continue;
            struct stat st;
            if (stat(path, &st) < 0)
                continue;
            for (int k = 0; k < 262144; k++)
                sum += (uint64_t)st.st_size + (unsigned)k;
            sum += (uint64_t)st.st_size;
            sum += (uint64_t)e->d_ino;
            count++;
        }
    }
    closedir(d);
    printf("DIR count=%u sum=%llu\n", count,
           (unsigned long long)sum);
    return (int)(sum % 255);
}
