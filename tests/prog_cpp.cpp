/*
 * 进阶功能 6/7 测试目标: 相对复杂的 C++ 程序
 *
 * - 启动阶段使用 STL (vector/map/string) 完成全部堆分配 (brk)
 * - 之后是纯计算循环 + 周期 CHECKPOINT 打印 (write)
 * - 冻结点之后不再分配内存、不打开文件 (baremetal 可模拟)
 * - --bad-syscall: 冻结后调用一个不支持的 syscall (验证 mock 报错)
 * - 退出码 = 最终计算结果 % 255 (不依赖输出, baremetal 可对比)
 */
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <unistd.h>
#include <sys/syscall.h>

static volatile unsigned long counter;

static unsigned long hash_combine(unsigned long a, unsigned long b)
{
    a ^= b + 0x9e3779b9UL + (a << 6) + (a >> 2);
    return a;
}

int main(int argc, char **argv)
{
    bool bad_syscall = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--bad-syscall") == 0)
            bad_syscall = true;
    }

    /* 启动阶段: 堆分配 (冻结前完成) */
    std::vector<unsigned long> data;
    for (int i = 0; i < 256; i++)
        data.push_back((unsigned long)i * 2654435761UL);

    std::map<unsigned long, std::string> labels;
    for (int i = 0; i < 64; i++)
        labels[i] = "label-" + std::to_string(i);

    std::string payload;
    for (int i = 0; i < 1000; i++)
        payload += 'a' + (i % 26);

    unsigned long x = 0x12345678UL;
    for (int c = 0; c < 8; c++) {
        for (unsigned long j = 0; j < 150000000UL; j++) {
            x = hash_combine(x, data[j & 255]);
            x ^= labels.size() + payload.size();
        }
        counter = x;
        printf("CKPT %d x=%lu\n", c, x);
        fflush(stdout);
    }

    if (bad_syscall) {
        /* 调用一个不支持的 syscall (261 = sysinfo 之外的实验号) */
        syscall(261, 0);
    }

    printf("DONE x=%lu\n", x);
    return (int)(x % 255);
}
