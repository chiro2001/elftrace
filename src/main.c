/*
 * elftrace 主入口: 子命令分发
 *   freeze <pid>              采集进程状态到 .elftrace
 *   build <in.elftrace>       组装可恢复执行的 ELF
 *   dump <in.elftrace>        可读化查看中间文件
 */
#include <stdio.h>
#include <string.h>
#include "util.h"

int freeze_main(int argc, char **argv);
int build_main(int argc, char **argv);
int dump_main(const char *path);
int trace_main(int argc, char **argv);

static void usage(void)
{
    fprintf(stderr,
            "elftrace - process slicing via freeze & ELF reassembly\n"
            "\n"
            "usage:\n"
            "  elftrace freeze <pid> [-o out.elftrace]\n"
            "  elftrace build <in.elftrace> [-o out.elf] [--ipc N]\n"
            "  elftrace dump <in.elftrace>\n"
            "  elftrace trace <pid> [--every N] [--out DIR]\n"
            "\n"
            "freeze 采集一个冻结进程的内存/寄存器/fd 快照到中间文件;\n"
            "build 将中间文件组装成可执行 ELF: 运行时恢复内存与寄存器,\n"
            "从冻结点继续执行。--ipc N 使切片在运行 N 条指令后自动退出;\n"
            "--mode baremetal 生成裸机切片 (syscall 被 mock, 不依赖内核);\n"
            "trace 每隔 N 条指令采集一个检查点 (供区间切片)。\n");
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage();
        return 1;
    }
    if (strcmp(argv[1], "freeze") == 0)
        return freeze_main(argc - 1, argv + 1);
    if (strcmp(argv[1], "build") == 0)
        return build_main(argc - 1, argv + 1);
    if (strcmp(argv[1], "dump") == 0)
        return dump_main(argv[2]);
    if (strcmp(argv[1], "trace") == 0)
        return trace_main(argc - 1, argv + 1);
    usage();
    return 1;
}
