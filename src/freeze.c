/*
 * elftrace freeze: 冻结指定进程并采集状态到 .elftrace
 *
 * 冻结语义: ptrace seize + interrupt + 采集 + SIGSTOP + detach,
 * 目标进程保持停止 (SIGCONT 可唤醒)。采集逻辑见 collect.c。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <signal.h>

#include "elftrace.h"
#include "collect.h"
#include "util.h"

int freeze_main(int argc, char **argv)
{
    const char *out = "snapshot.elftrace";
    pid_t pid = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            out = argv[++i];
        } else if (argv[i][0] >= '0' && argv[i][0] <= '9') {
            pid = atoi(argv[i]);
        } else {
            die("usage: elftrace freeze <pid> [-o out.elftrace]");
        }
    }
    if (pid == 0)
        die("usage: elftrace freeze <pid> [-o out.elftrace]");

    if (collect_freeze(pid) < 0)
        die("freeze %d", pid);

    struct collect_snapshot sn = {.pid = pid};
    collect_state(pid, &sn);
    collect_write(&sn, out);
    collect_detach_frozen(pid);
    fprintf(stderr, "freeze: %d detached and left frozen (SIGCONT to resume)\n",
            pid);
    return 0;
}
