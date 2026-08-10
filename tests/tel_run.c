/* 遥测读取器: 以 ptrace 运行切片, 在 exit-stop 时读取遥测页并打印。
 * 用法: tel_run <slice.elf>
 * tel_abs 从 ELF 的 desc 0xF8 读 (blob 文件偏移 = 首个 PT_LOAD p_offset;
 * builder 在普通构建把 tel_abs 写进该槽)。 */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#define TEL_MAGIC 0x4D4C4554ULL

static uint64_t rd64(const uint8_t *p) {
    uint64_t v;
    memcpy(&v, p, 8);
    return v;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <slice.elf>\n", argv[0]);
        return 2;
    }
    const char *path = argv[1];
    FILE *f = fopen(path, "rb");
    if (!f) { perror("open"); return 2; }
    uint8_t eh[64];
    if (fread(eh, 1, sizeof(eh), f) != sizeof(eh)) {
        fprintf(stderr, "short ELF header\n");
        return 2;
    }
    uint64_t entry = rd64(eh + 0x18);
    uint64_t phoff = rd64(eh + 0x20);
    uint16_t phentsize, phnum;
    memcpy(&phentsize, eh + 0x36, 2);
    memcpy(&phnum, eh + 0x38, 2);
    uint64_t blob_off = 0;
    for (uint16_t i = 0; i < phnum; i++) {
        uint8_t ph[56];
        if (fseek(f, (long)(phoff + (uint64_t)i * phentsize), SEEK_SET) ||
            fread(ph, 1, 56, f) != 56)
            break;
        uint32_t type = (uint32_t)rd64(ph);
        if (type == 1) {            /* PT_LOAD */
            blob_off = rd64(ph + 8);
            break;
        }
    }
    uint64_t tel_abs = 0;
    if (blob_off) {
        uint8_t d[8];
        if (fseek(f, (long)(blob_off + 0xF8), SEEK_SET) == 0 &&
            fread(d, 1, 8, f) == 8)
            tel_abs = rd64(d);
    }
    fclose(f);
    if (!tel_abs) {
        fprintf(stderr, "tel_run: no telemetry address (probe build?)\n");
        return 3;
    }
    fprintf(stderr, "tel_run: entry=%#llx tel_abs=%#llx\n",
            (unsigned long long)entry, (unsigned long long)tel_abs);

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 2; }
    if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
            _exit(126);
        execl(path, path, (char *)0);
        _exit(127);
    }
    int st;
    if (waitpid(pid, &st, 0) < 0 || !WIFSTOPPED(st)) {
        fprintf(stderr, "tel_run: exec stop failed\n");
        return 2;
    }
    if (ptrace(PTRACE_SETOPTIONS, pid, 0,
               (void *)(long)PTRACE_O_TRACEEXIT) < 0) {
        perror("SETOPTIONS");
        return 2;
    }
    for (;;) {
        if (ptrace(PTRACE_CONT, pid, 0, 0) < 0) { perror("CONT"); break; }
        if (waitpid(pid, &st, 0) < 0) { perror("wait"); break; }
        if (WIFEXITED(st) || WIFSIGNALED(st))
            break;
        if (!WIFSTOPPED(st))
            continue;
        int sig = WSTOPSIG(st);
        int event = (st >> 16) & 0xff;
        if (event == PTRACE_EVENT_EXIT) {
            char mpath[64];
            snprintf(mpath, sizeof(mpath), "/proc/%d/mem", pid);
            int mfd = open(mpath, O_RDONLY);
            uint8_t buf[0x80];
            ssize_t n = -1;
            if (mfd >= 0) {
                n = pread(mfd, buf, sizeof(buf), (off_t)tel_abs);
                close(mfd);
            }
            if (n == (ssize_t)sizeof(buf) && rd64(buf) == TEL_MAGIC) {
                printf("telemetry: reason=%llu site=%#llx ord=%llu "
                       "limit=%llu caller=%#llx\n",
                       (unsigned long long)rd64(buf + 8),
                       (unsigned long long)rd64(buf + 16),
                       (unsigned long long)rd64(buf + 24),
                       (unsigned long long)rd64(buf + 32),
                       (unsigned long long)rd64(buf + 40));
            } else {
                printf("telemetry: no record (magic %#llx n=%zd)\n",
                       (unsigned long long)rd64(buf), n);
            }
        }
        if (sig && event == 0)
            continue;               /* 普通信号: 继续递送 */
    }
    return 0;
}
