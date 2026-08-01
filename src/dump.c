/*
 * elftrace dump: .elftrace 可读化查看器 (维护/调试中间格式)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "elftrace.h"
#include "util.h"

static const char *arch_name(uint32_t arch)
{
    switch (arch) {
    case ELFTRACE_ARCH_X86_64:
        return "x86_64";
    case ELFTRACE_ARCH_AARCH64:
        return "aarch64";
    default:
        return "unknown";
    }
}

static const char *str_at(const uint8_t *f, const elftrace_hdr *h, uint64_t off)
{
    static char buf[512];
    uint64_t i, j;

    if (off >= h->strings_size)
        return "<?>";
    j = 0;
    for (i = off; i < h->strings_size && j < sizeof(buf) - 1; i++) {
        buf[j++] = f[h->strings_off + i];
        if (buf[j - 1] == 0)
            break;
    }
    buf[j] = 0;
    return buf;
}

int dump_main(const char *path)
{
    int fd;
    struct stat st;
    uint8_t *f;
    elftrace_hdr h;

    fd = open(path, O_RDONLY);
    if (fd < 0)
        die("cannot open %s", path);
    if (fstat(fd, &st) < 0)
        die("fstat %s", path);
    f = xmalloc(st.st_size);
    if (read(fd, f, st.st_size) != st.st_size)
        die("short read %s", path);
    close(fd);

    memcpy(&h, f, sizeof(h));
    if (h.magic != ELFTRACE_MAGIC)
        die("%s: not an elftrace file", path);
    if (h.version != ELFTRACE_VERSION)
        die("%s: unsupported version %u", path, h.version);

    printf("elftrace file: %s\n", path);
    printf("  version      %u\n", h.version);
    printf("  arch         %s (%u)\n", arch_name(h.arch), h.arch);
    printf("  flags        %#x\n", h.flags);
    printf("  task_tid     %llu\n", (unsigned long long)h.task_tid);
    printf("  entry_pc     %#llx\n", (unsigned long long)h.entry_pc);
    printf("  regs         off=%#llx size=%llu\n",
           (unsigned long long)h.regs_off, (unsigned long long)h.regs_size);
    printf("  fpu          off=%#llx size=%llu\n",
           (unsigned long long)h.fpu_off, (unsigned long long)h.fpu_size);
    printf("  sigmask      off=%#llx\n", (unsigned long long)h.sigmask_off);
    printf("  sigacts      off=%#llx (%s)\n", (unsigned long long)h.sigacts_off,
           h.sigacts_off ? "present" : "none");
    printf("  exe          %s\n", h.exe_off ? str_at(f, &h, h.exe_off) : "<?>");
    printf("  exe_bias     %#llx\n", (unsigned long long)h.exe_bias);
    printf("  segments     %llu\n", (unsigned long long)h.nsegs);
    printf("  fds          %llu\n", (unsigned long long)h.nfds);
    printf("  aux          %llu\n", (unsigned long long)h.aux_n);
    printf("  strings      off=%#llx size=%llu\n",
           (unsigned long long)h.strings_off, (unsigned long long)h.strings_size);
    printf("  payload      off=%#llx size=%llu\n",
           (unsigned long long)h.payload_off, (unsigned long long)h.payload_size);
    printf("\n");

    printf("== segments ==\n");
    printf("  %-16s %-12s %-12s %-10s %-16s %s\n", "vaddr", "filesz", "memsz",
           "flags", "payload_off", "name");
    for (uint64_t i = 0; i < h.nsegs; i++) {
        elftrace_seg s;
        memcpy(&s, f + h.segs_off + i * sizeof(s), sizeof(s));
        char fl[8] = "---";
        if (s.flags & ET_SEG_R) fl[0] = 'r';
        if (s.flags & ET_SEG_W) fl[1] = 'w';
        if (s.flags & ET_SEG_X) fl[2] = 'x';
        printf("  %#16llx %-12llu %-12llu %-10s %#16llx %s\n",
               (unsigned long long)s.vaddr, (unsigned long long)s.filesz,
               (unsigned long long)s.memsz, fl,
               (unsigned long long)s.payload_off,
               s.name_off ? str_at(f, &h, s.name_off) : "");
    }
    printf("\n");

    printf("== fds ==\n");
    for (uint64_t i = 0; i < h.nfds; i++) {
        elftrace_fd s;
        memcpy(&s, f + h.fds_off + i * sizeof(s), sizeof(s));
        printf("  fd %llu  flags=%#llo mode=%#llo pos=%llu  %s\n",
               (unsigned long long)s.fd, (unsigned long long)s.flags,
               (unsigned long long)s.mode, (unsigned long long)s.pos,
               s.path_len ? str_at(f, &h, s.path_off) : "(unsupported)");
    }
    printf("\n");

    if (h.aux_n) {
        printf("== aux (debug sections from exe) ==\n");
        for (uint64_t i = 0; i < h.aux_n; i++) {
            elftrace_aux s;
            memcpy(&s, f + h.aux_off + i * sizeof(s), sizeof(s));
            printf("  %-24s addr=%#llx size=%-9llu type=%#llx flags=%#llx "
                   "align=%llu entsize=%llu link=%llu info=%llu\n",
                   str_at(f, &h, s.name_off), (unsigned long long)s.addr,
                   (unsigned long long)s.size, (unsigned long long)s.type,
                   (unsigned long long)s.flags, (unsigned long long)s.align,
                   (unsigned long long)s.entsize, (unsigned long long)s.link,
                   (unsigned long long)s.info);
        }
        printf("\n");
    }

    if (h.sigacts_off) {
        printf("== sigactions ==\n");
        for (int i = 1; i < 64; i++) {
            elftrace_sigact s;
            memcpy(&s, f + h.sigacts_off + i * sizeof(s), sizeof(s));
            if (s.handler)
                printf("  sig %2d handler=%#llx flags=%#llx\n", i,
                       (unsigned long long)s.handler,
                       (unsigned long long)s.flags);
        }
    }

    printf("== registers ==\n");
    if (h.arch == ELFTRACE_ARCH_X86_64 && h.regs_size >= 27 * 8) {
        const uint64_t *r = (const uint64_t *)(f + h.regs_off);
        printf("  rax=%#llx rbx=%#llx rcx=%#llx rdx=%#llx\n"
               "  rsi=%#llx rdi=%#llx rbp=%#llx rsp=%#llx\n"
               "  r8 =%#llx r9 =%#llx r10=%#llx r11=%#llx\n"
               "  r12=%#llx r13=%#llx r14=%#llx r15=%#llx\n"
               "  rip=%#llx eflags=%#llx\n"
               "  fs_base=%#llx gs_base=%#llx\n",
               (unsigned long long)r[10], (unsigned long long)r[5],
               (unsigned long long)r[11], (unsigned long long)r[12],
               (unsigned long long)r[13], (unsigned long long)r[14],
               (unsigned long long)r[4], (unsigned long long)r[19],
               (unsigned long long)r[9], (unsigned long long)r[8],
               (unsigned long long)r[7], (unsigned long long)r[6],
               (unsigned long long)r[3], (unsigned long long)r[2],
               (unsigned long long)r[1], (unsigned long long)r[0],
               (unsigned long long)r[16], (unsigned long long)r[18],
               (unsigned long long)r[21], (unsigned long long)r[22]);
    }

    free(f);
    return 0;
}
