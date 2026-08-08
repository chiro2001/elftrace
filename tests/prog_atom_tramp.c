/* 原子记录跳板独立自测 (无 ptrace):
 * 1. mmap 事件缓冲 + 就近 RWX 记录页;
 * 2. 生成记录跳板并 patch 到自写自旋循环的 ldar 站点;
 * 3. 辅助线程稍后置 flag=1, 验证自旋退出且事件正确。 */
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "atomic_a64.h"

extern void spin_site_label(uint64_t);
__asm__(".global spin_site_label\n"
        ".type spin_site_label, %function\n"
        "spin_site_label:\n"
        "spin_site:\n"
        "    ldar w1, [x0]\n"
        "    cbz w1, spin_site\n"
        "    ret\n");

static volatile uint64_t flag;
static inline uint64_t get_tpidr(void) { uint64_t v; asm volatile("mrs %0, tpidr_el0" : "=r"(v)); return v; }
static void *setter(void *arg)
{
    (void)arg;
    usleep(200000);
    __atomic_store_n(&flag, 1, __ATOMIC_RELEASE);
    return NULL;
}

static uint64_t find_gap_near(uint64_t near, uint64_t size)
{
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512];
    struct { uint64_t s, e; } m[256];
    int n = 0;
    while (fgets(line, sizeof line, f) && n < 256) {
        unsigned long long s, e;
        if (sscanf(line, "%llx-%llx", &s, &e) == 2) {
            m[n].s = s; m[n].e = e; n++;
        }
    }
    fclose(f);
    uint64_t cur = (near + 0xfff) & ~0xfffULL;
    uint64_t lim = near + (128UL << 20);
    while (cur + size <= lim) {
        int busy = 0;
        for (int i = 0; i < n; i++) {
            if (cur < m[i].e && cur + size > m[i].s) {
                cur = (m[i].e + 0xfff) & ~0xfffULL;
                busy = 1;
                break;
            }
        }
        if (!busy)
            return cur;
    }
    return 0;
}

static uint64_t text_start(void)
{
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512];
    uint64_t best = 0;
    while (fgets(line, sizeof line, f)) {
        unsigned long long s;
        char perms[8], name[256] = "";
        if (sscanf(line, "%llx-%*llx %7s %*s %*s %*s %255[^\n]", &s,
                   perms, name) < 3)
            continue;
        if (perms[0] == 'r' && perms[2] == 'x' && name[0] &&
            !strstr(name, "vdso") && !strstr(name, "vvar")) {
            if (!best || s < best)
                best = s;
        }
    }
    fclose(f);
    return best;
}

int main(void)
{
    uint64_t buf_size = 64UL << 20;
    uint64_t buf = (uint64_t)(uintptr_t)mmap(NULL, buf_size,
                                             PROT_READ | PROT_WRITE,
                                             MAP_PRIVATE | MAP_ANONYMOUS,
                                             -1, 0);
    if (buf == (uint64_t)-1) { perror("mmap buf"); return 1; }
    fprintf(stderr, "buf=%#llx\n", (unsigned long long)buf);
    /* 缓冲区头 */
    uint64_t n_sites = 1;
    uint64_t state_off = A64_ATB_HDR_SIZE;
    uint64_t events_off = state_off + n_sites * A64_ATB_STATE_SIZE;
    uint64_t hdr[A64_ATB_HDR_SIZE / 8];
    memset(hdr, 0, sizeof(hdr));
    hdr[0] = A64_ATB_MAGIC;
    hdr[1] = A64_ATB_VERSION;
    hdr[2] = n_sites;
    hdr[3] = state_off;
    hdr[4] = events_off;
    hdr[5] = buf + events_off;          /* event_ptr */
    hdr[6] = buf + buf_size;            /* events_end */
    hdr[7] = 0;                         /* overflow */
    hdr[8] = buf_size;
    memcpy((void *)(uintptr_t)buf, hdr, sizeof(hdr));

    /* 记录页: 就近代码段 */
    uint64_t ts = text_start();
    uint64_t page = find_gap_near(ts, 0x1000);
    if (!page) { fprintf(stderr, "no gap\n"); return 1; }
    void *pm = mmap((void *)(uintptr_t)page, 0x1000,
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (pm == MAP_FAILED) { perror("mmap page"); return 1; }
    fprintf(stderr, "page=%#llx ts=%#llx\n", (unsigned long long)page, (unsigned long long)ts);

    /* 生成记录跳板 (站点: ldar w1,[x0] = 88dffc01) */
    uint8_t blk[A64_ATOM_BLOCK_SIZE];
    size_t bl = a64_atomic_record_block(blk, page, 0x88DFFC01U,
                                        get_tpidr(),
                                        0,
                                        buf + A64_ATB_HDR_SIZE,
                                        buf + A64_ATB_OFF_EVENT_PTR,
                                        buf + A64_ATB_OFF_EVENTS_END,
                                        buf + A64_ATB_OFF_OVERFLOW,
                                        (uint64_t)(uintptr_t)spin_site_label + 4);
    if (!bl) { fprintf(stderr, "gen failed\n"); return 1; }
    fprintf(stderr, "gen ok bl=%zu\n", bl);
    fprintf(stderr, "tls=%#llx blk_tls=%#llx\n", (unsigned long long)get_tpidr(), (unsigned long long)*(uint64_t *)(blk + 0x200));
    memcpy((void *)(uintptr_t)page, blk, sizeof(blk));

    /* patch 站点 → b page (self-modify) */
    uint64_t site = (uint64_t)(uintptr_t)spin_site_label;
    long pg = sysconf(_SC_PAGESIZE);
    uintptr_t base = site & ~(uintptr_t)(pg - 1);
    if (mprotect((void *)base, pg, PROT_READ | PROT_WRITE | PROT_EXEC) < 0) {
        perror("mprotect"); return 1;
    }
    uint32_t br = 0x14000000U |
                  (((uint32_t)((page - site) >> 2) & 0x03FFFFFFU));
    fprintf(stderr, "patching site=%#llx\n", (unsigned long long)site);
    memcpy((void *)(uintptr_t)site, &br, 4);
    __builtin___clear_cache((char *)site, (char *)site + 4);
    mprotect((void *)base, pg, PROT_READ | PROT_EXEC);

    /* 运行: 主线程自旋, 辅助线程置 flag */
    pthread_t t;
    pthread_create(&t, NULL, setter, NULL);
    spin_site_label((uint64_t)(uintptr_t)&flag);   /* 期望 0.2s 后返回 */
    fprintf(stderr, "runtime page_tls=%#llx mrs=%#llx\n", (unsigned long long)*(uint64_t *)(uintptr_t)(page + 0x200), (unsigned long long)get_tpidr());
    fprintf(stderr, "spin returned\n");
    pthread_join(t, NULL);
    fprintf(stderr, "joined\n");

    /* 校验事件 */
    uint64_t ord = *(volatile uint64_t *)(uintptr_t)(buf + A64_ATB_HDR_SIZE);
    uint64_t last = *(volatile uint64_t *)(uintptr_t)(buf + A64_ATB_HDR_SIZE + 8);
    uint64_t eptr = *(volatile uint64_t *)(uintptr_t)(buf + A64_ATB_OFF_EVENT_PTR);
    uint64_t n_ev = (eptr - (buf + events_off)) / 32;
    printf("site=%#llx page=%#llx br=%#x\n", (unsigned long long)site, (unsigned long long)page, br);
    printf("ord=%llu last=%llu events=%llu\n",
           (unsigned long long)ord, (unsigned long long)last,
           (unsigned long long)n_ev);
    if (ord == 0 || last != 1 || n_ev == 0) {
        fprintf(stderr, "TRAMP FAIL\n");
        return 1;
    }
    printf("TRAMP OK\n");
    return 0;
}
