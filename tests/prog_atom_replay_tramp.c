/* 原子回放跳板独立自测 (无 ptrace, 无辅助线程):
 * 1. mmap 就近 RWX 页, 生成回放跳板 (runs: 前 2 次返回 0, 第 3 次起
 *    返回 1), patch 到自写自旋循环的 ldar 站点;
 * 2. 自旋不依赖任何其他线程 (内存不变), 应仅凭录制值在第 3 次退出。
 * 同时验证 acquire 屏障 (ldar 到原地址) 不会因真实内存值不变而卡住。 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <signal.h>

#include "atomic_a64.h"
#include "a64.h"

extern void spin_site_label(uint64_t, uint64_t, uint32_t *);
__asm__(".global spin_site_label\n"
        ".type spin_site_label, %function\n"
        "spin_site_label:\n"
        "spin_site:\n"
        "    ldar w1, [x0]\n"
        "    str w1, [x2], #4\n"
        "    cmp w1, #2\n"
        "    b.lo spin_site\n"
        "    ret\n");

extern void spin8_label(uint64_t, uint64_t, uint64_t);
__asm__(".global spin8_label\n"
        ".type spin8_label, %function\n"
        "spin8_label:\n"
        "spin8_site:\n"
        "    ldar x18, [x2]\n"
        "    cbz x18, spin8_site\n"
        "    ret\n");

extern void spin1_label(uint64_t);
__asm__(".global spin1_label\n"
        ".type spin1_label, %function\n"
        "spin1_label:\n"
        "spin1_site:\n"
        "    ldarb w16, [x0]\n"
        "    cbz w16, spin1_site\n"
        "    ret\n");

static volatile uint64_t flag;   /* 永远为 0: 回放必须覆盖真实内存值 */
static volatile uint64_t dbg_ord, dbg_cur, dbg_run2v;
static void on_alarm(int s)
{
    (void)s;
    fprintf(stderr, "STUCK ord=%llu cursor=%llu run2.value=%llu site=%#x\n",
            (unsigned long long)dbg_ord,
            (unsigned long long)dbg_cur,
            (unsigned long long)dbg_run2v,
            *(volatile uint32_t *)(uintptr_t)spin_site_label);
    _exit(1);
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

static void patch_site(uint64_t site, uint64_t target)
{
    long pg = sysconf(_SC_PAGESIZE);
    uintptr_t b = site & ~(uintptr_t)(pg - 1);
    mprotect((void *)b, pg, PROT_READ | PROT_WRITE | PROT_EXEC);
    uint32_t br = 0x14000000U |
                  (((uint32_t)((target - site) >> 2) & 0x03FFFFFFU));
    memcpy((void *)(uintptr_t)site, &br, 4);
    __builtin___clear_cache((char *)site, (char *)site + 4);
    mprotect((void *)b, pg, PROT_READ | PROT_EXEC);
}

int main(void)
{
    static volatile uint64_t flag8 = 0;
    static volatile uint8_t flag1 = 0;
    uint64_t ts = text_start();
    uint64_t page = find_gap_near(ts, 0x1000);
    if (!page) { fprintf(stderr, "no gap\n"); return 1; }
    void *pm = mmap((void *)(uintptr_t)page, 0x1000,
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (pm == MAP_FAILED) { perror("mmap page"); return 1; }

    /* 运行表: {1,0} {3,1} {5,2}。期望观测序列 [0,0,1,1,2]:
       - 序号 2/4 落在运行段内部 (起点已过但下一事件未到), 必须持续
         返回本段值 (曾用 b.lo 误回退真实内存值 → 序列 [0,0,1,0,2])。 */
    struct { uint64_t start, addr, value; } runs[3] = {
        {1, (uint64_t)(uintptr_t)&flag, 0},
        {3, (uint64_t)(uintptr_t)&flag, 1},
        {5, (uint64_t)(uintptr_t)&flag, 2},
    };
    uint64_t runs_abs = (uint64_t)(uintptr_t)&runs[0];
    uint32_t obs[8];
    memset(obs, 0, sizeof(obs));

    uint8_t blk[A64_ATOM_BLOCK_SIZE];
    size_t bl = a64_atomic_replay_block(blk, page, runs_abs, 3, 0,
                                        1 /* rt */, 0 /* rn */,
                                        (uint64_t)(uintptr_t)spin_site_label
                                        + 4, 0, 0);
    if (!bl) { fprintf(stderr, "gen failed\n"); return 1; }
    memcpy((void *)(uintptr_t)page, blk, sizeof(blk));
    __builtin___clear_cache((char *)(uintptr_t)page,
                            (char *)(uintptr_t)page + sizeof(blk));
    dbg_ord = *(volatile uint64_t *)(uintptr_t)(page + 0x200);
    dbg_cur = *(volatile uint64_t *)(uintptr_t)(page + 0x208);
    dbg_run2v = runs[2].value;

    /* patch 站点 → b page */
    uint64_t site = (uint64_t)(uintptr_t)spin_site_label;
    fprintf(stderr, "site=%#llx page=%#llx\n",
            (unsigned long long)site, (unsigned long long)page);
    patch_site(site, page);

    signal(SIGALRM, on_alarm);
    alarm(5);
    spin_site_label((uint64_t)(uintptr_t)&flag, 0, obs);
    alarm(0);

    uint64_t ord = *(volatile uint64_t *)(uintptr_t)(page + 0x200);
    uint64_t cur = *(volatile uint64_t *)(uintptr_t)(page + 0x208);
    printf("ord=%llu cursor=%llu obs=%u,%u,%u,%u,%u\n",
           (unsigned long long)ord, (unsigned long long)cur,
           obs[0], obs[1], obs[2], obs[3], obs[4]);
    if (ord != 5 || cur != 2 || obs[0] != 0 || obs[1] != 0 ||
        obs[2] != 1 || obs[3] != 1 || obs[4] != 2) {
        fprintf(stderr, "REPLAY TRAMP FAIL\n");
        return 1;
    }

    /* 位宽/寄存器角落: 64 位 ldar x18,[x2] (rt=18, rn=2) */
    {
        struct { uint64_t start, addr, value; } runs8[2] = {
            {1, (uint64_t)(uintptr_t)&flag8, 0},
            {2, (uint64_t)(uintptr_t)&flag8, 1},
        };
        uint8_t *blk8 = (uint8_t *)(uintptr_t)page + 0x240;
        if (!a64_atomic_replay_block(blk8, page + 0x240,
                                     (uint64_t)(uintptr_t)&runs8[0], 2,
                                     8, 18, 2,
                                     (uint64_t)(uintptr_t)spin8_label + 4,
                                     0, 0)) {
            fprintf(stderr, "gen8 failed\n");
            return 1;
        }
        __builtin___clear_cache((char *)blk8, (char *)blk8 + 0x240);
        patch_site((uint64_t)(uintptr_t)spin8_label, page + 0x240);
        spin8_label(0, 0, (uint64_t)(uintptr_t)&flag8);
        uint64_t ord8 = *(volatile uint64_t *)(uintptr_t)(page + 0x440);
        printf("ord8=%llu\n", (unsigned long long)ord8);
        if (ord8 != 2) {
            fprintf(stderr, "REPLAY 64BIT FAIL\n");
            return 1;
        }
    }

    /* 位宽/寄存器角落: 8 位 ldarb w16,[x0] (rt=16, rn=0) */
    {
        struct { uint64_t start, addr, value; } runs1[2] = {
            {1, (uint64_t)(uintptr_t)&flag1, 0},
            {2, (uint64_t)(uintptr_t)&flag1, 1},
        };
        uint8_t *blk1 = (uint8_t *)(uintptr_t)page + 0x480;
        if (!a64_atomic_replay_block(blk1, page + 0x480,
                                     (uint64_t)(uintptr_t)&runs1[0], 2,
                                     1, 16, 0,
                                     (uint64_t)(uintptr_t)spin1_label + 4,
                                     0, 0)) {
            fprintf(stderr, "gen1 failed\n");
            return 1;
        }
        __builtin___clear_cache((char *)blk1, (char *)blk1 + 0x240);
        patch_site((uint64_t)(uintptr_t)spin1_label, page + 0x480);
        spin1_label((uint64_t)(uintptr_t)&flag1);
        uint64_t ord1 = *(volatile uint64_t *)(uintptr_t)(page + 0x680);
        printf("ord1=%llu\n", (unsigned long long)ord1);
        if (ord1 != 2) {
            fprintf(stderr, "REPLAY 8BIT FAIL\n");
            return 1;
        }
    }
    printf("REPLAY TRAMP OK\n");
    return 0;
}
