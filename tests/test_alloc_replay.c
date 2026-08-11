/* alloc 结果重放跳板独立单测 (qemu-aarch64 可跑)
 *
 * 构造假 malloc 入口 (patch 成 b <重放块>), 假事件表/游标/总数槽,
 * 校验:
 *   ok       : 按序消费 N 条事件, 返回录制 ret, 游标 == N;
 *   overrun  : 消费超过总数 → bail, exit_group(9);
 *   mismatch : 事件 kind 与重放块 kind 不符 → bail, exit_group(11)。
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include "alloc_build.h"
#include "a64.h"

#define BLK_ABS   0x40000000ULL
#define EV_ABS    0x40010000ULL
#define DATA_ABS  0x40020000ULL
#define FAKE_ABS  0x40030000ULL
#define BAIL_ABS  0x40040000ULL
#define EXIT_ABS  0x40050000ULL
#define CLEN_ABS  0x40060000ULL

static void *map_fixed(uint64_t addr, size_t len)
{
    void *p = mmap((void *)(uintptr_t)addr, len,
                   PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    return p == MAP_FAILED ? NULL : p;
}

static void flush_icache(void *p, size_t n)
{
    __builtin___clear_cache((char *)p, (char *)p + n);
}

__attribute__((noinline)) static uint64_t call_fake(uint64_t arg)
{
    register uint64_t r asm("x0") = arg;
    register uint64_t x16out asm("x19");
    register uint64_t x17out asm("x20");
    __asm__ volatile(
        "mov x16, %3\n\t"
        "mov x17, %4\n\t"
        "blr %5\n\t"
        "mov %0, x16\n\t"
        "mov %1, x17\n\t"
        : "=r"(x16out), "=r"(x17out), "+r"(r)
        : "r"(0x1111222233334444ULL), "r"(0x5555666677778888ULL),
          "r"(FAKE_ABS)
        : "x1", "x2", "x3", "x4", "x5", "x6", "x30", "memory");
    if (x16out != 0x1111222233334444ULL)
        return 0xDEAD000000000016ULL;
    if (x17out != 0x5555666677778888ULL)
        return 0xDEAD000000000017ULL;
    return r;
}

__attribute__((noinline)) static uint64_t call_calloc(uint64_t nmemb,
                                                      uint64_t esz)
{
    register uint64_t r asm("x0") = nmemb;
    register uint64_t x16out asm("x19");
    register uint64_t x17out asm("x20");
    __asm__ volatile(
        "mov x1, %3\n\t"
        "mov x16, %4\n\t"
        "mov x17, %5\n\t"
        "blr %6\n\t"
        "mov %0, x16\n\t"
        "mov %1, x17\n\t"
        : "=r"(x16out), "=r"(x17out), "+r"(r)
        : "r"(esz), "r"(0x1111222233334444ULL),
          "r"(0x5555666677778888ULL),
          "r"(FAKE_ABS)
        : "x1", "x2", "x3", "x4", "x5", "x6", "x30", "memory");
    return r;
}

/* bail 桩: 把 reason (x22) 作为 exit_group 码直接退出 */
static void emit_bail_stub(uint8_t *p)
{
    uint32_t w = 0xAA1603E0U;   /* mov x0, x22 */
    memcpy(p, &w, 4); p += 4;
    w = 0xD2800BA8U;            /* mov x8, #93 */
    memcpy(p, &w, 4); p += 4;
    w = 0xD4000001U;            /* svc #0 */
    memcpy(p, &w, 4); p += 4;
    w = 0x14000000U;            /* b . */
    memcpy(p, &w, 4);
}

static void setup_events(uint8_t *ev, uint64_t n, uint32_t kind)
{
    for (uint64_t i = 0; i < n; i++) {
        uint8_t *e = ev + i * 40;
        uint32_t k = kind;
        uint64_t size = 0x100 + i;
        uint64_t caller = 0x70000000ULL + i;
        uint64_t ret = 0x4000 + i * 0x111;
        uint64_t extra = 0;
        memcpy(e + 0, &k, 4);
        memcpy(e + 8, &size, 8);
        memcpy(e + 16, &caller, 8);
        memcpy(e + 24, &ret, 8);
        memcpy(e + 32, &extra, 8);
    }
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "ok";
    uint8_t *blk = map_fixed(BLK_ABS, 0x1000);
    uint8_t *ev = map_fixed(EV_ABS, 0x1000);
    uint8_t *data = map_fixed(DATA_ABS, 0x1000);
    uint8_t *fake = map_fixed(FAKE_ABS, 0x1000);
    uint8_t *bailp = map_fixed(BAIL_ABS, 0x1000);
    uint8_t *exitp = map_fixed(EXIT_ABS, 0x1000);
    uint8_t *clen = map_fixed(CLEN_ABS, 0x1000);
    if (!blk || !ev || !data || !fake || !bailp || !exitp || !clen) {
        printf("FAIL: mmap\n");
        return 1;
    }
    emit_bail_stub(bailp);
    flush_icache(bailp, 0x40);
    /* exit 桩: 校验 cursor==3 → exit_group(77), 否则 78 */
    {
        uint32_t w = 0x58000102U;   /* ldr x2,[pc,#32] → index 8 */
        memcpy(exitp, &w, 4);
        w = 0xF9400043U;            /* ldr x3,[x2] (cursor) */
        memcpy(exitp + 4, &w, 4);
        w = 0xD2800064U;            /* mov x4,#3 */
        memcpy(exitp + 8, &w, 4);
        w = 0xEB04007FU;            /* cmp x3,x4 */
        memcpy(exitp + 12, &w, 4);
        w = 0x9A9F07E0U;            /* cset x0, ne (eq→0) */
        memcpy(exitp + 16, &w, 4);
        w = 0x11013400U;            /* add w0,w0,#77 (eq→77, ne→78) */
        memcpy(exitp + 20, &w, 4);
        w = 0xD2800BA8U;            /* mov x8,#93 */
        memcpy(exitp + 24, &w, 4);
        w = 0xD4000001U;            /* svc #0 */
        memcpy(exitp + 28, &w, 4);
        memcpy(exitp + 32, &(uint64_t){DATA_ABS + 0x00}, 8);
    }

    uint64_t n = 0;
    uint32_t kind = 0;
    if (strcmp(mode, "overrun") == 0)
        n = 1;
    else if (strcmp(mode, "mismatch") == 0) {
        n = 1;
        kind = 1;               /* 块期待 calloc, 事件却是 malloc */
    } else if (strcmp(mode, "calloc") == 0 ||
               strcmp(mode, "callocbig") == 0) {
        n = 1;
        kind = 1;
    } else if (strcmp(mode, "realloc") == 0) {
        n = 1;
        kind = 2;
    } else
        n = 3;
    /* mismatch: 事件 kind 故意与块期待不同 (块 kind=1, 事件 kind=0) */
    setup_events(ev, n, strcmp(mode, "mismatch") == 0 ? 0 : kind);
    if (strcmp(mode, "calloc") == 0 ||
        strcmp(mode, "callocbig") == 0) {
        /* 单条 calloc 事件: nmemb=3, ret=DATA+0x400 (零化目标) */
        uint8_t *e0 = ev;
        uint32_t k = 1;
        uint64_t size = 3, caller = 0x70000000ULL, ret = DATA_ABS + 0x400;
        uint64_t extra = 4;          /* elem_size */
        memcpy(e0 + 0, &k, 4);
        memcpy(e0 + 8, &size, 8);
        memcpy(e0 + 16, &caller, 8);
        memcpy(e0 + 24, &ret, 8);
        memcpy(e0 + 32, &extra, 8);
    }
    if (strcmp(mode, "realloc") == 0) {
        /* realloc 事件: size 字段=old_ptr, pad=new_size, ret=新指针 */
        uint8_t *e0 = ev;
        uint32_t k = 2, pad = 0x80;
        uint64_t old = DATA_ABS + 0x200, caller = 0x70000000ULL;
        uint64_t ret = DATA_ABS + 0x400;
        uint64_t extra = 0x80;       /* new_size */
        memcpy(e0 + 0, &k, 4);
        memcpy(e0 + 4, &pad, 4);
        memcpy(e0 + 8, &old, 8);
        memcpy(e0 + 16, &caller, 8);
        memcpy(e0 + 24, &ret, 8);
        memcpy(e0 + 32, &extra, 8);
        /* copy_len 侧表: [0]=0x45 (69B, 非 8 对齐 → 跳板取整 72B) */
        uint64_t cl = 0x45;
        memcpy(clen, &cl, 8);
    }

    uint64_t cursor_addr = DATA_ABS + 0x00;
    uint64_t total_addr = DATA_ABS + 0x08;
    uint64_t tel_abs = DATA_ABS + 0x100;
    uint64_t cursor = 0, total = n;
    memcpy((void *)(uintptr_t)cursor_addr, &cursor, 8);
    memcpy((void *)(uintptr_t)total_addr, &total, 8);

    uint64_t exit_abs = 0;
    if (strcmp(mode, "fuse") == 0)
        exit_abs = EXIT_ABS;
    uint64_t copy_len_abs = 0;
    if (strcmp(mode, "realloc") == 0)
        copy_len_abs = CLEN_ABS;
    size_t sz = alloc_replay_block(blk, BLK_ABS, cursor_addr, total_addr,
                                   EV_ABS, kind, tel_abs, BAIL_ABS,
                                   FAKE_ABS, exit_abs, copy_len_abs);
    if (sz != 0x280) {
        printf("FAIL: block size %zu\n", sz);
        return 1;
    }
    flush_icache(blk, 0x280);
    uint32_t bw = a64_encode_b(FAKE_ABS, BLK_ABS);
    if (!bw) {
        printf("FAIL: patch branch\n");
        return 1;
    }
    memcpy(fake, &bw, 4);
    flush_icache(fake, 16);

    uint64_t rc = 0;
    if (strcmp(mode, "overrun") == 0) {
        if (call_fake(0x100) != 0x4000)
            rc = 2;             /* 首个事件 ret 错 */
        if (!rc)
            call_fake(0x100);   /* 超消费 → exit(9) */
        rc = rc ? rc : 90;      /* 未 bail: 失败 */
    } else if (strcmp(mode, "mismatch") == 0) {
        call_fake(1);           /* → exit(11) */
        rc = 91;
    } else if (strcmp(mode, "fuse") == 0) {
        for (uint64_t i = 0; i < n; i++)
            call_fake(0x100 + i); /* 第 3 次消费后 → exit(77/78) */
        rc = 92;                /* 未融合退出: 失败 */
    } else if (strcmp(mode, "argmis") == 0) {
        call_fake(0x200);       /* 参数与录制 size 不符 → exit(12) */
        rc = 93;
    } else if (strcmp(mode, "calloc") == 0) {
        memset((void *)(uintptr_t)(DATA_ABS + 0x400), 0xAA, 0x20);
        uint64_t r = call_calloc(3, 4);  /* 12B, 非 8 对齐 */
        if (r != DATA_ABS + 0x400)
            rc = 60;
        else {
            const uint8_t *z =
                (const uint8_t *)(uintptr_t)(DATA_ABS + 0x400);
            for (int i = 0; i < 12; i++)
                if (z[i]) { rc = 61; break; }
        }
        if (!rc) {
            memcpy(&cursor, (void *)(uintptr_t)cursor_addr, 8);
            if (cursor != 1)
                rc = 62;
        }
    } else if (strcmp(mode, "callocbig") == 0) {
        call_calloc(3, 0x10000000); /* 3*256MB > 256MB 上限 → exit(13) */
        rc = 94;
    } else if (strcmp(mode, "realloc") == 0) {
        memset((void *)(uintptr_t)(DATA_ABS + 0x200), 0x5A, 0x80);
        memset((void *)(uintptr_t)(DATA_ABS + 0x400), 0x00, 0x80);
        uint64_t r = call_calloc(DATA_ABS + 0x200, 0x80);
        if (r != DATA_ABS + 0x400)
            rc = 70;
        else {
            const uint8_t *src =
                (const uint8_t *)(uintptr_t)(DATA_ABS + 0x200);
            const uint8_t *dst =
                (const uint8_t *)(uintptr_t)(DATA_ABS + 0x400);
            for (int i = 0; i < 0x48; i++)
                if (dst[i] != src[i]) { rc = 71; break; }
            for (int i = 0x48; i < 0x80; i++)
                if (dst[i] != 0) { rc = 72; break; }
        }
    } else {
        uint64_t exp[3] = {0x4000, 0x4111, 0x4222};
        for (uint64_t i = 0; i < n; i++) {
            uint64_t r = call_fake(0x100 + i);
            if (r != exp[i]) {
                rc = 10 + i;    /* 返回值错 */
                break;
            }
        }
        if (!rc) {
            memcpy(&cursor, (void *)(uintptr_t)cursor_addr, 8);
            if (cursor != n)
                rc = 20;        /* 游标未推进 */
        }
        if (!rc) {
            uint64_t m;
            memcpy(&m, (void *)(uintptr_t)tel_abs, 8);
            if (m != 0)
                rc = 21;        /* 成功路径不应写遥测 */
        }
    }
    __asm__ volatile("mov x8, #93\n\t"
                     "mov x0, %0\n\t"
                     "svc #0\n\t" :: "r"(rc) : "x8", "x0");
    return 1;                   /* 不可达 */
}
