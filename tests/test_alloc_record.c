/* 分配器记录跳板独立单测 (qemu-aarch64 可跑)
 *
 * 构造假 malloc: `sub sp,sp,#0x10; add x0,x0,#0x123; add sp,sp,#0x10;
 * ret` (返回 size+0x123)。patch 入口 → 记录跳板, 调用两次, 校验:
 * 1) 返回值正确 (原函数被执行);
 * 2) 事件流含 {kind, size, caller, ret} 两条且与调用对应;
 * 3) 恢复入口后函数照常工作。
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include "alloc_trace.h"
#include "a64.h"

#define BLK_ABS   0x40000000ULL
#define BUF_ABS   0x40010000ULL
#define FAKE_ABS  0x40060000ULL

static void *map_fixed(uint64_t addr, size_t len)
{
    void *p = mmap((void *)(uintptr_t)addr, len,
                   PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    return p == MAP_FAILED ? NULL : p;
}

int main(void)
{
    uint8_t *blk = map_fixed(BLK_ABS, 0x1000);
    uint8_t *buf = map_fixed(BUF_ABS, 0x1000);
    uint8_t *fake = map_fixed(FAKE_ABS, 0x1000);
    if (!blk || !buf || !fake) {
        printf("FAIL: mmap\n");
        return 1;
    }
    /* 假 malloc: sub sp,#0x10; add x0,#0x123; add sp,#0x10; ret */
    const uint32_t code[] = {
        0xD10043FFU, 0x91048C00U, 0x910043FFU, 0xD65F03C0U,
    };
    memcpy(fake, code, sizeof(code));
    uint32_t saved = code[0];

    uint64_t tls;
    __asm__("mrs %0, tpidr_el0" : "=r"(tls));
    uint64_t hdr_ptr = BUF_ABS + 24;
    uint64_t hdr_end = BUF_ABS + 32;
    uint64_t hdr_ovf = BUF_ABS + 40;
    uint64_t kind = ALLOC_MALLOC;

    size_t n = alloc_record_block(blk, BLK_ABS, saved, FAKE_ABS + 4,
                                  tls, hdr_ptr, hdr_end, hdr_ovf, kind);
    if (!n) {
        printf("FAIL: block gen\n");
        return 1;
    }
    /* 缓冲区头 */
    memset(buf, 0, 0x1000);
    uint64_t v = ALLOC_BUF_MAGIC;
    memcpy(buf + 0, &v, 8);
    v = ALLOC_BUF_VERSION;
    memcpy(buf + 8, &v, 8);
    v = 1;
    memcpy(buf + 16, &v, 8);
    v = BUF_ABS + ALLOC_BUF_HDR_SIZE;
    memcpy(buf + 24, &v, 8);
    v = BUF_ABS + 0x1000;
    memcpy(buf + 32, &v, 8);
    v = 0;
    memcpy(buf + 40, &v, 8);
    v = tls;
    memcpy(buf + 48, &v, 8);
    v = 0x1000;
    memcpy(buf + 56, &v, 8);

    /* patch 入口 → 跳板 */
    uint32_t bw = a64_encode_b(FAKE_ABS, BLK_ABS);
    memcpy(fake, &bw, 4);

    /* 调用两次 */
    uint64_t (*fn)(uint64_t) = (uint64_t (*)(uint64_t))(uintptr_t)FAKE_ABS;
    uint64_t r1 = fn(5);
    uint64_t r2 = fn(100);

    /* 校验: 用原始 syscall 退出 (不依赖 main 栈帧/printf) */
    uint64_t ev0[4];
    memcpy(ev0, (void *)(uintptr_t)(BUF_ABS + ALLOC_BUF_HDR_SIZE),
           sizeof(ev0));
    int rc = 0;
    if (r1 != 5 + 0x123 || r2 != 100 + 0x123)
        rc = (int)(r1 & 0xff) + 10;   /* 100+r1 低位: 诊断 */
    else if ((uint32_t)ev0[0] != ALLOC_MALLOC)
        rc = 2;
    else if (ev0[1] != 5)
        rc = 3;
    else if (ev0[2] == 0)
        rc = 4;
    else if (ev0[3] != 5 + 0x123)
        rc = 5;
    /* 恢复入口 */
    memcpy(fake, &saved, 4);
    if (!rc && fn(7) != 7 + 0x123)
        rc = 3;                 /* 恢复后原函数错 */
    __asm__ volatile("mov x8, #93\n\t"   /* exit_group */
                     "mov x0, %0\n\t"
                     "svc #0\n\t" :: "r"((uint64_t)rc) : "x8", "x0");
    return 1;   /* 不可达 */
}
