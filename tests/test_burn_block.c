/* run-burn 融合退出独立单测 (qemu-aarch64 可跑, 不依赖远程硬件)
 *
 * 构造: 常量自旋 (run 表 1 条: start=1, addr=0 合成, value=0),
 * load_limit=N, clean_exit 命中。模拟"site 循环": RET_ADDR 桩检查
 * 返回值 x0, 为 0 则 re-enter 跳板, 否则挂起; CLEAN_EXIT 桩置
 * exit_hit 后 br x30 返回 main。
 *
 * 期望: 跳板入口次数 = 2 (首访问逐访问 + 中段整 run 烧录),
 * exit_hit=1, 模拟访问总数 = N。
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include "atomic_a64.h"
#include "a64.h"

#define BLK_ABS      0x40000000ULL
#define RUNS_ABS     0x40010000ULL
#define RET_ADDR     0x40020000ULL
#define EXIT_ADDR    0x40030000ULL
#define DATA_ADDR    0x40040000ULL
#define STACK_ABS    0x41000000ULL

/* ret 桩 (置于 RET_ADDR): 入口计数++, x0==0 → b BLK_ABS, 否则挂起 */
static uint32_t ret_stub[9];
/* exit 桩 (置于 EXIT_ADDR): exit_hit=1, 恢复 sp, ret x30 返回 */
static uint32_t exit_stub[10];

static void *map_fixed(uint64_t addr, size_t len)
{
    void *p = mmap((void *)(uintptr_t)addr, len,
                   PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    return p == MAP_FAILED ? NULL : p;
}

/* 设置 x1 = 门控地址 (模拟 site 的基址寄存器), 再跳入跳板 */
__attribute__((noinline, naked)) static void enter(void)
{
    __asm__ volatile(
        "mov x1, %0\n\t"
        "mov x2, sp\n\t"
        "str x2, [%2]\n\t"
        "mov x16, %1\n\t"
        "br x16\n\t" :: "r"((uint64_t)(DATA_ADDR + 16)),
        "r"((uint64_t)BLK_ABS),
        "r"((uint64_t)(DATA_ADDR + 24)) : "x1", "x2", "x16", "memory");
}

int main(void)
{
    uint64_t N = 10;
    uint8_t *blk = map_fixed(BLK_ABS, 0x1000);
    uint8_t *runs = map_fixed(RUNS_ABS, 0x1000);
    uint8_t *retp = map_fixed(RET_ADDR, 0x1000);
    uint8_t *exitp = map_fixed(EXIT_ADDR, 0x1000);
    uint8_t *data = map_fixed(DATA_ADDR, 0x1000);
    if (!blk || !runs || !retp || !exitp || !data) {
        printf("FAIL: mmap fixed failed\n");
        return 1;
    }
    /* ldr x2,[pc,#28]; ldr x3,[x2]; add x3,#1; str; cbz x0,+8; b .; b BLK */
    ret_stub[0] = 0x580000E2U;
    ret_stub[1] = 0xF9400043U;
    ret_stub[2] = 0x91000463U;
    ret_stub[3] = 0xF9000043U;
    ret_stub[4] = 0xB4000040U;          /* cbz x0, +8 → index 6 */
    ret_stub[5] = 0x14000000U;          /* b . (挂起, 不应发生) */
    ret_stub[6] = a64_encode_b(RET_ADDR + 6 * 4, BLK_ABS);
    memcpy(&ret_stub[7], &(uint64_t){DATA_ADDR}, 8);
    exit_stub[0] = 0x58000122U;         /* ldr x2,[pc,#36] → index 9 */
    exit_stub[1] = 0xF9400043U;         /* ldr x3,[x2] (sp_slot) */
    exit_stub[2] = 0x9100007FU;         /* mov sp, x3 */
    exit_stub[3] = 0x580000A2U;         /* ldr x2,[pc,#20] → index 8 */
    exit_stub[4] = 0xD2800023U;         /* mov x3,#1 */
    exit_stub[5] = 0xF9000043U;         /* str x3,[x2] (exit_hit) */
    exit_stub[6] = 0xD65F03C0U;         /* ret */
    exit_stub[7] = 0;
    memcpy(&exit_stub[8], &(uint64_t){DATA_ADDR + 8}, 8);   /* exit_hit */
    memcpy(&exit_stub[9], &(uint64_t){DATA_ADDR + 24}, 8);  /* sp_slot */
    memcpy(retp, ret_stub, sizeof(ret_stub));
    memcpy(exitp, exit_stub, sizeof(exit_stub));

    /* run 表: 合成首段 {start=1, addr=0, value=0} */
    struct ab_run {
        uint64_t start, addr, value;
    } r0 = {1, 0, 0};
    memcpy(runs, &r0, sizeof(r0));
    *(volatile uint64_t *)(data + 16) = 0;   /* 门控值 (恒 0 自旋) */

    size_t n = a64_atomic_replay_burn_block(
        blk, BLK_ABS, RUNS_ABS, 1, 4, 0, 1, RET_ADDR, N,
        0x40050000ULL /* bail (clean 路径不触达) */, EXIT_ADDR,
        0, 0, NULL, 2);
    if (!n) {
        printf("FAIL: block gen\n");
        return 1;
    }

    /* 从跳板进入 (模拟 site 的 b); 返回后由 ret 桩循环/退出 */
    printf("jump BLK_ABS first=%08x ret=%p\n", *(uint32_t*)blk, retp);
    printf("data ord=%llu cursor=%llu runs=%#llx n_runs=%llu "
           "limit=%llu exit=%#llx clean=%#llx\n",
           (unsigned long long)*(uint64_t*)(blk + 0x200),
           (unsigned long long)*(uint64_t*)(blk + 0x208),
           (unsigned long long)*(uint64_t*)(blk + 0x210),
           (unsigned long long)*(uint64_t*)(blk + 0x218),
           (unsigned long long)*(uint64_t*)(blk + 0x220),
           (unsigned long long)*(uint64_t*)(blk + 0x228),
           (unsigned long long)*(uint64_t*)(blk + 0x248));
    uint64_t sp0;
    __asm__("mov %0, sp" : "=r"(sp0));
    printf("main sp=%#llx\n", (unsigned long long)sp0);
    fflush(stdout);
    enter();

    /* 不依赖 main 栈帧局部量: 跳板/桩可能已改动 sp */
    uint64_t ret_count = *(volatile uint64_t *)(uintptr_t)(DATA_ADDR + 0);
    uint64_t exit_hit = *(volatile uint64_t *)(uintptr_t)(DATA_ADDR + 8);
    printf("burn test: entries=%llu exit_hit=%llu N=%llu\n",
           (unsigned long long)ret_count,
           (unsigned long long)exit_hit,
           (unsigned long long)N);
    if (exit_hit != 1) {
        printf("FAIL: clean exit not reached\n");
        return 1;
    }
    if (ret_count != 2) {
        printf("FAIL: entries=%llu (期望 2: 首访问逐访问 + 烧录入口)\n",
               (unsigned long long)ret_count);
        return 1;
    }
    printf("PASS: burn fused-exit logic\n");
    return 0;
}
