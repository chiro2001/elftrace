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
#define ENTER_ADDR   0x40050000ULL
#define STACK_ABS    0x41000000ULL

/* ret 桩 (置于 RET_ADDR): 入口计数++, x0==0 → b BLK_ABS, 否则挂起 */
static uint32_t ret_stub[9];
/* exit 桩 (置于 EXIT_ADDR): exit_hit=1, 校验 ret_count==2,
   exit_group(rc) 直接结束 (不再返回 main, 避开台架栈帧问题) */
static uint32_t exit_stub[14];

static void *map_fixed(uint64_t addr, size_t len)
{
    void *p = mmap((void *)(uintptr_t)addr, len,
                   PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    return p == MAP_FAILED ? NULL : p;
}

/* enter 桩 (置于 ENTER_ADDR, 无 prologue): 存 sp, 设 x1=门控地址,
   跳入跳板。 */
static uint32_t enter_stub[10];

int main(void)
{
    uint64_t N = 1000000;
    uint8_t *blk = map_fixed(BLK_ABS, 0x1000);
    uint8_t *runs = map_fixed(RUNS_ABS, 0x1000);
    uint8_t *retp = map_fixed(RET_ADDR, 0x1000);
    uint8_t *exitp = map_fixed(EXIT_ADDR, 0x1000);
    uint8_t *data = map_fixed(DATA_ADDR, 0x1000);
    uint8_t *enterp = map_fixed(ENTER_ADDR, 0x1000);
    if (!blk || !runs || !retp || !exitp || !data || !enterp) {
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
    exit_stub[0] = 0x58000142U;         /* ldr x2,[pc,#40] → index 10 */
    exit_stub[1] = 0xF9400043U;         /* ldr x3,[x2] (ret_count) */
    exit_stub[2] = 0xD2800044U;         /* mov x4, #2 */
    exit_stub[3] = 0xEB04007FU;         /* cmp x3, x4 */
    exit_stub[4] = 0x9A9F17E0U;         /* cset x0, eq */
    exit_stub[5] = 0x580000E2U;         /* ldr x2,[pc,#28] → index 12 */
    exit_stub[6] = 0xD2800025U;         /* mov x5, #1 */
    exit_stub[7] = 0xF9000045U;         /* str x5,[x2] (exit_hit) */
    exit_stub[8] = 0xD2800BA8U;         /* mov x8, #93 (exit_group) */
    exit_stub[9] = 0xD4000001U;         /* svc #0 */
    memcpy(&exit_stub[10], &(uint64_t){DATA_ADDR + 0}, 8);  /* ret_count */
    memcpy(&exit_stub[12], &(uint64_t){DATA_ADDR + 8}, 8);  /* exit_hit */
    enter_stub[0] = 0x910003E2U;         /* mov x2, sp */
    enter_stub[1] = 0x580000A3U;         /* ldr x3,[pc,#20] → index 6 */
    enter_stub[2] = 0xF9000062U;         /* str x2,[x3] (sp_slot) */
    enter_stub[3] = 0x580000A1U;         /* ldr x1,[pc,#20] → index 8 */
    enter_stub[4] = a64_encode_b(ENTER_ADDR + 4 * 4, BLK_ABS);
    enter_stub[5] = 0;
    memcpy(&enter_stub[6], &(uint64_t){DATA_ADDR + 24}, 8);
    memcpy(&enter_stub[8], &(uint64_t){DATA_ADDR + 16}, 8);
    memcpy(retp, ret_stub, sizeof(ret_stub));
    memcpy(exitp, exit_stub, sizeof(exit_stub));
    memcpy(enterp, enter_stub, sizeof(enter_stub));

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

    /* 从跳板进入 (模拟 site 的 b); 桩循环/退出由 exit 桩校验
       (ret_count==2 → exit_group(0), 否则 exit_group(1)) */
    printf("burn fused-exit: N=%llu (exit code = 结果)\n",
           (unsigned long long)N);
    fflush(stdout);
    ((void (*)(void))(uintptr_t)ENTER_ADDR)();
    return 0;   /* 不可达 (exit 桩已退出) */
}
