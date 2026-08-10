/* aarch64 原子指令编码判定单元测试 (纯静态, 可任意架构编译运行)。
 *
 * 用 gcc -march=armv8.1-a+lse 实测的编码 (见 commit b4e1191):
 *   cas    x0,x2,[x1] = 0xc8a07c22
 *   casl   x0,x2,[x1] = 0xc8a0fc22
 *   casa   x0,x2,[x1] = 0xc8e07c22
 *   casal  x0,x2,[x1] = 0xc8e0fc22
 *   swpal  x0,x0,[x1] = 0xf8e08020
 *   ldaddal x0,x0,[x1] = 0xf8e00020
 * 防回归: 掩码 (w & 0x08A07C00) == 0x08A07C00 必须同时命中
 * cas/casa/casl/casal, 且 a64_is_excl_store 必须拒绝 ldxr/ldar/
 * LSE CAS (bit22=1 是 load)。 */
#include <stdio.h>
#include "atomic_a64.h"

static int fails = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        printf("FAIL: %s\n", msg); \
        fails++; \
    } \
} while (0)

int main(void)
{
    unsigned rs, rt, rn;
    int size;

    /* LSE CAS 四变体 × 64/32 位 */
    static const uint32_t cas64[] = {
        0xc8a07c22U, 0xc8a0fc22U, 0xc8e07c22U, 0xc8e0fc22U,
    };
    static const uint32_t cas32[] = {
        0x08a07c22U, 0x08a0fc22U, 0x08e07c22U, 0x08e0fc22U,
    };
    for (size_t i = 0; i < 4; i++) {
        CHECK(a64_is_lse_cas(cas64[i], &rs, &rt, &rn),
              "64-bit CAS variant not matched");
        CHECK(rs == 0 && rt == 2 && rn == 1,
              "64-bit CAS register decode wrong");
        CHECK(a64_is_lse_cas(cas32[i], &rs, &rt, &rn),
              "32-bit CAS variant not matched");
    }

    /* 非 CAS 指令必须全部拒绝 */
    static const uint32_t noncas[] = {
        0xc85f7c40U,    /* ldxr x0,[x2] */
        0xc811fc41U,    /* stlxr w17,x1,[x2] */
        0xc8dffc20U,    /* ldar x0,[x1] */
        0xf8e08020U,    /* swpal x0,x0,[x1] */
        0xf8e00020U,    /* ldaddal x0,x0,[x1] */
        0x38208020U,    /* swp w0,w0,[x1] (32 位, bits14..10 非 11111) */
        0xd503201fU,    /* nop */
    };
    for (size_t i = 0;
         i < sizeof(noncas) / sizeof(noncas[0]); i++)
        CHECK(!a64_is_lse_cas(noncas[i], NULL, NULL, NULL),
              "non-CAS instruction matched as LSE CAS");

    /* a64_is_excl_store: 必须拒绝 load 类 (bit22=1) */
    CHECK(a64_is_excl_store(0xc811fc41U, &size, &rs, &rn, &rt, NULL),
          "stlxr not recognized as excl store");
    CHECK(size == 3 && rs == 17 && rn == 2 && rt == 1,
          "stlxr register decode wrong");
    CHECK(a64_is_excl_store(0xc8037c22U, NULL, NULL, NULL, NULL, NULL),
          "stxr not recognized as excl store");
    CHECK(!a64_is_excl_store(0xc85f7c40U, NULL, NULL, NULL, NULL, NULL),
          "ldxr misclassified as excl store");
    CHECK(!a64_is_excl_store(0xc8dffc20U, NULL, NULL, NULL, NULL, NULL),
          "ldar misclassified as excl store");
    CHECK(!a64_is_excl_store(0xc8e07c22U, NULL, NULL, NULL, NULL, NULL),
          "casa misclassified as excl store");
    CHECK(!a64_is_excl_store(0xc8a0fc22U, NULL, NULL, NULL, NULL, NULL),
          "casl misclassified as excl store");

    /* a64_is_excl_load: load 类命中, store 拒绝 */
    CHECK(a64_is_excl_load(0xc85f7c40U, &size, &rt, &rn, NULL),
          "ldxr not recognized as excl load");
    CHECK(a64_is_excl_load(0xc8dffc20U, NULL, NULL, NULL, NULL),
          "ldar not recognized as excl load");
    CHECK(!a64_is_excl_load(0xc811fc41U, NULL, NULL, NULL, NULL),
          "stlxr misclassified as excl load");
    CHECK(!a64_is_excl_load(0xc8e07c22U, NULL, NULL, NULL, NULL),
          "casa misclassified as excl load");

    if (fails) {
        printf("atomic encoding: %d FAILURES\n", fails);
        return 1;
    }
    printf("atomic encoding: all checks passed\n");
    return 0;
}
