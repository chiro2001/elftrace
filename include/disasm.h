#ifndef ELFTRACE_DISASM_H
#define ELFTRACE_DISASM_H

#include <stddef.h>
#include <stdint.h>

/* x86-64 指令长度解码 (仅长度, 不区分语义)。
 * 返回从 p 开始的完整指令长度 (含前缀); 无法解码返回 -1。
 * 用于 baremetal 构建时定位真正的 syscall 指令 (0F 05)。 */
int x86_len(const uint8_t *p, size_t cap);

/* p 处是否是一条完整的 syscall 指令 (0F 05, 长度恰为 2) */
int x86_is_syscall(const uint8_t *p, size_t cap);

#endif /* ELFTRACE_DISASM_H */
