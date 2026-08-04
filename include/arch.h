/*
 * elftrace 架构抽象 (x86_64 / aarch64)
 *
 * elftrace 工具链按目标架构交叉编译并运行在目标架构上 (freeze/trace
 * 用 ptrace 跟踪同架构进程), 因此用编译期条件编译区分架构, 而非运行
 * 期分派。host 侧通用逻辑 (ELF 组装、diff、bundle) 通过这里访问架构
 * 相关寄存器字段与 syscall 指令编码。
 *
 * 寄存器结构: 统一用 <sys/user.h> 的 struct user_regs_struct (即内核
 * GETREGSET NT_PRSTATUS 的原生布局):
 *   x86_64: 216B (r15..r9, rax..gs_base)
 *   aarch64: 272B (regs[31] + sp + pc + pstate)
 */
#ifndef ELFTRACE_ARCH_H
#define ELFTRACE_ARCH_H

#include <stdint.h>

#if defined(__x86_64__)

#define ELFTRACE_ARCH_CURRENT ELFTRACE_ARCH_X86_64
#define ARCH_SYSCALL_LEN 2            /* 0f 05 */
#define ARCH_REGS_RET_OFF 0x50         /* user_regs_struct.rax */

/* 寄存器字段访问 (user_regs_struct 命名) */
#define REG_PC(r)           ((r).rip)
#define REG_SET_PC(r, v)    ((r).rip = (uint64_t)(v))
#define REG_SYSCALL_NR(r)   ((r).orig_rax)
#define REG_RET(r)          ((r).rax)
#define REG_SP(r)           ((r).rsp)
#define REG_FS_BASE(r)      ((r).fs_base)
#define REG_GS_BASE(r)      ((r).gs_base)

/* 清掉 ptrace 停止机制残留的陷阱位 (x86: TF bit8)。
 * 目标正常运行时的 eflags 不含 TF, 清除是正确语义。 */
#define REG_CLEAR_TRAPS(r)  ((r).eflags &= ~0x100UL)

/* 判断 p 处是否为 syscall 指令 (x86_64: 0f 05) */
static inline int arch_is_syscall(const uint8_t *p, size_t cap)
{
    return cap >= 2 && p[0] == 0x0f && p[1] == 0x05;
}

/* syscall 指令 → 断点指令替换 (x86_64: 0f 05 → cc 90) */
static inline void arch_patch_syscall(uint8_t *p)
{
    p[0] = 0xcc;                    /* int3 */
    p[1] = 0x90;                    /* nop */
}

/* 断点判定: p 处是否已被替换为断点 (int3) */
static inline int arch_is_breakpoint(const uint8_t *p, size_t cap)
{
    return cap >= 1 && p[0] == 0xcc;
}

#elif defined(__aarch64__)

#define ELFTRACE_ARCH_CURRENT ELFTRACE_ARCH_AARCH64
#define ARCH_SYSCALL_LEN 4            /* d4000001 (svc #0) */
#define ARCH_REGS_RET_OFF 0x00         /* user_regs_struct.regs[0] (x0) */

#define REG_PC(r)           ((r).pc)
#define REG_SET_PC(r, v)    ((r).pc = (uint64_t)(v))
#define REG_SYSCALL_NR(r)   ((r).regs[8])   /* x8 = syscall 号 */
#define REG_RET(r)          ((r).regs[0])   /* x0 = 返回值 */
#define REG_SP(r)           ((r).sp)
#define REG_FS_BASE(r)      ((r).regs[18])  /* TPIDR_EL0 用户态不可读, x18 平台保留 */
#define REG_GS_BASE(r)      ((r).regs[18])

/* PSR.SS (bit 21): 单步状态位, ptrace 停止可能残留 */
#define REG_CLEAR_TRAPS(r)  ((r).pstate &= ~(1UL << 21))

static inline int arch_is_syscall(const uint8_t *p, size_t cap)
{
    uint32_t insn;
    if (cap < 4)
        return 0;
    __builtin_memcpy(&insn, p, 4);
    return insn == 0xd4000001U;     /* svc #0 */
}

static inline void arch_patch_syscall(uint8_t *p)
{
    uint32_t insn = 0xd4200000U;    /* brk #0 */
    __builtin_memcpy(p, &insn, 4);
}

static inline int arch_is_breakpoint(const uint8_t *p, size_t cap)
{
    uint32_t insn;
    if (cap < 4)
        return 0;
    __builtin_memcpy(&insn, p, 4);
    return insn == 0xd4200000U;
}

#else
#error "elftrace: unsupported build architecture (x86_64/aarch64)"
#endif

#endif /* ELFTRACE_ARCH_H */
