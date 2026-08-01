/*
 * elftrace aarch64 恢复 stub (占位)
 *
 * 接口与 x86_64 版一致 (见 elftrace_stub.h 的 blob 布局), 但寄存器布局与
 * 恢复机制不同。当前环境无 aarch64 机器, 此处仅保留实现框架与常量,
 * 待有硬件后按以下方案实现:
 *
 * 1. 布局: 与 x86_64 相同的 blob 布局 (desc/fpu/sigmask/sigacts/regs/
 *    stack/sigframe), 但 STUB_REGS_SIZE = 34 x 8 = 272 字节
 *    (struct user_pt_regs: x0-x30, sp, pc, pstate)。
 *
 * 2. 恢复流程 (与 x86_64 对应):
 *    - 内存段: 逐段 mmap(MAP_FIXED|ANON) + 拷贝 + mprotect
 *    - munmap 初始栈 (解析 /proc/self/maps 的 [stack])
 *    - fd: openat/dup2 重开
 *    - 寄存器恢复: 两种方案二选一:
 *      a) 构建 ucontext 信号帧 (uc_mcontext.gp_regs 填 x0-x30 + sp + pc
 *         + pstate, uc_sigmask 填掩码, fpsimd 状态填 NT_FPREGSET 数据),
 *         然后 svc #0 (rt_sigreturn syscall 139), 由内核一次性恢复;
 *      b) 手工恢复: ldp 成对加载 x0-x30, mov sp, ldr pc (PC 由 x30 间接)。
 *      方案 a 与 x86_64 一致, 推荐。
 *
 * 3. 信号帧布局 (aarch64 rt_sigframe):
 *    struct rt_sigframe {
 *        struct siginfo info;       (128B)
 *        struct ucontext uc;
 *    };
 *    struct ucontext {
 *        unsigned long uc_flags;    (0x00)
 *        struct ucontext *uc_link;  (0x08)
 *        stack_t uc_stack;          (0x10, 24B)
 *        struct sigcontext uc_mcontext;  (0x28)
 *        sigset_t uc_sigmask;       (0x28 + sizeof(sigcontext))
 *    };
 *    struct sigcontext {
 *        __u64 fault_address;       (0x00)
 *        __u64 regs[31];            (0x08: x0-x30)
 *        __u64 sp;                  (0x100)
 *        __u64 pc;                  (0x108)
 *        __u64 pstate;              (0x110)
 *        __u8 __reserved[4096];     (0x118)
 *        struct _aarch64_ctx *reserved;  (0x1118)
 *    };
 *    (详情见内核 arch/arm64/include/asm/sigcontext.h / uapi)
 *
 * 4. IPC (perf_event_open): 与 x86_64 相同, syscall 号 241。
 *
 * 5. 汇编器: `as` + 链接脚本 src/stub.ld, objcopy 出 blob —— 构建规则
 *    参照 Makefile 中 stub_x86_64 的规则 (stub_blob_aarch64.c)。
 */
