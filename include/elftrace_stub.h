/*
 * elftrace 恢复 stub 的 blob 布局 (x86_64)。
 *
 * 恢复 stub 是一段自包含的 PIC 汇编 (无任何外部依赖), 由 build 工具嵌入
 * 生成的 ELF 中, 作为 ELF 入口。loader 将整个 blob 以 RWX 映射到目标进程
 * 地址空间的一个空闲 gap 中, 入口位于 BASE + STUB_ENTRY_OFF。
 *
 * blob 内部所有固定偏移均以 blob 起始为原点; stub 在入口处通过 PC 相对
 * 寻址访问各区域。builder 追加的动态区域 (seg 表 / fd 表 / 字符串 /
 * payload) 的 blob 相对偏移由 builder 填入 desc。
 *
 * 布局 (0x8000 = 32KB 固定区):
 *   [0x0000] desc         256B   恢复描述符
 *   [0x0100] fpu blob     4096B  收集到的 xstate (XSAVE 非压缩格式)
 *   [0x1100] sigmask      8B     内核 sigset_t
 *   [0x1108] sigacts      2560B  64 x elftrace_sigact (可选)
 *   [0x1B08] regs         216B   x86_64 struct pt_regs 快照
 *   [0x1BE0] maps_buf     4096B  /proc/self/maps 解析缓冲
 *   [0x2BE0] ipc_attr     128B   perf_event_attr
 *   [0x2C60] ipc_sigact   48B    SIGIO 处理器的 sigaction
 *   [0x2CA0] stack        8KB    stub 自身栈
 *   [0x4CC0] sigframe     5632B  rt_sigreturn 信号帧 (ucontext + fpstate)
 *   [0x62C0] entry        代码起点
 *   [0x8000] ...          builder 追加: segs / fds / strings / payload
 */
#ifndef ELFTRACE_STUB_H
#define ELFTRACE_STUB_H

/* ---- 固定区域偏移 ---- */
#define STUB_DESC_OFF       0x0000
#define STUB_FPU_OFF        0x0100
#define STUB_FPU_CAP        0x1000       /* xstate 最大容量 4096B */
#define STUB_SIGMASK_OFF    0x1100
#define STUB_SIGACTS_OFF    0x1108
#define STUB_SIGACTS_SIZE   (64 * 40)    /* 64 x elftrace_sigact */
#if defined(__aarch64__)
/* aarch64: regs 272B (34x8), 后续区整体后移 */
#define STUB_REGS_OFF       0x1B08
#define STUB_REGS_SIZE      (34 * 8)     /* aarch64 struct pt_regs */
#define STUB_MAPS_BUF       0x1C20
#define STUB_MAPS_SIZE      0x1000
#define STUB_IPC_ATTR       0x2C20
#define STUB_IPC_SIGACT     0x2CA0
#define STUB_STACK_OFF      0x2CD0
#define STUB_STACK_SIZE     0x2000       /* 8KB */
#define STUB_STACK_TOP      (STUB_STACK_OFF + STUB_STACK_SIZE)
#define STUB_FRAME_OFF      0x4CD0       /* rt_sigreturn 信号帧 (aarch64 大) */
#define STUB_FRAME_SIZE     0x1600       /* 5632B: siginfo+ucontext+fpsimd */
#define STUB_ENTRY_OFF      0x62D0
#else
#define STUB_REGS_OFF       0x1B08
#define STUB_REGS_SIZE      (27 * 8)     /* x86_64 struct pt_regs */
#define STUB_MAPS_BUF       0x1BE0
#define STUB_MAPS_SIZE      0x1000
#define STUB_IPC_ATTR       0x2BE0
#define STUB_IPC_SIGACT     0x2C60
#define STUB_STACK_OFF      0x2CA0
#define STUB_STACK_SIZE     0x2000       /* 8KB */
#define STUB_STACK_TOP      (STUB_STACK_OFF + STUB_STACK_SIZE)
#define STUB_FRAME_OFF      0x4CC0       /* rt_sigreturn 信号帧 */
#define STUB_FRAME_SIZE     0x1600       /* 5632B: ucontext + fpstate 区 */
#define STUB_ENTRY_OFF      0x62C0
#endif
#define STUB_FIXED_SIZE     0x8000

/* ---- rst_desc 字段偏移 (256B, 全 u64) ---- */
#define RST_DESC_MAGIC      0x00
#define RST_DESC_VERSION    0x08
#define RST_DESC_FLAGS      0x10
#define RST_DESC_TARGET_RIP 0x18
#define RST_DESC_N_SEGS     0x20
#define RST_DESC_SEGS_OFF   0x28
#define RST_DESC_N_FDS      0x30
#define RST_DESC_FDS_OFF    0x38
#define RST_DESC_FPU_OFF    0x40
#define RST_DESC_FPU_SIZE   0x48
#define RST_DESC_SIGMASK_OFF 0x50
#define RST_DESC_SIGACTS_OFF 0x58
#define RST_DESC_REGS_OFF   0x60
#define RST_DESC_IPC_PERIOD 0x68
#define RST_DESC_IPC_FD     0x70
#define RST_DESC_IPC_BUF_OFF 0x78
#define RST_DESC_MODE       0x80   /* 0=real, 1=baremetal */
#define RST_DESC_EXIT_ADDR  0x88   /* baremetal 退出点 (0=无) */
#define RST_DESC_BRK_BASE   0x90   /* 冻结时堆尾 (brk 恢复/baremetal 模拟) */
#define RST_DESC_TARGET_TID 0x98   /* getpid 模拟值 */
#define RST_DESC_STACK_VADDR 0xA0  /* [stack] 段 vaddr (恢复时 MAP_GROWSDOWN) */
#define RST_DESC_RLIM_STACK_CUR 0xA8  /* RLIMIT_STACK 当前值 */
#define RST_DESC_RLIM_STACK_MAX 0xB0  /* RLIMIT_STACK 最大值 */
#define RST_DESC_REPLAY_OFF  0xB8  /* baremetal syscall 回放表偏移 (blob 相对) */
#define RST_DESC_REPLAY_SIZE 0xC0  /* 回放表大小 (0=无, 走旧 mock) */
#define RST_DESC_REPLAY_CUR  0xC8  /* 回放表游标 (stub 运行时维护, 顺序消费) */
#define RST_DESC_TLS         0xD0  /* aarch64 TPIDR_EL0 (x86_64 保留 0) */

#define RST_DESC_MAGIC_VAL  0x5253544452455354  /* "RESTDSTR" */

#define RST_FLAG_RESTORE_FDS      (1 << 0)
#define RST_FLAG_RESTORE_SIGACTS  (1 << 1)
#define RST_FLAG_IPC              (1 << 2)
#define RST_FLAG_BAREMETAL        (1 << 3)

/* ---- 工具常量 ---- */
#define PERF_EVENT_IOC_ENABLE   0x2400
#define PERF_EVENT_IOC_DISABLE  0x2401
#define PERF_EVENT_IOC_RESET    0x2403

/* x86_64 pt_regs 关键字段偏移 (与 arch/x86/include/asm/ptrace.h 一致) */
#define PT_REGS_R15      0x00
#define PT_REGS_R14      0x08
#define PT_REGS_R13      0x10
#define PT_REGS_R12      0x18
#define PT_REGS_RBP      0x20
#define PT_REGS_RBX      0x28
#define PT_REGS_R11      0x30
#define PT_REGS_R10      0x38
#define PT_REGS_R9       0x40
#define PT_REGS_R8       0x48
#define PT_REGS_RAX      0x50
#define PT_REGS_RCX      0x58
#define PT_REGS_RDX      0x60
#define PT_REGS_RSI      0x68
#define PT_REGS_RDI      0x70
#define PT_REGS_ORIG_RAX 0x78
#define PT_REGS_RIP      0x80
#define PT_REGS_CS       0x88
#define PT_REGS_EFLAGS   0x90
#define PT_REGS_RSP      0x98
#define PT_REGS_SS       0xA0
#define PT_REGS_FS_BASE  0xA8
#define PT_REGS_GS_BASE  0xB0

/* ---- aarch64 pt_regs 关键字段偏移 (user_pt_regs: regs[31]+sp+pc+pstate) ---- */
#if defined(__aarch64__)
#define PT_REGS_X0       0x00
#define PT_REGS_X1       0x08
#define PT_REGS_X2       0x10
#define PT_REGS_X3       0x18
#define PT_REGS_X4       0x20
#define PT_REGS_X5       0x28
#define PT_REGS_X6       0x30
#define PT_REGS_X7       0x38
#define PT_REGS_X8       0x40
#define PT_REGS_X9       0x48
#define PT_REGS_X10      0x50
#define PT_REGS_X11      0x58
#define PT_REGS_X12      0x60
#define PT_REGS_X13      0x68
#define PT_REGS_X14      0x70
#define PT_REGS_X15      0x78
#define PT_REGS_X16      0x80
#define PT_REGS_X17      0x88
#define PT_REGS_X18      0x90
#define PT_REGS_X19      0x98
#define PT_REGS_X20      0xA0
#define PT_REGS_X21      0xA8
#define PT_REGS_X22      0xB0
#define PT_REGS_X23      0xB8
#define PT_REGS_X24      0xC0
#define PT_REGS_X25      0xC8
#define PT_REGS_X26      0xD0
#define PT_REGS_X27      0xD8
#define PT_REGS_X28      0xE0
#define PT_REGS_X29      0xE8
#define PT_REGS_X30      0xF0
#define PT_REGS_SP       0xF8
#define PT_REGS_PC       0x100
#define PT_REGS_PSTATE   0x108
#endif

/* ---- rt_sigreturn 信号帧偏移 (内核 asm/sigcontext.h + uapi) ---- */
#define SIGFRAME_UC_FLAGS       0x00
#define SIGFRAME_UC_LINK        0x08
#define SIGFRAME_UC_STACK       0x10   /* 24B: ss_sp, ss_flags(+pad), ss_size */
#define SIGFRAME_UC_MCONTEXT    0x28
/* sigcontext 内偏移 (0x28 为 ucontext 基) */
#define SIGFRAME_SC_R8          0x00
#define SIGFRAME_SC_R9          0x08
#define SIGFRAME_SC_R10         0x10
#define SIGFRAME_SC_R11         0x18
#define SIGFRAME_SC_R12         0x20
#define SIGFRAME_SC_R13         0x28
#define SIGFRAME_SC_R14         0x30
#define SIGFRAME_SC_R15         0x38
#define SIGFRAME_SC_RDI         0x40
#define SIGFRAME_SC_RSI         0x48
#define SIGFRAME_SC_RBP         0x50
#define SIGFRAME_SC_RBX         0x58
#define SIGFRAME_SC_RDX         0x60
#define SIGFRAME_SC_RAX         0x68
#define SIGFRAME_SC_RCX         0x70
#define SIGFRAME_SC_RSP         0x78
#define SIGFRAME_SC_RIP         0x80
#define SIGFRAME_SC_EFLAGS      0x88
#define SIGFRAME_SC_CS          0x90   /* u16 */
#define SIGFRAME_SC_GS          0x92   /* u16 */
#define SIGFRAME_SC_FS          0x94   /* u16 */
#define SIGFRAME_SC_SS          0x96   /* u16 */
#define SIGFRAME_SC_ERR         0x98
#define SIGFRAME_SC_TRAPNO      0xA0
#define SIGFRAME_SC_OLDMASK     0xA8
#define SIGFRAME_SC_CR2         0xB0
#define SIGFRAME_SC_FPSTATE     0xB8   /* u64 指针 */
#define SIGFRAME_SC_RESERVED1   0xC0
#define SIGFRAME_UC_SIGMASK     0x128
#define SIGFRAME_UC_SIZE        0x130
#define SIGFRAME_FPSTATE_OFF    0x140  /* fpstate 位于 ucontext 之后, 64B 对齐 */
/* fpstate 内偏移 */
#define FPSTATE_SW_RESERVED     0x1D0  /* 464: _fpx_sw_bytes */
#define FPSTATE_MAGIC1          0x46505853
#define FPSTATE_MAGIC2          0x46505845
#define FPSTATE_XSTATE_BV       0x200  /* 512: xsave header xfeatures */
#define FPSTATE_XCOMP_BV        0x208  /* 520: xcomp_bv (必须为 0) */

#define USER_CS                 0x33
#define USER_SS                 0x2B

/* 指令计数: ioctl(ENABLE) 返回后到目标代码前 stub 执行的指令数 */
#define STUB_IPC_COMPENSATION   3

#endif /* ELFTRACE_STUB_H */
