/*
 * elftrace aarch64 恢复 stub (real 模式最小恢复链)
 *
 * 与 x86_64 版相同的 blob 布局 (见 elftrace_stub.h), 但寄存器为
 * aarch64 user_pt_regs (34x8 = 272B), 信号帧为 aarch64 rt_sigframe。
 *
 * 恢复流程 (_start → rt_sigreturn):
 *   1. 内存段: 逐段 mmap(MAP_FIXED|ANON|RW) + 拷贝 + mprotect
 *      ([stack] 段加 MAP_GROWSDOWN)
 *   2. munmap loader 初始栈 (解析 /proc/self/maps 的 [stack])
 *   3. fd: openat/dup2 重开
 *   4. RLIMIT_STACK 恢复
 *   5. TPIDR_EL0 (TLS): blob 是 RWX, jit `msr tpidr_el0, x0; ret`
 *      片段让目标架构执行 (用户态唯一能写 TPIDR_EL0 的方式)
 *   6. 构建 rt_sigframe (siginfo + ucontext + fpsimd) → sp = frame
 *      → svc #0 (rt_sigreturn 139), 内核恢复 x0-x30/sp/pc/pstate
 *
 * 寻址: blob 内一律 adrp+add :lo12:label (PIC); blob 可能 >1MB, 不能
 * 只用 adr。blob base 存 x9 (入口一次性计算)。
 *
 * syscall 约定: x8=号, x0-x5=参数, svc #0, 返回 x0 (负值即 -errno)。
 */
#include "elftrace_stub.h"

/* ---- aarch64 syscall 号 (asm-generic/unistd.h) ---- */
#define SYS_read       63
#define SYS_write      64
#define SYS_openat     56
#define SYS_close      57
#define SYS_lseek      62
#define SYS_mmap       222
#define SYS_mprotect   226
#define SYS_munmap     215
#define SYS_dup3       24
#define SYS_setrlimit  164
#define SYS_rt_sigreturn 139
#define SYS_rt_sigaction 134
#define SYS_brk         214
#define SYS_getpid      172
#define SYS_perf_event_open 241
#define SYS_fcntl      25

#define SIGIO          29
#define F_SETOWN       8
#define F_SETFL        4
#define O_ASYNC        0x2000

#define MAP_PRIVATE    0x02
#define MAP_ANON       0x20
#define MAP_FIXED      0x10
#define MAP_GROWSDOWN  0x0100
#define PROT_READ      0x1
#define PROT_WRITE     0x2
#define PROT_EXEC      0x4

#define AT_FDCWD       -100

/* ---- 段/fd 记录字段 (与 build.c 一致) ---- */
#define SEG_VADDR       0
#define SEG_FILESZ      8
#define SEG_MEMSZ       16
#define SEG_FLAGS       24
#define SEG_PAYLOAD_OFF 32

#define FD_FD           0
#define FD_FLAGS        8
#define FD_MODE         16
#define FD_POS          24
#define FD_PATH_LEN     32
#define FD_PATH_OFF     40

/* ---- aarch64 rt_sigframe 偏移 (frame 基) ----
 * struct rt_sigframe { siginfo(128B); ucontext; }
 * 内核 uapi struct ucontext:
 *   uc_flags(0x00) uc_link(0x08) uc_stack(0x10, 24B)
 *   uc_sigmask(0x28) ... uc_mcontext(0xB0)
 * sigcontext: fault(0) regs[31](0x08) sp(0x100) pc(0x108) pstate(0x110)
 *             __reserved(0x118, 4096B)  → 0x1118
 * (uapi 头显示 0xA8, 但 VM 实测内核把 mcontext 放在 0xB0 — 信号处理器
 * 里 glibc 读 uc_mcontext.pc 正确、raw 扫描在 0xB0+0x108 找到 pc;
 * 按 0x28 放 → pc/sp 读到零区 → badframe SIGSEGV)
 */
#define FRAME_UC         0x80
#define FRAME_UC_SIGMASK (FRAME_UC + 0x28)        /* 内核 8B sigset */
#define FRAME_SC         (FRAME_UC + 0xB0)        /* uc_mcontext (实测) */
#define FRAME_SC_REGS    (FRAME_SC + 0x08)        /* x0-x30 */
#define FRAME_SC_SP      (FRAME_SC + 0x100)
#define FRAME_SC_PC      (FRAME_SC + 0x108)
#define FRAME_SC_PSTATE  (FRAME_SC + 0x110)
#define FRAME_FPSIMD     (FRAME_SC + 0x120)       /* __reserved 起 (16B 对齐) */

#define FPSIMD_MAGIC     0x46508001
#define FPSIMD_CTX_SIZE  528                     /* 8 + 512 + 4 + 4 */
#define FPSIMD_DATA_SIZE 520                     /* vregs[32]+fpsr+fpcr */

.section .rst, "awx"

/* ===================== 恢复描述符 ===================== */
.org STUB_DESC_OFF
rst_desc:
    .quad RST_DESC_MAGIC_VAL   /* magic   @0x00 */
    .quad 1                    /* version @0x08 */
    .quad 0                    /* flags   @0x10 (builder 填) */
    .quad 0                    /* entry_pc @0x18 (builder 填) */
    .quad 0                    /* n_segs  @0x20 (builder 填) */
    .quad 0                    /* segs_off @0x28 (builder 填) */
    .quad 0                    /* n_fds   @0x30 (builder 填) */
    .quad 0                    /* fds_off @0x38 (builder 填) */
    .quad STUB_FPU_OFF         /* fpu_off @0x40 */
    .quad 0                    /* fpu_size @0x48 (builder 填) */
    .quad STUB_SIGMASK_OFF     /* sigmask_off @0x50 */
    .quad STUB_SIGACTS_OFF     /* sigacts_off @0x58 */
    .quad STUB_REGS_OFF        /* regs_off @0x60 */
    .quad 0                    /* ipc_period @0x68 (builder 填) */
    .quad 0                    /* ipc_fd @0x70 (stub 运行时填) */
    .quad 0                    /* ipc_buf_off @0x78 (stub 运行时填) */
    .quad 0                    /* mode @0x80 (builder 填) */
    .quad 0                    /* exit_addr @0x88 (builder 填) */
    .quad 0                    /* brk_base @0x90 (builder 填) */
    .quad 0                    /* target_tid @0x98 (builder 填) */
    .quad 0                    /* stack_vaddr @0xA0 (builder 填) */
    .quad 0                    /* rlim_stack_cur @0xA8 (builder 填) */
    .quad 0                    /* rlim_stack_max @0xB0 (builder 填) */
    .quad 0                    /* replay_off @0xB8 (builder 填) */
    .quad 0                    /* replay_size @0xC0 (builder 填) */
    .quad 0                    /* replay_cur @0xC8 (stub 运行时维护) */
    .quad 0                    /* tls @0xD0 (builder 填: aarch64 TPIDR_EL0) */
    .space 0x100 - (.-rst_desc)  /* 补足 256B */

/* ===================== FPU 状态 (NT_FPREGSET 528B) ===================== */
.org STUB_FPU_OFF
fpu_blob:
    .space STUB_FPU_CAP

/* ===================== 信号掩码 ===================== */
.org STUB_SIGMASK_OFF
sigmask_blob:
    .space 8

/* ===================== sigactions ===================== */
.org STUB_SIGACTS_OFF
sigacts_blob:
    .space STUB_SIGACTS_SIZE

/* ===================== 寄存器快照 (272B) ===================== */
.org STUB_REGS_OFF
regs_blob:
    .space STUB_REGS_SIZE

/* ===================== maps 解析缓冲 ===================== */
.org STUB_MAPS_BUF
maps_buf:
    .space STUB_MAPS_SIZE

/* ===================== perf 属性 ===================== */
.org STUB_IPC_ATTR
ipc_attr:
    .space 128

/* ===================== ipc sigaction ===================== */
.org STUB_IPC_SIGACT
ipc_sigact:
    .space 48

/* ===================== stub 栈 ===================== */
.org STUB_STACK_OFF
stub_stack:
    .space STUB_STACK_SIZE
stub_stack_top:
/* strict 回放期 stub 栈空闲, 复用为 syscall 回放调试环 (崩溃后可从
   core 读取最近回放的记录序列; 生产可移除) */
debug_ring = stub_stack

/* ===================== 信号帧 ===================== */
.org STUB_FRAME_OFF
stub_frame:
    .space STUB_FRAME_SIZE

/* ===================== 代码入口 ===================== */
.org STUB_ENTRY_OFF
.global _start
_start:
    /* 切到 blob 自带栈 */
    adrp x0, stub_stack_top
    add  x0, x0, :lo12:stub_stack_top
    mov  sp, x0

    /* x9 = blob base (全程保持); STUB_ENTRY_OFF 超 12 位立即数,
       movz/movk 组合 */
    adrp x9, _start
    add  x9, x9, :lo12:_start
    movz x10, #(STUB_ENTRY_OFF & 0xffff)
    movk x10, #(STUB_ENTRY_OFF >> 16), lsl #16
    sub  x9, x9, x10

    /* ======== 1. 恢复内存段 (strict baremetal: ELF loader 已建, 跳过) ======== */
    ldr  x0, [x9, #RST_DESC_MODE]
    ldr  x10, [x9, #RST_DESC_BM_STYLE]
    cmp  x0, #1
    bne  seg_restore_start
    cbz  x10, seg_restore_start
    b    seg_restore_skip
seg_restore_start:
    ldr  x14, [x9, #RST_DESC_N_SEGS]
    ldr  x15, [x9, #RST_DESC_SEGS_OFF]
    add  x15, x15, x9               /* x15 = segs 表绝对地址 */

seg_loop:
    cbz  x14, seg_done
    mov  x16, x15                   /* x16 = seg */

    /* mmap(vaddr, memsz, PROT_R|W, PRIVATE|ANON|FIXED[|GROWSDOWN], -1, 0) */
    ldr  x0, [x16]                  /* vaddr */
    ldr  x1, [x16, #SEG_MEMSZ]
    mov  x2, #(PROT_READ|PROT_WRITE)
    mov  x3, #(MAP_PRIVATE|MAP_ANON|MAP_FIXED)
    ldr  x4, [x9, #RST_DESC_STACK_VADDR]
    cbz  x4, 1f
    cmp  x0, x4
    bne  1f
    orr  x3, x3, #MAP_GROWSDOWN
1:
    mov  x4, #-1
    mov  x5, #0
    mov  x8, #SYS_mmap
    svc  #0
    tbnz x0, #63, seg_next          /* 映射失败则跳过该段 */

    /* memcpy(dst=mmap返回=vaddr, src=blob+payload_off, len=filesz) */
    ldr  x2, [x16, #SEG_FILESZ]
    ldr  x1, [x16, #SEG_PAYLOAD_OFF]
    add  x1, x1, x9                 /* src = blob + payload_off */
    bl   memcpy_bytes

    /* mprotect(vaddr, memsz, ET_SEG_* → PROT_*) */
    ldr  x0, [x16]
    ldr  x1, [x16, #SEG_MEMSZ]
    ldr  x2, [x16, #SEG_FLAGS]      /* ET: X=1 W=2 R=4 */
    mov  x3, #0
    tbz  x2, #0, 2f
    orr  x3, x3, #PROT_EXEC
2:
    tbz  x2, #1, 3f
    orr  x3, x3, #PROT_WRITE
3:
    tbz  x2, #2, 4f
    orr  x3, x3, #PROT_READ
4:
    mov  x2, x3
    mov  x8, #SYS_mprotect
    svc  #0

seg_next:
    add  x15, x15, #48
    sub  x14, x14, #1
    b    seg_loop

seg_done:
seg_restore_skip:
    /* ======== 2. munmap loader 初始栈 (暂禁) ======== */

    /* ======== 3. 恢复 fd ======== */
    ldr  x0, [x9, #RST_DESC_FLAGS]
    tbz  x0, #0, fd_done            /* RST_FLAG_RESTORE_FDS */
    ldr  x14, [x9, #RST_DESC_N_FDS]
    ldr  x15, [x9, #RST_DESC_FDS_OFF]
    add  x15, x15, x9

fd_loop:
    cbz  x14, fd_done
    ldr  x2, [x15, #FD_PATH_LEN]
    cbz  x2, fd_next                /* 不支持的 fd 类型: 跳过 */
    /* openat(AT_FDCWD, path, flags|O_LARGEFILE, mode) */
    mov  x0, #AT_FDCWD
    ldr  x1, [x15, #FD_PATH_OFF]
    add  x1, x1, x9                 /* path */
    ldr  x2, [x15, #FD_FLAGS]
    orr  x2, x2, #0x8000            /* O_LARGEFILE */
    ldr  x3, [x15, #FD_MODE]
    mov  x8, #SYS_openat
    svc  #0
    tbnz x0, #63, fd_next
    mov  x19, x0                    /* newfd */
    ldr  x4, [x15, #FD_POS]
    cbz  x4, 5f
    mov  x0, x19
    mov  x1, x4
    mov  x2, #0                     /* SEEK_SET */
    mov  x8, #SYS_lseek
    svc  #0
5:
    mov  x0, x19
    ldr  x1, [x15, #FD_FD]
    cmp  x19, x1
    beq  fd_next                    /* oldfd == target fd: 无需 dup */
    mov  x2, #0                     /* dup3 flags=0 (等价 dup2) */
    mov  x8, #SYS_dup3
    svc  #0
    mov  x0, x19
    mov  x8, #SYS_close
    svc  #0
fd_next:
    add  x15, x15, #48
    sub  x14, x14, #1
    b    fd_loop
fd_done:

    /* ======== 4.5 IPC 指令计数 (real 模式, perf) ======== */
    ldr  x0, [x9, #RST_DESC_FLAGS]
    tbz  x0, #2, ipc_done          /* RST_FLAG_IPC */
    ldr  x10, [x9, #RST_DESC_BM_STYLE]
    cbnz x10, ipc_done             /* strict: 无 perf/IPC syscall */
    bl   setup_ipc
ipc_done:

    /* ======== 4. RLIMIT_STACK ======== */
    ldr  x0, [x9, #RST_DESC_RLIM_STACK_CUR]
    cbz  x0, rlim_done
    adrp x19, rlimit_stack
    add  x19, x19, :lo12:rlimit_stack
    ldr  x0, [x9, #RST_DESC_RLIM_STACK_CUR]
    str  x0, [x19]
    ldr  x0, [x9, #RST_DESC_RLIM_STACK_MAX]
    str  x0, [x19, #8]
    mov  x0, #3                     /* RLIMIT_STACK */
    mov  x1, x19
    mov  x8, #SYS_setrlimit
    svc  #0
rlim_done:

    /* ======== 5. TPIDR_EL0 (TLS) ======== */
    ldr  x0, [x9, #RST_DESC_TLS]
    cbz  x0, tls_done
    adr  x16, tls_snippet
    blr  x16                        /* msr tpidr_el0, x0; ret */
tls_done:
    /* 安装 SIGTRAP 处理器 (baremetal: brk #0 → bm_handler) */
    ldr  x0, [x9, #RST_DESC_MODE]
    cbz  x0, 5f                    /* real 模式不装 */
    ldr  x10, [x9, #RST_DESC_BM_STYLE]
    cbnz x10, 5f                   /* strict 模式不装 (分支补偿, 无信号) */
    adrp x1, bm_sigact
    add  x1, x1, :lo12:bm_sigact   /* act */
    /* handler 需绝对地址: blob base + bm_handler 的 blob 偏移
       (bm_handler - _start + STUB_ENTRY_OFF, 如 0x6540; 超 12 位
       立即数, movz/movk 组合) */
    movz x10, #((bm_handler - _start + STUB_ENTRY_OFF) & 0xffff)
    movk x10, #((bm_handler - _start + STUB_ENTRY_OFF) >> 16), lsl #16
    add  x10, x10, x9
    str  x10, [x1]
    mov  x0, #5                    /* SIGTRAP */
    mov  x2, #0                    /* oact */
    mov  x3, #8                    /* sigsetsize */
    mov  x8, #SYS_rt_sigaction
    svc  #0
    tbnz x0, #63, bm_install_fail
5:
    /* ======== 6. 构建 rt_sigframe ======== */
    adrp x19, stub_frame
    add  x19, x19, :lo12:stub_frame /* x19 = frame */

    /* 清 frame (siginfo/ucontext/reserved 全零, 保证 terminator) */
    mov  x0, x19
    mov  x1, #STUB_FRAME_SIZE
    mov  x2, #0
    bl   memset_zero

    /* regs 272B: blob+REGS_OFF → frame+FRAME_SC_REGS (含 sp/pc/pstate) */
    add  x0, x19, #FRAME_SC_REGS   /* dst */
    ldr  x1, [x9, #RST_DESC_REGS_OFF]
    add  x1, x1, x9                /* src = blob + REGS_OFF */
    mov  x2, #STUB_REGS_SIZE
    bl   memcpy_bytes

    /* pstate 清 SS (bit21) */
    ldr  x0, [x19, #(FRAME_SC_PSTATE)]
    and  x0, x0, #~(1 << 21)
    str  x0, [x19, #(FRAME_SC_PSTATE)]

    /* fpsimd: NT_FPREGSET (528B, 数据 520B) → FRAME_FPSIMD
       {magic,size,vregs,fpsr,fpcr}。内核 restore_sigframe 强制要求
       frame 的 __reserved 含 fpsimd context (缺失 → -EINVAL →
       badframe → SIGSEGV)。 */
    ldr  x2, [x9, #RST_DESC_FPU_SIZE]
    cbz  x2, fpsimd_done
    mov  x3, #FPSIMD_DATA_SIZE
    cmp  x2, x3
    csel x2, x3, x2, gt           /* min(fpu_size, 520) */
    add  x0, x19, #FRAME_FPSIMD
    movz w1, #(FPSIMD_MAGIC & 0xffff)
    movk w1, #(FPSIMD_MAGIC >> 16), lsl #16
    str  w1, [x0]
    mov  w1, #FPSIMD_CTX_SIZE
    str  w1, [x0, #4]
    ldr  x1, [x9, #RST_DESC_FPU_OFF]
    add  x1, x1, x9               /* src */
    add  x0, x19, #(FRAME_FPSIMD + 8)
    bl   memcpy_bytes
fpsimd_done:

    /* sigmask (内核 ucontext: uc_sigmask @ uc+0x28) */
    ldr  x20, [x9, #RST_DESC_SIGMASK_OFF]
    add  x20, x20, x9
    ldr  x1, [x20]
    str  x1, [x19, #FRAME_UC_SIGMASK]

    /* 启用 perf 指令计数 (ioctl PERF_EVENT_IOC_ENABLE=0x2400) */
    ldr  x0, [x9, #RST_DESC_IPC_FD]
    cmn  x0, #1
    beq  ipc_enable_skip
    mov  x1, #PERF_EVENT_IOC_ENABLE
    mov  x2, #0
    mov  x8, #29                    /* SYS_ioctl */
    svc  #0
ipc_enable_skip:

    /* rt_sigreturn: aarch64 内核从 sp 取 frame */
    mov  sp, x19
    mov  x8, #SYS_rt_sigreturn
    svc  #0

    /* 不可达 */
    mov  x0, #0
    mov  x8, #94                    /* exit_group */
    svc  #0
    b    .

bm_install_fail:
    neg  x0, x0                    /* -errno → errno */
    mov  x8, #94
    svc  #0
    b    .

/* ===================== IPC (perf 指令计数) =====================
 * real 模式: perf_event_open 硬件指令事件 + SIGIO; 溢出后处理器
 * read(perf_fd) 取计数, 打印 "IPC: N instructions" 后 exit_group(0)。
 * 不需要 mmap 环形缓冲 (read 直接返回计数)。
 * 破坏 x0-x10, x19 (恢复前不被目标使用, stub 阶段无现场约束)。 */
setup_ipc:
    stp  x30, xzr, [sp, #-16]!      /* 保存返回地址 (内部 bl 会覆盖) */
    /* 安装 SIGIO 处理器: ipc_sigact = {handler, SA_SIGINFO, 0, 0} */
    adrp x10, ipc_handler
    add  x10, x10, :lo12:ipc_handler
    adrp x11, ipc_sigact
    add  x11, x11, :lo12:ipc_sigact
    str  x10, [x11]                /* sa_handler */
    mov  x10, #4                   /* SA_SIGINFO */
    str  x10, [x11, #8]            /* sa_flags */
    str  xzr, [x11, #16]           /* sa_restorer */
    str  xzr, [x11, #24]           /* sa_mask */
    mov  x0, #SIGIO
    mov  x1, x11
    mov  x2, #0                    /* oact */
    mov  x3, #8                    /* sigsetsize */
    mov  x8, #SYS_rt_sigaction
    svc  #0

    /* perf_event_attr (128B, 清零后填充) */
    adrp x19, ipc_attr
    add  x19, x19, :lo12:ipc_attr
    mov  x0, x19
    mov  x1, #128
    mov  x2, #0
    bl   memset_zero
    mov  w0, #0
    str  w0, [x19]                 /* type = PERF_TYPE_HARDWARE */
    mov  w0, #64
    str  w0, [x19, #4]             /* size = 64 */
    mov  x0, #1
    str  x0, [x19, #8]             /* config = PERF_COUNT_HW_INSTRUCTIONS */
    ldr  x0, [x9, #RST_DESC_IPC_PERIOD]
    add  x0, x0, #STUB_IPC_COMPENSATION
    str  x0, [x19, #16]            /* sample_period */
    mov  x0, #1
    str  x0, [x19, #24]            /* sample_type = PERF_SAMPLE_IP */
    mov  x0, #((1 << 0) | (1 << 5) | (1 << 6))
    str  x0, [x19, #40]            /* disabled|exclude_kernel|exclude_hv */
    mov  w0, #1
    str  w0, [x19, #48]            /* wakeup_events = 1 */

    /* perf_event_open(&attr, pid=0, cpu=-1, group=-1, flags=0) */
    mov  x0, x19
    mov  x1, #0
    mov  x2, #-1
    mov  x3, #-1
    mov  x4, #0
    mov  x8, #SYS_perf_event_open
    svc  #0
    tbnz x0, #63, ipc_no_perf
    mov  x19, x0                   /* perf fd */
    str  x0, [x9, #RST_DESC_IPC_FD]

    /* fcntl(fd, F_SETOWN, getpid()) */
    mov  x8, #SYS_getpid
    svc  #0
    mov  x2, x0
    mov  x0, x19
    mov  x1, #F_SETOWN
    mov  x8, #SYS_fcntl
    svc  #0
    /* fcntl(fd, F_SETFL, O_ASYNC) */
    mov  x0, x19
    mov  x1, #F_SETFL
    mov  x2, #O_ASYNC
    mov  x8, #SYS_fcntl
    svc  #0
    b    ipc_ok
ipc_no_perf:
    mov  x0, #-1
    str  x0, [x9, #RST_DESC_IPC_FD]
ipc_ok:
    ldp  x30, xzr, [sp], #16
    ret

/* SIGIO 处理器: 打印构建期指令数 (RST_DESC_IPC_PERIOD + 补偿) →
 * exit_group(0)。
 * 说明: aarch64 上 overflow 后 read(perf_fd) 返回的是复位以来的
 * 原始计数 (时序相关, 抖动可达一个周期), 不稳定; 打印静态周期值
 * 与 x86 测试语义一致 (IPC: N instructions, N == 请求值)。
 * 内核进入时 x0=sig, x1=siginfo, x2=ucontext, sp=信号帧。
 * 只使用 caller-saved 寄存器, 无需保存现场 (直接退出)。 */
ipc_handler:
    adrp x9, _start
    add  x9, x9, :lo12:_start
    movz x10, #(STUB_ENTRY_OFF & 0xffff)
    movk x10, #(STUB_ENTRY_OFF >> 16), lsl #16
    sub  x9, x9, x10

    ldr  x0, [x9, #RST_DESC_IPC_PERIOD]
    add  x0, x0, #STUB_IPC_COMPENSATION
    bl   utoa                       /* → bm_out_buf, 返回数字起点 */
    mov  x19, x0

    /* write(1, "IPC: ", 5) */
    adrp x1, ipc_prefix
    add  x1, x1, :lo12:ipc_prefix
    mov  x0, #1
    mov  x2, #5
    mov  x8, #SYS_write
    svc  #0
    /* write(1, digits, len) */
    mov  x1, x19
    adrp x2, bm_out_buf_end
    add  x2, x2, :lo12:bm_out_buf_end
    sub  x2, x2, x19
    mov  x0, #1
    mov  x8, #SYS_write
    svc  #0
    /* write(1, " instructions\n", 14) */
    adrp x1, ipc_suffix
    add  x1, x1, :lo12:ipc_suffix
    mov  x0, #1
    mov  x2, #14
    mov  x8, #SYS_write
    svc  #0
ipc_exit:
    mov  x0, #0
    mov  x8, #94                    /* exit_group */
    svc  #0
    b    .

1:  ldr  x16, [x16, #8]
    br   x16

/* ===================== baremetal SIGTRAP 处理器 =====================
 * 内核调用: x0=sig, x1=siginfo, x2=ucontext (帧在 sp, siginfo+ucontext)
 * 流程:
 *   1. 迁移内核信号帧 (~0x1200B) 到 STUB_FRAME_OFF 安全区
 *      (dirty 回放覆盖目标栈页时帧不被破坏; aarch64 fpsimd 内嵌在
 *      __reserved, 无需独立指针修正)
 *   2. trigger = sc->pc - 4 (brk 地址)
 *   3. 退出点 / exit_group → 真实退出
 *   4. 回放表命中: unmap/mmap+mprotect/dirty + x0=rec.rax, pc=rec.pc+4
 *   5. 无回放表: mock 路径按 x8 (syscall 号) 分派
 *   6. rt_sigreturn (sp = 迁移后的帧)
 *
 * 帧偏移 (内核构建的 handler 帧): siginfo@+0, ucontext@+0x80,
 * uc_mcontext@+0xB0 (实测), sc->pc@+0x108, sc->pstate@+0x110,
 * sc->regs[i]@+0x08+i*8。
 */
bm_handler:
    /* 处理器经内核信号投递进入, 目标寄存器已被恢复 — 重算 blob base */
    adrp x9, _start
    add  x9, x9, :lo12:_start
    movz x10, #(STUB_ENTRY_OFF & 0xffff)
    movk x10, #(STUB_ENTRY_OFF >> 16), lsl #16
    sub  x9, x9, x10

    mov  x19, sp                   /* 原帧 (目标栈上) */
    adrp x20, stub_frame
    add  x20, x20, :lo12:stub_frame  /* 迁移目标 */
    mov  x0, x20
    mov  x1, x19
    mov  x2, #0x1200
    bl   memcpy_bytes
    mov  sp, x20
    add  x21, x20, #0x130          /* sc = frame + 0x80 + 0xB0 */

    /* trigger = sc->pc (aarch64 brk 的 sigcontext pc = brk 地址本身,
       恢复时需 pc+4 跳过; 曾误按 -4 计算导致匹配错位/恢复回 brk 循环) */
    ldr  x22, [x21, #0x108]

    /* 退出点 (--to) */
    ldr  x23, [x9, #RST_DESC_EXIT_ADDR]
    cbz  x23, 1f
    cmp  x22, x23
    beq  bm_goto_exit
1:
    /* exit_group(94)/exit(93): 真实退出 */
    ldr  x0, [x21, #0x48]          /* sc->regs[8] = syscall 号 */
    cmp  x0, #94
    beq  bm_real_exit
    cmp  x0, #93
    beq  bm_real_exit

    /* 回放表 */
    ldr  x24, [x9, #RST_DESC_REPLAY_SIZE]
    cbz  x24, bm_mock_dispatch
    ldr  x24, [x9, #RST_DESC_REPLAY_OFF]
    add  x24, x24, x9              /* replay 起点 */
    ldr  x25, [x24]                /* n_recs */
    ldr  x26, [x9, #RST_DESC_REPLAY_CUR]
bm_replay_scan:
    cmp  x26, x25
    b.hs bm_replay_miss
    mov  x27, #80
    mul  x27, x26, x27
    add  x28, x24, x27
    add  x28, x28, #8              /* rec */
    ldr  x0, [x28]                 /* rec.pc */
    cmp  x0, x22
    beq  bm_replay_hit
    add  x26, x26, #1
    b    bm_replay_scan
bm_replay_hit:
    add  x26, x26, #1
    str  x26, [x9, #RST_DESC_REPLAY_CUR]

    /* unmap: munmap(vaddr, 1) */
    ldr  x10, [x28, #24]
    ldr  x11, [x28, #32]
    add  x11, x11, x24
bm_rp_unmap_loop:
    cbz  x10, bm_rp_newseg
    ldr  x0, [x11], #8
    mov  x1, #1
    mov  x8, #SYS_munmap
    svc  #0
    sub  x10, x10, #1
    b    bm_rp_unmap_loop

bm_rp_newseg:
    /* newseg: mmap(vaddr,memsz,RW,FIXED|ANON) + 拷贝 + mprotect */
    ldr  x10, [x28, #40]
    ldr  x11, [x28, #48]
    add  x11, x11, x24
bm_rp_newseg_loop:
    cbz  x10, bm_rp_dirty
    ldr  x0, [x11]                 /* vaddr */
    ldr  x1, [x11, #16]            /* memsz */
    mov  x2, #3
    mov  x3, #0x32
    mov  x4, #-1
    mov  x5, #0
    mov  x8, #SYS_mmap
    svc  #0
    ldr  x2, [x11, #8]             /* filesz */
    add  x1, x11, #32              /* src */
    bl   memcpy_bytes              /* dst=x0, src=x1, len=x2 */
    /* mprotect: ET_SEG(X=1,W=2,R=4) → PROT(R=1,W=2,X=4) */
    ldr  x0, [x11]
    ldr  x1, [x11, #16]
    ldr  x2, [x11, #24]
    mov  x3, #0
    tbz  x2, #0, 2f
    orr  x3, x3, #PROT_EXEC
2:  tbz  x2, #1, 3f
    orr  x3, x3, #PROT_WRITE
3:  tbz  x2, #2, 4f
    orr  x3, x3, #PROT_READ
4:  mov  x2, x3
    mov  x8, #SYS_mprotect
    svc  #0
    ldr  x2, [x11, #8]
    add  x11, x11, #32
    add  x11, x11, x2
    sub  x10, x10, #1
    b    bm_rp_newseg_loop

bm_rp_dirty:
    /* dirty: 整页覆盖 (数据内嵌 replay 区) */
    ldr  x10, [x28, #56]
    ldr  x11, [x28, #64]
    add  x11, x11, x24
bm_rp_dirty_loop:
    cbz  x10, bm_rp_done
    ldr  x0, [x11]                 /* dst */
    add  x1, x11, #8               /* src */
    mov  x2, #4096
    bl   memcpy_bytes
    add  x11, x11, #4096
    add  x11, x11, #8
    sub  x10, x10, #1
    b    bm_rp_dirty_loop

bm_rp_done:
    /* x0 = rec.rax; pc = rec.pc + 4 */
    ldr  x0, [x28, #16]
    str  x0, [x21, #0x08]          /* sc->regs[0] */
    ldr  x0, [x28]
    add  x0, x0, #4
    str  x0, [x21, #0x108]         /* sc->pc */
    b    bm_clear_ss_nopc

bm_replay_miss:
    /* 无回放记录: 回放表耗尽说明已到窗口外第一个 syscall,
       优雅退出 (窗口终点); 表未耗尽才是内部错误。 */
    cmp  x26, x25
    b.hs bm_goto_exit
    b    bm_unsupported

bm_real_exit:
    ldr  x0, [x21, #0x08]          /* sc->regs[0] = 退出码 */
    mov  x8, #94
    svc  #0
    b    .

bm_goto_exit:
    /* 退出点: 打印指令数后退出 (baremetal 数量为构建期静态值) */
    adrp x0, bm_exit_prefix
    add  x1, x0, :lo12:bm_exit_prefix
    mov  x0, #2
    mov  x2, #bm_exit_prefix_len
    mov  x8, #SYS_write
    svc  #0
    ldr  x0, [x9, #RST_DESC_IPC_PERIOD]
    adrp x1, bm_out_buf
    add  x1, x1, :lo12:bm_out_buf
    bl   utoa
    mov  x19, x0
    adrp x0, bm_out_buf_end
    add  x0, x0, :lo12:bm_out_buf_end
    sub  x2, x0, x19
    adrp x0, bm_out_buf
    add  x1, x0, :lo12:bm_out_buf
    mov  x0, #2
    mov  x8, #SYS_write
    svc  #0
    adrp x0, bm_exit_suffix
    add  x1, x0, :lo12:bm_exit_suffix
    mov  x0, #2
    mov  x2, #bm_exit_suffix_len
    mov  x8, #SYS_write
    svc  #0
    mov  x0, #0
    mov  x8, #94
    svc  #0
    b    .

bm_clear_ss:
    /* mock 路径: pc 跳过 brk (brk 的 sigcontext pc = brk 地址) */
    ldr  x0, [x21, #0x108]
    add  x0, x0, #4
    str  x0, [x21, #0x108]
bm_clear_ss_nopc:
    /* pstate 清 SS (bit21), 防单步风暴 */
    ldr  x0, [x21, #0x110]
    and  x0, x0, #~(1 << 21)
    str  x0, [x21, #0x110]
    b    bm_rt

bm_rt:
    mov  sp, x20
    mov  x8, #SYS_rt_sigreturn
    svc  #0
    b    .

/* ---- mock 路径 (无回放表): 按 x8 分派 ---- */
bm_mock_dispatch:
    ldr  x0, [x21, #0x48]          /* x8 = syscall 号 */
    cmp  x0, #94
    beq  bm_mock_exit
    cmp  x0, #93
    beq  bm_mock_exit
    cmp  x0, #63                   /* read → EOF */
    beq  bm_mock_zero
    cmp  x0, #64                   /* write → 假写全部 */
    beq  bm_mock_write
    cmp  x0, #66                   /* pwrite64 → 假写全部 */
    beq  bm_mock_write
    cmp  x0, #29                   /* ioctl → 0 */
    beq  bm_mock_zero
    cmp  x0, #25                   /* fcntl → 0 */
    beq  bm_mock_zero
    cmp  x0, #62                   /* lseek → 0 */
    beq  bm_mock_zero
    cmp  x0, #56                   /* openat → -ENOENT */
    beq  bm_mock_enoent
    cmp  x0, #57                   /* close → 0 */
    beq  bm_mock_zero
    cmp  x0, #222                  /* mmap → -ENOMEM */
    beq  bm_mock_enomem
    cmp  x0, #226                  /* mprotect → 0 */
    beq  bm_mock_zero
    cmp  x0, #215                  /* munmap → 0 */
    beq  bm_mock_zero
    cmp  x0, #214                  /* brk */
    beq  bm_mock_brk
    cmp  x0, #172                  /* getpid → target_tid */
    beq  bm_mock_getpid
    cmp  x0, #129                  /* kill → 0 */
    beq  bm_mock_zero
    cmp  x0, #134                  /* rt_sigaction → 0 */
    beq  bm_mock_zero
    cmp  x0, #135                  /* rt_sigprocmask → 0 */
    beq  bm_mock_zero
    b    bm_unsupported

bm_mock_exit:
    ldr  x0, [x21, #0x08]          /* 退出码 */
    mov  x8, #94
    svc  #0
    b    .

bm_mock_write:
    ldr  x0, [x21, #0x18]          /* sc->regs[2] = len */
    str  x0, [x21, #0x08]
    b    bm_clear_ss
bm_mock_zero:
    mov  x0, #0
    str  x0, [x21, #0x08]
    b    bm_clear_ss
bm_mock_enoent:
    mov  x0, #-2
    str  x0, [x21, #0x08]
    b    bm_clear_ss
bm_mock_enomem:
    mov  x0, #-12
    str  x0, [x21, #0x08]
    b    bm_clear_ss
bm_mock_getpid:
    ldr  x0, [x9, #RST_DESC_TARGET_TID]
    str  x0, [x21, #0x08]
    b    bm_clear_ss
bm_mock_brk:
    ldr  x0, [x21, #0x08]          /* sc->regs[0] = addr */
    ldr  x1, [x9, #RST_DESC_BRK_BASE]
    cbz  x0, 6f
    cmp  x0, x1
    b.ls 6f
    mov  x1, x0
    str  x1, [x9, #RST_DESC_BRK_BASE]
6:  str  x1, [x21, #0x08]
    b    bm_clear_ss

bm_unsupported:
    /* write(2, "elftrace baremetal: unsupported syscall ", len) */
    adrp x0, bm_err_prefix
    add  x1, x0, :lo12:bm_err_prefix
    mov  x0, #2
    mov  x2, #bm_err_prefix_len
    mov  x8, #SYS_write
    svc  #0
    ldr  x0, [x21, #0x48]          /* syscall 号 */
    adrp x1, bm_out_buf
    add  x1, x1, :lo12:bm_out_buf
    bl   utoa
    mov  x19, x0                   /* digits 起点 */
    adrp x0, bm_out_buf_end
    add  x0, x0, :lo12:bm_out_buf_end
    sub  x2, x0, x19               /* 长度 */
    adrp x0, bm_out_buf
    add  x1, x0, :lo12:bm_out_buf
    mov  x0, #2
    mov  x8, #SYS_write
    svc  #0
    adrp x0, bm_err_newline
    add  x1, x0, :lo12:bm_err_newline
    mov  x0, #2
    mov  x2, #1
    mov  x8, #SYS_write
    svc  #0
    mov  x0, #0x5e
    mov  x8, #94
    svc  #0
    b    .

/* utoa: x0 = 值 → 数字写入 bm_out_buf, 返回 x0 = 数字起点。
 * 破坏 x0-x5。 */
utoa:
    adrp x2, bm_out_buf_end
    add  x2, x2, :lo12:bm_out_buf_end
    strb wzr, [x2, #-1]!           /* 终止符 */
    mov  x3, #10
7:  udiv x4, x0, x3
    msub x5, x4, x3, x0
    add  w5, w5, #'0'
    strb w5, [x2, #-1]!
    mov  x0, x4
    cbnz x0, 7b
    mov  x0, x2                    /* 返回数字串起点 (含首位) */
    ret

/* ===================== baremetal 数据 ===================== */
bm_sigact:
    .quad bm_handler
    .quad 4                        /* SA_SIGINFO */
    .quad 0                        /* restorer */
    .quad 0                        /* mask */

bm_err_prefix:
    .ascii "elftrace baremetal: unsupported syscall "
bm_err_prefix_len = . - bm_err_prefix
bm_err_newline:
    .byte '\n'
bm_exit_prefix:
    .ascii "baremetal: "
bm_exit_prefix_len = . - bm_exit_prefix
bm_exit_suffix:
    .ascii " instructions\n"
bm_exit_suffix_len = . - bm_exit_suffix
ipc_prefix:
    .ascii "IPC: "
ipc_suffix:
    .ascii " instructions\n"
bm_out_buf:
    .space 24
bm_out_buf_end:
    .balign 4

/* ===================== 子过程 ===================== */

/* TLS jit 片段: TPIDR_EL0 用户态不能直接写, 但 blob 是 RWX,
 * 执行这条特权指令即可 (x0 = TLS 值)。 */
tls_snippet:
    msr  tpidr_el0, x0
    ret

/* memset_zero(dst=x0, len=x1, byte=x2) — 破坏 x0-x3 */
memset_zero:
    mov  x3, x0
    cbz  x1, 2f
1:
    strb w2, [x3], #1
    subs x1, x1, #1
    bne  1b
2:
    ret

/* memcpy_bytes(dst=x0, src=x1, len=x2) — 破坏 x0-x4 */
memcpy_bytes:
    cbz  x2, 3f
    lsr  x3, x2, #4
    cbz  x3, 5f
4:
    ldp  x4, x5, [x1], #16
    stp  x4, x5, [x0], #16
    subs x3, x3, #1
    bne  4b
5:
    and  x3, x2, #0xf
    cbz  x3, 3f
6:
    ldrb w4, [x1], #1
    strb w4, [x0], #1
    subs x3, x3, #1
    bne  6b
3:
    ret

/* 解析 /proc/self/maps, 找到 [stack] 行, munmap 之。
 * 破坏: x0-x8, x19-x20 */
unmap_initial_stack:
    /* openat(AT_FDCWD, "/proc/self/maps", O_RDONLY) */
    adrp x1, str_maps
    add  x1, x1, :lo12:str_maps
    mov  x0, #AT_FDCWD
    mov  x2, #0
    mov  x8, #SYS_openat
    svc  #0
    tbnz x0, #63, uis_done
    mov  x19, x0                    /* maps fd */
    mov  x0, x19
    adrp x1, maps_buf
    add  x1, x1, :lo12:maps_buf
    mov  x2, #STUB_MAPS_SIZE
    mov  x8, #SYS_read
    svc  #0
    mov  x20, x0                    /* 读取字节数 */
    mov  x0, x19
    mov  x8, #SYS_close
    svc  #0
    tbnz x20, #63, uis_done
    /* 在缓冲中查找 "[stack]" */
    adrp x0, maps_buf
    add  x0, x0, :lo12:maps_buf
    mov  x1, x20
    adrp x2, str_stack
    add  x2, x2, :lo12:str_stack
    mov  x3, #7
    bl   find_substr
    cbz  x0, uis_done
    /* 回退到该行行首 */
    mov  x1, x0
uis_line:
    cmp  x1, #0
    beq  uis_got
    ldrb w3, [x1, #-1]
    cmp  w3, #'\n'
    beq  uis_got
    sub  x1, x1, #1
    b    uis_line
uis_got:
    /* 解析行首 "start-end" (hex) */
    mov  x3, x1
    mov  x4, #0
uis_num:
    ldrb w5, [x3]
    cmp  w5, #'0'
    blo  uis_parse_done
    cmp  w5, #'9'
    bls  uis_digit
    cmp  w5, #'a'
    blo  uis_parse_done
    cmp  w5, #'f'
    bhi  uis_parse_done
    sub  w5, w5, #('a' - 10)
    b    uis_shift
uis_digit:
    sub  w5, w5, #'0'
uis_shift:
    lsl  x4, x4, #4
    orr  x4, x4, x5
    add  x3, x3, #1
    b    uis_num
uis_parse_done:
    /* x4 = start; 若下一个是 '-', 解析 end */
    ldrb w5, [x3]
    cmp  w5, #'-'
    bne  uis_done
    mov  x5, x4                     /* start */
    mov  x4, #0
    add  x3, x3, #1
uis_num2:
    ldrb w6, [x3]
    cmp  w6, #'0'
    blo  uis_end2
    cmp  w6, #'9'
    bls  uis_digit2
    cmp  w6, #'a'
    blo  uis_end2
    cmp  w6, #'f'
    bhi  uis_end2
    sub  w6, w6, #('a' - 10)
    b    uis_shift2
uis_digit2:
    sub  w6, w6, #'0'
uis_shift2:
    lsl  x4, x4, #4
    orr  x4, x4, x6
    add  x3, x3, #1
    b    uis_num2
uis_end2:
    sub  x6, x4, x5                 /* len */
    mov  x0, x5
    mov  x1, x6
    mov  x8, #SYS_munmap
    svc  #0
uis_done:
    ret

/* 移植 vvar: 找 segs 表 [vvar] 段 → 读 /proc/self/maps 找当前进程
 * [vvar] → memcpy 到恢复地址。strict 模式调用。
 * 破坏 x0-x8, x14-x20 (经 find_substr 还会破坏 x21-x27)。 */
transplant_vvar:
    stp  x19, x30, [sp, #-16]!      /* 保存调用者 x30 (bl 会覆盖) */
    /* 调试: 标记 transplant_vvar 已进入 */
    adrp x0, str_tvv_enter
    add  x1, x0, :lo12:str_tvv_enter
    mov  x0, #2
    mov  x2, #6
    mov  x8, #64
    svc  #0
    /* strings_off = fds_off + n_fds * 48 (elftrace_fd 48 字节;
       blob 内字符串池起点, seg.name_off 是快照字符串池偏移需叠加) */
    ldr  x16, [x9, #RST_DESC_N_FDS]
    ldr  x17, [x9, #RST_DESC_FDS_OFF]
    add  x17, x17, x16, lsl #5
    add  x17, x17, x16, lsl #4
    mov  x16, x17
    ldr  x14, [x9, #RST_DESC_N_SEGS]
    ldr  x15, [x9, #RST_DESC_SEGS_OFF]
    add  x15, x15, x9
tvv_seg_loop:
    cbz  x14, tvv_done
    ldr  x0, [x15, #40]             /* name_off (payload_off@32, name@40) */
    add  x0, x0, x16
    add  x0, x0, x9                 /* name */
    adrp x2, str_vvar
    add  x2, x2, :lo12:str_vvar
    mov  x1, #16
    mov  x3, #6
    bl   find_substr
    cbz  x0, tvv_next
    ldr  x19, [x15]                 /* seg vaddr */
    ldr  x20, [x15, #16]            /* memsz */
    b    tvv_read_maps
tvv_next:
    add  x15, x15, #48
    sub  x14, x14, #1
    b    tvv_seg_loop
tvv_read_maps:
    stp  x19, x20, [sp, #-16]!      /* 暂存 vaddr/memsz */
    adrp x1, str_maps
    add  x1, x1, :lo12:str_maps
    mov  x0, #AT_FDCWD
    mov  x2, #0
    mov  x8, #SYS_openat
    svc  #0
    tbnz x0, #63, tvv_pop_done
    mov  x19, x0                    /* fd */
    mov  x18, #0                    /* 偏移 (find_substr 不破坏 x18) */
tvv_map_loop:
    mov  x0, x19
    adrp x1, maps_buf
    add  x1, x1, :lo12:maps_buf
    mov  x2, #STUB_MAPS_SIZE
    mov  x3, x18
    mov  x8, #67                    /* pread64 */
    svc  #0
    tbnz x0, #63, tvv_map_done
    mov  x20, x0                    /* bytes */
    cbz  x20, tvv_map_done
    adrp x0, maps_buf
    add  x0, x0, :lo12:maps_buf
    mov  x1, x20
    adrp x2, str_vvar
    add  x2, x2, :lo12:str_vvar
    mov  x3, #6
    bl   find_substr
    cbnz x0, tvv_map_found
    cmp  x20, #STUB_MAPS_SIZE
    blt  tvv_map_done
    add  x18, x18, #(STUB_MAPS_SIZE - 512)  /* 重叠 512B 防行被截断 */
    b    tvv_map_loop
tvv_map_found:
    mov  x24, x0                    /* 保存匹配地址 (close 会破坏 x0) */
    /* 匹配落在重叠区 (前 512B) 时回退重搜, 保证行首在当前块内 */
    adrp x25, maps_buf
    add  x25, x25, :lo12:maps_buf
    sub  x25, x24, x25
    cmp  x25, #512
    b.hs 1f
    cmp  x18, #512
    blo  1f
    sub  x18, x18, #512
    b    tvv_map_loop
1:
    mov  x0, x19
    mov  x8, #57                    /* close */
    svc  #0
    /* 回退到该行行首 */
    mov  x1, x24
    b    tvv_line
tvv_map_done:
    mov  x0, x19
    mov  x8, #57                    /* close */
    svc  #0
    b    tvv_pop_done
tvv_line:
    cmp  x1, #0
    beq  tvv_parse
    ldrb w3, [x1, #-1]
    cmp  w3, #'\n'
    beq  tvv_parse
    sub  x1, x1, #1
    b    tvv_line
tvv_parse:
    /* 调试: dump [vvar] 行原始字节 (恢复阶段允许 write) */
    stp  x1, x30, [sp, #-16]!
    mov  x0, #2
    mov  x2, #96
    mov  x8, #64
    svc  #0
    ldp  x1, x30, [sp], #16
    mov  x3, x1
    mov  x4, #0
tvv_num:
    ldrb w5, [x3]
    cmp  w5, #'0'
    blo  tvv_parse_done
    cmp  w5, #'9'
    bls  tvv_digit
    cmp  w5, #'a'
    blo  tvv_parse_done
    cmp  w5, #'f'
    bhi  tvv_parse_done
    sub  w5, w5, #('a' - 10)
    b    tvv_shift
tvv_digit:
    sub  w5, w5, #'0'
tvv_shift:
    lsl  x4, x4, #4
    orr  x4, x4, x5
    add  x3, x3, #1
    b    tvv_num
tvv_parse_done:
    /* 恢复 vaddr/memsz; len = min(memsz, 0x4000) */
    ldp  x19, x20, [sp], #16
    /* 调试: dump 解析出的 src 原始字节 */
    adrp x0, debug_ring
    add  x0, x0, :lo12:debug_ring
    str  x4, [x0, #0x1000]
    add  x1, x0, #0x1000
    mov  x0, #2
    mov  x2, #8
    mov  x8, #64
    svc  #0
    mov  x0, x19
    mov  x1, x4                     /* src = 当前进程 vvar */
    mov  x2, x20
    cmp  x2, #0x4000
    bls  1f
    mov  x2, #0x4000
1:
    bl   memcpy_bytes
    b    tvv_done
tvv_pop_done:
    ldp  x19, x20, [sp], #16       /* 弹出第二层 (vaddr/memsz) */
tvv_done:
    ldp  x19, x30, [sp], #16
    ret

/* find_substr(haystack=x0, haylen=x1, needle=x2, needlelen=x3) → x0
 * 返回 needle 在 haystack 中的地址, 未找到返回 0。
 * 破坏 x0-x4, x21-x27 (needle/长度先存到 x21-x27, 防内层循环覆盖)。 */
find_substr:
    cbz  x3, 9f
    sub  x21, x1, x3
    add  x21, x21, #1               /* 外层剩余尝试次数 */
    cbz  x21, 9f
    mov  x22, x2                    /* needle */
    mov  x23, x3                    /* needlelen */
    mov  x24, x0                    /* hay 游标 */
    mov  x0, #0
10:
    mov  x25, x24                   /* 内层 hay 游标 */
    mov  x26, x22                   /* 内层 needle 游标 */
    mov  x27, x23                   /* 剩余 needle 长度 */
    mov  x0, #0
11:
    ldrb w1, [x25], #1
    ldrb w2, [x26], #1
    cmp  w1, w2
    bne  12f
    subs x27, x27, #1
    bne  11b
    mov  x0, x24
    ret
12:
    add  x24, x24, #1
    subs x21, x21, #1
    bne  10b
9:
    mov  x0, #0
    ret

/* ===================== 数据 ===================== */
str_maps:
    .asciz "/proc/self/maps"
str_stack:
    .asciz "[stack]"
str_vvar:
    .asciz "[vvar]"
str_tvv_enter:
    .asciz "TVVIN\n"
fake_clock:
    .quad 0
mock_spin_cnt:
    .quad 0
next_pending:
    .quad 0

rlimit_stack:
    .quad 0, 0

/* ===================== strict 专用区 (固定偏移) =====================
 * 布局 (由 elftrace_stub.h 的 STUB_STRICT_*_OFF 约定):
 *   STUB_STRICT_AREA_OFF: comp_engine (补偿引擎)
 *   STUB_STRICT_LOOP_OFF: loop_handler (循环跳板 counter)
 *   STUB_STRICT_EXIT_OFF: strict_exit_code (exit_group(0))
 * build 的跳板 literal 直接引用这些绝对偏移, 因此必须 .org 固定。 */
.org STUB_STRICT_AREA_OFF
/* ===================== strict baremetal: 补偿引擎 =====================
 * 跳板 (build 生成, 每站点 24B):
 *   ldr x16,[pc,#16]; ldr x17,[pc,#16]; br x17; .quad site_block; .quad comp_engine
 * 入口: x16 = site_block (blob 内绝对地址):
 *   [0]    站点 pc (回放表按 pc 匹配)
 *   [8]    ret_addr (svc 下一条)
 *   [16]   replay_abs (回放表起点)
 *   [24+r*8]  x0..x30 保存槽
 *   [272]  brk 边界 (mock)
 *   [280]  target_tid (mock getpid)
 *   [288]  回放游标 (站点 pc 的记录消费位置; 同 pc 多记录顺序消费)
 * 跳板入口已破坏 x16/x17 (IP0/IP1 约定破坏), 其余目标寄存器全部保存/恢复。
 * 补偿过程无任何 syscall (纯访存 + 退出除外)。 */
comp_engine:
    mov  x17, x16
    stp  x0, x1, [x17, #24]
    stp  x2, x3, [x17, #40]
    stp  x4, x5, [x17, #56]
    stp  x6, x7, [x17, #72]
    stp  x8, x9, [x17, #88]
    stp  x10, x11, [x17, #104]
    stp  x12, x13, [x17, #120]
    stp  x14, x15, [x17, #136]
    stp  x18, x19, [x17, #(24 + 18*8)]
    stp  x20, x21, [x17, #(24 + 20*8)]
    stp  x22, x23, [x17, #(24 + 22*8)]
    stp  x24, x25, [x17, #(24 + 24*8)]
    stp  x26, x27, [x17, #(24 + 26*8)]
    stp  x28, x29, [x17, #(24 + 28*8)]
    str  x30, [x17, #(24 + 30*8)]

    ldr  x16, [x17, #16]            /* replay_abs (0 = 无回放表 → mock) */
    cbz  x16, comp_mock
    ldr  x18, [x16]                 /* n_recs */
    ldr  x19, [x17, #288]           /* 游标 */
    ldr  x2, [x17, #0]              /* 站点 pc */
comp_scan:
    cmp  x19, x18
    b.hs comp_exhausted             /* 游标越界: 无记录 → 耗尽处理 */
    lsl  x0, x19, #4                /* *16 */
    lsl  x1, x0, #2                 /* *64 */
    add  x0, x0, x1                 /* *80 */
    add  x0, x16, x0
    add  x0, x0, #8                 /* rec */
    ldr  x20, [x0]                  /* rec.pc */
    cmp  x20, x2
    beq  comp_found
    add  x19, x19, #1
    b    comp_scan
comp_found:
    add  x19, x19, #1
    str  x19, [x17, #288]           /* 游标前进 (顺序消费) */
    /* 全局下一待回放索引 + 自旋计数复位 (顺序消费假设) */
    adrp x5, next_pending
    add  x5, x5, :lo12:next_pending
    str  x19, [x5]
    adrp x5, mock_spin_cnt
    add  x5, x5, :lo12:mock_spin_cnt
    str  xzr, [x5]
    mov  x23, x0                    /* rec 基址 (memcpy 会破坏 x0-x5) */

    /* 调试环: {站点 pc, rec_idx, sysno, rax} × 128 */
    adrp x24, debug_ring
    add  x24, x24, :lo12:debug_ring
    ldr  x25, [x24]                 /* head */
    add  x26, x25, #1
    str  x26, [x24]
    and  x26, x25, #127             /* slot = head & 127 */
    lsl  x26, x26, #5
    add  x26, x26, x24
    add  x26, x26, #8
    str  x2, [x26]                  /* 站点 pc */
    sub  x27, x19, #1
    str  x27, [x26, #8]             /* rec_idx */
    ldr  x27, [x23, #8]
    str  x27, [x26, #16]            /* sysno */
    ldr  x27, [x23, #16]
    str  x27, [x26, #24]            /* rax */

    /* newseg: 把记录数据写入预映射区 (纯访存) */
    ldr  x18, [x23, #40]            /* n_newseg */
    ldr  x19, [x23, #48]
    add  x19, x19, x16
comp_newseg_loop:
    cbz  x18, comp_dirty
    ldr  x20, [x19]                 /* vaddr */
    ldr  x21, [x19, #8]             /* filesz */
    add  x22, x19, #32              /* src */
    mov  x0, x20
    mov  x1, x22
    mov  x2, x21
    bl   memcpy_bytes
    add  x19, x19, #32
    add  x19, x19, x21
    sub  x18, x18, #1
    b    comp_newseg_loop
comp_dirty:
    ldr  x18, [x23, #56]            /* n_dirty */
    ldr  x19, [x23, #64]
    add  x19, x19, x16
comp_dirty_loop:
    cbz  x18, comp_done
    ldr  x20, [x19]                 /* dst */
    add  x21, x19, #8               /* src */
    mov  x0, x20
    mov  x1, x21
    mov  x2, #4096
    bl   memcpy_bytes
    add  x19, x19, #4096
    add  x19, x19, #8
    sub  x18, x18, #1
    b    comp_dirty_loop
comp_done:
    ldr  x1, [x23, #16]             /* rec.rax */
    str  x1, [x17, #24]             /* x0 槽 */
    b    comp_restore

comp_exhausted:
    /* 回放表耗尽: strict 模式 (站点块 [296] 由 build 写入 exit_abs)
       表示已到窗口外第一个 syscall → 优雅退出 (rc=0);
       非 strict 保持 0 → 旧 mock 路径 */
    ldr  x16, [x17, #296]
    cbz  x16, comp_mock
    br   x16

/* ---- mock (无回放表, freeze 快照) ---- */
comp_mock:
    ldr  x16, [x17, #16]            /* replay_abs (comp_exhausted 已破坏) */
    ldr  x2, [x17, #(24 + 8*8)]     /* 目标 x8 = syscall 号 */
    adrp x5, debug_ring
    add  x5, x5, :lo12:debug_ring
    str  x2, [x5, #0x1010]          /* 调试: 记录最近 mock sysno */
    /* mock 自旋检测: 同一 mock 站点连续命中超过阈值 (中间无真实回放)
       说明切片在 Python 级等待循环里空转 (等待并发线程设置的共享标志,
       普通字段读取无法按站点 patch)。此时按顺序提前应用下一条待回放
       记录的边界 diff, 把并发线程的写入补进内存, 让等待循环看到
       标志变化; 记录耗尽则直接严格退出 (rc=0)。 */
    adrp x5, mock_spin_cnt
    add  x5, x5, :lo12:mock_spin_cnt
    ldr  x3, [x5]
    add  x3, x3, #1
    str  x3, [x5]
    cmp  x3, #256
    b.lt mock_dispatch
    str  xzr, [x5]
    adrp x6, next_pending
    add  x6, x6, :lo12:next_pending
    ldr  x3, [x6]
    ldr  x4, [x16]                  /* n_recs */
    cmp  x3, x4
    b.hs mock_exhausted_exit
    /* 应用记录 x3 的边界 diff (newseg + dirty, 纯访存) */
    mov  x4, #80
    mul  x4, x3, x4
    add  x4, x4, x16
    add  x4, x4, #8                 /* x4 = rec base */
    ldr  x18, [x4, #40]             /* n_newseg */
    ldr  x19, [x4, #48]
    add  x19, x19, x16
mock_ns_loop:
    cbz  x18, mock_dirty
    ldr  x20, [x19]                 /* vaddr */
    ldr  x21, [x19, #8]             /* filesz */
    add  x22, x19, #32              /* src */
    mov  x0, x20
    mov  x1, x22
    mov  x2, x21
    bl   memcpy_bytes
    add  x19, x19, #32
    add  x19, x19, x21
    sub  x18, x18, #1
    b    mock_ns_loop
mock_dirty:
    ldr  x18, [x4, #56]             /* n_dirty */
    ldr  x19, [x4, #64]
    add  x19, x19, x16
mock_dirty_loop:
    cbz  x18, mock_applied
    ldr  x20, [x19]                 /* dst */
    add  x21, x19, #8               /* src */
    mov  x0, x20
    mov  x1, x21
    mov  x2, #4096
    bl   memcpy_bytes
    add  x19, x19, #4096
    add  x19, x19, #8
    sub  x18, x18, #1
    b    mock_dirty_loop
mock_applied:
    adrp x7, debug_ring
    add  x7, x7, :lo12:debug_ring
    ldr  x5, [x7, #0x1018]
    add  x5, x5, #1
    str  x5, [x7, #0x1018]          /* 调试: 自旋应用次数 */
    add  x3, x3, #1
    str  x3, [x6]                   /* next_pending 前进 (顺序应用) */
    ldr  x2, [x17, #(24 + 8*8)]     /* 重新装载 sysno */
mock_dispatch:
    cmp  x2, #94
    beq  comp_mock_exit
    cmp  x2, #93
    beq  comp_mock_exit
    cmp  x2, #63                    /* read → 0 */
    beq  comp_mock_zero
    cmp  x2, #64                    /* write → len */
    beq  comp_mock_write
    cmp  x2, #66                    /* pwrite64 → len */
    beq  comp_mock_write
    cmp  x2, #29                    /* ioctl → 0 */
    beq  comp_mock_zero
    cmp  x2, #25                    /* fcntl → 0 */
    beq  comp_mock_zero
    cmp  x2, #62                    /* lseek → 0 */
    beq  comp_mock_zero
    cmp  x2, #56                    /* openat → -ENOENT */
    beq  comp_mock_enoent
    cmp  x2, #57                    /* close → 0 */
    beq  comp_mock_zero
    cmp  x2, #222                   /* mmap → -ENOMEM */
    beq  comp_mock_enomem
    cmp  x2, #226                   /* mprotect → 0 */
    beq  comp_mock_zero
    cmp  x2, #215                   /* munmap → 0 */
    beq  comp_mock_zero
    cmp  x2, #214                   /* brk */
    beq  comp_mock_brk
    cmp  x2, #172                   /* getpid → target_tid */
    beq  comp_mock_getpid
    cmp  x2, #129                   /* kill → 0 */
    beq  comp_mock_zero
    cmp  x2, #134                   /* rt_sigaction → 0 */
    beq  comp_mock_zero
    cmp  x2, #135                   /* rt_sigprocmask → 0 */
    beq  comp_mock_zero
    cmp  x2, #113                   /* clock_gettime → 伪单调时钟 */
    beq  comp_mock_clock
    cmp  x2, #98                    /* futex → 0 (维持前进) */
    beq  comp_mock_zero
    cmp  x2, #233                   /* madvise → 0 */
    beq  comp_mock_zero
    cmp  x2, #278                   /* getrandom → -EAGAIN */
    beq  comp_mock_again
    cmp  x2, #79                    /* getcwd → "/" */
    beq  comp_mock_getcwd
    /* 未支持: -ENOSYS (不能真实 exit, strict 禁止额外 syscall) */
    adrp x5, debug_ring
    add  x5, x5, :lo12:debug_ring
    str  x2, [x5, #0x1008]          /* 调试: 记录未支持 sysno */
    mov  x1, #-38
    b    comp_mock_set
comp_mock_again:
    mov  x1, #-11
    b    comp_mock_set
comp_mock_getcwd:
    ldr  x1, [x17, #(24 + 1*8)]     /* 目标 x1 = buf */
    mov  w2, #'/'
    strb w2, [x1]
    mov  w2, #0
    strb w2, [x1, #1]
    mov  x1, #2                     /* 返回长度 */
    b    comp_mock_set
comp_mock_exit:
    ldr  x0, [x17, #24]             /* 目标 x0 = 退出码 */
    mov  x8, #94
    svc  #0
    b    .
mock_exhausted_exit:
    /* 回放记录已全部应用而切片仍在 mock 自旋: 窗口内容已耗尽,
       直接严格退出 (rc=0) */
    adrp x5, _start
    add  x5, x5, :lo12:_start
    movz x6, #(STUB_ENTRY_OFF & 0xffff)
    movk x6, #(STUB_ENTRY_OFF >> 16), lsl #16
    sub  x5, x5, x6
    movz x6, #(STUB_STRICT_EXIT_OFF & 0xffff)
    add  x5, x5, x6
    br   x5
comp_mock_write:
    ldr  x1, [x17, #(24 + 2*8)]     /* 目标 x2 = len */
    b    comp_mock_set
comp_mock_zero:
    mov  x1, #0
    b    comp_mock_set
comp_mock_enoent:
    mov  x1, #-2
    b    comp_mock_set
comp_mock_enomem:
    mov  x1, #-12
    b    comp_mock_set
comp_mock_getpid:
    ldr  x1, [x17, #280]
    b    comp_mock_set
comp_mock_brk:
    ldr  x2, [x17, #24]             /* 目标 x0 = addr */
    ldr  x1, [x17, #272]            /* 边界/当前 */
    cbz  x2, 1f
    cmp  x2, x1
    b.hi 1f
    str  x2, [x17, #272]
    mov  x1, x2
1:
comp_mock_clock:
    /* clock_gettime(id, ts): 伪单调时钟 = 0x40000000 + 调用计数 (秒)。
       恢复内存里的 deadline 是录制时的真实时间 (~30871s), 大基数让
       绝对 deadline 立即过期; 相对超时循环 (start+0.5) 因每次调用
       +1s 也在 1-2 次内退出。 */
    ldr  x1, [x17, #(24 + 1*8)]     /* 目标 x1 = ts 缓冲区 */
    adrp x2, fake_clock
    add  x2, x2, :lo12:fake_clock
    ldr  x3, [x2]
    add  x3, x3, #1
    str  x3, [x2]
    movz x4, #0x4000, lsl #16       /* 0x40000000 */
    add  x3, x3, x4
    str  x3, [x1]                   /* tv_sec = 基数 + 计数 */
    str  xzr, [x1, #8]              /* tv_nsec = 0 */
    mov  x1, #0                     /* 返回值 0 */
    b    comp_mock_set
comp_mock_set:
    str  x1, [x17, #24]             /* x0 槽 */

comp_restore:
    ldr  x0, [x17, #24]             /* 恢复目标 x0 (返回值, 已由引擎设置) */
    ldr  x16, [x17, #8]             /* ret_addr */
    ldp  x1, x2, [x17, #32]
    ldp  x3, x4, [x17, #48]
    ldp  x5, x6, [x17, #64]
    ldp  x7, x8, [x17, #80]
    ldp  x9, x10, [x17, #96]
    ldp  x11, x12, [x17, #112]
    ldp  x13, x14, [x17, #128]
    ldp  x15, x18, [x17, #144]
    ldp  x19, x20, [x17, #(24 + 19*8)]
    ldp  x21, x22, [x17, #(24 + 21*8)]
    ldp  x23, x24, [x17, #(24 + 23*8)]
    ldp  x25, x26, [x17, #(24 + 25*8)]
    ldp  x27, x28, [x17, #(24 + 27*8)]
    ldp  x29, x30, [x17, #(24 + 29*8)]
    br   x16

.org STUB_STRICT_LOOP_OFF
/* ===================== strict: 循环跳板 handler =====================
 * 跳板: ldr x16,[pc,#8]; br x16; .quad loop_block
 * loop_block: [0] counter(32), [8] loop_head, [16] exit_code
 * 每次经过回边 counter--; 非 0 → 跳回循环头; 0 → 退出。
 * 破坏 x16 (目标原值已由跳板破坏) 与 x17 (counter 值)。 */
loop_handler:
    ldr  w17, [x16]
    sub  w17, w17, #1
    str  w17, [x16]
    cbnz w17, 1f
    ldr  x16, [x16, #16]
    br   x16
1:  ldr  x16, [x16, #8]
    br   x16

/* ===================== strict: 目标指令计数跳板 =====================
 * while 型循环 (回边条件分支) 的退出: patch 目标指令 P → b <跳板>,
 * count_handler 每执行到 P 递减 counter; 到 0 → 退出; 否则执行
 * 原始指令 (blob 内副本) 后跳回 P+4, 循环自身语义完全保留。
 * block (40B): [0] counter, [8] exit_code, [16] 原指令,
 *              [20] ldr x16,[pc,#12], [24] br x16, [28] nop,
 *              [32] ret_addr (P+4)
 * 破坏 x16/x17 (跳板入口已破坏), 不碰 flags。 */
.org STUB_STRICT_COUNT_OFF
count_handler:
    ldr  w17, [x16]
    sub  w17, w17, #1
    str  w17, [x16]
    cbnz w17, 1f
    ldr  x16, [x16, #8]
    br   x16
1:  add  x16, x16, #16
    br   x16

/* ===================== strict: 退出代码 =====================
 * 唯一路径退出/循环结束跳到这里: 真实 exit_group(0)。 */
.org STUB_STRICT_EXIT_OFF
strict_exit_code:
    mov  x0, #0
    mov  x8, #94
    svc  #0
    b    .

/* 代码区末尾: 补齐到固定区大小 */
    .org STUB_FIXED_SIZE
