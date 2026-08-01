/*
 * elftrace x86_64 恢复 stub
 *
 * 自包含 PIC 汇编, 由 build 工具作为生成的 ELF 的入口。
 *
 * 执行流程:
 *   1. 切换到 blob 自带栈
 *   2. 恢复内存段: 对每个段 mmap(MAP_FIXED|ANON) + 拷贝 payload + mprotect
 *   3. munmap loader 初始栈 (解析 /proc/self/maps 中的 [stack])
 *   4. 恢复 fd: 按路径重新打开 + lseek + dup2
 *   5. 恢复 sigactions
 *   6. arch_prctl 恢复 fs_base/gs_base
 *   7. 构建 rt_sigreturn 信号帧 (GPR + eflags + rip + rsp + sigmask + fpstate)
 *   8. (可选 IPC) perf_event_open 指令计数, SIGIO 溢出自动退出
 *   9. rt_sigreturn: 内核一次性恢复所有寄存器 + 信号掩码 + FPU 状态
 *
 * 所有 syscall 通过裸 syscall 指令完成; 循环状态保存在 syscall 不破坏的
 * rbx/r12-r15 中。rt_sigreturn 由内核完成 GPR/eflags/rsp/rip/sigmask/
 * xstate 的恢复, 因此 stub 无需手动恢复 GPR。
 */
#include "elftrace_stub.h"

/* ---- x86_64 syscall 号 ---- */
#define SYS_read           0
#define SYS_write          1
#define SYS_close          3
#define SYS_lseek          8
#define SYS_mmap           9
#define SYS_mprotect       10
#define SYS_munmap         11
#define SYS_rt_sigaction   13
#define SYS_rt_sigprocmask 14
#define SYS_rt_sigreturn   15
#define SYS_ioctl          16
#define SYS_getpid         39
#define SYS_dup2           33
#define SYS_fcntl          72
#define SYS_arch_prctl     158
#define SYS_exit_group     231
#define SYS_openat         257
#define SYS_perf_event_open 298

#define PROT_READ   0x1
#define PROT_WRITE  0x2
#define PROT_EXEC   0x4
#define MAP_PRIVATE 0x2
#define MAP_ANON    0x20
#define MAP_FIXED   0x10
#define MAP_SHARED  0x1
#define AT_FDCWD    (-100)

#define ARCH_SET_FS 0x1002
#define ARCH_SET_GS 0x1001

#define SIGIO       29
#define SA_RESTORER 0x04000000
#define SIGKILL     9
#define SIGSTOP     19
#define SIG_SETMASK 2

#define F_SETOWN    8
#define F_SETFL     4
#define O_ASYNC     0x2000

/* 段记录字段 (elftrace_seg, 48 字节) */
#define SEG_VADDR   0
#define SEG_FILESZ  8
#define SEG_MEMSZ   16
#define SEG_FLAGS   24
#define SEG_PAYLOAD_OFF 32

/* fd 记录字段 (elftrace_fd) */
#define FD_FD       0
#define FD_FLAGS    8
#define FD_MODE     16
#define FD_POS      24
#define FD_PATH_LEN 32
#define FD_PATH_OFF 40

/* sigact 记录字段 (elftrace_sigact, 内核 k_sigaction 前 32B) */
#define SA_HANDLER  0
#define SA_FLAGS    8
#define SA_RESTORER_FIELD 16
#define SA_MASK     24

.section .rst, "awx"

/* ===================== 恢复描述符 ===================== */
.org STUB_DESC_OFF
rst_desc:
    .quad RST_DESC_MAGIC_VAL   /* magic   @0x00 */
    .quad 1                    /* version @0x08 */
    .quad 0                    /* flags   @0x10 (builder 填) */
    .quad 0                    /* rip     @0x18 (builder 填) */
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

/* ===================== FPU 状态 ===================== */
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

/* ===================== 寄存器快照 ===================== */
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

/* ===================== 信号帧 ===================== */
.org STUB_FRAME_OFF
sigframe:
    .space STUB_FRAME_SIZE

/* ===================== 代码入口 ===================== */
.org STUB_ENTRY_OFF
.global _start
_start:
    /* 切换到 blob 自带栈 (不再使用 loader 初始栈) */
    lea stub_stack_top(%rip), %rsp
    cld

    /* ======== 1. 恢复内存段 ======== */
    movq rst_desc+RST_DESC_N_SEGS(%rip), %r14
    movq rst_desc+RST_DESC_SEGS_OFF(%rip), %r15
    call 1f
1:  popq %rax
    subq $(1b - _start), %rax      /* rax = 本指令绝对地址 */
    subq $STUB_ENTRY_OFF, %rax     /* rax = blob base */
    movq %rax, %rbx                /* rbx = blob base (全程保持) */
    addq %rbx, %r15                /* r15 = segs 表绝对地址 */

seg_loop:
    testq %r14, %r14
    jz seg_done
    movq %r15, %r12                /* r12 = seg */

    /* mmap(vaddr, memsz, PROT_R|W, MAP_PRIVATE|ANON|FIXED, -1, 0) */
    movq SEG_VADDR(%r12), %rdi
    movq SEG_MEMSZ(%r12), %rsi
    movq $6, %rdx                  /* PROT_READ|PROT_WRITE */
    movq $(MAP_PRIVATE|MAP_ANON|MAP_FIXED), %r10
    movq $-1, %r8
    xorq %r9, %r9
    movq $SYS_mmap, %rax
    syscall
    testq %rax, %rax
    js seg_next                    /* 映射失败则跳过该段 */

    /* memcpy(base + payload_off -> vaddr, filesz) */
    movq SEG_PAYLOAD_OFF(%r12), %rsi
    addq %rbx, %rsi
    movq SEG_VADDR(%r12), %rdi
    movq SEG_FILESZ(%r12), %rcx
    rep movsb

    /* mprotect(vaddr, memsz, 转换后的 PROT_*) */
    movq SEG_VADDR(%r12), %rdi
    movq SEG_MEMSZ(%r12), %rsi
    movq SEG_FLAGS(%r12), %rdx
    xorq %rcx, %rcx
    testq $1, %rdx                 /* PF_X -> PROT_EXEC */
    jz 2f
    orq $PROT_EXEC, %rcx
2:  testq $2, %rdx                 /* PF_W -> PROT_WRITE */
    jz 3f
    orq $PROT_WRITE, %rcx
3:  testq $4, %rdx                 /* PF_R -> PROT_READ */
    jz 4f
    orq $PROT_READ, %rcx
4:  movq %rcx, %rdx
    movq $SYS_mprotect, %rax
    syscall

seg_next:
    addq $48, %r15
    decq %r14
    jmp seg_loop

seg_done:

    /* ======== 2. munmap loader 初始栈 ======== */
    call unmap_initial_stack

    /* ======== 3. 恢复 fd ======== */
    movq rst_desc+RST_DESC_FLAGS(%rip), %rax
    testq $RST_FLAG_RESTORE_FDS, %rax
    jz fd_done
    movq rst_desc+RST_DESC_N_FDS(%rip), %r14
    movq rst_desc+RST_DESC_FDS_OFF(%rip), %r15
    addq %rbx, %r15

fd_loop:
    testq %r14, %r14
    jz fd_done
    movq %r15, %r12                /* r12 = fdrec */
    movq FD_PATH_LEN(%r12), %r13
    testq %r13, %r13
    jz fd_next                     /* 不支持的类型, 跳过 */

    /* openat(AT_FDCWD, path, flags, mode) */
    movq $AT_FDCWD, %rdi
    movq FD_PATH_OFF(%r12), %rsi
    addq %rbx, %rsi
    movq FD_FLAGS(%r12), %rdx
    movq FD_MODE(%r12), %r10
    movq $SYS_openat, %rax
    syscall
    testq %rax, %rax
    js fd_next
    movq %rax, %r13                /* r13 = 新 fd */

    /* lseek(newfd, pos, SEEK_SET) */
    movq %r13, %rdi
    movq FD_POS(%r12), %rsi
    xorq %rdx, %rdx
    movq $SYS_lseek, %rax
    syscall

    /* dup2(newfd, target_fd) */
    movq %r13, %rdi
    movq FD_FD(%r12), %rsi
    movq $SYS_dup2, %rax
    syscall

    /* 若 newfd == target_fd, dup2 是 no-op, 不能 close */
    cmpq FD_FD(%r12), %r13
    je fd_next_keep

    /* close(newfd) */
    movq %r13, %rdi
    movq $SYS_close, %rax
    syscall

fd_next_keep:
fd_next:
    addq $48, %r15
    decq %r14
    jmp fd_loop

fd_done:

    /* ======== 4. 恢复 sigactions ======== */
    movq rst_desc+RST_DESC_FLAGS(%rip), %rax
    testq $RST_FLAG_RESTORE_SIGACTS, %rax
    jz sa_done
    lea sigacts_blob(%rip), %r12
    movq $1, %r13                   /* sig = 1 */
sa_loop:
    cmpq $64, %r13
    jg sa_done
    cmpq $SIGKILL, %r13
    je sa_next
    cmpq $SIGSTOP, %r13
    je sa_next
    movq SA_HANDLER(%r12), %rax
    testq %rax, %rax
    jz sa_next
    /* rt_sigaction(sig, act, NULL, 8) */
    movq %r13, %rdi
    movq %r12, %rsi
    xorq %rdx, %rdx
    movq $8, %r10
    movq $SYS_rt_sigaction, %rax
    syscall
sa_next:
    addq $40, %r12
    incq %r13
    jmp sa_loop
sa_done:

    /* ======== 5. 恢复 fs_base / gs_base ======== */
    movq regs_blob+PT_REGS_FS_BASE(%rip), %rsi
    testq %rsi, %rsi
    jz 5f
    movq $ARCH_SET_FS, %rdi
    movq $SYS_arch_prctl, %rax
    syscall
5:  movq regs_blob+PT_REGS_GS_BASE(%rip), %rsi
    testq %rsi, %rsi
    jz 6f
    movq $ARCH_SET_GS, %rdi
    movq $SYS_arch_prctl, %rax
    syscall
6:

    /* ======== 6. (可选) IPC 指令计数 ======== */
    movq rst_desc+RST_DESC_IPC_PERIOD(%rip), %rax
    testq %rax, %rax
    jz ipc_done
    call setup_ipc

ipc_done:

    /* ======== 7. 构建 rt_sigreturn 信号帧 ======== */
    call build_sigframe            /* r14 = sigframe base, r13 = fpstate */

    /* ======== 8. (可选) 启用 perf 计数 ======== */
    movq rst_desc+RST_DESC_IPC_FD(%rip), %rdi
    cmpq $-1, %rdi
    je 7f
    movq $PERF_EVENT_IOC_ENABLE, %rsi
    xorq %rdx, %rdx
    movq $SYS_ioctl, %rax
    syscall
7:
    /* ======== 9. rt_sigreturn ======== */
    movq %r14, %rsp                /* rsp = &ucontext */
    movq $SYS_rt_sigreturn, %rax
    syscall

    /* 不可达 */
    movq $SYS_exit_group, %rax
    xorq %rdi, %rdi
    syscall

/* ===================== 子过程 ===================== */

/*
 * 解析 /proc/self/maps, 找到 [stack] 行, munmap 之。
 * 破坏: rax rcx rdx rsi rdi r8 r9 r10 r11 r12 r13
 */
unmap_initial_stack:
    movq $AT_FDCWD, %rdi
    lea str_maps(%rip), %rsi
    xorq %rdx, %rdx
    xorq %r10, %r10
    movq $SYS_openat, %rax
    syscall
    testq %rax, %rax
    js uis_done
    movq %rax, %r12                /* r12 = maps fd */
    movq %r12, %rdi
    lea maps_buf(%rip), %rsi
    movq $STUB_MAPS_SIZE, %rdx
    movq $SYS_read, %rax
    syscall
    movq %rax, %r13                /* r13 = 读取字节数 */
    movq %r12, %rdi
    movq $SYS_close, %rax
    syscall
    testq %r13, %r13
    jle uis_done
    /* 在缓冲中查找 "[stack]" */
    lea maps_buf(%rip), %rdi
    movq %r13, %rcx
    lea str_stack(%rip), %rsi
    movq $7, %rdx
    call find_substr
    testq %rax, %rax
    jz uis_done
    /* 回退到行首 */
    movq %rax, %rsi
uis_line_start:
    lea maps_buf(%rip), %rcx
    cmpq %rcx, %rsi
    je uis_got_start
    decq %rsi
    cmpb $'\n', (%rsi)
    je uis_got_start
    jmp uis_line_start
uis_got_start:
    incq %rsi                       /* rsi = 行首 (start 十六进制) */
    call parse_hex
    movq %rax, %r12                 /* r12 = start */
    cmpb $'-', (%rsi)
    jne uis_done
    incq %rsi
    call parse_hex                  /* rax = end */
    subq %r12, %rax                 /* rax = len */
    movq %r12, %rdi
    movq %rax, %rsi
    movq $SYS_munmap, %rax
    syscall
uis_done:
    ret

/*
 * rsi 指向十六进制串, 解析到非十六进制字符为止。
 * 返回 rax = 值, rsi 前进。破坏 rcx。
 */
parse_hex:
    xorq %rax, %rax
ph_loop:
    movzbl (%rsi), %ecx
    cmpb $'0', %cl
    jb ph_done
    cmpb $'9', %cl
    ja ph_alpha
    subb $'0', %cl
    jmp ph_add
ph_alpha:
    cmpb $'a', %cl
    jb ph_alpha2
    cmpb $'f', %cl
    ja ph_alpha2
    subb $'a'-10, %cl
    jmp ph_add
ph_alpha2:
    cmpb $'A', %cl
    jb ph_done
    cmpb $'F', %cl
    ja ph_done
    subb $'A'-10, %cl
ph_add:
    shlq $4, %rax
    addq %rcx, %rax
    incq %rsi
    jmp ph_loop
ph_done:
    ret

/*
 * find_substr: rdi=haystack, rcx=len, rsi=needle, rdx=needle_len
 * 返回 rax = 匹配位置 (0 = 未找到)。破坏 rcx rdx rdi rsi r8 r9 r10 r11。
 */
find_substr:
    movq %rdi, %r8                  /* r8 = haystack */
    movq %rcx, %r9                  /* r9 = haystack len */
    movq %rsi, %r10                 /* r10 = needle */
    movq %rdx, %r11                 /* r11 = needle len */
    movq %rdi, %rax
fs_outer:
    cmpq %r9, %rax
    jae fs_fail
    movq %rax, %rdi
    movq %r10, %rsi
    movq %r11, %rcx
    repe cmpsb
    je fs_found
    incq %rax
    jmp fs_outer
fs_found:
    ret
fs_fail:
    xorq %rax, %rax
    ret

/*
 * 恢复 fd 后调用。若 perf_event_open 不可用则 ipc_fd = -1。
 * 破坏 rax rcx rdx rsi rdi r8 r9 r10 r11 r12。
 */
setup_ipc:
    /* 安装 SIGIO 处理器 (x86_64 内核要求 SA_RESTORER, 否则拒绝投递) */
    lea ipc_handler(%rip), %rax
    movq %rax, ipc_sigact+SA_HANDLER(%rip)
    movq $SA_RESTORER, ipc_sigact+SA_FLAGS(%rip)
    lea ipc_restorer(%rip), %rax
    movq %rax, ipc_sigact+SA_RESTORER_FIELD(%rip)
    movq $0, ipc_sigact+SA_MASK(%rip)
    movq $SIGIO, %rdi
    lea ipc_sigact(%rip), %rsi
    xorq %rdx, %rdx
    movq $8, %r10
    movq $SYS_rt_sigaction, %rax
    syscall

    /* 初始化 perf_event_attr (128B 清零 + 填充) */
    lea ipc_attr(%rip), %r12
    movq $0, 0(%r12)
    movq $0, 8(%r12)
    movq $0, 16(%r12)
    movq $0, 24(%r12)
    movq $0, 32(%r12)
    movq $0, 40(%r12)
    movq $0, 48(%r12)
    movq $0, 56(%r12)
    movq $0, 64(%r12)
    movq $0, 72(%r12)
    movq $0, 80(%r12)
    movq $0, 88(%r12)
    movq $0, 96(%r12)
    movq $0, 104(%r12)
    movq $0, 112(%r12)
    movq $0, 120(%r12)
    movl $0, 0(%r12)               /* type = PERF_TYPE_HARDWARE */
    movl $64, 4(%r12)              /* size */
    movq $1, 8(%r12)               /* config = PERF_COUNT_HW_INSTRUCTIONS */
    movq rst_desc+RST_DESC_IPC_PERIOD(%rip), %rax
    addq $STUB_IPC_COMPENSATION, %rax
    movq %rax, 16(%r12)            /* sample_period = N + 补偿 */
    movq $1, 24(%r12)              /* sample_type = PERF_SAMPLE_IP */
    movq $1, 48(%r12)              /* wakeup_events = 1 */
    movq $(1<<0)|(1<<5)|(1<<6), 40(%r12)  /* disabled|exclude_kernel|exclude_hv */

    /* perf_event_open(&attr, pid=0, cpu=-1, group=-1, flags=0) */
    movq %r12, %rdi
    xorq %rsi, %rsi
    movq $-1, %rdx
    movq $-1, %r10
    xorq %r8, %r8
    movq $SYS_perf_event_open, %rax
    syscall
    testq %rax, %rax
    js ipc_no_perf
    movq %rax, %r12                /* r12 = perf fd */
    movq %rax, rst_desc+RST_DESC_IPC_FD(%rip)

    /* mmap 环形缓冲: 大小必须为 (1 + 2^k) 页 */
    xorq %rdi, %rdi
    movq $20480, %rsi              /* 5 页 = 1 头页 + 4 数据页 */
    movq $3, %rdx                  /* PROT_READ|PROT_WRITE */
    movq $MAP_SHARED, %r10
    movq %r12, %r8
    xorq %r9, %r9
    movq $SYS_mmap, %rax
    syscall

    /* fcntl(fd, F_SETOWN, getpid()) */
    movq $SYS_getpid, %rax
    syscall
    movq %rax, %rdx
    movq %r12, %rdi
    movq $F_SETOWN, %rsi
    movq $SYS_fcntl, %rax
    syscall

    /* fcntl(fd, F_SETFL, O_ASYNC) */
    movq %r12, %rdi
    movq $F_SETFL, %rsi
    movq $O_ASYNC, %rdx
    movq $SYS_fcntl, %rax
    syscall
    jmp ipc_ok
ipc_no_perf:
    movq $-1, rst_desc+RST_DESC_IPC_FD(%rip)
ipc_ok:
    ret

/*
 * 构建 rt_sigreturn 信号帧。
 * 返回 r14 = sigframe base, r13 = fpstate 指针。
 * 破坏 rax rcx rdx rsi rdi r8 r9 r10 r11 r12 r13 r14 r15。
 */
build_sigframe:
    lea sigframe(%rip), %r14       /* r14 = frame base */

    /* ucontext: uc_flags / uc_link / uc_stack 清零 */
    movq $0, (SIGFRAME_UC_FLAGS)(%r14)
    movq $0, (SIGFRAME_UC_LINK)(%r14)
    movq $0, (SIGFRAME_UC_STACK)(%r14)
    movq $0, (SIGFRAME_UC_STACK+8)(%r14)
    movq $0, (SIGFRAME_UC_STACK+16)(%r14)

    /* sigcontext: GPR (来自 regs_blob, pt_regs 布局) */
    movq regs_blob+PT_REGS_R8(%rip), %rax
    movq %rax, (SIGFRAME_UC_MCONTEXT+SIGFRAME_SC_R8)(%r14)
    movq regs_blob+PT_REGS_R9(%rip), %rax
    movq %rax, (SIGFRAME_UC_MCONTEXT+SIGFRAME_SC_R9)(%r14)
    movq regs_blob+PT_REGS_R10(%rip), %rax
    movq %rax, (SIGFRAME_UC_MCONTEXT+SIGFRAME_SC_R10)(%r14)
    movq regs_blob+PT_REGS_R11(%rip), %rax
    movq %rax, (SIGFRAME_UC_MCONTEXT+SIGFRAME_SC_R11)(%r14)
    movq regs_blob+PT_REGS_R12(%rip), %rax
    movq %rax, (SIGFRAME_UC_MCONTEXT+SIGFRAME_SC_R12)(%r14)
    movq regs_blob+PT_REGS_R13(%rip), %rax
    movq %rax, (SIGFRAME_UC_MCONTEXT+SIGFRAME_SC_R13)(%r14)
    movq regs_blob+PT_REGS_R14(%rip), %rax
    movq %rax, (SIGFRAME_UC_MCONTEXT+SIGFRAME_SC_R14)(%r14)
    movq regs_blob+PT_REGS_R15(%rip), %rax
    movq %rax, (SIGFRAME_UC_MCONTEXT+SIGFRAME_SC_R15)(%r14)
    movq regs_blob+PT_REGS_RDI(%rip), %rax
    movq %rax, (SIGFRAME_UC_MCONTEXT+SIGFRAME_SC_RDI)(%r14)
    movq regs_blob+PT_REGS_RSI(%rip), %rax
    movq %rax, (SIGFRAME_UC_MCONTEXT+SIGFRAME_SC_RSI)(%r14)
    movq regs_blob+PT_REGS_RBP(%rip), %rax
    movq %rax, (SIGFRAME_UC_MCONTEXT+SIGFRAME_SC_RBP)(%r14)
    movq regs_blob+PT_REGS_RBX(%rip), %rax
    movq %rax, (SIGFRAME_UC_MCONTEXT+SIGFRAME_SC_RBX)(%r14)
    movq regs_blob+PT_REGS_RDX(%rip), %rax
    movq %rax, (SIGFRAME_UC_MCONTEXT+SIGFRAME_SC_RDX)(%r14)
    movq regs_blob+PT_REGS_RAX(%rip), %rax
    movq %rax, (SIGFRAME_UC_MCONTEXT+SIGFRAME_SC_RAX)(%r14)
    movq regs_blob+PT_REGS_RCX(%rip), %rax
    movq %rax, (SIGFRAME_UC_MCONTEXT+SIGFRAME_SC_RCX)(%r14)
    movq regs_blob+PT_REGS_RSP(%rip), %rax
    movq %rax, (SIGFRAME_UC_MCONTEXT+SIGFRAME_SC_RSP)(%r14)
    movq regs_blob+PT_REGS_RIP(%rip), %rax
    movq %rax, (SIGFRAME_UC_MCONTEXT+SIGFRAME_SC_RIP)(%r14)
    movq regs_blob+PT_REGS_EFLAGS(%rip), %rax
    movq %rax, (SIGFRAME_UC_MCONTEXT+SIGFRAME_SC_EFLAGS)(%r14)

    /* cs/gs/fs/ss 选择子 */
    movw $USER_CS, (SIGFRAME_UC_MCONTEXT+SIGFRAME_SC_CS)(%r14)
    movw $0, (SIGFRAME_UC_MCONTEXT+SIGFRAME_SC_GS)(%r14)
    movw $0, (SIGFRAME_UC_MCONTEXT+SIGFRAME_SC_FS)(%r14)
    movw $USER_SS, (SIGFRAME_UC_MCONTEXT+SIGFRAME_SC_SS)(%r14)
    /* err / trapno / oldmask / cr2 */
    movq $0, (SIGFRAME_UC_MCONTEXT+SIGFRAME_SC_ERR)(%r14)
    movq $0, (SIGFRAME_UC_MCONTEXT+SIGFRAME_SC_TRAPNO)(%r14)
    movq $0, (SIGFRAME_UC_MCONTEXT+SIGFRAME_SC_OLDMASK)(%r14)
    movq $0, (SIGFRAME_UC_MCONTEXT+SIGFRAME_SC_CR2)(%r14)
    /* reserved1[8] */
    movq $0, (SIGFRAME_UC_MCONTEXT+SIGFRAME_SC_RESERVED1)(%r14)
    movq $0, (SIGFRAME_UC_MCONTEXT+SIGFRAME_SC_RESERVED1+8)(%r14)
    movq $0, (SIGFRAME_UC_MCONTEXT+SIGFRAME_SC_RESERVED1+16)(%r14)
    movq $0, (SIGFRAME_UC_MCONTEXT+SIGFRAME_SC_RESERVED1+24)(%r14)
    movq $0, (SIGFRAME_UC_MCONTEXT+SIGFRAME_SC_RESERVED1+32)(%r14)
    movq $0, (SIGFRAME_UC_MCONTEXT+SIGFRAME_SC_RESERVED1+40)(%r14)
    movq $0, (SIGFRAME_UC_MCONTEXT+SIGFRAME_SC_RESERVED1+48)(%r14)
    movq $0, (SIGFRAME_UC_MCONTEXT+SIGFRAME_SC_RESERVED1+56)(%r14)

    /* fpstate: 拷贝 xstate 并修补 */
    lea (SIGFRAME_FPSTATE_OFF)(%r14), %r13   /* r13 = fpstate (64B 对齐) */
    movq %r13, (SIGFRAME_UC_MCONTEXT+SIGFRAME_SC_FPSTATE)(%r14)
    lea fpu_blob(%rip), %rsi
    movq rst_desc+RST_DESC_FPU_SIZE(%rip), %rcx
    movq %r13, %rdi
    rep movsb
    /* _fpx_sw_bytes @ fpstate+464 */
    movl $FPSTATE_MAGIC1, (FPSTATE_SW_RESERVED)(%r13)
    movq rst_desc+RST_DESC_FPU_SIZE(%rip), %rax
    movq %rax, %r15
    addq $4, %rax
    movl %eax, (FPSTATE_SW_RESERVED+4)(%r13)      /* extended_size */
    movq (FPSTATE_XSTATE_BV)(%r13), %rcx          /* xstate_bv (已拷贝) */
    movq %rcx, (FPSTATE_SW_RESERVED+8)(%r13)      /* fx_sw.xfeatures */
    movl %r15d, (FPSTATE_SW_RESERVED+16)(%r13)    /* fx_sw.xstate_size */
    /* magic2 @ fpstate + fpu_size */
    movq rst_desc+RST_DESC_FPU_SIZE(%rip), %rax
    movl $FPSTATE_MAGIC2, (%r13,%rax)

    /* uc_sigmask */
    movq sigmask_blob(%rip), %rax
    movq %rax, (SIGFRAME_UC_SIGMASK)(%r14)

    ret

/* ===================== IPC 处理器 ===================== */
/* 处理器返回后跳到这里: rt_sigreturn 恢复被中断的现场 */
ipc_restorer:
    movq $SYS_rt_sigreturn, %rax
    syscall

/*
 * SIGIO 处理器: 读取指令计数, 打印后退出。
 * 运行在目标代码的栈上 (内核信号帧), 仅使用 syscall。
 */
ipc_handler:
    pushq %rax
    pushq %rbx
    pushq %rcx
    pushq %rdx
    pushq %rsi
    pushq %rdi
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    movq rst_desc+RST_DESC_IPC_FD(%rip), %rdi
    lea ipc_count_buf(%rip), %rsi
    movq $8, %rdx
    movq $SYS_read, %rax
    syscall
    testq %rax, %rax
    jle ipc_exit

    /* 十进制转换: 从尾部向前填 */
    movq ipc_count_buf(%rip), %rbx
    lea ipc_out_end(%rip), %rdi
    movq $10, %rcx
ipc_conv:
    xorq %rdx, %rdx
    movq %rbx, %rax
    divq %rcx
    movq %rax, %rbx
    addb $'0', %dl
    decq %rdi
    movb %dl, (%rdi)
    testq %rbx, %rbx
    jnz ipc_conv
    movq %rdi, %r8                 /* r8 = 数字串指针 (syscall 会破坏 rdi) */

    /* write(1, "IPC: ", 5) */
    lea ipc_prefix(%rip), %rsi
    movq $5, %rdx
    movq $1, %rdi
    movq $SYS_write, %rax
    syscall
    /* write(1, digits, len) */
    movq %r8, %rsi
    lea ipc_out_end(%rip), %rax
    subq %r8, %rax
    movq %rax, %rdx
    movq $1, %rdi
    movq $SYS_write, %rax
    syscall
    /* write(1, " instructions\n", 14) */
    lea ipc_suffix(%rip), %rsi
    movq $14, %rdx
    movq $1, %rdi
    movq $SYS_write, %rax
    syscall
ipc_exit:
    movq $SYS_exit_group, %rax
    xorq %rdi, %rdi
    syscall

/* ===================== 数据 ===================== */
str_maps:
    .asciz "/proc/self/maps"
str_stack:
    .asciz "[stack]"
ipc_prefix:
    .ascii "IPC: "
ipc_suffix:
    .ascii " instructions\n"
ipc_count_buf:
    .space 8
ipc_out_buf:
    .space 24
ipc_out_end:

.org STUB_FIXED_SIZE
.section .note.GNU-stack,"",@progbits
