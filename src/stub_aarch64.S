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
#define SYS_dup2       33
#define SYS_setrlimit  164
#define SYS_rt_sigreturn 139
#define SYS_rt_sigaction 134
#define SYS_brk         214
#define SYS_getpid      172

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

    /* ======== 1. 恢复内存段 ======== */
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
    mov  x8, #SYS_dup2
    svc  #0
    cmp  x19, x1
    beq  fd_next                    /* newfd == target_fd: 不 close */
    mov  x0, x19
    mov  x8, #SYS_close
    svc  #0
fd_next:
    add  x15, x15, #48
    sub  x14, x14, #1
    b    fd_loop
fd_done:

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
    /* 无回放记录: 报错退出 (与 x86 一致) */
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
    add  x0, x2, #1
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

rlimit_stack:
    .quad 0, 0

/* 代码区末尾: 补齐到固定区大小 */
    .org STUB_FIXED_SIZE
