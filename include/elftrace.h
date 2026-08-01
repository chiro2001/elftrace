/*
 * elftrace - 中间数据文件 (.elftrace) 格式定义
 *
 * .elftrace 是"数据采集"与"ELF 组装"之间的解耦点:
 *   freeze <pid>           -> 采集进程状态, 写入 .elftrace
 *   build <file.elftrace>  -> 读取 .elftrace, 组装出可恢复执行的 ELF
 *
 * 文件布局 (全部小端, 所有字段按偏移顺序排列):
 *
 *   [0x000] elftrace_hdr          固定头
 *   [hdr]   regs blob             通用寄存器 (arch 相关布局, regs_size 字节)
 *   [hdr]   fpu blob              xsave/fpregs 状态 (fpu_size 字节)
 *   [hdr]   sigmask               内核 sigset_t (8 字节, x86_64)
 *   [hdr]   segs 表               nsegs 个 elftrace_seg (40 字节/个)
 *   [hdr]   fds 表                nfds 个 elftrace_fd (48 字节/个)
 *   [hdr]   strings 区            空字符结尾字符串池 (fd 路径等)
 *   [hdr]   sigacts 表             64 个 elftrace_sigact (40 字节/个, 可选)
 *   [hdr]   aux 表                aux_n 个 elftrace_aux (80 字节/个, 可选调试节)
 *   [hdr]   payload               所有段内容 + aux 节内容, 顺序拼接
 *
 * 所有 *_off 均为从文件起始的绝对偏移。
 */
#ifndef ELFTRACE_H
#define ELFTRACE_H

#include <stdint.h>

#define ELFTRACE_MAGIC          0x4554464C  /* "ELFT" (LE) */
#define ELFTRACE_VERSION        3

/* 架构 ID */
#define ELFTRACE_ARCH_X86_64    1
#define ELFTRACE_ARCH_AARCH64   2

/* 头标志 */
#define ELFTRACE_FLAG_NONE      0x0000
#define ELFTRACE_FLAG_HAS_SIGACTS 0x0001  /* 记录了 sigactions 表 */

/* 段标志 (同 ELF PF_*) */
#define ET_SEG_X                0x1
#define ET_SEG_W                0x2
#define ET_SEG_R                0x4

#define ELFTRACE_SIG_MAX        64       /* 支持的最大信号数 (同内核 _NSIG) */

typedef struct {
    uint32_t magic;             /* ELFTRACE_MAGIC */
    uint32_t version;           /* ELFTRACE_VERSION */
    uint32_t arch;              /* ELFTRACE_ARCH_* */
    uint32_t flags;             /* ELFTRACE_FLAG_* */

    uint64_t entry_pc;          /* 冻结时刻的指令指针 */
    uint64_t task_tid;          /* 被冻结线程 tid */

    uint64_t regs_off;          /* GPR blob 偏移 */
    uint64_t regs_size;         /* GPR blob 大小 */
    uint64_t fpu_off;           /* FPU blob 偏移 */
    uint64_t fpu_size;          /* FPU blob 大小 */
    uint64_t sigmask_off;       /* 内核 sigset_t (8 字节) 偏移 */

    uint64_t segs_off;          /* 段表偏移 */
    uint64_t nsegs;             /* 段数 */
    uint64_t fds_off;           /* fd 表偏移 */
    uint64_t nfds;              /* fd 数 */
    uint64_t sigacts_off;       /* sigactions 表偏移 (无则为 0) */

    uint64_t strings_off;       /* 字符串池偏移 */
    uint64_t strings_size;      /* 字符串池大小 */
    uint64_t aux_off;           /* aux 表偏移 (调试节, 无则为 0) */
    uint64_t aux_n;             /* aux 条目数 */
    uint64_t exe_off;           /* 主可执行文件路径在字符串池中的偏移 (无则为 0) */

    uint64_t payload_off;       /* payload 偏移 */
    uint64_t payload_size;      /* payload 大小 */
    uint64_t exe_bias;          /* PIE 加载偏置 (运行时基址 - 文件 p_vaddr),
                                   用于调试节地址修正; 非 PIE 为 0 */
    uint64_t rlim_stack_cur;    /* RLIMIT_STACK 当前值 (切片进程恢复) */
    uint64_t rlim_stack_max;    /* RLIMIT_STACK 最大值 */
} elftrace_hdr;

/* 内存段 (40 字节) */
typedef struct {
    uint64_t vaddr;             /* 段起始虚拟地址 */
    uint64_t filesz;            /* 采集到的字节数 */
    uint64_t memsz;             /* 原始映射大小 */
    uint64_t flags;             /* ET_SEG_* */
    uint64_t payload_off;       /* 在 payload 内的偏移 */
    uint64_t name_off;          /* 段名 (如 "[stack]"/"/usr/lib/libc.so.6") 在字符串池的偏移 */
} elftrace_seg;

/* fd 记录 (48 字节)。path_len == 0 表示该 fd 类型暂不支持 (pipe/socket 等), stub 跳过。 */
typedef struct {
    uint64_t fd;                /* 目标进程的 fd 编号 */
    uint64_t flags;             /* O_* 打开标志 */
    uint64_t mode;              /* 打开模式 */
    uint64_t pos;               /* 当前文件偏移 */
    uint64_t path_len;          /* 路径长度 */
    uint64_t path_off;          /* 路径在字符串池中的偏移 */
} elftrace_fd;

/* sigaction 记录 (40 字节), 按信号编号索引 (0 不用), 仅记录非默认且非不可捕获的 */
typedef struct {
    uint64_t handler;           /* sa_handler / SA_SIGINFO 时 sa_sigaction */
    uint64_t flags;             /* sa_flags */
    uint64_t restorer;          /* sa_restorer */
    uint64_t mask_lo;           /* sa_mask 低 64 位 */
    uint64_t mask_hi;           /* sa_mask 高 64 位 */
} elftrace_sigact;

/* aux 节记录 (80 字节): 从原可执行文件提取的调试节, 组装时重建为 ELF 节 */
typedef struct {
    uint64_t name_off;          /* 节名在字符串池中的偏移 */
    uint64_t addr;              /* 原节地址 */
    uint64_t payload_off;       /* 内容在 payload 内的偏移 */
    uint64_t size;              /* 节大小 */
    uint64_t type;              /* SHT_* */
    uint64_t flags;             /* SHF_* */
    uint64_t align;             /* 对齐 */
    uint64_t entsize;           /* 条目大小 */
    uint64_t link;              /* sh_link (原索引, 组装时重映射) */
    uint64_t info;              /* sh_info */
} elftrace_aux;

#endif /* ELFTRACE_H */
