# elftrace 设计与实现笔记

## 总体思路

CRIU 的做法是"重启"，elftrace 的做法是"切片"：不重建一个进程，而是把
被冻结进程的完整用户态状态打包成一个**静态可执行 ELF**。执行该 ELF =
从冻结点继续运行原进程。核心挑战是地址空间一致性：内存必须恢复到
完全相同的虚拟地址（随机化的 PIE 基址、栈位置等），寄存器要原样恢复。

参考了 CRIU 的 compel/restorer 思路（stub 内 mmap+拷贝恢复内存、构建
sigframe 让内核恢复寄存器），但代码从头编写。

## .elftrace 格式 (v3)

```
hdr | regs | fpu | sigmask | segs表 | fds表 | strings | aux表 | payload
```

- 全部小端字段化，`*_off` 为绝对文件偏移；payload 顺序拼接段内容。
- aux 记录描述从原 exe 提取的调试节/分配节（含链接元数据），组装时重建节。
- 头含 `exe_bias`（PIE 加载偏置）与 `rlim_stack_cur/max`（RLIMIT_STACK，
  切片进程恢复栈增长限制用）。
- 改动格式字段必须 `ELTRACE_VERSION +1`（collect 写、build/dump 读同步）。

## 恢复 stub blob 布局 (x86_64)

```
[0x0000] desc(256B)  [0x0100] xstate(4KB)  [0x1100] sigmask(8B)
[0x1108] sigacts(2.5KB)  [0x1B08] regs(216B)  [0x1BE0] maps buf(4KB)
[0x2BE0] perf attr  [0x2C60] ipc sigact  [0x2C80] 栈(8KB)
[0x4CC0] rt_sigreturn 信号帧区  [0x62C0] 代码  [0x8000] 追加区起点
```

desc 字段（0x100-0xB8 已用）：magic/version/flags/target_rip/n_segs/segs_off/
n_fds/fds_off/fpu_off/fpu_size/sigmask_off/sigacts_off/regs_off/ipc_period/
ipc_fd/ipc_buf_off/mode/exit_addr/brk_base/target_tid/stack_vaddr/
rlim_stack_cur/rlim_stack_max。新增字段需同步三处（头文件宏、stub .quad、
build blob_patch_u64）。

追加区（builder 填充）：segs 表(48B/条)、fds 表(48B/条)、字符串、payload。
所有固定偏移用 `label+const(%rip)` 寻址（PIC，objcopy 前经 ld 解析重定位）。
注意：**不能**用 `常量(%rip)`——那是绝对位移，不产生重定位。

## rt_sigreturn 信号帧 (x86_64, 内核 6.x 验证)

内核 `restore_sigcontext` 恢复 r8-r15/rdi/rsi/rbp/rbx/rdx/rax/rcx/rsp/rip、
eflags(FIX_EFLAGS 掩码)、cs/ss（|3）；`fpu__restore_sig(sc.fpstate)` 从
帧内 fpstate 恢复完整 xstate（含 AVX）。要点：

- ucontext 偏移：uc_flags@0, uc_link@8, uc_stack@0x10(24B), uc_mcontext@0x28,
  uc_sigmask@0x128；sigcontext 内 fpstate 指针@0xB8。
- uc_stack 必须全零（无 sigaltstack 时 restore_altstack 直接通过）。
- fpstate 布局 = GETREGSET NT_X86_XSTATE 输出（fxstate 0..464,
  sw_reserved@464, xstate header@512, 扩展状态@576）：
  - `_fpx_sw_bytes`@464：magic1=0x46505853, extended_size=size+4,
    xfeatures=xstate_bv, xstate_size=size
  - magic2=0x46505845 @ (fpstate+size)
  - fpstate 需 64B 对齐
- 内核要求信号处理器带 SA_RESTORER（6.x 起 `x64_setup_rt_frame` 直接
  `-EFAULT` 拒绝无 restorer 的投递！）——stub 的 IPC sigaction 必须设
  SA_RESTORER(0x04000000) + 自带的 rt_sigreturn 蹦床。

## 调试符号 (PIE bias)

PIE 的 symtab/DWARF 地址是镜像相对（0 基），恢复后实际基址随机。freeze
时记录 `exe_bias = 运行时最低 exe 映射 - 文件首个 PT_LOAD p_vaddr`，
对以下内容加 bias：

- symtab 中已定义符号的 st_value
- `.debug_info` 的 DW_FORM_addr 属性（需 .debug_abbrev 解析 DIE）
- `.debug_line` 的 DW_LNE_set_address（v5 行头是
  format_count→formats→count→entries 顺序）
- `.debug_aranges` 元组、`.debug_ranges` 序列（(0,0) 终止符不动）、
  `.debug_rnglists` 各 RLE 项

## IPC 指令计数

- perf_event_open(PERF_COUNT_HW_INSTRUCTIONS, self)：attr 要点
  - config=1（0 是 CYCLES！），sample_period=N+3（ENABLE 到 rt_sigreturn
    之间有 3 条 stub 指令）
  - disabled=1 + ioctl(PERF_EVENT_IOC_ENABLE=0x2400) 在跳转前一刻启用
  - sample_type=PERF_SAMPLE_IP(1)，wakeup_events=1
  - ring mmap 大小必须是 (1+2^k) 页（如 20480=5 页），否则 EINVAL
- 溢出 → fcntl(F_SETOWN=8 + F_SETFL=O_ASYNC) 使内核发 SIGIO
  （注意 F_SETOWN=8 不是 6！）
- 处理器读取计数、十进制转换、打印 "IPC: N instructions"、exit_group(0)

## 排查记录

- `常量(%rip)` 不产生重定位：所有 blob 内寻址必须用符号。
- xxd -i 从 stdin 读会输出全零（bug），必须传文件名参数。
- elftrace_seg 是 48B（含 name_off），stub 步进不能想当然。
- rep movsb 方向：rsi 是源。
- 信号帧构建失败（-EFAULT）的根因是 SA_RESTORER 缺失，kprobe
  x64_setup_rt_frame 返回值定位（-14）。
- gdb 无法在 stub 恢复内存前插入软件断点 → 构建期 int3 注入
  （--breakpoint）。


## 栈增长与堆边界 (v3 起)

- `[stack]` 段恢复加 `MAP_GROWSDOWN`（desc.stack_vaddr 标记），允许目标
  越过冻结时栈底继续向下增长（深递归程序）。
- RLIMIT_STACK 恢复：freeze 读 `/proc/pid/limits` 存入头，stub 在段恢复
  前 `setrlimit(RLIMIT_STACK)`（目标 setrlimit 的栈限制在切片进程是
  默认 8MB，不恢复会 SIGSEGV）。
- brk 不恢复：目标 glibc 的 brk 缓存（恢复的内存）与切片进程内核 brk
  指针不一致，差距可达数十 TB，一次 brk 扩展被 overcommit 拒绝且 brk
  不能跨 VMA；glibc malloc 会 fallback mmap（分配仍可用）。
- `heap_end`（desc.brk_base）定位取**第一个** `[heap]` 段：mmap 的大块
  匿名段也可能被内核标为 `[heap]`，真实 brk 指针是第一个。
