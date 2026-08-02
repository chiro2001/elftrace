# elftrace — 进程切片基础设施

将指定进程**冻结**，采集其内存镜像、寄存器镜像与进程状态，打包为一个
**可执行 ELF**；加载并执行该 ELF 时自动恢复内存与寄存器，从冻结点继续执行，
等价于"恢复该进程的运行"。

```
  冻结点                         恢复点
  ┌────────┐   freeze    ┌───────────┐   build    ┌──────────┐
  │ 目标进程 │ ────────► │ .elftrace │ ─────────► │ sliced ELF │
  └────────┘   采集快照   └───────────┘   组装      └──────────┘
                                                         │ exec
                                                         ▼
                                                stub 恢复内存/寄存器/fd
                                                跳转回冻结 PC, 继续执行
```

数据采集（freeze）与 ELF 组装（build）通过中间文件 `.elftrace` 解耦：
采集器与组装器可独立演进，中间文件可用 `dump` 子命令人读。

## 构建与使用

```bash
make                          # 需要 gcc/as/ld/objcopy
./build/elftrace freeze <pid> -o snap.elftrace   # 冻结并采集
./build/elftrace dump snap.elftrace              # 查看中间文件
./build/elftrace build snap.elftrace -o sliced.elf     [--mode real|baremetal] [--ipc N] [--breakpoint ADDR]
./sliced.elf                  # 恢复执行

# 指令区间切片 (功能 7): 先采集检查点, 再从任意检查点恢复/退出
./build/elftrace trace <pid> --every 200000000 --out ckpts/
./build/elftrace build -o slice.elf --checkpoints ckpts/ --from 2 --to 5     [--mode real|baremetal]
```

- `--mode baremetal`：生成裸机切片——目标代码中的 syscall 指令被替换为
  int3，运行时由 stub 的 SIGTRAP 模拟器 mock（read/write/writev/open/
  close/mmap/mprotect/munmap/brk/getpid/kill/arch_prctl/rt_sigaction/
  rt_sigprocmask/exit_group/exit 等），不支持的 syscall 打印后以退出码
  0x5e 退出；退出不用 perf，而是把退出点指令替换为 int3。默认 real 模式。
- `--ipc N`：real 模式为 perf_event_open 指令计数退出（溢出触发 SIGIO，
  打印 `IPC: <count> instructions` 后退出，返回 0）；baremetal 模式需
  配合 `--checkpoints` 确定第 N 条指令的地址。
- `--checkpoints DIR --from K --to M`：从 trace 检查点 K 恢复、在检查点
  M 处退出（real 用 perf 计数，baremetal 用指令替换）；区间指令数 =
  (M-K)×检查点间隔。
- `--breakpoint ADDR`：在构建期向内存映像注入 int3（gdb 无法在 stub 恢复
  内存前插入软件断点；此方法在恢复时自动生效，配合 gdb 调试切片）。

## 架构

| 组件 | 路径 | 说明 |
|---|---|---|
| 采集器 | `src/collect.c` | freeze/trace 共用的状态采集：寄存器（GETREGSET NT_PRSTATUS）、FPU（NT_X86_XSTATE）、信号掩码、RLIMIT_STACK、内存段（/proc/pid/maps + mem）、fd、主可执行文件的调试节 + PIE 偏置 |
| 冻结入口 | `src/freeze.c` | CLI：seize+interrupt 冻结，采集后 SIGSTOP+detach 保持冻结 |
| 中间格式 | `include/elftrace.h` | `.elftrace` v3 二进制格式（小端、字段化、可扩展） |
| 恢复 stub | `src/stub_x86_64.S` | 自包含 PIC 汇编，作为生成 ELF 的入口 |
| 组装器 | `src/build.c` | 解析 `.elftrace`，把 stub blob 放入目标地址空间空闲 gap，组装 ET_EXEC |
| DWARF 修补 | `src/dwarf.c` | PIE 程序的调试节地址加加载偏置（DWARF v4/v5） |
| 查看器 | `src/dump.c` | `.elftrace` 人读 |
| 检查点采集 | `src/trace.c` | perf 指令计数，每 N 条指令冻结采集一个检查点 + manifest |
| COW 注入器 | `src/inject.c` | 冻结目标时注入 fork（两阶段：mmap 专用页+自跳转），目标停顿 ~100ns，内存快照从自旋的镜像代理异步读取 |

### 恢复流程（x86_64 stub）

1. 切换到 blob 自带栈（不再使用 loader 初始栈）；
2. 恢复 `RLIMIT_STACK`（目标栈继续向下增长需要）；
3. 逐段 `mmap(MAP_FIXED|ANON)` + 拷贝 payload + `mprotect` 恢复内存；
   `[stack]` 段加 `MAP_GROWSDOWN`（允许越过冻结时栈底继续增长）；
4. `munmap` loader 初始栈（解析 `/proc/self/maps` 的 `[stack]`）；
5. fd 恢复：按路径重开 + `lseek` 到冻结偏移 + `dup2` 回原 fd 号；
6. 恢复 sigactions（格式支持，采集暂缺，见限制）；
7. `arch_prctl` 恢复 fs_base/gs_base；
8. （可选）perf_event_open 指令计数 + SIGIO 处理器；
9. 在 blob 栈上构建 rt_sigreturn 信号帧（GPR + eflags + rip + rsp +
   信号掩码 + xstate，xstate 格式与内核 sigframe 布局一致）；
10. `rt_sigreturn`：内核一次性恢复全部寄存器、信号掩码与 FPU/AVX 状态，
    跳转到冻结 PC。

### 关键设计点

- **恢复位置**：stub blob（含全部 payload）放在目标地址空间的一个空闲
  gap（构建期扫描，避开初始栈可能出现的顶部区域），运行时不再依赖
  loader 建映射，避免了与目标既有映射/初始栈的冲突。
- **寄存器恢复走 rt_sigreturn**：手动恢复 GPR 无法同步内核视角的 FPU
  状态与信号掩码；信号帧让内核原子完成全部恢复（含 AVX 等扩展状态）。
- **PIE 调试符号**：记录加载偏置（exe 运行时基址 - 文件 p_vaddr），
  symtab 与 DWARF 各节（info/line/aranges/ranges/rnglists）的地址统一
  加偏置，使 gdb 在切片上可直接断点/看行号/回溯。

## 测试

```bash
tests/run_tests.sh     # 一键运行全部 13 项测试
```

| 测试 | 覆盖 |
|---|---|
| `test_basic.sh` | 基础：循环程序冻结→切片→输出/退出码与基准一致 |
| `test_dbg.sh` | 调试符号（PIE bias、DWARF、gdb 回溯/局部变量） |
| `test_fd.sh` | fd 重开 + 偏移续写 |
| `test_ipc.sh` | perf 指令计数自动退出 |
| `test_cpp.sh` | C++（STL）real/baremetal/区间切片 |
| `test_fd_rw.sh` | 文件读写程序（写+读回验证），real/baremetal |
| `test_py.sh` | CPython 进程（外部冻结/代码打桩自暂停/baremetal） |
| `test_syscall.sh` | 冻结阻塞在 syscall 中的进程（告警+续跑） |
| `test_stack.sh` | 深递归 96MB 栈（最大深度 + 下降途中栈生长） |
| `test_bigmem.sh` | 137MB payload 大内存 |
| `test_thread.sh` | 多线程不崩溃（语义未定义） |
| `test_append.sh` | O_APPEND fd 偏移语义 |
| `test_bareheap.sh` | baremetal brk mock + real malloc fallback |

需要 `kernel.yama.ptrace_scope=0`（或目标进程允许被跟踪）。

## 已知限制

- 单线程进程；不支持多线程（可采集但语义未定义）。
- trace 的 COW 检查点：注入 fork 创建的镜像代理保持自旋（退出会破坏
  perf 事件对目标的计数），由 trace 结束时统一回收；每检查点目标地址
  空间增加一个 ~4KB 专用页。
- baremetal 退出点为检查点粒度（trace 间隔），"第 N 条指令"取最近检查点
  PC，误差 < 间隔；若退出点恰在循环内，进程在首次执行到该指令时退出。
- baremetal 的 brk 模拟只允许在冻结时堆边界内移动；mmap 返回 -ENOMEM，
  冻结点之后的新增堆分配会失败（测试程序约定启动阶段完成分配）。
- real 模式下目标后续 sbrk/brk 增长受限：目标 glibc 的 brk 缓存（恢复
  的内存）与切片进程内核 brk 指针不一致，跨地址空间差距的 brk 扩展被
  overcommit 拒绝；glibc malloc 会 fallback 到 mmap，分配仍可用。
- trace 被强杀（timeout/kill -9）时 COW 镜像代理不会回收（正常结束时
  统一回收）；代理是目标的子进程并自旋，目标退出后成为孤儿。
- 指令流精确到单条（Intel PT/dynamorio 级）留作增强；当前检查点粒度 = N。
- 冻结在系统调用中途时，该次 in-flight syscall 会丢失（检测到会告警）。
- vdso/vvar/vsyscall 为内核管理区域，不采集不恢复；程序若在冻结后
  依赖 vdso 内已有指针可能出错（常见库调用不受影响，因为 vdso 由内核
  重新映射）。
- sigactions 暂未采集（格式与 stub 恢复逻辑已就绪）；切片进程的信号
  处理器为默认动作。
- MAP_SHARED/文件后备映射按匿名副本恢复，共享语义丢失。
- pipe/socket/anon_inode 类型 fd 跳过（path_len=0）。
- `.debug_loc/.debug_loclists` 未做偏置修补（变量位置信息在 PIE 切片
  中可能偏移；函数/行号信息完整）。
- xstate 上限 4096 字节（AMX 等大状态会被截断）。
- aarch64：格式/接口已预留（`ELFTRACE_ARCH_AARCH64`、GETREGSET 采集、
  `src/stub_aarch64.S` 框架），stub 待有硬件后实现。
