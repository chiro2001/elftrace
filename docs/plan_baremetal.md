# 功能 6/7 设计：baremetal 模式与指令区间切片（历史规划，已实现）

> 本文是功能开发前的设计规划，功能已全部实现。实际行为以 README.md 和
> 代码为准；brk 恢复方案（stub 先 brk 到堆尾）已放弃（见下"实施修正"）。

## 总览

- **功能 6（baremetal）**：生成不依赖内核服务的切片。目标代码中的 syscall
  指令在构建期被替换为 int3，运行时由 stub 的 SIGTRAP 模拟器 mock
  （基于内存镜像与寄存器上下文），不支持的 syscall 报错退出（0x5e）。
  退出不用 perf_event_open：把"第 N 条指令"处指令替换为 int3，处理器
  识别后跳 stub 退出代码。
- **功能 7（区间切片）**：新增 `elftrace trace` 采集器，用 perf 指令计数
  每 N 条指令冻结目标并采集一个检查点（完整 .elftrace + 溢出 IP），
  `build --from K --to M` 从任意检查点 K 恢复、在检查点 M 退出。
- 两功能通过检查点（.elftrace + manifest）联动：baremetal 的"第 N 条
  指令"地址来自 manifest 的检查点 IP（粒度 = 检查点间隔，误差 < N）。

## trace 采集器（替代 dynamorio 的选择）

用户建议 dynamorio 采集指令流。本实现改用 **perf 指令计数**：
tracer 侧 `perf_event_open(PERF_COUNT_HW_INSTRUCTIONS, pid=tracee)`
绑定目标进程，环形缓冲 + 溢出唤醒；每次溢出（每 N 条指令）：
PTRACE_INTERRUPT 冻结 → 采集检查点 → PTRACE_CONT。优点：

- 零注入（无需向目标进程植入代码），与现有 freeze/ptrace 体系天然一致
- 检查点直接复用 freeze 的采集逻辑，格式就是 .elftrace
- 溢出 sample 带 IP（PERF_SAMPLE_IP），记录每检查点的指令地址
- 冻结期间指令不执行，计数天然暂停，检查点边界即指令边界

指令流精确到单条（Intel PT/dynamorio）留作后续增强：v1 的"第 xn 条
指令"取最近检查点（粒度 N）。

## baremetal 模式机制

### syscall 替换

构建期遍历所有 PF_X 段的 payload：字节序列 `0f 05`（syscall）→ `cc 90`
（int3 + nop）。PF_X 段中的 0f 05 必为 syscall 指令（.rodata 在 r-- 段
不含 X，不会误伤数据）。目标执行到 int3 → SIGTRAP → stub 处理器按
被中断上下文（sigcontext）的 rax 分派模拟。

### SIGTRAP 处理器（stub 内，裸汇编）

- 入口 rsp = 信号帧 uc 地址（与 rt_sigreturn 帧同布局）
- 触发地址 = sc->rip - 1：
  - == desc.exit_addr → 修改 sc->rip = 退出代码，返回（rt_sigreturn）
  - 否则按 sc->rax 分派模拟，结果写回 sc->rax，返回
- 处理器经 sigaction 的 restorer（rt_sigreturn 蹦床）返回，内核恢复
  目标上下文（int3 之后继续执行）

### 模拟语义（v1）

| syscall | 模拟 |
|---|---|
| 231/60 exit_group/exit | 真实退出（宿主操作），码 = 参数 |
| 0 read | 返回 0（EOF） |
| 1 write / 20 writev | 返回长度（内容丢弃） |
| 2 open / 257 openat | -ENOENT |
| 3 close | 0 |
| 9 mmap | -ENOMEM |
| 10 mprotect / 11 munmap | 0 |
| 12 brk | 游标在 [0, brk_base] 内移动，超出返回当前值 |
| 39 getpid | desc.target_tid（冻结时 tid） |
| 62 kill | 0 |
| 158 arch_prctl | -EINVAL |
| 其他 | 打印 "unsupported syscall N" 后 exit_group(0x5e) |

brk_base = 冻结时 [heap] 段的 end（builder 从 .elftrace 段名计算）。
测试程序约定：冻结点之后不再增长堆（malloc 在启动阶段完成）。

### 退出点选择（"只执行一次的路径"）

- 退出地址来自 trace 检查点 IP（溢出时刻的指令，指令计数 ≈ k×N）
- 处理器在 int3 处直接改 rip 跳退出代码，不关心原指令长度/后续字节
- 若退出地址恰为循环内指令：int3 首次执行即触发，语义 = "执行到该
  指令即退出"，计数 ≈ k×N（可接受；文档注明）
- 用户提供的 --ipc N（baremetal）对齐到最近检查点，打印实际指令数

## 构建参数

```
elftrace build <in.elftrace> [-o out.elf]
    [--mode real|baremetal]        # 默认 real（"默认使能，添加选项关闭"）
    [--ipc N]                      # real: perf 计数; baremetal: 需 --checkpoints
    [--checkpoints DIR]            # trace 输出目录（manifest.txt + ckpt_*.elftrace）
    [--from K]                     # 用 DIR/ckpt_K.elftrace 作为基础镜像
    [--to M]                       # 在检查点 M 处退出（real: perf; baremetal: 替换）
    [--breakpoint ADDR]
```

## desc 扩展（elftrace_stub.h）

desc 扩至 256B（fpu 移至 0x100，后续区域顺移），新增：
`mode`(0x80: 0=real 1=baremetal)、`exit_addr`(0x88)、`brk_base`(0x90)、
`target_tid`(0x98)。flags 增 RST_FLAG_BAREMETAL(1<<3)。

## 测试

- tests/prog_cpp.cpp：C++（vector/map/string STL + 纯计算循环 + 周期
  CHECKPOINT 打印），启动时完成全部堆分配；可选 --bad-syscall 触发
  不支持 syscall；退出码 = 计算结果 % 255
- test_cpp_real.sh：freeze → build real → 输出/退出码与基准一致
  （基准 = SIGCONT 原进程跑完）
- test_baremetal.sh：freeze → build --mode baremetal → strace 验证目标
  阶段无真实 syscall；退出码 == real 切片；--bad-syscall 变体验证
  报错退出 0x5e
- test_trace.sh：trace --every N 采集 → build --from K --to M 两种模式
  验证从检查点 K 恢复、M 处退出


## 实施修正（与规划不同的点）

1. **brk 恢复放弃**：规划中"stub 恢复 [heap] 前先 brk(冻结堆尾)"不可行——
   切片进程（静态 ELF）内核 brk 起点低（~几百 MB），目标堆在随机高位，
   一次 brk 扩展跨数十 TB，被内核 overcommit/跨 VMA 检查拒绝。实测
   放弃；real 模式下目标 sbrk 会失败，但 glibc malloc fallback mmap。
2. **RLIMIT_STACK 恢复**：深栈测试暴露目标 setrlimit 的栈限制未恢复
   （切片进程默认 8MB），栈增长 SIGSEGV；v3 起 freeze 采集并恢复。
3. **COW 注入轮询排除旧代理**：旧代理 flag 早已置 1，误选导致从旧代理
   读取缺新段（EIO → 检查点段零填充 → 切片崩溃）。
4. **代理 PDEATHSIG 方案不可行**：注入代码里 prctl(PR_SET_PDEATHSIG,
   SIGKILL) 在 ptrace 场景下子进程立即死亡；代理保持自旋由 trace 结束
   统一回收（被强杀时泄漏）。
