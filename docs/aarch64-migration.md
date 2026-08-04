# aarch64 迁移建议

> 目标：让 elftrace 在 aarch64（ARM64）主机上完成"冻结 → 切片 → 恢复"
> 全链路，包括 baremetal 回放。本文档梳理全部架构耦合点、迁移方案、
> 工作量估算与验证方式。当前状态：格式层已预留
> （`ELFTRACE_ARCH_AARCH64`、`stub_aarch64.S` 框架、NT_FPREGSET 采集），
> 但 build 仍拒绝非 x86_64 输入，stub 未实现。

## 0. 现状盘点（x86_64 特有假设清单）

| 组件 | x86_64 特定实现 | aarch64 对应 |
|---|---|---|
| 寄存器布局 | `struct user_regs_struct`（216B，`pt_regs` 语义） | `struct user_pt_regs`（272B：x0-x30, sp, pc, pstate） |
| 寄存器恢复 | ucontext + `rt_sigreturn`（15） | ucontext（gp_regs 布局不同）+ `rt_sigreturn`（139） |
| syscall 指令 | `0f 05`（2 字节） | `svc #0`（`d4000001`，4 字节） |
| 断点 | `int3`（`cc`，1 字节，SIGTRAP SI_KERNEL） | `brk #0`（`d4200000`，4 字节，SIGTRAP TRAP_BRKPT） |
| syscall 号 | 见 stub 头 `SYS_*`（read=0, write=1, mmap=9…） | 完全不同（read=63, write=64, mmap=222…） |
| TLS/FS | `arch_prctl(ARCH_SET_FS/GS)` | 无该 syscall；glibc TLS 用 `TPIDR_EL0`（需采集/恢复） |
| FPU 状态 | NT_X86_XSTATE（xsave 域，≤4096 截断） | NT_FPREGSET（fpsimd 512B）；SVE 用 NT_ARM_SVE（可超 16KB，容量风险） |
| 信号帧 | frame(uc-8) + ucontext（~0x130，fpstate 0x140 起内嵌或独立） | rt_sigframe：siginfo(128B) + ucontext；sigcontext 内嵌 `__reserved[4096]`（fpsimd/SVE 上下文存于此处或独立分配） |
| eflags | TF/RF/AC 位（baremetal 恢复须清 TF 防单步风暴） | `pstate`（无 TF；SS 位 bit21 需清，SPSR 语义不同） |
| 栈增长 | `[stack]` 段 `MAP_GROWSDOWN` | arm64 内核同样支持 MAP_GROWSDOWN（栈向下增长）✓ |
| 注入 stage2 | 手写 x86_64 字节（movabs/lea/自跳转） | 需 aarch64 指令字节（adr/ldr/b/bl/svc） |
| 指令计数 | perf_event_open + SIGIO ✓ | 同（syscall 号 241）✓ |
| 回放表 rec | pc 修正 `pc-2`（int3 前） | `pc-4`（brk 前） |
| 断点替换 | `0f 05 → cc 90`（2 字节成对） | `d4000001 → d4200000`（4 字节整替换，无需 nop） |
| ELF 组装 | `e_machine=EM_X86_64` | `e_machine=EM_AARCH64`（其余 Elf64 结构通用） |

## 1. 迁移工作分解（按依赖顺序）

### Phase 1：采集侧架构抽象（collect.c / include/elftrace.h）

**1.1 寄存器快照结构体化**

- 现状：`sn->regs` 是 `struct user_regs_struct`（x86_64 专用），
  `h.regs_size = sizeof(...)` 写死。
- 迁移：定义 `union`/`struct elftrace_regs`（或保持 u8 缓冲 +
  `regs_size`），按 `sn->arch` 决定解释：
  - x86_64：`user_regs_struct`（216B，偏移见 `PT_REGS_*`）
  - aarch64：`struct user_pt_regs`（`sys/user.h`：`regs[31]`, `sp`, `pc`,
    `pstate`，共 272B）
- 注意：`.elftrace` 头 `regs_size` 已字段化（v4），格式兼容；
  但 `dump.c:166` 按 `27*8` 硬编码 x86_64 偏移打印，需按 arch 分支。

**1.2 in-flight syscall 检测（collect.c:636）**

- 现状：`sn->regs.orig_rax == -1` 判"在 syscall 中"。
- aarch64：syscall 进行中时 `pstate` 无直接标志；用
  `PTRACE_GET_SYSCALL_INFO`（trace 路径已用）或检查
  `sn->regs.pc` 处指令是否为 `svc #0` 的前 4 字节窗口；
  内核的 syscall-stop 状态可通过 `PTRACE_GET_SYSCALL_INFO`
  （`PSYSCALL_TRACE_ENTER/EXIT`）获得，建议统一走它。

**1.3 eflags/pstate 清理（collect.c:878）**

- 现状：`#if defined(__x86_64__)` 清 eflags TF(bit8)（ptrace 停止机制残留）。
- aarch64：`pstate` 的 SS 位（bit21，单步）同样会被 ptrace 残留；
  清 `pstate &= ~(1<<21)`；注意保留 NZCV/DAIF。

**1.4 TLS 恢复（fs_base/gs_base → TPIDR_EL0）**

- 现状：stub 用 `arch_prctl(ARCH_SET_FS)` 恢复 TLS。
- aarch64：`ptrace(PTRACE_GETREGSET, NT_ARM_TLS)` 采集 `tpidr_el0`；
  恢复用 `ptrace` 不行（stub 是用户态）——用户态写 TPIDR_EL0 不可行，
  只能：a) 在 stub 恢复阶段用 `mrs x0, tpidr_el0` 读取当前值后
  `msr tpidr_el0, xN`？**用户态禁止写 tpidr_el0**（EL0 不可写，会 SIGSEGV/
  SIGILL）——正确做法：**通过 sigframe 恢复**（内核在 rt_sigreturn 时恢复
  TPIDR_EL0）——所以 ucontext 方案天然支持：内核信号帧里有没有 tpidr？
  没有（ucontext 无 TLS 字段）——**方案：采集 tpidr_el0 到 desc，
  stub 在目标首次信号帧建立后用 `svc` 不可行**……实际可行方案：
  a) 把 TLS 值写入新进程的 `prctl(PR_SET_TSC?)` 无；b) 用 `sigaltstack`
  无；c) **在 stub 代码里用 `msr tpidr_el0, x0`（EL1 指令，用户态非法）**
  ——正确做法是：**aarch64 的 `set_tls` 用户态唯一入口是
  `arch_prctl` 的 aarch64 对应物不存在**，但**内核提供
  `prctl(PR_SET_MM)`？不**——实际上 glibc 的 TLS 初始化通过
  **信号帧的 uc_mcontext 无法携带**。结论：**aarch64 上 TPIDR_EL0 的
  用户态恢复只能通过"先让目标执行一段 stub 代码"（在目标上下文内
  `msr`）或依赖 glibc 的 TLS 布局与切片进程一致（动态链接器重定位
  后 tpidr 重新初始化，通常无害）**。建议 Phase 2 实验验证：
  切片进程的 ld.so 初始化会重置 TPIDR_EL0，目标后续 `__thread` 访问
  依赖其一致性——若不一致，需要 stub 在 rt_sigreturn 前把一段
  `msr tpidr_el0, x0; ret` 代码注入目标执行（stub 内 jit 一段）。

**1.5 FPU regset**

- 现状：`NT_X86_XSTATE`（xsave），上限 4096 截断告警。
- aarch64：`NT_FPREGSET`（512B fpsimd）内嵌 sigframe reserved 区；
  SVE 时 `NT_ARM_SVE`（大小可变，最大 256×32×2+…可超 16KB）——
  **4096 容量限制是主要风险**；建议 Phase 2 先支持 fpsimd（512B），
  SVE 标记"不支持"（告警降级，目标若依赖 SVE 寄存器会坏）。

### Phase 2：stub_aarch64.S 完整实现（最大工作量）

现有 50 行框架注释已给出正确方向（ucontext + svc #0 139），按
x86_64 stub 的结构逐段移植：

**2.1 启动恢复链（对应 stub_x86_64.S _start~ipc_done）**

- blob 布局不变（desc/fpu/sigmask/sigacts/regs/maps_buf/ipc/stack/
  sigframe/entry，见 elftrace_stub.h）——但 `STUB_REGS_SIZE=272`、
  信号帧区需按 aarch64 frame 大小重估（见 2.4）。
- 寻址：x86_64 用 `label+const(%rip)`（自动重定位）；
  aarch64 用 `adrp xN, label; add xN, xN, :lo12:label`（PIC 地址计算），
  或 `adr`（±1MB 内）。**注意**：blob 可能超过 1MB（大 payload），
  跨页寻址必须 adrp+add 成对，不能只 adr。
- syscall 号表：aarch64 常用（Linux asm-generic/unistd.h）：
  read=63, write=64, openat=56, close=57, lseek=62, mmap=222,
  mprotect=226, munmap=215, brk=214, rt_sigaction=134, rt_sigreturn=139,
  rt_sigprocmask=135, ioctl=29, getpid=172, kill=129, dup2=33,
  fstat=80, fsync=82, setrlimit=164, prctl=167, perf_event_open=241,
  exit=93, exit_group=94, membarrier=276。
- syscall 调用约定：x8=号，x0-x5=参数，返回值 x0；`svc #0`。

**2.2 寄存器恢复：ucontext + svc #0（推荐方案 a）**

- 构建 aarch64 rt_sigframe：
  ```
  struct rt_sigframe {
      struct siginfo info;      /* 128B */
      struct ucontext uc;
  };
  struct ucontext {
      unsigned long uc_flags;       /* 0x00 */
      struct ucontext *uc_link;     /* 0x08 */
      stack_t uc_stack;             /* 0x10 (24B) */
      struct sigcontext uc_mcontext;/* 0x28 */
      sigset_t uc_sigmask;          /* 0x28+sizeof(sigcontext) */
  };
  struct sigcontext {
      __u64 fault_address;          /* 0x00 */
      __u64 regs[31];               /* 0x08: x0-x30 */
      __u64 sp;                     /* 0x100 */
      __u64 pc;                     /* 0x108 */
      __u64 pstate;                 /* 0x110 */
      __u8 __reserved[4096];        /* 0x118 */
      struct _aarch64_ctx *reserved;/* 0x1118 */
  };
  ```
- fpsimd 上下文（512B）写入 reserved 区起始：
  `{magic=0x45565301(FPSIMD_MAGIC), size, vregs[32], fpsr, fpcr}`；
  SVE 时 `SVEC_MAGIC=0x53564501` 结构（Phase 2 不支持则清 X 标志
  或用 fpsimd 降级）。
- 内核要求 sigframe 完整（siginfo 非空指针也需有效），
  `svc #0` 触发 rt_sigreturn（139），内核恢复 x0-x30/sp/pc/pstate。

**2.3 fd / 段 / RLIMIT 恢复**：逻辑同 x86_64，仅换 syscall 号与
寻址方式；`MAP_GROWSDOWN`（0x100）aarch64 支持。

**2.4 baremetal 处理器移植（bm_handler~bm_done）**

- 断点：`brk #0`（`d4200000`）触发 SIGTRAP（si_code=TRAP_BRKPT）；
  处理器触发地址 = `sc->pc - 4`（brk 前 4 字节 = svc 指令）。
- 信号帧迁移：aarch64 帧大（siginfo 128 + ucontext ≈ 0x140 +
  sigcontext 4096 reserved ≈ 4.4KB）——**x86_64 的 SAFE 区
  （0x4CA0-0x62C0 = 0x1620）装不下**，需扩大安全区或迁移策略调整
  （只迁移 siginfo+uc 主体，fpsimd 数据单独拷贝重指——同 x86_64
  fpstate 处理思路）。
- 处理器保存现场：aarch64 处理器用 x19-x28（callee-saved）保存目标
  寄存器；push 到安全区；恢复时从 sigcontext 写回。
- 回放命中：unmap（munmap 215）/ newseg（mmap 222 + mprotect 226）/
  dirty（rep 等价：`ldr/str` 循环或 `memset` 优化——注意 aarch64 无
  rep movsb，用 `stp` 成对存储循环，页拷贝需避免 dcache 问题——
  普通内存拷贝即可，无需 cache flush（数据非指令））。
- 恢复现场：x0 = rec.rax（返回值）、pc = rec.pc+4、pstate 清 SS
  （bit21）与保留位（D/A/I/F 由 sigframe 原值）。
- 处理器内部 syscall（unmap/newseg 的 mmap/munmap/mprotect、exit）
  与 x86_64 一致：直接 svc。

**2.5 指令计数 IPC**：perf_event_open（241）+ SIGIO，逻辑同 x86_64。

**2.6 信号帧里的 sigactions**：aarch64 `struct sigaction` 布局
（`sa_handler, sa_flags, sa_restorer, sa_mask` 同 x86_64 位宽）
——k_sigaction 前 32B 结构一致，stub 恢复逻辑可复用（确认
`rt_sigaction` 的 sigsetsize 参数同为 8）。

### Phase 3：build.c 架构化

**3.1 按 arch 选择 stub blob**

- 现状：`build.c:518` 拒绝非 x86_64；`stub_blob_x86_64` 硬编码。
- 迁移：`extern stub_blob_aarch64`；按 `s.h.arch` 选 blob；
  Makefile 增加 `stub_aarch64.S → stub_blob_aarch64.c` 规则
  （交叉汇编：`aarch64-linux-gnu-as` 或本机 as，取决于构建主机）。

**3.2 syscall 替换与 pc 修正**

- x86_64：`0f 05 → cc 90`（2B），rec.pc 修正 `pc-2`（0xcc 处）。
- aarch64：`d4000001 → d4200000`（svc→brk，4B 整替换）；
  rec.pc 修正 `pc-4`；"替换地址判定"用 blob 中 `d4200000` 前 4 字节
  匹配。
- 退出点（exit_override/--to）：brk #0 替换同上。

**3.3 ELF 组装**

- `e_machine = EM_AARCH64`、`e_flags = 0`（LP64）、`e_ident[EI_CLASS]=64`
  已通用；`e_entry` 指向 stub 入口（blob 内偏移不变）。
- gap 选址（pick_base）：aarch64 用户空间布局与 x86_64 不同
  （aarch64 48 位 VA：0x000000000000-0x0000ffffffffffff；内核地址
  0xffff000000000000+）；pick_base 逻辑（扫描 maps 找空闲区）通用，
  但需注意 aarch64 的 mmap 起始地址（0x550000000000 附近）与
  vdso/vvar 位置。
- 回放表布局（rec 80B）通用（pc/sysno/rax…），rax 字段解释为
  x0 返回值。

**3.4 desc 布局**：`RST_DESC_*` 字段全部 u64 通用；
`RST_DESC_REGS_OFF/SIZE` 按架构写（272B aarch64）。

### Phase 4：inject.c 移植

- stage2 字节序列（`build_stage2`）重写为 aarch64：
  - `movabs reg, imm64` → `movz/movk`（4×16bit）或 `ldr xN, #label`
    （字面量池，推荐：专用页内放常量区）
  - 自跳转/返回：`bl/b` 或 `adr + br`
  - fork 调用：`svc #0`（fork=220？aarch64 无 fork——用 clone 或
    vfork=98；**注意 aarch64 没有 fork 系统调用**（asm-generic 下
    fork 不存在，用 clone（220）或 posix_spawn 语义）
  - 自旋等待：`wfe`/循环
- `struct user_regs_struct` 参数 → 按 arch 传递 regs 快照。

### Phase 5：trace.c / freeze.c / dump.c 架构化

- trace：`rip - 2` → `pc - 4`（syscall 指令长）；`regs.rip` →
  `regs.pc`；`PTRACE_GET_SYSCALL_INFO` 通用 ✓。
- freeze：seize/interrupt/SIGSTOP 通用 ✓。
- dump：regs 打印按 arch（x86_64 现硬编码 27×8）。

### Phase 6：测试

- 现有 prog_*.c 全部纯 C 可交叉编译 ✓；`-pthread` 的 thread 测试
  语义不变。
- tests/IMIX：DynamoRIO 支持 aarch64 ✓（drrun 有 arm64 版）。
- run_tests.sh 在 aarch64 主机直接跑（前提 ptrace_scope=0）。
- 新增 aarch64 专用断言：
  - svc→brk 替换生效（切片 strace 无 `svc` 系统调用）
  - TPIDR_EL0 一致性（`__thread` 变量跨切片）
  - fpsimd 恢复（浮点计算跨切片）
  - baremetal 回放 9 负载（复用 test_baremetal.sh 框架）

## 2. 关键风险与决策点

| 风险 | 说明 | 建议 |
|---|---|---|
| 信号帧尺寸 | aarch64 sigframe 含 siginfo 128B + reserved 4096B ≈ 4.4KB，x86_64 安全区（0x1620）装不下 | Phase 2.4：扩大安全区或 fpsimd 数据单独拷贝重指（复用 x86_64 fpstate 经验）；注意安全区上限（当前 blob 固定区 0x8000 布局可调） |
| SVE/SME 状态 | NT_ARM_SVE 可超 16KB，远大于 4096 xstate 上限 | 先只支持 fpsimd（512B）；SVE 检测到即告警降级（目标若用 SVE 会丢状态） |
| TPIDR_EL0 | 用户态不可写，ucontext 无法携带 | 实验：切片进程 ld.so 会重置 TLS 通常无害；若需严格恢复，stub 内 jit `msr tpidr_el0, x0; ret` 让目标执行 |
| 无 fork syscall | aarch64 asm-generic 无 fork（用 clone/vfork） | inject stage2 改用 clone（220） |
| brk SIGTRAP 语义 | aarch64 `brk` 的 si_code=TRAP_BRKPT（非 SI_KERNEL），处理器判定逻辑按 si_code 处需适配 | 处理器按"收到 SIGTRAP 且 pc-4 是 brk 编码"判定，不依赖 si_code |
| 指令数一致性 | baremetal 处理器指令流与 x86_64 不同（stp 循环 vs rep movsb），指令数差需重新标定 | IMIX/perf 断言阈值沿用（<1%），以实际测量为准 |
| 交叉构建 | stub 汇编需 aarch64 汇编器；无硬件时无法验证 | 用 QEMU user 模式（qemu-aarch64）跑切片 ELF 做冒烟验证；PTRACE 相关需 qemu 支持（qemu-user 不支持 ptrace 目标跟踪，需真机或 qemu-system+内核） |
| big endian | aarch64 大端变体（BE8） | 目标为小端 LE（默认），格式头可加 endian 标志（暂不需要） |

## 3. 工作量估算

| 阶段 | 内容 | 估算 |
|---|---|---|
| P1 | 采集侧抽象（regs 结构体化、in-flight 检测、TLS 采集、pstate 清理、FPU regset） | 0.5-1 天 |
| P2 | stub_aarch64.S（启动恢复 + baremetal 处理器 + fpsimd + 信号帧） | 3-5 天（含调试） |
| P3 | build.c（stub 选择、svc→brk、pc-4、ELF 组装、Makefile） | 1 天 |
| P4 | inject.c stage2（aarch64 字节码，clone 替代 fork） | 0.5-1 天 |
| P5 | trace/freeze/dump 架构化 | 0.5 天 |
| P6 | 测试适配 + 真机/QEMU 验证 | 1-2 天 |
| 合计 | | 7-11 天（不含 SVE） |

## 4. 建议实施顺序

1. **P1 + P3 先行**（纯 C 侧）：打通"freeze aarch64 目标 → build 报错前
   能解析 → 占位 stub 输出可执行但恢复不完整"的链路，尽早暴露格式问题。
2. **P2 最小恢复链**：先不做 baremetal，只做 real 模式（段/fd/寄存器/
   fpsimd/信号帧恢复），用 qemu-aarch64 或真机验证 simple/fd/stack。
3. **P4 注入**（trace/检查点依赖）。
4. **P2.4 baremetal 处理器** + 回放表验证（fd_rw 10/10 对标 x86_64）。
5. **P6 全量测试** + IMIX/指令数标定。

## 5. 验证环境建议

- 真机（树莓派 4/5、RK3588 等）最理想：ptrace/perf/dynamorio 全可用。
- qemu-system-aarch64 + 内核（virt 机型）可跑全套（慢 10-50x）。
- qemu-user 只适合跑"已构建的切片 ELF"冒烟（不能作为 ptrace 目标）。
- 交叉编译工具链：`aarch64-linux-gnu-gcc`（collect/build/trace 是
  主机侧工具，运行在 aarch64 主机上编译即可；stub 汇编用目标
  汇编器）。

## 6. 迁移进展（2026-08，qemu-system 验证通过）

本机 (x86_64) 已用 **qemu-system-aarch64 + Alpine arm64 内核 +
initramfs** 打通完整工具链验证，`tests/aarch64/run_vm_tests.sh` 驱动：

| 用例 | 结果 |
|---|---|
| simple real 切片 | rc/输出与 ref 全等 |
| stack real 切片 (96MB 深栈) | rc/输出与 ref 全等 |
| fd real 切片 (fd 恢复续写) | rc/输出/文件内容 (AAABBB) 全等 |
| bigmem real 切片 (128MB) | rc/输出全等 |
| baremetal mock (freeze) | rc 与 ref 全等 |
| baremetal 回放表 (trace) | rc 与 ref 全等 |

已实现: collect/trace/dump 架构抽象 (include/arch.h), stub_aarch64.S
real 恢复链 + baremetal 处理器, build svc→brk 替换 + EM_AARCH64,
Makefile ARCH=aarch64 交叉构建, TPIDR_EL0 jit 采集 (collect_tls_jit),
trace perf 软件事件回退。

关键发现 (踩坑记录):
- **qemu-user 无 ptrace** (SEIZE/GETREGSET 返回 ENOSYS) → 必须用
  qemu-system。
- **qemu TCG 无 PMU** → perf 硬件指令事件不可用; trace 已加
  PERF_TYPE_SOFTWARE task-clock 回退 (时间基检查点, 回放表照常)。
- **内核 NT_ARM_TLS 只在上下文切换时同步** uw.tp_value, 从未被换出的
  目标读到 exec 后的陈旧 0 → 用 jit (`mrs x0, tpidr_el0; brk`) 让目标
  自己读 HW 寄存器。
- **aarch64 brk 的 sigcontext pc = brk 地址本身 (非 +4)**; baremetal
  处理器 trigger = sc->pc, 恢复 pc 需 +4 跳过 brk。
- **内核 ucontext 布局**: uc_sigmask 在 uc+0x28, uc_mcontext 实测在
  uc+0xB0 (uapi 头显示 0xA8 但 VM 实测为 0xB0); sigcontext.__reserved
  16B 对齐 (sc+0x120); rt_sigreturn 强制要求 fpsimd context。
- 处理器经内核进入后目标寄存器已恢复, 必须重算 blob base; sigaction
  的 handler 必须是绝对地址 (blob base + blob 偏移)。

未完成 (真机/继续): inject.c stage2 aarch64 (trace 当前不依赖),
--ipc 指令数精确断言, DynamoRIO imix, SVE 状态, 完整 17 项测试矩阵。
