# AGENTS.md — elftrace 开发指南（给 Agent 看）

进程切片基础设施：freeze 冻结进程采集状态到 `.elftrace`，build 组装成
可执行 ELF，运行该 ELF 等价于从冻结点恢复进程。功能与用法见 README.md。

## 构建

```bash
make                 # 生成 build/elftrace（含汇编 stub 的 blob 生成）
make clean           # 全量重编（改 include/*.h 后若依赖不触发，先 clean）
```

- 工具链：gcc / as / ld / objcopy / xxd
- `Makefile` 的 `%.o` 规则已依赖 `$(wildcard include/*.h)`；但**改头文件
  后仍建议 make clean**（历史教训：结构大小不一致导致栈溢出崩溃）
- stub 生成链：`stub_x86_64.S` → as → ld(stub.ld) → objcopy → 字节数组
  嵌入 `src/stub_blob_x86_64.c`（生成的，勿手改）

## 运行环境

- `kernel.yama.ptrace_scope=0`（冻结任意进程）；perf_event_paranoid ≤ 2
  （trace/IPC 用 perf 自计数）
- 测试需要同 uid 跟踪目标

## 测试

```bash
tests/run_tests.sh   # 一键运行全部 17 项测试（basic/dbg/fd/ipc/cpp/fd_rw/
                     # py/syscall/stack/bigmem/thread/append/bareheap/
                     # interval/bundle/baremetal/imix；imix 在
                     # tests/IMIX/test_imix.sh，run_tests 特判路径）
```

测试脚本约定（新增测试必须遵守）：
- bash + `set -u` + `cd "$(dirname "$0")/.."`
- 用 `timeout` 防挂；PASS/FAIL 输出；失败给出明确断言信息
- **清理残留进程用 `pgrep -x <精确进程名>`**（禁止 `pgrep/pkill -f`，
  会匹配到 shell 自身命令行导致自杀挂起）
- **strace 必须直接跟踪目标**：`timeout 60 strace -o f ./target`，
  不能 `strace -o f timeout 60 ./target`（后者跟踪的是 timeout）
- baremetal 测试断言只查退出码（write 被 mock 丢弃，输出不可见）

## baremetal 回放（新机制，改代码前必读）

- **采集**（trace.c）：PTRACE_SYSCALL 捕获每个 syscall 的 ENTRY（A）/EXIT
  （B）状态 → 离线 `collect_write_diff(A,B)` 写 `syscalls/sys_%06zu.elftrace`
  + `syscall.map`（行号=索引）；被打断的 syscall 补记 A=上一检查点，map
  行追加第 4 字段 `I`（build 据此丢弃悬空记录，见下）。
- **构建**（build.c 3.5a/3.5b/3.6）：
  - 3.5a 解析 map，只保留切片区间 `[syscall_start, syscall_end)` 记录；
    **丢弃悬空的被打断记录**：`I` 标记且 `rec.pc+2 == resume_pc`（该
    syscall 在恢复检查点时刻在途，恢复 pc 在其指令之后，切片不会重执行
    它；保留会被下一条同 pc 的 syscall 误消费——libc 共享 trampoline
    场景曾致 read 被回放成已完成的 nanosleep 而返回 EOF）。
  - 3.5b **syscall→int3 定点替换**：只把回放记录对应的 syscall 指令
    （entry-stop ip = syscall+2，指令在 pc-2；被打断记录 pc 已是指令
    本身）替换为 int3。**禁止改回全段 `0f 05` 模式扫描**——会误伤指令
    立即数中的同字节序列（如 `movabs $0x50f` → `48 b8 0f 05 ...` 被改
    成 `cc 90`，静默改变切片行为；回归测试 tests/test_bm_edge.sh imm）。
    无 trace 数据的旧 mock 路径（freeze 快照）保留模式扫描 + 警告。
  - 3.6 布局回放表：`n_recs + rec×80B + 数据区`。
- **stub 处理器**（stub_x86_64.S bm_handler~bm_done）：
  - 有回放表时把内核 sigframe 迁移到 `bm_safe_area`（blob+0x4CA0，
    容量上限 0x62C0-0x4CA0=0x1620）；**fpstate 统一拷贝到 SAFE+0xB50 并
    重指 sc->fpstate**（大 xstate 时内核在 frame 外分配独立缓冲，dirty
    回放会覆盖它；迁移区装不下，不能靠扩迁移区——曾因扩到 0x2300 覆盖
    代码区自我崩溃）。
  - 回放命中：unmap=munmap；newseg=mmap(RW,FIXED)+拷贝+mprotect
    （**ET_SEG flags(X=1,W=2,R=4)≠PROT(R=1,W=2,X=4)，必须转换**）；
    dirty=rep movsb 整页覆盖（数据内嵌回放区）。
  - 恢复现场：rax=rec.rax、rip=rec.pc+2、eflags 清 TF/RF/AC
    （掩码 -0x50101，注意 -0x50100 的 TF 位未清）。
- **调试教训**：禁止在处理器内用 write 打印调试（fd 已被 stub 恢复成目标
  输出文件，污染输出与指令数；BMS_RSP/BMS_RBP 等宏定义在处理器区头部，
  改代码前确认存在）。

## 代码结构

| 文件 | 职责 |
|---|---|
| `src/collect.c` | 状态采集（freeze/trace 共用）：regs/xstate/sigmask/RLIMIT_STACK/内存段/fd/调试节/PIE 偏置 |
| `src/freeze.c` | freeze CLI：seize+interrupt → 采集 → SIGSTOP+detach（保持冻结） |
| `src/trace.c` | trace CLI：perf 指令计数 + 每 N 条注入 fork 采集检查点 + manifest |
| `src/inject.c` | 两阶段注入（compel 式）：stage1 冷代码页 mmap 专用页，stage2 fork；子进程（镜像代理）自旋持 fork 时刻 COW 快照 |
| `src/build.c` | 组装 ELF：gap 选址、desc 补丁、baremetal syscall→int3 替换、调试节重建；--checkpoints 应用增量差异链合成 |
| `src/bundle.c` | trace bundle 归档（目录↔单文件），build 自动识别 |
| `src/stub_x86_64.S` | 恢复 stub（PIC 汇编）：内存/fd/RLIMIT/fs_base/信号帧/baremetal 模拟器 |
| `src/dwarf.c` | DWARF v4/v5 地址偏置修补 |
| `include/elftrace.h` | `.elftrace` v3 格式 |
| `include/elftrace_stub.h` | stub blob 布局 + desc 字段（C 与 .S 共享，纯宏） |

## 关键约定与坑（改代码前必读）

- **stub 寻址**：blob 内一律 `label+const(%rip)`（符号产生重定位）；
  **禁止 `常量(%rip)`**——那是绝对位移，不产生重定位，运行必错。
- **desc 布局**：`include/elftrace_stub.h` 的 `RST_DESC_*` 偏移是
  build（补丁）与 stub（读取）之间的契约；新增字段要同步三处：
  头文件宏、`stub_x86_64.S` 的 `.quad`、`build.c` 的 `blob_patch_u64`。
- **blob 固定区**：0x8000 字节（desc/xstate/sigmask/regs/栈/信号帧/代码）；
  追加区（segs/fds/字符串/payload）由 build 拼接。fpu 容量 4096。
- **ptrace 语义**：
  - SEIZE+INTERRUPT 后 DETACH 会唤醒 tracee（新内核），冻结需先
    `kill(SIGSTOP)` 再 detach；`SIGCONT` 可唤醒。
  - trace 全程保持 SEIZE，检查点之间只 INTERRUPT/CONT（不能重复 SEIZE）。
  - freeze 可采集已 SIGSTOP（T 状态）的进程。
- **perf 与注入**：注入的 fork 子进程退出会破坏 perf 事件对目标的计数
  （重新 enable/重开均无效）——代理由 trace 结束统一回收；trace 被强杀
  （SIGKILL）时代理泄漏。
- **延迟 dump**：trace 在线只做轻量采集（fork 代理 + 状态），内存 dump
  在目标阶段结束后按检查点顺序离线进行（diff 需要顺序）；代理 pause
  阻塞 + setpgid 脱离目标组（避免孤儿组 SIGHUP 击杀），不占 CPU。
  SIGTERM/SIGINT 触发优雅退出（先离线 dump）。
- **COW 注入轮询**：必须排除旧代理（上一轮检查点的代理 flag 早已置 1，
  误选会导致从旧代理读取缺新段 → EIO → 检查点段零填充 → 切片崩溃）。
- **增量检查点**：检查点 0 完整 .elftrace，后续 elftrace_diff 文件
  （状态区 regs/xstate/sigmask/fds + unmap 段 + newseg 段 + dirty 页）；
  build 从 ckpt_000000 应用差异链合成（collect_snapshot_load + apply_diff
  需同步维护 payload_offs）。diff 的脏页覆盖以 vaddr 找段、用 payload_offs
  定位，禁止顺序累积偏移（段序会变）。
- **meta 区**：v4 头含 meta_off/meta_size（采集环境信息 key=value）；
  collect_write 只在 meta 非空时写 meta 区（含 NUL, size+1）——NULL 时
  偏移规划不得 +1（曾导致 1 字节错位全线崩溃）。
- **brk**：不恢复内核 brk（目标 glibc brk 缓存与切片内核 brk 差距可达
  数十 TB，overcommit 拒绝）；glibc malloc 会 fallback mmap。
- **RLIMIT_STACK**：必须恢复（目标 setrlimit 的栈限制在切片进程是默认
  8MB，深栈程序会 SIGSEGV）。
- **`[stack]` 段恢复加 MAP_GROWSDOWN**（允许越过冻结栈底增长）。
- **`[heap]` 定位**：取第一个 `[heap]` 段（mmap 大块匿名段也可能被内核
  标为 `[heap]`）。
- **信号帧**：处理器入口 rsp = frame（uc-8），push 后偏移要算准；
  内核要求信号处理器带 SA_RESTORER，否则拒绝投递（-EFAULT→SIGSEGV）。
- **格式版本**：`ELTRACE_VERSION` 在 include/elftrace.h；改动格式字段
  必须 +1（collect 写、build/dump 读需同步）。

## 已知限制（勿试图"修复"成不支持的东西）

- 单线程（多线程切片语义未定义）；vdso/vvar/vsyscall 不恢复；
  sigactions 未采集；MAP_SHARED 按匿名副本；pipe/socket fd 跳过；
  xstate 上限 4096。
- 改 `src/` 核心代码前先跑 `tests/run_tests.sh` 建立基线。

## aarch64 (交叉构建 + qemu-system 验证)

- 本机交叉构建: `make ARCH=aarch64 BUILD=build-aarch64 LDFLAGS=-static`
  (需 aarch64-linux-gnu-* 工具链; 产物在 build-aarch64/, 已 gitignore)。
- 本机验证: `tests/aarch64/run_vm_tests.sh` (qemu-system-aarch64 +
  arm64 内核 + initramfs; 6 用例: real simple/stack/fd/bigmem +
  baremetal mock/replay)。通过条件与 x64 对齐: rc/输出与 ref 全等。
- qemu-user 无 ptrace、qemu TCG 无 PMU → trace 用软件事件回退。
- **TPIDR_EL0 采集必须用 jit** (collect_tls_jit): 内核 NT_ARM_TLS 只在
  上下文切换时同步, 从未被换出的目标读到陈旧 0。
- **aarch64 brk 的 sigcontext pc = brk 地址本身**: baremetal 处理器
  trigger=sc->pc, 恢复 pc=sc->pc+4。
- 内核 ucontext: uc_mcontext 实测在 uc+0xB0, __reserved 16B 对齐
  (sc+0x120), rt_sigreturn 强制 fpsimd context — 改 frame 布局前
  必读 src/stub_aarch64.S 顶部的注释。

## aarch64 strict baremetal (--bm-strict, ELF loader 型)

真机 (postmarketOS aarch64) 验证通过。目标: 运行期除 execve +
exit_group 外零 syscall。

- 内存布局: build 把所有初始段、窗口内未来 newseg (回放记录)、栈预留
  (`--stack-reserve`, 默认 256MB)、跳板页全部发成 PT_LOAD, 由 ELF
  loader 建立; stub 跳过运行时 mmap/mprotect/munmap。
- syscall 替换: 目标代码 `svc #0` (d4000001) 定点替换为 `b <跳板>`;
  跳板 32B 条目 (ldr x16,[pc,#16]; ldr x17,[pc,#20]; br x17; nop;
  .quad data_block; .quad handler) → comp_engine (STUB_STRICT_COMP_OFF):
  - 站点块 304B: pc / ret_addr / replay_abs / x0-x30 保存槽 / brk 边界 /
    target_tid / 游标;
  - 引擎按 pc 从游标顺序扫描回放表 (同 pc 多记录正确消费), 无表
    (replay_abs=0) 或越界走 mock; 回放只做纯访存 (newseg/dirty 拷贝),
    恢复现场 (x0=rax, 仅 x16/x17 破坏);
  - **rec 指针必须保存在 x23** (memcpy 破坏 x0-x5, 曾致 dirty 循环后
    rax 读错/越界)。
- 退出点:
  - 唯一路径: 目标指令 → `b <exit 跳板>` → strict_exit_code
    (STUB_STRICT_EXIT_OFF, exit_group(0));
  - do-while 循环 (回边无条件): patch 回边 → loop_handler
    (STUB_STRICT_LOOP_OFF), counter 决定何时退出;
  - while 循环 (回边条件): **不能 patch 回边** (会破坏循环退出语义,
    如 j<n 越界); 改为 patch 目标指令 → count_handler
    (STUB_STRICT_COUNT_OFF), 计数器到 0 → 退出, 否则执行 blob 内
    原指令副本 (仅限非 PC 相对指令) 后跳回 P+4;
  - 站点块/跳板必须 16B 对齐 (内嵌可执行指令; blob 尺寸可能非对齐,
    build 已补)。
- 采集侧:
  - collect_tls_jit 对已 SIGSTOP 目标需要 SIGCONT 放行一次再等 brk;
  - collect_snapshot_load 必须带出 tls/rlim/exe 字段 (增量合成否则丢);
  - aarch64 syscall entry-stop 的 ip 指向 svc 本身 (detect_in_syscall
    查 pc 而非 pc-4);
  - syscall.map 每条记录追加捕获时 perf 计数 (第 5 字段), build 按
    [count_from, count_to) 过滤窗口 (manifest 的 nsys 滞后不可靠);
  - trace 的 perf ring sample 在频繁 syscall-stop 下可能首样本后哑掉,
    有 read 计数器兜底。

## aarch64 测试

- tests/test_strict.sh: freeze mock / trace 回放中间窗口 / ioctl 设备
  操作负载 (prog_ioctl.c)。
- tests/test_realworld.sh: CRC32 文件校验 (prog_crc32.c)、RLE 压缩
  (prog_lz.c)、JSON 数字解析 (prog_json.c) — 每负载 trace 全程 +
  全窗口 strict 切片 (rc == ref) + 中间窗口切片 (rc=0, 零 syscall)。
  注意: 真机每 syscall 采集约 20-40s (全量内存 diff), 数据量需控制在
  trace 超时内 (32MB/4MB 块 ≈ 8-16 syscall)。
- 其余 baremetal 测试在 aarch64 上自动加 --bm-strict。
