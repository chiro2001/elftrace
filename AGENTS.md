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
tests/run_tests.sh   # 一键运行全部 13 项测试（basic/dbg/fd/ipc/cpp/fd_rw/
                     # py/syscall/stack/bigmem/thread/append/bareheap）
```

测试脚本约定（新增测试必须遵守）：
- bash + `set -u` + `cd "$(dirname "$0")/.."`
- 用 `timeout` 防挂；PASS/FAIL 输出；失败给出明确断言信息
- **清理残留进程用 `pgrep -x <精确进程名>`**（禁止 `pgrep/pkill -f`，
  会匹配到 shell 自身命令行导致自杀挂起）
- **strace 必须直接跟踪目标**：`timeout 60 strace -o f ./target`，
  不能 `strace -o f timeout 60 ./target`（后者跟踪的是 timeout）
- baremetal 测试断言只查退出码（write 被 mock 丢弃，输出不可见）

## 代码结构

| 文件 | 职责 |
|---|---|
| `src/collect.c` | 状态采集（freeze/trace 共用）：regs/xstate/sigmask/RLIMIT_STACK/内存段/fd/调试节/PIE 偏置 |
| `src/freeze.c` | freeze CLI：seize+interrupt → 采集 → SIGSTOP+detach（保持冻结） |
| `src/trace.c` | trace CLI：perf 指令计数 + 每 N 条注入 fork 采集检查点 + manifest |
| `src/inject.c` | 两阶段注入（compel 式）：stage1 冷代码页 mmap 专用页，stage2 fork；子进程（镜像代理）自旋持 fork 时刻 COW 快照 |
| `src/build.c` | 组装 ELF：gap 选址、desc 补丁、baremetal syscall→int3 替换、调试节重建 |
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
  （重新 enable/重开均无效）——所以镜像代理必须保持自旋，由 trace 结束
  统一回收；这也导致 trace 被强杀时代理泄漏。
- **COW 注入轮询**：必须排除旧代理（上一轮检查点的代理 flag 早已置 1，
  误选会导致从旧代理读取缺新段 → EIO → 检查点段零填充 → 切片崩溃）。
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
  xstate 上限 4096；aarch64 仅接口预留。
- 改 `src/` 核心代码前先跑 `tests/run_tests.sh` 建立基线。
