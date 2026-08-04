# aarch64 验证 (qemu-system VM)

本机 (x86_64) 无 aarch64 硬件; qemu-user 不支持 ptrace (SEIZE 返回
ENOSYS), 因此用 qemu-system-aarch64 + Linux 内核跑完整工具链:

```
tests/aarch64/run_vm_tests.sh
```

前置:
- aarch64-linux-gnu-gcc / as / ld / objcopy (交叉工具链)
- qemu-system-aarch64
- 静态 aarch64 busybox + bash (initramfs shell; 无则脚本提示路径)
- arm64 Linux 内核 (vmlinuz, 例如 Alpine netboot 的 vmlinuz-virt)
- kernel 内 perf_event 硬件事件可用性: qemu TCG 无 PMU, trace 自动
  回退软件事件 (task-clock, 时间基检查点) — 回放表照常采集

脚本交叉编译测试程序与 elftrace, 组装 initramfs (含测试驱动), 启动
VM 跑用例, 从串口输出解析 PASS/FAIL。通过条件与 x64 对齐: rc 与
ref 全等、输出一致 (fd 恢复续写处)、baremetal 目标阶段无真实 syscall。

已知限制 (qemu TCG):
- perf 硬件指令计数不可用 → trace 检查点按时间 (1s), interval/IPC
  指令数断言不适用 (rc/输出断言仍有效)
- DynamoRIO 不可用 (x64 专属) → imix 指令分布断言跳过
- 切片运行慢 (TCG), 用例数少于 x64 矩阵; 真机上可跑完整 tests/
