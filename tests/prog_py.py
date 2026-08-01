#!/usr/bin/env python3
"""测试3: 冻结一个运行中的 CPython 进程, 切片后应等价继续执行。

解释器状态 (堆/栈/字节码/模块) 全部在进程内存中, 恢复后从冻结点
继续打印 CHECKPOINT 与最终 DONE, 退出码 = 最终计算结果 % 255。

--stub: 模拟"代码打桩"——在 CKPT 1 之后显式 os.kill(self, SIGSTOP)
暂停自己, 由外部 freeze 采集已停止的进程。
"""
import os
import signal
import sys


def main():
    stub = "--stub" in sys.argv
    data = [i * 2654435761 % 2**64 for i in range(256)]
    x = 0x12345678
    for c in range(5):
        for j in range(15000000):
            x = (x + data[j & 255]) * 31 & (2**64 - 1)
        print(f"CKPT {c} x={x}")
        sys.stdout.flush()
        if stub and c == 1:
            # 打桩: 暂停自己, 等待外部采集 (模拟代码内埋暂停点)
            os.kill(os.getpid(), signal.SIGSTOP)
    print(f"DONE x={x}")
    return x % 255


sys.exit(main())
