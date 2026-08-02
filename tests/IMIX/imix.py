#!/usr/bin/env python3
"""imix.py — 从 DynamoRIO instrace 输出计算指令混合 (instruction mix)

instrace_simple 输出格式: 每行 "<addr>,<opcode>"
本工具统计 opcode 分布, 输出:
  total       总指令数
  opcode 表   每 opcode 计数 + 百分比 (按次数降序)

用法: imix.py <trace.log> [--top N] [--csv out.csv]
"""
import sys
from collections import Counter


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    top = 0
    csv = None
    i = 1
    while i < len(sys.argv):
        if sys.argv[i] == "--top":
            top = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == "--csv":
            csv = sys.argv[i + 1]
            i += 2
        else:
            i += 1

    if not args:
        print("usage: imix.py <trace.log> [--top N] [--csv out.csv]")
        return 1

    cnt = Counter()
    total = 0
    with open(args[0], "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                _, op = line.split(",", 1)
            except ValueError:
                continue
            cnt[op] += 1
            total += 1

    print(f"total {total}")
    items = cnt.most_common(top if top else None)
    for op, n in items:
        print(f"{n:12d} {n / total * 100:6.3f}%  {op}")

    if csv:
        with open(csv, "w") as f:
            f.write("opcode,count,pct\n")
            for op, n in cnt.most_common():
                f.write(f"{op},{n},{n / total * 100:.4f}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
