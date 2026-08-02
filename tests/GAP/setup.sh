#!/bin/bash
# GAP Benchmark Suite 下载与构建脚本
# - 下载 gapbs 代码 (可过代理) 到本目录 gapbs/ (git 不管理)
# - 编译 (需要 g++)
# - 数据集: gapbs 内置 kron 图生成器 (-g <scale>) 足够小图测试;
#   外部大图下载为可选 (见底部注释)
set -u
cd "$(dirname "$0")"

# 代理 (可选, 环境变量 HTTP_PROXY/HTTPS_PROXY 已设则直接用)
GIT_BASE="https://github.com/sbeamer/gapbs.git"
if [ ! -d gapbs/.git ]; then
    git clone --depth 1 "$GIT_BASE" gapbs || exit 1
fi
cd gapbs
make -j"$(nproc)" || exit 1
echo "GAPBS built: $PWD"
echo "测试: ./bfs -g 20 (kron 图 scale 20, ~200MB 内存)"
