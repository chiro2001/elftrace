#!/bin/bash
# 压缩负载 setup: 下载 enwik8 (100MB 维基百科文本, 经典压缩基准数据)
# - 下载到本目录 data/ (git 不管理)
# - 截取前 32MB 作测试数据 (zstd --ultra -22 单线程压缩 ~30s)
set -u
cd "$(dirname "$0")"

# 代理: 首选本地 127.0.0.1:14514, 不通回退局域网代理
if curl -s --max-time 2 -o /dev/null http://127.0.0.1:14514 2>/dev/null; then
    export HTTP_PROXY=http://127.0.0.1:14514
    export HTTPS_PROXY=http://127.0.0.1:14514
else
    export HTTP_PROXY=http://192.168.101.5:14514
    export HTTPS_PROXY=http://192.168.101.5:14514
fi

mkdir -p data
if [ ! -f data/enwik8.32m ]; then
    [ -f enwik8.zip ] || curl -fL --max-time 180 -o enwik8.zip \
        "http://mattmahoney.net/dc/enwik8.zip" || exit 1
    unzip -o -q enwik8.zip -d data || exit 1
    head -c 33554432 data/enwik8 > data/enwik8.32m
    rm -f data/enwik8
fi
ls -la data/enwik8.32m
echo "测试: zstd --ultra -22 等价压缩 (zstd_wrap, 单线程, 内存 ~750MB)"

# 编译 zstd_wrap (libzstd 单线程 API; zstd CLI 内部 ZSTDMT 封装的状态
# 在切片下不可回放, 见 zstd_wrap.c 注释)
if [ ! -x zstd_wrap ]; then
    gcc -O2 -o zstd_wrap zstd_wrap.c -lzstd || exit 1
fi
echo "zstd_wrap built"
