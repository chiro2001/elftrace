#!/bin/bash
# 编译负载 setup: 下载 sqlite 合并源文件 (sqlite-amalgamation)
# - 下载到本目录 sqlite-src/ (git 不管理)
# - 用于 clang -O2 -c 单线程编译切片测试 (编译器真实负载, 内存峰值 1GB+)
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

VER=3530400
ZIP="sqlite-amalgamation-$VER.zip"
URL="https://www.sqlite.org/2026/$ZIP"

mkdir -p sqlite-src
if [ ! -f "sqlite-src/sqlite3.c" ]; then
    [ -f "$ZIP" ] || curl -fL --max-time 120 -o "$ZIP" "$URL" || { echo "下载失败: $URL"; exit 1; }
    unzip -o -q "$ZIP" -d sqlite-src || exit 1
    mv -f "sqlite-src/sqlite-amalgamation-$VER/sqlite3.c" \
          "sqlite-src/sqlite-amalgamation-$VER/sqlite3.h" sqlite-src/ 2>/dev/null
fi
ls -la sqlite-src/sqlite3.c
echo "测试: clang -O2 -c sqlite3.c (内存峰值 ~1.5GB)"
