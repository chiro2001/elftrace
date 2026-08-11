/*
 * elftrace 构建端: alloc 结果重放跳板生成器 (M1)
 *
 * 纯代码生成, 无 build.c 依赖 (可在 qemu-aarch64 单测里直接链接)。
 * 每个分配器入口 patch 成 b <该函数的重放块>, 块按序消费录制事件流:
 *   校验 kind → x0=录制 ret → 游标++ → 返回调用者。
 * 超消费 (reason=9) / kind 失配 (reason=11) → 写遥测后跳 bail。
 */
#ifndef ELFTRACE_ALLOC_BUILD_H
#define ELFTRACE_ALLOC_BUILD_H

#include <stdint.h>
#include <stddef.h>

/* 生成 0x280B 重放块到 out (调用方提供 RWX 页面, block_abs 为其绝对
 * 地址); 返回块大小, 0 表示生成失败。 */
size_t alloc_replay_block(uint8_t *out, uint64_t block_abs,
                          uint64_t cursor_addr, uint64_t total_addr,
                          uint64_t events_abs, uint32_t kind,
                          uint64_t tel_abs, uint64_t bail_abs,
                          uint64_t site_pc);

#endif
