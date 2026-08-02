/* zstd_wrap.c — libzstd 单线程流式压缩
 *
 * zstd CLI 内部 (libzstd 1.5.x) 即使单线程也初始化 ZSTDMT 封装的
 * pthread 条件变量/互斥锁, 其 futex 状态在进程切片恢复下不可回放
 * (冻结可能落在 cond_wait 内部, 恢复后无限等待/abort)。
 *
 * 本程序直接用 ZSTD_compressStream2 单线程 API (nbWorkers=0, 不创建
 * MT 上下文), 压缩核心与 zstd --ultra -22 等价 (level 22 + windowLog
 * 27), 用于真实压缩负载的切片测试。
 *
 * 用法: zstd_wrap <in> <out>
 * 退出码: 0 成功, 4 压缩错误
 */
#include <stdio.h>
#include <stdlib.h>
#include <zstd.h>

int main(int argc, char **argv)
{
    if (argc != 3)
        return 2;
    FILE *fin = fopen(argv[1], "rb");
    FILE *fout = fopen(argv[2], "wb");
    if (!fin || !fout)
        return 3;

    ZSTD_CCtx *c = ZSTD_createCCtx();
    if (!c)
        return 4;
    ZSTD_CCtx_setParameter(c, ZSTD_c_compressionLevel, 22);
    ZSTD_CCtx_setParameter(c, ZSTD_c_windowLog, 27);

    char ibuf[1 << 16], obuf[1 << 16];
    ZSTD_inBuffer in = { ibuf, 0, 0 };
    for (;;) {
        size_t r = fread(ibuf, 1, sizeof ibuf, fin);
        in.src = ibuf;
        in.size = r;
        in.pos = 0;
        int last = r < sizeof ibuf;
        for (;;) {
            ZSTD_outBuffer out = { obuf, sizeof obuf, 0 };
            size_t ret = ZSTD_compressStream2(c, &out, &in,
                                              last ? ZSTD_e_end
                                                   : ZSTD_e_continue);
            if (ZSTD_isError(ret)) {
                fclose(fout);
                fclose(fin);
                return 4;
            }
            if (out.pos)
                fwrite(obuf, 1, out.pos, fout);
            if (last && ret == 0)
                break;
            if (!last && in.pos == in.size)
                break;
        }
        if (last)
            break;
    }
    fclose(fout);
    fclose(fin);
    ZSTD_freeCCtx(c);
    return 0;
}
