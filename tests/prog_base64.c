/* 真实负载: 2MB base64 编码/解码回环 (表驱动 + 位操作 + 堆分配)。
 * 确定性: 固定种子 LCG; 输出 READY/DONE。 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char b64tab[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static int b64rev[256];

static uint64_t rng = 0xfeedfacecafebeefULL;
static uint64_t next_rand(void)
{
    rng = rng * 6364136223846793005ULL + 1442695040888963407ULL;
    return rng;
}

static size_t b64_encode(const unsigned char *in, size_t n, char *out)
{
    size_t o = 0;
    for (size_t i = 0; i + 2 < n || i < n; i += 3) {
        unsigned v = 0;
        int left = (int)(n - i) > 3 ? 3 : (int)(n - i);
        v = in[i] << 16;
        if (left > 1)
            v |= in[i + 1] << 8;
        if (left > 2)
            v |= in[i + 2];
        out[o++] = b64tab[(v >> 18) & 63];
        out[o++] = b64tab[(v >> 12) & 63];
        out[o++] = left > 1 ? b64tab[(v >> 6) & 63] : '=';
        out[o++] = left > 2 ? b64tab[v & 63] : '=';
        if (left <= 0)
            break;
    }
    return o;
}

static size_t b64_decode(const char *in, size_t n, unsigned char *out)
{
    size_t o = 0;
    for (size_t i = 0; i + 3 < n || i < n; i += 4) {
        int a = b64rev[(unsigned char)in[i]];
        int b = i + 1 < n ? b64rev[(unsigned char)in[i + 1]] : 0;
        int c = i + 2 < n ? b64rev[(unsigned char)in[i + 2]] : 0;
        int d = i + 3 < n ? b64rev[(unsigned char)in[i + 3]] : 0;
        out[o++] = (unsigned char)((a << 2) | (b >> 4));
        if (i + 2 < n && in[i + 2] != '=')
            out[o++] = (unsigned char)((b << 4) | (c >> 2));
        if (i + 3 < n && in[i + 3] != '=')
            out[o++] = (unsigned char)((c << 6) | d);
        if (n - i < 4)
            break;
    }
    return o;
}

int main(void)
{
    enum { N = 2 * 1024 * 1024 };
    unsigned char *in = malloc(N);
    char *enc = malloc(N * 2);
    unsigned char *dec = malloc(N * 2);
    if (!in || !enc || !dec)
        return 2;
    for (int i = 0; i < 256; i++)
        b64rev[i] = -1;
    for (int i = 0; i < 64; i++)
        b64rev[(unsigned char)b64tab[i]] = i;
    for (int i = 0; i < N; i++)
        in[i] = (unsigned char)(next_rand() & 0xff);
    printf("READY\n");
    fflush(stdout);

    size_t el = b64_encode(in, N, enc);
    size_t dl = b64_decode(enc, el, dec);
    if (dl != (size_t)N || memcmp(in, dec, N) != 0) {
        printf("MISMATCH\n");
        return 3;
    }
    uint64_t sum = 0;
    for (int i = 0; i < N; i++)
        sum = sum * 131 + in[i];
    printf("DONE sum=%llu\n", (unsigned long long)sum);
    free(in);
    free(enc);
    free(dec);
    return 0;
}
