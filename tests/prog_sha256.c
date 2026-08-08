/* 真实场景负载: 文件 SHA-256 哈希 (完整实现, 无外部依赖)。
 * 读取大文件, 更新哈希状态, 输出摘要; rc = 首字节 % 255。
 * 验证 strict baremetal 切片在窗口内回放 read/dirty 后哈希不变。 */
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const uint32_t sha256_k[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

static uint32_t rotr32(uint32_t x, int n)
{
    return (x >> n) | (x << (32 - n));
}

static void sha256_block(uint32_t h[8], const unsigned char *p)
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)p[i * 4] << 24) |
               ((uint32_t)p[i * 4 + 1] << 16) |
               ((uint32_t)p[i * 4 + 2] << 8) |
               (uint32_t)p[i * 4 + 3];
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^
                      (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^
                      (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = hh + s1 + ch + sha256_k[i] + w[i];
        uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + maj;
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return 2;
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0)
        return 2;
    printf("READY\n");
    fflush(stdout);

    static unsigned char buf[64 << 10];
    uint32_t h[8] = {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
    };
    uint64_t total = 0;
    unsigned char tail[128];
    size_t tail_len = 0;
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        total += (uint64_t)n;
        const unsigned char *p = buf;
        ssize_t left = n;
        if (tail_len) {
            size_t need = 64 - tail_len;
            if ((size_t)left < need)
                need = (size_t)left;
            memcpy(tail + tail_len, p, need);
            tail_len += need;
            p += need;
            left -= (ssize_t)need;
            if (tail_len == 64) {
                sha256_block(h, tail);
                tail_len = 0;
            }
        }
        while (left >= 64) {
            sha256_block(h, p);
            p += 64;
            left -= 64;
        }
        if (left > 0)
            memcpy(tail, p, (size_t)left);
        tail_len = (size_t)left;
    }
    close(fd);

    /* 填充 + 长度 (一个或两个 64B 块) */
    uint64_t bitlen = total * 8;
    unsigned char pad[128];
    memset(pad, 0, sizeof(pad));
    memcpy(pad, tail, tail_len);
    pad[tail_len] = 0x80;
    size_t plen = ((tail_len + 1 + 8 + 63) / 64) * 64;
    pad[plen - 8] = (unsigned char)(bitlen >> 56);
    pad[plen - 7] = (unsigned char)(bitlen >> 48);
    pad[plen - 6] = (unsigned char)(bitlen >> 40);
    pad[plen - 5] = (unsigned char)(bitlen >> 32);
    pad[plen - 4] = (unsigned char)(bitlen >> 24);
    pad[plen - 3] = (unsigned char)(bitlen >> 16);
    pad[plen - 2] = (unsigned char)(bitlen >> 8);
    pad[plen - 1] = (unsigned char)bitlen;
    sha256_block(h, pad);
    if (plen == 128)
        sha256_block(h, pad + 64);

    printf("SHA256 %08x%08x%08x%08x%08x%08x%08x%08x\n",
           h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
    return (int)(h[0] % 255);
}
