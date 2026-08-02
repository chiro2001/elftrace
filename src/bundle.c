/*
 * trace bundle (归档) 格式: 将检查点目录 (ckpt_*.elftrace + manifest.txt)
 * 打包为单个文件, 便于存档/传输。build --checkpoints 可直接读取。
 *
 * 格式 (小端, 自定义, 无压缩):
 *   magic   "ELFTBNDL" (8 字节)
 *   version u32 = 1
 *   nfiles  u64
 *   文件记录 x nfiles:
 *     name_len u64
 *     size     u64
 *     name     (name_len 字节)
 *     data     (size 字节)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "util.h"
#include "bundle.h"

#define BUNDLE_MAGIC "ELFTBNDL"
#define BUNDLE_VERSION 1

/* 将 <dir> 下的检查点文件打包到 <out> */
int bundle_create(const char *dir, const char *out)
{
    DIR *d = opendir(dir);
    if (!d)
        die("bundle: cannot open %s", dir);

    /* 收集文件 (ckpt_*.elftrace, manifest.txt; 跳过 .synth_* 与隐藏) */
    char **names = NULL;
    size_t n = 0;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (de->d_name[0] == '.')
            continue;
        if (strstr(de->d_name, ".synth_"))
            continue;
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
        struct stat st;
        if (stat(path, &st) == 0 && S_ISREG(st.st_mode))
            names = xrealloc(names, (n + 1) * sizeof(char *));
        else
            continue;
        names[n++] = xstrdup(de->d_name);
    }
    closedir(d);
    if (!n)
        die("bundle: no checkpoint files in %s", dir);

    /* 写 bundle */
    int fd = open(out, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        die("bundle: cannot create %s", out);

    uint8_t hdr[20];
    memcpy(hdr, BUNDLE_MAGIC, 8);
    uint32_t ver = BUNDLE_VERSION;
    memcpy(hdr + 8, &ver, 4);
    uint64_t nf = n;
    memcpy(hdr + 12, &nf, 8);
    if (write(fd, hdr, 20) != 20)
        die("bundle: short write");

    for (size_t i = 0; i < n; i++) {
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", dir, names[i]);
        int infd = open(path, O_RDONLY);
        if (infd < 0)
            die("bundle: cannot open %s", path);
        struct stat st;
        fstat(infd, &st);
        uint64_t nlen = strlen(names[i]);
        uint64_t sz = st.st_size;
        uint8_t rec[16];
        memcpy(rec, &nlen, 8);
        memcpy(rec + 8, &sz, 8);
        if (write(fd, rec, 16) != 16 ||
            write(fd, names[i], nlen) != (ssize_t)nlen)
            die("bundle: short write");
        char buf[65536];
        ssize_t r;
        while ((r = read(infd, buf, sizeof(buf))) > 0)
            if (write(fd, buf, r) != r)
                die("bundle: short write");
        close(infd);
        free(names[i]);
    }
    free(names);
    close(fd);
    fprintf(stderr, "bundle: %zu files from %s -> %s\n", n, dir, out);
    return 0;
}

/* 解包 <bundle> 到 <dest_dir> (目录需存在) */
int bundle_extract(const char *bundle, const char *dest_dir)
{
    int fd = open(bundle, O_RDONLY);
    if (fd < 0)
        die("bundle: cannot open %s", bundle);
    struct stat st;
    fstat(fd, &st);
    uint8_t *f = xmalloc(st.st_size);
    if (read(fd, f, st.st_size) != st.st_size)
        die("bundle: short read");
    close(fd);

    if (st.st_size < 16 || memcmp(f, BUNDLE_MAGIC, 8) != 0)
        die("%s: not a trace bundle", bundle);
    uint64_t nf;
    memcpy(&nf, f + 12, 8);
    size_t off = 20;

    for (uint64_t i = 0; i < nf; i++) {
        if (off + 16 > st.st_size)
            die("bundle: corrupt (record %llu)", (unsigned long long)i);
        uint64_t nlen, sz;
        memcpy(&nlen, f + off, 8);
        memcpy(&sz, f + off + 8, 8);
        off += 16;
        if (off + nlen > st.st_size)
            die("bundle: corrupt name");
        char *name = xmalloc(nlen + 1);
        memcpy(name, f + off, nlen);
        name[nlen] = 0;
        off += nlen;
        if (off + sz > st.st_size)
            die("bundle: corrupt data (%s)", name);
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", dest_dir, name);
        int outfd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (outfd < 0)
            die("bundle: cannot create %s", path);
        if (write(outfd, f + off, sz) != (ssize_t)sz)
            die("bundle: short write");
        close(outfd);
        off += sz;
        free(name);
    }
    free(f);
    fprintf(stderr, "bundle: %llu files -> %s\n",
            (unsigned long long)nf, dest_dir);
    return 0;
}

/* 判断文件是否为 bundle 格式 (读前 8 字节) */
int bundle_is_bundle(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return 0;
    char mg[8];
    ssize_t r = read(fd, mg, 8);
    close(fd);
    return (r == 8 && memcmp(mg, BUNDLE_MAGIC, 8) == 0);
}
