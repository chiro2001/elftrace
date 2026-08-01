#ifndef ELFTRACE_UTIL_H
#define ELFTRACE_UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#define die(fmt, ...) elftrace_die(__FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define warn(fmt, ...) elftrace_warn(fmt, ##__VA_ARGS__)

void elftrace_die(const char *file, int line, const char *fmt, ...);
void elftrace_warn(const char *fmt, ...);

void *xmalloc(size_t size);
void *xcalloc(size_t n, size_t size);
void *xrealloc(void *ptr, size_t size);
char *xstrdup(const char *s);

#endif /* ELFTRACE_UTIL_H */
