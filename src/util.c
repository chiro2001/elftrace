#include "util.h"
#include <stdarg.h>
#include <unistd.h>

void elftrace_die(const char *file, int line, const char *fmt, ...)
{
    va_list ap;

    fprintf(stderr, "elftrace: %s:%d: ", file, line);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, ": %s\n", strerror(errno));
    exit(1);
}

void elftrace_warn(const char *fmt, ...)
{
    va_list ap;

    fprintf(stderr, "elftrace: warning: ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}

void *xmalloc(size_t size)
{
    void *p = malloc(size);
    if (!p)
        die("out of memory (%zu bytes)", size);
    return p;
}

void *xcalloc(size_t n, size_t size)
{
    void *p = calloc(n, size);
    if (!p)
        die("out of memory (%zu x %zu bytes)", n, size);
    return p;
}

void *xrealloc(void *ptr, size_t size)
{
    void *p = realloc(ptr, size);
    if (!p)
        die("out of memory (%zu bytes)", size);
    return p;
}

char *xstrdup(const char *s)
{
    char *p = strdup(s);
    if (!p)
        die("out of memory");
    return p;
}
