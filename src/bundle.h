#ifndef ELFTRACE_BUNDLE_H
#define ELFTRACE_BUNDLE_H

#include <stddef.h>

int bundle_create(const char *dir, const char *out);
int bundle_extract(const char *bundle, const char *dest_dir);
int bundle_is_bundle(const char *path);

#endif
