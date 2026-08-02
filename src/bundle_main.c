#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#include <errno.h>

#include "bundle.h"
#include "util.h"

int bundle_main(int argc, char **argv)
{
    const char *target = NULL;
    const char *out = NULL;
    int unpack = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            out = argv[++i];
        } else if (strcmp(argv[i], "--unpack") == 0) {
            unpack = 1;
        } else if (argv[i][0] != '-') {
            target = argv[i];
        } else {
            die("usage: elftrace bundle <dir|-o out.bundle> | "
                "<file.bundle> --unpack -o dir");
        }
    }
    if (!target)
        die("bundle: missing target");
    if (!out)
        die("bundle: missing -o");

    if (unpack) {
        mkdir(out, 0755);
        bundle_extract(target, out);
    } else {
        bundle_create(target, out);
    }
    return 0;
}
