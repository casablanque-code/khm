#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "commands/list.h"
#include "commands/verify.h"
#include "commands/diff.h"
#include "commands/scan.h"

static void usage(void) {
    fprintf(stderr,
        "Usage: khm <command> [options]\n"
        "\n"
        "Commands:\n"
        "  list   [--file <path>] [--no-color]   Show known_hosts entries\n"
        "  verify <host[:port]>   [--file <path>] Verify host key against known_hosts\n"
        "  scan   <cidr|file>     [--file <path>] Scan hosts and check keys\n"
        "  diff   <file1> <file2>                 Diff two known_hosts files\n"
        "\n"
        "  -h, --help    Show this help\n"
    );
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(); return 1; }

    const char *cmd = argv[1];

    if (strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0) {
        usage(); return 0;
    }

    /* ---- list ---- */
    if (strcmp(cmd, "list") == 0) {
        const char *file = NULL;
        int no_color = 0;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--file") == 0 && i + 1 < argc)
                file = argv[++i];
            else if (strcmp(argv[i], "--no-color") == 0)
                no_color = 1;
            else {
                fprintf(stderr, "khm list: unknown option '%s'\n", argv[i]);
                return 1;
            }
        }
        return cmd_list(file, no_color);
    }

    /* ---- verify ---- */
    if (strcmp(cmd, "verify") == 0) {
        const char *file     = NULL;
        const char *host_arg = NULL;
        int no_color = 0;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--file") == 0 && i + 1 < argc)
                file = argv[++i];
            else if (strcmp(argv[i], "--no-color") == 0)
                no_color = 1;
            else if (!host_arg)
                host_arg = argv[i];
            else {
                fprintf(stderr, "khm verify: unexpected argument '%s'\n", argv[i]);
                return 1;
            }
        }
        if (!host_arg) {
            fprintf(stderr, "khm verify: missing host argument\n");
            fprintf(stderr, "usage: khm verify <host[:port]> [--file <path>]\n");
            return 1;
        }
        return cmd_verify(host_arg, file, no_color);
    }

    /* ---- diff ---- */
    if (strcmp(cmd, "diff") == 0) {
        const char *file_a = NULL, *file_b = NULL;
        int no_color = 0;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--no-color") == 0) no_color = 1;
            else if (!file_a) file_a = argv[i];
            else if (!file_b) file_b = argv[i];
            else { fprintf(stderr, "khm diff: unexpected argument '%s'\n", argv[i]); return 1; }
        }
        if (!file_a || !file_b) {
            fprintf(stderr, "usage: khm diff <file1> <file2>\n");
            return 1;
        }
        return cmd_diff(file_a, file_b, no_color);
    }

    /* ---- scan ---- */
    if (strcmp(cmd, "scan") == 0) {
        const char *target   = NULL;
        const char *file     = NULL;
        int port       = 22;
        int timeout_ms = 3000;
        int no_color   = 0;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--file") == 0 && i+1 < argc)
                file = argv[++i];
            else if (strcmp(argv[i], "--port") == 0 && i+1 < argc)
                port = atoi(argv[++i]);
            else if (strcmp(argv[i], "--timeout") == 0 && i+1 < argc)
                timeout_ms = atoi(argv[++i]) * 1000;
            else if (strcmp(argv[i], "--no-color") == 0)
                no_color = 1;
            else if (!target)
                target = argv[i];
            else { fprintf(stderr, "khm scan: unexpected argument '%s'\n", argv[i]); return 1; }
        }
        if (!target) {
            fprintf(stderr, "usage: khm scan <cidr|file|host> [--file <known_hosts>] [--port N] [--timeout N]\n");
            return 1;
        }
        return cmd_scan(target, file, port, timeout_ms, no_color);
    }

    fprintf(stderr, "khm: unknown command '%s'\n", cmd);
    usage();
    return 1;
}
