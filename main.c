#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "commands/list.h"
#include "commands/verify.h"
#include "commands/diff.h"
#include "commands/scan.h"
#include "commands/fingerprint.h"

static void usage(void) {
    fprintf(stderr,
        "Usage: khm [--json] <command> [options]\n"
        "\n"
        "Commands:\n"
        "  list   [--file <path>] [--no-color]   Show known_hosts entries\n"
        "  verify <host[:port]>   [--file <path>] Verify host key against known_hosts\n"
        "  verify --all           [--file <path>] Verify every host in known_hosts\n"
        "  fingerprint <host[:port]>              Show a host's live key fingerprint\n"
        "  scan   <cidr|file>     [--file <path>] Scan hosts and check keys\n"
        "  diff   <file1> <file2>                 Diff two known_hosts files\n"
        "\n"
        "  --json        Emit machine-readable JSON instead of formatted text\n"
        "                (accepted anywhere on the command line)\n"
        "  -h, --help    Show this help\n"
    );
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(); return 1; }

    /* ---- global --json pre-scan ----
     * Recognised anywhere on the command line, not just before the
     * subcommand name, so `khm verify host --json` works the same as
     * `khm --json verify host`. Stripped out here so per-command option
     * loops never have to know about it. */
    int json_output = 0;
    char *filtered[argc + 1];
    int fargc = 0;
    for (int i = 0; i < argc; i++) {
        if (i > 0 && strcmp(argv[i], "--json") == 0) {
            json_output = 1;
            continue;
        }
        filtered[fargc++] = argv[i];
    }
    filtered[fargc] = NULL;
    argv = filtered;
    argc = fargc;

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
        return cmd_list(file, no_color, json_output);
    }

    /* ---- verify ---- */
    if (strcmp(cmd, "verify") == 0) {
        const char *file     = NULL;
        const char *host_arg = NULL;
        int no_color = 0;
        int all      = 0;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--file") == 0 && i + 1 < argc)
                file = argv[++i];
            else if (strcmp(argv[i], "--no-color") == 0)
                no_color = 1;
            else if (strcmp(argv[i], "--all") == 0)
                all = 1;
            else if (!host_arg)
                host_arg = argv[i];
            else {
                fprintf(stderr, "khm verify: unexpected argument '%s'\n", argv[i]);
                return 1;
            }
        }
        if (all) {
            if (host_arg) {
                fprintf(stderr, "khm verify: --all does not take a host argument ('%s')\n", host_arg);
                return 1;
            }
            return cmd_verify_all(file, no_color, json_output);
        }
        if (!host_arg) {
            fprintf(stderr, "khm verify: missing host argument\n");
            fprintf(stderr, "usage: khm verify <host[:port]> [--file <path>]\n");
            fprintf(stderr, "       khm verify --all [--file <path>]\n");
            return 1;
        }
        return cmd_verify(host_arg, file, no_color, json_output);
    }

    /* ---- fingerprint ---- */
    if (strcmp(cmd, "fingerprint") == 0) {
        const char *host_arg = NULL;
        int no_color = 0;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--no-color") == 0)
                no_color = 1;
            else if (!host_arg)
                host_arg = argv[i];
            else {
                fprintf(stderr, "khm fingerprint: unexpected argument '%s'\n", argv[i]);
                return 1;
            }
        }
        if (!host_arg) {
            fprintf(stderr, "usage: khm fingerprint <host[:port]>\n");
            return 1;
        }
        return cmd_fingerprint(host_arg, no_color, json_output);
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
