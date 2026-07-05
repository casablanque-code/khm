#include "fingerprint.h"
#include "../hostkey.h"
#include "../json.h"

#include <stdio.h>

#define COL_RESET  "\033[0m"
#define COL_CYAN   "\033[36m"
#define COL_DIM    "\033[2m"
#define COL_YELLOW "\033[33m"
#define COL_RED    "\033[31m"

#define FINGERPRINT_TIMEOUT_MS 5000

int cmd_fingerprint(const char *host_arg, int no_color, int json_output) {
    char host[256];
    int  port;
    khm_parse_host_port(host_arg, host, sizeof(host), &port);

    khm_hostkey_t live;
    int r = khm_fetch_hostkey(host, port, FINGERPRINT_TIMEOUT_MS, &live);

    if (json_output) {
        /* Reuses khm_result_t: status NONE means "fetched, no
         * known_hosts comparison was attempted" (this command never
         * reads known_hosts at all). known_fp/record_index stay unset
         * since there's nothing on file to compare against. */
        khm_result_t result = {
            .host         = host,
            .port         = port,
            .status       = (r < 0) ? KHM_STATUS_UNREACHABLE : KHM_STATUS_NONE,
            .algorithm    = (r < 0) ? NULL : live.keytype_str,
            .fetched_fp   = (r < 0) ? NULL : live.fingerprint,
            .known_fp     = NULL,
            .record_index = -1,
        };
        khm_json_write_result(stdout, &result);
        fputc('\n', stdout);
        return (r < 0) ? 2 : 0;
    }

#define C(code) (no_color ? "" : code)

    printf("  host:  %s%s%s", C(COL_CYAN), host, C(COL_RESET));
    if (port != 22) printf(":%s%d%s", C(COL_CYAN), port, C(COL_RESET));
    printf("\n");

    if (r == -2) {
        printf("  fetch: %sTIMEOUT%s (no response in %ds)\n",
               C(COL_YELLOW), C(COL_RESET), FINGERPRINT_TIMEOUT_MS / 1000);
        return 2;
    }
    if (r < 0) {
        printf("  fetch: %sERROR%s (connection refused or protocol failure)\n",
               C(COL_RED), C(COL_RESET));
        return 2;
    }

    printf("  type:  %s%s%s\n", C(COL_CYAN), live.keytype_str, C(COL_RESET));
    printf("  fp:    %s%s%s\n", C(COL_DIM), live.fingerprint, C(COL_RESET));

    return 0;
}
