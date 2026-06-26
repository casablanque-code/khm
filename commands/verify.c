#include "verify.h"
#include "../parser.h"
#include "../hostkey.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define COL_RESET   "\033[0m"
#define COL_BOLD    "\033[1m"
#define COL_GREEN   "\033[32m"
#define COL_RED     "\033[31m"
#define COL_YELLOW  "\033[33m"
#define COL_CYAN    "\033[36m"
#define COL_DIM     "\033[2m"

#define VERIFY_TIMEOUT_MS 5000

/* ------------------------------------------------------------------ */
/* Parse "host" or "host:port" or "[host]:port"                        */
/* ------------------------------------------------------------------ */

static void parse_host_arg(const char *arg, char *host, size_t hlen, int *port) {
    *port = 22;

    /* [host]:port */
    if (arg[0] == '[') {
        const char *close = strchr(arg, ']');
        if (close) {
            size_t n = (size_t)(close - arg - 1);
            if (n >= hlen) n = hlen - 1;
            memcpy(host, arg + 1, n);
            host[n] = '\0';
            if (*(close + 1) == ':') *port = atoi(close + 2);
            return;
        }
    }

    /* host:port — but only if there's exactly one colon
       (IPv6 addresses have multiple colons, skip them) */
    const char *colon = strchr(arg, ':');
    if (colon && strchr(colon + 1, ':') == NULL) {
        size_t n = (size_t)(colon - arg);
        if (n >= hlen) n = hlen - 1;
        memcpy(host, arg, n);
        host[n] = '\0';
        *port = atoi(colon + 1);
        return;
    }

    strncpy(host, arg, hlen - 1);
    host[hlen - 1] = '\0';
}

/* ------------------------------------------------------------------ */
/* Match a db entry against host+port                                  */
/* ------------------------------------------------------------------ */

static int entry_matches(const khm_entry_t *e, const char *host, int port) {
    if (e->hashed) return 0; /* skip hashed entries for now */

    int entry_port = (e->port == 0) ? 22 : e->port;
    if (entry_port != port) return 0;

    for (int i = 0; i < e->hostname_count; i++) {
        if (strcasecmp(e->hostnames[i], host) == 0) return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Main verify logic                                                    */
/* ------------------------------------------------------------------ */

int cmd_verify(const char *host_arg, const char *file, int no_color) {
    char host[256];
    int  port;
    parse_host_arg(host_arg, host, sizeof(host), &port);

    /* resolve known_hosts path */
    char default_path[512];
    if (!file) {
        khm_default_path(default_path, sizeof(default_path));
        file = default_path;
    }

#define C(code) (no_color ? "" : code)

    printf("  host:  %s%s%s", C(COL_CYAN), host, C(COL_RESET));
    if (port != 22) printf(":%s%d%s", C(COL_CYAN), port, C(COL_RESET));
    printf("\n");
    printf("  file:  %s%s%s\n", C(COL_DIM), file, C(COL_RESET));

    /* fetch live key */
    printf("  fetch: connecting...\r");
    fflush(stdout);

    khm_hostkey_t live;
    int r = khm_fetch_hostkey(host, port, VERIFY_TIMEOUT_MS, &live);
    if (r == -2) {
        printf("  fetch: %sTIMEOUT%s (no response in %ds)\n",
               C(COL_YELLOW), C(COL_RESET), VERIFY_TIMEOUT_MS / 1000);
        return 2;
    }
    if (r < 0) {
        printf("  fetch: %sERROR%s (connection refused or protocol failure)\n",
               C(COL_RED), C(COL_RESET));
        return 2;
    }

    printf("  fetch: %s%s%s  %s%s%s\n",
           C(COL_CYAN), live.keytype_str, C(COL_RESET),
           C(COL_DIM),  live.fingerprint, C(COL_RESET));

    /* parse known_hosts */
    khm_db_t db = {0};
    if (khm_parse_file(file, &db) < 0) {
        fprintf(stderr, "khm: cannot open '%s'\n", file);
        return 1;
    }

    /* find matching entries */
    int found = 0;
    int status = 0; /* 0=ok, 1=changed, 2=not_found */

    for (size_t i = 0; i < db.count; i++) {
        khm_entry_t *e = &db.entries[i];
        if (!entry_matches(e, host, port)) continue;

        found++;

        /* compare key type + base64 blob */
        int type_match = (strcmp(e->keytype_str, live.keytype_str) == 0);
        int key_match  = (strcmp(e->keydata_b64, live.keydata_b64)  == 0);

        if (type_match && key_match) {
            printf("  match: %s✔ OK%s  (record #%zu)\n",
                   C(COL_GREEN), C(COL_RESET), i + 1);
            status = 0;
        } else if (type_match && !key_match) {
            printf("  match: %s✘ KEY CHANGED%s  (record #%zu, same type)\n",
                   C(COL_RED), C(COL_RESET), i + 1);
            printf("  stored fp: %s%s%s\n",
                   C(COL_DIM), e->keydata_b64 + (strlen(e->keydata_b64) > 16
                                ? strlen(e->keydata_b64) - 16 : 0),
                   C(COL_RESET));
            status = 1;
        } else {
            /* different key type — server may offer multiple, not alarming */
            printf("  note:  record #%zu has %s%s%s (different type, skipping)\n",
                   i + 1, C(COL_DIM), e->keytype_str, C(COL_RESET));
        }
    }

    if (!found) {
        printf("  match: %s? NOT FOUND%s  (host not in known_hosts)\n",
               C(COL_YELLOW), C(COL_RESET));
        printf("  hint:  ssh %s  # to add via TOFU\n", host);
        status = 3;
    }

    khm_db_free(&db);
    return status;
}
