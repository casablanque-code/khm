#include "verify.h"
#include "../parser.h"
#include "../hostkey.h"
#include "../json.h"

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
/* Shared check used by both --json single-host and verify --all.      */
/*                                                                      */
/* Picks the first known_hosts record whose algorithm matches what the */
/* server offered live. If none matches type-wise, status is NEW. This */
/* is a simpler rule than the human-readable path below (which narrates*/
/* every candidate record and lets the last matching-type one win) —   */
/* fine here since JSON output wants one canonical verdict, not a      */
/* transcript. Records of a different type than what was fetched are   */
/* not visited at all (no live check was made for that type).          */
/* ------------------------------------------------------------------ */

static khm_status_t verify_host_against_db(const char *host, int port,
                                            const khm_db_t *db,
                                            khm_hostkey_t *live,
                                            long *record_index,
                                            char *known_fp, size_t known_fp_len) {
    *record_index = -1;
    known_fp[0] = '\0';

    int r = khm_fetch_hostkey(host, port, VERIFY_TIMEOUT_MS, live);
    if (r < 0) return KHM_STATUS_UNREACHABLE;

    for (size_t i = 0; i < db->count; i++) {
        const khm_entry_t *e = &db->entries[i];
        if (!entry_matches(e, host, port)) continue;
        if (strcmp(e->keytype_str, live->keytype_str) != 0) continue;

        *record_index = (long)(i + 1);
        khm_fingerprint_from_b64(e->keydata_b64, known_fp, known_fp_len);

        return (strcmp(e->keydata_b64, live->keydata_b64) == 0)
                   ? KHM_STATUS_OK : KHM_STATUS_CHANGED;
    }

    return KHM_STATUS_NEW;
}

/* ------------------------------------------------------------------ */
/* Single-host verify                                                   */
/* ------------------------------------------------------------------ */

int cmd_verify(const char *host_arg, const char *file, int no_color, int json_output) {
    char host[256];
    int  port;
    parse_host_arg(host_arg, host, sizeof(host), &port);

    /* resolve known_hosts path */
    char default_path[512];
    if (!file) {
        khm_default_path(default_path, sizeof(default_path));
        file = default_path;
    }

    khm_db_t db = {0};
    if (khm_parse_file(file, &db) < 0) {
        fprintf(stderr, "khm: cannot open '%s'\n", file);
        return 1;
    }

    if (json_output) {
        khm_hostkey_t live = {0};
        long record_index;
        char known_fp[128] = {0};
        khm_status_t status = verify_host_against_db(host, port, &db, &live,
                                                       &record_index, known_fp, sizeof(known_fp));

        khm_result_t result = {
            .host         = host,
            .port         = port,
            .status       = status,
            .algorithm    = (status != KHM_STATUS_UNREACHABLE) ? live.keytype_str : NULL,
            .fetched_fp   = (status != KHM_STATUS_UNREACHABLE) ? live.fingerprint : NULL,
            .known_fp     = known_fp[0] ? known_fp : NULL,
            .record_index = record_index,
        };
        khm_json_write_result(stdout, &result);
        fputc('\n', stdout);

        khm_db_free(&db);
        switch (status) {
            case KHM_STATUS_OK:      return 0;
            case KHM_STATUS_CHANGED: return 1;
            case KHM_STATUS_NEW:     return 3;
            default:                 return 2; /* unreachable */
        }
    }

    /* ---- human-readable path (unchanged from before --json/--all) ---- */

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
        khm_db_free(&db);
        return 2;
    }
    if (r < 0) {
        printf("  fetch: %sERROR%s (connection refused or protocol failure)\n",
               C(COL_RED), C(COL_RESET));
        khm_db_free(&db);
        return 2;
    }

    printf("  fetch: %s%s%s  %s%s%s\n",
           C(COL_CYAN), live.keytype_str, C(COL_RESET),
           C(COL_DIM),  live.fingerprint, C(COL_RESET));

    /* find matching entries (db already parsed above) */
    int found = 0;
    int status = 0; /* 0=ok, 1=changed, 3=not_found */

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

/* ------------------------------------------------------------------ */
/* verify --all                                                         */
/* ------------------------------------------------------------------ */

typedef struct {
    char host[KHM_MAX_HOSTNAME];
    int  port;
} khm_target_t;

/* Dedup on (host, port); a host commonly appears in more than one
 * record (one per algorithm) and comma-joined hostname lists expand
 * to multiple hostname_count entries pointing at the same record. */
static int add_target(khm_target_t **targets, size_t *count, size_t *cap,
                       const char *host, int port) {
    for (size_t i = 0; i < *count; i++) {
        if (strcasecmp((*targets)[i].host, host) == 0 && (*targets)[i].port == port)
            return 0;
    }
    if (*count == *cap) {
        size_t new_cap = *cap ? *cap * 2 : 16;
        khm_target_t *tmp = realloc(*targets, new_cap * sizeof(khm_target_t));
        if (!tmp) return -1;
        *targets = tmp;
        *cap = new_cap;
    }
    strncpy((*targets)[*count].host, host, KHM_MAX_HOSTNAME - 1);
    (*targets)[*count].host[KHM_MAX_HOSTNAME - 1] = '\0';
    (*targets)[*count].port = port;
    (*count)++;
    return 0;
}

int cmd_verify_all(const char *file, int no_color, int json_output) {
    char default_path[512];
    if (!file) {
        khm_default_path(default_path, sizeof(default_path));
        file = default_path;
    }

    khm_db_t db = {0};
    if (khm_parse_file(file, &db) < 0) {
        fprintf(stderr, "khm: cannot open '%s'\n", file);
        return 1;
    }

    khm_target_t *targets = NULL;
    size_t t_count = 0, t_cap = 0;

    for (size_t i = 0; i < db.count; i++) {
        const khm_entry_t *e = &db.entries[i];
        if (e->hashed) continue; /* hostname unrecoverable — can't connect to it */

        int port = e->port ? e->port : 22;
        for (int j = 0; j < e->hostname_count; j++) {
            if (add_target(&targets, &t_count, &t_cap, e->hostnames[j], port) < 0) {
                fprintf(stderr, "khm verify --all: out of memory\n");
                free(targets);
                khm_db_free(&db);
                return 1;
            }
        }
    }

#define C(code) (no_color ? "" : code)

    int n_ok = 0, n_changed = 0, n_new = 0, n_unreachable = 0;
    int first = 1;
    if (json_output) khm_json_array_begin(stdout);

    for (size_t i = 0; i < t_count; i++) {
        khm_hostkey_t live = {0};
        long record_index;
        char known_fp[128] = {0};
        khm_status_t status = verify_host_against_db(targets[i].host, targets[i].port, &db,
                                                       &live, &record_index, known_fp, sizeof(known_fp));

        switch (status) {
            case KHM_STATUS_OK:          n_ok++;          break;
            case KHM_STATUS_CHANGED:     n_changed++;     break;
            case KHM_STATUS_NEW:         n_new++;         break;
            case KHM_STATUS_UNREACHABLE: n_unreachable++; break;
            default: break;
        }

        if (json_output) {
            khm_result_t result = {
                .host         = targets[i].host,
                .port         = targets[i].port,
                .status       = status,
                .algorithm    = (status != KHM_STATUS_UNREACHABLE) ? live.keytype_str : NULL,
                .fetched_fp   = (status != KHM_STATUS_UNREACHABLE) ? live.fingerprint : NULL,
                .known_fp     = known_fp[0] ? known_fp : NULL,
                .record_index = record_index,
            };
            khm_json_array_next(stdout, &first);
            khm_json_write_result(stdout, &result);
        } else {
            const char *label, *color;
            switch (status) {
                case KHM_STATUS_OK:          label = "OK";          color = COL_GREEN;  break;
                case KHM_STATUS_CHANGED:     label = "CHANGED";     color = COL_RED;    break;
                case KHM_STATUS_NEW:         label = "NEW";         color = COL_YELLOW; break;
                case KHM_STATUS_UNREACHABLE: label = "UNREACHABLE"; color = COL_DIM;    break;
                default:                     label = "?";           color = COL_DIM;    break;
            }
            printf("  %s%-11s%s  %s", C(color), label, C(COL_RESET), targets[i].host);
            if (targets[i].port != 22) printf(":%d", targets[i].port);
            printf("\n");
        }
    }

    if (json_output) {
        khm_json_array_end(stdout);
    } else {
        printf("\n%s%zu hosts%s  ", C(COL_BOLD), t_count, C(COL_RESET));
        printf("%s%d OK%s", C(COL_GREEN), n_ok, C(COL_RESET));
        if (n_changed)     printf("  %s%d changed%s",     C(COL_RED),    n_changed,     C(COL_RESET));
        if (n_new)         printf("  %s%d new%s",         C(COL_YELLOW), n_new,         C(COL_RESET));
        if (n_unreachable) printf("  %s%d unreachable%s", C(COL_DIM),    n_unreachable, C(COL_RESET));
        printf("\n");
    }

    free(targets);
    khm_db_free(&db);

    return (n_changed > 0 || n_unreachable > 0) ? 1 : 0;
}
