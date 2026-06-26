#include "diff.h"
#include "../parser.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>

#define COL_RESET   "\033[0m"
#define COL_BOLD    "\033[1m"
#define COL_GREEN   "\033[32m"
#define COL_RED     "\033[31m"
#define COL_YELLOW  "\033[33m"
#define COL_CYAN    "\033[36m"
#define COL_DIM     "\033[2m"

#define C(code) (no_color ? "" : code)

/* Build a display name for an entry: "host[:port]" or "<hashed>" */
static void entry_display(const khm_entry_t *e, char *buf, size_t len) {
    if (e->hashed) {
        snprintf(buf, len, "<hashed>");
        return;
    }
    buf[0] = '\0';
    for (int i = 0; i < e->hostname_count; i++) {
        if (i > 0) strncat(buf, ",", len - strlen(buf) - 1);
        strncat(buf, e->hostnames[i], len - strlen(buf) - 1);
    }
    if (e->port) {
        char tmp[16];
        snprintf(tmp, sizeof(tmp), ":%d", e->port);
        strncat(buf, tmp, len - strlen(buf) - 1);
    }
}

/* Return 1 if two entries describe the same host+port */
static int same_host(const khm_entry_t *a, const khm_entry_t *b) {
    if (a->hashed || b->hashed) return 0;

    int port_a = a->port ? a->port : 22;
    int port_b = b->port ? b->port : 22;
    if (port_a != port_b) return 0;

    for (int i = 0; i < a->hostname_count; i++)
        for (int j = 0; j < b->hostname_count; j++)
            if (strcasecmp(a->hostnames[i], b->hostnames[j]) == 0)
                return 1;
    return 0;
}

int cmd_diff(const char *file_a, const char *file_b, int no_color) {
    khm_db_t db_a = {0}, db_b = {0};

    if (khm_parse_file(file_a, &db_a) < 0) {
        fprintf(stderr, "khm diff: cannot open '%s'\n", file_a);
        return 1;
    }
    if (khm_parse_file(file_b, &db_b) < 0) {
        fprintf(stderr, "khm diff: cannot open '%s'\n", file_b);
        khm_db_free(&db_a);
        return 1;
    }

    printf("%s--- %s%s\n", C(COL_DIM), file_a, C(COL_RESET));
    printf("%s+++ %s%s\n", C(COL_DIM), file_b, C(COL_RESET));
    printf("\n");

    int changed = 0;
    char name[512];

    /* Pass 1: entries in A — check if missing or changed in B */
    for (size_t i = 0; i < db_a.count; i++) {
        khm_entry_t *ea = &db_a.entries[i];
        entry_display(ea, name, sizeof(name));

        int found = 0;
        for (size_t j = 0; j < db_b.count; j++) {
            khm_entry_t *eb = &db_b.entries[j];
            if (!same_host(ea, eb)) continue;
            if (strcmp(ea->keytype_str, eb->keytype_str) != 0) continue;
            found = 1;

            if (strcmp(ea->keydata_b64, eb->keydata_b64) != 0) {
                /* key changed */
                printf("%s~ CHANGED  %s%-40s  %s%s\n",
                       C(COL_YELLOW), C(COL_RESET),
                       name, ea->keytype_str, C(COL_RESET));
                printf("  %s- ...%s%s\n", C(COL_RED),
                       ea->keydata_b64 + (strlen(ea->keydata_b64) > 16
                                          ? strlen(ea->keydata_b64) - 16 : 0),
                       C(COL_RESET));
                printf("  %s+ ...%s%s\n", C(COL_GREEN),
                       eb->keydata_b64 + (strlen(eb->keydata_b64) > 16
                                          ? strlen(eb->keydata_b64) - 16 : 0),
                       C(COL_RESET));
                changed++;
            }
            break;
        }

        if (!found) {
            printf("%s- REMOVED  %s%-40s  %s\n",
                   C(COL_RED), C(COL_RESET), name, ea->keytype_str);
            changed++;
        }
    }

    /* Pass 2: entries in B not in A → added */
    for (size_t j = 0; j < db_b.count; j++) {
        khm_entry_t *eb = &db_b.entries[j];
        entry_display(eb, name, sizeof(name));

        int found = 0;
        for (size_t i = 0; i < db_a.count; i++) {
            khm_entry_t *ea = &db_a.entries[i];
            if (same_host(eb, ea) &&
                strcmp(eb->keytype_str, ea->keytype_str) == 0) {
                found = 1;
                break;
            }
        }

        if (!found) {
            printf("%s+ ADDED    %s%-40s  %s\n",
                   C(COL_GREEN), C(COL_RESET), name, eb->keytype_str);
            changed++;
        }
    }

    if (!changed) {
        printf("%s✔ identical  (%zu entries each)%s\n",
               C(COL_GREEN), db_a.count, C(COL_RESET));
    } else {
        printf("\n%s%d difference(s)%s\n",
               C(COL_BOLD), changed, C(COL_RESET));
    }

    khm_db_free(&db_a);
    khm_db_free(&db_b);
    return changed ? 1 : 0;
}
