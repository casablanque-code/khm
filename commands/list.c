#include "list.h"
#include "../parser.h"

#include <stdio.h>
#include <string.h>

/* ANSI colours */
#define COL_RESET   "\033[0m"
#define COL_BOLD    "\033[1m"
#define COL_DIM     "\033[2m"
#define COL_CYAN    "\033[36m"
#define COL_YELLOW  "\033[33m"
#define COL_GREEN   "\033[32m"
#define COL_MAGENTA "\033[35m"
#define COL_RED     "\033[31m"

static const char *keytype_label(khm_keytype_t t) {
    switch (t) {
        case KHM_KEY_RSA:       return "RSA      ";
        case KHM_KEY_ECDSA_256: return "ECDSA-256";
        case KHM_KEY_ECDSA_384: return "ECDSA-384";
        case KHM_KEY_ECDSA_521: return "ECDSA-521";
        case KHM_KEY_ED25519:   return "ED25519  ";
        default:                return "UNKNOWN  ";
    }
}

static const char *keytype_color(khm_keytype_t t) {
    switch (t) {
        case KHM_KEY_ED25519:   return COL_GREEN;
        case KHM_KEY_ECDSA_256:
        case KHM_KEY_ECDSA_384:
        case KHM_KEY_ECDSA_521: return COL_CYAN;
        case KHM_KEY_RSA:       return COL_YELLOW;
        default:                return COL_DIM;
    }
}

/* Print first N chars of base64 as a visual "fingerprint hint" */
static void print_keypreview(const char *b64) {
    /* show last 8 chars — more unique than first */
    size_t len = strlen(b64);
    if (len > 8)
        printf("%s...%.*s", COL_DIM, 8, b64 + len - 8);
    else
        printf("%s%s", COL_DIM, b64);
    printf(COL_RESET);
}

int cmd_list(const char *path, int no_color) {
    char default_path[512];
    if (!path) {
        khm_default_path(default_path, sizeof(default_path));
        path = default_path;
    }

    khm_db_t db = {0};
    if (khm_parse_file(path, &db) < 0) {
        fprintf(stderr, "khm: cannot open '%s'\n", path);
        return 1;
    }

    if (db.count == 0) {
        printf("No entries found in %s\n", path);
        khm_db_free(&db);
        return 0;
    }

    /* header */
    if (!no_color)
        printf(COL_BOLD);
    printf("%-40s  %-9s  %s\n", "HOST", "KEY TYPE", "KEY (tail)");
    printf("%-40s  %-9s  %s\n",
           "----------------------------------------",
           "---------",
           "--------");
    if (!no_color)
        printf(COL_RESET);

    for (size_t i = 0; i < db.count; i++) {
        khm_entry_t *e = &db.entries[i];

        /* build display name */
        char display[KHM_MAX_HOSTNAME + 16];
        if (e->hashed) {
            snprintf(display, sizeof(display), "<hashed>");
        } else {
            /* join hostnames */
            display[0] = '\0';
            for (int j = 0; j < e->hostname_count; j++) {
                if (j > 0) strncat(display, ", ", sizeof(display) - strlen(display) - 1);
                strncat(display, e->hostnames[j], sizeof(display) - strlen(display) - 1);
            }
            if (e->port)  {
                char portbuf[16];
                snprintf(portbuf, sizeof(portbuf), ":%d", e->port);
                strncat(display, portbuf, sizeof(display) - strlen(display) - 1);
            }
        }

        /* truncate display for alignment */
        char truncated[41];
        snprintf(truncated, sizeof(truncated), "%s", display);

        if (!no_color) {
            printf("%s%-40s%s  ", e->hashed ? COL_DIM : COL_CYAN,
                   truncated, COL_RESET);
            printf("%s%s%s  ", keytype_color(e->keytype),
                   keytype_label(e->keytype), COL_RESET);
        } else {
            printf("%-40s  %-9s  ", truncated, keytype_label(e->keytype));
        }

        print_keypreview(e->keydata_b64);
        printf("\n");
    }

    if (!no_color)
        printf(COL_DIM);
    printf("\n%zu entries  •  %s\n", db.count, path);
    if (!no_color)
        printf(COL_RESET);

    khm_db_free(&db);
    return 0;
}
