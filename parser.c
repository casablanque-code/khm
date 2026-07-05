#include "parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pwd.h>
#include <unistd.h>

#define INITIAL_CAPACITY 64
#define LINE_MAX_LEN     8192

/* ------------------------------------------------------------------ */
/* helpers                                                              */
/* ------------------------------------------------------------------ */

static char *ltrim(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    return s;
}

static void rtrim(char *s) {
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1])) s[--n] = '\0';
}

khm_keytype_t khm_keytype_from_str(const char *s) {
    if (strcmp(s, "ssh-rsa")             == 0) return KHM_KEY_RSA;
    if (strcmp(s, "ecdsa-sha2-nistp256") == 0) return KHM_KEY_ECDSA_256;
    if (strcmp(s, "ecdsa-sha2-nistp384") == 0) return KHM_KEY_ECDSA_384;
    if (strcmp(s, "ecdsa-sha2-nistp521") == 0) return KHM_KEY_ECDSA_521;
    if (strcmp(s, "ssh-ed25519")         == 0) return KHM_KEY_ED25519;
    return KHM_KEY_UNKNOWN;
}

void khm_default_path(char *buf, size_t len) {
    const char *home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        home = pw ? pw->pw_dir : "/root";
    }
    snprintf(buf, len, "%s/.ssh/known_hosts", home);
}

/* ------------------------------------------------------------------ */
/* hostname field parser                                                */
/*                                                                      */
/* Formats:                                                             */
/*   hostname                                                           */
/*   hostname,hostname2                                                 */
/*   [hostname]:port                                                    */
/*   |1|salt|hash|   (hashed)                                          */
/* ------------------------------------------------------------------ */

static int parse_hostnames(char *field, khm_entry_t *e) {
    e->hostname_count = 0;
    e->port = 0;
    e->hashed = 0;

    /* hashed entry */
    if (field[0] == '|') {
        e->hashed = 1;
        if (e->hostname_count < KHM_MAX_HOSTS) {
            snprintf(e->hostnames[e->hostname_count],
                     KHM_MAX_HOSTNAME, "%s", field);
            e->hostname_count++;
        }
        return 0;
    }

    /* split on comma */
    char *save = NULL;
    char *tok = strtok_r(field, ",", &save);
    while (tok) {
        if (e->hostname_count >= KHM_MAX_HOSTS) break;

        /* [host]:port */
        if (tok[0] == '[') {
            char *close = strchr(tok, ']');
            if (close && *(close + 1) == ':') {
                *close = '\0';
                char *host = tok + 1;
                int port = atoi(close + 2);
                strncpy(e->hostnames[e->hostname_count], host,
                        KHM_MAX_HOSTNAME - 1);
                e->hostname_count++;
                if (e->port == 0) e->port = port;
                tok = strtok_r(NULL, ",", &save);
                continue;
            }
        }

        strncpy(e->hostnames[e->hostname_count], tok, KHM_MAX_HOSTNAME - 1);
        e->hostname_count++;
        tok = strtok_r(NULL, ",", &save);
    }
    return e->hostname_count > 0 ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* parse one line → entry                                              */
/* Returns: 1  = valid entry parsed                                    */
/*          0  = skip (comment/blank)                                  */
/*         -1  = parse error                                            */
/* ------------------------------------------------------------------ */

static int parse_line(char *line, khm_entry_t *e) {
    memset(e, 0, sizeof(*e));

    line = ltrim(line);
    rtrim(line);

    if (!*line || *line == '#') return 0;

    /* "@cert-authority" / "@revoked" markers — skip for now */
    if (*line == '@') return 0;

    /* field 1: hostnames */
    char *p = line;
    char *space = strpbrk(p, " \t");
    if (!space) return -1;
    *space = '\0';
    if (parse_hostnames(p, e) < 0) return -1;
    p = ltrim(space + 1);

    /* field 2: key type */
    space = strpbrk(p, " \t");
    if (!space) return -1;
    *space = '\0';
    strncpy(e->keytype_str, p, KHM_MAX_KEYTYPE - 1);
    e->keytype = khm_keytype_from_str(e->keytype_str);
    p = ltrim(space + 1);

    /* field 3: base64 key data */
    /* strip trailing comment if any */
    char *comment = strpbrk(p, " \t");
    if (comment) *comment = '\0';
    strncpy(e->keydata_b64, p, KHM_MAX_KEYDATA - 1);

    return 1;
}

/* ------------------------------------------------------------------ */
/* public API                                                           */
/* ------------------------------------------------------------------ */

int khm_parse_file(const char *path, khm_db_t *db) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    db->entries  = malloc(INITIAL_CAPACITY * sizeof(khm_entry_t));
    if (!db->entries) { fclose(f); return -1; }
    db->count    = 0;
    db->capacity = INITIAL_CAPACITY;

    db->errors         = NULL;
    db->error_count    = 0;
    db->error_capacity = 0;

    char line[LINE_MAX_LEN];
    long lineno = 0;
    while (fgets(line, sizeof(line), f)) {
        lineno++;

        /* Keep a trimmed copy for error reporting before parse_line
         * mutates the buffer in place (ltrim/rtrim/strtok). Bounded
         * copy done manually (not snprintf) since `line` can be up to
         * LINE_MAX_LEN and truncation here is intentional, not a bug
         * gcc needs to warn about. */
        char raw_copy[256];
        size_t copy_len = strlen(line);
        if (copy_len >= sizeof(raw_copy)) copy_len = sizeof(raw_copy) - 1;
        memcpy(raw_copy, line, copy_len);
        raw_copy[copy_len] = '\0';
        size_t rl = copy_len;
        while (rl > 0 && (raw_copy[rl - 1] == '\n' || raw_copy[rl - 1] == '\r'))
            raw_copy[--rl] = '\0';

        khm_entry_t e;
        int r = parse_line(line, &e);

        if (r == 1) {
            e.line_number = lineno;
            if (db->count == db->capacity) {
                size_t newcap = db->capacity * 2;
                khm_entry_t *tmp = realloc(db->entries,
                                           newcap * sizeof(khm_entry_t));
                if (!tmp) { fclose(f); return -1; }
                db->entries  = tmp;
                db->capacity = newcap;
            }
            db->entries[db->count++] = e;
        } else if (r == -1) {
            if (db->error_count == db->error_capacity) {
                size_t newcap = db->error_capacity ? db->error_capacity * 2 : 8;
                khm_parse_error_t *tmp = realloc(db->errors, newcap * sizeof(khm_parse_error_t));
                if (tmp) { db->errors = tmp; db->error_capacity = newcap; }
                /* on realloc failure, just drop this one error rather
                 * than aborting the whole parse over a cosmetic issue */
            }
            if (db->error_count < db->error_capacity) {
                db->errors[db->error_count].line_number = lineno;
                snprintf(db->errors[db->error_count].raw,
                         sizeof(db->errors[db->error_count].raw), "%s", raw_copy);
                db->error_count++;
            }
        }
        /* r == 0: comment or blank line — legitimately skipped */
    }

    fclose(f);
    return 0;
}

void khm_db_free(khm_db_t *db) {
    free(db->entries);
    free(db->errors);
    db->entries        = NULL;
    db->count          = 0;
    db->capacity       = 0;
    db->errors         = NULL;
    db->error_count    = 0;
    db->error_capacity = 0;
}
