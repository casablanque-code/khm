#include "doctor.h"
#include "../parser.h"
#include "../hostkey.h"
#include "../json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>

#define COL_RESET   "\033[0m"
#define COL_BOLD    "\033[1m"
#define COL_GREEN   "\033[32m"
#define COL_RED     "\033[31m"
#define COL_YELLOW  "\033[33m"
#define COL_DIM     "\033[2m"

#define DOCTOR_REACHABLE_TIMEOUT_MS 3000

typedef enum { SEV_INFO, SEV_WARNING, SEV_ERROR } sev_t;

typedef struct {
    const char *check;   /* static string, never freed */
    sev_t       severity;
    char        message[300];
} finding_t;

typedef struct {
    finding_t *items;
    size_t     count;
    size_t     cap;
} findings_t;

static void add_finding(findings_t *f, const char *check, sev_t sev, const char *fmt, ...) {
    if (f->count == f->cap) {
        size_t newcap = f->cap ? f->cap * 2 : 16;
        finding_t *tmp = realloc(f->items, newcap * sizeof(finding_t));
        if (!tmp) return; /* best-effort: drop the finding, don't crash a health check */
        f->items = tmp;
        f->cap = newcap;
    }
    finding_t *item = &f->items[f->count++];
    item->check = check;
    item->severity = sev;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(item->message, sizeof(item->message), fmt, ap);
    va_end(ap);
}

/* ------------------------------------------------------------------ */
/* checks                                                                */
/* ------------------------------------------------------------------ */

static int entries_equal(const khm_entry_t *a, const khm_entry_t *b) {
    if (a->hashed != b->hashed) return 0;
    if (a->port != b->port) return 0;
    if (strcmp(a->keytype_str, b->keytype_str) != 0) return 0;
    if (strcmp(a->keydata_b64, b->keydata_b64) != 0) return 0;
    if (a->hostname_count != b->hostname_count) return 0;
    for (int i = 0; i < a->hostname_count; i++)
        if (strcasecmp(a->hostnames[i], b->hostnames[i]) != 0) return 0;
    return 1;
}

static void check_malformed(const khm_db_t *db, findings_t *f) {
    for (size_t i = 0; i < db->error_count; i++) {
        add_finding(f, "malformed_line", SEV_ERROR,
                    "line %ld could not be parsed: \"%s\"",
                    db->errors[i].line_number, db->errors[i].raw);
    }
}

/* Visible duplicates: two non-hashed lines that are byte-for-byte the
 * same record — the kind you'd spot yourself scrolling the file. */
static void check_duplicates(const khm_db_t *db, findings_t *f) {
    for (size_t i = 0; i < db->count; i++) {
        const khm_entry_t *a = &db->entries[i];
        if (a->hashed) continue;
        for (size_t j = i + 1; j < db->count; j++) {
            const khm_entry_t *b = &db->entries[j];
            if (b->hashed || !entries_equal(a, b)) continue;
            add_finding(f, "duplicate_entries", SEV_WARNING,
                        "line %ld is an exact duplicate of line %ld (%s)",
                        b->line_number, a->line_number, a->hostnames[0]);
        }
    }
}

/* Hidden duplicates: hashed lines sharing the same hash token. Unlike
 * the plain-text case above, you cannot eyeball these — the hostname
 * is concealed, so two stale entries for the same host just look like
 * two unrelated random strings. */
static void check_hashed_duplicates(const khm_db_t *db, findings_t *f) {
    for (size_t i = 0; i < db->count; i++) {
        const khm_entry_t *a = &db->entries[i];
        if (!a->hashed) continue;
        for (size_t j = i + 1; j < db->count; j++) {
            const khm_entry_t *b = &db->entries[j];
            if (!b->hashed) continue;
            if (strcmp(a->hostnames[0], b->hostnames[0]) != 0) continue;

            int key_match = (strcmp(a->keytype_str, b->keytype_str) == 0 &&
                              strcmp(a->keydata_b64, b->keydata_b64) == 0);
            if (key_match) {
                add_finding(f, "hashed_duplicate", SEV_WARNING,
                            "line %ld repeats the same hashed host as line %ld "
                            "(identical key, safe to drop one)",
                            b->line_number, a->line_number);
            } else {
                add_finding(f, "hashed_duplicate", SEV_WARNING,
                            "line %ld has the same hashed host as line %ld but a "
                            "DIFFERENT key (stale entry left behind after a key change?)",
                            b->line_number, a->line_number);
            }
        }
    }
}

static void check_obsolete_algorithms(const khm_db_t *db, findings_t *f) {
    for (size_t i = 0; i < db->count; i++) {
        const khm_entry_t *e = &db->entries[i];
        int is_dss = strcmp(e->keytype_str, "ssh-dss") == 0;
        int is_rsa = strcmp(e->keytype_str, "ssh-rsa") == 0;
        if (!is_dss && !is_rsa) continue;

        add_finding(f, "obsolete_algorithm", SEV_WARNING,
                    "line %ld uses %s (%s) for %s",
                    e->line_number, e->keytype_str,
                    is_dss ? "DSA, deprecated" : "relies on SHA-1 signatures, deprecated",
                    e->hashed ? "<hashed>" : e->hostnames[0]);
    }
}

/* One host offering more than one key type is often legitimate (a
 * server that publishes RSA and ED25519 both) — informational, not a
 * warning, and doesn't affect the exit code. */
typedef struct {
    char host[KHM_MAX_HOSTNAME];
    char types[8][KHM_MAX_KEYTYPE];
    int  type_count;
} host_types_t;

static void check_mixed_algorithms(const khm_db_t *db, findings_t *f) {
    host_types_t *groups = NULL;
    size_t count = 0, cap = 0;

    for (size_t i = 0; i < db->count; i++) {
        const khm_entry_t *e = &db->entries[i];
        if (e->hashed) continue;

        for (int h = 0; h < e->hostname_count; h++) {
            size_t gi = count;
            for (size_t k = 0; k < count; k++) {
                if (strcasecmp(groups[k].host, e->hostnames[h]) == 0) { gi = k; break; }
            }
            if (gi == count) {
                if (count == cap) {
                    size_t newcap = cap ? cap * 2 : 16;
                    host_types_t *tmp = realloc(groups, newcap * sizeof(host_types_t));
                    if (!tmp) { free(groups); return; }
                    groups = tmp;
                    cap = newcap;
                }
                snprintf(groups[count].host, KHM_MAX_HOSTNAME, "%s", e->hostnames[h]);
                groups[count].type_count = 0;
                count++;
            }
            host_types_t *g = &groups[gi];
            int dup = 0;
            for (int t = 0; t < g->type_count; t++)
                if (strcmp(g->types[t], e->keytype_str) == 0) { dup = 1; break; }
            if (!dup && g->type_count < 8) {
                snprintf(g->types[g->type_count], KHM_MAX_KEYTYPE, "%s", e->keytype_str);
                g->type_count++;
            }
        }
    }

    for (size_t i = 0; i < count; i++) {
        if (groups[i].type_count <= 1) continue;
        char joined[256] = "";
        for (int t = 0; t < groups[i].type_count; t++) {
            if (t > 0) strncat(joined, ", ", sizeof(joined) - strlen(joined) - 1);
            strncat(joined, groups[i].types[t], sizeof(joined) - strlen(joined) - 1);
        }
        add_finding(f, "mixed_algorithms", SEV_INFO,
                    "%s has %d key types on file: %s",
                    groups[i].host, groups[i].type_count, joined);
    }
    free(groups);
}

/* Opt-in only (--check-reachable): the one check that touches the network. */
typedef struct { char host[KHM_MAX_HOSTNAME]; int port; } target_t;

static int add_target(target_t **targets, size_t *count, size_t *cap, const char *host, int port) {
    for (size_t i = 0; i < *count; i++)
        if (strcasecmp((*targets)[i].host, host) == 0 && (*targets)[i].port == port) return 0;
    if (*count == *cap) {
        size_t newcap = *cap ? *cap * 2 : 16;
        target_t *tmp = realloc(*targets, newcap * sizeof(target_t));
        if (!tmp) return -1;
        *targets = tmp;
        *cap = newcap;
    }
    snprintf((*targets)[*count].host, KHM_MAX_HOSTNAME, "%s", host);
    (*targets)[*count].port = port;
    (*count)++;
    return 0;
}

static void check_unreachable(const khm_db_t *db, findings_t *f) {
    target_t *targets = NULL;
    size_t t_count = 0, t_cap = 0;
    size_t hashed_skipped = 0;

    for (size_t i = 0; i < db->count; i++) {
        const khm_entry_t *e = &db->entries[i];
        if (e->hashed) { hashed_skipped++; continue; }
        int port = e->port ? e->port : 22;
        for (int h = 0; h < e->hostname_count; h++) {
            if (add_target(&targets, &t_count, &t_cap, e->hostnames[h], port) < 0) {
                free(targets);
                return;
            }
        }
    }

    if (t_count == 0 && hashed_skipped > 0) {
        /* --check-reachable was requested but there was nothing it
         * could actually test — surfaced as info, not folded into the
         * unreachable_host check name, so it doesn't make the
         * checklist header look like a failure when nothing failed. */
        add_finding(f, "reachability_note", SEV_INFO,
                    "--check-reachable had nothing to test: all %zu entr%s are hashed "
                    "(hostname unknown, can't connect)",
                    hashed_skipped, hashed_skipped == 1 ? "y" : "ies");
        free(targets);
        return;
    }

    for (size_t i = 0; i < t_count; i++) {
        khm_hostkey_t live;
        int r = khm_fetch_hostkey(targets[i].host, targets[i].port, DOCTOR_REACHABLE_TIMEOUT_MS, &live);
        if (r >= 0) continue;

        const char *reason = (r == -2) ? "timeout" : "connection error";
        if (targets[i].port != 22)
            add_finding(f, "unreachable_host", SEV_WARNING, "%s:%d is unreachable (%s)",
                        targets[i].host, targets[i].port, reason);
        else
            add_finding(f, "unreachable_host", SEV_WARNING, "%s is unreachable (%s)",
                        targets[i].host, reason);
    }
    free(targets);
}

/* ------------------------------------------------------------------ */

static void write_finding_json(FILE *out, const finding_t *item) {
    const char *sev = item->severity == SEV_ERROR   ? "error"
                     : item->severity == SEV_WARNING ? "warning"
                                                      : "info";
    fputc('{', out);
    fputs("\"check\":\"", out);    khm_json_escape(out, item->check);   fputs("\"", out);
    fputs(",\"severity\":\"", out); khm_json_escape(out, sev);          fputs("\"", out);
    fputs(",\"message\":\"", out);  khm_json_escape(out, item->message); fputs("\"", out);
    fputc('}', out);
}

int cmd_doctor(const char *path, int no_color, int json_output, int check_reachable) {
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

    findings_t f = {0};
    check_malformed(&db, &f);
    check_duplicates(&db, &f);
    check_hashed_duplicates(&db, &f);
    check_obsolete_algorithms(&db, &f);
    check_mixed_algorithms(&db, &f);
    if (check_reachable) check_unreachable(&db, &f);

    size_t n_error = 0, n_warning = 0, n_info = 0;
    for (size_t i = 0; i < f.count; i++) {
        switch (f.items[i].severity) {
            case SEV_ERROR:   n_error++;   break;
            case SEV_WARNING: n_warning++; break;
            case SEV_INFO:    n_info++;    break;
        }
    }

    if (json_output) {
        int first = 1;
        khm_json_array_begin(stdout);
        for (size_t i = 0; i < f.count; i++) {
            khm_json_array_next(stdout, &first);
            write_finding_json(stdout, &f.items[i]);
        }
        khm_json_array_end(stdout);
    } else {
#define C(code) (no_color ? "" : code)
        static const char *checks[] = {
            "malformed_line", "duplicate_entries", "hashed_duplicate",
            "obsolete_algorithm", "mixed_algorithms",
        };
        for (size_t c = 0; c < sizeof(checks) / sizeof(checks[0]); c++) {
            size_t n = 0;
            for (size_t i = 0; i < f.count; i++)
                if (strcmp(f.items[i].check, checks[c]) == 0) n++;
            if (n == 0)
                printf("  %s\xe2\x9c\x93%s %s\n", C(COL_GREEN), C(COL_RESET), checks[c]);
            else
                printf("  %s\xe2\x9c\x98%s %s (%zu)\n", C(COL_RED), C(COL_RESET), checks[c], n);
        }
        if (check_reachable) {
            size_t n = 0;
            for (size_t i = 0; i < f.count; i++)
                if (strcmp(f.items[i].check, "unreachable_host") == 0) n++;
            if (n == 0)
                printf("  %s\xe2\x9c\x93%s unreachable_host\n", C(COL_GREEN), C(COL_RESET));
            else
                printf("  %s\xe2\x9c\x98%s unreachable_host (%zu)\n", C(COL_RED), C(COL_RESET), n);
        }

        if (f.count > 0) {
            printf("\n");
            for (size_t i = 0; i < f.count; i++) {
                const char *color = f.items[i].severity == SEV_ERROR   ? COL_RED
                                  : f.items[i].severity == SEV_WARNING ? COL_YELLOW
                                                                        : COL_DIM;
                const char *label = f.items[i].severity == SEV_ERROR   ? "error"
                                  : f.items[i].severity == SEV_WARNING ? "warn "
                                                                        : "info ";
                printf("  %s%s%s  [%s]  %s\n", C(color), label, C(COL_RESET),
                       f.items[i].check, f.items[i].message);
            }
        }

        printf("\n%s%zu findings%s", C(COL_BOLD), f.count, C(COL_RESET));
        if (n_error)   printf("  %s%zu error%s%s",   C(COL_RED),    n_error,   n_error   == 1 ? "" : "s", C(COL_RESET));
        if (n_warning) printf("  %s%zu warning%s%s", C(COL_YELLOW), n_warning, n_warning == 1 ? "" : "s", C(COL_RESET));
        if (n_info)    printf("  %s%zu info%s",      C(COL_DIM),    n_info,                              C(COL_RESET));
        printf("\n");
    }

    free(f.items);
    khm_db_free(&db);

    return (n_error > 0 || n_warning > 0) ? 1 : 0;
}
