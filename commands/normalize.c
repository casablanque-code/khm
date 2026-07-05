#include "normalize.h"
#include "../parser.h"
#include "../hostkey.h"
#include "../json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* ------------------------------------------------------------------ */
/* Grouping plain (non-hashed) entries by identical key                 */
/*                                                                      */
/* Two known_hosts lines for different hostnames but the *same*        */
/* algorithm+key+port are, cryptographically, the same trusted          */
/* identity — merging their hostname lists into one line is safe        */
/* cosmetic cleanup, unlike merging across two files where a changed    */
/* key could be hidden.                                                 */
/* ------------------------------------------------------------------ */

/* Returns: 0 = fully redundant (every hostname already in the group),
 *          1 = merged into an existing group (added new hostname(s)),
 *          2 = created a brand new group,
 *         -1 = out of memory                                          */
static int find_or_add_group(khm_entry_t **groups, size_t *count, size_t *cap,
                              const khm_entry_t *e) {
    for (size_t i = 0; i < *count; i++) {
        khm_entry_t *g = &(*groups)[i];
        if (g->port != e->port) continue;
        if (strcmp(g->keytype_str, e->keytype_str) != 0) continue;
        if (strcmp(g->keydata_b64, e->keydata_b64) != 0) continue;

        int added_any = 0;
        for (int j = 0; j < e->hostname_count; j++) {
            int dup = 0;
            for (int k = 0; k < g->hostname_count; k++) {
                if (strcasecmp(g->hostnames[k], e->hostnames[j]) == 0) { dup = 1; break; }
            }
            if (!dup && g->hostname_count < KHM_MAX_HOSTS) {
                snprintf(g->hostnames[g->hostname_count], KHM_MAX_HOSTNAME, "%s", e->hostnames[j]);
                g->hostname_count++;
                added_any = 1;
            }
        }
        return added_any ? 1 : 0;
    }

    if (*count == *cap) {
        size_t new_cap = *cap ? *cap * 2 : 16;
        khm_entry_t *tmp = realloc(*groups, new_cap * sizeof(khm_entry_t));
        if (!tmp) return -1;
        *groups = tmp;
        *cap = new_cap;
    }
    (*groups)[*count] = *e; /* fixed-size arrays inside — plain struct copy is safe */
    (*count)++;
    return 2;
}

static int cmp_group(const void *a, const void *b) {
    const khm_entry_t *ea = a, *eb = b;
    int c = strcasecmp(ea->hostnames[0], eb->hostnames[0]);
    if (c != 0) return c;
    return strcmp(ea->keytype_str, eb->keytype_str);
}

/* ------------------------------------------------------------------ */
/* Hashed entries: dedupe on exact match only, order preserved as-is —  */
/* the hash conceals the hostname so there is nothing meaningful to     */
/* sort or merge by.                                                    */
/* ------------------------------------------------------------------ */

static int is_exact_dup_hashed(const khm_entry_t *kept, size_t kept_count, const khm_entry_t *e) {
    for (size_t i = 0; i < kept_count; i++) {
        if (strcmp(kept[i].hostnames[0], e->hostnames[0]) == 0 &&
            strcmp(kept[i].keytype_str, e->keytype_str) == 0 &&
            strcmp(kept[i].keydata_b64, e->keydata_b64) == 0)
            return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* known_hosts line writer                                              */
/* ------------------------------------------------------------------ */

static void write_plain_entry(FILE *out, const khm_entry_t *e) {
    for (int i = 0; i < e->hostname_count; i++) {
        if (i > 0) fputc(',', out);
        if (e->port && e->port != 22)
            fprintf(out, "[%s]:%d", e->hostnames[i], e->port);
        else
            fputs(e->hostnames[i], out);
    }
    fprintf(out, " %s %s\n", e->keytype_str, e->keydata_b64);
}

static void write_hashed_entry(FILE *out, const khm_entry_t *e) {
    /* hostnames[0] already holds the full "|1|salt|hash|" token */
    fprintf(out, "%s %s %s\n", e->hostnames[0], e->keytype_str, e->keydata_b64);
}

/* ------------------------------------------------------------------ */

int cmd_normalize(const char *path, int write_back, int json_output) {
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

    khm_entry_t *groups = NULL;
    size_t g_count = 0, g_cap = 0;
    khm_entry_t *hashed_kept = NULL;
    size_t h_count = 0, h_cap = 0;

    size_t full_duplicates = 0; /* lines that added nothing new */
    size_t merges = 0;          /* existing groups that gained hostnames */

    for (size_t i = 0; i < db.count; i++) {
        const khm_entry_t *e = &db.entries[i];

        if (e->hashed) {
            if (is_exact_dup_hashed(hashed_kept, h_count, e)) {
                full_duplicates++;
                continue;
            }
            if (h_count == h_cap) {
                size_t new_cap = h_cap ? h_cap * 2 : 16;
                khm_entry_t *tmp = realloc(hashed_kept, new_cap * sizeof(khm_entry_t));
                if (!tmp) {
                    fprintf(stderr, "khm normalize: out of memory\n");
                    free(groups); free(hashed_kept); khm_db_free(&db);
                    return 1;
                }
                hashed_kept = tmp;
                h_cap = new_cap;
            }
            hashed_kept[h_count++] = *e;
            continue;
        }

        int r = find_or_add_group(&groups, &g_count, &g_cap, e);
        if (r < 0) {
            fprintf(stderr, "khm normalize: out of memory\n");
            free(groups); free(hashed_kept); khm_db_free(&db);
            return 1;
        }
        if (r == 0) full_duplicates++;
        else if (r == 1) merges++;
    }

    qsort(groups, g_count, sizeof(khm_entry_t), cmp_group);

    size_t total_out = g_count + h_count;

    if (json_output && !write_back) {
        int first = 1;
        khm_json_array_begin(stdout);
        for (size_t i = 0; i < g_count; i++) {
            khm_json_array_next(stdout, &first);
            char fp[128];
            const char *fp_ptr = (khm_fingerprint_from_b64(groups[i].keydata_b64, fp, sizeof(fp)) == 0) ? fp : NULL;
            khm_json_write_entry(stdout, &groups[i], fp_ptr);
        }
        for (size_t i = 0; i < h_count; i++) {
            khm_json_array_next(stdout, &first);
            khm_json_write_entry(stdout, &hashed_kept[i], NULL);
        }
        khm_json_array_end(stdout);
    } else if (write_back) {
        char tmp_path[600];
        snprintf(tmp_path, sizeof(tmp_path), "%s.khm-tmp", path);

        FILE *out = fopen(tmp_path, "w");
        if (!out) {
            fprintf(stderr, "khm normalize: cannot create '%s'\n", tmp_path);
            free(groups); free(hashed_kept); khm_db_free(&db);
            return 1;
        }
        for (size_t i = 0; i < g_count; i++) write_plain_entry(out, &groups[i]);
        for (size_t i = 0; i < h_count; i++) write_hashed_entry(out, &hashed_kept[i]);
        fclose(out);

        if (rename(tmp_path, path) != 0) {
            fprintf(stderr, "khm normalize: failed to replace '%s' (result left at '%s')\n",
                    path, tmp_path);
            free(groups); free(hashed_kept); khm_db_free(&db);
            return 1;
        }
    } else {
        for (size_t i = 0; i < g_count; i++) write_plain_entry(stdout, &groups[i]);
        for (size_t i = 0; i < h_count; i++) write_hashed_entry(stdout, &hashed_kept[i]);
    }

    fprintf(stderr, "khm normalize: %zu lines -> %zu lines  (%zu exact duplicates removed, %zu merged by shared key)%s\n",
            db.count, total_out, full_duplicates, merges,
            write_back ? "  [written]" : "");

    free(groups);
    free(hashed_kept);
    khm_db_free(&db);
    return 0;
}
