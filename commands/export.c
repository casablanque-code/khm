#include "export.h"
#include "../parser.h"
#include "../hostkey.h"
#include "../json.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>

typedef enum { FMT_CSV, FMT_MD, FMT_HTML, FMT_JSON } khm_fmt_t;

/* Comma-joined hostnames can exceed a small buffer once every slot is
 * near KHM_MAX_HOSTNAME; size for the worst case. */
#define HOSTS_BUF_LEN (KHM_MAX_HOSTS * (KHM_MAX_HOSTNAME + 2))

static int parse_format(const char *s, khm_fmt_t *out) {
    if (!s || strcasecmp(s, "csv") == 0)                            { *out = FMT_CSV;  return 0; }
    if (strcasecmp(s, "md") == 0 || strcasecmp(s, "markdown") == 0) { *out = FMT_MD;   return 0; }
    if (strcasecmp(s, "html") == 0)                                 { *out = FMT_HTML; return 0; }
    if (strcasecmp(s, "json") == 0)                                 { *out = FMT_JSON; return 0; }
    return -1;
}

static void join_hostnames(const khm_entry_t *e, char *buf, size_t buflen, const char *sep) {
    if (e->hashed) { snprintf(buf, buflen, "<hashed>"); return; }
    buf[0] = '\0';
    for (int i = 0; i < e->hostname_count; i++) {
        if (i > 0) strncat(buf, sep, buflen - strlen(buf) - 1);
        strncat(buf, e->hostnames[i], buflen - strlen(buf) - 1);
    }
}

/* Best-effort fingerprint for one entry; "" (not NULL) when hashed or
 * malformed, so callers can print it unconditionally without a NULL
 * check breaking table alignment. */
static void entry_fingerprint(const khm_entry_t *e, char *fp, size_t fp_len) {
    fp[0] = '\0';
    if (!e->hashed) khm_fingerprint_from_b64(e->keydata_b64, fp, fp_len);
}

/* ------------------------------------------------------------------ */
/* Per-format escaping                                                  */
/* ------------------------------------------------------------------ */

static void csv_field(FILE *out, const char *s) {
    if (!strpbrk(s, ",\"\n")) { fputs(s, out); return; }
    fputc('"', out);
    for (const char *p = s; *p; p++) {
        if (*p == '"') fputc('"', out); /* RFC4180: double up embedded quotes */
        fputc(*p, out);
    }
    fputc('"', out);
}

static void md_field(FILE *out, const char *s) {
    for (const char *p = s; *p; p++) {
        if (*p == '|') fputc('\\', out); /* escape pipe or it breaks the table */
        fputc(*p, out);
    }
}

static void html_field(FILE *out, const char *s) {
    for (const char *p = s; *p; p++) {
        switch (*p) {
            case '&':  fputs("&amp;",  out); break;
            case '<':  fputs("&lt;",   out); break;
            case '>':  fputs("&gt;",   out); break;
            case '"':  fputs("&quot;", out); break;
            default:   fputc(*p, out);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Format writers                                                       */
/* ------------------------------------------------------------------ */

static void export_json(const khm_db_t *db) {
    int first = 1;
    khm_json_array_begin(stdout);
    for (size_t i = 0; i < db->count; i++) {
        const khm_entry_t *e = &db->entries[i];
        khm_json_array_next(stdout, &first);

        char fp[128];
        const char *fp_ptr = NULL;
        if (!e->hashed && khm_fingerprint_from_b64(e->keydata_b64, fp, sizeof(fp)) == 0)
            fp_ptr = fp;

        khm_json_write_entry(stdout, e, fp_ptr);
    }
    khm_json_array_end(stdout);
}

static void export_csv(const khm_db_t *db) {
    fputs("hostnames,hashed,port,algorithm,fingerprint\n", stdout);
    for (size_t i = 0; i < db->count; i++) {
        const khm_entry_t *e = &db->entries[i];
        char hosts[HOSTS_BUF_LEN], fp[128];
        join_hostnames(e, hosts, sizeof(hosts), ";");
        entry_fingerprint(e, fp, sizeof(fp));

        csv_field(stdout, hosts);                          fputc(',', stdout);
        fputs(e->hashed ? "true" : "false", stdout);        fputc(',', stdout);
        fprintf(stdout, "%d", e->port ? e->port : 22);      fputc(',', stdout);
        csv_field(stdout, e->keytype_str);                  fputc(',', stdout);
        csv_field(stdout, fp);
        fputc('\n', stdout);
    }
}

static void export_md(const khm_db_t *db) {
    fputs("| Hostnames | Hashed | Port | Algorithm | Fingerprint |\n", stdout);
    fputs("|---|---|---|---|---|\n", stdout);
    for (size_t i = 0; i < db->count; i++) {
        const khm_entry_t *e = &db->entries[i];
        char hosts[HOSTS_BUF_LEN], fp[128];
        join_hostnames(e, hosts, sizeof(hosts), ", ");
        entry_fingerprint(e, fp, sizeof(fp));

        fputs("| ", stdout);   md_field(stdout, hosts);
        fputs(" | ", stdout);  fputs(e->hashed ? "yes" : "no", stdout);
        fprintf(stdout, " | %d | ", e->port ? e->port : 22);
        md_field(stdout, e->keytype_str);
        fputs(" | ", stdout);  md_field(stdout, fp);
        fputs(" |\n", stdout);
    }
}

static void export_html(const khm_db_t *db) {
    fputs("<table>\n"
          "  <thead>\n"
          "    <tr><th>Hostnames</th><th>Hashed</th><th>Port</th>"
          "<th>Algorithm</th><th>Fingerprint</th></tr>\n"
          "  </thead>\n  <tbody>\n", stdout);
    for (size_t i = 0; i < db->count; i++) {
        const khm_entry_t *e = &db->entries[i];
        char hosts[HOSTS_BUF_LEN], fp[128];
        join_hostnames(e, hosts, sizeof(hosts), ", ");
        entry_fingerprint(e, fp, sizeof(fp));

        fputs("    <tr><td>", stdout);  html_field(stdout, hosts);
        fputs("</td><td>", stdout);     fputs(e->hashed ? "yes" : "no", stdout);
        fprintf(stdout, "</td><td>%d</td><td>", e->port ? e->port : 22);
        html_field(stdout, e->keytype_str);
        fputs("</td><td>", stdout);     html_field(stdout, fp);
        fputs("</td></tr>\n", stdout);
    }
    fputs("  </tbody>\n</table>\n", stdout);
}

/* ------------------------------------------------------------------ */

int cmd_export(const char *path, const char *format, int json_output) {
    khm_fmt_t fmt = FMT_JSON;
    if (!json_output && parse_format(format, &fmt) < 0) {
        fprintf(stderr, "khm export: unknown format '%s' (want csv, md, html, or json)\n",
                format ? format : "(null)");
        return 1;
    }

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

    switch (fmt) {
        case FMT_JSON: export_json(&db); break;
        case FMT_CSV:  export_csv(&db);  break;
        case FMT_MD:   export_md(&db);   break;
        case FMT_HTML: export_html(&db); break;
    }

    khm_db_free(&db);
    return 0;
}
