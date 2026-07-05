#include "json.h"

#include <string.h>

void khm_json_escape(FILE *out, const char *s) {
    if (!s) return;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        switch (*p) {
            case '"':  fputs("\\\"", out); break;
            case '\\': fputs("\\\\", out); break;
            case '\n': fputs("\\n",  out); break;
            case '\r': fputs("\\r",  out); break;
            case '\t': fputs("\\t",  out); break;
            default:
                if (*p < 0x20) {
                    fprintf(out, "\\u%04x", *p);
                } else {
                    fputc(*p, out);
                }
        }
    }
}

static void json_str(FILE *out, const char *s) {
    if (!s) { fputs("null", out); return; }
    fputc('"', out);
    khm_json_escape(out, s);
    fputc('"', out);
}

static const char *status_str(khm_status_t s) {
    switch (s) {
        case KHM_STATUS_OK:          return "ok";
        case KHM_STATUS_CHANGED:     return "changed";
        case KHM_STATUS_NEW:         return "new";
        case KHM_STATUS_UNREACHABLE: return "unreachable";
        case KHM_STATUS_NONE:
        default:                     return "none";
    }
}

void khm_json_write_entry(FILE *out, const khm_entry_t *e, const char *fingerprint) {
    fputc('{', out);

    fputs("\"hostnames\":", out);
    if (e->hashed) {
        /* Hostname is not recoverable — mirror list.c's "<hashed>" display
         * by not pretending we know it. */
        fputs("[]", out);
    } else {
        fputc('[', out);
        for (int i = 0; i < e->hostname_count; i++) {
            if (i > 0) fputc(',', out);
            json_str(out, e->hostnames[i]);
        }
        fputc(']', out);
    }

    fprintf(out, ",\"hashed\":%s", e->hashed ? "true" : "false");
    fprintf(out, ",\"port\":%d", e->port ? e->port : 22);

    fputs(",\"algorithm\":", out);
    json_str(out, e->keytype_str);

    if (fingerprint) {
        fputs(",\"fingerprint\":", out);
        json_str(out, fingerprint);
    }

    fputc('}', out);
}

void khm_json_write_result(FILE *out, const khm_result_t *r) {
    fputc('{', out);

    fputs("\"host\":", out);
    json_str(out, r->host);

    fprintf(out, ",\"port\":%d", r->port ? r->port : 22);

    fputs(",\"status\":", out);
    json_str(out, status_str(r->status));

    fputs(",\"algorithm\":", out);
    json_str(out, r->algorithm);

    fputs(",\"fetched_fingerprint\":", out);
    json_str(out, r->fetched_fp);

    fputs(",\"known_fingerprint\":", out);
    json_str(out, r->known_fp);

    fputs(",\"record\":", out);
    if (r->record_index > 0)
        fprintf(out, "%ld", r->record_index);
    else
        fputs("null", out);

    fputc('}', out);
}

void khm_json_array_begin(FILE *out) {
    fputc('[', out);
}

void khm_json_array_next(FILE *out, int *first) {
    if (!*first) fputc(',', out);
    *first = 0;
}

void khm_json_array_end(FILE *out) {
    fputc(']', out);
    fputc('\n', out);
}
