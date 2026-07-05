#ifndef KHM_JSON_H
#define KHM_JSON_H

#include <stdio.h>
#include "parser.h"

/*
 * Two independent JSON shapes:
 *
 *   khm_json_write_entry()  — a static known_hosts record (list/export/doctor).
 *                              No network involved, fingerprint is derived
 *                              locally from keydata_b64.
 *
 *   khm_json_write_result() — outcome of a live check (verify/scan/fingerprint).
 *                              Carries both the freshly fetched key and,
 *                              optionally, what was already on file.
 *
 * Keeping these separate avoids a single struct full of fields that are
 * null half the time depending on which command produced it.
 */

typedef enum {
    KHM_STATUS_NONE = 0,   /* list/export — no live check was performed   */
    KHM_STATUS_OK,
    KHM_STATUS_CHANGED,
    KHM_STATUS_NEW,
    KHM_STATUS_UNREACHABLE
} khm_status_t;

typedef struct {
    const char   *host;         /* as given on the command line            */
    int           port;
    khm_status_t  status;
    const char   *algorithm;    /* live key type, NULL if fetch failed     */
    const char   *fetched_fp;   /* "SHA256:...", NULL if not fetched       */
    const char   *known_fp;     /* "SHA256:...", NULL if no matching entry */
    long          record_index; /* 1-based known_hosts line/record, -1 if none */
} khm_result_t;

/* Escape a string into out as a JSON string body (no surrounding quotes). */
void khm_json_escape(FILE *out, const char *s);

/*
 * Serialize one known_hosts entry.
 *
 * fingerprint: pass NULL to omit the "fingerprint" field entirely — this is
 * the caller's decision, not this function's: khm_fingerprint_from_b64()
 * cannot recover anything from a hashed hostname, but the fingerprint of a
 * hashed entry is still mathematically valid (it comes from keydata_b64,
 * not from the hostname). Callers that consider it not worth emitting for
 * hashed records should pass NULL themselves.
 */
void khm_json_write_entry(FILE *out, const khm_entry_t *e, const char *fingerprint);

/* Serialize one live-check result. */
void khm_json_write_result(FILE *out, const khm_result_t *r);

/* Array helpers so callers don't hand-count commas. */
void khm_json_array_begin(FILE *out);
void khm_json_array_next(FILE *out, int *first);
void khm_json_array_end(FILE *out);

#endif /* KHM_JSON_H */
