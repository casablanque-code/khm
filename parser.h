#ifndef KHM_PARSER_H
#define KHM_PARSER_H

#include <stddef.h>

#define KHM_MAX_HOSTS     16
#define KHM_MAX_HOSTNAME  256
#define KHM_MAX_KEYTYPE   64
#define KHM_MAX_KEYDATA   2048

typedef enum {
    KHM_KEY_UNKNOWN = 0,
    KHM_KEY_RSA,
    KHM_KEY_ECDSA_256,
    KHM_KEY_ECDSA_384,
    KHM_KEY_ECDSA_521,
    KHM_KEY_ED25519,
} khm_keytype_t;

typedef struct {
    char      hostnames[KHM_MAX_HOSTS][KHM_MAX_HOSTNAME]; /* comma-separated expanded */
    int       hostname_count;
    int       hashed;                /* 1 if |1|salt|hash| format */
    khm_keytype_t keytype;
    char      keytype_str[KHM_MAX_KEYTYPE];
    char      keydata_b64[KHM_MAX_KEYDATA];  /* raw base64 blob */
    int       port;                  /* 0 = default 22 */
} khm_entry_t;

typedef struct {
    khm_entry_t *entries;
    size_t       count;
    size_t       capacity;
} khm_db_t;

/* Parse known_hosts file. Returns 0 on success, -1 on error. */
int  khm_parse_file(const char *path, khm_db_t *db);
void khm_db_free(khm_db_t *db);

/* Resolve default known_hosts path into buf (len bytes). */
void khm_default_path(char *buf, size_t len);

khm_keytype_t khm_keytype_from_str(const char *s);

#endif /* KHM_PARSER_H */
