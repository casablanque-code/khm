#ifndef KHM_HOSTKEY_H
#define KHM_HOSTKEY_H

#include <stddef.h>
#include <stdint.h>

#define KHM_KEYDATA_MAX 2048

typedef struct {
    char     keytype_str[64];
    uint8_t  keydata[KHM_KEYDATA_MAX];  /* raw DER/wire-format public key */
    size_t   keydata_len;
    char     keydata_b64[KHM_KEYDATA_MAX]; /* base64 of keydata (for comparison) */
    char     fingerprint[128];          /* SHA256:base64url */
} khm_hostkey_t;

/*
 * Connect to host:port, perform SSH version exchange + KEX_INIT,
 * extract the server's host public key.
 *
 * Returns  0 on success
 *         -1 connection / protocol error
 *         -2 timeout
 */
int khm_fetch_hostkey(const char *host, int port, int timeout_ms,
                      khm_hostkey_t *out);

#endif /* KHM_HOSTKEY_H */
