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

/*
 * Parse "host", "host:port", or "[host]:port" into separate host/port.
 * Defaults port to 22 if not specified. IPv6 addresses with multiple
 * colons and no brackets are treated as bare hostnames (ambiguous
 * without brackets, same convention ssh itself uses).
 */
void khm_parse_host_port(const char *arg, char *host, size_t hlen, int *port);

/*
 * Compute SSH-style fingerprint ("SHA256:...") from a base64-encoded
 * key blob as stored in a known_hosts entry (khm_entry_t.keydata_b64).
 * Purely local — no network I/O.
 *
 * Returns  0 on success
 *         -1 on malformed base64 or output buffer too small
 */
int khm_fingerprint_from_b64(const char *keydata_b64, char *out, size_t out_len);

/*
 * Internal — exposed only so the SSH binary packet header validation
 * (RFC 4253 §6) can be unit tested without opening a socket. Not a
 * stable public API.
 *
 * Validates pkt_len/pad_len and derives:
 *   out_total        bytes left to read off the wire after the header
 *   out_payload_len  resulting payload length (msg type + body)
 *
 * Returns 0 if consistent, -1 if pkt_len/pad_len are malformed or
 * would underflow (e.g. pad_len >= pkt_len).
 */
int khm_ssh_packet_lengths(uint32_t pkt_len, uint8_t pad_len,
                            uint32_t *out_total, uint32_t *out_payload_len);

#endif /* KHM_HOSTKEY_H */
