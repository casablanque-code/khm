#include "hostkey.h"
#include "sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

/* ------------------------------------------------------------------ */
/* Base64 encode (standard alphabet, with padding)                     */
/* ------------------------------------------------------------------ */

static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void b64_encode(const uint8_t *src, size_t len, char *dst) {
    size_t i = 0, j = 0;
    for (; i + 2 < len; i += 3) {
        dst[j++] = B64[ src[i]          >> 2];
        dst[j++] = B64[(src[i]   & 0x3) << 4 | src[i+1] >> 4];
        dst[j++] = B64[(src[i+1] & 0xf) << 2 | src[i+2] >> 6];
        dst[j++] = B64[ src[i+2] & 0x3f];
    }
    if (i < len) {
        dst[j++] = B64[src[i] >> 2];
        if (i + 1 < len) {
            dst[j++] = B64[(src[i] & 0x3) << 4 | src[i+1] >> 4];
            dst[j++] = B64[(src[i+1] & 0xf) << 2];
        } else {
            dst[j++] = B64[(src[i] & 0x3) << 4];
            dst[j++] = '=';
        }
        dst[j++] = '=';
    }
    dst[j] = '\0';
}

/* Decode standard base64 (with or without padding) into raw bytes.
 * dst must be large enough (3/4 of strlen(src) rounded up is safe).
 * Returns decoded length, or (size_t)-1 on malformed input. */
static size_t b64_decode(const char *src, uint8_t *dst, size_t dst_cap) {
    static int8_t rev[256];
    static int rev_ready = 0;
    if (!rev_ready) {
        for (int i = 0; i < 256; i++) rev[i] = -1;
        for (int i = 0; i < 64; i++) rev[(unsigned char)B64[i]] = (int8_t)i;
        rev_ready = 1;
    }

    size_t j = 0;
    uint32_t acc = 0;
    int bits = 0;

    for (const char *p = src; *p; p++) {
        if (*p == '=' || *p == '\n' || *p == '\r') continue;
        int v = rev[(unsigned char)*p];
        if (v < 0) return (size_t)-1; /* malformed */

        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (j >= dst_cap) return (size_t)-1; /* too small */
            dst[j++] = (uint8_t)((acc >> bits) & 0xff);
        }
    }
    return j;
}

/* Base64url (no padding) for SSH fingerprint display */
static void b64url_encode_nopad(const uint8_t *src, size_t len, char *dst) {
    b64_encode(src, len, dst);
    /* replace + → - and / → _ and strip = */
    for (char *p = dst; *p; p++) {
        if      (*p == '+') *p = '-';
        else if (*p == '/') *p = '_';
    }
    /* strip trailing = */
    size_t n = strlen(dst);
    while (n > 0 && dst[n-1] == '=') dst[--n] = '\0';
}

/* ------------------------------------------------------------------ */
/* Network helpers                                                      */
/* ------------------------------------------------------------------ */

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int tcp_connect(const char *host, int port, int timeout_ms) {
    struct addrinfo hints = {0}, *res = NULL;
    char portstr[8];
    snprintf(portstr, sizeof(portstr), "%d", port);
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, portstr, &hints, &res) != 0) return -1;

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return -1; }

    set_nonblocking(fd);
    int r = connect(fd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    if (r < 0 && errno != EINPROGRESS) { close(fd); return -1; }

    struct pollfd pfd = { .fd = fd, .events = POLLOUT };
    if (poll(&pfd, 1, timeout_ms) <= 0) { close(fd); return -2; }

    int err = 0; socklen_t elen = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
    if (err) { close(fd); return -1; }

    /* restore blocking for simplicity */
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);

    /* set recv timeout */
    struct timeval tv = { .tv_sec = timeout_ms / 1000,
                          .tv_usec = (timeout_ms % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    return fd;
}

/* recv until '\n' (for SSH banner line) */
static int recv_line(int fd, char *buf, size_t max) {
    size_t i = 0;
    while (i < max - 1) {
        char c;
        ssize_t n = recv(fd, &c, 1, 0);
        if (n <= 0) return -1;
        buf[i++] = c;
        if (c == '\n') break;
    }
    buf[i] = '\0';
    return (int)i;
}

/* recv exactly n bytes */
static int recv_exact(int fd, uint8_t *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = recv(fd, buf + got, n - got, 0);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* SSH binary packet helpers (RFC 4253)                                */
/*                                                                      */
/* Packet layout:                                                       */
/*   uint32  packet_length   (excl. MAC, incl. padding_length+payload) */
/*   byte    padding_length                                             */
/*   byte[n] payload                                                    */
/*   byte[p] random padding                                             */
/* ------------------------------------------------------------------ */

#define SSH_MAX_PACKET (256 * 1024)

typedef struct {
    uint8_t *data;   /* payload only (after padding_length) */
    size_t   len;
} ssh_packet_t;

static int read_packet(int fd, ssh_packet_t *pkt) {
    uint8_t hdr[5];
    if (recv_exact(fd, hdr, 5) < 0) return -1;

    uint32_t pkt_len = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) |
                       ((uint32_t)hdr[2] <<  8) |  (uint32_t)hdr[3];
    uint8_t  pad_len = hdr[4];

    if (pkt_len < 2 || pkt_len > SSH_MAX_PACKET) return -1;

    uint32_t payload_len = pkt_len - 1 - pad_len; /* minus padding_length byte, minus padding */
    uint32_t total       = pkt_len - 1;            /* padding_length already consumed in hdr */

    uint8_t *buf = malloc(total);
    if (!buf) return -1;

    if (recv_exact(fd, buf, total) < 0) { free(buf); return -1; }

    pkt->data = buf;            /* first byte is msg type */
    pkt->len  = payload_len;
    return 0;
}

static void free_packet(ssh_packet_t *pkt) {
    free(pkt->data);
    pkt->data = NULL;
    pkt->len  = 0;
}

/* Read uint32 big-endian from buf; advance *pos */
static uint32_t read_u32(const uint8_t *buf, size_t buf_len, size_t *pos) {
    if (*pos + 4 > buf_len) return 0;
    uint32_t v = ((uint32_t)buf[*pos]   << 24) |
                 ((uint32_t)buf[*pos+1] << 16) |
                 ((uint32_t)buf[*pos+2] <<  8) |
                  (uint32_t)buf[*pos+3];
    *pos += 4;
    return v;
}

/* Read SSH string (uint32 len + data); returns pointer into buf, sets *slen */
static const uint8_t *read_str(const uint8_t *buf, size_t buf_len,
                                size_t *pos, uint32_t *slen) {
    if (*pos + 4 > buf_len) return NULL;
    *slen = read_u32(buf, buf_len, pos);
    if (*pos + *slen > buf_len) return NULL;
    const uint8_t *p = buf + *pos;
    *pos += *slen;
    return p;
}

/* ------------------------------------------------------------------ */
/* Build a minimal SSH_MSG_KEXINIT to send                             */
/* We advertise only what we need:                                     */
/*   kex:        curve25519-sha256 (most common modern server support) */
/*   host key:   ssh-ed25519,ecdsa-sha2-nistp256,ssh-rsa               */
/*   ciphers:    aes128-ctr (both directions, we don't actually use it)*/
/*   mac:        hmac-sha2-256                                         */
/*   compress:   none                                                  */
/* ------------------------------------------------------------------ */

#define SSH_MSG_DISCONNECT  1
#define SSH_MSG_KEXINIT    20
#define SSH_MSG_NEWKEYS    21
#define SSH_MSG_KEX_ECDH_INIT   30
#define SSH_MSG_KEX_ECDH_REPLY  31

/* Diagnostic-only tracing, off unless KHM_DEBUG=1 is set. Does not
 * change any protocol behavior — pure stderr narration to find out
 * *where* a handshake fails without guessing. */
static int khm_debug_enabled(void) {
    static int checked = 0, enabled = 0;
    if (!checked) {
        const char *v = getenv("KHM_DEBUG");
        enabled = (v && *v && strcmp(v, "0") != 0);
        checked = 1;
    }
    return enabled;
}
#define KHM_DBG(...) do { if (khm_debug_enabled()) fprintf(stderr, "[khm-debug] " __VA_ARGS__); } while (0)

/* SSH_MSG_DISCONNECT payload: uint32 reason_code, string description,
 * string language_tag. If the server sends this instead of what we
 * were waiting for, it is telling us exactly why — always worth
 * surfacing even outside debug mode, since "protocol failure" alone
 * throws away information the server handed us for free. */
static void report_disconnect(const uint8_t *payload, size_t plen) {
    size_t pos = 1; /* skip msg type */
    uint32_t reason = read_u32(payload, plen, &pos);
    uint32_t desc_len;
    const uint8_t *desc = read_str(payload, plen, &pos, &desc_len);
    fprintf(stderr, "khm: server sent SSH_MSG_DISCONNECT (reason %u): %.*s\n",
            reason, desc ? (int)desc_len : 0, desc ? (const char *)desc : "");
}

static void write_u32(uint8_t *buf, size_t *pos, uint32_t v) {
    buf[(*pos)++] = (v >> 24) & 0xff;
    buf[(*pos)++] = (v >> 16) & 0xff;
    buf[(*pos)++] = (v >>  8) & 0xff;
    buf[(*pos)++] =  v        & 0xff;
}

static void write_str(uint8_t *buf, size_t *pos, const char *s) {
    uint32_t len = (uint32_t)strlen(s);
    write_u32(buf, pos, len);
    memcpy(buf + *pos, s, len);
    *pos += len;
}

/* Seeded once, used for both the KEXINIT cookie and the ECDH ephemeral
 * key below. Not cryptographic quality and doesn't need to be — the
 * exchange is discarded right after we read the host key, no
 * encryption is ever negotiated. It only needs to avoid landing on
 * one of the handful of known low-order curve25519 points (see
 * send_kex_ecdh_init) — see rand() is more than enough for that. */
static void khm_rand_bytes(uint8_t *buf, size_t len) {
    static int seeded = 0;
    if (!seeded) {
        srand((unsigned)(time(NULL) ^ (unsigned)getpid()));
        seeded = 1;
    }
    for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)(rand() & 0xff);
}

static int send_kexinit(int fd) {
    uint8_t payload[1024];
    size_t  p = 0;

    payload[p++] = SSH_MSG_KEXINIT;

    /* 16 bytes random cookie */
    {
        uint8_t cookie[16];
        khm_rand_bytes(cookie, sizeof(cookie));
        memcpy(payload + p, cookie, sizeof(cookie));
        p += sizeof(cookie);
    }

    /* name-list fields (10 of them) */
    const char *kex_algs     = "curve25519-sha256,ecdh-sha2-nistp256";
    const char *host_key_algs= "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-rsa";
    const char *ciphers      = "aes128-ctr,aes256-ctr";
    const char *macs         = "hmac-sha2-256,hmac-sha1";
    const char *compress     = "none";
    const char *langs        = "";

    write_str(payload, &p, kex_algs);
    write_str(payload, &p, host_key_algs);
    write_str(payload, &p, ciphers);   /* enc c→s */
    write_str(payload, &p, ciphers);   /* enc s→c */
    write_str(payload, &p, macs);      /* mac c→s */
    write_str(payload, &p, macs);      /* mac s→c */
    write_str(payload, &p, compress);  /* cmp c→s */
    write_str(payload, &p, compress);  /* cmp s→c */
    write_str(payload, &p, langs);     /* lang c→s */
    write_str(payload, &p, langs);     /* lang s→c */

    payload[p++] = 0;    /* first_kex_packet_follows = false */
    write_u32(payload, &p, 0); /* reserved */

    /* wrap in binary packet */
    uint8_t  pad_len = (uint8_t)(8 - ((p + 5) % 8));
    if (pad_len < 4) pad_len += 8;
    uint32_t pkt_len = 1 + (uint32_t)p + pad_len; /* padding_length + payload + padding */

    uint8_t pkt[1100];
    size_t  pp = 0;
    write_u32(pkt, &pp, pkt_len);
    pkt[pp++] = pad_len;
    memcpy(pkt + pp, payload, p); pp += p;
    memset(pkt + pp, 0, pad_len); pp += pad_len;

    return (send(fd, pkt, pp, 0) == (ssize_t)pp) ? 0 : -1;
}

/* Send a minimal ephemeral ECDH public key so the server sends back
   its host key in KEX_ECDH_REPLY. We don't care about the resulting
   shared secret (the connection is torn down right after we read the
   host key, no encryption is ever negotiated) — but the key still has
   to be a *plausible* curve25519 point. All-zero is one of a small
   set of known low-order points, and RFC 8731 requires servers to
   check for and reject exactly these — a compliant modern sshd
   (GitHub's included) will silently drop the connection right here
   rather than reply. Random bytes avoid landing on any of them. */
static int send_kex_ecdh_init(int fd) {
    uint8_t ephemeral[32];
    khm_rand_bytes(ephemeral, sizeof(ephemeral));

    uint8_t payload[64];
    size_t  p = 0;
    payload[p++] = SSH_MSG_KEX_ECDH_INIT;
    write_u32(payload, &p, 32);
    memcpy(payload + p, ephemeral, 32); p += 32;

    uint8_t  pad_len = (uint8_t)(8 - ((p + 5) % 8));
    if (pad_len < 4) pad_len += 8;
    uint32_t pkt_len = 1 + (uint32_t)p + pad_len;

    uint8_t pkt[128];
    size_t  pp = 0;
    write_u32(pkt, &pp, pkt_len);
    pkt[pp++] = pad_len;
    memcpy(pkt + pp, payload, p); pp += p;
    memset(pkt + pp, 0, pad_len); pp += pad_len;

    return (send(fd, pkt, pp, 0) == (ssize_t)pp) ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* Parse KEX_ECDH_REPLY (msg type 31)                                  */
/*                                                                      */
/* Payload:                                                             */
/*   string  server host key blob                                       */
/*   string  ephemeral server public key                                */
/*   string  signature                                                  */
/* ------------------------------------------------------------------ */

static int parse_kex_ecdh_reply(const uint8_t *payload, size_t plen,
                                 khm_hostkey_t *out) {
    size_t pos = 1; /* skip msg type byte */

    /* host key blob */
    uint32_t blob_len;
    const uint8_t *blob = read_str(payload, plen, &pos, &blob_len);
    if (!blob) return -1;

    /* store raw keydata */
    if (blob_len > KHM_KEYDATA_MAX) return -1;
    memcpy(out->keydata, blob, blob_len);
    out->keydata_len = blob_len;

    /* base64 encode */
    b64_encode(blob, blob_len, out->keydata_b64);

    /* parse key type string from blob */
    size_t bpos = 0;
    uint32_t kt_len;
    const uint8_t *kt = read_str(blob, blob_len, &bpos, &kt_len);
    if (!kt || kt_len >= sizeof(out->keytype_str)) return -1;
    memcpy(out->keytype_str, kt, kt_len);
    out->keytype_str[kt_len] = '\0';

    /* SHA256 fingerprint */
    uint8_t digest[32];
    khm_sha256(blob, blob_len, digest);

    char b64fp[64];
    b64url_encode_nopad(digest, 32, b64fp);
    snprintf(out->fingerprint, sizeof(out->fingerprint), "SHA256:%s", b64fp);

    return 0;
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

int khm_fetch_hostkey(const char *host, int port, int timeout_ms,
                      khm_hostkey_t *out) {
    memset(out, 0, sizeof(*out));

    int fd = tcp_connect(host, port, timeout_ms);
    if (fd < 0) {
        KHM_DBG("tcp_connect failed (%d)\n", fd);
        return fd;
    }
    KHM_DBG("tcp connected to %s:%d\n", host, port);

    /* SSH version exchange */
    char banner[256];
    /* read server banner — may be preceded by informational lines */
    int got_banner = 0;
    for (int tries = 0; tries < 16; tries++) {
        if (recv_line(fd, banner, sizeof(banner)) < 0) {
            KHM_DBG("recv_line failed while waiting for banner (try %d)\n", tries);
            close(fd);
            return -1;
        }
        if (strncmp(banner, "SSH-", 4) == 0) { got_banner = 1; break; }
        KHM_DBG("skipping pre-banner line: %s", banner);
    }
    if (!got_banner) { KHM_DBG("never saw a line starting with SSH-\n"); close(fd); return -1; }
    KHM_DBG("server banner: %s", banner);

    /* send our banner */
    const char *our_banner = "SSH-2.0-khm_0.1\r\n";
    if (send(fd, our_banner, strlen(our_banner), 0) < 0) {
        KHM_DBG("send(our banner) failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    /* send KEXINIT */
    if (send_kexinit(fd) < 0) {
        KHM_DBG("send_kexinit failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    KHM_DBG("sent our KEXINIT\n");

    /* read packets until we get KEXINIT from server */
    int got_server_kexinit = 0;
    for (int i = 0; i < 8 && !got_server_kexinit; i++) {
        ssh_packet_t pkt;
        if (read_packet(fd, &pkt) < 0) {
            KHM_DBG("read_packet failed while waiting for server KEXINIT (try %d)\n", i);
            close(fd);
            return -1;
        }
        KHM_DBG("received packet, msg type %d, len %zu\n",
                pkt.len > 0 ? pkt.data[0] : -1, pkt.len);
        if (pkt.len > 0 && pkt.data[0] == SSH_MSG_DISCONNECT) {
            report_disconnect(pkt.data, pkt.len);
            free_packet(&pkt);
            close(fd);
            return -1;
        }
        if (pkt.len > 0 && pkt.data[0] == SSH_MSG_KEXINIT)
            got_server_kexinit = 1;
        free_packet(&pkt);
    }
    if (!got_server_kexinit) { KHM_DBG("never got server KEXINIT within retry budget\n"); close(fd); return -1; }
    KHM_DBG("got server KEXINIT\n");

    /* send ECDH init to trigger KEX_ECDH_REPLY */
    if (send_kex_ecdh_init(fd) < 0) {
        KHM_DBG("send_kex_ecdh_init failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    KHM_DBG("sent KEX_ECDH_INIT\n");

    /* read packets until KEX_ECDH_REPLY */
    int ret = -1;
    for (int i = 0; i < 8; i++) {
        ssh_packet_t pkt;
        if (read_packet(fd, &pkt) < 0) {
            KHM_DBG("read_packet failed while waiting for KEX_ECDH_REPLY (try %d)\n", i);
            break;
        }
        KHM_DBG("received packet, msg type %d, len %zu\n",
                pkt.len > 0 ? pkt.data[0] : -1, pkt.len);

        if (pkt.len > 0 && pkt.data[0] == SSH_MSG_DISCONNECT) {
            report_disconnect(pkt.data, pkt.len);
            free_packet(&pkt);
            break;
        }

        if (pkt.len > 0 && pkt.data[0] == SSH_MSG_KEX_ECDH_REPLY) {
            ret = parse_kex_ecdh_reply(pkt.data, pkt.len, out);
            KHM_DBG("parsed KEX_ECDH_REPLY, result %d\n", ret);
            free_packet(&pkt);
            break;
        }
        free_packet(&pkt);
    }

    close(fd);
    return ret;
}

/* ------------------------------------------------------------------ */
/* host:port parsing (shared by verify and fingerprint commands)       */
/* ------------------------------------------------------------------ */

void khm_parse_host_port(const char *arg, char *host, size_t hlen, int *port) {
    *port = 22;

    /* [host]:port */
    if (arg[0] == '[') {
        const char *close = strchr(arg, ']');
        if (close) {
            size_t n = (size_t)(close - arg - 1);
            if (n >= hlen) n = hlen - 1;
            memcpy(host, arg + 1, n);
            host[n] = '\0';
            if (*(close + 1) == ':') *port = atoi(close + 2);
            return;
        }
    }

    /* host:port — but only if there's exactly one colon
       (IPv6 addresses have multiple colons, skip them) */
    const char *colon = strchr(arg, ':');
    if (colon && strchr(colon + 1, ':') == NULL) {
        size_t n = (size_t)(colon - arg);
        if (n >= hlen) n = hlen - 1;
        memcpy(host, arg, n);
        host[n] = '\0';
        *port = atoi(colon + 1);
        return;
    }

    strncpy(host, arg, hlen - 1);
    host[hlen - 1] = '\0';
}

/* ------------------------------------------------------------------ */
/* Fingerprint for a known_hosts entry (no network involved)           */
/* ------------------------------------------------------------------ */

int khm_fingerprint_from_b64(const char *keydata_b64, char *out, size_t out_len) {
    if (!keydata_b64 || !*keydata_b64) return -1;

    uint8_t raw[KHM_KEYDATA_MAX];
    size_t raw_len = b64_decode(keydata_b64, raw, sizeof(raw));
    if (raw_len == (size_t)-1) return -1;

    uint8_t digest[32];
    khm_sha256(raw, raw_len, digest);

    char b64fp[64];
    b64url_encode_nopad(digest, 32, b64fp);
    return snprintf(out, out_len, "SHA256:%s", b64fp) < (int)out_len ? 0 : -1;
}
