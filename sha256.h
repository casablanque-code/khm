#ifndef KHM_SHA256_H
#define KHM_SHA256_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buf[64];
} khm_sha256_ctx;

void khm_sha256_init(khm_sha256_ctx *ctx);
void khm_sha256_update(khm_sha256_ctx *ctx, const uint8_t *data, size_t len);
void khm_sha256_final(khm_sha256_ctx *ctx, uint8_t digest[32]);

/* One-shot */
void khm_sha256(const uint8_t *data, size_t len, uint8_t digest[32]);

#endif
