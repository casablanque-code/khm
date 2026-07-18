#include "test.h"
#include "../hostkey.h"

#include <string.h>

/*
 * Regression test for the keydata_b64 buffer overflow: base64 expands
 * 3 raw bytes into 4 characters, so a buffer sized as KHM_KEYDATA_MAX
 * (meant for the *raw* key) overflows by ~700 bytes once blob_len
 * approaches KHM_KEYDATA_MAX. A malicious SSH server could reach this
 * by sending a host key blob up to the KHM_KEYDATA_MAX cap.
 *
 * This doesn't call the static parse_kex_ecdh_reply() directly (that
 * needs a full struct + wire-format blob); instead it pins down the
 * two invariants that make the fix correct:
 *   1. KHM_KEYDATA_B64_MAX actually fits base64(KHM_KEYDATA_MAX bytes).
 *   2. keydata_b64 is sized as KHM_KEYDATA_B64_MAX, not KHM_KEYDATA_MAX.
 * Sizeof checks at compile-observable runtime are the simplest way to
 * pin a struct layout down without duplicating the encoder here.
 */

static void test_b64_max_fits_worst_case_encoding(void) {
    /* Worst case: no padding needed, so all KHM_KEYDATA_MAX bytes
     * encode to ceil(KHM_KEYDATA_MAX/3)*4 chars + NUL. */
    size_t needed = ((KHM_KEYDATA_MAX + 2) / 3) * 4 + 1;
    CHECK(needed == KHM_KEYDATA_B64_MAX);
}

static void test_keydata_b64_field_uses_b64_max_not_raw_max(void) {
    khm_hostkey_t hk;
    CHECK_EQ_INT(sizeof(hk.keydata_b64), KHM_KEYDATA_B64_MAX);
    /* The bug this guards against: this field used to be sized
     * KHM_KEYDATA_MAX (too small by ~700 bytes for full-size blobs). */
    CHECK(sizeof(hk.keydata_b64) > KHM_KEYDATA_MAX);
}

int main(void) {
    RUN(test_b64_max_fits_worst_case_encoding);
    RUN(test_keydata_b64_field_uses_b64_max_not_raw_max);
    return TEST_REPORT();
}
