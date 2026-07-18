#include "test.h"
#include "../hostkey.h"

#include <stdint.h>

/*
 * Regression tests for khm_ssh_packet_lengths(). Before the fix, a
 * server could send pkt_len=2, pad_len=255 and the length arithmetic
 * (`pkt_len - 1 - pad_len` in uint32_t) would underflow to a huge
 * value, while the actual allocated buffer was 1 byte — a heap
 * out-of-bounds read waiting to happen the moment the payload was
 * parsed. These tests pin the fix down so it can't quietly regress.
 */

static void test_rejects_pad_len_exceeding_packet(void) {
    uint32_t total, payload_len;

    /* The exact malicious case: pkt_len=2, pad_len=255. */
    int r = khm_ssh_packet_lengths(2, 255, &total, &payload_len);
    CHECK_EQ_INT(r, -1);
}

static void test_rejects_pad_len_equal_to_remaining_space(void) {
    uint32_t total, payload_len;

    /* pkt_len=5 leaves 4 bytes after the padding_length byte;
     * pad_len=4 would consume all of it, leaving zero payload bytes
     * for the mandatory msg-type byte. Must be rejected, not silently
     * accepted with payload_len == 0. */
    int r = khm_ssh_packet_lengths(5, 4, &total, &payload_len);
    CHECK_EQ_INT(r, -1);
}

static void test_accepts_well_formed_packet(void) {
    uint32_t total, payload_len;

    /* pkt_len=20, pad_len=8: 20 - 1 - 8 = 11 bytes of payload. */
    int r = khm_ssh_packet_lengths(20, 8, &total, &payload_len);
    CHECK_EQ_INT(r, 0);
    CHECK_EQ_INT(total, 19);
    CHECK_EQ_INT(payload_len, 11);
}

static void test_rejects_pkt_len_below_minimum(void) {
    uint32_t total, payload_len;

    /* pkt_len must be >= 2 (padding_length byte + at least 1 payload
     * byte for msg type). */
    int r = khm_ssh_packet_lengths(1, 0, &total, &payload_len);
    CHECK_EQ_INT(r, -1);

    r = khm_ssh_packet_lengths(0, 0, &total, &payload_len);
    CHECK_EQ_INT(r, -1);
}

static void test_rejects_pkt_len_above_max(void) {
    uint32_t total, payload_len;

    int r = khm_ssh_packet_lengths(256 * 1024 + 1, 0, &total, &payload_len);
    CHECK_EQ_INT(r, -1);
}

static void test_accepts_minimum_valid_packet(void) {
    uint32_t total, payload_len;

    /* pkt_len=2, pad_len=0: 1 byte of payload, no padding. Smallest
     * legal packet. */
    int r = khm_ssh_packet_lengths(2, 0, &total, &payload_len);
    CHECK_EQ_INT(r, 0);
    CHECK_EQ_INT(total, 1);
    CHECK_EQ_INT(payload_len, 1);
}

static void test_rejects_zero_payload(void) {
    uint32_t total, payload_len;

    /* pkt_len=2, pad_len=1 leaves exactly 0 payload bytes — no room
     * for even the mandatory msg-type byte. Must be rejected. */
    int r = khm_ssh_packet_lengths(2, 1, &total, &payload_len);
    CHECK_EQ_INT(r, -1);
}

int main(void) {
    RUN(test_rejects_pad_len_exceeding_packet);
    RUN(test_rejects_pad_len_equal_to_remaining_space);
    RUN(test_accepts_well_formed_packet);
    RUN(test_rejects_pkt_len_below_minimum);
    RUN(test_rejects_pkt_len_above_max);
    RUN(test_accepts_minimum_valid_packet);
    RUN(test_rejects_zero_payload);
    return TEST_REPORT();
}
