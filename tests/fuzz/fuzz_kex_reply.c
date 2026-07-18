/*
 * libFuzzer harness for the SSH binary-packet parsing path in
 * hostkey.c: khm_ssh_packet_lengths() -> {parse_kex_ecdh_reply,
 * report_disconnect}. This is the only place khm parses bytes that
 * come directly from a remote, potentially malicious/compromised SSH
 * server, so it is the highest-value fuzz target in the codebase —
 * both bugs found and fixed so far (the length underflow in
 * read_packet, and the base64 buffer overflow in parse_kex_ecdh_reply)
 * lived exactly here.
 *
 * Rather than duplicate the length-derivation logic, this harness
 * mirrors what read_packet() actually does: treat the first 5 fuzzer
 * bytes as the wire header (4-byte pkt_len + 1-byte pad_len), validate
 * with the real (fixed) khm_ssh_packet_lengths(), and if that accepts
 * the header, feed the resulting payload slice into the same static
 * parsers production code calls. #include-ing hostkey.c directly (a
 * standard whitebox-fuzzing technique in C) gives access to those
 * static functions without changing their linkage just for testing.
 *
 * Build (needs clang):
 *   clang -g -O1 -fsanitize=fuzzer,address -I.. \
 *       tests/fuzz/fuzz_kex_reply.c ../sha256.c -o fuzz_kex_reply
 *
 * Run:
 *   ./fuzz_kex_reply                  # fuzz indefinitely
 *   ./fuzz_kex_reply -max_total_time=60
 *   ./fuzz_kex_reply crash-<hash>     # reproduce a saved crash
 */

#include "../../hostkey.c"

#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 5) return 0;

    uint32_t pkt_len = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
                       ((uint32_t)data[2] <<  8) |  (uint32_t)data[3];
    uint8_t  pad_len  = data[4];

    uint32_t total, payload_len;
    if (khm_ssh_packet_lengths(pkt_len, pad_len, &total, &payload_len) != 0)
        return 0; /* rejected header, same as read_packet() would do */

    const uint8_t *rest = data + 5;
    size_t rest_len = size - 5;
    if (total > rest_len) return 0; /* not enough fuzzer bytes to fill this packet */

    const uint8_t *payload = rest; /* first payload_len bytes of `rest` */
    if (payload_len == 0 || payload_len > rest_len) return 0;

    switch (payload[0]) {
        case SSH_MSG_KEX_ECDH_REPLY: {
            khm_hostkey_t hk;
            memset(&hk, 0, sizeof(hk));
            parse_kex_ecdh_reply(payload, payload_len, &hk);
            break;
        }
        case SSH_MSG_DISCONNECT:
            report_disconnect(payload, payload_len);
            break;
        default:
            break;
    }
    return 0;
}
