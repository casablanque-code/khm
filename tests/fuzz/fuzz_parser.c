/*
 * libFuzzer harness for parse_line() in parser.c — the known_hosts
 * line parser. Lower severity than the SSH wire-format parsers (the
 * input here is a local file, not attacker-controlled network data
 * from a stranger), but known_hosts files do get synced from dotfile
 * repos, config-management tooling, and shared team infra, so a
 * corrupted or crafted line landing there isn't a purely theoretical
 * input source either. Included mainly to backstop future changes to
 * the hand-rolled field splitting in parse_hostnames()/parse_line().
 *
 * Build (needs clang):
 *   clang -g -O1 -fsanitize=fuzzer,address -I.. \
 *       tests/fuzz/fuzz_parser.c -o fuzz_parser
 */

#include "../../parser.c"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* parse_line() takes a mutable, NUL-terminated C string and wants
     * to run strpbrk/strncpy on it — reject embedded NULs (not a
     * meaningful known_hosts line anyway) and give it its own
     * writable, NUL-terminated copy. */
    if (size == 0 || memchr(data, '\0', size)) return 0;

    char *line = malloc(size + 1);
    if (!line) return 0;
    memcpy(line, data, size);
    line[size] = '\0';

    khm_entry_t e;
    parse_line(line, &e);

    free(line);
    return 0;
}
