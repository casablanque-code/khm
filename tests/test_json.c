#define _POSIX_C_SOURCE 200809L
#include "test.h"
#include "../json.h"

#include <stdio.h>
#include <stdlib.h>

/* Runs khm_json_escape(s) and returns a malloc'd string with the
 * result. Caller must free(). */
static char *escape(const char *s) {
    char *buf = NULL;
    size_t len = 0;
    FILE *f = open_memstream(&buf, &len);
    khm_json_escape(f, s);
    fclose(f);
    return buf;
}

static void test_plain_string_unchanged(void) {
    char *r = escape("github.com");
    CHECK_EQ_STR(r, "github.com");
    free(r);
}

static void test_quote_escaped(void) {
    char *r = escape("ho\"st");
    CHECK_EQ_STR(r, "ho\\\"st");
    free(r);
}

static void test_backslash_escaped(void) {
    char *r = escape("C:\\path");
    CHECK_EQ_STR(r, "C:\\\\path");
    free(r);
}

static void test_newline_and_tab_escaped(void) {
    char *r = escape("line1\nline2\ttabbed");
    CHECK_EQ_STR(r, "line1\\nline2\\ttabbed");
    free(r);
}

static void test_control_char_escaped_as_unicode(void) {
    /* \x01 (SOH) is below 0x20 and has no dedicated short escape, so
     * it must come out as \u0001, not raw. This is the case that
     * actually matters for security: a hostname containing raw
     * control bytes must never reach the output unescaped, or a
     * crafted known_hosts entry could break out of the JSON string
     * context. */
    char in[2] = { 0x01, 0 };
    char *r = escape(in);
    CHECK_EQ_STR(r, "\\u0001");
    free(r);
}

static void test_null_input_produces_nothing(void) {
    char *r = escape(NULL);
    CHECK_EQ_STR(r, "");
    free(r);
}

static void test_write_entry_produces_valid_looking_json(void) {
    khm_entry_t e = {0};
    e.hostname_count = 1;
    snprintf(e.hostnames[0], KHM_MAX_HOSTNAME, "%s", "github.com");
    snprintf(e.keytype_str, KHM_MAX_KEYTYPE, "%s", "ssh-ed25519");
    e.port = 22;
    e.hashed = 0;

    char *buf = NULL;
    size_t len = 0;
    FILE *f = open_memstream(&buf, &len);
    khm_json_write_entry(f, &e, "SHA256:abc123");
    fclose(f);

    /* Not a full JSON parser here — just check the pieces we
     * explicitly control are present in expected form. */
    CHECK(strstr(buf, "\"hostnames\":[\"github.com\"]") != NULL);
    CHECK(strstr(buf, "\"hashed\":false") != NULL);
    CHECK(strstr(buf, "\"port\":22") != NULL);
    CHECK(strstr(buf, "\"fingerprint\":\"SHA256:abc123\"") != NULL);
    free(buf);
}

static void test_write_entry_hashed_hides_hostnames(void) {
    khm_entry_t e = {0};
    e.hostname_count = 1;
    snprintf(e.hostnames[0], KHM_MAX_HOSTNAME, "%s", "|1|salt|hash");
    snprintf(e.keytype_str, KHM_MAX_KEYTYPE, "%s", "ssh-ed25519");
    e.hashed = 1;

    char *buf = NULL;
    size_t len = 0;
    FILE *f = open_memstream(&buf, &len);
    khm_json_write_entry(f, &e, NULL);
    fclose(f);

    /* Mirrors list.c's "<hashed>" display: never emit a hostname we
     * can't actually recover from a hashed entry. */
    CHECK(strstr(buf, "\"hostnames\":[]") != NULL);
    CHECK(strstr(buf, "\"hashed\":true") != NULL);
    free(buf);
}

int main(void) {
    RUN(test_plain_string_unchanged);
    RUN(test_quote_escaped);
    RUN(test_backslash_escaped);
    RUN(test_newline_and_tab_escaped);
    RUN(test_control_char_escaped_as_unicode);
    RUN(test_null_input_produces_nothing);
    RUN(test_write_entry_produces_valid_looking_json);
    RUN(test_write_entry_hashed_hides_hostnames);
    return TEST_REPORT();
}
