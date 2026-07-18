#include "test.h"
#include "../parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* Writes `content` to a temp file and parses it. Caller must call
 * khm_db_free(db) and the returned path is caller-owned (unlink it). */
static void parse_string(const char *content, khm_db_t *db) {
    char path[] = "/tmp/khm_test_XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    FILE *f = fdopen(fd, "w");
    fputs(content, f);
    fclose(f);

    int r = khm_parse_file(path, db);
    CHECK_EQ_INT(r, 0);
    unlink(path);
}

static void test_simple_entry(void) {
    khm_db_t db = {0};
    parse_string(
        "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n",
        &db);

    CHECK_EQ_INT(db.count, 1);
    CHECK_EQ_INT(db.error_count, 0);
    if (db.count == 1) {
        CHECK_EQ_INT(db.entries[0].hostname_count, 1);
        CHECK_EQ_STR(db.entries[0].hostnames[0], "github.com");
        CHECK_EQ_INT(db.entries[0].keytype, KHM_KEY_ED25519);
        CHECK_EQ_INT(db.entries[0].hashed, 0);
    }
    khm_db_free(&db);
}

static void test_comments_and_blank_lines_skipped(void) {
    khm_db_t db = {0};
    parse_string(
        "# a comment\n"
        "\n"
        "   \n"
        "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n",
        &db);

    CHECK_EQ_INT(db.count, 1);
    CHECK_EQ_INT(db.error_count, 0);
    khm_db_free(&db);
}

static void test_multiple_hostnames_comma_separated(void) {
    khm_db_t db = {0};
    parse_string(
        "host1.example.com,host2.example.com,10.0.0.1 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB\n",
        &db);

    CHECK_EQ_INT(db.count, 1);
    if (db.count == 1) {
        CHECK_EQ_INT(db.entries[0].hostname_count, 3);
        CHECK_EQ_STR(db.entries[0].hostnames[0], "host1.example.com");
        CHECK_EQ_STR(db.entries[0].hostnames[1], "host2.example.com");
        CHECK_EQ_STR(db.entries[0].hostnames[2], "10.0.0.1");
    }
    khm_db_free(&db);
}

static void test_bracketed_host_with_port(void) {
    khm_db_t db = {0};
    parse_string(
        "[myserver.example.com]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n",
        &db);

    CHECK_EQ_INT(db.count, 1);
    if (db.count == 1) {
        CHECK_EQ_INT(db.entries[0].hostname_count, 1);
        CHECK_EQ_STR(db.entries[0].hostnames[0], "myserver.example.com");
        CHECK_EQ_INT(db.entries[0].port, 2222);
    }
    khm_db_free(&db);
}

static void test_hashed_entry(void) {
    khm_db_t db = {0};
    parse_string(
        "|1|dGVzdHNhbHQ=|dGVzdGhhc2g= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n",
        &db);

    CHECK_EQ_INT(db.count, 1);
    if (db.count == 1) {
        CHECK_EQ_INT(db.entries[0].hashed, 1);
    }
    khm_db_free(&db);
}

static void test_cert_authority_marker_skipped(void) {
    khm_db_t db = {0};
    parse_string(
        "@cert-authority *.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n"
        "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n",
        &db);

    /* @-marker lines are explicitly not treated as parse errors, just
     * silently skipped for now — pin that behavior down. */
    CHECK_EQ_INT(db.count, 1);
    CHECK_EQ_INT(db.error_count, 0);
    khm_db_free(&db);
}

static void test_malformed_line_recorded_as_error(void) {
    khm_db_t db = {0};
    parse_string(
        "this-line-has-only-one-field\n"
        "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n",
        &db);

    CHECK_EQ_INT(db.count, 1);
    CHECK_EQ_INT(db.error_count, 1);
    if (db.error_count == 1) {
        CHECK_EQ_INT(db.errors[0].line_number, 1);
    }
    khm_db_free(&db);
}

static void test_unknown_keytype_still_parses(void) {
    khm_db_t db = {0};
    parse_string(
        "github.com ssh-totally-made-up AAAAB3NzaC1yc2EAAAADAQABAAAB\n",
        &db);

    /* Unknown algorithm strings should not be treated as a parse
     * error — just surfaced as KHM_KEY_UNKNOWN so callers (e.g.
     * doctor's obsolete-algorithm check) can decide what to do. */
    CHECK_EQ_INT(db.count, 1);
    CHECK_EQ_INT(db.error_count, 0);
    if (db.count == 1) {
        CHECK_EQ_INT(db.entries[0].keytype, KHM_KEY_UNKNOWN);
    }
    khm_db_free(&db);
}

static void test_trailing_comment_after_key_ignored(void) {
    khm_db_t db = {0};
    parse_string(
        "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@laptop\n",
        &db);

    CHECK_EQ_INT(db.count, 1);
    if (db.count == 1) {
        CHECK_EQ_STR(db.entries[0].keydata_b64,
                     "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl");
    }
    khm_db_free(&db);
}

static void test_leading_trailing_whitespace_trimmed(void) {
    khm_db_t db = {0};
    parse_string(
        "   github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl   \n",
        &db);

    CHECK_EQ_INT(db.count, 1);
    CHECK_EQ_INT(db.error_count, 0);
    khm_db_free(&db);
}

static void test_nonexistent_file_returns_error(void) {
    khm_db_t db = {0};
    int r = khm_parse_file("/nonexistent/path/that/should/not/exist", &db);
    CHECK_EQ_INT(r, -1);
}

int main(void) {
    RUN(test_simple_entry);
    RUN(test_comments_and_blank_lines_skipped);
    RUN(test_multiple_hostnames_comma_separated);
    RUN(test_bracketed_host_with_port);
    RUN(test_hashed_entry);
    RUN(test_cert_authority_marker_skipped);
    RUN(test_malformed_line_recorded_as_error);
    RUN(test_unknown_keytype_still_parses);
    RUN(test_trailing_comment_after_key_ignored);
    RUN(test_leading_trailing_whitespace_trimmed);
    RUN(test_nonexistent_file_returns_error);
    return TEST_REPORT();
}
