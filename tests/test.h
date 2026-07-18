#ifndef KHM_TEST_H
#define KHM_TEST_H

/*
 * Minimal, dependency-free test framework. In the spirit of the rest
 * of khm: no libcheck, no unity, no cmocka — just stdio and macros.
 *
 * Usage:
 *
 *   #include "test.h"
 *
 *   static void test_something(void) {
 *       CHECK(1 + 1 == 2);
 *       CHECK_EQ_INT(foo(), 42);
 *       CHECK_EQ_STR(bar(), "expected");
 *   }
 *
 *   int main(void) {
 *       RUN(test_something);
 *       return TEST_REPORT();
 *   }
 */

#include <stdio.h>
#include <string.h>

static int khm_test_pass = 0;
static int khm_test_fail = 0;
static const char *khm_test_current = "";

#define RUN(fn) do { \
        khm_test_current = #fn; \
        fn(); \
    } while (0)

#define CHECK(cond) do { \
        if (cond) { \
            khm_test_pass++; \
        } else { \
            khm_test_fail++; \
            fprintf(stderr, "  FAIL  %s:%d  %s  -- %s\n", \
                    __FILE__, __LINE__, khm_test_current, #cond); \
        } \
    } while (0)

#define CHECK_EQ_INT(a, b) do { \
        long _a = (long)(a), _b = (long)(b); \
        if (_a == _b) { \
            khm_test_pass++; \
        } else { \
            khm_test_fail++; \
            fprintf(stderr, "  FAIL  %s:%d  %s  -- %s == %s  (%ld != %ld)\n", \
                    __FILE__, __LINE__, khm_test_current, #a, #b, _a, _b); \
        } \
    } while (0)

#define CHECK_EQ_STR(a, b) do { \
        const char *_a = (a), *_b = (b); \
        if (_a && _b && strcmp(_a, _b) == 0) { \
            khm_test_pass++; \
        } else { \
            khm_test_fail++; \
            fprintf(stderr, "  FAIL  %s:%d  %s  -- %s == %s  (\"%s\" != \"%s\")\n", \
                    __FILE__, __LINE__, khm_test_current, #a, #b, \
                    _a ? _a : "(null)", _b ? _b : "(null)"); \
        } \
    } while (0)

#define TEST_REPORT() ( \
    fprintf(stderr, "\n%d passed, %d failed\n", khm_test_pass, khm_test_fail), \
    khm_test_fail > 0 ? 1 : 0 \
)

#endif /* KHM_TEST_H */
