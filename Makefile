CC      = gcc
KHM_VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo unknown)
VERSION_DEF = -DKHM_VERSION=\"$(KHM_VERSION)\"
CFLAGS  = -std=c11 -Wall -Wextra -Wpedantic -O2 -D_POSIX_C_SOURCE=200809L
TARGET  = khm

SRCS    = main.c \
          parser.c \
          sha256.c \
          hostkey.c \
          json.c \
          commands/list.c \
          commands/verify.c \
          commands/diff.c \
          commands/scan.c \
          commands/fingerprint.c \
          commands/export.c \
          commands/normalize.c \
          commands/doctor.c

OBJS    = $(SRCS:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ -lpthread

%.o: %.c
	$(CC) $(CFLAGS) $(VERSION_DEF) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET) tests/*.o tests/test_parser tests/test_json tests/test_hostkey_packet tests/test_hostkey_b64 tests/fuzz/fuzz_kex_reply tests/fuzz/fuzz_parser

release: clean
	$(CC) $(CFLAGS) $(VERSION_DEF) -static -o khm-linux-amd64 $(SRCS) -lpthread

# --- tests ---------------------------------------------------------
# Dependency-free: each test binary links directly against the
# relevant .c files (no separate lib step, no test framework beyond
# tests/test.h). Kept deliberately simple.

TEST_CFLAGS = -std=c11 -Wall -Wextra -D_POSIX_C_SOURCE=200809L -g

.PHONY: test
test: tests/test_parser tests/test_json tests/test_hostkey_packet tests/test_hostkey_b64 $(TARGET)
	@echo "=== parser ===";         ./tests/test_parser
	@echo "=== json ===";           ./tests/test_json
	@echo "=== hostkey packet ===";  ./tests/test_hostkey_packet
	@echo "=== hostkey b64 ===";     ./tests/test_hostkey_b64
	@echo "=== cli smoke ===";      ./tests/cli_smoke.sh ./$(TARGET)

tests/test_parser: tests/test_parser.c parser.c
	$(CC) $(TEST_CFLAGS) -o $@ tests/test_parser.c parser.c

tests/test_json: tests/test_json.c json.c
	$(CC) $(TEST_CFLAGS) -o $@ tests/test_json.c json.c

tests/test_hostkey_packet: tests/test_hostkey_packet.c hostkey.c sha256.c
	$(CC) $(TEST_CFLAGS) -o $@ tests/test_hostkey_packet.c hostkey.c sha256.c -lpthread

tests/test_hostkey_b64: tests/test_hostkey_b64.c
	$(CC) $(TEST_CFLAGS) -o $@ tests/test_hostkey_b64.c

# --- fuzzing ---------------------------------------------------------
# Whitebox libFuzzer harnesses over the two spots that have actually
# had bugs: the SSH wire-format parsers (hostkey.c, attacker-controlled
# network input) and the known_hosts line parser (parser.c, local but
# often synced from shared/dotfile sources). Needs clang; not part of
# `make test` since it requires a different toolchain and runs
# indefinitely by design. See tests/fuzz/README.md.

FUZZ_CC = clang

.PHONY: fuzz-build fuzz-smoke
fuzz-build: tests/fuzz/fuzz_kex_reply tests/fuzz/fuzz_parser

tests/fuzz/fuzz_kex_reply: tests/fuzz/fuzz_kex_reply.c hostkey.c sha256.c hostkey.h
	$(FUZZ_CC) -g -O1 -fsanitize=fuzzer,address -I. tests/fuzz/fuzz_kex_reply.c sha256.c -o $@

tests/fuzz/fuzz_parser: tests/fuzz/fuzz_parser.c parser.c parser.h
	$(FUZZ_CC) -g -O1 -fsanitize=fuzzer,address -I. tests/fuzz/fuzz_parser.c -o $@

# Bounded regression run for CI: replays the checked-in crash corpus
# (which alone reproduces every fuzz-found bug fixed so far) and then
# fuzzes briefly for anything new.
# Bounded regression run for CI: replays the checked-in crash corpus
# (which alone reproduces every fuzz-found bug fixed so far) and then
# fuzzes briefly for anything new. Runs against a scratch copy of the
# corpus — libFuzzer writes newly-interesting inputs back into
# whatever corpus dir you give it, and the checked-in one should only
# grow when a developer deliberately adds a curated regression case.
fuzz-smoke: fuzz-build
	rm -rf /tmp/khm-fuzz-scratch && cp -r tests/fuzz/corpus_kex_reply /tmp/khm-fuzz-scratch
	./tests/fuzz/fuzz_kex_reply -max_total_time=60 /tmp/khm-fuzz-scratch
	mkdir -p /tmp/khm-fuzz-scratch-parser
	./tests/fuzz/fuzz_parser -max_total_time=60 /tmp/khm-fuzz-scratch-parser
