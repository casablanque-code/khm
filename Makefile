CC      = gcc
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
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET) tests/*.o tests/test_parser tests/test_json tests/test_hostkey_packet

release: clean
	$(CC) $(CFLAGS) -static -o khm-linux-amd64 $(SRCS) -lpthread

# --- tests ---------------------------------------------------------
# Dependency-free: each test binary links directly against the
# relevant .c files (no separate lib step, no test framework beyond
# tests/test.h). Kept deliberately simple.

TEST_CFLAGS = -std=c11 -Wall -Wextra -D_POSIX_C_SOURCE=200809L -g

.PHONY: test
test: tests/test_parser tests/test_json tests/test_hostkey_packet
	@echo "=== parser ===";         ./tests/test_parser
	@echo "=== json ===";           ./tests/test_json
	@echo "=== hostkey packet ===";  ./tests/test_hostkey_packet

tests/test_parser: tests/test_parser.c parser.c
	$(CC) $(TEST_CFLAGS) -o $@ tests/test_parser.c parser.c

tests/test_json: tests/test_json.c json.c
	$(CC) $(TEST_CFLAGS) -o $@ tests/test_json.c json.c

tests/test_hostkey_packet: tests/test_hostkey_packet.c hostkey.c sha256.c
	$(CC) $(TEST_CFLAGS) -o $@ tests/test_hostkey_packet.c hostkey.c sha256.c -lpthread
