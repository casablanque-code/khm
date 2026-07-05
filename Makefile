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
          commands/fingerprint.c

OBJS    = $(SRCS:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ -lpthread

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)

release: clean
	$(CC) $(CFLAGS) -static -o khm-linux-amd64 $(SRCS) -lpthread
