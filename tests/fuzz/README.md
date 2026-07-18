# Fuzzing

Whitebox libFuzzer harnesses over the two spots in khm that parse
input it didn't generate itself:

- **`fuzz_kex_reply.c`** — the SSH binary-packet layer in `hostkey.c`
  (`khm_ssh_packet_lengths` → `parse_kex_ecdh_reply` /
  `report_disconnect`). This is attacker-reachable: it's parsing bytes
  sent by whatever's on the other end of `khm verify`/`khm
  fingerprint`. Both bugs fixed so far (the packet-length integer
  underflow, and the base64 buffer overflow in `parse_kex_ecdh_reply`)
  lived exactly here — `corpus_kex_reply/bigblob_seed` is the crafted
  input that reproduces the second one in under a second against
  unpatched code.
- **`fuzz_parser.c`** — `parse_line()` in `parser.c`, the known_hosts
  line parser. Lower severity (local file, not a stranger on the
  network), but known_hosts files do get synced from dotfile repos and
  config management, so a malformed line isn't purely theoretical
  either.

Both `#include` the target `.c` file directly to reach `static`
functions without changing their linkage just for testing — a
standard whitebox-fuzzing pattern in C, and why these live outside the
normal `tests/*.c` unit tests (which go through the public API).

## Requirements

Needs `clang` (for `-fsanitize=fuzzer,address`); `gcc` doesn't ship
libFuzzer. Not part of `make test` for that reason.

## Running

```sh
make fuzz-build          # compiles both harnesses

# fuzz indefinitely (writes new interesting inputs into a scratch dir
# you name — don't point it at tests/fuzz/corpus_kex_reply directly,
# or every run pollutes the checked-in seed corpus)
mkdir -p /tmp/scratch && cp tests/fuzz/corpus_kex_reply/* /tmp/scratch/
./tests/fuzz/fuzz_kex_reply /tmp/scratch
./tests/fuzz/fuzz_parser /tmp/scratch2

# fuzz for a bounded time against a scratch corpus (what CI does)
make fuzz-smoke

# reproduce a specific crash or seed (read-only, safe)
./tests/fuzz/fuzz_kex_reply tests/fuzz/corpus_kex_reply/bigblob_seed
```

A crash produces a `crash-<hash>` file in the working directory —
rerun the binary on that file to get a full ASan report, and consider
adding it to `corpus_kex_reply/` (or a new `corpus_parser/`) once
fixed, so it's checked forever after.

## Adding a seed corpus

Seed inputs go in a `corpus_<target>/` directory next to the harness
and are passed as an argument, e.g. `./fuzz_kex_reply corpus_kex_reply/`.
Structured binary formats like the SSH packet layer fuzz far more
effectively with even one or two valid-shaped seeds than from a cold
start — blind mutation rarely stumbles onto the right header fields,
string-length prefixes, and message type byte all at once.
