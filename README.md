# khm — known hosts manager

[![CI](https://github.com/casablanque-code/khm/actions/workflows/ci.yml/badge.svg)](https://github.com/casablanque-code/khm/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/casablanque-code/khm)](https://github.com/casablanque-code/khm/releases/latest)
[![Pure C](https://img.shields.io/badge/pure-C11-blue)](#implementation)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)](#how-it-works)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)](#install)

A CLI tool for managing SSH `known_hosts` files. No libssh, no OpenSSL, no nothing — raw BSD sockets, a hand-rolled SHA-256, and a partial SSH handshake to fetch host keys directly.

## Why

`known_hosts` is your database of trusted server identities, yet OpenSSH gives you almost no tooling to inspect, compare, audit, or maintain it. You either trust TOFU blindly, grep through a plain-text file by hand, or disable `StrictHostKeyChecking` in scripts and give up on verification entirely. `khm` treats `known_hosts` as what it actually is — a security asset — not a cache you can delete and rebuild without thinking.

| Task | OpenSSH | khm |
|---|---|---|
| List trusted hosts | `grep` | ✅ |
| Verify one host | `ssh` + compare manually | ✅ |
| Verify all hosts | ❌ | ✅ |
| Compare two known_hosts | ❌ | ✅ |
| Export to CSV/Markdown/HTML | ❌ | ✅ |
| Health check (dupes, weak algos, malformed lines) | ❌ | ✅ |

### Real-world use cases

- **CI/CD gate** — `khm verify --all` before a deploy step, fail the pipeline on drift instead of silently trusting whatever's on the runner.
- **Workstation audit** — sweep a fleet of dev laptops with `khm doctor` to catch stale RSA/DSS entries and duplicate junk that's accumulated over years.
- **Post key-rotation check** — after rotating a server's host key, confirm every client's `known_hosts` picked it up cleanly instead of silently falling back to unchecked TOFU.
- **Migration diff** — `khm diff old_known_hosts new_known_hosts` when moving to a new bastion or jump host, to see exactly what changed.
- **Scheduled drift detection** — `khm doctor && khm verify --all` on a cron, alerting the moment a host key changes unexpectedly.
- **Onboarding** — `khm export --format md` to drop a readable table of trusted hosts straight into internal docs.

## Install

```bash
curl -Lo /usr/local/bin/khm \
  https://github.com/casablanque-code/khm/releases/latest/download/khm-linux-amd64
chmod +x /usr/local/bin/khm
```

Or build from source (requires only `gcc` and `make`):

```bash
git clone https://github.com/casablanque-code/khm
cd khm && make
sudo cp khm /usr/local/bin/
```

## Usage

Every command accepts a global `--json` flag, in any position on the command line (`khm --json verify host` and `khm verify host --json` are equivalent). It emits machine-readable JSON instead of formatted text — useful for CI, Ansible, or anything scripted.

### `list` — inspect your known_hosts

```
khm list [--file <path>] [--no-color]
```

```
HOST                                      KEY TYPE   KEY (tail)
----------------------------------------  ---------  --------
github.com                                ED25519    ...h2l9GKJl
gitlab.com                                ECDSA-256  ...+Tpockg=
myserver.example.com:2222                 ED25519    ...XwKpZpHs
<hashed>                                  ED25519    ...XwKpZpHs

4 entries  •  /root/.ssh/known_hosts
```

Key types are color-coded: ED25519 green, ECDSA blue, RSA yellow, hashed entries dimmed.

---

### `verify` — check a host against known_hosts

```
khm verify <host[:port]> [--file <path>] [--no-color]
```

```
  host:  github.com
  file:  /root/.ssh/known_hosts
  fetch: ssh-ed25519  SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU
  match: ✔ OK  (record #3)
```

Returns exit code `0` on match, `1` on key change, `3` if not found.

Useful in provisioning scripts:

```bash
khm verify myserver.example.com || echo "WARNING: host key mismatch"
```

**`verify --all`** checks every non-hashed host already in the file — a regular drift check, not a one-off:

```
khm verify --all [--file <path>] [--no-color]
```

```
  OK           github.com
  OK           gitlab.com
  CHANGED      oldserver.example.com
  UNREACHABLE  decommissioned.example.com

4 hosts  2 OK  1 changed  1 unreachable
```

Exit code `0` only if nothing changed and everything was reachable — plug it into a cron job or CI step:

```bash
khm verify --all || alert "known_hosts drift detected"
```

---

### `fingerprint` — check a host's key before you trust it

```
khm fingerprint <host[:port]>
```

```
  host:  github.com
  type:  ssh-ed25519
  fp:    SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU
```

Unlike `verify`, this never touches `known_hosts` — it's the "what would TOFU show me right now" check, useful before you've ever connected, or when comparing against a fingerprint published out-of-band (e.g. GitHub's [SSH key fingerprints page](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints)).

---

### `diff` — compare two known_hosts files

```
khm diff <file1> <file2> [--no-color]
```

```
--- /root/.ssh/known_hosts
+++ /backup/known_hosts

~ CHANGED  gitlab.com                        ecdsa-sha2-nistp256
  - ...++Tpockg=
  + ...++NEWKEY=
- REMOVED  oldserver.example.com             ssh-rsa
+ ADDED    newserver.example.com             ssh-ed25519

3 difference(s)
```

Returns exit code `0` if identical, `1` if differences found.

---

### `scan` — scan a network or host list

```
khm scan <cidr|file|host> [--file <known_hosts>] [--port N] [--timeout N] [--no-color]
```

```
khm scan 10.0.0.0/24
khm scan hosts.txt --file ~/.ssh/known_hosts
khm scan myserver.example.com
```

```
scan  10.0.0.0/24  port 22  254 hosts

  ✔ OK       10.0.0.1     ssh-ed25519   SHA256:...
  ✔ OK       10.0.0.5     ssh-ed25519   SHA256:...
  ✘ CHANGED  10.0.0.12    ssh-ed25519   SHA256:...
  ? NEW      10.0.0.99    ssh-rsa       SHA256:...

summary  3 ok  1 changed  1 new  249 no-ssh
```

Hosts are scanned in parallel (up to 64 threads). Returns exit code `1` if any key has changed.

---

### `export` — get known_hosts data out, for audits

```
khm export [--file <path>] [--format csv|md|html|json]
```

```bash
khm export --format csv > known_hosts.csv
khm export --format md   # paste straight into a wiki page or PR description
```

Defaults to CSV. Hashed entries are included with a `<hashed>` placeholder and no fingerprint (can't be computed without the real hostname). Multiple hostnames sharing a line are joined with `;` so the comma stays the CSV delimiter.

---

### `normalize` — dedupe, merge, sort a known_hosts file

```
khm normalize [--file <path>] [--write]
```

```bash
khm normalize --file ~/.ssh/known_hosts          # preview to stdout, file untouched
khm normalize --file ~/.ssh/known_hosts --write  # apply, atomically
```

```
zulu.example,alpha.example ssh-ed25519 AAAA...
gitlab.com ssh-rsa AAAA...

khm normalize: 6 lines -> 2 lines  (2 exact duplicates removed, 1 merged by shared key)
```

Single-file only, on purpose: it will merge two lines into one when they share the exact same algorithm+key (that's just cosmetic — same key, same trusted identity), and it will drop exact duplicate lines (including duplicate *hashed* entries, which you can't otherwise spot by eye). It will **not** merge `known_hosts` with `known_hosts.old` or any second file — that kind of merge can silently paper over a real key change, which is exactly what `doctor` and `verify` exist to catch instead. `--write` replaces the file atomically (write to a temp file, then rename), so a crash mid-write can't corrupt your original.

---

### `doctor` — health check for known_hosts

```
khm doctor [--file <path>] [--check-reachable]
```

```
  ✓ malformed_line
  ✘ duplicate_entries (1)
  ✘ hashed_duplicate (1)
  ✘ obsolete_algorithm (1)
  ✓ mixed_algorithms

  warn   [duplicate_entries]    line 3 is an exact duplicate of line 2 (github.com)
  warn   [hashed_duplicate]     line 6 has the same hashed host as line 5 but a DIFFERENT key (stale entry after rotation?)
  warn   [obsolete_algorithm]   line 4 uses ssh-dss (DSA, deprecated) for legacy.example

3 findings  3 warnings
```

Six checks, five of them fully offline:

| check | severity | catches |
|---|---|---|
| `malformed_line` | error | a line missing required fields |
| `duplicate_entries` | warning | exact duplicate plain-text lines |
| `hashed_duplicate` | warning | duplicate *hashed* entries — you can't eyeball these, the hostname is hidden |
| `obsolete_algorithm` | warning | `ssh-rsa` / `ssh-dss` |
| `mixed_algorithms` | info only | one host offering several key types — often intentional, never fails the run |
| `unreachable_host` | warning | opt-in via `--check-reachable`, the only check that touches the network |

Exit code `1` if there's any `error` or `warning` finding; `info` alone never fails the run. Key-size checks (e.g. flagging small RSA moduli) are planned for a later release — they need a base64/ASN.1 decode step that didn't make it into this one.

---

## How it works

No authentication. No session. No shell. Just enough of the SSH handshake to obtain the host key.

`khm verify` and `khm scan` connect over raw TCP, exchange SSH version banners, send a `SSH_MSG_KEXINIT`, then a `SSH_MSG_KEX_ECDH_INIT`. The server responds with `SSH_MSG_KEX_ECDH_REPLY`, which contains the host public key blob — and the connection is closed immediately after.

The SHA-256 fingerprint is computed from the raw key blob using a self-contained implementation (no libcrypto). This matches the output of `ssh-keygen -lf`.

## Implementation

```
khm/
├── parser.c / parser.h      known_hosts parser
├── hostkey.c / hostkey.h    TCP + partial SSH handshake, host:port parsing
├── sha256.c / sha256.h      SHA-256, RFC 6234
├── json.c / json.h          --json serialization (shared by every command)
└── commands/
    ├── list.c               pretty-print known_hosts
    ├── verify.c             verify single host / verify --all
    ├── fingerprint.c        live key fingerprint, no known_hosts involved
    ├── export.c             csv/md/html/json export
    ├── normalize.c          dedupe/merge/sort a known_hosts file
    ├── doctor.c             health check
    ├── diff.c               diff two files
    └── scan.c               parallel network scan
```

## Build

```
make          # debug/dev binary
make release  # static binary → khm-linux-amd64
make clean
```

Requires: `gcc`, `make`, `glibc` (or `musl` for static builds). Nothing else.

## License

MIT
