# khm — known hosts manager

[![CI](https://github.com/casablanque-code/khm/actions/workflows/ci.yml/badge.svg)](https://github.com/casablanque-code/khm/actions/workflows/ci.yml)
![Pure C](https://img.shields.io/badge/pure-C-blue)
![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)

A CLI tool for managing SSH `known_hosts` files. No libssh, no OpenSSL, no nothing — raw BSD sockets, a hand-rolled SHA-256, and a partial SSH handshake to fetch host keys directly.

## Why

SSH gives you no good way to audit or compare `known_hosts` files. You either trust TOFU, grep through a plain-text file, or disable `StrictHostKeyChecking` in scripts. `khm` fills that gap.

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

## How it works

`khm verify` and `khm scan` connect over raw TCP, exchange SSH version banners, send a `SSH_MSG_KEXINIT`, then a `SSH_MSG_KEX_ECDH_INIT`. The server responds with `SSH_MSG_KEX_ECDH_REPLY` which contains the host public key blob. The connection is closed immediately after — no authentication, no encryption negotiated.

The SHA-256 fingerprint is computed from the raw key blob using a self-contained implementation (no libcrypto). This matches the output of `ssh-keygen -lf`.

## Implementation

```
khm/
├── parser.c / parser.h      known_hosts parser
├── hostkey.c / hostkey.h    TCP + partial SSH handshake
├── sha256.c / sha256.h      SHA-256, RFC 6234
└── commands/
    ├── list.c               pretty-print known_hosts
    ├── verify.c             verify single host
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
