# homemta

A minimal MTA for home servers, written in Rust.

- **Receives mail from the internet.** Binds IPv4 `0.0.0.0:25` and accepts
  mail for `local_domains` from anywhere — but **never relays**: only
  trusted hosts in `relay_from_hosts` may send to other domains. No open
  relay, ever.
- **Smarthost only for outgoing.** Everything not in a local domain is
  queued and sent through one configured smarthost over SMTPS (or
  STARTTLS).
- **Local delivery** into `mbox` files under `/var/spool/mail/` in the
  traditional BSD mailbox format that Dovecot reads, including
  `/etc/aliases` and `~/.forward` handling.
- **Modern smarthost authentication**: SCRAM-SHA-256 (RFC 7677, preferred),
  CRAM-MD5, PLAIN, LOGIN and XOAUTH2; `"auth": "auto"` picks the strongest
  mechanism the smarthost offers.
- **IPv4 only**, **TLS support** (STARTTLS for incoming connections, TLS
  for the smarthost), classic retry schedule and bounce messages.
- **Static musl binary.** Two runtime dependencies: `rustls` (TLS, with
  the pure-Rust `ring` backend) and `libc` (musl bindings). The JSONC
  config parser, DNS, base64, MD5, SHA-256, HMAC, PBKDF2, SCRAM and the
  SMTP client/server are all hand-written. No C/C++ libraries are linked
  other than musl libc.

## Build

```sh
rustup target add x86_64-unknown-linux-musl
make            # -> target/x86_64-unknown-linux-musl/release/homemta
```

The result is fully static:

```sh
$ ldd target/x86_64-unknown-linux-musl/release/homemta
        not a dynamic executable
```

If your host toolchain is glibc-based you also need a musl-capable C
compiler for the few C files inside `ring`:

```sh
CC_x86_64-unknown-linux_musl=musl-gcc make
```

## Configuration

Copy `homemta.jsonc.example` to `/etc/homemta.jsonc` (JSON with comments
and trailing commas) and adjust:

| option                       | meaning                                                          |
| ---------------------------- | ---------------------------------------------------------------- |
| `primary_hostname`           | this host's FQDN                                                 |
| `local_domains`              | domains mail is accepted for and delivered locally               |
| `relay_from_hosts`           | IPs/CIDRs allowed to send to any domain (default `127.0.0.1`)    |
| `listen_addr` / `listen_ports` | `0.0.0.0` / `[25]` by default (inbound MX)                      |
| `smarthost.host`             | host all non-local mail is sent to (`smarthost` router)          |
| `smarthost.port`             | 465 by default (`remote_auth_smtp` transport)                    |
| `smarthost.tls`              | `smtps` (port 465) / `starttls` / `none`                         |
| `smarthost.auth`             | `auto`, `scram-sha-256`, `cram-md5`, `plain`, `login`, `xoauth2`, `none` |
| `smarthost.username`/`password` | credentials (for `xoauth2`, password is the access token)    |
| `smarthost.ca_file`          | CA bundle for verifying the smarthost cert (see below)           |
| `smarthost.verify`           | `false` to accept self-signed smarthost certs (insecure)         |
| `tls.cert` / `tls.key`       | enable STARTTLS on the listen ports                              |
| `mailbox_dir`                | where mbox files live (default `/var/spool/mail`)                |
| `aliases_file`               | default `/etc/aliases`                                           |
| `spool_dir`                  | outgoing queue (default `/var/spool/homemta`)                    |

Run it (as root, or with `CAP_NET_BIND_SERVICE`):

```sh
/usr/local/sbin/homemta -c /etc/homemta.jsonc
```

A systemd unit is in `contrib/homemta.service`. On systems without
systemd, run it as a background daemon:

```sh
/usr/local/sbin/homemta -b -c /etc/homemta.jsonc --pidfile /run/homemta.pid
```

`-b`/`--daemon` double-forks and detaches from the terminal; startup
errors are still printed before detaching. The pid file is written once
the listeners are up and removed again on clean shutdown.

### Behaviour notes

- **Accept policy** (the classic ACL checks): local domains are
  accepted from anyone after local-part sanity checks and user
  verification (`verify = recipient`); `postmaster` is always accepted
  (falls back to `root`); non-local recipients are accepted only from
  `relay_from_hosts` and only when a smarthost is configured — everything
  else gets `550 relay not permitted`.
- Restricted local parts are rejected (leading dots,
  `@ % ! / |`, `/../`).
- **Submission mode** (the classic `control = submission` behaviour)
  applies only to
  `relay_from_hosts` peers: missing `Date:`, `Message-ID:` and `From:`
  headers are added, and unqualified addresses are qualified. Inbound
  mail from the internet is stored as received (with a `Received:` header).
- Local mailboxes get the envelope `From ` line plus `Return-path:`,
  `Envelope-to:` and `Delivery-date:` headers (`delivery_date_add`,
  `envelope_to_add`, `return_path_add`), `>From ` escaping, and are
  locked while appending.
- Outgoing mail is queued immediately; temporary failures retry with the
  classic schedule (`F,2h,15m; G,16h,1h,1.5; F,4d,6h`), permanent
  failures and timeouts produce RFC 3464 bounce messages. Failing bounces
  freeze after 2 days and are removed after 7 (`ignore_bounce_errors_after`,
  `timeout_frozen_after`).
- `homemta -q` processes the queue once and exits (useful for cron).
- **Logging**: all log output goes to the `log_file` from the
  configuration. Without a configured `log_file`, messages go to stderr —
  which works in the foreground, but in daemon mode (`-b`) stdout/stderr
  are detached, so a `log_file` is effectively required there (a warning
  is printed at startup if it is missing). `-d` additionally mirrors the
  log to stderr.
- `homemta --exit-on-stdin-eof` shuts the daemon down when its stdin
  closes; handy for supervisors and sandboxes where signalling is
  unavailable.

## Limitations (by design)

- IPv4 only; no MX lookups (the smarthost is the only remote peer); no
  daemonization (use the systemd unit); no config reload on SIGHUP.
- Authentication to the smarthost always requires TLS (never send
  credentials in plaintext).

### Fresh CA bundles

`smarthost.ca_file` is the place to point at an up-to-date CA bundle when
the system's `/etc/ssl/certs/ca-certificates.crt` is stale:

```sh
curl -o /etc/ssl/certs/cacert.pem https://curl.se/ca/cacert.pem
```

```jsonc
"smarthost": { "ca_file": "/etc/ssl/certs/cacert.pem", ... }
```

The bundle must be one or more PEM `CERTIFICATE` blocks (the standard
`cacert.pem` format; concatenated files work too) and must be readable by
the daemon user. It is re-read on every smarthost connection, so updating
the file takes effect immediately without restarting. Verification uses
rustls with the bundle you provide only - the system trust store is never
consulted, so old distro packages don't matter.
- Pipe and file targets in aliases/`.forward` run under `pipe_user`
  (default `nobody`); `:blackhole:` is supported.
- No outbound delivery directly to destination MXes: everything goes
  through the smarthost.

## Security

See [SECURITY.md](SECURITY.md) for the full security audit (cryptography,
authentication, untrusted-input handling) and operational recommendations.

## Tests

```sh
make test
```

Unit tests cover the crypto (RFC 1321/2104/2195/2202/4231/5802/7677
vectors, SCRAM-SHA-256 proof/signature round-trips), JSONC parsing, relay
host-list matching and mbox format. Integration tests in `tests/smoke.rs`
spawn the real binary plus a fake SMTPS smarthost (with server-side
SCRAM/CRAM-MD5/PLAIN/LOGIN implementations) and exercise local delivery,
STARTTLS submission, inbound-MX relaying rejection, all authentication
mechanisms, bounces and retries.
