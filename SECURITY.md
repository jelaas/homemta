# Security audit

This document records the security reviews of homemta: what was examined,
what was found and fixed, and the residual risks that remain by design.
Last reviewed: 2026-11-26 (post IPC redesign; see git history for the
earlier setuid-binary review).

## Threat model

- The **daemon** starts as root (bind :25, prepare state), forks the
  delivery helper, then drops to an unprivileged user (`user`/`group`);
  all SMTP, queue and spool work runs unprivileged.
- A **forked root helper process** is the only code path that retains
  privileges. It listens on a private abstract unix socket and serves
  only the daemon's own connections; for each request it becomes the
  mailbox owner, then exits. No setuid binary exists.
- Untrusted input arrives from: remote SMTP peers (HELO/MAIL/RCPT/DATA),
  the smarthost's SMTP/TLS responses, DNS results, `/etc/aliases`,
  `~/.forward`, local users who can connect to the helper socket, and
  (indirectly) message content echoed into bounces.
- Trusted (root-controlled) inputs: the JSONC config, `/etc/passwd`,
  `/etc/group`, TLS keys, the spool directory.

## Interprocess communication

### Delivery helper socket (abstract unix socket)

| property | status |
| --- | --- |
| Name | 160-bit random, bound in the abstract namespace |
| Name visibility | **not** a secret: abstract socket names are listed in `/proc/net/unix` for all users, and any process knowing the name can `connect()` (abstract sockets have no owner/permissions) |
| Factor 1 - SO_PEERCRED | checked in the helper parent *before* forking: the connecting process's real uid must equal the daemon's runtime uid (or 0 when the daemon deliberately runs as root) |
| Factor 2 - shared secret | a 256-bit random value generated before the fork, shared by fork inheritance only (never argv/env/logs); the first request line must match it, compared in constant time |
| Request framing | every line length-capped (1 KiB); message capped at 128 MiB; the client half-closes so the helper can read to EOF and reply |
| Response | `OK` / `ERR <reason>`, single line; the daemon caps its reply read |
| Concurrency | helper children capped at 32; per-child I/O timeouts (30 s) |
| Shutdown | life-line pipe: the write end exists only in the daemon, so when the daemon exits (any cause) the helper's poll sees POLLHUP and exits; no orphaned root process |
| Fork safety | the helper is forked while the daemon is still single-threaded, and is itself single-threaded, so its per-request `fork()` is safe |

**Reviewed scenarios**

- *Arbitrary local user connects*: refused by SO_PEERCRED before any
  parsing or fork (cheap).
- *Same-uid process connects* (e.g. another `mail` service): fails the
  secret check in the forked child (constant-time), no delivery, logged.
- *Root connects when the daemon runs as root*: the secret is the only
  remaining factor; root could also read the daemon's memory directly,
  so this is defence in depth, not a boundary against root.
- *Same-uid process with ptrace access*: could extract the secret, but
  already passes SO_PEERCRED; the secret protects against same-uid
  processes that are *not* fully compromised.
- *Connection floods*: non-matching uids are rejected pre-fork; matching
  uids are bounded by MAX_CHILDREN and 30 s timeouts. Residual: a
  malicious same-uid process can still slow local deliveries (see below).
- *Stale zombies*: helper delivery children are reaped on each loop
  iteration (waitpid WNOHANG); a zombie may linger until the next event -
  cosmetic, no resource growth.

### Daemon - helper protocol (untrusted data)

Everything the helper receives is treated as untrusted:

- Config re-read per request, must be root-owned and not group/world
  writable (`file_is_secure`), parse warnings are fatal.
- User name: length-capped, must exist in the (root-owned) passwd file,
  refused if uid 0, in `never_users`, or containing `/`, `.`, `..`.
- Envelope and message: length-capped; privileges are dropped *before*
  any file is touched; the mailbox open is `O_NOFOLLOW` and locked.
- **Fixed:** the shared mbox writer now also strips control characters
  from the envelope strings before writing `From_`/`Return-path:`/
  `Envelope-to:` lines, so a compromised daemon cannot inject mbox
  lines or headers through the helper.
- Helper-side error paths always reply `ERR ...` (never crash on input).

### Other IPC

- **Life-line pipe**: write end held only by the daemon; delivery
  children close their inherited ends. No fd duplication into spawned
  pipe commands (std marks non-stdio fds close-on-exec).
- **Signals**: SIGTERM/SIGINT only set a shutdown flag (async-signal-
  safe); SIGHUP/SIGPIPE ignored; handlers installed before the helper
  fork and inherited harmlessly.
- **stdin (supervisor hook)**: `--exit-on-stdin-eof` works in daemon
  mode; stdin data is read and discarded, EOF triggers clean shutdown.
- **Spool flock**: prevents concurrent daemons/queue-runners on the same
  spool.

## Untrusted input handling (SMTP)

**Fixed in the previous audit, still in place:**

- Symlink/TOCTOU: `O_NOFOLLOW` + `fchown` on mailbox and alias-file
  deliveries; path-traversal user names refused.
- HELO/EHLO validation (header injection into `Received:`).
- Bounce generation: control-character truncation of addresses/reasons,
  unpredictable multipart boundary.
- Spool directory chowned to the daemon user, mode 0700.
- `max_sessions` (default 64) connection-flood cap; 8 KiB line cap;
  `max_message_size`; NUL rejection; dot-stuffing; RFC address
  validation (control chars, spaces, metacharacters, length limits);
  ACL local-part restrictions; no open relaying (CIDR-aware
  `relay_from_hosts`); VRFY/EXPN disabled; alias/forward loop detection;
  bounces never bounce; atomic spool writes.

**Fixed in this audit:**

- mbox envelope sanitization at the shared writer (see above).
- Capped reply-line read on the daemon side of the helper socket.

## Cryptography

| area | status |
| --- | --- |
| SHA-256, HMAC-SHA-256, PBKDF2-HMAC-SHA-256 | RFC-vector tested, cross-checked with Python hashlib |
| SCRAM-SHA-256 | client proof + server signature verified against the RFC 5802/7677 exchange; nonce extension enforced; constant-time comparisons |
| MD5 (CRAM-MD5) | legacy compatibility only; never selected when SCRAM is offered |
| Randomness | /dev/urandom for socket name, shared secret, nonces, message-ids, bounce boundaries |
| TLS | rustls + ring, TLS 1.2/1.3, certificate verification against the configured CA bundle |

## Authentication

- Smarthost: SCRAM-SHA-256 preferred, then CRAM-MD5, PLAIN, LOGIN,
  XOAUTH2; credentials only ever sent inside TLS; `verify: false` +
  credentials triggers a startup warning.
- Config file must be root-owned and not group/world-writable (fatal in
  the helper, warning in the daemon).

## Residual risks (by design)

- **Local-delivery DoS**: a malicious process sharing the daemon's uid
  can occupy helper slots (32 x 30 s) and slow local delivery. It cannot
  escalate beyond the daemon's own capabilities.
- **Helper overload bounces**: when all helper children are busy the
  daemon gets an error and bounces the message instead of deferring
  (home-server scale; a deferred-queue redesign is out of scope).
- No DANE/MTA-STS (opportunistic inbound STARTTLS); no SASL server side
  (inbound trust = source IP); single process without chroot/jail;
  credentials in plaintext in the root-owned config; JSONC parser
  recursion bounded only by config size (config is root-controlled).
- The debug log (`-d`) prints the helper socket name (not the secret);
  with the default log file mode any local user could learn the name -
  irrelevant, since uid + secret are the boundary.

## Operational recommendations

1. Keep the config `0600 root:root`; restrict the log file if `-d` is
   used in production.
2. Alias `root` and `postmaster` to a real admin account.
3. Use `smarthost.verify: true` with an up-to-date CA bundle.
4. Run with `user: mail` (or a dedicated account); spool `0700`.
5. Keep `max_message_size` and `max_sessions` at sane values.
