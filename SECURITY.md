# Security audit

This document records the security review of homemta: what was examined,
what was found and fixed, and the residual risks that remain by design.
Last reviewed: 2026-11-25 (commit `3bbf7a5`..`security-audit`).

## Threat model

- The **daemon** starts as root (bind :25, prepare state) and drops to an
  unprivileged user (`user`/`group`); all SMTP, queue and spool work runs
  unprivileged.
- A **setuid-root helper** (`homemta-deliver`) is the only code path that
  regains privileges, and only to become the mailbox owner for local
  delivery.
- Untrusted input arrives from: remote SMTP peers (HELO/MAIL/RCPT/DATA),
  the smarthost's SMTP/TLS responses, DNS results, `/etc/aliases`,
  `~/.forward`, and (indirectly) message content echoed into bounces.
- Trusted (root-controlled) inputs: the JSONC config, `/etc/passwd`,
  `/etc/group`, TLS keys, the spool directory.

## Reviewed areas and findings

### 1. Cryptography

| area | status |
| --- | --- |
| SHA-256, HMAC-SHA-256, PBKDF2-HMAC-SHA-256 | hand-written; verified against RFC 6234/4231 vectors and cross-checked with Python hashlib |
| SCRAM-SHA-256 (RFC 7677) | client proof + server signature verified both ways against the RFC 5802/7677 exchange (recomputed with SHA-256); server nonce extension is enforced (downgrade/MITM detection) |
| MD5 (CRAM-MD5) | legacy mechanism, kept only for smarthost compatibility; never selected when SCRAM-SHA-256 is offered |
| Randomness | /dev/urandom for nonces, message-ids and bounce boundaries; deterministic fallback only if /dev/urandom is unreadable |
| TLS | rustls + ring; TLS 1.2/1.3; certificate verification against the configured CA bundle; no OpenSSL, no system trust store |

**Fixed:** SCRAM proof/signature comparisons now use a constant-time
comparison (`ct_eq`).

**Residual:** CRAM-MD5 is weak by modern standards (MD5, no channel
binding). It exists only for compatibility with smarthosts that offer
nothing better and is never the automatic first choice.

### 2. Authentication

| area | status |
| --- | --- |
| Smarthost auth | SCRAM-SHA-256, CRAM-MD5, PLAIN, LOGIN, XOAUTH2; `auto` prefers the strongest offered mechanism |
| Credentials over plaintext | refused: AUTH is only attempted inside TLS (SMTPS or STARTTLS) |
| Certificate verification | on by default; `verify: false` is an explicit insecure escape hatch (startup warning now emitted when combined with credentials) |
| Setuid helper | refuses uid 0 and `never_users`; requires euid 0 at entry (fail-closed if not installed setuid); drops supplementary groups; cleans environment |
| Setuid invocation gating | **fixed:** a setuid invocation (real uid ≠ 0, euid 0) is only allowed in `--deliver-mbox` mode; running the daemon/queue/pidfile startup path via the setuid bit is refused (it would otherwise be a root file-write primitive via `--pidfile`) |
| Config file | must be root-owned and not group/world-writable: **fatal** in the helper, warning in the daemon |

**Residual:** credentials are stored in plaintext in the config file;
protect it with `0600 root:root`. XOAUTH2 tokens expire and must be
rotated externally.

### 3. Untrusted input handling

**Fixed in this audit:**

- **Symlink attacks on mailboxes** (CWE-59/TOCTOU): `open()` on
  `/var/spool/mail/<user>` and alias/forward file targets now uses
  `O_NOFOLLOW`, and ownership changes use `fchown` on the open handle
  instead of `chown` on the path. A local attacker with write access to
  the mailbox directory can no longer redirect delivery into arbitrary
  files (e.g. `/root/.ssh/authorized_keys`).
- **HELO/EHLO header injection**: the HELO argument is echoed into the
  `Received:` header. It is now validated (alphanumerics, `. - [ ] :`
  only); embedded CR/LF, spaces and controls are rejected with 501.
- **Bounce header injection**: failure reasons (smarthost reply text) and
  envelope addresses are truncated at the first control character before
  being placed into bounce headers.
- **Bounce MIME smuggling**: the multipart boundary is now unpredictable
  (random per bounce), so attacker-influenced message content cannot
  guess the boundary and smuggle MIME parts out of the `message/rfc822`
  attachment.
- **Spool privacy**: the spool directory is chowned to the daemon user
  and set `0700` (it contains complete message bodies).
- **Connection floods**: `max_sessions` (default 64) caps concurrent SMTP
  sessions; excess connections get `421` instead of consuming threads.
- **Path traversal via passwd names**: user names are checked for `/`,
  `.`, `..` before being used as file-name components.

**Already in place (verified, not changed):**

- Address parsing rejects control characters, spaces and metacharacters
  in local parts; domains are restricted to `[A-Za-z0-9.-]` plus
  bracketed literals; length limits (64/254) enforced.
- Line-length cap (8 KiB), message-size cap (`max_message_size`), NUL
  byte rejection, dot-stuffing/destuffing per RFC 5321.
- ACL-style local-part restrictions (leading dots, `@ % ! / |`, `/../`)
  per recipient class.
- No open relaying: non-local recipients only from `relay_from_hosts`
  (exact IPs or CIDR), and only via the smarthost.
- `VRFY`/`EXPN` disabled (no user enumeration); `550 Unknown user` only
  for local domains where the user truly does not exist.
- Received/Message-ID/From headers are generated internally; the
  Message-ID is random.
- Alias/forward expansion has loop detection (`check_ancestor`
  equivalent).
- Bounces never bounce: envelope sender of a bounce is empty, and failing
  bounces are frozen then removed.
- Spool files are written atomically (temp + rename) and parsed from a
  directory only the daemon user can write.
- Session idle timeout (300 s), bounded queue-retry schedule.

## Residual risks and limitations (by design)

- **No DANE/MTA-STS**: STARTTLS is opportunistic for inbound connections;
  a MITM can strip it (standard for classic MTAs).
- **No SASL server side**: incoming connections are authenticated only by
  source IP (`relay_from_hosts`). Submission from untrusted networks is
  not supported.
- **TLS session limits**: a TLS handshake consumes a session slot for up
  to the session timeout; bounded by `max_sessions`.
- **`verify: false`** disables smarthost certificate validation entirely;
  combined with password auth it exposes credentials to a MITM (warned at
  startup).
- **Aliases pipes and file targets** execute commands as the daemon user;
  `/etc/aliases` must be root-controlled (pipes in `~/.forward` are an
  intended user feature).
- **Single process**: no chroot/jail; a daemon compromise is bounded by
  the unprivileged user, the setuid helper's fixed paths and
  `never_users`, but not by a sandbox.
- **No TLS client certificate** authentication for the smarthost.
- JSONC parser recursion depth is bounded only by config-file size
  (config is root-controlled).

## Operational recommendations

1. Keep the config `0600 root:root` (enforced as a warning/fatal error).
2. Install `homemta-deliver` setuid root only from trusted builds; keep it
   outside user-writable filesystems.
3. Alias `root` and `postmaster` to a real admin account; never rely on
   direct root mailbox delivery (refused by `never_users`).
4. Use `smarthost.verify: true` and an up-to-date CA bundle.
5. Run the daemon with `user: mail` (or a dedicated account); give the
   spool directory no group/other access.
6. Keep `max_message_size` and `max_sessions` at sane values.
