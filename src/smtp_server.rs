//! Submission SMTP server. Binds to the configured IPv4 address
//! (127.0.0.1 by default), accepts mail only from loopback peers, offers
//! STARTTLS when a certificate is configured, and routes:
//!   - local domains  -> /etc/aliases, ~/.forward, mbox delivery
//!   - everything else -> smarthost queue
//! Implements the classic ACL checks (restricted local parts, postmaster
//! acceptance, submission fixes for Date/Message-ID/From).

use crate::address::{self};
use crate::bounce::{self, Failure};
use crate::config::Config;
use crate::log;
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::collections::HashMap;
use std::io::{BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_LINE: usize = 8192;
/// Idle timeout for a single read/write.
const SESSION_TIMEOUT: Duration = Duration::from_secs(300);
/// Total wall-clock limit for one SMTP session (slow-drip connections
/// must not hold a session slot forever).
const SESSION_MAX: Duration = Duration::from_secs(30 * 60);
/// Recipients per transaction (RFC 5321 4.5.3.1.8 requires at least 100).
/// Bounds the local-delivery fan-out and the Received: header.
const MAX_RCPTS: usize = 100;

/// How a raw input line was terminated.
#[derive(Debug, PartialEq, Eq)]
enum LineEnd {
    CrLf,
    /// `\n` without a preceding `\r` (never accepted inside DATA: it is the
    /// SMTP smuggling vector).
    BareLf,
    /// Connection closed before a terminator.
    Eof,
}

static MSG_SEQ: AtomicU64 = AtomicU64::new(0);
static RANDOM_SEED: AtomicU64 = AtomicU64::new(0);

fn random_seed() -> u64 {
    let mut buf = [0u8; 8];
    let mut seed = 0;
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        if f.read_exact(&mut buf).is_ok() {
            seed = u64::from_le_bytes(buf);
        }
    }
    seed ^ ((log::unix_now() as u64) << 32) ^ (std::process::id() as u64)
}

/// Classic message id: <E<timehex><random>@hostname>
pub fn message_id(host: &str) -> String {
    if RANDOM_SEED.load(Ordering::Relaxed) == 0 {
        RANDOM_SEED.store(random_seed(), Ordering::Relaxed);
    }
    let n = MSG_SEQ.fetch_add(1, Ordering::Relaxed);
    let seed = RANDOM_SEED.load(Ordering::Relaxed) ^ n.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    format!("<E{:x}-{:08x}@{}>", log::unix_now(), seed as u32, host)
}

enum Io {
    Plain(TcpStream),
    Tls(StreamOwned<ServerConnection, TcpStream>),
}

impl Read for Io {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Io::Plain(s) => s.read(buf),
            Io::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Io {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Io::Plain(s) => s.write(buf),
            Io::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Io::Plain(s) => s.flush(),
            Io::Tls(s) => s.flush(),
        }
    }
}

/// A HELO/EHLO argument ends up in the Received: header, so only
/// characters that are safe there are allowed (no controls, no spaces).
pub fn valid_helo(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-[]:".contains(c))
}

struct Session {
    rd: Option<BufReader<Io>>,
    cfg: Arc<Config>,
    wake: mpsc::Sender<()>,
    tls_config: Option<Arc<ServerConfig>>,
    peer_ip: String,
    /// True when the peer may submit mail to any domain (relay_from_hosts).
    relay: bool,
    helo: Option<String>,
    mail_from: Option<String>,
    rcpts: Vec<(String, bool)>, // (address, is_local)
    tls_active: bool,
    quit: bool,
    /// End of the session's total time budget (SESSION_MAX).
    deadline: Instant,
}

impl Session {
    fn io(&mut self) -> &mut BufReader<Io> {
        self.rd.as_mut().expect("session io taken")
    }

    fn reply(&mut self, code: u16, text: &str) {
        let rd = self.io();
        let _ = rd.get_mut().write_all(format!("{} {}\r\n", code, text).as_bytes());
        let _ = rd.get_mut().flush();
    }

    /// Read one raw line (at most MAX_LINE bytes before the terminator) and
    /// report how it ended. The terminator (`\r\n` or `\n`) is stripped; a
    /// `\r` anywhere else stays in the returned bytes.
    fn read_raw_line(&mut self) -> std::io::Result<Option<(Vec<u8>, LineEnd)>> {
        let mut buf = Vec::new();
        loop {
            if buf.len() % 256 == 0 && Instant::now() > self.deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "session time limit exceeded",
                ));
            }
            let mut byte = [0u8; 1];
            let got = self.io().read(&mut byte)?;
            if got == 0 {
                return Ok(if buf.is_empty() { None } else { Some((buf, LineEnd::Eof)) });
            }
            if byte[0] == b'\n' {
                if buf.last() == Some(&b'\r') {
                    buf.pop();
                    return Ok(Some((buf, LineEnd::CrLf)));
                }
                return Ok(Some((buf, LineEnd::BareLf)));
            }
            if buf.len() >= MAX_LINE {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "line too long"));
            }
            buf.push(byte[0]);
        }
    }

    /// Read one command line (CRLF or LF terminated, leniently), stripping
    /// the terminator and trailing CRs.
    fn read_line(&mut self) -> std::io::Result<Option<String>> {
        let Some((mut buf, _)) = self.read_raw_line()? else {
            return Ok(None);
        };
        while buf.last() == Some(&b'\r') {
            buf.pop();
        }
        Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
    }

    fn ehlo_lines(&self, helo: &str) -> String {
        let mut caps = vec![
            format!(
                "250-{} Hello {} [{}]",
                self.cfg.primary_hostname, helo, self.peer_ip
            ),
            format!("250-SIZE {}", self.cfg.max_message_size),
            "250-8BITMIME".to_string(),
        ];
        if self.tls_config.is_some() && !self.tls_active {
            caps.push("250-STARTTLS".to_string());
        }
        caps.push("250 HELP".to_string());
        caps.join("\r\n") + "\r\n"
    }

    fn handle(&mut self) {
        if self.greeting_failed() {
            return;
        }
        loop {
            if self.quit {
                return;
            }
            let line = match self.read_line() {
                Ok(Some(l)) => l,
                Ok(None) => return,
                Err(e) => {
                    log::debug(&format!("session from {} error: {}", self.peer_ip, e));
                    return;
                }
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                self.reply(500, "empty command");
                continue;
            }
            let (verb, arg) = match trimmed.split_once(' ') {
                Some((v, a)) => (v.to_ascii_uppercase(), a.trim().to_string()),
                None => (trimmed.to_ascii_uppercase(), String::new()),
            };
            match verb.as_str() {
                "HELO" | "EHLO" => {
                    if arg.is_empty() {
                        self.reply(501, "HELO requires an argument");
                    } else if !valid_helo(&arg) {
                        // The argument ends up in the Received: header, so
                        // anything else (controls, spaces, \r) must be
                        // rejected to prevent header injection.
                        self.reply(501, "invalid HELO argument");
                    } else {
                        self.helo = Some(arg.clone());
                        if verb == "EHLO" {
                            let lines = self.ehlo_lines(&arg);
                            let rd = self.io();
                            let _ = rd.get_mut().write_all(lines.as_bytes());
                            let _ = rd.get_mut().flush();
                        } else {
                            self.reply(
                                250,
                                &format!(
                                    "{} Hello {} [{}]",
                                    self.cfg.primary_hostname, arg, self.peer_ip
                                ),
                            );
                        }
                    }
                }
                "MAIL" => self.cmd_mail(&arg),
                "RCPT" => self.cmd_rcpt(&arg),
                "DATA" => self.cmd_data(),
                "RSET" => {
                    self.reset();
                    self.reply(250, "Reset OK");
                }
                "NOOP" => self.reply(250, "OK"),
                "QUIT" => {
                    self.reply(
                        221,
                        &format!("{} closing connection", self.cfg.primary_hostname),
                    );
                    self.quit = true;
                }
                "STARTTLS" => self.cmd_starttls(),
                "VRFY" => self.reply(252, "Cannot VRFY user"),
                "EXPN" => self.reply(502, "EXPN not supported"),
                "HELP" => self.reply(214, "See RFC 5321"),
                _ => self.reply(500, "command unrecognized"),
            }
        }
    }

    /// Greet. All IPv4 peers may connect; relaying is enforced per-RCPT.
    fn greeting_failed(&mut self) -> bool {
        let host = self.cfg.primary_hostname.clone();
        let rd = self.io();
        let _ = rd
            .get_mut()
            .write_all(format!("220 {} ESMTP homemta\r\n", host).as_bytes());
        let _ = rd.get_mut().flush();
        false
    }

    /// RSET per RFC 5321: aborts the mail transaction but keeps the
    /// EHLO/HELO state.
    fn reset(&mut self) {
        self.mail_from = None;
        self.rcpts.clear();
    }

    fn cmd_mail(&mut self, arg: &str) {
        if self.helo.is_none() {
            self.reply(503, "send HELO/EHLO first");
            return;
        }
        let Some(rest) = arg.strip_prefix("FROM:") else {
            self.reply(501, "MAIL syntax: MAIL FROM:<address>");
            return;
        };
        let (path, params) = match rest.split_once(' ') {
            Some((p, ps)) => (p.trim(), ps.trim()),
            None => (rest.trim(), ""),
        };
        // SIZE= parameter check (BODY=/AUTH= accepted and ignored).
        if let Some(p) = params.split_whitespace().find(|p| p.starts_with("SIZE=")) {
            if let Ok(n) = p[5..].parse::<u64>() {
                if n > self.cfg.max_message_size {
                    self.reply(552, "message too large");
                    return;
                }
            }
        }
        if path.trim() == "<>" {
            // Null reverse path (bounces etc.).
            self.mail_from = Some(String::new());
            self.rcpts.clear();
            self.reply(250, "OK");
            return;
        }
        let addr = match address::parse(path) {
            Ok(a) => a,
            Err(e) if e == "unqualified address" => {
                // Unqualified senders are only accepted from relay hosts
                // (submission mode), and are qualified with our hostname.
                if !self.relay {
                    self.reply(501, "unqualified sender address not accepted");
                    return;
                }
                let bare = path.trim_matches(|c| c == '<' || c == '>');
                match address::qualify(bare, &self.cfg.primary_hostname) {
                    Ok(a) => a,
                    Err(e2) => {
                        self.reply(501, &format!("bad sender address: {}", e2));
                        return;
                    }
                }
            }
            Err(e) => {
                self.reply(501, &format!("bad sender address: {}", e));
                return;
            }
        };
        self.mail_from = Some(addr.full());
        self.rcpts.clear();
        self.reply(250, "OK");
    }

    fn cmd_rcpt(&mut self, arg: &str) {
        if self.mail_from.is_none() {
            self.reply(503, "need MAIL command first");
            return;
        }
        let Some(rest) = arg.strip_prefix("TO:") else {
            self.reply(501, "RCPT syntax: RCPT TO:<address>");
            return;
        };
        // Checked before any lookup: bounds memory, the Received: header
        // and the per-recipient delivery fan-out of a single message.
        if self.rcpts.len() >= MAX_RCPTS {
            self.reply(452, "too many recipients");
            return;
        }
        let path = rest.trim();
        let addr = match address::parse(path) {
            Ok(a) => a,
            Err(e) if e == "unqualified address" => {
                if !self.relay {
                    self.reply(501, "unqualified recipient address not accepted");
                    return;
                }
                let bare = path.trim_matches(|c| c == '<' || c == '>');
                match address::qualify(bare, &self.cfg.primary_hostname) {
                    Ok(a) => a,
                    Err(e2) => {
                        self.reply(501, &format!("bad recipient address: {}", e2));
                        return;
                    }
                }
            }
            Err(e) => {
                self.reply(501, &format!("bad recipient address: {}", e));
                return;
            }
        };
        let is_local = self.cfg.is_local_domain(&addr.domain);
        // ACL restricted-character checks.
        if is_local && address::restricted_local(&addr.local) {
            self.reply(550, "Restricted characters in address");
            return;
        }
        if !is_local && address::restricted_remote(&addr.local) {
            self.reply(550, "Restricted characters in address");
            return;
        }
        if is_local {
            if !crate::routing::verify_local(&self.cfg, &addr.local) {
                self.reply(550, "Unknown user");
                return;
            }
        } else {
            // No relaying: only trusted hosts may send to other domains,
            // and only through the smarthost.
            if !self.relay {
                self.reply(550, "relay not permitted");
                return;
            }
            if self.cfg.smarthost.is_none() {
                self.reply(550, "no smarthost configured");
                return;
            }
        }
        let full = addr.full();
        if self.rcpts.iter().any(|(r, _)| *r == full) {
            // Duplicate: accept, but deliver only once.
            self.reply(250, "OK (duplicate recipient)");
            return;
        }
        self.rcpts.push((full, is_local));
        self.reply(250, "OK");
    }

    fn cmd_data(&mut self) {
        if self.rcpts.is_empty() {
            self.reply(503, "no valid recipients");
            return;
        }
        self.reply(354, "Enter message, ending with \".\" on a line by itself");
        // The message is kept as raw bytes (8BITMIME: no UTF-8 conversion),
        // CRLF-terminated lines in one buffer (no per-line allocations, so
        // memory use stays close to max_message_size).
        let mut msg: Vec<u8> = Vec::new();
        // Once a problem is found the rest of the data is still read and
        // discarded up to the end-of-data line: returning early would make
        // the remaining message lines be parsed as SMTP commands.
        let mut reject: Option<(u16, &'static str)> = None;
        loop {
            let (line, end) = match self.read_raw_line() {
                Ok(Some(x)) => x,
                Ok(None) => {
                    self.reply(451, "connection lost during message");
                    self.quit = true;
                    return;
                }
                Err(e) => {
                    log::debug(&format!("error reading message: {}", e));
                    self.quit = true;
                    return;
                }
            };
            // SMTP smuggling defence (RFC 5321 2.3.8): only CRLF ends a
            // line, so only CRLF.CRLF ends the data. A bare LF or CR could
            // make us see the end of the message where the previous hop did
            // not (or vice versa); there is no safe way to resynchronize, so
            // the connection is closed.
            match end {
                LineEnd::CrLf => {}
                LineEnd::Eof => {
                    self.reply(451, "connection lost during message");
                    self.quit = true;
                    return;
                }
                LineEnd::BareLf => {
                    log::warn(&format!("{}: bare LF in message data, closing", self.peer_ip));
                    self.reply(554, "bare LF in message data is not permitted (RFC 5321 2.3.8)");
                    self.quit = true;
                    return;
                }
            }
            if line.contains(&b'\r') {
                log::warn(&format!("{}: bare CR in message data, closing", self.peer_ip));
                self.reply(554, "bare CR in message data is not permitted (RFC 5321 2.3.8)");
                self.quit = true;
                return;
            }
            if line == b"." {
                break;
            }
            if reject.is_some() {
                continue;
            }
            // Dot-unstuffing.
            let data: &[u8] = match line.strip_prefix(b".") {
                Some(d) => d,
                None => &line,
            };
            if data.contains(&0) {
                log::warn("message contains NUL byte, rejecting");
                reject = Some((554, "message contains NUL byte"));
                msg = Vec::new();
                continue;
            }
            if msg.len() as u64 + data.len() as u64 + 2 > self.cfg.max_message_size {
                log::warn("message over size limit, rejecting");
                reject = Some((552, "message too large"));
                msg = Vec::new();
                continue;
            }
            msg.extend_from_slice(data);
            msg.extend_from_slice(b"\r\n");
        }
        if let Some((code, text)) = reject {
            self.reply(code, text);
            self.reset();
            return;
        }

        let id = message_id(&self.cfg.primary_hostname);
        let sender = self.mail_from.clone().unwrap_or_default();
        let rcpts = std::mem::take(&mut self.rcpts);

        let msg = build_message(
            &self.cfg,
            self.helo.as_deref().unwrap_or("unknown"),
            &self.peer_ip,
            &id,
            &sender,
            &rcpts,
            &msg,
            self.relay, // submission fixes only for trusted local hosts
        );

        log::info(&format!(
            "<= {} ({}) for {}",
            sender,
            self.peer_ip,
            rcpts.iter()
                .map(|(r, _)| format!("<{}>", r))
                .collect::<Vec<_>>()
                .join(", ")
        ));
        self.deliver(&id, &sender, &rcpts, &msg);
        self.reply(250, &format!("OK id={}", id));
        self.reset();
    }

    fn deliver(&mut self, id: &str, sender: &str, rcpts: &[(String, bool)], msg: &[u8]) {
        let mut remote: Vec<String> = Vec::new();
        let mut failures: Vec<Failure> = Vec::new();

        for (rcpt, is_local) in rcpts {
            if *is_local {
                match crate::routing::deliver_local(&self.cfg, sender, rcpt, msg) {
                    Ok(more_remote) => remote.extend(more_remote),
                    Err(e) => {
                        log::warn(&format!("{}: local delivery to {} failed: {}", id, rcpt, e));
                        failures.push(Failure {
                            rcpt: rcpt.clone(),
                            reason: e,
                        });
                    }
                }
            } else {
                remote.push(rcpt.clone());
            }
        }

        if !remote.is_empty() {
            match crate::queue::enqueue(&self.cfg, sender, &remote, msg) {
                Ok(()) => {
                    let _ = self.wake.send(());
                }
                Err(e) => {
                    for r in remote {
                        failures.push(Failure {
                            rcpt: r,
                            reason: e.clone(),
                        });
                    }
                }
            }
        }

        if !failures.is_empty() {
            log::info(&format!(
                "{}: {} recipient(s) failed, bouncing",
                id,
                failures.len()
            ));
            if sender.is_empty() {
                log::warn(&format!("{}: failures for bounce message, dropping", id));
                return;
            }
            let body = bounce::build(&self.cfg.primary_hostname, sender, &failures, msg);
            bounce::deliver(&self.cfg, sender, &body, &self.wake);
        }
    }

    fn cmd_starttls(&mut self) {
        if self.tls_active {
            self.reply(503, "already in TLS session");
            return;
        }
        let Some(tls_config) = self.tls_config.clone() else {
            self.reply(454, "TLS not available");
            return;
        };
        self.reply(220, "TLS go ahead");
        let io = match self.rd.take() {
            Some(io) => io,
            None => return,
        };
        // into_inner() discards any plaintext the client pipelined after
        // STARTTLS (command injection defence). The io is gone from here
        // on: every early exit must end the session, never touch self.io().
        let sock = match io.into_inner() {
            Io::Plain(s) => s,
            Io::Tls(_) => {
                self.quit = true;
                return;
            }
        };
        let conn = match ServerConnection::new(tls_config) {
            Ok(c) => c,
            Err(e) => {
                log::error(&format!("TLS setup error: {}", e));
                self.quit = true;
                return;
            }
        };
        let tls = StreamOwned::new(conn, sock);
        self.rd = Some(BufReader::new(Io::Tls(tls)));
        self.tls_active = true;
        // RFC 3207: reset the session state after STARTTLS.
        self.reset();
        self.helo = None;
    }
}

/// Assemble the final message: Received header always; Date/Message-ID/From
/// fixes only in submission mode (trusted relay hosts), CRLF normalization.
fn build_message(
    cfg: &Config,
    helo: &str,
    peer: &str,
    id: &str,
    sender: &str,
    rcpts: &[(String, bool)],
    data: &[u8],
    submission: bool,
) -> Vec<u8> {
    // `data` is the received message as CRLF-terminated lines. Split it
    // at the first empty line into the header block (each header line
    // keeps its CRLF) and the body; borrowed, not copied.
    let empty: &[u8] = &[];
    let (headers, body): (&[u8], &[u8]) = if data.starts_with(b"\r\n") {
        (empty, &data[2..])
    } else {
        match data.windows(4).position(|w| w == b"\r\n\r\n") {
            Some(i) => (&data[..i + 2], &data[i + 4..]),
            None => (data, empty),
        }
    };

    let has = |name: &str| {
        let n = name.as_bytes();
        headers.split(|&b| b == b'\n').any(|h| {
            h.len() > n.len()
                && h[..n.len()].eq_ignore_ascii_case(n)
                && h[n.len()] == b':'
        })
    };

    let mut out: Vec<u8> = format!(
        "Received: from {} ([{}])\r\n\tby {} (homemta) with ESMTP id {}\r\n\tfor {}; {}\r\n",
        helo,
        peer,
        cfg.primary_hostname,
        id,
        rcpts.iter()
            .map(|(r, _)| format!("<{}>", r))
            .collect::<Vec<_>>()
            .join(", "),
        crate::log::rfc2822_now()
    )
    .into_bytes();

    let mut add = |name: &str, value: &str| {
        out.extend_from_slice(format!("{}: {}\r\n", name, value).as_bytes());
    };
    if submission {
        if !has("Date") {
            add("Date", &crate::log::rfc2822_now());
        }
        if !has("Message-ID") {
            add("Message-ID", id);
        }
        if !has("From") && !sender.is_empty() {
            add("From", sender);
        }
    }
    out.reserve(headers.len() + 2 + body.len());
    out.extend_from_slice(headers);
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

/// Concurrent sessions per client IP, shared by all listeners.
type PerIp = Arc<Mutex<HashMap<Ipv4Addr, usize>>>;

/// A reserved session slot (global and per-IP). Released on drop, so a
/// session thread that fails to spawn or ends in any way frees its slot.
struct SlotGuard {
    active: Arc<AtomicUsize>,
    per_ip: PerIp,
    ip: Option<Ipv4Addr>,
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
        if let Some(ip) = self.ip {
            let mut m = self.per_ip.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(c) = m.get_mut(&ip) {
                *c = c.saturating_sub(1);
                if *c == 0 {
                    m.remove(&ip);
                }
            }
        }
    }
}

/// Reserve a session slot: at most `max_sessions` in total and, for
/// peers that are not relay hosts, a quarter of that (min 4) per IP, so a
/// single remote host cannot occupy every slot with idle connections.
fn reserve_slot(cfg: &Config, active: &Arc<AtomicUsize>, per_ip: &PerIp, ip: Ipv4Addr, relay: bool) -> Option<SlotGuard> {
    // Atomic check-and-increment (no load/add race between listeners).
    active
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
            (n < cfg.max_sessions).then_some(n + 1)
        })
        .ok()?;
    let mut guard = SlotGuard {
        active: active.clone(),
        per_ip: per_ip.clone(),
        ip: None,
    };
    if !relay {
        let limit = (cfg.max_sessions / 4).max(4);
        let mut m = per_ip.lock().unwrap_or_else(|e| e.into_inner());
        let c = m.entry(ip).or_insert(0);
        if *c >= limit {
            return None; // guard drops: releases the global slot
        }
        *c += 1;
        guard.ip = Some(ip);
    }
    Some(guard)
}

/// Bind and serve one port forever (until shutdown requested).
/// The listener is bound by main before dropping privileges.
fn serve_port(
    cfg: Arc<Config>,
    listener: TcpListener,
    tls_config: Option<Arc<ServerConfig>>,
    wake: mpsc::Sender<()>,
    active: Arc<AtomicUsize>,
    per_ip: PerIp,
) {
    let bind = match listener.local_addr() {
        Ok(a) => a.to_string(),
        Err(_) => "?:?".to_string(),
    };
    log::info(&format!("serving {} (IPv4)", bind));
    while !crate::queue::shutdown_flag() {
        match listener.accept() {
            Ok((sock, peer)) => {
                let std::net::IpAddr::V4(ip) = peer.ip() else {
                    continue; // IPv4 only
                };
                let relay = crate::config::match_host_list(&cfg.relay_from_hosts, &ip);
                // Connection-flood guard: refuse extra sessions instead of
                // letting an attacker exhaust threads/memory.
                let Some(slot) = reserve_slot(&cfg, &active, &per_ip, ip, relay) else {
                    let mut s = sock;
                    let _ = s.set_write_timeout(Some(Duration::from_secs(5)));
                    let _ = s.write_all(
                        b"421 too many concurrent connections, please try again later\r\n",
                    );
                    continue;
                };
                let cfg = cfg.clone();
                let wake = wake.clone();
                let tls_config = tls_config.clone();
                // Builder::spawn instead of thread::spawn: running out of
                // threads must refuse the connection, not panic (which
                // aborts the whole daemon with panic = "abort").
                let spawned = std::thread::Builder::new().spawn(move || {
                    let _slot = slot;
                    let _ = sock.set_read_timeout(Some(SESSION_TIMEOUT));
                    let _ = sock.set_write_timeout(Some(SESSION_TIMEOUT));
                    let mut s = Session {
                        rd: Some(BufReader::new(Io::Plain(sock))),
                        cfg,
                        wake,
                        tls_config,
                        peer_ip: ip.to_string(),
                        relay,
                        helo: None,
                        mail_from: None,
                        rcpts: Vec::new(),
                        tls_active: false,
                        quit: false,
                        deadline: Instant::now() + SESSION_MAX,
                    };
                    s.handle();
                });
                if let Err(e) = spawned {
                    log::warn(&format!("cannot start session thread: {}", e));
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(e) => {
                log::warn(&format!("accept error on {}: {}", bind, e));
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
}

/// Start one thread per pre-bound listener.
pub fn serve(
    cfg: Arc<Config>,
    tls_config: Option<Arc<ServerConfig>>,
    wake: mpsc::Sender<()>,
    listeners: Vec<TcpListener>,
) -> Vec<std::thread::JoinHandle<()>> {
    let active = Arc::new(AtomicUsize::new(0));
    let per_ip: PerIp = Arc::new(Mutex::new(HashMap::new()));
    let mut handles = Vec::new();
    for listener in listeners {
        let cfg = cfg.clone();
        let tls_config = tls_config.clone();
        let wake = wake.clone();
        let active = active.clone();
        let per_ip = per_ip.clone();
        handles.push(std::thread::spawn(move || {
            serve_port(cfg, listener, tls_config, wake, active, per_ip);
        }));
    }
    handles
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        let mut c = Config::default();
        c.primary_hostname = "test.example".to_string();
        c.local_domains = vec!["test.example".to_string()];
        c
    }

    /// Join lines into the CRLF-terminated form cmd_data produces.
    fn crlf(lines: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for l in lines {
            out.extend_from_slice(l);
            out.extend_from_slice(b"\r\n");
        }
        out
    }

    /// Run a Session over a loopback socket, feed it `script`, and return
    /// everything the server replied.
    fn run_session(c: Config, script: &[u8]) -> String {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (sock, _) = l.accept().unwrap();
        let h = std::thread::spawn(move || {
            let (tx, _rx) = mpsc::channel();
            let mut s = Session {
                rd: Some(BufReader::new(Io::Plain(sock))),
                cfg: Arc::new(c),
                wake: tx,
                tls_config: None,
                peer_ip: "127.0.0.1".to_string(),
                relay: true,
                helo: None,
                mail_from: None,
                rcpts: Vec::new(),
                tls_active: false,
                quit: false,
                deadline: Instant::now() + SESSION_MAX,
            };
            s.handle();
            // Consume the rest of the script before closing, so the close
            // is a FIN (not an RST that could discard unread replies).
            if let Some(mut rd) = s.rd.take() {
                let mut rest = Vec::new();
                let _ = rd.read_to_end(&mut rest);
            }
        });
        client.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        client.write_all(script).unwrap();
        let _ = client.shutdown(std::net::Shutdown::Write);
        let mut out = Vec::new();
        let _ = client.read_to_end(&mut out);
        h.join().unwrap();
        String::from_utf8_lossy(&out).into_owned()
    }

    #[test]
    fn bare_lf_end_of_data_is_not_accepted() {
        // Classic SMTP smuggling: "\n.\n" must not end the message, and
        // nothing after it may be executed as a command.
        let out = run_session(
            cfg(),
            b"EHLO a\r\nMAIL FROM:<a@b.example>\r\nRCPT TO:<postmaster@test.example>\r\n\
              DATA\r\nSubject: x\r\n\r\nhello\n.\nMAIL FROM:<evil@x.example>\r\n\
              RCPT TO:<postmaster@test.example>\r\nDATA\r\nforged\r\n.\r\nQUIT\r\n",
        );
        assert!(out.contains("554 bare LF"), "{}", out);
        assert_eq!(out.matches("250 OK\r\n").count(), 2, "smuggled commands ran: {}", out);
        assert!(!out.contains("OK id="), "a message was accepted: {}", out);
    }

    #[test]
    fn bare_cr_in_data_is_not_accepted() {
        let out = run_session(
            cfg(),
            b"EHLO a\r\nMAIL FROM:<a@b.example>\r\nRCPT TO:<postmaster@test.example>\r\n\
              DATA\r\nSubject: x\r\n\r\nhello\r.\rQUIT\r\n.\r\n",
        );
        assert!(out.contains("554 bare CR"), "{}", out);
        assert!(!out.contains("OK id="), "{}", out);
    }

    #[test]
    fn rejected_data_is_drained_not_executed() {
        // After a NUL byte the rest of the message must still be consumed
        // as data, not parsed as commands.
        let out = run_session(
            cfg(),
            b"EHLO a\r\nMAIL FROM:<a@b.example>\r\nRCPT TO:<postmaster@test.example>\r\n\
              DATA\r\nSubject: x\r\n\r\na\0b\r\nRSET\r\nMAIL FROM:<evil@x.example>\r\n.\r\nQUIT\r\n",
        );
        assert!(out.contains("554 message contains NUL byte"), "{}", out);
        assert!(!out.contains("Reset OK"), "body line ran as a command: {}", out);
        assert_eq!(out.matches("250 OK\r\n").count(), 2, "{}", out);
        assert!(out.contains("221 "), "{}", out);
    }

    #[test]
    fn recipient_count_is_capped_and_deduplicated() {
        let mut c = cfg();
        c.smarthost = Some("smarthost.example".to_string());
        let mut script = b"EHLO a\r\nMAIL FROM:<a@b.example>\r\n".to_vec();
        script.extend_from_slice(b"RCPT TO:<dup@remote.example>\r\nRCPT TO:<dup@remote.example>\r\n");
        for i in 1..MAX_RCPTS + 1 {
            script.extend_from_slice(format!("RCPT TO:<u{}@remote.example>\r\n", i).as_bytes());
        }
        script.extend_from_slice(b"QUIT\r\n");
        let out = run_session(c, &script);
        assert_eq!(out.matches("250 OK (duplicate recipient)").count(), 1, "{}", out);
        // dup + 99 distinct fill the 100 slots; the 100th distinct is refused.
        assert_eq!(out.matches("452 too many recipients").count(), 1, "{}", out);
    }

    #[test]
    fn message_without_body_and_8bit_kept() {
        let c = cfg();
        let data = b"Subject: \xe9t\xe9\r\nX-Bin: \xff\xfe\r\n".to_vec();
        let msg = build_message(&c, "h", "127.0.0.1", "<E9@x>", "s@d", &[], &data, false);
        // Header block preserved byte for byte (no UTF-8 replacement),
        // followed by the separating empty line.
        assert!(msg.ends_with(b"Subject: \xe9t\xe9\r\nX-Bin: \xff\xfe\r\n\r\n"));
    }

    #[test]
    fn helo_validation() {
        assert!(valid_helo("mail.example.com"));
        assert!(valid_helo("[192.0.2.1]"));
        assert!(valid_helo("localhost"));
        assert!(!valid_helo(""));
        assert!(!valid_helo("a b"));
        assert!(!valid_helo("a\r\nBcc: evil@x"));
        assert!(!valid_helo("a\tb"));
        assert!(!valid_helo("a@b"));
    }

    #[test]
    fn submission_fixes() {
        let c = cfg();
        let lines: Vec<Vec<u8>> = vec![
            b"To: someone@else.example".to_vec(),
            b"Subject: hi".to_vec(),
            b"".to_vec(),
            b"body line".to_vec(),
        ];
        let msg = build_message(
            &c,
            "myhost",
            "127.0.0.1",
            "<E1@test.example>",
            "me@test.example",
            &[("someone@else.example".to_string(), false)],
            &crlf(&lines),
            true,
        );
        let s = String::from_utf8(msg).unwrap();
        assert!(s.starts_with("Received: from myhost ([127.0.0.1])"));
        assert!(s.contains("Date: "));
        assert!(s.contains("Message-ID: <E1@test.example>"));
        assert!(s.contains("From: me@test.example"));
        assert!(s.contains("To: someone@else.example"));
        assert!(s.contains("\r\n\r\nbody line\r\n"));
    }

    #[test]
    fn headers_preserved_when_present() {
        let c = cfg();
        let lines: Vec<Vec<u8>> = vec![
            b"Date: Fri, 1 Jan 2026 00:00:00 +0000".to_vec(),
            b"From: x@y".to_vec(),
            b"".to_vec(),
            b"b".to_vec(),
        ];
        let msg = build_message(&c, "h", "127.0.0.1", "<E2@x>", "s@d", &[], &crlf(&lines), true);
        let s = String::from_utf8(msg).unwrap();
        assert_eq!(s.matches("Date: ").count(), 1);
        assert_eq!(s.matches("From: ").count(), 1);
    }

    #[test]
    fn no_submission_fixes_for_inbound() {
        let c = cfg();
        let lines: Vec<Vec<u8>> = vec![
            b"To: jelaas@test.example".to_vec(),
            b"Subject: inbound".to_vec(),
            b"".to_vec(),
            b"body".to_vec(),
        ];
        let msg = build_message(
            &c,
            "external.example",
            "203.0.113.7",
            "<E3@test.example>",
            "remote@external.example",
            &[("jelaas@test.example".to_string(), true)],
            &crlf(&lines),
            false,
        );
        let s = String::from_utf8(msg).unwrap();
        // Received is always added; submission fixes must NOT be.
        assert!(s.starts_with("Received: from external.example ([203.0.113.7])"));
        assert!(!s.contains("Date: "));
        assert!(!s.contains("Message-ID: "));
        assert!(!s.contains("From: remote@external.example"));
        assert!(s.contains("Subject: inbound"));
    }
}
