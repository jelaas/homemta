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
use std::io::{BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

const MAX_LINE: usize = 8192;
const SESSION_TIMEOUT: Duration = Duration::from_secs(300);

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

    /// Read one line (CRLF or LF terminated), stripping the terminator.
    fn read_line(&mut self) -> std::io::Result<Option<String>> {
        let mut buf = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            let got = self.io().read(&mut byte)?;
            if got == 0 {
                return if buf.is_empty() { Ok(None) } else { Ok(Some(String::from_utf8_lossy(&buf).into_owned())) };
            }
            if byte[0] == b'\n' {
                break;
            }
            if buf.len() > MAX_LINE {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "line too long"));
            }
            buf.push(byte[0]);
        }
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
        self.rcpts.push((addr.full(), is_local));
        self.reply(250, "OK");
    }

    fn cmd_data(&mut self) {
        if self.rcpts.is_empty() {
            self.reply(503, "no valid recipients");
            return;
        }
        self.reply(354, "Enter message, ending with \".\" on a line by itself");
        let mut lines: Vec<Vec<u8>> = Vec::new();
        let mut size: u64 = 0;
        loop {
            match self.read_line() {
                Ok(Some(line)) => {
                    if line == "." {
                        break;
                    }
                    let mut bytes = line.into_bytes();
                    if bytes.first() == Some(&b'.') {
                        bytes.remove(0); // dot-unstuffing
                    }
                    if bytes.contains(&0) {
                        log::warn("message contains NUL byte, rejecting");
                        self.reply(554, "message contains NUL byte");
                        return;
                    }
                    size += bytes.len() as u64 + 2;
                    if size > self.cfg.max_message_size {
                        log::warn("message over size limit, rejecting");
                        self.reply(552, "message too large");
                        return;
                    }
                    lines.push(bytes);
                }
                Ok(None) => {
                    self.reply(451, "connection lost during message");
                    return;
                }
                Err(e) => {
                    log::debug(&format!("error reading message: {}", e));
                    return;
                }
            }
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
            &lines,
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
        let sock = match io.into_inner() {
            Io::Plain(s) => s,
            Io::Tls(_) => {
                self.reply(454, "TLS unavailable");
                return;
            }
        };
        let conn = match ServerConnection::new(tls_config) {
            Ok(c) => c,
            Err(e) => {
                log::error(&format!("TLS setup error: {}", e));
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
    lines: &[Vec<u8>],
    submission: bool,
) -> Vec<u8> {
    let mut headers: Vec<Vec<u8>> = Vec::new();
    let mut body: Vec<Vec<u8>> = Vec::new();
    let mut in_body = false;
    for l in lines {
        if !in_body && l.is_empty() {
            in_body = true;
            continue;
        }
        if in_body {
            body.push(l.clone());
        } else {
            headers.push(l.clone());
        }
    }

    let has = |name: &str| {
        let n = name.as_bytes();
        headers.iter().any(|h| {
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
    for h in &headers {
        out.extend_from_slice(h);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    for b in &body {
        out.extend_from_slice(b);
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// Bind and serve one port forever (until shutdown requested).
/// The listener is bound by main before dropping privileges.
fn serve_port(
    cfg: Arc<Config>,
    listener: TcpListener,
    tls_config: Option<Arc<ServerConfig>>,
    wake: mpsc::Sender<()>,
    active: Arc<AtomicUsize>,
) {
    let bind = match listener.local_addr() {
        Ok(a) => a.to_string(),
        Err(_) => "?:?".to_string(),
    };
    log::info(&format!("serving {} (IPv4)", bind));
    while !crate::queue::shutdown_flag() {
        match listener.accept() {
            Ok((sock, peer)) => {
                // Connection-flood guard: refuse extra sessions instead of
                // letting an attacker exhaust threads/memory.
                if active.load(Ordering::Relaxed) >= cfg.max_sessions {
                    let mut s = sock;
                    let _ = s.write_all(
                        b"421 too many concurrent connections, please try again later\r\n",
                    );
                    continue;
                }
                active.fetch_add(1, Ordering::Relaxed);
                let active = active.clone();
                let cfg = cfg.clone();
                let wake = wake.clone();
                let tls_config = tls_config.clone();
                let relay = match peer.ip() {
                    std::net::IpAddr::V4(ip) => crate::config::match_host_list(&cfg.relay_from_hosts, &ip),
                    _ => false,
                };
                std::thread::spawn(move || {
                    let _ = sock.set_read_timeout(Some(SESSION_TIMEOUT));
                    let _ = sock.set_write_timeout(Some(SESSION_TIMEOUT));
                    let mut s = Session {
                        rd: Some(BufReader::new(Io::Plain(sock))),
                        cfg,
                        wake,
                        tls_config,
                        peer_ip: peer.ip().to_string(),
                        relay,
                        helo: None,
                        mail_from: None,
                        rcpts: Vec::new(),
                        tls_active: false,
                        quit: false,
                    };
                    s.handle();
                    active.fetch_sub(1, Ordering::Relaxed);
                });
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
    let mut handles = Vec::new();
    for listener in listeners {
        let cfg = cfg.clone();
        let tls_config = tls_config.clone();
        let wake = wake.clone();
        let active = active.clone();
        handles.push(std::thread::spawn(move || {
            serve_port(cfg, listener, tls_config, wake, active);
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
            &lines,
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
        let msg = build_message(&c, "h", "127.0.0.1", "<E2@x>", "s@d", &[], &lines, true);
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
            &lines,
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
