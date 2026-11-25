//! SMTP client for the smarthost (per exim.conf: SMTPS on port 465 with
//! CRAM-MD5 or PLAIN authentication). No relaying, no MX lookups: every
//! remote message goes through the smarthost.

use crate::base64;
use crate::config::{AuthMode, Config, TlsMode};
use crate::md5;
use rustls::{ClientConnection, StreamOwned};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug)]
pub enum Fail {
    /// Temporary: retry later per the queue schedule.
    Temp(String),
    /// Permanent: bounce immediately.
    Perm(String),
}

#[derive(Debug)]
pub struct RcptFail {
    pub rcpt: String,
    pub code: u16,
    pub text: String,
}

enum Transport {
    Plain(TcpStream),
    Tls(StreamOwned<ClientConnection, TcpStream>),
}

impl Read for Transport {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Transport::Plain(s) => s.read(buf),
            Transport::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Transport {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Transport::Plain(s) => s.write(buf),
            Transport::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Transport::Plain(s) => s.flush(),
            Transport::Tls(s) => s.flush(),
        }
    }
}

/// A connection with buffered reading. All protocol traffic is strict
/// request/response, so writes through the BufReader never race with
/// buffered input.
struct Conn {
    rd: BufReader<Transport>,
    tls_active: bool,
}

struct Reply {
    code: u16,
    text: String,
}

impl Conn {
    fn send(&mut self, cmd: &str) -> std::io::Result<()> {
        self.rd.get_mut().write_all(cmd.as_bytes())?;
        self.rd.get_mut().write_all(b"\r\n")?;
        self.rd.get_mut().flush()
    }

    fn read_reply(&mut self) -> std::io::Result<Reply> {
        let mut line = String::new();
        let mut text = String::new();
        loop {
            line.clear();
            self.rd.read_line(&mut line)?;
            if line.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed",
                ));
            }
            let code: u16 = line.get(..3).and_then(|c| c.parse().ok()).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "bad reply line")
            })?;
            let rest = line[4..].trim_end_matches(['\r', '\n']).to_string();
            text.push_str(&rest);
            let multiline = line.as_bytes().get(3) == Some(&b'-');
            if !multiline {
                return Ok(Reply { code, text });
            }
            text.push('\n');
        }
    }
}

struct Caps {
    size: bool,
    starttls: bool,
    auth: Vec<String>,
}

fn parse_caps(r: &Reply) -> Caps {
    let mut c = Caps {
        size: false,
        starttls: false,
        auth: Vec::new(),
    };
    for line in r.text.lines() {
        let up = line.to_ascii_uppercase();
        let Some((kw, val)) = up.split_once(' ') else {
            match up.as_str() {
                "SIZE" => c.size = true,
                "STARTTLS" => c.starttls = true,
                _ => {}
            }
            continue;
        };
        match kw {
            "SIZE" => c.size = true,
            "STARTTLS" => c.starttls = true,
            "AUTH" => {
                for m in val.split_whitespace() {
                    if m != "=" && !c.auth.contains(&m.to_string()) {
                        c.auth.push(m.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    c
}

fn ehlo(conn: &mut Conn, host: &str) -> Result<Caps, Fail> {
    conn.send(&format!("EHLO {}", host))
        .map_err(|e| Fail::Temp(e.to_string()))?;
    let r = conn.read_reply().map_err(|e| Fail::Temp(e.to_string()))?;
    if r.code >= 500 {
        // Fall back to HELO.
        conn.send(&format!("HELO {}", host))
            .map_err(|e| Fail::Temp(e.to_string()))?;
        let r2 = conn.read_reply().map_err(|e| Fail::Temp(e.to_string()))?;
        if r2.code != 250 {
            return Err(Fail::Temp(format!("HELO rejected: {} {}", r2.code, r2.text)));
        }
        return Ok(Caps {
            size: false,
            starttls: false,
            auth: Vec::new(),
        });
    }
    if r.code != 250 {
        return Err(Fail::Temp(format!("EHLO rejected: {} {}", r.code, r.text)));
    }
    Ok(parse_caps(&r))
}

fn make_client(cfg: &Config, host: &str) -> Result<ClientConnection, Fail> {
    let config = match &cfg.smarthost_ca_file {
        Some(path) if cfg.smarthost_verify => crate::tls::load_client_config(path)
            .map_err(|e| Fail::Perm(format!("TLS setup: {}", e)))?,
        _ => crate::tls::load_client_config_insecure(),
    };
    let name = crate::tls::server_name(host).map_err(|e| Fail::Perm(e))?;
    Ok(ClientConnection::new(config, name)
        .map_err(|e| Fail::Perm(format!("TLS setup: {}", e)))?)
}

fn connect(cfg: &Config, addr: Ipv4Addr) -> Result<TcpStream, Fail> {
    let sa = SocketAddr::new(IpAddr::V4(addr), cfg.smarthost_port);
    let sock = TcpStream::connect_timeout(&sa, Duration::from_secs(30))
        .map_err(|e| Fail::Temp(format!("connect {}: {}", sa, e)))?;
    sock.set_read_timeout(Some(Duration::from_secs(120)))
        .map_err(|e| Fail::Temp(e.to_string()))?;
    sock.set_write_timeout(Some(Duration::from_secs(120)))
        .map_err(|e| Fail::Temp(e.to_string()))?;
    Ok(sock)
}

/// Greet + (SMTPS/STARTTLS) + EHLO. Returns the connection and caps.
fn setup(cfg: &Config, host: &str, sock: TcpStream) -> Result<(Conn, Caps), Fail> {
    match cfg.smarthost_tls {
        TlsMode::Smtps => {
            let client = make_client(cfg, host)?;
            let tls = StreamOwned::new(client, sock);
            let mut conn = Conn {
                rd: BufReader::new(Transport::Tls(tls)),
                tls_active: true,
            };
            let r = conn.read_reply().map_err(|e| Fail::Temp(format!("SMTPS: {}", e)))?;
            if r.code != 220 {
                return Err(Fail::Temp(format!("greeting: {} {}", r.code, r.text)));
            }
            let caps = ehlo(&mut conn, host)?;
            Ok((conn, caps))
        }
        TlsMode::StartTls => {
            let mut conn = Conn {
                rd: BufReader::new(Transport::Plain(sock)),
                tls_active: false,
            };
            let r = conn.read_reply().map_err(|e| Fail::Temp(e.to_string()))?;
            if r.code != 220 {
                return Err(Fail::Temp(format!("greeting: {} {}", r.code, r.text)));
            }
            let caps = ehlo(&mut conn, host)?;
            if !caps.starttls {
                return Err(Fail::Perm("smarthost does not offer STARTTLS".to_string()));
            }
            conn.send("STARTTLS").map_err(|e| Fail::Temp(e.to_string()))?;
            let r = conn.read_reply().map_err(|e| Fail::Temp(e.to_string()))?;
            if r.code != 220 {
                return Err(Fail::Temp(format!("STARTTLS rejected: {}", r.text)));
            }
            let sock = match conn.rd.into_inner() {
                Transport::Plain(s) => s,
                _ => return Err(Fail::Temp("protocol error".to_string())),
            };
            let client = make_client(cfg, host)?;
            let tls = StreamOwned::new(client, sock);
            let mut conn = Conn {
                rd: BufReader::new(Transport::Tls(tls)),
                tls_active: true,
            };
            let caps = ehlo(&mut conn, host)?;
            Ok((conn, caps))
        }
        TlsMode::None => {
            let mut conn = Conn {
                rd: BufReader::new(Transport::Plain(sock)),
                tls_active: false,
            };
            let r = conn.read_reply().map_err(|e| Fail::Temp(e.to_string()))?;
            if r.code != 220 {
                return Err(Fail::Temp(format!("greeting: {} {}", r.code, r.text)));
            }
            let caps = ehlo(&mut conn, host)?;
            Ok((conn, caps))
        }
    }
}

fn offered(caps: &Caps, m: &str) -> bool {
    caps.auth.iter().any(|a| a.eq_ignore_ascii_case(m))
}

/// Pick the mechanism for the configured mode out of the offered list.
fn pick_mech(cfg: &Config, caps: &Caps) -> Option<&'static str> {
    match cfg.smarthost_auth {
        AuthMode::Auto => ["SCRAM-SHA-256", "CRAM-MD5", "PLAIN", "LOGIN"]
            .iter()
            .find(|m| offered(caps, m))
            .copied(),
        AuthMode::ScramSha256 => offered(caps, "SCRAM-SHA-256").then_some("SCRAM-SHA-256"),
        AuthMode::CramMd5 => offered(caps, "CRAM-MD5").then_some("CRAM-MD5"),
        AuthMode::Plain => offered(caps, "PLAIN").then_some("PLAIN"),
        AuthMode::Login => offered(caps, "LOGIN").then_some("LOGIN"),
        AuthMode::Xoauth2 => offered(caps, "XOAUTH2").then_some("XOAUTH2"),
        AuthMode::None => None,
    }
}

fn auth(conn: &mut Conn, cfg: &Config, caps: &Caps) -> Result<(), Fail> {
    if cfg.smarthost_auth == AuthMode::None {
        return Ok(());
    }
    let (user, pass) = match (&cfg.smarthost_user, &cfg.smarthost_pass) {
        (Some(u), Some(p)) => (u.clone(), p.clone()),
        _ => {
            return Err(Fail::Perm(
                "smarthost_auth configured but no smarthost username/password".to_string(),
            ))
        }
    };
    if !conn.tls_active {
        return Err(Fail::Perm(
            "refusing to send credentials without TLS (set smarthost.tls to smtps or starttls)"
                .to_string(),
        ));
    }
    let Some(mech) = pick_mech(cfg, caps) else {
        return Err(Fail::Perm(format!(
            "smarthost offers none of the configured AUTH mechanisms (offered: {})",
            caps.auth.join(", ")
        )));
    };
    match mech {
        "SCRAM-SHA-256" => auth_scram(conn, &user, &pass),
        "CRAM-MD5" => auth_cram_md5(conn, &user, &pass),
        "PLAIN" => auth_plain(conn, &user, &pass),
        "LOGIN" => auth_login(conn, &user, &pass),
        "XOAUTH2" => auth_xoauth2(conn, &user, &pass),
        _ => Err(Fail::Perm(format!("unsupported mechanism {}", mech))),
    }
}

/// SCRAM-SHA-256 (RFC 7677).
fn auth_scram(conn: &mut Conn, user: &str, pass: &str) -> Result<(), Fail> {
    conn.send("AUTH SCRAM-SHA-256")
        .map_err(|e| Fail::Temp(e.to_string()))?;
    let r = conn.read_reply().map_err(|e| Fail::Temp(e.to_string()))?;
    if r.code != 334 {
        return Err(Fail::Perm(format!("AUTH SCRAM-SHA-256 rejected: {}", r.text)));
    }
    let client_nonce = crate::scram::nonce();
    let client_first = crate::scram::client_first(user, &client_nonce);
    let client_first_bare = client_first.strip_prefix("n,,").unwrap_or(&client_first);
    conn.send(&base64::encode(client_first.as_bytes()))
        .map_err(|e| Fail::Temp(e.to_string()))?;
    let r = conn.read_reply().map_err(|e| Fail::Temp(e.to_string()))?;
    if r.code != 334 {
        return Err(Fail::Perm(format!("SCRAM server-first rejected: {}", r.text)));
    }
    let server_first_msg = match base64::decode(r.text.trim()) {
        Some(b) => String::from_utf8_lossy(&b).into_owned(),
        None => return Err(Fail::Perm("invalid SCRAM server-first base64".to_string())),
    };
    let server_first = crate::scram::parse_server_first(&server_first_msg)
        .map_err(|e| Fail::Perm(format!("SCRAM server-first: {}", e)))?;
    let (client_final, _proof) = crate::scram::client_final(
        pass,
        client_first_bare,
        &server_first,
        &client_nonce,
    )
    .map_err(|e| Fail::Perm(format!("SCRAM: {}", e)))?;
    conn.send(&base64::encode(client_final.as_bytes()))
        .map_err(|e| Fail::Temp(e.to_string()))?;
    let r = conn.read_reply().map_err(|e| Fail::Temp(e.to_string()))?;
    if r.code == 334 {
        // Server-final with signature.
        let server_final = match base64::decode(r.text.trim()) {
            Some(b) => String::from_utf8_lossy(&b).into_owned(),
            None => return Err(Fail::Perm("invalid SCRAM server-final base64".to_string())),
        };
        let auth_message = format!(
            "{},{},{}",
            client_first_bare,
            server_first_msg,
            client_final.split(",p=").next().unwrap_or(&client_final)
        );
        crate::scram::verify_server_final(
            pass,
            &server_first.salt,
            server_first.iterations,
            &auth_message,
            &server_final,
        )
        .map_err(|e| Fail::Perm(format!("SCRAM: {}", e)))?;
        conn.send("").map_err(|e| Fail::Temp(e.to_string()))?;
        let r = conn.read_reply().map_err(|e| Fail::Temp(e.to_string()))?;
        if r.code != 235 {
            return Err(Fail::Perm(format!("SCRAM-SHA-256 authentication failed: {}", r.text)));
        }
    } else if r.code != 235 {
        return Err(Fail::Perm(format!("SCRAM-SHA-256 authentication failed: {}", r.text)));
    }
    Ok(())
}

/// CRAM-MD5 (RFC 2195).
fn auth_cram_md5(conn: &mut Conn, user: &str, pass: &str) -> Result<(), Fail> {
    conn.send("AUTH CRAM-MD5")
        .map_err(|e| Fail::Temp(e.to_string()))?;
    let r = conn.read_reply().map_err(|e| Fail::Temp(e.to_string()))?;
    if r.code != 334 {
        return Err(Fail::Perm(format!("AUTH CRAM-MD5 rejected: {}", r.text)));
    }
    let challenge = match base64::decode(r.text.trim()) {
        Some(c) => c,
        None => return Err(Fail::Perm("invalid CRAM-MD5 challenge".to_string())),
    };
    let digest = md5::hex(&md5::hmac_md5(pass.as_bytes(), &challenge));
    let resp = base64::encode(format!("{} {}", user, digest).as_bytes());
    conn.send(&resp).map_err(|e| Fail::Temp(e.to_string()))?;
    let r = conn.read_reply().map_err(|e| Fail::Temp(e.to_string()))?;
    if r.code != 235 {
        return Err(Fail::Perm(format!("CRAM-MD5 authentication failed: {}", r.text)));
    }
    Ok(())
}

/// PLAIN (RFC 4616): initial response, retry bare on a 334 prompt.
fn auth_plain(conn: &mut Conn, user: &str, pass: &str) -> Result<(), Fail> {
    let creds = base64::encode(format!("\0{}\0{}", user, pass).as_bytes());
    conn.send(&format!("AUTH PLAIN {}", creds))
        .map_err(|e| Fail::Temp(e.to_string()))?;
    let r = conn.read_reply().map_err(|e| Fail::Temp(e.to_string()))?;
    if r.code == 334 {
        conn.send(&creds).map_err(|e| Fail::Temp(e.to_string()))?;
        let r = conn.read_reply().map_err(|e| Fail::Temp(e.to_string()))?;
        if r.code != 235 {
            return Err(Fail::Perm(format!("PLAIN authentication failed: {}", r.text)));
        }
    } else if r.code != 235 {
        return Err(Fail::Perm(format!("PLAIN authentication failed: {}", r.text)));
    }
    Ok(())
}

/// LOGIN (the traditional Microsoft mechanism): separate username and
/// password prompts.
fn auth_login(conn: &mut Conn, user: &str, pass: &str) -> Result<(), Fail> {
    conn.send("AUTH LOGIN").map_err(|e| Fail::Temp(e.to_string()))?;
    let r = conn.read_reply().map_err(|e| Fail::Temp(e.to_string()))?;
    if r.code == 334 {
        conn.send(&base64::encode(user.as_bytes()))
            .map_err(|e| Fail::Temp(e.to_string()))?;
        let r = conn.read_reply().map_err(|e| Fail::Temp(e.to_string()))?;
        if r.code != 334 {
            return Err(Fail::Perm(format!("LOGIN authentication failed: {}", r.text)));
        }
        conn.send(&base64::encode(pass.as_bytes()))
            .map_err(|e| Fail::Temp(e.to_string()))?;
        let r = conn.read_reply().map_err(|e| Fail::Temp(e.to_string()))?;
        if r.code != 235 {
            return Err(Fail::Perm(format!("LOGIN authentication failed: {}", r.text)));
        }
    } else if r.code != 235 {
        return Err(Fail::Perm(format!("LOGIN authentication failed: {}", r.text)));
    }
    Ok(())
}

/// XOAUTH2 (OAuth 2.0 bearer token; `password` holds the access token).
fn auth_xoauth2(conn: &mut Conn, user: &str, token: &str) -> Result<(), Fail> {
    let init = base64::encode(
        format!("user={}\x01auth=Bearer {}\x01\x01", user, token).as_bytes(),
    );
    conn.send(&format!("AUTH XOAUTH2 {}", init))
        .map_err(|e| Fail::Temp(e.to_string()))?;
    let r = conn.read_reply().map_err(|e| Fail::Temp(e.to_string()))?;
    if r.code == 334 {
        // Error continuation: an empty response acknowledges failure.
        conn.send("").map_err(|e| Fail::Temp(e.to_string()))?;
        let r = conn.read_reply().map_err(|e| Fail::Temp(e.to_string()))?;
        return Err(Fail::Perm(format!("XOAUTH2 authentication failed: {}", r.text)));
    }
    if r.code != 235 {
        return Err(Fail::Perm(format!("XOAUTH2 authentication failed: {}", r.text)));
    }
    Ok(())
}

fn write_message(conn: &mut Conn, msg: &[u8]) -> std::io::Result<()> {
    // msg is CRLF-normalized and normally ends with CRLF. Each line is
    // dot-stuffed per RFC 5321 and re-terminated with CRLF.
    let mut rest = msg;
    while !rest.is_empty() {
        let Some(pos) = rest.iter().position(|&b| b == b'\n') else {
            break;
        };
        let (line, tail) = rest.split_at(pos + 1);
        let line = line.strip_suffix(b"\n").unwrap_or(line);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.starts_with(b".") {
            conn.rd.get_mut().write_all(b".")?;
        }
        conn.rd.get_mut().write_all(line)?;
        conn.rd.get_mut().write_all(b"\r\n")?;
        rest = tail;
    }
    // Defensive: a final line without a newline.
    if !rest.is_empty() {
        let line = rest.strip_suffix(b"\r").unwrap_or(rest);
        if line.starts_with(b".") {
            conn.rd.get_mut().write_all(b".")?;
        }
        conn.rd.get_mut().write_all(line)?;
        conn.rd.get_mut().write_all(b"\r\n")?;
    }
    conn.rd.get_mut().write_all(b".\r\n")?;
    conn.rd.get_mut().flush()
}

fn try_addr(
    cfg: &Config,
    host: &str,
    addr: Ipv4Addr,
    sender: &str,
    rcpts: &[String],
    msg: &[u8],
) -> Result<Vec<RcptFail>, Fail> {
    let sock = connect(cfg, addr)?;
    let (mut conn, caps) = setup(cfg, host, sock)?;
    auth(&mut conn, cfg, &caps)?;

    let mut cmd = format!("MAIL FROM:<{}>", sender);
    if caps.size {
        cmd.push_str(&format!(" SIZE={}", msg.len()));
    }
    conn.send(&cmd).map_err(|e| Fail::Temp(e.to_string()))?;
    let r = conn.read_reply().map_err(|e| Fail::Temp(e.to_string()))?;
    if r.code >= 400 {
        let fails: Vec<RcptFail> = rcpts
            .iter()
            .map(|rcpt| RcptFail {
                rcpt: rcpt.clone(),
                code: r.code,
                text: r.text.clone(),
            })
            .collect();
        return if r.code >= 500 {
            Ok(fails)
        } else {
            Err(Fail::Temp(format!("MAIL FROM: {} {}", r.code, r.text)))
        };
    }

    let mut accepted: Vec<String> = Vec::new();
    let mut fails: Vec<RcptFail> = Vec::new();
    for rcpt in rcpts {
        conn.send(&format!("RCPT TO:<{}>", rcpt))
            .map_err(|e| Fail::Temp(e.to_string()))?;
        let r = conn.read_reply().map_err(|e| Fail::Temp(e.to_string()))?;
        match r.code {
            250 | 251 | 252 => accepted.push(rcpt.clone()),
            400..=499 => {
                return Err(Fail::Temp(format!(
                    "temporary failure for {}: {} {}",
                    rcpt, r.code, r.text
                )))
            }
            _ => fails.push(RcptFail {
                rcpt: rcpt.clone(),
                code: r.code,
                text: r.text.clone(),
            }),
        }
    }
    if accepted.is_empty() {
        let _ = conn.send("QUIT");
        return Ok(fails);
    }

    conn.send("DATA").map_err(|e| Fail::Temp(e.to_string()))?;
    let r = conn.read_reply().map_err(|e| Fail::Temp(e.to_string()))?;
    if r.code != 354 {
        return Err(if r.code >= 500 { Fail::Perm } else { Fail::Temp }(format!(
            "DATA rejected: {} {}",
            r.code, r.text
        )));
    }
    write_message(&mut conn, msg).map_err(|e| Fail::Temp(format!("sending message: {}", e)))?;
    let r = conn.read_reply().map_err(|e| Fail::Temp(e.to_string()))?;
    if r.code >= 400 {
        for rcpt in accepted {
            fails.push(RcptFail {
                rcpt,
                code: r.code,
                text: r.text.clone(),
            });
        }
    }
    let _ = conn.send("QUIT");
    Ok(fails)
}

/// Deliver to the smarthost. Returns per-recipient permanent failures;
/// Ok(vec![]) means full success.
pub fn deliver(
    cfg: &Arc<Config>,
    sender: &str,
    rcpts: &[String],
    msg: &[u8],
) -> Result<Vec<RcptFail>, Fail> {
    let host = match &cfg.smarthost {
        Some(h) => h.clone(),
        None => return Err(Fail::Perm("no smarthost configured".to_string())),
    };
    let addrs = match crate::dns::resolve_a(&host) {
        Ok(a) => a,
        Err(e) => return Err(Fail::Temp(e)),
    };
    let mut last_temp: Option<String> = None;
    for a in addrs {
        match try_addr(cfg, &host, a, sender, rcpts, msg) {
            Ok(fails) => return Ok(fails),
            Err(Fail::Perm(e)) => return Err(Fail::Perm(e)),
            Err(Fail::Temp(e)) => last_temp = Some(e),
        }
    }
    Err(Fail::Temp(
        last_temp.unwrap_or_else(|| "smarthost unreachable".to_string()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_parsing() {
        let r = Reply {
            code: 250,
            text: "host Hello\nSIZE 52428800\n8BITMIME\nAUTH CRAM-MD5 PLAIN\nSTARTTLS".to_string(),
        };
        let c = parse_caps(&r);
        assert!(c.size);
        assert!(c.starttls);
        assert_eq!(c.auth, vec!["CRAM-MD5".to_string(), "PLAIN".to_string()]);
    }

    #[test]
    fn cram_md5_response_format() {
        // The wire response is base64("user hexdigest").
        let challenge = b"<123@x>";
        let digest = md5::hex(&md5::hmac_md5(b"pass", challenge));
        let resp = format!("{} {}", "user", digest);
        let b64 = base64::encode(resp.as_bytes());
        let decoded = base64::decode(&b64).unwrap();
        assert_eq!(
            String::from_utf8(decoded).unwrap(),
            format!("user {}", md5::hex(&md5::hmac_md5(b"pass", challenge)))
        );
    }
}
