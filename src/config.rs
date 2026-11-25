//! Configuration loading from JSONC (JSON with comments), plus IPv4
//! host-list matching for relay control.
//!
//! Example structure (see homemta.jsonc.example):
//! {
//!   "primary_hostname": "jelaas.eu",
//!   "local_domains": ["@", "jelaas.eu"],
//!   "relay_from_hosts": ["127.0.0.1", "10.0.0.53"],
//!   "listen_addr": "0.0.0.0",
//!   "listen_ports": [25],
//!   "smarthost": { "host": "...", "port": 465, "tls": "smtps", ... },
//!   "tls": { "cert": "...", "key": "..." },
//!   ...
//! }

use crate::jsonc::Json;
use std::net::Ipv4Addr;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TlsMode {
    Smtps,
    StartTls,
    None,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuthMode {
    Auto,
    ScramSha256,
    CramMd5,
    Plain,
    Login,
    Xoauth2,
    None,
}

#[derive(Debug)]
pub struct Config {
    pub primary_hostname: String,
    pub local_domains: Vec<String>,
    /// Hosts (exact IPs or CIDR) allowed to submit mail to any domain.
    /// Everyone else may only send to local domains (no relaying).
    pub relay_from_hosts: Vec<String>,
    pub listen_addr: String,
    pub listen_ports: Vec<u16>,
    pub spool_dir: String,
    pub mailbox_dir: String,
    pub aliases_file: String,
    pub passwd_file: String,
    pub group_file: String,
    pub log_file: Option<String>,
    pub max_message_size: u64,
    pub smarthost: Option<String>,
    pub smarthost_port: u16,
    pub smarthost_tls: TlsMode,
    pub smarthost_auth: AuthMode,
    pub smarthost_user: Option<String>,
    pub smarthost_pass: Option<String>,
    pub smarthost_ca_file: Option<String>,
    pub smarthost_verify: bool,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    /// Unprivileged identity the daemon drops to after binding (the classic
    /// "mail" user). Use "root" to explicitly keep running as root.
    pub user: String,
    /// Group for the daemon (defaults to the user's primary gid).
    pub group: Option<String>,
    /// Setuid-root helper used to deliver user-owned mailboxes.
    pub deliver_helper: String,
    /// Never run a delivery as these users (the classic never_users rule).
    pub never_users: Vec<String>,
    /// Path of the loaded config file (set at startup, not from the file).
    pub config_path: String,
    /// Optional pid file written after startup and removed on shutdown
    /// (also settable via --pidfile).
    pub pid_file: Option<String>,
    /// Seconds between queue scans.
    pub queue_interval: u64,
    /// Retry interval for the first 2h after first failure (seconds).
    pub retry_first_interval: u64,
    /// Total time a message is retried before it bounces (seconds).
    pub retry_timeout: u64,
    /// Freeze bounce messages after this long (seconds).
    pub bounce_freeze_after: u64,
    /// Delete frozen bounce messages after this long (seconds).
    pub frozen_timeout: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            primary_hostname: hostname(),
            local_domains: vec!["@".to_string()],
            relay_from_hosts: vec!["127.0.0.1".to_string()],
            listen_addr: "0.0.0.0".to_string(),
            listen_ports: vec![25],
            spool_dir: "/var/spool/homemta".to_string(),
            mailbox_dir: "/var/spool/mail".to_string(),
            aliases_file: "/etc/aliases".to_string(),
            passwd_file: "/etc/passwd".to_string(),
            group_file: "/etc/group".to_string(),
            log_file: Some("/var/log/homemta.log".to_string()),
            max_message_size: 64 * 1024 * 1024,
            smarthost: None,
            smarthost_port: 465,
            smarthost_tls: TlsMode::Smtps,
            smarthost_auth: AuthMode::Auto,
            smarthost_user: None,
            smarthost_pass: None,
            smarthost_ca_file: Some("/etc/ssl/certs/ca-certificates.crt".to_string()),
            smarthost_verify: true,
            tls_cert: None,
            tls_key: None,
            user: "mail".to_string(),
            group: None,
            deliver_helper: "/usr/local/libexec/homemta-deliver".to_string(),
            never_users: vec!["root".to_string()],
            config_path: String::new(),
            pid_file: None,
            queue_interval: 30,
            retry_first_interval: 900,
            retry_timeout: 4 * 24 * 3600,
            bounce_freeze_after: 2 * 24 * 3600,
            frozen_timeout: 7 * 24 * 3600,
        }
    }
}

fn want_str(key: &str, v: &Json) -> Result<String, String> {
    v.as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| format!("`{}` must be a string", key))
}

fn want_str_list(key: &str, v: &Json) -> Result<Vec<String>, String> {
    let arr = v
        .as_arr()
        .ok_or_else(|| format!("`{}` must be an array of strings", key))?;
    let mut out = Vec::new();
    for (i, item) in arr.iter().enumerate() {
        out.push(
            item.as_str()
                .map(|s| s.to_string())
                .ok_or_else(|| format!("`{}[{}]` must be a string", key, i))?,
        );
    }
    Ok(out)
}

fn want_u64(key: &str, v: &Json) -> Result<u64, String> {
    v.as_u64()
        .ok_or_else(|| format!("`{}` must be a non-negative integer", key))
}

fn want_u16_list(key: &str, v: &Json) -> Result<Vec<u16>, String> {
    let arr = v
        .as_arr()
        .ok_or_else(|| format!("`{}` must be an array of ports", key))?;
    let mut out = Vec::new();
    for (i, item) in arr.iter().enumerate() {
        let n = item
            .as_u64()
            .ok_or_else(|| format!("`{}[{}]` must be an integer", key, i))?;
        if n == 0 || n > 65535 {
            return Err(format!("`{}[{}]` is not a valid port", key, i));
        }
        out.push(n as u16);
    }
    if out.is_empty() {
        return Err(format!("`{}` must not be empty", key));
    }
    Ok(out)
}

/// Accepts a size as a number of bytes or a string with a K/M/G suffix.
fn want_size(key: &str, v: &Json) -> Result<u64, String> {
    match v {
        Json::Num(_) => want_u64(key, v),
        Json::Str(s) => parse_size(s).map_err(|e| format!("`{}`: {}", key, e)),
        _ => Err(format!("`{}` must be a size (\"64M\") or integer", key)),
    }
}

/// Accepts a duration as seconds or a string with s/m/h/d/w suffix.
fn want_duration(key: &str, v: &Json) -> Result<u64, String> {
    match v {
        Json::Num(_) => want_u64(key, v),
        Json::Str(s) => parse_duration(s).map_err(|e| format!("`{}`: {}", key, e)),
        _ => Err(format!("`{}` must be a duration (\"4d\") or seconds", key)),
    }
}

fn want_bool(key: &str, v: &Json) -> Result<bool, String> {
    v.as_bool()
        .ok_or_else(|| format!("`{}` must be true or false", key))
}

impl Config {
    /// Parse JSONC config text over the defaults. Returns warnings.
    pub fn parse(&mut self, text: &str) -> Vec<String> {
        let mut warnings = Vec::new();
        let value = match crate::jsonc::parse(text) {
            Ok(v) => v,
            Err(e) => {
                return vec![format!("config parse error: {}", e)];
            }
        };
        let Json::Obj(map) = value else {
            return vec!["config must be a JSON object".to_string()];
        };
        for (key, v) in &map {
            let r = match key.as_str() {
                "primary_hostname" => want_str(key, v).map(|s| self.primary_hostname = s),
                "local_domains" => want_str_list(key, v).map(|l| self.local_domains = l),
                "relay_from_hosts" => want_str_list(key, v).map(|l| self.relay_from_hosts = l),
                "listen_addr" | "listen_address" => want_str(key, v).map(|s| self.listen_addr = s),
                "listen_ports" => want_u16_list(key, v).map(|l| self.listen_ports = l),
                "spool_dir" => want_str(key, v).map(|s| self.spool_dir = s),
                "mailbox_dir" => want_str(key, v).map(|s| self.mailbox_dir = s),
                "aliases_file" => want_str(key, v).map(|s| self.aliases_file = s),
                "passwd_file" => want_str(key, v).map(|s| self.passwd_file = s),
                "group_file" => want_str(key, v).map(|s| self.group_file = s),
                "log_file" => match v {
                    Json::Null => Ok(self.log_file = None),
                    _ => want_str(key, v).map(|s| self.log_file = Some(s)),
                },
                "max_message_size" => want_size(key, v).map(|n| self.max_message_size = n),
                "user" => want_str(key, v).map(|s| self.user = s),
                "group" => match v {
                    Json::Null => Ok(self.group = None),
                    _ => want_str(key, v).map(|s| self.group = Some(s)),
                },
                "deliver_helper" => want_str(key, v).map(|s| self.deliver_helper = s),
                "never_users" => want_str_list(key, v).map(|l| self.never_users = l),
                "pid_file" => match v {
                    Json::Null => Ok(self.pid_file = None),
                    _ => want_str(key, v).map(|s| self.pid_file = Some(s)),
                },
                "queue_interval" => {
                    want_u64(key, v).and_then(|n| {
                        if n > 0 {
                            self.queue_interval = n;
                            Ok(())
                        } else {
                            Err(format!("`{}` must be > 0", key))
                        }
                    })
                }
                "retry_first_interval" => want_duration(key, v)
                    .and_then(|n| {
                        if n > 0 {
                            self.retry_first_interval = n;
                            Ok(())
                        } else {
                            Err(format!("`{}` must be > 0", key))
                        }
                    }),
                "retry_timeout" => want_duration(key, v).map(|n| self.retry_timeout = n),
                "bounce_freeze_after" => {
                    want_duration(key, v).map(|n| self.bounce_freeze_after = n)
                }
                "frozen_timeout" => want_duration(key, v).map(|n| self.frozen_timeout = n),
                "smarthost" => self.apply_smarthost(key, v),
                "tls" => self.apply_tls(key, v),
                _ => Err(format!("unknown option `{}`", key)),
            };
            if let Err(e) = r {
                warnings.push(e);
            }
        }
        // Expand "@" in local_domains to the primary hostname, dedupe.
        let host = self.primary_hostname.clone();
        let mut seen = std::collections::HashSet::new();
        let mut domains = Vec::new();
        for d in &self.local_domains {
            let d = if d == "@" { host.clone() } else { d.clone() };
            let d = d.trim().to_ascii_lowercase();
            if !d.is_empty() && seen.insert(d.clone()) {
                domains.push(d);
            }
        }
        self.local_domains = domains;
        warnings
    }

    fn apply_smarthost(&mut self, key: &str, v: &Json) -> Result<(), String> {
        match v {
            // Shorthand: "smarthost": "mail.example.com" (host only).
            Json::Str(h) => {
                self.smarthost = if h.is_empty() { None } else { Some(h.to_string()) };
                Ok(())
            }
            Json::Null => {
                self.smarthost = None;
                Ok(())
            }
            Json::Obj(map) => {
                let mut r = Ok(());
                for (k, v) in map {
                    let step = match k.as_str() {
                        "host" => want_str("smarthost.host", v).map(|s| self.smarthost = Some(s)),
                        "port" => want_u16_list("smarthost.port", &Json::Arr(vec![v.clone()]))
                            .map(|l| self.smarthost_port = l[0]),
                        "tls" => match want_str("smarthost.tls", v)?.to_ascii_lowercase().as_str() {
                            "smtps" => Ok(self.smarthost_tls = TlsMode::Smtps),
                            "starttls" => Ok(self.smarthost_tls = TlsMode::StartTls),
                            "none" | "off" => Ok(self.smarthost_tls = TlsMode::None),
                            other => Err(format!("smarthost.tls must be smtps, starttls or none, got `{}`", other)),
                        },
                        "auth" => match want_str("smarthost.auth", v)?.to_ascii_lowercase().as_str() {
                            "auto" => Ok(self.smarthost_auth = AuthMode::Auto),
                            "scram-sha-256" | "scram_sha_256" | "scram" => {
                                Ok(self.smarthost_auth = AuthMode::ScramSha256)
                            }
                            "cram-md5" | "cram_md5" => Ok(self.smarthost_auth = AuthMode::CramMd5),
                            "plain" => Ok(self.smarthost_auth = AuthMode::Plain),
                            "login" => Ok(self.smarthost_auth = AuthMode::Login),
                            "xoauth2" | "oauth2" => Ok(self.smarthost_auth = AuthMode::Xoauth2),
                            "none" | "off" => Ok(self.smarthost_auth = AuthMode::None),
                            other => Err(format!("unknown smarthost.auth `{}`", other)),
                        },
                        "username" | "user" => {
                            want_str("smarthost.username", v).map(|s| self.smarthost_user = Some(s))
                        }
                        "password" | "pass" => {
                            want_str("smarthost.password", v).map(|s| self.smarthost_pass = Some(s))
                        }
                        "ca_file" => match v {
                            Json::Null => Ok(self.smarthost_ca_file = None),
                            _ => want_str("smarthost.ca_file", v)
                                .map(|s| self.smarthost_ca_file = Some(s)),
                        },
                        "verify" => want_bool("smarthost.verify", v)
                            .map(|b| self.smarthost_verify = b),
                        _ => Err(format!("unknown option `smarthost.{}`", k)),
                    };
                    if let Err(e) = step {
                        r = Err(e);
                    }
                }
                r
            }
            _ => Err(format!("`{}` must be a string or object", key)),
        }
    }

    fn apply_tls(&mut self, key: &str, v: &Json) -> Result<(), String> {
        match v {
            Json::Null => Ok(()),
            Json::Obj(map) => {
                let mut r = Ok(());
                for (k, v) in map {
                    let step = match k.as_str() {
                        "cert" | "certificate" => {
                            want_str("tls.cert", v).map(|s| self.tls_cert = Some(s))
                        }
                        "key" => want_str("tls.key", v).map(|s| self.tls_key = Some(s)),
                        _ => Err(format!("unknown option `tls.{}`", k)),
                    };
                    if let Err(e) = step {
                        r = Err(e);
                    }
                }
                r
            }
            _ => Err(format!("`{}` must be an object", key)),
        }
    }

    pub fn is_local_domain(&self, domain: &str) -> bool {
        self.local_domains
            .iter()
            .any(|d| d.eq_ignore_ascii_case(domain))
    }
}

/// Match an IPv4 address against a host list (exact IPs or CIDR ranges).
pub fn match_host_list(list: &[String], ip: &Ipv4Addr) -> bool {
    list.iter().any(|e| {
        let e = e.trim();
        if let Some((net, bits)) = e.split_once('/') {
            let (Ok(net), Ok(bits)) = (net.parse::<Ipv4Addr>(), bits.parse::<u32>()) else {
                return false;
            };
            if bits > 32 {
                return false;
            }
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            u32::from(*ip) & mask == u32::from(net) & mask
        } else {
            e.parse::<Ipv4Addr>().map(|a| a == *ip).unwrap_or(false)
        }
    })
}

/// Parse a size: plain bytes, or with K/M/G suffix.
pub fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (num, mult) = match s.chars().last() {
        Some('k') | Some('K') => (&s[..s.len() - 1], 1024u64),
        Some('m') | Some('M') => (&s[..s.len() - 1], 1024 * 1024),
        Some('g') | Some('G') => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        _ => (s, 1),
    };
    num.trim()
        .parse::<u64>()
        .map(|n| n * mult)
        .map_err(|_| format!("invalid size: {}", s))
}

/// Parse a duration in seconds, or with s/m/h/d/w suffixes.
pub fn parse_duration(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (num, mult) = match s.chars().last() {
        Some('s') | Some('S') => (&s[..s.len() - 1], 1u64),
        Some('m') | Some('M') => (&s[..s.len() - 1], 60),
        Some('h') | Some('H') => (&s[..s.len() - 1], 3600),
        Some('d') | Some('D') => (&s[..s.len() - 1], 86400),
        Some('w') | Some('W') => (&s[..s.len() - 1], 7 * 86400),
        _ => (s, 1),
    };
    num.trim()
        .parse::<u64>()
        .map(|n| n * mult)
        .map_err(|_| format!("invalid duration: {}", s))
}

/// Hostname for defaults, via musl gethostname.
pub fn hostname() -> String {
    let mut buf = [0u8; 256];
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if rc == 0 {
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        if end > 0 {
            return String::from_utf8_lossy(&buf[..end]).into_owned();
        }
    }
    "localhost".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_and_durations() {
        assert_eq!(parse_size("100").unwrap(), 100);
        assert_eq!(parse_size("64M").unwrap(), 64 * 1024 * 1024);
        assert_eq!(parse_size("1G").unwrap(), 1024 * 1024 * 1024);
        assert!(parse_size("12X").is_err());
        assert_eq!(parse_duration("30").unwrap(), 30);
        assert_eq!(parse_duration("2h").unwrap(), 7200);
        assert_eq!(parse_duration("4d").unwrap(), 345600);
    }

    #[test]
    fn full_config() {
        let mut c = Config::default();
        c.primary_hostname = "host.example".to_string();
        let w = c.parse(
            r#"{
            // home server
            "primary_hostname": "jelaas.eu",
            "local_domains": ["@", "xn--ls-yiaa.eu", "jelaas.eu"],
            "relay_from_hosts": ["127.0.0.1", "10.0.0.53"],
            "listen_addr": "0.0.0.0",
            "listen_ports": [25],
            "max_message_size": "10M",
            "smarthost": {
                "host": "mailout.privat.bahnhof.se",
                "port": 465,
                "tls": "smtps",
                "auth": "auto",
                "username": "bob",
                "password": "secret",
            },
            "tls": { "cert": "/etc/ssl/x.crt", "key": "/etc/ssl/x.key" },
            "retry_timeout": "2d",
            "unknown_key": 1,
        }"#,
        );
        assert_eq!(c.primary_hostname, "jelaas.eu");
        assert_eq!(
            c.local_domains,
            vec!["jelaas.eu".to_string(), "xn--ls-yiaa.eu".to_string()]
        );
        assert_eq!(c.relay_from_hosts, vec!["127.0.0.1", "10.0.0.53"]);
        assert_eq!(c.listen_addr, "0.0.0.0");
        assert_eq!(c.listen_ports, vec![25]);
        assert_eq!(c.max_message_size, 10 * 1024 * 1024);
        assert_eq!(c.smarthost.as_deref(), Some("mailout.privat.bahnhof.se"));
        assert_eq!(c.smarthost_port, 465);
        assert_eq!(c.smarthost_tls, TlsMode::Smtps);
        assert_eq!(c.smarthost_auth, AuthMode::Auto);
        assert_eq!(c.smarthost_user.as_deref(), Some("bob"));
        assert_eq!(c.smarthost_pass.as_deref(), Some("secret"));
        assert_eq!(c.tls_cert.as_deref(), Some("/etc/ssl/x.crt"));
        assert_eq!(c.retry_timeout, 172800);
        assert!(c.is_local_domain("JELAAS.EU"));
        assert!(!c.is_local_domain("other.eu"));
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("unknown_key"));
    }

    #[test]
    fn smarthost_shorthand_and_auth_modes() {
        let mut c = Config::default();
        c.parse(r#"{ "smarthost": "mx.example.net" }"#);
        assert_eq!(c.smarthost.as_deref(), Some("mx.example.net"));
        c.parse(r#"{ "smarthost": { "host": "h", "auth": "scram-sha-256" } }"#);
        assert_eq!(c.smarthost_auth, AuthMode::ScramSha256);
        c.parse(r#"{ "smarthost": { "auth": "login" } }"#);
        assert_eq!(c.smarthost_auth, AuthMode::Login);
        c.parse(r#"{ "smarthost": { "auth": "xoauth2" } }"#);
        assert_eq!(c.smarthost_auth, AuthMode::Xoauth2);
        c.parse(r#"{ "smarthost": null }"#);
        assert!(c.smarthost.is_none());
        assert!(c.parse(r#"{ "smarthost": { "auth": "bogus" } }"#).len() == 1);
    }

    #[test]
    fn jsonc_parse_error_reported() {
        let mut c = Config::default();
        let w = c.parse(r#"{ "a": }"#);
        assert!(w[0].contains("config parse error"));
    }

    #[test]
    fn host_list_matching() {
        let list = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let ip = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        let l = list(&["127.0.0.1", "10.0.0.53", "192.168.0.0/16"]);
        assert!(match_host_list(&l, &ip("127.0.0.1")));
        assert!(match_host_list(&l, &ip("10.0.0.53")));
        assert!(!match_host_list(&l, &ip("10.0.0.54")));
        assert!(match_host_list(&l, &ip("192.168.1.42")));
        assert!(!match_host_list(&l, &ip("192.169.1.42")));
        assert!(!match_host_list(&l, &ip("8.8.8.8")));
        // CIDR edge cases.
        let l32 = list(&["10.1.2.3/32"]);
        assert!(match_host_list(&l32, &ip("10.1.2.3")));
        assert!(!match_host_list(&l32, &ip("10.1.2.4")));
        let l0 = list(&["0.0.0.0/0"]);
        assert!(match_host_list(&l0, &ip("203.0.113.7")));
        // Garbage entries never match.
        let bad = list(&["not-an-ip"]);
        assert!(!match_host_list(&bad, &ip("127.0.0.1")));
    }
}
