//! Delivery-failure report generation (RFC 3464 multipart/report).

use crate::log;

pub struct Failure {
    pub rcpt: String,
    pub reason: String,
}

fn msgid(host: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    format!("<E{:x}{:08x}@{}>", crate::log::unix_now(), n % 0xffff_ffff, host)
}

/// Build a bounce message addressed to `sender` reporting `failures`.
/// The returned bytes are CRLF-normalized.
pub fn build(hostname: &str, sender: &str, failures: &[Failure], original: &[u8]) -> Vec<u8> {
    let boundary = format!("homemta-{:x}", crate::log::unix_now());
    let mut m = String::new();
    m.push_str(&format!(
        "Return-path: <>\r\n\
         From: Mail Delivery System <Mailer-Daemon@{}>\r\n\
         To: {}\r\n\
         Subject: Mail delivery failed: returning message to sender\r\n\
         Date: {}\r\n\
         Message-ID: {}\r\n\
         Auto-Submitted: auto-replied\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: multipart/report; report-type=delivery-status; boundary={}\r\n\
         \r\n\
         This is a MIME-encapsulated message.\r\n\
         \r\n\
         --{}\r\n\
         Content-Type: text/plain; charset=us-ascii\r\n\
         \r\n\
         This message was created automatically by mail delivery software.\r\n\
         \r\n\
         A message that you sent could not be delivered to one or more of its\r\n\
         recipients. This is a permanent error. The following address(es) failed:\r\n\
         \r\n",
        hostname,
        sender,
        crate::log::rfc2822_now(),
        msgid(hostname),
        boundary,
        boundary
    ));
    for f in failures {
        m.push_str(&format!("  {}\r\n    {}\r\n\r\n", f.rcpt, f.reason));
    }
    m.push_str(&format!(
        "--{}\r\n\
         Content-Type: message/delivery-status\r\n\
         \r\n\
         Reporting-MTA: dns; {}\r\n\
         \r\n",
        boundary, hostname
    ));
    for f in failures {
        m.push_str(&format!(
            "Final-Recipient: rfc822; {}\r\n\
             Action: failed\r\n\
             Status: 5.0.0\r\n\
             Diagnostic-Code: smtp; {}\r\n\
             \r\n",
            f.rcpt, f.reason
        ));
    }
    m.push_str(&format!(
        "--{}\r\n\
         Content-Type: message/rfc822\r\n\
         \r\n",
        boundary
    ));
    let mut out = m.into_bytes();
    out.extend_from_slice(original);
    if !out.ends_with(b"\r\n") {
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("\r\n--{}--\r\n", boundary).as_bytes());
    out
}

/// Deliver a bounce (or any generated message) to `rcpt` using the same
/// routing as normal mail. Envelope sender is empty to prevent loops.
/// Logs rather than recursing on failure.
pub fn deliver(
    cfg: &std::sync::Arc<crate::config::Config>,
    rcpt: &str,
    body: &[u8],
    wake: &std::sync::mpsc::Sender<()>,
) {
    match crate::address::parse(&format!("<{}>", rcpt)) {
        Ok(addr) => {
            if cfg.is_local_domain(&addr.domain) {
                match crate::routing::deliver_local(cfg, "", rcpt, body) {
                    Ok(remote) => {
                        for r in remote {
                            let _ = crate::queue::enqueue(cfg, "", &[r], body);
                        }
                        let _ = wake.send(());
                    }
                    Err(e) => log::warn(&format!("bounce to {} undeliverable, dropping: {}", rcpt, e)),
                }
            } else {
                match crate::queue::enqueue(cfg, "", &[rcpt.to_string()], body) {
                    Ok(()) => {
                        let _ = wake.send(());
                    }
                    Err(e) => log::warn(&format!("cannot queue bounce to {}: {}", rcpt, e)),
                }
            }
        }
        Err(e) => log::warn(&format!("cannot bounce to malformed address {}: {}", rcpt, e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounce_shape() {
        let b = build(
            "host.example",
            "sender@example.com",
            &[Failure {
                rcpt: "x@y.z".to_string(),
                reason: "550 no such user".to_string(),
            }],
            b"Subject: hi\r\n\r\nbody\r\n",
        );
        let s = String::from_utf8(b).unwrap();
        assert!(s.contains("Return-path: <>"));
        assert!(s.contains("Mail delivery failed"));
        assert!(s.contains("Final-Recipient: rfc822; x@y.z"));
        assert!(s.contains("Diagnostic-Code: smtp; 550 no such user"));
        assert!(s.contains("Content-Type: message/rfc822"));
        assert!(s.contains("Subject: hi"));
        assert!(s.ends_with("\r\n"));
        assert!(s.contains("--"));
    }
}
