//! Local routing: /etc/aliases, ~/.forward, and delivery into the
//! traditional BSD mailbox format (readable by Dovecot) under the mailbox
//! directory.
//!
//! Message bodies are carried around CRLF-normalized (as received via SMTP);
//! mbox files are written with LF line endings and `>From ` escaping,
//! matching the classic appendfile transports that Dovecot reads.

use crate::address::{strip_suffix, Addr};
use crate::config::Config;
use crate::log;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct User {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
}

#[derive(Debug)]
pub enum Target {
    /// Deliver to the user's mbox file.
    Mbox { user: User, addr: String },
    /// Remote address discovered via alias/forward: goes to the smarthost.
    RemoteAddr(String),
    /// Append to an arbitrary file (alias/forward file target).
    File { path: String },
    /// Pipe the message through a shell command.
    Pipe { cmd: String },
    /// :blackhole:
    Blackhole,
}

/// Parse one passwd entry. Fields: name:passwd:uid:gid:gecos:home:shell
pub fn getpwnam(cfg: &Config, name: &str) -> Option<User> {
    let text = std::fs::read_to_string(&cfg.passwd_file).ok()?;
    for line in text.lines() {
        let f: Vec<&str> = line.splitn(7, ':').collect();
        if f.len() >= 6 && f[0] == name {
            return Some(User {
                name: f[0].to_string(),
                uid: f[2].parse().unwrap_or(0),
                gid: f[3].parse().unwrap_or(0),
                home: f[5].to_string(),
            });
        }
    }
    None
}

/// Look up a group id by name.
pub fn getgrnam(cfg: &Config, name: &str) -> Option<u32> {
    let text = std::fs::read_to_string(&cfg.group_file).ok()?;
    for line in text.lines() {
        let f: Vec<&str> = line.splitn(4, ':').collect();
        if f.len() >= 3 && f[0] == name {
            return f[2].parse().ok();
        }
    }
    None
}

/// Resolve a local user id for pipes/files from /etc/aliases.

/// Verify that a local recipient is deliverable (used at RCPT time).
/// Verifies recipients the classic way (verify = recipient): alias hit,
/// or a real local user,
/// or postmaster (always accepted per the ACL).
pub fn verify_local(cfg: &Config, local: &str) -> bool {
    if alias_lookup(cfg, local).is_some() {
        return true;
    }
    if getpwnam(cfg, strip_suffix(local)).is_some() {
        return true;
    }
    local.eq_ignore_ascii_case("postmaster")
}

/// Expand a local address into concrete delivery targets, following
/// /etc/aliases and ~/.forward with loop detection.
pub fn expand(cfg: &Config, addr: &Addr, chain: &mut Vec<String>) -> Result<Vec<Target>, String> {
    let key = format!("{}@{}", addr.local.to_lowercase(), addr.domain.to_lowercase());
    if chain.contains(&key) {
        return Err(format!("alias/forward loop involving {}", addr.full()));
    }
    chain.push(key);
    let r = expand_inner(cfg, addr, chain);
    chain.pop();
    r
}

fn expand_inner(cfg: &Config, addr: &Addr, chain: &mut Vec<String>) -> Result<Vec<Target>, String> {
    // 1. System aliases (with an optional +suffix).
    if let Some(items) = alias_lookup(cfg, &addr.local) {
        let mut out = Vec::new();
        for item in items {
            out.extend(expand_item(cfg, &item, chain)?);
        }
        return Ok(out);
    }

    // 2. Real local user: check ~/.forward, else deliver to mbox.
    let user_name = strip_suffix(&addr.local);
    if let Some(user) = getpwnam(cfg, user_name) {
        let fwd = Path::new(&user.home).join(".forward");
        if let Ok(text) = std::fs::read_to_string(&fwd) {
            let items = parse_items(&text);
            if !items.is_empty() {
                let mut out = Vec::new();
                for item in items {
                    out.extend(expand_item(cfg, &item, chain)?);
                }
                return Ok(out);
            }
        }
        return Ok(vec![Target::Mbox {
            user,
            addr: addr.full(),
        }]);
    }

    // 3. postmaster falls back to root (per the ACL it is always accepted).
    if addr.local.eq_ignore_ascii_case("postmaster") {
        if let Some(root) = getpwnam(cfg, "root") {
            return Ok(vec![Target::Mbox {
                user: root,
                addr: addr.full(),
            }]);
        }
    }
    Err(format!("unknown user {}", addr.local))
}

/// Expand one alias/forward item (address, |pipe, /file, :blackhole:).
fn expand_item(cfg: &Config, item: &str, chain: &mut Vec<String>) -> Result<Vec<Target>, String> {
    let item = item.trim();
    if item.is_empty() {
        return Ok(vec![]);
    }
    if item == ":blackhole:" {
        return Ok(vec![Target::Blackhole]);
    }
    if let Some(cmd) = item.strip_prefix('|') {
        return Ok(vec![Target::Pipe { cmd: cmd.to_string() }]);
    }
    if item.starts_with('/') {
        return Ok(vec![Target::File {
            path: item.to_string(),
        }]);
    }
    // Address: qualify local parts with the primary hostname.
    let addr = match crate::address::parse(&format!("<{}>", item)) {
        Ok(a) => a,
        Err(_) => {
            // Unqualified: treat as a local user at the primary hostname.
            crate::address::qualify(item, &cfg.primary_hostname)?
        }
    };
    if cfg.is_local_domain(&addr.domain) {
        expand(cfg, &addr, chain)
    } else {
        Ok(vec![Target::RemoteAddr(addr.full())])
    }
}

/// Look up a local part in the aliases file (linear-search style).
pub fn alias_lookup(cfg: &Config, local: &str) -> Option<Vec<String>> {
    let text = std::fs::read_to_string(&cfg.aliases_file).ok()?;
    for candidate in [local.to_string(), strip_suffix(local).to_string()] {
        for line in text.lines() {
            let line = line.trim_end();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            if key.trim() == candidate {
                return Some(parse_items(value));
            }
        }
    }
    None
}

/// Split an alias/forward value on commas, respecting double quotes.
pub fn parse_items(value: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    for c in value.chars() {
        match c {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                let t = cur.trim();
                if !t.is_empty() {
                    items.push(t.trim_matches('"').to_string());
                }
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    let t = cur.trim();
    if !t.is_empty() {
        items.push(t.trim_matches('"').to_string());
    }
    items
}

/// Deliver to local targets. Returns any remote addresses discovered via
/// alias/forward expansion (these go to the smarthost queue).
/// `rcpt_full` is the original envelope recipient.
pub fn deliver_local(
    cfg: &Arc<Config>,
    sender: &str,
    rcpt_full: &str,
    msg: &[u8],
) -> Result<Vec<String>, String> {
    let addr = crate::address::parse(&format!("<{}>", rcpt_full))
        .map_err(|e| format!("{}: {}", rcpt_full, e))?;
    let mut chain = Vec::new();
    let targets = expand(cfg, &addr, &mut chain)?;
    let mut remote = Vec::new();
    for t in targets {
        match t {
            Target::Mbox { user, addr } => {
                deliver_mbox(cfg, &user, sender, &addr, msg)?;
            }
            Target::RemoteAddr(a) => remote.push(a),
            Target::File { path } => deliver_file(sender, rcpt_full, &path, msg)?,
            Target::Pipe { cmd } => {
                // Pipes from aliases/.forward run as the daemon user,
                // matching the classic default (no explicit user
                // configured for pipe deliveries).
                deliver_pipe(&cmd, sender, rcpt_full, msg)?;
            }
            Target::Blackhole => {}
        }
    }
    Ok(remote)
}

/// Append to a user's mbox in the traditional BSD mailbox format.
/// Adds the envelope "From " line plus Return-path:, Envelope-to: and
/// Delivery-date: headers (the classic delivery_date_add, envelope_to_add
/// and return_path_add options).
///
/// The daemon normally runs unprivileged; mbox files must be owned by the
/// mailbox user, so delivery goes through the setuid-root helper which
/// becomes the target user. When the daemon itself still runs as root the
/// append is done directly and the file is chowned to the user.
fn deliver_mbox(cfg: &Config, user: &User, sender: &str, rcpt_full: &str, msg: &[u8]) -> Result<(), String> {
    if user.uid == 0 || cfg.never_users.iter().any(|n| n == &user.name) {
        return Err(format!(
            "refusing to run a delivery as `{}` (never_users)",
            user.name
        ));
    }
    // Defence in depth: a user name is used as a file name component.
    if user.name.is_empty() || user.name.contains('/') || user.name == "." || user.name == ".." {
        return Err(format!("unsafe user name `{}`", user.name));
    }
    if unsafe { libc::geteuid() } == 0 {
        // Root daemon: direct append, make the mailbox user-owned.
        let path = Path::new(&cfg.mailbox_dir).join(&user.name);
        let created = !path.exists();
        let mut f = open_mbox(&path)?;
        append_mbox(&mut f, sender, rcpt_full, msg)?;
        if created {
            // Owned by the user, group mail if it exists (Dovecot friendly).
            // fchown on the handle, not chown on the path: the path could
            // have been swapped for a symlink between open() and chown().
            let gid = getgrnam(cfg, "mail").unwrap_or(user.gid);
            unsafe {
                let _ = libc::fchown(
                    std::os::unix::io::AsRawFd::as_raw_fd(&f),
                    user.uid,
                    gid,
                );
            }
            let _ = f.set_permissions(std::fs::Permissions::from_mode(0o660));
        }
        Ok(())
    } else {
        // Unprivileged daemon: delegate to the setuid-root helper.
        deliver_mbox_via_helper(cfg, user, sender, rcpt_full, msg)
    }
}

fn open_mbox(path: &Path) -> Result<std::fs::File, String> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .append(true)
        .create(true)
        .mode(0o660)
        // Never follow symlinks: the mailbox path is predictable and a
        // local attacker could otherwise point it at an arbitrary file.
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| format!("{}: {}", path.display(), e))
}

/// Helper path: append to a user's mailbox running *as* that user, so a
/// newly created file is owned by the user. Used by the setuid helper
/// (homemta-deliver).
pub fn helper_append_mbox(
    cfg: &Config,
    user: &User,
    sender: &str,
    rcpt_full: &str,
    msg: &[u8],
) -> Result<(), String> {
    let path = Path::new(&cfg.mailbox_dir).join(&user.name);
    let created = !path.exists();
    let mut f = open_mbox(&path)?;
    if created {
        // The setgid mailbox directory gives the file group mail; make sure
        // the mode is 0660 regardless of umask.
        let _ = f.set_permissions(std::fs::Permissions::from_mode(0o660));
    }
    append_mbox(&mut f, sender, rcpt_full, msg)
}

/// Write the mbox-format data to an already-open mailbox, taking an
/// exclusive lock while appending.
pub fn append_mbox(
    f: &mut std::fs::File,
    sender: &str,
    rcpt_full: &str,
    msg: &[u8],
) -> Result<(), String> {
    f.lock().map_err(|e| format!("lock failed: {}", e))?;

    // Ensure a fresh line before the next message if needed.
    let len = f.metadata().map_err(|e| e.to_string())?.len();
    if len > 0 {
        f.seek(SeekFrom::End(-1)).map_err(|e| e.to_string())?;
        let mut last = [0u8; 1];
        f.read_exact(&mut last).map_err(|e| e.to_string())?;
        if last[0] != b'\n' {
            f.write_all(b"\n").map_err(|e| e.to_string())?;
        }
    }

    let from_sender = if sender.is_empty() { "MAILER-DAEMON" } else { sender };
    let head = format!(
        "From {} {}\n\
         Return-path: <{}>\n\
         Envelope-to: <{}>\n\
         Delivery-date: {}\n",
        from_sender,
        crate::log::ctime_now(),
        sender,
        rcpt_full,
        crate::log::rfc2822_now()
    );
    f.write_all(head.as_bytes()).map_err(|e| e.to_string())?;

    // Message body: CRLF -> LF, escape lines that start with "From ".
    for line in msg.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.starts_with(b"From ") {
            f.write_all(b">").map_err(|e| e.to_string())?;
        }
        f.write_all(line)
            .and_then(|_| f.write_all(b"\n"))
            .map_err(|e| e.to_string())?;
    }

    f.flush().map_err(|e| e.to_string())?;
    let _ = f.unlock();
    Ok(())
}

/// Deliver by executing the setuid-root helper, which setuids to the
/// mailbox owner before appending (so the file is owned by the user).
/// The envelope (sender and recipient, each on its own line) is written to
/// the helper's stdin followed by the raw CRLF message.
fn deliver_mbox_via_helper(
    cfg: &Config,
    user: &User,
    sender: &str,
    rcpt_full: &str,
    msg: &[u8],
) -> Result<(), String> {
    use std::process::{Command, Stdio};
    let mut child = Command::new(&cfg.deliver_helper)
        .arg("--deliver-mbox")
        .arg(&user.name)
        .arg("-c")
        .arg(&cfg.config_path)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            format!(
                "cannot run delivery helper {}: {} (is it installed setuid root?)",
                cfg.deliver_helper, e
            )
        })?;
    if let Some(mut si) = child.stdin.take() {
        if si.write_all(sender.as_bytes()).is_err()
            || si.write_all(b"\n").is_err()
            || si.write_all(rcpt_full.as_bytes()).is_err()
            || si.write_all(b"\n").is_err()
            || si.write_all(msg).is_err()
        {
            let _ = child.wait();
            return Err(format!("writing to delivery helper failed"));
        }
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("delivery helper: {}", e))?;
    if out.status.success() {
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        Err(format!(
            "delivery helper failed (exit {}): {}",
            out.status,
            err.trim()
        ))
    }
}

/// Append to a file target from /etc/aliases or .forward. Same added
/// headers as classic file deliveries; no "From " line. Runs as the daemon
/// user (the classic default when no explicit user is configured).
fn deliver_file(
    sender: &str,
    rcpt_full: &str,
    path: &str,
    msg: &[u8],
) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        // Never follow symlinks for alias/forward file targets either.
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| format!("{}: {}", path, e))?;
    f.lock().map_err(|e| format!("{}: lock failed: {}", path, e))?;
    let head = format!(
        "Return-path: <{}>\n\
         Envelope-to: <{}>\n\
         Delivery-date: {}\n",
        sender,
        rcpt_full,
        crate::log::rfc2822_now()
    );
    f.write_all(head.as_bytes())
        .and_then(|_| f.write_all(&lf_escape(msg)))
        .map_err(|e| format!("{}: {}", path, e))?;
    f.flush().map_err(|e| format!("{}: {}", path, e))?;
    let _ = f.unlock();
    Ok(())
}

/// Convert CRLF to LF with ">From " escaping.
fn lf_escape(msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(msg.len() + 16);
    for line in msg.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.starts_with(b"From ") {
            out.push(b'>');
        }
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out
}

/// Pipe the message through a shell command (alias/forward pipe target).
/// Runs as the daemon user, like classic pipe deliveries without an
/// explicit user setting.
fn deliver_pipe(cmd: &str, sender: &str, rcpt_full: &str, msg: &[u8]) -> Result<(), String> {
    let mut child = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(cmd)
        .env_clear()
        .env("PATH", "/bin:/usr/bin:/usr/local/bin")
        .env("SENDER", sender)
        .env("RECIPIENT", rcpt_full)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot spawn pipe `{}`: {}", cmd, e))?;
    if let Some(mut si) = child.stdin.take() {
        if let Err(e) = si.write_all(&lf_escape(msg)) {
            return Err(format!("pipe `{}` write error: {}", cmd, e));
        }
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("pipe `{}` wait error: {}", cmd, e))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "pipe `{}` exited {}: {}",
            cmd,
            out.status,
            err.trim()
        ));
    }
    if !out.stdout.is_empty() {
        log::info(&format!(
            "pipe `{}` output ignored ({} bytes)",
            cmd,
            out.stdout.len()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn test_cfg(tmp: &std::path::Path) -> Config {
        let mut c = Config::default();
        c.primary_hostname = "jelaas.eu".to_string();
        c.local_domains = vec!["jelaas.eu".to_string()];
        c.passwd_file = tmp.join("passwd").display().to_string();
        c.group_file = tmp.join("group").display().to_string();
        c.aliases_file = tmp.join("aliases").display().to_string();
        c.mailbox_dir = tmp.join("mail").display().to_string();
        c.user = "jelaas".to_string();
        std::fs::create_dir_all(tmp.join("mail")).unwrap();
        std::fs::write(
            c.passwd_file.clone(),
            "root:x:0:0:root:/root:/bin/sh\njelaas:x:1000:1000:J:/home/jelaas:/bin/sh\n",
        )
        .unwrap();
        std::fs::write(c.group_file.clone(), "mail:x:12:\n").unwrap();
        std::fs::write(c.aliases_file.clone(), "").unwrap();
        c
    }

    #[test]
    fn passwd_and_group() {
        let tmp = std::env::temp_dir().join(format!("homemta-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        let c = test_cfg(&tmp);
        let u = getpwnam(&c, "jelaas").unwrap();
        assert_eq!((u.uid, u.gid, u.home.as_str()), (1000, 1000, "/home/jelaas"));
        assert!(getpwnam(&c, "nosuch").is_none());
        assert_eq!(getgrnam(&c, "mail"), Some(12));
    }

    #[test]
    fn alias_parsing() {
        assert_eq!(
            parse_items("a, b, c"),
            vec!["a", "b", "c"]
        );
        assert_eq!(
            parse_items("\"x, y\", z"),
            vec!["x, y", "z"]
        );
        assert_eq!(parse_items(""), Vec::<String>::new());
    }

    #[test]
    fn alias_lookup_and_expansion() {
        let tmp = std::env::temp_dir().join(format!("homemta-test-alias-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        let c = test_cfg(&tmp);
        std::fs::write(
            c.aliases_file.clone(),
            "root: jelaas\nlist: jelaas+one, other@example.org\n",
        )
        .unwrap();
        assert_eq!(
            alias_lookup(&c, "root"),
            Some(vec!["jelaas".to_string()])
        );
        assert_eq!(
            alias_lookup(&c, "list"),
            Some(vec!["jelaas+one".to_string(), "other@example.org".to_string()])
        );
        let mut chain = Vec::new();
        let targets = expand(
            &c,
            &crate::address::parse("<root@jelaas.eu>").unwrap(),
            &mut chain,
        )
        .unwrap();
        assert_eq!(targets.len(), 1);
        match &targets[0] {
            Target::Mbox { user, .. } => assert_eq!(user.name, "jelaas"),
            _ => panic!("expected mbox"),
        }
    }

    #[test]
    fn forward_loop_detected() {
        let tmp = std::env::temp_dir().join(format!("homemta-test-fwd-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        let home = tmp.join("home");
        std::fs::create_dir_all(&home).unwrap();
        let c = test_cfg(&tmp);
        std::fs::write(
            c.passwd_file.clone(),
            format!(
                "root:x:0:0:root:/root:/bin/sh\njelaas:x:1000:1000:J:{}:/bin/sh\n",
                home.display()
            ),
        )
        .unwrap();
        std::fs::write(home.join(".forward"), "jelaas@jelaas.eu\n").unwrap();
        let mut chain = Vec::new();
        let e = expand(
            &c,
            &crate::address::parse("<jelaas@jelaas.eu>").unwrap(),
            &mut chain,
        );
        assert!(e.is_err());
        assert!(e.unwrap_err().contains("loop"));
    }

    #[test]
    fn mbox_delivery_format() {
        let tmp = std::env::temp_dir().join(format!("homemta-test-mbox-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        let c = test_cfg(&tmp);
        let cfg = Arc::new(c);
        let _user = getpwnam(&cfg, "jelaas").unwrap();
        let msg = b"From: a@b\r\nTo: jelaas@jelaas.eu\r\nSubject: hi\r\n\r\nFrom here on\r\nbody\r\n";
        deliver_local(&cfg, "sender@example.org", "jelaas@jelaas.eu", msg).unwrap();
        let path = tmp.join("mail").join("jelaas");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.starts_with("From sender@example.org "));
        assert!(content.contains("\nReturn-path: <sender@example.org>\n"));
        assert!(content.contains("\nEnvelope-to: <jelaas@jelaas.eu>\n"));
        assert!(content.contains("\nDelivery-date: "));
        // From-escaping of body lines.
        assert!(content.contains("\n>From here on\n"));
        // Second message appends cleanly: file starts with "From " and the
        // second From_ line follows the first message's trailing newline.
        deliver_local(&cfg, "b@c", "jelaas@jelaas.eu", b"Subject: two\r\n\r\nbody2\r\n").unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.starts_with("From sender@example.org "));
        assert_eq!(content.matches("\nFrom b@c ").count(), 1);
        assert_eq!(content.matches("Return-path:").count(), 2);
    }

    #[test]
    fn mbox_refuses_symlinks() {
        let tmp = std::env::temp_dir().join(format!("homemta-test-symlink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let c = test_cfg(&tmp);
        let target = tmp.join("victim");
        std::fs::write(&target, "keep me").unwrap();
        let link = tmp.join("mail").join("jelaas");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let cfg = Arc::new(c);
        let r = deliver_local(
            &cfg,
            "s@d",
            "jelaas@jelaas.eu",
            b"Subject: x\r\n\r\nbody\r\n",
        );
        assert!(r.is_err(), "delivery through a symlink must fail");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep me");
    }

    #[test]
    fn unsafe_user_names_refused() {
        let tmp = std::env::temp_dir().join(format!("homemta-test-unsafe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let c = test_cfg(&tmp);
        // A passwd entry with a path-traversal name must not escape the
        // mailbox directory even if the root daemon path is used.
        std::fs::write(
            c.passwd_file.clone(),
            "root:x:0:0:root:/root:/bin/sh\n../../etc/passwd:x:1001:1001:X:/tmp:/bin/sh\n",
        )
        .unwrap();
        let cfg = Arc::new(c);
        let r = deliver_local(
            &cfg,
            "s@d",
            "../../etc/passwd@jelaas.eu",
            b"Subject: x\r\n\r\nbody\r\n",
        );
        assert!(r.is_err());
        assert!(!tmp.join("etc").exists());
    }

    #[test]
    fn pipe_delivery() {
        let tmp = std::env::temp_dir().join(format!("homemta-test-pipe-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        let c = test_cfg(&tmp);
        let _cfg = Arc::new(c);
        let out_file = tmp.join("piped");
        let cmd = format!("cat > {}", out_file.display());
        deliver_pipe(&cmd, "s@d", "r@d", b"Subject: p\r\n\r\npiped body\r\n").unwrap();
        let content = std::fs::read_to_string(&out_file).unwrap();
        assert!(content.contains("Subject: p\n"));
        assert!(content.contains("piped body\n"));
    }
}
