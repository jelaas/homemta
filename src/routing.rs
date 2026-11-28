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
            // A malformed uid/gid must never turn into 0 (root): fail
            // closed and treat the user as unknown.
            let (Ok(uid), Ok(gid)) = (f[2].parse::<u32>(), f[3].parse::<u32>()) else {
                log::warn(&format!("malformed passwd entry for `{}` in {}", name, cfg.passwd_file));
                return None;
            };
            return Some(User {
                name: f[0].to_string(),
                uid,
                gid,
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
        if let Some(text) = read_forward(&fwd, &user) {
            // ~/.forward is controlled by an ordinary local user, but
            // deliveries run as the daemon user (which can read the spool
            // and, via group mail, every mailbox). So a .forward may only
            // redirect to addresses: pipe and file targets are ignored.
            // (Pipes/files in the root-owned /etc/aliases still work.)
            let items: Vec<String> = parse_items(&text)
                .into_iter()
                .filter(|it| {
                    let t = it.trim();
                    let cmd = t.starts_with('|') || t.starts_with('/');
                    if cmd {
                        log::warn(&format!(
                            "{}: ignoring pipe/file target (not permitted in .forward)",
                            fwd.display()
                        ));
                    }
                    !cmd
                })
                .collect();
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

/// Cap on a ~/.forward file (it is a short list of addresses).
const MAX_FORWARD: u64 = 64 * 1024;

/// Read a user's ~/.forward the classic safe way: never through a symlink,
/// only a regular file owned by the user (or root) and not writable by
/// group/other, size-capped. Anything else is ignored with a warning.
fn read_forward(path: &Path, user: &User) -> Option<String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let f = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            if e.raw_os_error() == Some(libc::ELOOP) {
                log::warn(&format!("{}: is a symlink, ignored", path.display()));
            }
            return None;
        }
    };
    let md = f.metadata().ok()?;
    if !md.is_file() || (md.uid() != user.uid && md.uid() != 0) || md.mode() & 0o022 != 0 {
        log::warn(&format!(
            "{}: not a regular file owned by {} (or root) and not group/world-writable, ignored",
            path.display(),
            user.name
        ));
        return None;
    }
    let mut buf = Vec::new();
    f.take(MAX_FORWARD + 1).read_to_end(&mut buf).ok()?;
    if buf.len() as u64 > MAX_FORWARD {
        log::warn(&format!("{}: larger than {} bytes, ignored", path.display(), MAX_FORWARD));
        return None;
    }
    String::from_utf8(buf).ok()
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
/// mailbox user, so delivery goes through the forked root helper, which
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
        // Unprivileged daemon: delegate to the forked root helper.
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
/// newly created file is owned by the user. Used by the forked root
/// delivery helper.
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

    // The envelope strings come from two paths (validated SMTP input, or
    // the helper socket request from the daemon). Defence in depth: strip
    // anything that could break out of a header or the From_ line.
    let clean = |s: &str| {
        s.chars()
            .take_while(|c| *c >= ' ' && *c != '\u{7f}')
            .collect::<String>()
    };
    let sender = clean(sender);
    let rcpt_full = clean(rcpt_full);
    let from_sender = if sender.is_empty() { "MAILER-DAEMON".to_string() } else { sender.clone() };
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

/// Deliver by connecting to the forked root helper over its private
/// abstract unix socket. The helper verifies our credentials (SO_PEERCRED),
/// then becomes the mailbox owner and appends (so the file is owned by the
/// user). The request is: user name, sender and recipient each on their
/// own line, followed by the raw CRLF message.
fn deliver_mbox_via_helper(
    cfg: &Config,
    user: &User,
    sender: &str,
    rcpt_full: &str,
    msg: &[u8],
) -> Result<(), String> {
    use std::io::BufRead;
    use std::os::unix::net::UnixStream;
    let Some(sock_name) = &cfg.helper_socket else {
        return Err(
            "local delivery unavailable: no delivery helper (was homemta started as root?)"
                .to_string(),
        );
    };
    use std::os::linux::net::SocketAddrExt;
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(sock_name.as_bytes())
        .map_err(|e| format!("delivery helper address: {}", e))?;
    let Some(secret) = &cfg.helper_secret else {
        return Err(
            "local delivery unavailable: no delivery helper (was homemta started as root?)"
                .to_string(),
        );
    };
    let stream = UnixStream::connect_addr(&addr)
        .map_err(|e| format!("cannot connect to delivery helper: {}", e))?;
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(30)));
    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(30)));
    let mut writer = stream.try_clone().map_err(|e| e.to_string())?;
    let mut req = format!(
        "{}\n{}\n{}\n{}\n",
        secret, user.name, sender, rcpt_full
    )
    .into_bytes();
    req.extend_from_slice(msg);
    writer.write_all(&req).map_err(|e| format!("delivery helper: {}", e))?;
    // Half-close: the helper reads the message up to EOF, then replies on
    // the same connection.
    let _ = writer.shutdown(std::net::Shutdown::Write);
    drop(writer);
    let mut rd = std::io::BufReader::new(stream);
    // Cap the helper's reply line (the helper is trusted, but never let a
    // stream dictate an unbounded allocation).
    let resp = {
        let mut limited = rd.by_ref().take(1025);
        let mut line = String::new();
        if limited.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
            return Err("delivery helper closed the connection".to_string());
        }
        line
    };
    let resp = resp.trim_end_matches(['\r', '\n']).trim().to_string();
    if resp == "OK" {
        Ok(())
    } else {
        Err(resp.strip_prefix("ERR ").unwrap_or(&resp).to_string())
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
/// Wall-clock limit for a pipe command (the classic pipe transport default
/// is one hour; a home server does not need more than this).
const PIPE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);
/// How much of a pipe command's stdout/stderr is kept (the rest is drained).
const PIPE_OUTPUT_CAP: u64 = 64 * 1024;

/// Read a stream to EOF, keeping at most `cap` bytes and discarding the
/// rest so the writer never blocks on a full pipe.
fn drain_capped(mut r: impl Read, cap: u64) -> (Vec<u8>, u64) {
    let mut kept = Vec::new();
    let _ = (&mut r).take(cap).read_to_end(&mut kept);
    let extra = std::io::copy(&mut r, &mut std::io::sink()).unwrap_or(0);
    let total = kept.len() as u64 + extra;
    (kept, total)
}

fn deliver_pipe(cmd: &str, sender: &str, rcpt_full: &str, msg: &[u8]) -> Result<(), String> {
    use std::os::unix::process::CommandExt;
    use std::sync::mpsc;
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
        // Own process group, so a timeout kills the whole pipeline (and
        // no background grandchild keeps our pipes open).
        .process_group(0)
        .spawn()
        .map_err(|e| format!("cannot spawn pipe `{}`: {}", cmd, e))?;

    // Feed stdin and drain stdout/stderr on their own threads: writing the
    // whole message first would deadlock against a command that fills its
    // output pipe before reading its input.
    let input = lf_escape(msg);
    let (wtx, wrx) = mpsc::channel();
    let stdin = child.stdin.take();
    std::thread::spawn(move || {
        let r = match stdin {
            Some(mut si) => si.write_all(&input),
            None => Ok(()),
        };
        let _ = wtx.send(r);
    });
    let (otx, orx) = mpsc::channel();
    if let Some(so) = child.stdout.take() {
        std::thread::spawn(move || {
            let _ = otx.send(drain_capped(so, PIPE_OUTPUT_CAP));
        });
    }
    let (etx, erx) = mpsc::channel();
    if let Some(se) = child.stderr.take() {
        std::thread::spawn(move || {
            let _ = etx.send(drain_capped(se, PIPE_OUTPUT_CAP));
        });
    }

    let deadline = std::time::Instant::now() + PIPE_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) => {}
            Err(e) => return Err(format!("pipe `{}` wait error: {}", cmd, e)),
        }
        if std::time::Instant::now() >= deadline {
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "pipe `{}` timed out after {}s and was killed",
                cmd,
                PIPE_TIMEOUT.as_secs()
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };

    // The command has exited; its helpers finish as soon as the pipes are
    // closed. Never wait forever on them (a detached grandchild could still
    // hold a pipe end).
    let grace = std::time::Duration::from_secs(5);
    let write_res = wrx.recv_timeout(grace).unwrap_or(Ok(()));
    let (_, out_len) = orx.recv_timeout(grace).unwrap_or((Vec::new(), 0));
    let (err_buf, _) = erx.recv_timeout(grace).unwrap_or((Vec::new(), 0));
    if !status.success() {
        let err = String::from_utf8_lossy(&err_buf);
        return Err(format!(
            "pipe `{}` exited {}: {}",
            cmd,
            status,
            err.trim()
        ));
    }
    if let Err(e) = write_res {
        return Err(format!("pipe `{}` write error: {}", cmd, e));
    }
    if out_len > 0 {
        log::info(&format!(
            "pipe `{}` output ignored ({} bytes)",
            cmd,
            out_len
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
        // The .forward must be owned by the user: use our own uid.
        let uid = unsafe { libc::getuid() };
        std::fs::write(
            c.passwd_file.clone(),
            format!(
                "root:x:0:0:root:/root:/bin/sh\njelaas:x:{}:{}:J:{}:/bin/sh\n",
                uid,
                uid,
                home.display()
            ),
        )
        .unwrap();
        std::fs::write(home.join(".forward"), "jelaas@jelaas.eu\n").unwrap();
        std::fs::set_permissions(home.join(".forward"), std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut chain = Vec::new();
        let e = expand(
            &c,
            &crate::address::parse("<jelaas@jelaas.eu>").unwrap(),
            &mut chain,
        );
        assert!(e.is_err());
        assert!(e.unwrap_err().contains("loop"));
    }

    /// Writes passwd with our own uid and a .forward with `content`/`mode`,
    /// then expands jelaas@jelaas.eu.
    fn expand_with_forward(tag: &str, content: &str, mode: u32) -> Vec<Target> {
        let tmp = std::env::temp_dir().join(format!("homemta-test-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let home = tmp.join("home");
        std::fs::create_dir_all(&home).unwrap();
        let c = test_cfg(&tmp);
        let uid = unsafe { libc::getuid() };
        std::fs::write(
            c.passwd_file.clone(),
            format!("jelaas:x:{}:{}:J:{}:/bin/sh\n", uid, uid, home.display()),
        )
        .unwrap();
        std::fs::write(home.join(".forward"), content).unwrap();
        std::fs::set_permissions(home.join(".forward"), std::fs::Permissions::from_mode(mode)).unwrap();
        let mut chain = Vec::new();
        expand(&c, &crate::address::parse("<jelaas@jelaas.eu>").unwrap(), &mut chain).unwrap()
    }

    #[test]
    fn forward_pipes_and_files_ignored() {
        // Pipe/file targets in a user's .forward would run as the daemon
        // user: they are dropped; with nothing else left, mail goes to the
        // mbox.
        let t = expand_with_forward("fwd-cmd", "|cat /etc/shadow, \"/tmp/x\"\n", 0o644);
        assert_eq!(t.len(), 1);
        assert!(matches!(t[0], Target::Mbox { .. }));
        // Addresses next to a pipe still work; the pipe is not run.
        let t = expand_with_forward("fwd-mixed", "|true, other@example.org\n", 0o644);
        assert_eq!(t.len(), 1);
        assert!(matches!(&t[0], Target::RemoteAddr(a) if a == "other@example.org"));
    }

    #[test]
    fn forward_writable_by_others_ignored() {
        let t = expand_with_forward("fwd-perm", "other@example.org\n", 0o666);
        assert_eq!(t.len(), 1);
        assert!(matches!(t[0], Target::Mbox { .. }));
    }

    #[test]
    fn malformed_passwd_uid_is_not_root() {
        let tmp = std::env::temp_dir().join(format!("homemta-test-pwbad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let c = test_cfg(&tmp);
        std::fs::write(c.passwd_file.clone(), "jelaas:x:abc:1000:J:/home/j:/bin/sh\n").unwrap();
        assert!(getpwnam(&c, "jelaas").is_none());
    }

    #[test]
    fn pipe_that_ignores_stdin_with_big_output_does_not_hang() {
        // Writes > pipe buffer to stdout without reading stdin, then exits.
        let big = vec![b'x'; 1024 * 1024];
        let mut msg = b"Subject: big\r\n\r\n".to_vec();
        msg.extend_from_slice(&big);
        msg.extend_from_slice(b"\r\n");
        let r = deliver_pipe("head -c 2000000 /dev/zero", "s@d", "r@d", &msg);
        // Exit status is 0; the unread stdin may yield a write error, but
        // the call must return instead of deadlocking.
        let _ = r;
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
    fn mbox_envelope_sanitization() {
        let tmp = std::env::temp_dir().join(format!("homemta-test-clean-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let c = test_cfg(&tmp);
        let cfg = Arc::new(c);
        let user = getpwnam(&cfg, "jelaas").unwrap();
        // A hostile envelope (as a compromised daemon could send via the
        // helper socket) must not be able to inject mbox lines/headers.
        // The SMTP/daemon path rejects such envelopes up front; here we
        // exercise the shared mbox writer directly (the layer the helper
        // process trusts if the daemon were compromised).
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(tmp.join("mail").join("jelaas"))
            .unwrap();
        append_mbox(
            &mut f,
            "evil@sender.example\nX-Injected: yes\r\nFrom fake",
            "jelaas@jelaas.eu\nMore: injected",
            b"Subject: clean\r\n\r\nbody\r\n",
        )
        .unwrap();
        let content = std::fs::read_to_string(tmp.join("mail").join("jelaas")).unwrap();
        assert!(!content.contains("X-Injected"), "header injection in mbox");
        assert!(!content.contains("More: injected"), "header injection in mbox");
        assert!(content.contains("evil@sender.example"), "sender prefix kept");
        assert!(content.contains("jelaas@jelaas.eu"), "recipient prefix kept");
        let _ = user;
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
