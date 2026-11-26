//! The internal root delivery helper.
//!
//! The daemon starts as root, binds its listeners, and then forks this
//! helper *before* dropping privileges. The helper stays root, listens on
//! a private abstract unix socket, and - after checking the peer's
//! credentials with SO_PEERCRED - becomes the target user and appends to
//! their mailbox. No setuid binary is involved; the helper exists only as
//! long as the daemon (a life-line pipe ends the loop when the daemon
//! exits).
//!
//! Security boundary: only connections whose real uid equals the daemon's
//! runtime uid are served. Everything else the client supplies (user
//! name, envelope, message) is validated exactly like untrusted input:
//! the config file must be root-owned and not group/world-writable, the
//! user must exist in the passwd file, and uid 0 / never_users are
//! refused. Privileges are dropped *before* any file is touched.

use crate::config::{file_is_secure, Config};
use crate::routing;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixListener;
use std::time::Duration;

const MAX_MSG: u64 = 128 * 1024 * 1024;
const MAX_LINE: u64 = 1024;
/// Cap on concurrent delivery children (refuse extra requests).
const MAX_CHILDREN: i32 = 32;

fn peer_uid(listener_fd: i32) -> Option<u32> {
    unsafe {
        let mut cred: libc::ucred = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        if libc::getsockopt(
            listener_fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        ) == 0
        {
            Some(cred.uid)
        } else {
            None
        }
    }
}

fn send_reply(mut w: &std::os::unix::net::UnixStream, s: &str) {
    let _ = w.write_all(s.as_bytes());
    let _ = w.write_all(b"\n");
    let _ = w.flush();
}

/// Read one line with a length cap (never trust the peer's framing).
fn read_capped_line(rd: &mut impl BufRead, buf: &mut String, cap: u64) -> bool {
    buf.clear();
    let mut limited = rd.take(cap + 1);
    match limited.read_line(buf) {
        Ok(0) | Err(_) => false,
        Ok(_) => buf.len() as u64 <= cap,
    }
}

/// Handle one accepted connection. Runs in a forked child: verifies the
/// shared secret, drops to the target user and appends the message to
/// their mailbox.
fn process_request(stream: std::os::unix::net::UnixStream, secret: &[u8], config_path: &str) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
    let writer = match stream.try_clone() {
        Ok(w) => w,
        Err(_) => return,
    };
    let mut rd = BufReader::new(stream);

    // First line: the shared secret (constant-time comparison).
    let mut line = String::new();
    if !read_capped_line(&mut rd, &mut line, MAX_LINE) {
        send_reply(&writer, "ERR truncated request");
        return;
    }
    if !crate::scram::ct_eq(line.trim_end_matches(['\r', '\n']).as_bytes(), secret) {
        crate::log::warn("delivery helper: refused request with a bad secret");
        return;
    }

    if !read_capped_line(&mut rd, &mut line, MAX_LINE) {
        send_reply(&writer, "ERR truncated request");
        return;
    }
    let user_name = line.trim_end_matches(['\r', '\n']).to_string();
    if !read_capped_line(&mut rd, &mut line, MAX_LINE) {
        send_reply(&writer, "ERR truncated request");
        return;
    }
    let sender = line.trim_end_matches(['\r', '\n']).to_string();
    if !read_capped_line(&mut rd, &mut line, MAX_LINE) {
        send_reply(&writer, "ERR truncated request");
        return;
    }
    let rcpt_full = line.trim_end_matches(['\r', '\n']).to_string();

    let mut msg = Vec::new();
    if rd.take(MAX_MSG + 1).read_to_end(&mut msg).is_err() || msg.len() as u64 > MAX_MSG {
        send_reply(&writer, "ERR message too large");
        return;
    }

    // The helper trusts only a root-owned, non-writable config file.
    if !file_is_secure(config_path) {
        send_reply(&writer, "ERR config file is not root-owned or is group/world-writable");
        return;
    }
    let cfg = match Config::from_file(config_path) {
        Ok(c) => c,
        Err(e) => {
            send_reply(&writer, &format!("ERR config: {}", e));
            return;
        }
    };

    let Some(u) = routing::getpwnam(&cfg, &user_name) else {
        send_reply(&writer, &format!("ERR no such user `{}`", user_name));
        return;
    };
    if u.uid == 0
        || cfg.never_users.iter().any(|n| n == &u.name)
        || u.name.contains('/')
        || u.name == "."
        || u.name == ".."
    {
        send_reply(&writer, &format!("ERR refusing to deliver as `{}` (never_users)", u.name));
        return;
    }

    // Drop to the target user before touching any file. Keep the "mail"
    // group so the setgid mailbox directory stays writable.
    let mail_gid = routing::getgrnam(&cfg, "mail");
    let mut groups: Vec<u32> = vec![u.gid];
    if let Some(g) = mail_gid {
        if !groups.contains(&g) {
            groups.push(g);
        }
    }
    unsafe {
        if libc::setgroups(groups.len(), groups.as_ptr() as *const libc::gid_t) != 0
            || libc::setgid(u.gid) != 0
            || libc::setuid(u.uid) != 0
            || libc::geteuid() != u.uid
        {
            send_reply(&writer, &format!("ERR cannot drop to uid {}", u.uid));
            return;
        }
    }

    match routing::helper_append_mbox(&cfg, &u, &sender, &rcpt_full, &msg) {
        Ok(()) => send_reply(&writer, "OK"),
        Err(e) => send_reply(&writer, &format!("ERR {}", e)),
    }
}

/// The helper process's main loop; never returns (exits via the life-line
/// pipe or when its parent dies).
pub fn serve(
    listener: UnixListener,
    life_pipe: std::os::unix::io::RawFd,
    expected_uid: u32,
    secret: String,
    config_path: String,
) -> ! {
    let _ = listener.set_nonblocking(true);
    let listener_fd = listener.as_raw_fd();
    let secret_bytes = secret.into_bytes();
    let mut active_children: i32 = 0;
    loop {
        let mut fds = [
            libc::pollfd {
                fd: listener_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: life_pipe,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        if unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) } < 0 {
            std::process::exit(1);
        }
        // Reap finished delivery children.
        loop {
            let mut st = 0;
            if unsafe { libc::waitpid(-1, &mut st, libc::WNOHANG) } <= 0 {
                break;
            }
            active_children -= 1;
        }
        // The daemon closed the life-line pipe (EOF = POLLIN, or the
        // daemon died = POLLHUP; both are reported persistently): shut
        // down.
        if fds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            std::process::exit(0);
        }
        if fds[0].revents & libc::POLLIN == 0 {
            continue;
        }
        let (stream, _) = match listener.accept() {
            Ok(x) => x,
            Err(_) => continue,
        };
        // The only callers allowed are the daemon's own processes (which
        // run as the configured user - or root when the daemon stays
        // root). Everything else is refused before any parsing happens.
        if peer_uid(stream.as_raw_fd()) != Some(expected_uid) {
            crate::log::warn("delivery helper: refused connection from an unexpected uid");
            drop(stream);
            continue;
        }
        if active_children >= MAX_CHILDREN {
            crate::log::warn("delivery helper: too many concurrent deliveries, refusing");
            drop(stream);
            continue;
        }
        active_children += 1;
        let config_path = config_path.clone();
        let secret_bytes = secret_bytes.clone();
        unsafe {
            let pid = libc::fork();
            if pid == 0 {
                // Child: close the listener and the life-line, verify the
                // secret, serve the request, exit. Single-threaded, so
                // fork here is safe.
                drop(listener);
                let _ = libc::close(life_pipe);
                process_request(stream, &secret_bytes, &config_path);
                std::process::exit(0);
            }
        }
        // Parent: the child owns the connection now; close our copy.
        drop(stream);
    }
}
