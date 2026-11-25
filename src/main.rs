//! homemta - a minimal MTA for home servers.
//!
//! Starts as root (to bind port 25), prepares its state, then drops to an
//! unprivileged user. User-owned mailboxes are written through a
//! setuid-root helper (`homemta-deliver`) that becomes the target user.
//! Accepts mail from the internet for local domains only; no relaying.
//! IPv4 only, static musl build.

use homemta::config::{Config, TlsMode};
use homemta::{log, queue, routing, smtp_server, tls};
use std::net::TcpListener;
use std::sync::{mpsc, Arc};

extern "C" fn on_signal(_sig: libc::c_int) {
    queue::request_shutdown();
}

/// Detach from the terminal: double-fork, new session, stdin from
/// /dev/null. stdout/stderr stay attached until logging is initialized so
/// startup errors remain visible; see detach_stdio().
fn daemonize() {
    unsafe {
        let pid = libc::fork();
        if pid < 0 {
            eprintln!("homemta: fork failed");
            std::process::exit(1);
        }
        if pid > 0 {
            // Original process: done.
            std::process::exit(0);
        }
        // Child: new session, then a second fork so we can never reacquire
        // a controlling terminal.
        if libc::setsid() < 0 {
            eprintln!("homemta: setsid failed");
            std::process::exit(1);
        }
        let pid = libc::fork();
        if pid < 0 {
            eprintln!("homemta: fork failed");
            std::process::exit(1);
        }
        if pid > 0 {
            std::process::exit(0);
        }
        // Grandchild: detach stdin.
        let null = libc::open(
            b"/dev/null\0".as_ptr() as *const libc::c_char,
            libc::O_RDONLY,
        );
        if null >= 0 {
            libc::dup2(null, 0);
            if null > 2 {
                libc::close(null);
            }
        }
    }
}

/// Silence stdout/stderr once logging is established (daemon mode).
fn detach_stdio() {
    unsafe {
        let null = libc::open(
            b"/dev/null\0".as_ptr() as *const libc::c_char,
            libc::O_WRONLY,
        );
        if null >= 0 {
            libc::dup2(null, 1);
            libc::dup2(null, 2);
            if null > 2 {
                libc::close(null);
            }
        }
    }
}

fn write_pidfile(cfg: &Config) {
    let Some(p) = &cfg.pid_file else { return };
    if let Err(e) = std::fs::write(p, format!("{}\n", std::process::id())) {
        log::error(&format!("cannot write pid file {}: {}", p, e));
    }
}

fn remove_pidfile(cfg: &Config) {
    if let Some(p) = &cfg.pid_file {
        let _ = std::fs::remove_file(p);
    }
}

fn install_signal_handlers() {
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
}

/// Hold an exclusive flock on the spool directory for the daemon's lifetime
/// so two instances (or a daemon plus a queue runner) never fight over it.
fn lock_spool(dir: &str) -> std::fs::File {
    std::fs::create_dir_all(dir).expect("cannot create spool directory");
    let f = std::fs::OpenOptions::new()
        .read(true)
        .open(dir)
        .expect("cannot open spool directory");
    let rc = unsafe { libc::flock(std::os::unix::io::AsRawFd::as_raw_fd(&f), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        eprintln!("homemta: another instance seems to be running (spool {} is locked)", dir);
        std::process::exit(1);
    }
    f
}

fn load_config(path: &str) -> Config {
    let mut cfg = Config::default();
    match std::fs::read_to_string(path) {
        Ok(text) => {
            for w in cfg.parse(&text) {
                eprintln!("homemta: config warning: {}", w);
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "homemta: no config file at {}; running with defaults (remote mail will bounce: no smarthost)",
                path
            );
        }
        Err(e) => {
            eprintln!("homemta: cannot read {}: {}", path, e);
            std::process::exit(1);
        }
    }
    // The config file must not be writable by the daemon user, since the
    // setuid delivery helper trusts it.
    if let Ok(md) = std::fs::metadata(path) {
        use std::os::unix::fs::MetadataExt;
        if md.uid() != 0 || md.mode() & 0o022 != 0 {
            eprintln!(
                "homemta: config file {} must be owned by root and not writable by group/other",
                path
            );
        }
    }
    cfg.config_path = path.to_string();
    cfg
}

fn usage() -> ! {
    eprintln!(
        "usage: homemta [options]\n\
         options:\n\
         \x20 -c FILE   configuration file (default /etc/homemta.jsonc)\n\
         \x20 -b        run as a background daemon (double fork, detach)\n\
         \x20 --pidfile FILE  write the daemon pid to FILE (init scripts)\n\
         \x20 -q        run the queue once and exit\n\
         \x20 -d        debug logging to stderr\n\
         \x20 -V        show version and exit\n\
         \x20 --exit-on-stdin-eof  shut down when stdin closes (supervisors/tests)\n\
         \x20 --deliver-mbox USER  internal: setuid delivery helper mode"
    );
    std::process::exit(1);
}

fn euid() -> u32 {
    unsafe { libc::geteuid() }
}

/// Drop root after all privileged setup is done. `cfg.user = "root"` keeps
/// running as root (containers, tests, debugging).
fn drop_privileges(cfg: &Config) {
    if euid() != 0 {
        log::info(&format!("already running unprivileged (uid {})", euid()));
        return;
    }
    if cfg.user == "root" {
        log::warn("configured to keep running as root");
        return;
    }
    let Some(u) = routing::getpwnam(cfg, &cfg.user) else {
        log::error(&format!(
            "user `{}` not found in {}; refusing to keep running as root",
            cfg.user, cfg.passwd_file
        ));
        std::process::exit(1);
    };
    let gid = match &cfg.group {
        Some(g) => routing::getgrnam(cfg, g).unwrap_or(u.gid),
        None => u.gid,
    };
    unsafe {
        if libc::setgroups(0, std::ptr::null()) != 0 {
            log::error("setgroups failed");
            std::process::exit(1);
        }
        if libc::setgid(gid) != 0 {
            log::error(&format!("setgid({}) failed", gid));
            std::process::exit(1);
        }
        if libc::setuid(u.uid) != 0 {
            log::error(&format!("setuid({}) failed", u.uid));
            std::process::exit(1);
        }
    }
    if euid() != u.uid {
        log::error("privilege drop did not take effect");
        std::process::exit(1);
    }
    log::info(&format!(
        "dropped privileges to {} (uid {}, gid {})",
        cfg.user, u.uid, gid
    ));
}

/// Prepare directories and ownership while still root: the mailbox
/// directory (mode 2775, group mail) and the spool (owned by the daemon
/// user). No-ops when already unprivileged.
fn prepare_dirs(cfg: &Config) {
    if euid() != 0 {
        return;
    }
    if let Err(e) = std::fs::create_dir_all(&cfg.mailbox_dir) {
        log::warn(&format!("cannot create mailbox dir {}: {}", cfg.mailbox_dir, e));
    } else if let Some(gid) = routing::getgrnam(cfg, "mail") {
        let _ = std::os::unix::fs::chown(&cfg.mailbox_dir, None, Some(gid));
        let _ = std::fs::set_permissions(
            &cfg.mailbox_dir,
            std::os::unix::fs::PermissionsExt::from_mode(0o2775),
        );
    }
    if cfg.user != "root" {
        if let Some(u) = routing::getpwnam(cfg, &cfg.user) {
            if std::fs::create_dir_all(&cfg.spool_dir).is_ok() {
                let _ = std::os::unix::fs::chown(&cfg.spool_dir, Some(u.uid), Some(u.gid));
            }
        }
    }
}

/// Bind all listener sockets while still root (port 25 needs privileges).
fn bind_listeners(cfg: &Config) -> Vec<TcpListener> {
    let mut listeners = Vec::new();
    for port in &cfg.listen_ports {
        let bind = format!("{}:{}", cfg.listen_addr, port);
        match TcpListener::bind(&bind) {
            Ok(l) => {
                if let Err(e) = l.set_nonblocking(true) {
                    log::error(&format!("{}: {}", bind, e));
                    continue;
                }
                log::info(&format!("listening on {} (IPv4)", bind));
                listeners.push(l);
            }
            Err(e) => log::error(&format!("cannot bind {}: {}", bind, e)),
        }
    }
    if listeners.is_empty() {
        log::error("no listener could be bound");
        std::process::exit(1);
    }
    listeners
}

/// Setuid delivery helper: appends to a user's mbox *as that user*, so the
/// file is owned by the user. Must be installed setuid root. Reads the
/// envelope (sender line, recipient line) and the raw message from stdin.
fn helper_deliver_mbox(user: &str, config_path: &str) -> ! {
    if euid() != 0 {
        eprintln!("homemta-deliver: must be installed setuid root (effective uid is {})", euid());
        std::process::exit(1);
    }
    let cfg = load_config(config_path);
    // Envelope: two lines, then the message.
    const CAP: u64 = 128 * 1024 * 1024;
    let mut input = Vec::new();
    {
        use std::io::Read;
        let mut stdin = std::io::stdin().lock().take(CAP + 1);
        if stdin.read_to_end(&mut input).is_err() || input.len() as u64 > CAP {
            eprintln!("homemta-deliver: message too large");
            std::process::exit(1);
        }
    }
    let nl1 = input.iter().position(|&b| b == b'\n');
    let nl2 = nl1.and_then(|p| input[p + 1..].iter().position(|&b| b == b'\n').map(|q| p + 1 + q));
    let (Some(nl1), Some(nl2)) = (nl1, nl2) else {
        eprintln!("homemta-deliver: bad envelope");
        std::process::exit(1);
    };
    let sender = String::from_utf8_lossy(&input[..nl1]).into_owned();
    let rcpt_full = String::from_utf8_lossy(&input[nl1 + 1..nl2]).into_owned();
    let msg = &input[nl2 + 1..];

    let Some(u) = routing::getpwnam(&cfg, user) else {
        eprintln!("homemta-deliver: no such user `{}`", user);
        std::process::exit(1);
    };
    if u.uid == 0 || cfg.never_users.iter().any(|n| n == &u.name) || u.name.contains('/') {
        eprintln!("homemta-deliver: refusing to deliver as `{}` (never_users)", u.name);
        std::process::exit(1);
    }
    // Keep the "mail" group so the mailbox directory (mode 2775, group
    // mail) stays writable after setuid - the classic `group = mail`
    // transport setting.
    let mail_gid = routing::getgrnam(&cfg, "mail");
    let mut groups: Vec<u32> = vec![u.gid];
    if let Some(mg) = mail_gid {
        if !groups.contains(&mg) {
            groups.push(mg);
        }
    }
    unsafe {
        if libc::setgroups(groups.len(), groups.as_ptr() as *const libc::gid_t) != 0
            || libc::setgid(u.gid) != 0
            || libc::setuid(u.uid) != 0
        {
            eprintln!("homemta-deliver: cannot drop to uid {}", u.uid);
            std::process::exit(1);
        }
    }
    if euid() != u.uid {
        eprintln!("homemta-deliver: privilege drop failed");
        std::process::exit(1);
    }
    if let Err(e) = routing::helper_append_mbox(&cfg, &u, &sender, &rcpt_full, msg) {
        eprintln!("homemta-deliver: {}", e);
        std::process::exit(1);
    }
    std::process::exit(0);
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut config_path = "/etc/homemta.jsonc".to_string();
    let mut queue_only = false;
    let mut debug = false;
    let mut daemon_mode = false;
    let mut pidfile_arg: Option<String> = None;
    let mut exit_on_stdin_eof = false;
    let mut deliver_user: Option<String> = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "-c" | "--config" => match args.next() {
                Some(v) => config_path = v,
                None => usage(),
            },
            "-q" | "--queue-run" => queue_only = true,
            "-d" | "--debug" => debug = true,
            "-b" | "--daemon" => daemon_mode = true,
            "--pidfile" => match args.next() {
                Some(v) => pidfile_arg = Some(v),
                None => usage(),
            },
            "--exit-on-stdin-eof" => exit_on_stdin_eof = true,
            "--deliver-mbox" => match args.next() {
                Some(v) => deliver_user = Some(v),
                None => usage(),
            },
            "-V" | "--version" => {
                println!("homemta {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "-h" | "--help" => usage(),
            _ => usage(),
        }
    }

    if let Some(user) = deliver_user {
        helper_deliver_mbox(&user, &config_path);
    }

    // Detach first so the invoking shell gets its prompt back immediately;
    // stdout/stderr remain attached until logging is initialized below, so
    // startup errors (e.g. a broken config) still reach the terminal.
    if daemon_mode {
        daemonize();
    }

    let mut cfg = load_config(&config_path);
    if let Some(p) = pidfile_arg {
        cfg.pid_file = Some(p);
    }
    let cfg = Arc::new(cfg);
    log::init(cfg.log_file.as_deref(), debug);

    if daemon_mode {
        if cfg.log_file.is_none() {
            eprintln!(
                "homemta: warning: daemon mode without a log_file; logging will be lost"
            );
        }
        detach_stdio();
    }
    log::info(&format!(
        "homemta {} starting: hostname {}, smarthost {:?}",
        env!("CARGO_PKG_VERSION"),
        cfg.primary_hostname,
        cfg.smarthost
    ));

    install_signal_handlers();
    prepare_dirs(&cfg);

    if queue_only {
        let _spool_lock = lock_spool(&cfg.spool_dir);
        drop_privileges(&cfg);
        queue::run_once(&cfg);
        return;
    }

    let _spool_lock = lock_spool(&cfg.spool_dir);

    // TLS: server side (STARTTLS for incoming connections) and client side
    // (smarthost). Loaded while root: the keys may be root-only.
    let tls_config = match (&cfg.tls_cert, &cfg.tls_key) {
        (Some(c), Some(k)) => match tls::load_server_config(c, k) {
            Ok(cfg) => {
                log::info("TLS enabled for incoming connections (STARTTLS)");
                Some(cfg)
            }
            Err(e) => {
                log::error(&format!("TLS server setup failed: {}", e));
                None
            }
        },
        _ => {
            log::warn("no tls.cert/tls.key configured: STARTTLS disabled");
            None
        }
    };
    if cfg.smarthost.is_some() && cfg.smarthost_tls != TlsMode::None && cfg.smarthost_verify {
        if let Some(ca) = &cfg.smarthost_ca_file {
            match tls::load_client_config(ca) {
                Ok(_) => {}
                Err(e) => log::warn(&format!("cannot load smarthost CA file {}: {}", ca, e)),
            }
            // After dropping privileges the daemon still needs to read it.
            if let Ok(md) = std::fs::metadata(ca) {
                use std::os::unix::fs::MetadataExt;
                if md.mode() & 0o004 == 0 {
                    log::warn(&format!(
                        "smarthost CA file {} is not readable by others; delivery will fail after dropping privileges",
                        ca
                    ));
                }
            }
        }
    }

    // Bind before dropping privileges: port 25 requires root.
    let listeners = bind_listeners(&cfg);
    write_pidfile(&cfg);
    drop_privileges(&cfg);

    let (wake_tx, wake_rx) = mpsc::channel();

    // Test/debug helper: shut down when stdin reaches EOF. Lets supervisors
    // (and the integration tests) stop the daemon without signalling it,
    // which matters in sandboxes where the kill syscall is unavailable.
    // Meaningless in daemon mode (stdin is /dev/null).
    if exit_on_stdin_eof && !daemon_mode {
        let stdin_wake = wake_tx.clone();
        std::thread::spawn(move || {
            use std::io::Read;
            let mut buf = [0u8; 64];
            loop {
                match std::io::stdin().read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
            log::info("stdin closed, shutting down");
            queue::request_shutdown();
            let _ = stdin_wake.send(());
        });
    }

    let runner_cfg = cfg.clone();
    let runner_wake = wake_tx.clone();
    let shutdown_wake = wake_tx.clone();
    let runner = std::thread::spawn(move || queue::runner(runner_cfg, wake_rx, runner_wake));
    let handles = smtp_server::serve(cfg.clone(), tls_config, wake_tx, listeners);

    // Wait for a shutdown request: a signal, or stdin EOF in test mode.
    while !queue::shutdown_flag() {
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    log::info("shutting down");
    let _ = shutdown_wake.send(()); // unblock the runner's recv_timeout
    for h in handles {
        let _ = h.join();
    }
    let _ = runner.join();
    remove_pidfile(&cfg);
    log::info("homemta exiting");
}
