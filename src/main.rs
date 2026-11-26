//! homemta - a minimal MTA for home servers.
//!
//! Starts as root (to bind port 25), prepares its state, then drops to an
//! unprivileged user. Before the drop it forks a root delivery helper that
//! listens on a private abstract unix socket and appends to user-owned
//! mailboxes after verifying the caller's credentials (SO_PEERCRED).
//! Accepts mail from the internet for local domains only; no relaying.
//! IPv4 only, static musl build.

use homemta::config::{self, Config, TlsMode};
use homemta::{log, queue, routing, smtp_server, tls};
use std::net::TcpListener;
use std::sync::{mpsc, Arc};

extern "C" fn on_signal(_sig: libc::c_int) {
    queue::request_shutdown();
}

/// Detach from the terminal: double-fork, new session. stdout/stderr stay
/// attached until logging is initialized so startup errors remain
/// visible; see detach_stdio(). When `keep_stdin` is set (--exit-on-stdin-
/// eof), stdin is left attached too so a supervisor can stop the daemon
/// by closing it.
fn daemonize(keep_stdin: bool) {
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
        // Grandchild: detach stdin unless a supervisor needs it.
        if !keep_stdin {
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
        // Runs after the privilege drop; the directory (e.g. /run) may not
        // be writable by the daemon user. Tell the operator instead of
        // failing silently.
        match std::fs::remove_file(p) {
            Ok(()) => {}
            Err(e) => log::warn(&format!(
                "cannot remove pid file {}: {} (remove it in the stop script)",
                p, e
            )),
        }
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
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let mut cfg = Config::default();
            for w in cfg.parse(&text) {
                eprintln!("homemta: config warning: {}", w);
            }
            // The config file must not be writable by the daemon user: the
            // root delivery helper relies on it.
            if !config::file_is_secure(path) {
                eprintln!(
                    "homemta: warning: config file {} must be owned by root and not writable by group/other",
                    path
                );
            }
            cfg.config_path = path.to_string();
            cfg
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "homemta: no config file at {}; running with defaults (remote mail will bounce: no smarthost)",
                path
            );
            Config::default()
        }
        Err(e) => {
            eprintln!("homemta: cannot read {}: {}", path, e);
            std::process::exit(1);
        }
    }
}

fn usage() -> ! {
    eprintln!("usage: homemta [options]  (try `homemta -h` for help)");
    std::process::exit(1);
}

fn help() -> ! {
    print!(
        r#"homemta - minimal home-server MTA (IPv4 only, static musl build)

USAGE:
    homemta [options]

OPTIONS:
    -c FILE           read the JSONC configuration from FILE
                      (default: /etc/homemta.jsonc)
    -b                detach from the terminal and run as a background daemon
    --pidfile FILE    write the daemon PID to FILE once the listeners are up;
                      removed again on clean shutdown (for init scripts)
    -q                process the outgoing queue once and exit (e.g. from cron)
    -d                debug mode: mirror the log to stderr as well
    -V                print the version and exit
    -h, --help        show this help and exit
    --exit-on-stdin-eof
                      shut down when stdin closes (for supervisors and tests;
                      works with -b: stdin stays attached in that case)

MAIL FLOW:
    Inbound SMTP on the configured ports is accepted only for local domains
    (no open relaying). Everything else is sent through the configured
    smarthost. Local mail is delivered to mbox files under mailbox_dir.
    The daemon starts as root to bind port 25, then drops to the
    configured unprivileged user.

See README.md for configuration and SECURITY.md for the security audit.
"#
    );
    std::process::exit(0);
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
                // The spool holds complete messages: keep it private to
                // the daemon user.
                let _ = std::fs::set_permissions(
                    &cfg.spool_dir,
                    std::os::unix::fs::PermissionsExt::from_mode(0o700),
                );
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

/// Fork the root delivery helper before dropping privileges. The helper
/// listens on a private abstract unix socket and serves only connections
/// from the daemon's runtime uid. Returns (life-line pipe write fd,
/// helper pid); the pipe is closed on shutdown to stop the helper.
fn start_delivery_helper(cfg: &mut Config) -> Option<(i32, i32)> {
    use std::os::unix::net::UnixListener;
    if euid() != 0 {
        log::warn("not started as root: local mailbox delivery will be unavailable");
        return None;
    }
    // Random, unguessable abstract socket name (defence in depth; the
    // real boundary is the SO_PEERCRED check plus the shared secret).
    let mut buf = [0u8; 20];
    let mut ok = false;
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        ok = f.read_exact(&mut buf).is_ok();
    }
    if !ok {
        let seed = log::unix_now().to_le_bytes();
        buf = seed.repeat(3).as_slice()[..20].try_into().unwrap_or([7u8; 20]);
    }
    // A second factor shared with the helper: the helper accepts a request
    // only when the first line matches this secret (constant-time). Passed
    // by fork inheritance; never in argv/env/logs.
    let mut secret_buf = [0u8; 32];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut secret_buf);
    } else {
        let seed = log::unix_now().to_le_bytes();
        secret_buf = seed.repeat(4).as_slice()[..32].try_into().unwrap_or([7u8; 32]);
    }
    let secret = homemta::md5::hex(&secret_buf);
    let name = format!("homemta-{}", homemta::base64::encode(&buf));
    use std::os::linux::net::SocketAddrExt;
    let addr = match std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()) {
        Ok(a) => a,
        Err(e) => {
            log::error(&format!("delivery helper address: {}", e));
            return None;
        }
    };
    let listener = match UnixListener::bind_addr(&addr) {
        Ok(l) => l,
        Err(e) => {
            log::error(&format!("delivery helper: cannot bind abstract socket: {}", e));
            return None;
        }
    };
    let mut pipefds = [0i32; 2];
    if unsafe { libc::pipe(pipefds.as_mut_ptr()) } != 0 {
        log::error("delivery helper: pipe() failed");
        return None;
    }
    // The helper must only serve the daemon's own runtime uid (0 when the
    // daemon deliberately keeps running as root).
    let expected_uid = if cfg.user == "root" {
        0
    } else {
        routing::getpwnam(cfg, &cfg.user).map(|u| u.uid).unwrap_or(u32::MAX)
    };
    let config_path = cfg.config_path.clone();
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        log::error("delivery helper: fork failed");
        return None;
    }
    if pid == 0 {
        // Helper child: never returns.
        unsafe { libc::close(pipefds[1]) };
        homemta::helper::serve(listener, pipefds[0], expected_uid, secret, config_path);
    }
    // Parent (daemon): close the listener and the pipe's read end, keep
    // the socket name for connects and the write end as the life-line.
    unsafe { libc::close(pipefds[0]) };
    drop(listener);
    cfg.helper_socket = Some(name.clone());
    cfg.helper_secret = Some(secret);
    log::info("delivery helper started (root, private socket, shared secret)");
    // Logged for tests and debugging.
    log::debug(&format!("delivery helper socket: {}", name));
    Some((pipefds[1], pid))
}

/// Shut the delivery helper down: close the life-line pipe and reap it.
fn stop_delivery_helper(handle: Option<(i32, i32)>) {
    if let Some((pipe_write, pid)) = handle {
        unsafe {
            libc::close(pipe_write);
            let mut st = 0;
            libc::waitpid(pid, &mut st, 0);
        }
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut config_path = "/etc/homemta.jsonc".to_string();
    let mut queue_only = false;
    let mut debug = false;
    let mut daemon_mode = false;
    let mut pidfile_arg: Option<String> = None;
    let mut exit_on_stdin_eof = false;
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
            "-V" | "--version" => {
                println!("homemta {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "-h" | "--help" => help(),
            _ => usage(),
        }
    }

    // Detach first so the invoking shell gets its prompt back immediately;
    // stdout/stderr remain attached until logging is initialized below, so
    // startup errors (e.g. a broken config) still reach the terminal.
    if daemon_mode {
        daemonize(exit_on_stdin_eof);
    }

    let mut cfg = load_config(&config_path);
    if let Some(p) = pidfile_arg {
        cfg.pid_file = Some(p);
    }
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
        let helper = start_delivery_helper(&mut cfg);
        drop_privileges(&cfg);
        queue::run_once(&Arc::new(cfg));
        stop_delivery_helper(helper);
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
    if !cfg.smarthost_verify
        && cfg.smarthost_auth != config::AuthMode::None
        && cfg.smarthost_user.is_some()
    {
        log::warn(
            "smarthost certificate verification is disabled while credentials are \
             configured: a man-in-the-middle could steal them",
        );
    }

    // Bind before dropping privileges: port 25 requires root. The delivery
    // helper is forked here as well, so it stays root after the drop.
    let listeners = bind_listeners(&cfg);
    write_pidfile(&cfg);
    let helper = start_delivery_helper(&mut cfg);
    drop_privileges(&cfg);
    let cfg = Arc::new(cfg);

    let (wake_tx, wake_rx) = mpsc::channel();

    // Test/debug helper: shut down when stdin reaches EOF. Lets supervisors
    // (and the integration tests) stop the daemon without signalling it,
    // which matters in sandboxes where the kill syscall is unavailable.
    if exit_on_stdin_eof {
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
    stop_delivery_helper(helper);
    log::info("homemta exiting");
}
