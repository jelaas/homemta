//! End-to-end smoke tests: spawn the real homemta binary plus a fake
//! SMTPS smarthost, submit mail over SMTP (plain and STARTTLS), and check
//! local mbox delivery, smarthost relay with CRAM-MD5 auth, bounces and
//! queue retries.

use homemta::base64;
use homemta::md5;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, SanType,
};
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------- helpers

fn wait_for<F: Fn() -> bool>(what: &str, f: F) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if f() {
            return;
        }
        if Instant::now() > deadline {
            panic!("timeout waiting for {}", what);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn read_line(r: &mut impl BufRead) -> String {
    let mut s = String::new();
    r.read_line(&mut s).expect("read line");
    s.trim_end_matches(['\r', '\n']).to_string()
}

fn read_smtp_reply(r: &mut impl BufRead) -> (u16, Vec<String>) {
    let mut lines = Vec::new();
    loop {
        let l = read_line(r);
        let code: u16 = l[..3].parse().expect("reply code");
        let multiline = l.as_bytes().get(3) == Some(&b'-');
        lines.push(l);
        if !multiline {
            return (code, lines);
        }
    }
}

fn expect_code(r: &mut impl BufRead, expected: u16) -> (u16, Vec<String>) {
    let (code, lines) = read_smtp_reply(r);
    assert_eq!(code, expected, "unexpected reply: {:?}", lines);
    (code, lines)
}

enum SubConn {
    Plain(TcpStream),
    Tls(StreamOwned<ClientConnection, TcpStream>),
}

impl Read for SubConn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            SubConn::Plain(s) => s.read(buf),
            SubConn::Tls(s) => s.read(buf),
        }
    }
}

impl Write for SubConn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            SubConn::Plain(s) => s.write(buf),
            SubConn::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            SubConn::Plain(s) => s.flush(),
            SubConn::Tls(s) => s.flush(),
        }
    }
}

/// Submit a message to the MTA. Lines are joined with CRLF, dot-stuffed,
/// and terminated with "." as RFC 5321 requires.
fn smtp_submit(port: u16, use_starttls: bool, roots: &RootCertStore, sender: &str, rcpts: &[&str], lines: &[&str]) -> (u16, Vec<String>) {
    let sock = TcpStream::connect(("127.0.0.1", port)).expect("connect to MTA");
    sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut conn: SubConn = SubConn::Plain(sock);
    let mut rd = BufReader::new(&mut conn);
    expect_code(&mut rd, 220);
    rd.get_mut().write_all(b"EHLO tester\r\n").unwrap();
    rd.get_mut().flush().unwrap();
    let (_, ehlo) = expect_code(&mut rd, 250);
    if use_starttls {
        assert!(ehlo.iter().any(|l| l.contains("STARTTLS")), "STARTTLS not advertised: {:?}", ehlo);
        rd.get_mut().write_all(b"STARTTLS\r\n").unwrap();
        rd.get_mut().flush().unwrap();
        expect_code(&mut rd, 220);
        drop(rd);
        let sock = match conn {
            SubConn::Plain(s) => s,
            SubConn::Tls(_) => unreachable!(),
        };
        let client = ClientConnection::new(
            Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(roots.clone())
                    .with_no_client_auth(),
            ),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        let mut tls = StreamOwned::new(client, sock);
        tls.flush().unwrap(); // complete the handshake
        conn = SubConn::Tls(tls);
        rd = BufReader::new(&mut conn);
        rd.get_mut().write_all(b"EHLO tester\r\n").unwrap();
        rd.get_mut().flush().unwrap();
        expect_code(&mut rd, 250);
    }
    rd.get_mut().write_all(format!("MAIL FROM:<{}>\r\n", sender).as_bytes()).unwrap();
    rd.get_mut().flush().unwrap();
    expect_code(&mut rd, 250);
    for rcpt in rcpts {
        rd.get_mut().write_all(format!("RCPT TO:<{}>\r\n", rcpt).as_bytes()).unwrap();
        rd.get_mut().flush().unwrap();
        let (code, _) = read_smtp_reply(&mut rd);
        if code != 250 {
            return (code, Vec::new());
        }
    }
    rd.get_mut().write_all(b"DATA\r\n").unwrap();
    rd.get_mut().flush().unwrap();
    expect_code(&mut rd, 354);
    for l in lines {
        let line = l.strip_prefix('.').map(|_| format!(".{}", l)).unwrap_or_else(|| l.to_string());
        rd.get_mut().write_all(format!("{}\r\n", line).as_bytes()).unwrap();
    }
    rd.get_mut().write_all(b".\r\n").unwrap();
    rd.get_mut().flush().unwrap();
    let (code, reply) = read_smtp_reply(&mut rd);
    rd.get_mut().write_all(b"QUIT\r\n").unwrap();
    rd.get_mut().flush().unwrap();
    (code, reply)
}

// ------------------------------------------------------------- certificates

fn make_cert(
    ca: Option<(&rcgen::Certificate, &KeyPair)>,
    common_name: &str,
    sans: Vec<SanType>,
) -> (rcgen::Certificate, KeyPair) {
    let mut params = CertificateParams::new(Vec::new()).unwrap();
    params.distinguished_name.push(DnType::CommonName, common_name);
    params.subject_alt_names = sans;
    let key = KeyPair::generate().unwrap();
    let cert = match ca {
        Some((ca_cert, ca_key)) => params.signed_by(&key, ca_cert, ca_key).unwrap(),
        None => {
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.self_signed(&key).unwrap()
        }
    };
    (cert, key)
}

fn write_pem_file(path: &Path, cert_pem: &str, key_pem: Option<&str>) {
    let mut out = String::new();
    out.push_str(cert_pem);
    if let Some(k) = key_pem {
        out.push_str(k);
    }
    std::fs::write(path, out).unwrap();
}

// --------------------------------------------------------- fake smarthost

#[derive(Default)]
struct SmarthostState {
    connections: usize,
    refuse: usize,
    bad_rcpt: Option<String>,
    /// AUTH mechanisms to advertise (in this order).
    mechs: Vec<String>,
    /// The mechanism actually used on the last connection.
    last_mech: Option<String>,
    messages: Vec<Captured>,
}

#[derive(Clone)]
struct Captured {
    sender: String,
    rcpts: Vec<String>,
    data: String,
}

fn read_line_opt(r: &mut impl BufRead) -> Option<String> {
    let mut s = String::new();
    match r.read_line(&mut s) {
        Ok(0) => None,
        Ok(_) => Some(s.trim_end_matches(['\r', '\n']).to_string()),
        Err(_) => None,
    }
}

type SmtRd<'a> = BufReader<&'a mut StreamOwned<ServerConnection, TcpStream>>;

fn wline(rd: &mut SmtRd, s: &str) {
    rd.get_mut().write_all(format!("{}\r\n", s).as_bytes()).unwrap();
    rd.get_mut().flush().unwrap();
}

/// Fake smarthost side of SCRAM-SHA-256 (RFC 7677), verifying the client
/// proof with the shared secret and sending the server signature.
fn scram_server(rd: &mut SmtRd, _arg: &str) {
    wline(rd, "334 ");
    let cf_line = read_line_opt(rd).expect("client-first");
    let cf = String::from_utf8(base64::decode(&cf_line).expect("b64 client-first")).unwrap();
    let bare = cf.strip_prefix("n,,").expect("GS2 header");
    let mut user = String::new();
    let mut client_nonce = String::new();
    for part in bare.split(',') {
        if let Some((k, v)) = part.split_once('=') {
            match k {
                "n" => user = v.to_string(),
                "r" => client_nonce = v.to_string(),
                _ => {}
            }
        }
    }
    assert_eq!(user, "testuser");
    let salt = b"homemta-test-salt";
    let iterations = 4096u32;
    let combined_nonce = format!("{}-srvsrv", client_nonce);
    let server_first =
        format!("r={},s={},i={}", combined_nonce, base64::encode(salt), iterations);
    wline(rd, &format!("334 {}", base64::encode(server_first.as_bytes())));

    let cf_final_line = read_line_opt(rd).expect("client-final");
    let cf_final =
        String::from_utf8(base64::decode(&cf_final_line).expect("b64 client-final")).unwrap();
    let mut proof_b64 = None;
    let mut cb = "biws".to_string();
    for part in cf_final.split(',') {
        if let Some((k, v)) = part.split_once('=') {
            match k {
                "c" => cb = v.to_string(),
                "r" => assert_eq!(v, combined_nonce, "nonce mismatch"),
                "p" => proof_b64 = Some(v.to_string()),
                _ => {}
            }
        }
    }
    let proof = base64::decode(&proof_b64.expect("p= missing")).unwrap();
    let client_final_without_proof = format!("c={},r={}", cb, combined_nonce);
    let auth_message = format!("{},{},{}", bare, server_first, client_final_without_proof);
    let sf = homemta::scram::ServerFirst {
        nonce: combined_nonce.clone(),
        salt: salt.to_vec(),
        iterations,
    };
    assert!(
        homemta::scram::check_client_proof("secret", &sf, &auth_message, &proof),
        "SCRAM client proof mismatch"
    );
    let sig = homemta::scram::server_signature("secret", salt, iterations, &auth_message);
    wline(rd, &format!("334 {}", base64::encode(format!("v={}", sig).as_bytes())));
    read_line_opt(rd); // empty response
    wline(rd, "235 Authentication successful");
}

fn cram_server(rd: &mut SmtRd, _arg: &str) {
    wline(rd, "334 ZmFrZS1jaGFsbGVuZ2U="); // "fake-challenge"
    let resp = read_line_opt(rd).expect("CRAM-MD5 response");
    let expected = format!(
        "testuser {}",
        md5::hex(&md5::hmac_md5(b"secret", b"fake-challenge"))
    );
    assert_eq!(
        String::from_utf8(base64::decode(&resp).unwrap()).unwrap(),
        expected,
        "CRAM-MD5 response mismatch"
    );
    wline(rd, "235 Authentication successful");
}

fn plain_server(rd: &mut SmtRd, arg: &str) {
    let initial = arg.split_whitespace().nth(1);
    let creds = match initial {
        Some(b64) => base64::decode(b64).expect("b64 PLAIN creds"),
        None => {
            wline(rd, "334 ");
            let l = read_line_opt(rd).expect("PLAIN response");
            base64::decode(&l).expect("b64 PLAIN creds")
        }
    };
    assert_eq!(
        String::from_utf8(creds).unwrap(),
        "\0testuser\0secret",
        "PLAIN credentials mismatch"
    );
    wline(rd, "235 Authentication successful");
}

fn login_server(rd: &mut SmtRd) {
    wline(rd, "334 VXNlcm5hbWU6"); // "Username:"
    let u = read_line_opt(rd).expect("LOGIN username");
    assert_eq!(String::from_utf8(base64::decode(&u).unwrap()).unwrap(), "testuser");
    wline(rd, "334 UGFzc3dvcmQ6"); // "Password:"
    let p = read_line_opt(rd).expect("LOGIN password");
    assert_eq!(String::from_utf8(base64::decode(&p).unwrap()).unwrap(), "secret");
    wline(rd, "235 Authentication successful");
}

fn handle_smarthost_conn(
    sock: TcpStream,
    tls_cfg: Arc<ServerConfig>,
    state: Arc<Mutex<SmarthostState>>,
) {
    let mut tls = StreamOwned::new(ServerConnection::new(tls_cfg).unwrap(), sock);
    let mut rd = BufReader::new(&mut tls);
    // SMTPS (RFC 8314): the server greets immediately after the TLS
    // handshake, before any client commands.
    rd.get_mut().write_all(b"220 smarthost.test ESMTP\r\n").unwrap();
    rd.get_mut().flush().unwrap();
    let mut sender = String::new();
    let mut rcpts: Vec<String> = Vec::new();
    let mut authed = false;
    let mut data = String::new();
    loop {
        let Some(l) = read_line_opt(&mut rd) else {
            // Client went away: keep whatever was fully received.
            if !data.is_empty() {
                state.lock().unwrap().messages.push(Captured {
                    sender: sender.clone(),
                    rcpts: rcpts.clone(),
                    data: std::mem::take(&mut data),
                });
            }
            return;
        };
        let (verb, arg) = l.split_once(' ').map(|(v, a)| (v, a)).unwrap_or((l.as_str(), ""));
        match verb.to_ascii_uppercase().as_str() {
            "EHLO" | "HELO" => {
                let mechs = state.lock().unwrap().mechs.join(" ");
                let resp = format!(
                    "250-smarthost.test Hello\r\n250-SIZE 99999999\r\n250-8BITMIME\r\n250-AUTH {}\r\n250 HELP\r\n",
                    mechs
                );
                rd.get_mut().write_all(resp.as_bytes()).unwrap();
                rd.get_mut().flush().unwrap();
            }
            "AUTH" => {
                let mech = arg.split_whitespace().next().unwrap_or("");
                let mut st = state.lock().unwrap();
                st.last_mech = Some(mech.to_string());
                drop(st);
                match mech {
                    "SCRAM-SHA-256" => scram_server(&mut rd, arg),
                    "CRAM-MD5" => cram_server(&mut rd, arg),
                    "PLAIN" => plain_server(&mut rd, arg),
                    "LOGIN" => login_server(&mut rd),
                    _ => {
                        rd.get_mut().write_all(b"504 mechanism not supported\r\n").unwrap();
                        rd.get_mut().flush().unwrap();
                    }
                }
                authed = true;
            }
            "MAIL" => {
                assert!(authed, "mail without auth");
                let path = arg
                    .trim_start_matches("FROM:")
                    .trim()
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .trim_matches('<')
                    .trim_matches('>')
                    .to_string();
                sender = path;
                rd.get_mut().write_all(b"250 OK\r\n").unwrap();
                rd.get_mut().flush().unwrap();
            }
            "RCPT" => {
                let rcpt = arg.trim_start_matches("TO:").trim().trim_matches('<').trim_matches('>');
                let bad = { state.lock().unwrap().bad_rcpt.clone() };
                if bad.as_deref() == Some(rcpt) {
                    rd.get_mut().write_all(b"550 no such user\r\n").unwrap();
                    rd.get_mut().flush().unwrap();
                } else {
                    rcpts.push(rcpt.to_string());
                    rd.get_mut().write_all(b"250 OK\r\n").unwrap();
                    rd.get_mut().flush().unwrap();
                }
            }
            "DATA" => {
                rd.get_mut().write_all(b"354 go ahead\r\n").unwrap();
                rd.get_mut().flush().unwrap();
                loop {
                    let Some(l) = read_line_opt(&mut rd) else { return };
                    if l == "." {
                        break;
                    }
                    data.push_str(l.strip_prefix('.').unwrap_or(&l)); // unstuff
                    data.push('\n');
                }
                rd.get_mut().write_all(b"250 OK\r\n").unwrap();
                rd.get_mut().flush().unwrap();
            }
            "QUIT" => {
                rd.get_mut().write_all(b"221 bye\r\n").unwrap();
                rd.get_mut().flush().unwrap();
                state.lock().unwrap().messages.push(Captured {
                    sender: sender.clone(),
                    rcpts: rcpts.clone(),
                    data: std::mem::take(&mut data),
                });
                return;
            }
            _ => {
                rd.get_mut().write_all(b"500 huh\r\n").unwrap();
                rd.get_mut().flush().unwrap();
            }
        }
    }
}

fn start_smarthost(
    state: Arc<Mutex<SmarthostState>>,
    mechs: &[&str],
    ca: &rcgen::Certificate,
    ca_key: &KeyPair,
) -> (u16, std::thread::JoinHandle<()>) {
    state.lock().unwrap().mechs = mechs.iter().map(|s| s.to_string()).collect();
    let (cert, key) = make_cert(
        Some((ca, ca_key)),
        "smarthost.test",
        vec![
            SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            SanType::DnsName("smarthost.test".try_into().unwrap()),
        ],
    );
    let mut server_cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                key.serialize_der(),
            )),
        )
        .unwrap();
    server_cfg.ignore_client_order = true;
    let tls_cfg = Arc::new(server_cfg);

    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(sock) = stream else { break };
            {
                let mut st = state.lock().unwrap();
                st.connections += 1;
                if st.refuse > 0 {
                    st.refuse -= 1;
                    let mut s = sock;
                    let _ = s.write_all(b"421 try again later\r\n");
                    continue;
                }
            }
            let tls_cfg = tls_cfg.clone();
            let state = state.clone();
            std::thread::spawn(move || handle_smarthost_conn(sock, tls_cfg, state));
        }
    });
    (port, handle)
}

// ------------------------------------------------------------------- MTA

struct Mta {
    child: Child,
    stdin: Option<std::process::ChildStdin>,
    dir: PathBuf,
    mailbox: PathBuf,
    spool: PathBuf,
    port: u16,
}

impl Drop for Mta {
    fn drop(&mut self) {
        // Shut the MTA down by closing its stdin (--exit-on-stdin-eof).
        // Signal-based shutdown (kill) may be unavailable in sandboxes
        // where the kill syscall is blocked.
        drop(self.stdin.take());
        let _ = self.child.wait();
    }
}

/// Can this test environment drop privileges? Determines whether the
/// daemon runs the full privilege-separation path (drop to testuser +
/// setuid delivery helper) or the root fallback.
fn can_setuid() -> bool {
    static CAN: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *CAN.get_or_init(|| unsafe {
        let pid = libc::fork();
        if pid == 0 {
            // child: probe setuid and exit without touching any state
            if libc::setuid(1000) == 0 && libc::geteuid() == 1000 {
                libc::_exit(0);
            }
            libc::_exit(1);
        }
        if pid < 0 {
            return false;
        }
        let mut st = 0;
        libc::waitpid(pid, &mut st, 0);
        libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0
    })
}

fn start_mta(
    smarthost_port: Option<u16>,
    relay_from_hosts: &[&str],
    smarthost_auth: &str,
    cfg_extra: &str,
    ca_file: &Path,
    cert_file: &Path,
    key_file: &Path,
) -> Mta {
    // Pick a free port so parallel tests never collide.
    let probe = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let submit_port = probe.local_addr().unwrap().port();
    drop(probe);

    let dir = std::env::temp_dir().join(format!("homemta-e2e-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    std::fs::create_dir_all(dir.join("mail")).unwrap();
    std::fs::create_dir_all(dir.join("spool")).unwrap();
    std::fs::write(
        dir.join("passwd"),
        "root:x:0:0:root:/root:/bin/sh\ntestuser:x:1000:1000:Test:/home/testuser:/bin/sh\n",
    )
    .unwrap();
    std::fs::write(dir.join("group"), "mail:x:12:\n").unwrap();
    std::fs::write(
        dir.join("aliases"),
        format!(
            "postmaster: testuser\npipe: |cat > {}\n",
            dir.join("piped-out").display()
        ),
    )
    .unwrap();
    std::fs::write(dir.join("piped-out"), "").unwrap();
    std::fs::set_permissions(dir.join("piped-out"), std::os::unix::fs::PermissionsExt::from_mode(0o666)).unwrap();

    // Privilege separation: install a setuid-root copy of the binary as the
    // delivery helper, and drop the daemon to "testuser" when the
    // environment supports it.
    let helper = dir.join("homemta-deliver");
    std::fs::copy(env!("CARGO_BIN_EXE_homemta"), &helper).unwrap();
    let mut perms = std::fs::metadata(&helper).unwrap().permissions();
    use std::os::unix::fs::PermissionsExt;
    perms.set_mode(perms.mode() | 0o4755);
    std::fs::set_permissions(&helper, perms).unwrap();
    let user_cfg = if can_setuid() {
        format!(
            "\"user\": \"testuser\",\n\"deliver_helper\": \"{}\",",
            helper.display()
        )
    } else {
        "\"user\": \"root\",".to_string()
    };

    let relay_json = relay_from_hosts
        .iter()
        .map(|h| format!("\"{}\"", h))
        .collect::<Vec<_>>()
        .join(", ");
    let smarthost_json = match smarthost_port {
        Some(port) => format!(
            "\"smarthost\": {{ \"host\": \"127.0.0.1\", \"port\": {}, \"tls\": \"smtps\", \
             \"auth\": \"{}\", \"username\": \"testuser\", \"password\": \"secret\", \
             \"ca_file\": \"{}\" }},",
            port,
            smarthost_auth,
            ca_file.display(),
        ),
        None => String::new(),
    };
    let config = format!(
        "{{\n\
         // test config (jsonc)\n\
         \"primary_hostname\": \"test.example\",\n\
         \"local_domains\": [\"test.example\"],\n\
         \"relay_from_hosts\": [{}],\n\
         \"listen_addr\": \"127.0.0.1\",\n\
         \"listen_ports\": [{}],\n\
         \"spool_dir\": \"{}\",\n\
         \"mailbox_dir\": \"{}\",\n\
         \"aliases_file\": \"{}\",\n\
         \"passwd_file\": \"{}\",\n\
         \"group_file\": \"{}\",\n\
         \"log_file\": \"{}\",\n\
         \"max_message_size\": \"1M\",\n\
         {}\"tls\": {{ \"cert\": \"{}\", \"key\": \"{}\" }},\n\
         {}\"never_users\": [\"root\"],\n\
         \"queue_interval\": 1,\n\
         \"retry_first_interval\": 1,\n\
         {}\n\
         }}",
        relay_json,
        submit_port,
        dir.join("spool").display(),
        dir.join("mail").display(),
        dir.join("aliases").display(),
        dir.join("passwd").display(),
        dir.join("group").display(),
        dir.join("log").display(),
        smarthost_json,
        cert_file.display(),
        key_file.display(),
        user_cfg,
        cfg_extra,
    );
    let cfg_path = dir.join("homemta.jsonc");
    std::fs::write(&cfg_path, config).unwrap();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_homemta"));
    cmd.arg("-c")
        .arg(&cfg_path)
        .arg("--exit-on-stdin-eof")
        .arg("-d")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = cmd.spawn().expect("spawn homemta");
    let stdin = child.stdin.take();

    let mta = Mta {
        child,
        stdin,
        mailbox: dir.join("mail"),
        spool: dir.join("spool"),
        port: submit_port,
        dir,
    };
    // Wait until the listener is up.
    wait_for("MTA startup", || TcpStream::connect(("127.0.0.1", submit_port)).is_ok());
    mta
}

fn mbox_content(mta: &Mta, user: &str) -> String {
    std::fs::read_to_string(mta.mailbox.join(user)).unwrap_or_default()
}

fn spool_files(mta: &Mta) -> Vec<PathBuf> {
    std::fs::read_dir(&mta.spool)
        .map(|it| {
            it.filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| !p.file_name().unwrap().to_string_lossy().starts_with('.'))
                .collect()
        })
        .unwrap_or_default()
}

// ------------------------------------------------------------------ tests

struct CertFiles {
    ca: rcgen::Certificate,
    ca_key: KeyPair,
    ca_file: PathBuf,
    cert_file: PathBuf,
    key_file: PathBuf,
}

fn setup() -> CertFiles {
    let dir = std::env::temp_dir().join(format!("homemta-certs-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    std::fs::create_dir_all(&dir).unwrap();
    let (ca, ca_key) = make_cert(
        None,
        "homemta-test-ca",
        vec![SanType::DnsName("homemta-test-ca".try_into().unwrap())],
    );
    // Write a cacert.pem-style bundle: multiple PEM certificates in one
    // file (like a downloaded CA bundle). The MTA's smarthost.ca_file
    // points here and must handle all blocks.
    let ca_file = dir.join("cacert-bundle.pem");
    let mut bundle = String::new();
    bundle.push_str(&ca.pem());
    let (extra_cert, _extra_key) = make_cert(
        Some((&ca, &ca_key)),
        "unrelated.example",
        vec![SanType::DnsName("unrelated.example".try_into().unwrap())],
    );
    bundle.push_str(&extra_cert.pem());
    std::fs::write(&ca_file, bundle).unwrap();

    // MTA server certificate (STARTTLS).
    let (server_cert, server_key) = make_cert(
        Some((&ca, &ca_key)),
        "localhost",
        vec![
            SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            SanType::DnsName("localhost".try_into().unwrap()),
        ],
    );
    let cert_file = dir.join("server-cert.pem");
    let key_file = dir.join("server-key.pem");
    write_pem_file(&cert_file, &server_cert.pem(), None);
    write_pem_file(&key_file, "", Some(&server_key.serialize_pem()));
    CertFiles {
        ca,
        ca_key,
        ca_file,
        cert_file,
        key_file,
    }
}

fn client_roots(ca: &rcgen::Certificate) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    roots
}

#[test]
fn end_to_end_local_remote_starttls_and_auth() {
    let c = setup();
    let roots = client_roots(&c.ca);
    let state = Arc::new(Mutex::new(SmarthostState::default()));
    let (smarthost_port, _sm) =
        start_smarthost(state.clone(), &["SCRAM-SHA-256", "CRAM-MD5", "PLAIN", "LOGIN"], &c.ca, &c.ca_key);
    let mta = start_mta(
        Some(smarthost_port),
        &["127.0.0.1"],
        "auto",
        "",
        &c.ca_file,
        &c.cert_file,
        &c.key_file,
    );

    // Unknown local user must be rejected.
    let (code, _) = smtp_submit(
        mta.port,
        false,
        &roots,
        "testuser@test.example",
        &["nosuchuser@test.example"],
        &["Subject: x", "", "body"],
    );
    assert_eq!(code, 550, "unknown user should be rejected");

    // Local + remote delivery over STARTTLS.
    let (code, reply) = smtp_submit(
        mta.port,
        true,
        &roots,
        "testuser@test.example",
        &["testuser@test.example", "someone@example.org"],
        &[
            "Subject: e2e test",
            "To: someone@example.org",
            "",
            "Hello there",
            "From this line must be escaped in mbox",
            ".dot at start of line",
        ],
    );
    assert_eq!(code, 250, "submission failed: {:?}", reply);

    // Local mbox: exim/dovecot format.
    wait_for("local mbox delivery", || {
        mbox_content(&mta, "testuser").contains("Subject: e2e test")
    });
    let mbox = mbox_content(&mta, "testuser");
    assert!(mbox.starts_with("From testuser@test.example "), "mbox From_ line: {}", mbox.lines().next().unwrap_or(""));
    assert!(mbox.contains("\nReturn-path: <testuser@test.example>\n"));
    assert!(mbox.contains("\nEnvelope-to: <testuser@test.example>\n"));
    assert!(mbox.contains("\nDelivery-date: "));
    assert!(mbox.contains("\n>From this line must be escaped in mbox\n"), "From-escaping missing");
    assert!(mbox.contains("\n.dot at start of line\n"), "dot-stuffed line must be received unstuffed");

    // With privilege separation the mailbox must be owned by the user
    // (written via the setuid helper as uid 1000).
    if can_setuid() {
        use std::os::unix::fs::MetadataExt;
        let md = std::fs::metadata(mta.mailbox.join("testuser")).unwrap();
        assert_eq!(md.uid(), 1000, "mailbox must be owned by the user");
        assert_eq!(md.mode() & 0o777, 0o660, "mailbox mode 0660");
    }

    // Smarthost: SMTPS + SCRAM-SHA-256 (auto preference) + envelope intact.
    wait_for("smarthost delivery", || !state.lock().unwrap().messages.is_empty());
    let cap = state.lock().unwrap().messages[0].clone();
    assert_eq!(cap.sender, "testuser@test.example");
    assert_eq!(cap.rcpts, vec!["someone@example.org".to_string()]);
    assert_eq!(
        state.lock().unwrap().last_mech.as_deref(),
        Some("SCRAM-SHA-256"),
        "auto must prefer SCRAM-SHA-256"
    );
    assert!(cap.data.contains("Subject: e2e test"));
    assert!(cap.data.contains("Received: from tester ([127.0.0.1])"));
    assert!(cap.data.contains("Date: "), "Date added by submission");
    assert!(cap.data.contains("Message-ID: "), "Message-ID added by submission");
    assert!(cap.data.contains(".dot at start of line"), "dot-stuffing must be undone");

    // Queue must be empty after successful delivery.
    wait_for("queue drain", || spool_files(&mta).is_empty());
}

#[test]
fn remote_failure_bounces_to_local_sender() {
    let c = setup();
    let roots = client_roots(&c.ca);
    let state = Arc::new(Mutex::new(SmarthostState {
        bad_rcpt: Some("bad@example.org".to_string()),
        ..Default::default()
    }));
    let (smarthost_port, _sm) = start_smarthost(state.clone(), &["PLAIN"], &c.ca, &c.ca_key);
    let mta = start_mta(
        Some(smarthost_port),
        &["127.0.0.1"],
        "auto",
        "",
        &c.ca_file,
        &c.cert_file,
        &c.key_file,
    );

    let (code, reply) = smtp_submit(
        mta.port,
        false,
        &roots,
        "testuser@test.example",
        &["bad@example.org"],
        &["Subject: will bounce", "", "body"],
    );
    assert_eq!(code, 250, "submission failed: {:?}", reply);

    wait_for("bounce delivery", || {
        mbox_content(&mta, "testuser").contains("Mail delivery failed")
    });
    assert_eq!(state.lock().unwrap().last_mech.as_deref(), Some("PLAIN"));
    let mbox = mbox_content(&mta, "testuser");
    assert!(mbox.contains("Mail delivery failed: returning message to sender"));
    assert!(mbox.contains("Final-Recipient: rfc822; bad@example.org"));
    assert!(mbox.contains("550"), "bounce includes the smarthost error");
    assert!(mbox.contains("Subject: will bounce"), "original message attached");
    assert!(mbox.starts_with("From MAILER-DAEMON "), "bounce envelope sender is empty");
    wait_for("queue drain", || spool_files(&mta).is_empty());
}

#[test]
fn temporary_failure_is_retried() {
    let c = setup();
    let roots = client_roots(&c.ca);
    let state = Arc::new(Mutex::new(SmarthostState {
        refuse: 2,
        ..Default::default()
    }));
    let (smarthost_port, _sm) = start_smarthost(state.clone(), &["SCRAM-SHA-256"], &c.ca, &c.ca_key);
    let mta = start_mta(
        Some(smarthost_port),
        &["127.0.0.1"],
        "auto",
        "",
        &c.ca_file,
        &c.cert_file,
        &c.key_file,
    );

    let (code, _) = smtp_submit(
        mta.port,
        false,
        &roots,
        "testuser@test.example",
        &["later@example.org"],
        &["Subject: retry me", "", "body"],
    );
    assert_eq!(code, 250);

    wait_for("retried delivery", || !state.lock().unwrap().messages.is_empty());
    assert!(
        state.lock().unwrap().connections >= 3,
        "expected at least 3 connection attempts, got {}",
        state.lock().unwrap().connections
    );
    let cap = state.lock().unwrap().messages[0].clone();
    assert_eq!(cap.rcpts, vec!["later@example.org".to_string()]);
    wait_for("queue drain", || spool_files(&mta).is_empty());
}

#[test]
fn alias_pipe_delivery() {
    let c = setup();
    let roots = client_roots(&c.ca);
    let state = Arc::new(Mutex::new(SmarthostState::default()));
    let (smarthost_port, _sm) = start_smarthost(state.clone(), &["LOGIN"], &c.ca, &c.ca_key);
    let mta = start_mta(
        Some(smarthost_port),
        &["127.0.0.1"],
        "auto",
        "",
        &c.ca_file,
        &c.cert_file,
        &c.key_file,
    );

    let (code, reply) = smtp_submit(
        mta.port,
        false,
        &roots,
        "testuser@test.example",
        &["pipe@test.example"],
        &["Subject: piped", "", "pipe body"],
    );
    assert_eq!(code, 250, "submission failed: {:?}", reply);
    wait_for("pipe delivery", || {
        std::fs::read_to_string(mta.dir.join("piped-out"))
            .map(|s| s.contains("pipe body"))
            .unwrap_or(false)
    });
}

#[test]
fn remote_rejected_when_no_smarthost() {
    let c = setup();
    let roots = client_roots(&c.ca);
    // No smarthost in the config: remote rcpts must be refused at RCPT
    // even from a relay host.
    let mta = start_mta(
        None,
        &["127.0.0.1"],
        "auto",
        "",
        &c.ca_file,
        &c.cert_file,
        &c.key_file,
    );
    let (code, _) = smtp_submit(
        mta.port,
        false,
        &roots,
        "testuser@test.example",
        &["someone@example.org"],
        &["Subject: x", "", "body"],
    );
    assert_eq!(code, 550, "remote recipient without smarthost must be rejected");
    // Local mail still works.
    let (code, _) = smtp_submit(
        mta.port,
        false,
        &roots,
        "testuser@test.example",
        &["testuser@test.example"],
        &["Subject: local only", "", "body"],
    );
    assert_eq!(code, 250);
    wait_for("local delivery without smarthost", || {
        mbox_content(&mta, "testuser").contains("Subject: local only")
    });
}

/// An MX for external senders: with no relay_from_hosts entries, mail to
/// local domains is accepted from anyone, but relaying is refused.
#[test]
fn inbound_mx_accepts_local_rejects_relay() {
    let c = setup();
    let roots = client_roots(&c.ca);
    let state = Arc::new(Mutex::new(SmarthostState::default()));
    let (smarthost_port, _sm) = start_smarthost(state.clone(), &["PLAIN"], &c.ca, &c.ca_key);
    // Empty relay list: our loopback test peer acts like an external host.
    let mta = start_mta(
        Some(smarthost_port),
        &[],
        "auto",
        "",
        &c.ca_file,
        &c.cert_file,
        &c.key_file,
    );

    // Mail to a local user must be accepted and delivered.
    let (code, reply) = smtp_submit(
        mta.port,
        false,
        &roots,
        "external@sender.example",
        &["testuser@test.example"],
        &["Subject: inbound mx", "From: external@sender.example", "", "body"],
    );
    assert_eq!(code, 250, "inbound mail must be accepted: {:?}", reply);
    wait_for("inbound local delivery", || {
        mbox_content(&mta, "testuser").contains("Subject: inbound mx")
    });
    let mbox = mbox_content(&mta, "testuser");
    assert!(mbox.starts_with("From external@sender.example "));

    // Relaying to a remote domain must be refused.
    let (code, _) = smtp_submit(
        mta.port,
        false,
        &roots,
        "external@sender.example",
        &["victim@elsewhere.example"],
        &["Subject: relay attempt", "", "body"],
    );
    assert_eq!(code, 550, "relay attempt must be refused");

    // Nothing may have reached the smarthost.
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        state.lock().unwrap().messages.is_empty(),
        "no mail may reach the smarthost from a non-relay host"
    );
    // Unknown local users still get 550.
    let (code, _) = smtp_submit(
        mta.port,
        false,
        &roots,
        "external@sender.example",
        &["nosuchuser@test.example"],
        &["Subject: x", "", "body"],
    );
    assert_eq!(code, 550);
}

/// relay_from_hosts supports CIDR ranges (exim-style host lists).
#[test]
fn relay_cidr_allows_submission() {
    let c = setup();
    let roots = client_roots(&c.ca);
    let state = Arc::new(Mutex::new(SmarthostState::default()));
    let (smarthost_port, _sm) = start_smarthost(state.clone(), &["PLAIN"], &c.ca, &c.ca_key);
    let mta = start_mta(
        Some(smarthost_port),
        &["127.0.0.0/8"],
        "auto",
        "",
        &c.ca_file,
        &c.cert_file,
        &c.key_file,
    );

    let (code, reply) = smtp_submit(
        mta.port,
        false,
        &roots,
        "testuser@test.example",
        &["someone@example.org"],
        &["Subject: via cidr relay", "", "body"],
    );
    assert_eq!(code, 250, "CIDR relay host must be able to submit: {:?}", reply);
    wait_for("cidr smarthost delivery", || !state.lock().unwrap().messages.is_empty());
    assert_eq!(state.lock().unwrap().messages[0].rcpts, vec!["someone@example.org".to_string()]);
    wait_for("queue drain", || spool_files(&mta).is_empty());
}

/// CRAM-MD5 still works when it is the only mechanism offered.
#[test]
fn smarthost_auth_cram_md5() {
    let c = setup();
    let roots = client_roots(&c.ca);
    let state = Arc::new(Mutex::new(SmarthostState::default()));
    let (smarthost_port, _sm) = start_smarthost(state.clone(), &["CRAM-MD5"], &c.ca, &c.ca_key);
    let mta = start_mta(
        Some(smarthost_port),
        &["127.0.0.1"],
        "auto",
        "",
        &c.ca_file,
        &c.cert_file,
        &c.key_file,
    );

    let (code, _) = smtp_submit(
        mta.port,
        false,
        &roots,
        "testuser@test.example",
        &["cram@example.org"],
        &["Subject: cram", "", "body"],
    );
    assert_eq!(code, 250);
    wait_for("cram delivery", || !state.lock().unwrap().messages.is_empty());
    assert_eq!(state.lock().unwrap().last_mech.as_deref(), Some("CRAM-MD5"));
    wait_for("queue drain", || spool_files(&mta).is_empty());
}

/// Explicitly configured mechanism that the server does not offer fails
/// permanently (bounces) instead of hanging or falling back.
#[test]
fn smarthost_auth_mismatch_bounces() {
    let c = setup();
    let roots = client_roots(&c.ca);
    let state = Arc::new(Mutex::new(SmarthostState::default()));
    let (smarthost_port, _sm) = start_smarthost(state.clone(), &["PLAIN"], &c.ca, &c.ca_key);
    // Server offers only PLAIN, config demands CRAM-MD5.
    let mta = start_mta(
        Some(smarthost_port),
        &["127.0.0.1"],
        "cram-md5",
        "",
        &c.ca_file,
        &c.cert_file,
        &c.key_file,
    );

    let (code, _) = smtp_submit(
        mta.port,
        false,
        &roots,
        "testuser@test.example",
        &["x@example.org"],
        &["Subject: mismatch", "", "body"],
    );
    assert_eq!(code, 250);
    wait_for("auth mismatch bounce", || {
        mbox_content(&mta, "testuser").contains("Mail delivery failed")
    });
    assert!(state.lock().unwrap().messages.is_empty());
}

/// postmaster without an alias falls back to root, which never_users
/// forbids: the message must bounce instead of being delivered as root.
#[test]
fn never_users_forbids_root_delivery() {
    let c = setup();
    let roots = client_roots(&c.ca);
    let state = Arc::new(Mutex::new(SmarthostState::default()));
    let (smarthost_port, _sm) = start_smarthost(state.clone(), &["PLAIN"], &c.ca, &c.ca_key);
    let mta = start_mta(
        Some(smarthost_port),
        &["127.0.0.1"],
        "auto",
        "",
        &c.ca_file,
        &c.cert_file,
        &c.key_file,
    );
    // Drop the postmaster alias so postmaster resolves to root.
    std::fs::write(mta.dir.join("aliases"), "").unwrap();

    let (code, _) = smtp_submit(
        mta.port,
        false,
        &roots,
        "testuser@test.example",
        &["postmaster@test.example"],
        &["Subject: to root", "", "body"],
    );
    // postmaster is always accepted at RCPT; the delivery refusal
    // surfaces as a bounce.
    assert_eq!(code, 250);
    wait_for("postmaster bounce", || {
        mbox_content(&mta, "testuser").contains("Mail delivery failed")
    });
    let mbox = mbox_content(&mta, "testuser");
    assert!(mbox.contains("Final-Recipient: rfc822; postmaster@test.example"));
    assert!(mbox.contains("never_users"), "bounce must mention never_users: {}", mbox);
}
