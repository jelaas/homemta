//! Tiny logger: timestamps + messages to stderr and/or a log file.
//! Timestamps use musl localtime_r; musl's `struct tm` provides tm_gmtoff,
//! which we need for RFC 2822 dates.

use libc::{localtime_r, time, tm};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

static LOG_FILE: Mutex<Option<std::fs::File>> = Mutex::new(None);
static DEBUG: AtomicBool = AtomicBool::new(false);

const WDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

pub fn init(path: Option<&str>, debug: bool) {
    if let Some(p) = path {
        match std::fs::OpenOptions::new().create(true).append(true).open(p) {
            Ok(f) => *LOG_FILE.lock().unwrap() = Some(f),
            Err(e) => eprintln!("homemta: cannot open log file {}: {}", p, e),
        }
    }
    DEBUG.store(debug, Ordering::Relaxed);
}

/// Unix time in seconds. Avoids naming libc::time_t (deprecated alias);
/// on musl x86_64 time_t is a 64-bit integer.
#[allow(deprecated)]
fn now_secs() -> i64 {
    let mut t: i64 = 0;
    unsafe {
        time(&mut t as *mut i64 as *mut libc::time_t);
    }
    t
}

#[allow(deprecated)]
fn now_tm() -> tm {
    unsafe {
        let t = now_secs();
        let mut tv: tm = std::mem::zeroed();
        localtime_r(&t as *const i64 as *const libc::time_t, &mut tv);
        tv
    }
}

/// Local timestamp for log lines: "2026-11-24 21:03:05".
pub fn ts_local() -> String {
    let t = now_tm();
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        t.tm_year + 1900,
        t.tm_mon + 1,
        t.tm_mday,
        t.tm_hour,
        t.tm_min,
        t.tm_sec
    )
}

/// RFC 2822 date with numeric zone: "Tue, 24 Nov 2026 21:03:05 +0100".
pub fn rfc2822_now() -> String {
    let t = now_tm();
    let off = t.tm_gmtoff;
    let (sign, ao) = if off < 0 { ('-', -off) } else { ('+', off) };
    format!(
        "{}, {} {} {:04} {:02}:{:02}:{:02} {}{:02}{:02}",
        WDAYS[t.tm_wday as usize],
        t.tm_mday,
        MONTHS[t.tm_mon as usize],
        t.tm_year + 1900,
        t.tm_hour,
        t.tm_min,
        t.tm_sec,
        sign,
        ao / 3600,
        (ao % 3600) / 60
    )
}

/// ctime(3)-style string for mbox "From " lines: "Tue Nov 24 21:03:05 2026".
pub fn ctime_now() -> String {
    let t = now_tm();
    format!(
        "{} {} {:>2} {:02}:{:02}:{:02} {:04}",
        WDAYS[t.tm_wday as usize],
        MONTHS[t.tm_mon as usize],
        t.tm_mday,
        t.tm_hour,
        t.tm_min,
        t.tm_sec,
        t.tm_year + 1900
    )
}

/// Unix time in seconds.
pub fn unix_now() -> i64 {
    now_secs()
}

fn emit(level: &str, msg: &str) {
    let line = format!("{} {} {}\n", ts_local(), level, msg);
    let mut guard = LOG_FILE.lock().unwrap();
    if let Some(f) = guard.as_mut() {
        let _ = f.write_all(line.as_bytes());
        let _ = f.flush();
    } else {
        let _ = std::io::stderr().write_all(line.as_bytes());
    }
    if DEBUG.load(Ordering::Relaxed) {
        let _ = std::io::stderr().write_all(line.as_bytes());
    }
}

pub fn info(msg: &str) {
    emit(" ", msg);
}

pub fn debug(msg: &str) {
    if DEBUG.load(Ordering::Relaxed) {
        emit("D", msg);
    }
}

pub fn warn(msg: &str) {
    emit("-Warning", msg);
}

/// Raw fd of the log file, if one is configured (used by the delivery
/// helper to keep exactly the fds it needs when closing inherited ones).
pub fn file_fd() -> Option<i32> {
    use std::os::unix::io::AsRawFd;
    LOG_FILE.lock().unwrap().as_ref().map(|f| f.as_raw_fd())
}

pub fn error(msg: &str) {
    emit("**Error", msg);
}
