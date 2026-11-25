//! On-disk spool and queue runner.
//!
//! Each message is one file: a small metadata header (S/R/F/L/N/Z lines),
//! a blank line, then the CRLF-normalized message. Files are written
//! atomically (temp file + rename).
//!
//! Retry schedule follows the reference exim.conf:
//!   F,2h,15m; G,16h,1h,1.5; F,4d,6h
//! i.e. every 15 minutes for the first 2 hours, then geometrically growing
//! intervals (1h, 1.5h, ... capped at 16h) until 4 days after the first
//! failure, then the message bounces. Bounce messages themselves are frozen
//! after `bounce_freeze_after` and dropped after `frozen_timeout`.

use crate::bounce::{self, Failure};
use crate::config::Config;
use crate::log;
use crate::smtp_client;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};

static FILE_SEQ: AtomicU64 = AtomicU64::new(0);

struct SpoolMsg {
    sender: String,
    rcpts: Vec<String>,
    first_fail: i64,
    last_try: i64,
    tries: u64,
    frozen: i64,
    msg: Vec<u8>,
}

fn spool_path(cfg: &Config) -> &Path {
    Path::new(&cfg.spool_dir)
}

/// Write a queued message. `sender` may be empty (bounce).
pub fn enqueue(cfg: &Arc<Config>, sender: &str, rcpts: &[String], msg: &[u8]) -> Result<(), String> {
    let dir = spool_path(cfg);
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {}", dir.display(), e))?;
    let name = format!(
        "{:x}-{:x}-{}",
        log::unix_now(),
        std::process::id(),
        FILE_SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let mut data = String::new();
    data.push_str(&format!("S{}\n", sender));
    for r in rcpts {
        data.push_str(&format!("R{}\n", r));
    }
    data.push_str("F0\nL0\nN0\nZ0\n\n");
    let mut bytes = data.into_bytes();
    bytes.extend_from_slice(msg);

    let tmp = dir.join(format!(".{}.tmp", name));
    let final_path = dir.join(&name);
    std::fs::write(&tmp, &bytes).map_err(|e| format!("{}: {}", tmp.display(), e))?;
    std::fs::rename(&tmp, &final_path).map_err(|e| format!("{}: {}", final_path.display(), e))?;
    log::info(&format!(
        "queued message {} ({} bytes, {} recipients)",
        name,
        msg.len(),
        rcpts.len()
    ));
    Ok(())
}

fn read_spool(path: &Path) -> Option<SpoolMsg> {
    let data = std::fs::read(path).ok()?;
    let text = String::from_utf8_lossy(&data);
    let (head, body) = match text.split_once("\n\n") {
        Some((h, b)) => (h, b),
        None => return None,
    };
    let mut m = SpoolMsg {
        sender: String::new(),
        rcpts: Vec::new(),
        first_fail: 0,
        last_try: 0,
        tries: 0,
        frozen: 0,
        msg: Vec::new(),
    };
    for line in head.lines() {
        let (k, v) = line.split_at(1);
        match k {
            "S" => m.sender = v.to_string(),
            "R" => m.rcpts.push(v.to_string()),
            "F" => m.first_fail = v.parse().unwrap_or(0),
            "L" => m.last_try = v.parse().unwrap_or(0),
            "N" => m.tries = v.parse().unwrap_or(0),
            "Z" => m.frozen = v.parse().unwrap_or(0),
            _ => {}
        }
    }
    if m.rcpts.is_empty() {
        return None;
    }
    m.msg = body.as_bytes().to_vec();
    Some(m)
}

fn write_spool(path: &Path, m: &SpoolMsg) {
    let mut data = String::new();
    data.push_str(&format!("S{}\n", m.sender));
    for r in &m.rcpts {
        data.push_str(&format!("R{}\n", r));
    }
    data.push_str(&format!(
        "F{}\nL{}\nN{}\nZ{}\n\n",
        m.first_fail, m.last_try, m.tries, m.frozen
    ));
    let mut bytes = data.into_bytes();
    bytes.extend_from_slice(&m.msg);
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let tmp = path.with_file_name(format!(".{}.tmp", name));
    if std::fs::write(&tmp, &bytes).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

/// When should the next delivery attempt happen? None means "timed out".
fn next_try(cfg: &Config, first_fail: i64, last_try: i64) -> Option<i64> {
    let age = last_try.saturating_sub(first_fail);
    if age < 2 * 3600 {
        // F,2h,15m
        Some(last_try + cfg.retry_first_interval as i64)
    } else if age < cfg.retry_timeout as i64 {
        // G,16h,1h,1.5
        let steps = (age - 2 * 3600) / 3600;
        let mut interval = 3600u64;
        for _ in 0..steps {
            interval = (interval * 3 / 2).min(16 * 3600);
        }
        Some(last_try + interval as i64)
    } else {
        None
    }
}

/// Process every due spool file once.
fn process_once(cfg: &Arc<Config>, wake: &mpsc::Sender<()>) {
    let dir = spool_path(cfg);
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file() && !p.file_name().unwrap_or_default().to_string_lossy().starts_with('.'))
        .collect();
    files.sort();

    let now = log::unix_now();
    for path in files {
        if shutdown_flag() {
            break;
        }
        let Some(mut m) = read_spool(&path) else {
            log::warn(&format!("corrupt spool file {}, ignoring", path.display()));
            continue;
        };

        if m.frozen != 0 {
            if now - m.frozen > cfg.frozen_timeout as i64 {
                let _ = std::fs::remove_file(&path);
                log::info(&format!("removed frozen bounce {}", path.display()));
            }
            continue;
        }

        let due = if m.first_fail == 0 {
            true
        } else {
            match next_try(cfg, m.first_fail, m.last_try) {
                Some(t) => now >= t,
                None => true, // retry window expired -> bounce below
            }
        };
        if !due {
            continue;
        }

        match smtp_client::deliver(cfg, &m.sender, &m.rcpts, &m.msg) {
            Ok(fails) => {
                if fails.is_empty() {
                    let _ = std::fs::remove_file(&path);
                    log::info(&format!("delivered and removed {}", path.display()));
                    continue;
                }
                // Permanent failures per recipient: bounce each, keep the rest.
                let failed: std::collections::HashSet<String> =
                    fails.iter().map(|f| f.rcpt.clone()).collect();
                let kept: Vec<String> = m.rcpts.iter().filter(|r| !failed.contains(*r)).cloned().collect();
                for f in &fails {
                    bounce_recipient(
                        cfg,
                        wake,
                        &m.sender,
                        &m.msg,
                        &Failure {
                            rcpt: f.rcpt.clone(),
                            reason: format!("{} {}", f.code, f.text),
                        },
                    );
                }
                if kept.is_empty() {
                    let _ = std::fs::remove_file(&path);
                    log::info(&format!("delivered and removed {}", path.display()));
                } else {
                    m.rcpts = kept;
                    write_spool(&path, &m);
                    log::info(&format!(
                        "partial delivery of {}: {} recipients remain",
                        path.display(),
                        m.rcpts.len()
                    ));
                }
            }
            Err(smtp_client::Fail::Perm(e)) => {
                // Permanent failure for the whole message.
                log::info(&format!("permanent failure delivering {}: {}", path.display(), e));
                if m.sender.is_empty() {
                    let _ = std::fs::remove_file(&path);
                    log::info(&format!("bounce undeliverable, dropped {}", path.display()));
                } else {
                    for r in &m.rcpts {
                        bounce_recipient(
                            cfg,
                            wake,
                            &m.sender,
                            &m.msg,
                            &Failure { rcpt: r.clone(), reason: e.clone() },
                        );
                    }
                    let _ = std::fs::remove_file(&path);
                }
            }
            Err(smtp_client::Fail::Temp(e)) => {
                let first = if m.first_fail == 0 { now } else { m.first_fail };
                let timed_out = now - first >= cfg.retry_timeout as i64;
                if timed_out && !m.sender.is_empty() {
                    log::info(&format!(
                        "message {} timed out after {}s: bouncing",
                        path.display(),
                        cfg.retry_timeout
                    ));
                    for r in &m.rcpts {
                        bounce_recipient(
                            cfg,
                            wake,
                            &m.sender,
                            &m.msg,
                            &Failure {
                                rcpt: r.clone(),
                                reason: format!("delivery timed out: {}", e),
                            },
                        );
                    }
                    let _ = std::fs::remove_file(&path);
                } else if m.sender.is_empty() && now - first >= cfg.bounce_freeze_after as i64 {
                    log::info(&format!("freezing failing bounce {}", path.display()));
                    m.first_fail = first;
                    m.frozen = now;
                    write_spool(&path, &m);
                } else {
                    m.first_fail = first;
                    m.last_try = now;
                    m.tries += 1;
                    write_spool(&path, &m);
                    log::info(&format!(
                        "temporary failure for {} (try {}): {}",
                        path.display(),
                        m.tries,
                        e
                    ));
                }
            }
        }
    }
}

fn bounce_recipient(
    cfg: &Arc<Config>,
    wake: &mpsc::Sender<()>,
    sender: &str,
    original: &[u8],
    f: &Failure,
) {
    log::info(&format!("bouncing {}: {}", f.rcpt, f.reason));
    let body = bounce::build(&cfg.primary_hostname, sender, &[Failure { rcpt: f.rcpt.clone(), reason: f.reason.clone() }], original);
    bounce::deliver(cfg, sender, &body, wake);
}

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

pub fn request_shutdown() {
    SHUTDOWN.store(true, Ordering::Relaxed);
}

pub fn shutdown_flag() -> bool {
    SHUTDOWN.load(Ordering::Relaxed)
}

/// Queue runner loop. Woken immediately after every enqueue (including
/// bounces queued during queue processing, via the same channel);
/// otherwise scans on the configured interval.
pub fn runner(cfg: Arc<Config>, rx: mpsc::Receiver<()>, wake: mpsc::Sender<()>) {
    loop {
        if shutdown_flag() {
            break;
        }
        process_once(&cfg, &wake);
        match rx.recv_timeout(std::time::Duration::from_secs(cfg.queue_interval)) {
            Ok(()) => {} // woken by an enqueue
            Err(mpsc::RecvTimeoutError::Timeout) => {} // periodic scan
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    log::info("queue runner exiting");
}

/// Run the queue once and exit (for `homemta -q`).
pub fn run_once(cfg: &Arc<Config>) {
    let (tx, _rx) = mpsc::channel();
    process_once(cfg, &tx);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_schedule() {
        let cfg = Config::default();
        // First phase: every 15 minutes.
        assert_eq!(next_try(&cfg, 0, 0), Some(900));
        assert_eq!(next_try(&cfg, 0, 3599), Some(3599 + 900));
        // Geometric phase starts at 1h after the 2h mark.
        assert_eq!(next_try(&cfg, 0, 7200), Some(7200 + 3600));
        assert_eq!(next_try(&cfg, 0, 10800), Some(10800 + 5400));
        // Capped at 16h once the geometric growth reaches it.
        let t = 7200 + 7 * 3600;
        assert_eq!(next_try(&cfg, 0, t), Some(t + 16 * 3600));
        // Expired after the retry window.
        assert_eq!(next_try(&cfg, 0, cfg.retry_timeout as i64), None);
    }

    #[test]
    fn spool_roundtrip() {
        let tmp = std::env::temp_dir().join(format!("homemta-test-spool-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        let mut cfg = Config::default();
        cfg.spool_dir = tmp.display().to_string();
        let cfg = Arc::new(cfg);
        enqueue(
            &cfg,
            "a@b.c",
            &["x@y.z".to_string(), "q@r.s".to_string()],
            b"Subject: t\r\n\r\nbody\r\n",
        )
        .unwrap();
        let files: Vec<_> = std::fs::read_dir(&tmp)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| !p.file_name().unwrap().to_str().unwrap().starts_with('.'))
            .collect();
        assert_eq!(files.len(), 1);
        let m = read_spool(&files[0]).unwrap();
        assert_eq!(m.sender, "a@b.c");
        assert_eq!(m.rcpts, vec!["x@y.z".to_string(), "q@r.s".to_string()]);
        assert_eq!(m.msg, b"Subject: t\r\n\r\nbody\r\n");
    }
}
