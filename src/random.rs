//! Kernel randomness: getrandom(2), falling back to /dev/urandom.
//!
//! Fails closed: callers get an error instead of a predictable value
//! (no time-based or all-zero fallbacks for secrets, nonces or names).

pub fn fill(buf: &mut [u8]) -> Result<(), String> {
    let mut off = 0;
    while off < buf.len() {
        let rest = &mut buf[off..];
        let n = unsafe { libc::getrandom(rest.as_mut_ptr() as *mut libc::c_void, rest.len(), 0) };
        if n > 0 {
            off += n as usize;
            continue;
        }
        if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        break;
    }
    if off == buf.len() {
        return Ok(());
    }
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(buf))
        .map_err(|e| format!("no kernel randomness available: {}", e))
}

#[cfg(test)]
mod tests {
    #[test]
    fn fills_and_differs() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        super::fill(&mut a).unwrap();
        super::fill(&mut b).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }
}
