//! IPv4-only address resolution via musl libc getaddrinfo (AF_INET only).

use libc::{addrinfo, freeaddrinfo, gai_strerror, getaddrinfo, sockaddr_in, AF_INET, EAI_SYSTEM, SOCK_STREAM};
use std::ffi::{CStr, CString};
use std::net::Ipv4Addr;

pub fn resolve_a(host: &str) -> Result<Vec<Ipv4Addr>, String> {
    let h = host.trim().trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = h.parse::<Ipv4Addr>() {
        return Ok(vec![ip]);
    }
    let c = CString::new(h).map_err(|_| "invalid hostname".to_string())?;
    let hints = addrinfo {
        ai_flags: 0,
        ai_family: AF_INET,
        ai_socktype: SOCK_STREAM,
        ai_protocol: 0,
        ai_addrlen: 0,
        ai_addr: std::ptr::null_mut(),
        ai_canonname: std::ptr::null_mut(),
        ai_next: std::ptr::null_mut(),
    };
    let mut res: *mut addrinfo = std::ptr::null_mut();
    let rc = unsafe { getaddrinfo(c.as_ptr(), std::ptr::null(), &hints, &mut res) };
    if rc != 0 {
        let msg = if rc == EAI_SYSTEM {
            format!(
                "getaddrinfo({}) failed: {}",
                h,
                std::io::Error::last_os_error()
            )
        } else {
            let p = unsafe { gai_strerror(rc) };
            if p.is_null() {
                format!("getaddrinfo({}) error {}", h, rc)
            } else {
                unsafe { CStr::from_ptr(p) }
                    .to_string_lossy()
                    .into_owned()
            }
        };
        return Err(msg);
    }
    let mut out: Vec<Ipv4Addr> = Vec::new();
    let mut p = res;
    while !p.is_null() {
        let ai = unsafe { &*p };
        if ai.ai_family == AF_INET && ai.ai_addrlen as usize >= std::mem::size_of::<sockaddr_in>() {
            let sin = unsafe { &*(ai.ai_addr as *const sockaddr_in) };
            // sin_addr.s_addr is in network byte order.
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            if !out.contains(&ip) {
                out.push(ip);
            }
        }
        p = ai.ai_next;
    }
    unsafe { freeaddrinfo(res) };
    if out.is_empty() {
        Err(format!("no IPv4 address for {}", h))
    } else {
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_ip() {
        assert_eq!(
            resolve_a("192.0.2.1").unwrap(),
            vec!["192.0.2.1".parse::<Ipv4Addr>().unwrap()]
        );
    }

    #[test]
    fn bracketed_literal() {
        assert_eq!(
            resolve_a("[192.0.2.2]").unwrap(),
            vec!["192.0.2.2".parse::<Ipv4Addr>().unwrap()]
        );
    }

    #[test]
    fn loopback() {
        // Only works if the host resolves; in the musl test env it should.
        assert!(resolve_a("localhost").map(|v| !v.is_empty()).unwrap_or(false));
    }
}
