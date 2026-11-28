//! SCRAM-SHA-256 SASL (RFC 7677 / RFC 5802) client and verification logic
//! in pure Rust. Used for smarthost authentication.

use crate::base64;
use crate::sha256::{hmac_sha256, pbkdf2_hmac_sha256};

fn xor(a: &mut [u8], b: &[u8]) {
    for (x, y) in a.iter_mut().zip(b.iter()) {
        *x ^= *y;
    }
}

/// Constant-time comparison for digests/signatures and the delivery
/// helper's shared secret.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    a.len() == b.len() && diff == 0
}

fn hmac(key: &[u8], msg: &[u8]) -> [u8; 32] {
    hmac_sha256(key, msg)
}

/// Generate a random base64 nonce. Fails instead of returning a
/// predictable value when no kernel randomness is available.
pub fn nonce() -> Result<String, String> {
    let mut buf = [0u8; 18];
    crate::random::fill(&mut buf)?;
    Ok(base64::encode(&buf))
}

/// Accepted PBKDF2 iteration counts from the server. RFC 7677 recommends
/// at least 4096; the upper bound stops a hostile or spoofed server from
/// pinning the queue runner in PBKDF2 for hours (u32::MAX iterations).
pub const MIN_ITERATIONS: u32 = 1;
pub const MAX_ITERATIONS: u32 = 1_000_000;

/// Client-first message: "n,,n=<user>,r=<nonce>".
pub fn client_first(username: &str, nonce: &str) -> String {
    // SASLprep is out of scope; usernames are used verbatim apart from the
    // RFC 5802 saslname escaping of ',' and '=' (which would otherwise
    // break the attribute syntax).
    let user = username.replace('=', "=3D").replace(',', "=2C");
    format!("n,,n={},r={}", user, nonce)
}

#[derive(Debug)]
pub struct ServerFirst {
    pub nonce: String,
    pub salt: Vec<u8>,
    pub iterations: u32,
}

/// Parse a server-first message "r=...,s=...,i=...".
pub fn parse_server_first(msg: &str) -> Result<ServerFirst, String> {
    let mut nonce = None;
    let mut salt = None;
    let mut iter = None;
    for part in msg.split(',') {
        let (k, v) = part
            .split_once('=')
            .ok_or_else(|| format!("bad SCRAM attribute: {}", part))?;
        match k {
            "r" => nonce = Some(v.to_string()),
            "s" => salt = Some(base64::decode(v).ok_or("bad SCRAM salt base64")?),
            "i" => {
                let n = v
                    .parse::<u32>()
                    .map_err(|_| format!("bad SCRAM iteration count: {}", v))?;
                if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&n) {
                    return Err(format!(
                        "SCRAM iteration count {} outside {}..={}",
                        n, MIN_ITERATIONS, MAX_ITERATIONS
                    ));
                }
                iter = Some(n)
            }
            "m" | "e" => return Err(format!("SCRAM extension not supported: {}", k)),
            _ => {}
        }
    }
    Ok(ServerFirst {
        nonce: nonce.ok_or("SCRAM server-first missing r=")?,
        salt: salt.ok_or("SCRAM server-first missing s=")?,
        iterations: iter.ok_or("SCRAM server-first missing i=")?,
    })
}

fn salted_password(password: &str, salt: &[u8], iterations: u32) -> Vec<u8> {
    pbkdf2_hmac_sha256(password.as_bytes(), salt, iterations, 32)
}

fn client_signature(stored_key: &[u8], auth_message: &str) -> [u8; 32] {
    hmac(stored_key, auth_message.as_bytes())
}

/// Build the client-final message and return (client_final_message, proof).
pub fn client_final(
    password: &str,
    client_first_bare: &str,
    server_first: &ServerFirst,
    client_nonce: &str,
) -> Result<(String, Vec<u8>), String> {
    if !server_first.nonce.starts_with(client_nonce) || server_first.nonce.len() <= client_nonce.len()
    {
        return Err("SCRAM server nonce does not extend the client nonce".to_string());
    }
    let client_final_without_proof = format!("c=biws,r={}", server_first.nonce);
    let auth_message = format!(
        "{},{},{}",
        client_first_bare, // = "n=<user>,r=<client nonce>"
        format_args!("r={},s={},i={}", server_first.nonce, base64::encode(&server_first.salt), server_first.iterations),
        client_final_without_proof
    );
    let salted = salted_password(password, &server_first.salt, server_first.iterations);
    let client_key = hmac(&salted, b"Client Key");
    let stored_key = crate::sha256::sha256(&client_key);
    let signature = client_signature(&stored_key, &auth_message);
    let mut proof = client_key.to_vec();
    xor(&mut proof, &signature);
    Ok((
        format!("{},p={}", client_final_without_proof, base64::encode(&proof)),
        proof,
    ))
}

/// Verify the server-final "v=..." signature (RFC 5802).
pub fn verify_server_final(
    password: &str,
    salt: &[u8],
    iterations: u32,
    auth_message: &str,
    server_final: &str,
) -> Result<(), String> {
    let mut v = None;
    for part in server_final.split(',') {
        if let Some((k, val)) = part.split_once('=') {
            if k == "v" {
                v = Some(base64::decode(val).ok_or("bad SCRAM server signature base64")?);
            }
            if k == "e" {
                return Err(format!("SCRAM error from server: {}", val));
            }
        }
    }
    let expected = {
        let salted = salted_password(password, salt, iterations);
        let server_key = hmac(&salted, b"Server Key");
        hmac(&server_key, auth_message.as_bytes()).to_vec()
    };
    match v {
        Some(v) if ct_eq(&v, &expected) => Ok(()),
        _ => Err("SCRAM server signature mismatch".to_string()),
    }
}

/// Server-side check of a client proof (used by tests and useful for
/// debugging): recompute the expected proof from the password.
#[allow(dead_code)]
pub fn check_client_proof(
    password: &str,
    server_first: &ServerFirst,
    auth_message: &str,
    proof: &[u8],
) -> bool {
    let salted = salted_password(password, &server_first.salt, server_first.iterations);
    let client_key = hmac(&salted, b"Client Key");
    let stored_key = crate::sha256::sha256(&client_key);
    let signature = client_signature(&stored_key, auth_message);
    let mut expected = client_key;
    xor(&mut expected, &signature);
    ct_eq(&expected, proof)
}

/// Compute the server signature for a given exchange (tests / debugging).
#[allow(dead_code)]
pub fn server_signature(
    password: &str,
    salt: &[u8],
    iterations: u32,
    auth_message: &str,
) -> String {
    let salted = salted_password(password, salt, iterations);
    let server_key = hmac(&salted, b"Server Key");
    base64::encode(&hmac(&server_key, auth_message.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 5802 section 5 exchange, computed with SHA-256 as SCRAM-SHA-256
    /// (RFC 7677) requires. Expected values verified against Python's
    /// hashlib PBKDF2/HMAC implementation.
    #[test]
    fn rfc5802_example_sha256() {
        let user = "user";
        let password = "pencil";
        let client_nonce = "fyko+d2lbbFgONRv9qkxdawL";
        let server_first_msg = "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096";

        let cf = client_first(user, client_nonce);
        assert_eq!(cf, "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL");
        let client_first_bare = cf.strip_prefix("n,,").unwrap();

        let sf = parse_server_first(server_first_msg).unwrap();
        let (final_msg, proof) =
            client_final(password, client_first_bare, &sf, client_nonce).unwrap();

        assert_eq!(
            final_msg,
            "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=qQRLRHGPDGjB+7iVAE7NNi5xEoHKHuLCHPNQ8BTmvds="
        );
        assert_eq!(base64::encode(&proof), "qQRLRHGPDGjB+7iVAE7NNi5xEoHKHuLCHPNQ8BTmvds=");

        // Auth message and server-side verification round-trip.
        let auth_message = format!(
            "{},{},{}",
            client_first_bare,
            server_first_msg,
            "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j"
        );
        assert!(check_client_proof(password, &sf, &auth_message, &proof));
        let sig = server_signature(password, &sf.salt, sf.iterations, &auth_message);
        assert_eq!(sig, "XKW6VuW1FANROQabnJBz1KaeCnQL/HZByQtX/iU+o30=");

        // Server-final verification from the client side.
        let server_final = format!("v={}", sig);
        verify_server_final(password, &sf.salt, sf.iterations, &auth_message, &server_final)
            .unwrap();
    }

    #[test]
    fn rejects_tampered_nonce() {
        let sf = parse_server_first("r=AAAA,s=QSXCR+Q6sek8bf92,i=4096").unwrap();
        let r = client_final("pencil", "n=user,r=BBBB", &sf, "BBBB");
        assert!(r.is_err());
    }

    #[test]
    fn nonce_is_base64() {
        let n = nonce().unwrap();
        assert!(!n.is_empty());
        assert!(base64::decode(&n).is_some());
    }

    #[test]
    fn iteration_count_bounded() {
        assert!(parse_server_first("r=A,s=QSXCR+Q6sek8bf92,i=0").is_err());
        assert!(parse_server_first("r=A,s=QSXCR+Q6sek8bf92,i=4294967295").is_err());
        assert!(parse_server_first("r=A,s=QSXCR+Q6sek8bf92,i=4096").is_ok());
    }

    #[test]
    fn username_is_escaped() {
        assert_eq!(client_first("a,b=c", "N"), "n,,n=a=2Cb=3Dc,r=N");
    }

    #[test]
    fn hex_helper() {
        assert_eq!(crate::md5::hex(b"\xde\xad"), "dead");
    }
}
