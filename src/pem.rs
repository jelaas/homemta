//! Minimal PEM block parser. Returns (label, DER bytes) pairs.
//! Used for TLS certificates, private keys and CA bundles so we do not
//! need an extra parsing dependency.

use crate::base64;

pub fn blocks(text: &str) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("-----BEGIN ") {
            if let Some(label) = rest.strip_suffix("-----") {
                let mut b64 = String::new();
                let mut closed = false;
                for inner in lines.by_ref() {
                    let inner = inner.trim();
                    if inner.starts_with("-----END ") {
                        closed = true;
                        break;
                    }
                    b64.push_str(inner);
                }
                if closed {
                    if let Some(der) = base64::decode(&b64) {
                        out.push((label.to_string(), der));
                    }
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_multiple_blocks() {
        let text = "junk before\n\
-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n\
-----BEGIN PRIVATE KEY-----\nYmFy\n-----END PRIVATE KEY-----\n";
        let b = blocks(text);
        assert_eq!(b.len(), 2);
        assert_eq!(b[0].0, "CERTIFICATE");
        assert_eq!(b[0].1, b"foo");
        assert_eq!(b[1].0, "PRIVATE KEY");
        assert_eq!(b[1].1, b"bar");
    }

    #[test]
    fn ignores_unclosed() {
        let text = "-----BEGIN CERTIFICATE-----\nZm9v\n";
        assert!(blocks(text).is_empty());
    }
}
