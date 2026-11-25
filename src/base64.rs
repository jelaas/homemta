//! Minimal RFC 4648 base64, no dependencies.

const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        out.push(TABLE[(b[0] >> 2) as usize] as char);
        out.push(TABLE[(((b[0] & 0x03) << 4) | (b[1] >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(((b[1] & 0x0f) << 2) | (b[2] >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(b[2] & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Decode base64, tolerating embedded whitespace (needed for PEM).
/// `=` marks padding; a padding byte may only appear in the last two
/// positions of a quartet.
pub fn decode(s: &str) -> Option<Vec<u8>> {
    let mut vals: Vec<u8> = Vec::with_capacity(s.len());
    for &c in s.as_bytes() {
        let v = match c {
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            b'=' => 255,
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        vals.push(v);
    }
    if vals.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(vals.len() / 4 * 3);
    for q in vals.chunks(4) {
        if q[0] == 255 || q[1] == 255 {
            return None; // padding may not start a quartet
        }
        out.push((q[0] << 2) | (q[1] >> 4));
        if q[2] != 255 {
            out.push(((q[1] & 0x0f) << 4) | (q[2] >> 2));
            if q[3] != 255 {
                out.push(((q[2] & 0x03) << 6) | q[3]);
            }
        } else if q[3] != 255 {
            return None;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg==");
        assert_eq!(encode(b"fo"), "Zm8=");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(encode(b"foob"), "Zm9vYg==");
        assert_eq!(encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn roundtrip() {
        for len in 0..64 {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let enc = encode(&data);
            assert_eq!(decode(&enc).unwrap(), data);
        }
    }

    #[test]
    fn decode_whitespace() {
        assert_eq!(
            decode("Z m 9\nv\rYmFy").unwrap(),
            b"foobar".to_vec()
        );
    }

    #[test]
    fn decode_garbage() {
        assert!(decode("a$$$").is_none());
        assert!(decode("Zg").is_none()); // not a full quartet
        assert!(decode("=m9v").is_none()); // padding at start
    }
}
