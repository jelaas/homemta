//! RFC 5321 path parsing and the classic local-part sanity checks.

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Addr {
    pub local: String,
    pub domain: String,
}

impl Addr {
    pub fn full(&self) -> String {
        format!("{}@{}", self.local, self.domain)
    }
}

/// Parse a reverse path or forward path. Accepts `<a@b>`, `<a@b> PARAMS`
/// and `a@b` (lenient submission). Returns Err on syntax problems.
pub fn parse(s: &str) -> Result<Addr, String> {
    let s = s.trim();
    let inner = if let Some(rest) = s.strip_prefix('<') {
        match rest.find('>') {
            Some(i) => &rest[..i],
            None => return Err("missing `>`".to_string()),
        }
    } else {
        if s.contains('<') || s.contains('>') {
            return Err("malformed angle brackets".to_string());
        }
        s
    };
    let Some(at) = inner.rfind('@') else {
        return Err("unqualified address".to_string());
    };
    let (local, domain) = (&inner[..at], &inner[at + 1..]);
    if local.is_empty() {
        return Err("empty local part".to_string());
    }
    if domain.is_empty() {
        return Err("empty domain".to_string());
    }
    if local.len() > 64 || inner.len() > 254 {
        return Err("address too long".to_string());
    }
    for c in local.chars() {
        if c.is_control() || c == ' ' || "\"()<>[];:\\".contains(c) {
            return Err(format!("invalid character in local part: {:?}", c));
        }
    }
    // Domain literal user@[192.0.2.1] is kept verbatim; other domains are
    // restricted to letters/digits/-/.
    let domain = if domain.starts_with('[') && domain.ends_with(']') {
        domain.to_string()
    } else {
        if !domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        {
            return Err("invalid character in domain".to_string());
        }
        domain.to_string()
    };
    Ok(Addr {
        local: local.to_string(),
        domain,
    })
}

/// Qualify an unqualified address with the primary hostname (submission mode).
pub fn qualify(local: &str, host: &str) -> Result<Addr, String> {
    parse(&format!("<{}@{}>", local, host))
}

/// ACL-style rule for local domains: local parts that start with a dot
/// or contain @ % ! / | are rejected.
pub fn restricted_local(local: &str) -> bool {
    local.starts_with('.') || local.chars().any(|c| "@%!/|".contains(c))
}

/// ACL-style rule for other domains: local parts that start with ./| or
/// contain @ % ! or the sequence /../ are rejected.
pub fn restricted_remote(local: &str) -> bool {
    local.starts_with(['.', '/', '|'])
        || local.chars().any(|c| "@%!".contains(c))
        || local.contains("/../")
}

/// Strip a `+suffix` from a local part (the classic +-addressing style).
pub fn strip_suffix(local: &str) -> &str {
    match local.find('+') {
        Some(i) => &local[..i],
        None => local,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic() {
        let a = parse("<user@example.com>").unwrap();
        assert_eq!(a.local, "user");
        assert_eq!(a.domain, "example.com");
        assert_eq!(a.full(), "user@example.com");
    }

    #[test]
    fn parse_lenient_and_params() {
        let a = parse("<user@example.com> SIZE=100").unwrap();
        assert_eq!(a.full(), "user@example.com");
        let b = parse("plain@example.com").unwrap();
        assert_eq!(b.full(), "plain@example.com");
        // Unqualified addresses are rejected here; the server qualifies them.
        assert!(parse("<postmaster>").is_err());
    }

    #[test]
    fn parse_errors() {
        assert!(parse("no-at-sign").is_err());
        assert!(parse("<>").is_err());
        assert!(parse("<a@b").is_err());
        assert!(parse("<a b@c>").is_err());
    }

    #[test]
    fn domain_literal() {
        let a = parse("<user@[192.0.2.1]>").unwrap();
        assert_eq!(a.domain, "[192.0.2.1]");
    }

    #[test]
    fn restricted() {
        assert!(restricted_local(".foo"));
        assert!(restricted_local("a/b"));
        assert!(restricted_local("a|b"));
        assert!(!restricted_local("normal.user"));
        assert!(restricted_remote("x@y"));
        assert!(restricted_remote("/x"));
        assert!(restricted_remote("a/../b"));
        assert!(!restricted_remote("a/b"));
    }

    #[test]
    fn suffixes() {
        assert_eq!(strip_suffix("jelaas+list"), "jelaas");
        assert_eq!(strip_suffix("jelaas"), "jelaas");
    }
}
