//! Minimal JSONC parser: JSON with `//` and `/* */` comments and trailing
//! commas. Hand-written, no dependencies.

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Integer number (rejects fractional/negative values).
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Num(n) if *n >= 0.0 && n.fract() == 0.0 => Some(*n as u64),
            _ => None,
        }
    }

    pub fn as_arr(&self) -> Option<&[Json]> {
        match self {
            Json::Arr(a) => Some(a),
            _ => None,
        }
    }
}

struct Parser<'a> {
    s: &'a [u8],
    pos: usize,
    line: usize,
}

pub fn parse(text: &str) -> Result<Json, String> {
    let mut p = Parser {
        s: text.as_bytes(),
        pos: 0,
        line: 1,
    };
    let v = p.value()?;
    p.skip_trivia()?;
    if p.pos != p.s.len() {
        return Err(format!("line {}: trailing data after JSON value", p.line));
    }
    Ok(v)
}

impl Parser<'_> {
    fn err(&self, msg: &str) -> String {
        format!("line {}: {}", self.line, msg)
    }

    /// Skip whitespace and comments (returns Err on unterminated comment).
    fn skip_trivia(&mut self) -> Result<(), String> {
        loop {
            match self.s.get(self.pos) {
                Some(b' ') | Some(b'\t') | Some(b'\r') => self.pos += 1,
                Some(b'\n') => {
                    self.pos += 1;
                    self.line += 1;
                }
                Some(b'/') if self.s.get(self.pos + 1) == Some(&b'/') => {
                    self.pos += 2;
                    while let Some(c) = self.s.get(self.pos) {
                        if *c == b'\n' {
                            break;
                        }
                        self.pos += 1;
                    }
                }
                Some(b'/') if self.s.get(self.pos + 1) == Some(&b'*') => {
                    self.pos += 2;
                    loop {
                        match self.s.get(self.pos) {
                            None => return Err(self.err("unterminated block comment")),
                            Some(b'*') if self.s.get(self.pos + 1) == Some(&b'/') => {
                                self.pos += 2;
                                break;
                            }
                            Some(b'\n') => {
                                self.pos += 1;
                                self.line += 1;
                            }
                            Some(_) => self.pos += 1,
                        }
                    }
                }
                _ => return Ok(()),
            }
        }
    }

    fn peek(&mut self) -> Result<u8, String> {
        self.skip_trivia()?;
        self.s
            .get(self.pos)
            .copied()
            .ok_or_else(|| self.err("unexpected end of input"))
    }

    fn value(&mut self) -> Result<Json, String> {
        let c = self.peek()?;
        match c {
            b'{' => self.object(),
            b'[' => self.array(),
            b'"' => self.string().map(Json::Str),
            b't' => {
                self.keyword("true")?;
                Ok(Json::Bool(true))
            }
            b'f' => {
                self.keyword("false")?;
                Ok(Json::Bool(false))
            }
            b'n' => {
                self.keyword("null")?;
                Ok(Json::Null)
            }
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(self.err(&format!("unexpected character `{}`", c as char))),
        }
    }

    fn keyword(&mut self, kw: &str) -> Result<(), String> {
        let end = self.pos + kw.len();
        if self.s.get(self.pos..end) == Some(kw.as_bytes()) {
            self.pos = end;
            Ok(())
        } else {
            Err(self.err(&format!("expected `{}`", kw)))
        }
    }

    fn object(&mut self) -> Result<Json, String> {
        self.pos += 1; // consume '{'
        let mut map: Vec<(String, Json)> = Vec::new();
        loop {
            let c = self.peek()?;
            if c == b'}' {
                self.pos += 1;
                return Ok(Json::Obj(map));
            }
            let key = self.string()?;
            let c = self.peek()?;
            if c != b':' {
                return Err(self.err("expected `:` after object key"));
            }
            self.pos += 1;
            let v = self.value()?;
            map.push((key, v));
            let c = self.peek()?;
            match c {
                b',' => {
                    self.pos += 1;
                    // trailing comma allowed
                    if self.peek()? == b'}' {
                        self.pos += 1;
                        return Ok(Json::Obj(map));
                    }
                }
                b'}' => {
                    self.pos += 1;
                    return Ok(Json::Obj(map));
                }
                _ => return Err(self.err("expected `,` or `}` in object")),
            }
        }
    }

    fn array(&mut self) -> Result<Json, String> {
        self.pos += 1; // consume '['
        let mut arr: Vec<Json> = Vec::new();
        loop {
            let c = self.peek()?;
            if c == b']' {
                self.pos += 1;
                return Ok(Json::Arr(arr));
            }
            let v = self.value()?;
            arr.push(v);
            let c = self.peek()?;
            match c {
                b',' => {
                    self.pos += 1;
                    if self.peek()? == b']' {
                        self.pos += 1;
                        return Ok(Json::Arr(arr));
                    }
                }
                b']' => {
                    self.pos += 1;
                    return Ok(Json::Arr(arr));
                }
                _ => return Err(self.err("expected `,` or `]` in array")),
            }
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.pos += 1; // consume '"'
        let mut out = String::new();
        loop {
            let c = self
                .s
                .get(self.pos)
                .copied()
                .ok_or_else(|| self.err("unterminated string"))?;
            match c {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    let e = self
                        .s
                        .get(self.pos + 1)
                        .copied()
                        .ok_or_else(|| self.err("unterminated escape"))?;
                    self.pos += 2;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hex = self
                                .s
                                .get(self.pos..self.pos + 4)
                                .ok_or_else(|| self.err("short \\u escape"))?;
                            self.pos += 4;
                            let code = std::str::from_utf8(hex)
                                .ok()
                                .and_then(|h| u32::from_str_radix(h, 16).ok())
                                .and_then(char::from_u32)
                                .ok_or_else(|| self.err("invalid \\u escape"))?;
                            out.push(code);
                        }
                        _ => return Err(self.err("invalid escape sequence")),
                    }
                }
                b'\n' => return Err(self.err("newline in string")),
                _ if c < 0x80 => {
                    out.push(c as char);
                    self.pos += 1;
                }
                _ => {
                    // Multi-byte UTF-8 character: copy it whole (pushing
                    // each byte as a char would turn "é" into "Ã©", e.g.
                    // breaking non-ASCII passwords). The input came from a
                    // &str, so it is valid UTF-8; still checked, not assumed.
                    let len = match c {
                        0xc0..=0xdf => 2,
                        0xe0..=0xef => 3,
                        0xf0..=0xf7 => 4,
                        _ => return Err(self.err("invalid UTF-8 in string")),
                    };
                    let ch = self
                        .s
                        .get(self.pos..self.pos + len)
                        .and_then(|b| std::str::from_utf8(b).ok())
                        .ok_or_else(|| self.err("invalid UTF-8 in string"))?;
                    out.push_str(ch);
                    self.pos += len;
                }
            }
        }
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.pos;
        if self.s.get(self.pos) == Some(&b'-') {
            self.pos += 1;
        }
        while matches!(self.s.get(self.pos), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        if self.s.get(self.pos) == Some(&b'.') {
            self.pos += 1;
            while matches!(self.s.get(self.pos), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.s.get(self.pos), Some(b'e') | Some(b'E')) {
            self.pos += 1;
            if matches!(self.s.get(self.pos), Some(b'+') | Some(b'-')) {
                self.pos += 1;
            }
            while matches!(self.s.get(self.pos), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        let text = std::str::from_utf8(&self.s[start..self.pos])
            .map_err(|_| self.err("invalid number"))?;
        text.parse::<f64>()
            .map(Json::Num)
            .map_err(|_| self.err("invalid number"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_ascii_strings_kept() {
        let j = parse("{\"p\": \"p\u{e5}ss\u{2603}\u{1f600}\"}").unwrap();
        assert_eq!(j.get("p").unwrap().as_str(), Some("p\u{e5}ss\u{2603}\u{1f600}"));
    }

    #[test]
    fn basic_types() {
        let j = parse(r#"{"a": 1, "b": -2.5, "c": "x\ny", "d": true, "e": null, "f": [1,2,3]}"#)
            .unwrap();
        assert_eq!(j.get("a").unwrap().as_u64(), Some(1));
        assert_eq!(j.get("b").unwrap(), &Json::Num(-2.5));
        assert_eq!(j.get("c").unwrap().as_str(), Some("x\ny"));
        assert_eq!(j.get("d").unwrap().as_bool(), Some(true));
        assert_eq!(j.get("e").unwrap(), &Json::Null);
        assert_eq!(j.get("f").unwrap().as_arr().unwrap().len(), 3);
    }

    #[test]
    fn comments_and_trailing_commas() {
        let j = parse(
            r#"{
            // line comment
            "a": 1, // trailing
            /* block
               comment */
            "b": [1, 2,],  // trailing comma in array
            "c": { "d": "e", },
        }"#,
        )
        .unwrap();
        assert_eq!(j.get("a").unwrap().as_u64(), Some(1));
        assert_eq!(j.get("b").unwrap().as_arr().unwrap().len(), 2);
        assert_eq!(j.get("c").unwrap().get("d").unwrap().as_str(), Some("e"));
    }

    #[test]
    fn comment_markers_inside_strings() {
        let j = parse(r#"{"url": "http://example.com/*x*/", "p": "a//b"}"#).unwrap();
        assert_eq!(j.get("url").unwrap().as_str(), Some("http://example.com/*x*/"));
        assert_eq!(j.get("p").unwrap().as_str(), Some("a//b"));
    }

    #[test]
    fn unicode_escapes() {
        let j = parse(r#"{"x": "\u0041\u00e9"}"#).unwrap();
        assert_eq!(j.get("x").unwrap().as_str(), Some("Aé"));
    }

    #[test]
    fn errors() {
        assert!(parse("{").is_err());
        assert!(parse(r#"{"a": }"#).is_err());
        assert!(parse("/* unterminated").is_err());
        assert!(parse(r#"{"a": 1} extra"#).is_err());
        assert!(parse(r#"{"a" 1}"#).is_err());
        assert!(parse(r#"{"a": "unterminated}"#).is_err());
    }

    #[test]
    fn nested_objects() {
        let j = parse(r#"{"s": {"host": "h", "port": 465, "tls": "smtps"}}"#).unwrap();
        let s = j.get("s").unwrap();
        assert_eq!(s.get("host").unwrap().as_str(), Some("h"));
        assert_eq!(s.get("port").unwrap().as_u64(), Some(465));
    }
}
