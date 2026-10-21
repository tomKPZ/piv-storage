//! Minimal strict JSON reader for `cryptsetup luksDump --dump-json-metadata`.
//!
//! Only what LUKS2 metadata needs: objects, arrays, strings (with escapes),
//! integers, booleans and null. Duplicate object keys and trailing data are
//! rejected. Numbers keep their source text; callers parse what they use.

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(map) => map.get(key),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&BTreeMap<String, Value>> {
        match self {
            Value::Object(map) => Some(map),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Number(n) if !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) => n.parse().ok(),
            _ => None,
        }
    }

    /// Python-style truthiness, used only for LUKS `config.requirements`.
    pub fn is_truthy(&self) -> bool {
        match self {
            Value::Null => false,
            Value::Bool(b) => *b,
            Value::Number(n) => n.parse::<f64>().map_or(true, |v| v != 0.0),
            Value::String(s) => !s.is_empty(),
            Value::Array(a) => !a.is_empty(),
            Value::Object(o) => !o.is_empty(),
        }
    }
}

pub fn parse(text: &str) -> Result<Value, String> {
    let mut parser = Parser { bytes: text.as_bytes(), pos: 0, depth: 0 };
    parser.ws();
    let value = parser.value()?;
    parser.ws();
    if parser.pos != parser.bytes.len() {
        return Err("Trailing data after JSON value".into());
    }
    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    depth: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.bytes.get(self.pos) {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn expect(&mut self, literal: &str) -> Result<(), String> {
        if self.bytes[self.pos..].starts_with(literal.as_bytes()) {
            self.pos += literal.len();
            Ok(())
        } else {
            Err(format!("Invalid JSON at byte {}", self.pos))
        }
    }

    fn value(&mut self) -> Result<Value, String> {
        match self.peek() {
            Some(b'{') => self.nested(Self::object),
            Some(b'[') => self.nested(Self::array),
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b't') => self.expect("true").map(|_| Value::Bool(true)),
            Some(b'f') => self.expect("false").map(|_| Value::Bool(false)),
            Some(b'n') => self.expect("null").map(|_| Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(format!("Invalid JSON at byte {}", self.pos)),
        }
    }

    fn nested(&mut self, f: fn(&mut Self) -> Result<Value, String>) -> Result<Value, String> {
        self.depth += 1;
        if self.depth > 64 {
            return Err("JSON nesting too deep".into());
        }
        let value = f(self);
        self.depth -= 1;
        value
    }

    fn object(&mut self) -> Result<Value, String> {
        self.pos += 1;
        let mut map = BTreeMap::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Object(map));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(format!("Expected object key at byte {}", self.pos));
            }
            let key = self.string()?;
            self.ws();
            self.expect(":")?;
            self.ws();
            let value = self.value()?;
            if map.insert(key, value).is_some() {
                return Err("Duplicate JSON object key".into());
            }
            self.ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Value::Object(map));
                }
                _ => return Err(format!("Invalid JSON object at byte {}", self.pos)),
            }
        }
    }

    fn array(&mut self) -> Result<Value, String> {
        self.pos += 1;
        let mut items = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.ws();
            items.push(self.value()?);
            self.ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err(format!("Invalid JSON array at byte {}", self.pos)),
            }
        }
    }

    fn number(&mut self) -> Result<Value, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let digits = self.pos;
        while let Some(b'0'..=b'9') = self.peek() {
            self.pos += 1;
        }
        if self.pos == digits || (self.bytes[digits] == b'0' && self.pos - digits > 1) {
            return Err(format!("Invalid JSON number at byte {start}"));
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            let fraction = self.pos;
            while let Some(b'0'..=b'9') = self.peek() {
                self.pos += 1;
            }
            if self.pos == fraction {
                return Err(format!("Invalid JSON number at byte {start}"));
            }
        }
        if let Some(b'e' | b'E') = self.peek() {
            self.pos += 1;
            if let Some(b'+' | b'-') = self.peek() {
                self.pos += 1;
            }
            let exponent = self.pos;
            while let Some(b'0'..=b'9') = self.peek() {
                self.pos += 1;
            }
            if self.pos == exponent {
                return Err(format!("Invalid JSON number at byte {start}"));
            }
        }
        Ok(Value::Number(String::from_utf8_lossy(&self.bytes[start..self.pos]).into_owned()))
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let digits = self.bytes.get(self.pos..self.pos + 4).ok_or("Truncated JSON escape")?;
        let text = std::str::from_utf8(digits).map_err(|_| "Invalid JSON escape")?;
        let value = u32::from_str_radix(text, 16).map_err(|_| "Invalid JSON escape")?;
        self.pos += 4;
        Ok(value)
    }

    fn string(&mut self) -> Result<String, String> {
        self.pos += 1;
        let mut out = String::new();
        loop {
            let start = self.pos;
            while let Some(b) = self.peek() {
                if b == b'"' || b == b'\\' || b < 0x20 {
                    break;
                }
                self.pos += 1;
            }
            out.push_str(std::str::from_utf8(&self.bytes[start..self.pos]).map_err(|_| "Invalid UTF-8 in JSON")?);
            match self.peek() {
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.pos += 1;
                    let escape = self.peek().ok_or("Truncated JSON escape")?;
                    self.pos += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let mut code = self.hex4()?;
                            if (0xd800..0xdc00).contains(&code) {
                                self.expect("\\u")?;
                                let low = self.hex4()?;
                                if !(0xdc00..0xe000).contains(&low) {
                                    return Err("Invalid JSON surrogate pair".into());
                                }
                                code = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
                            }
                            out.push(char::from_u32(code).ok_or("Invalid JSON code point")?);
                        }
                        _ => return Err("Invalid JSON escape".into()),
                    }
                }
                _ => return Err("Unterminated or invalid JSON string".into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_luks_like_metadata() {
        let value = parse(r#"{"config":{"json_size":"12288","requirements":{}},
            "segments":{"0":{"type":"crypt","offset":"16777216","size":"dynamic","iv_tweak":"0",
            "encryption":"aegis128-random","sector_size":4096,
            "integrity":{"type":"aead","journal_encryption":"none","journal_integrity":"none"}}},
            "list":[1,-2.5e3,true,false,null,"a\u00e9\ud83d\ude00\n"]}"#)
        .unwrap();
        let segment = value.get("segments").unwrap().get("0").unwrap();
        assert_eq!(segment.get("sector_size").unwrap().as_u64(), Some(4096));
        assert_eq!(segment.get("offset").unwrap().as_str(), Some("16777216"));
        assert!(!value.get("config").unwrap().get("requirements").unwrap().is_truthy());
        match value.get("list").unwrap() {
            Value::Array(items) => assert_eq!(items[5], Value::String("a\u{e9}\u{1f600}\n".into())),
            _ => panic!(),
        }
    }

    #[test]
    fn rejects_malformed_input() {
        for text in ["", "{", "{\"a\":1,}", "[1 2]", "{\"a\":1}x", "01", "\"\\x\"", "{\"a\":1,\"a\":2}",
                     "\"\u{1}\"", "1.", "-"] {
            assert!(parse(text).is_err(), "{text:?}");
        }
    }
}
