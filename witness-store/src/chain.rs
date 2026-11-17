//! Hash-chain line encoding (DESIGN.md §4.5).
//!
//! A stored line is a JSON object whose last key is `h`:
//! `{...,"h":"<64 hex>"}`. The hashed payload `B` is the line with the fixed-width
//! suffix `,"h":"<64 hex>"` removed (closing brace kept), and
//! `h_n = SHA256(h_{n-1} || B_n)`. Nothing is ever re-serialized, so no canonical
//! JSON form is needed.

use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

/// `h_0` for the very first record ever written.
pub const GENESIS: Hash = [0u8; 32];

const KEY: &[u8] = b",\"h\":\"";
const HEX_LEN: usize = 64;
/// `,"h":"` + 64 hex digits + closing quote and brace.
const SUFFIX_LEN: usize = KEY.len() + HEX_LEN + 2;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LineError {
    #[error("body must be a non-empty JSON object ending in '}}'")]
    BadBody,
    #[error("line is too short or missing the hash suffix")]
    NoSuffix,
    #[error("hash suffix is not 64 lowercase hex digits")]
    BadHex,
}

pub fn link(prev: &Hash, body: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update(prev);
    h.update(body);
    h.finalize().into()
}

pub fn to_hex(h: &Hash) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(HEX_LEN);
    for b in h {
        s.push(D[(b >> 4) as usize] as char);
        s.push(D[(b & 15) as usize] as char);
    }
    s
}

pub fn from_hex(s: &[u8]) -> Option<Hash> {
    if s.len() != HEX_LEN {
        return None;
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = (nib(s[2 * i])? << 4) | nib(s[2 * i + 1])?;
    }
    Some(out)
}

/// Builds the stored line (without trailing newline) for `body` chained after `prev`.
pub fn encode_line(prev: &Hash, body: &[u8]) -> Result<(Vec<u8>, Hash), LineError> {
    if body.len() < 3 || body[0] != b'{' || body[body.len() - 1] != b'}' {
        return Err(LineError::BadBody);
    }
    let h = link(prev, body);
    let mut line = Vec::with_capacity(body.len() + SUFFIX_LEN);
    line.extend_from_slice(&body[..body.len() - 1]);
    line.extend_from_slice(KEY);
    line.extend_from_slice(to_hex(&h).as_bytes());
    line.extend_from_slice(b"\"}");
    Ok((line, h))
}

/// Splits a stored line (no trailing newline) into the hashed body and the recorded hash.
pub fn decode_line(line: &[u8]) -> Result<(Vec<u8>, Hash), LineError> {
    if line.len() <= SUFFIX_LEN {
        return Err(LineError::NoSuffix);
    }
    let (head, suffix) = line.split_at(line.len() - SUFFIX_LEN);
    if !suffix.starts_with(KEY) || !suffix.ends_with(b"\"}") {
        return Err(LineError::NoSuffix);
    }
    let hex = &suffix[KEY.len()..KEY.len() + HEX_LEN];
    let h = from_hex(hex).ok_or(LineError::BadHex)?;
    let mut body = Vec::with_capacity(head.len() + 1);
    body.extend_from_slice(head);
    body.push(b'}');
    Ok((body, h))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let body = br#"{"seq":1,"type":"x"}"#;
        let (line, h) = encode_line(&GENESIS, body).unwrap();
        assert_eq!(h, link(&GENESIS, body));
        let (b2, h2) = decode_line(&line).unwrap();
        assert_eq!(b2, body);
        assert_eq!(h2, h);
        // The stored line is itself valid JSON.
        let v: serde_json::Value = serde_json::from_slice(&line).unwrap();
        assert_eq!(v["h"], to_hex(&h));
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(encode_line(&GENESIS, b"{}"), Err(LineError::BadBody));
        assert_eq!(encode_line(&GENESIS, b"[1]"), Err(LineError::BadBody));
        assert_eq!(decode_line(b"{\"a\":1}"), Err(LineError::NoSuffix));
        let (mut line, _) = encode_line(&GENESIS, br#"{"a":1}"#).unwrap();
        let n = line.len();
        line[n - 5] = b'Z';
        assert_eq!(decode_line(&line), Err(LineError::BadHex));
    }

    #[test]
    fn hex_roundtrip() {
        let h = link(&GENESIS, b"abc");
        assert_eq!(from_hex(to_hex(&h).as_bytes()), Some(h));
        assert_eq!(from_hex(b"ABCD"), None);
    }
}
