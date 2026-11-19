//! Blocking client for the daemon API (DESIGN.md §9): HTTP/1.1 over a Unix socket.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;

pub const DEFAULT_SOCKET: &str = "/run/witness/witness.sock";

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("cannot reach witnessd at {path}: {source}")]
    Connect {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("i/o error talking to witnessd: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed response from witnessd: {0}")]
    Protocol(String),
    #[error("witnessd returned {status}: {title}: {detail}")]
    Api {
        status: u16,
        title: String,
        detail: String,
    },
}

pub type Result<T> = std::result::Result<T, ClientError>;

#[derive(Clone)]
pub struct Client {
    socket: PathBuf,
    timeout: Duration,
}

/// Percent-encodes a query-string value.
pub fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

struct Head {
    status: u16,
    chunked: bool,
    length: Option<usize>,
}

fn read_head(r: &mut impl BufRead) -> Result<Head> {
    let mut line = String::new();
    r.read_line(&mut line)?;
    let status = line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ClientError::Protocol(format!("bad status line {line:?}")))?;
    let (mut chunked, mut length) = (false, None);
    loop {
        line.clear();
        if r.read_line(&mut line)? == 0 {
            return Err(ClientError::Protocol("connection closed in headers".into()));
        }
        let l = line.trim_end();
        if l.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
            if k == "transfer-encoding" && v.eq_ignore_ascii_case("chunked") {
                chunked = true;
            } else if k == "content-length" {
                length = v.parse().ok();
            }
        }
    }
    Ok(Head {
        status,
        chunked,
        length,
    })
}

/// Reads one chunk of a chunked body; `None` at the terminating zero-length chunk.
fn read_chunk(r: &mut impl BufRead) -> Result<Option<Vec<u8>>> {
    let mut line = String::new();
    if r.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    let n = usize::from_str_radix(line.trim().split(';').next().unwrap_or("0"), 16)
        .map_err(|_| ClientError::Protocol(format!("bad chunk size {line:?}")))?;
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    let mut crlf = [0u8; 2];
    r.read_exact(&mut crlf)?;
    Ok((n > 0).then_some(buf))
}

fn api_error(status: u16, body: &[u8]) -> ClientError {
    let v: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    ClientError::Api {
        status,
        title: v["title"].as_str().unwrap_or("error").into(),
        detail: v["detail"]
            .as_str()
            .map(String::from)
            .unwrap_or_else(|| String::from_utf8_lossy(body).into_owned()),
    }
}

impl Client {
    pub fn new(socket: impl Into<PathBuf>) -> Client {
        Client {
            socket: socket.into(),
            timeout: Duration::from_secs(30),
        }
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }

    fn open(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<BufReader<UnixStream>> {
        let mut s = UnixStream::connect(&self.socket).map_err(|source| ClientError::Connect {
            path: self.socket.clone(),
            source,
        })?;
        s.set_read_timeout(Some(self.timeout))?;
        let payload = body.map(Value::to_string).unwrap_or_default();
        write!(
            s,
            "{method} {path} HTTP/1.1\r\nHost: witness\r\nAccept: application/json\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        )?;
        Ok(BufReader::new(s))
    }

    fn request(&self, method: &str, path: &str, body: Option<&Value>) -> Result<(u16, Vec<u8>)> {
        let mut r = self.open(method, path, body)?;
        let head = read_head(&mut r)?;
        let mut out = Vec::new();
        if head.chunked {
            while let Some(c) = read_chunk(&mut r)? {
                out.extend(c);
            }
        } else if let Some(n) = head.length {
            out.resize(n, 0);
            r.read_exact(&mut out)?;
        } else {
            r.read_to_end(&mut out)?;
        }
        Ok((head.status, out))
    }

    /// GET a JSON endpoint.
    pub fn get(&self, path: &str) -> Result<Value> {
        self.json("GET", path, None)
    }

    pub fn post(&self, path: &str, body: &Value) -> Result<Value> {
        self.json("POST", path, Some(body))
    }

    pub fn put(&self, path: &str, body: &Value) -> Result<Value> {
        self.json("PUT", path, Some(body))
    }

    pub fn delete(&self, path: &str) -> Result<Value> {
        self.json("DELETE", path, None)
    }

    fn json(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value> {
        let (status, bytes) = self.request(method, path, body)?;
        if !(200..300).contains(&status) {
            return Err(api_error(status, &bytes));
        }
        serde_json::from_slice(&bytes).map_err(|e| ClientError::Protocol(e.to_string()))
    }

    /// GET a binary body (the incident bundle).
    pub fn get_bytes(&self, path: &str) -> Result<Vec<u8>> {
        let (status, bytes) = self.request("GET", path, None)?;
        if !(200..300).contains(&status) {
            return Err(api_error(status, &bytes));
        }
        Ok(bytes)
    }

    /// GET a text body (raw records, exports).
    pub fn get_text(&self, path: &str) -> Result<String> {
        let (status, bytes) = self.request("GET", path, None)?;
        if !(200..300).contains(&status) {
            return Err(api_error(status, &bytes));
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Follows a chunked NDJSON stream, calling `f` per line until it returns `false`, the
    /// server ends the stream, or the connection drops. The read timeout is lifted: a quiet
    /// stream is normal (the server sends heartbeats).
    pub fn stream(&self, path: &str, mut f: impl FnMut(Value) -> bool) -> Result<()> {
        let mut r = self.open("GET", path, None)?;
        r.get_ref()
            .set_read_timeout(Some(Duration::from_secs(60)))?;
        let head = read_head(&mut r)?;
        if head.status != 200 {
            let mut b = Vec::new();
            r.read_to_end(&mut b)?;
            return Err(api_error(head.status, &b));
        }
        let mut pending = Vec::new();
        while let Some(chunk) = read_chunk(&mut r)? {
            pending.extend(chunk);
            while let Some(nl) = pending.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = pending.drain(..=nl).collect();
                if let Ok(v) = serde_json::from_slice::<Value>(&line) {
                    if !f(v) {
                        return Ok(());
                    }
                }
            }
        }
        Ok(())
    }
}
