//! The daemon API: JSON over HTTP/1.1 on a Unix socket (DESIGN.md §9).
//!
//! Deviation from the design: a small hand-written HTTP/1.1 server (std threads, no async
//! runtime, no hyper/axum). The API is local, small and read-mostly; this keeps the daemon's
//! dependency tree and attack surface small. Every connection is `Connection: close`.
//!
//! The OS enforces access (socket mode `0660 root:witness`). `SO_PEERCRED` decides the tier:
//! tier 1 reads and triages, tier 2 (root or `admin_group`) also changes rules.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use witness_common::schema::{ApiAccess, TriageStatus};
use witness_store::chain;
use witness_store::index::{Filter, Index};
use witness_store::store::read_head;
use witness_store::verify::{verify_dirs, Options};

const MAX_HEADER: usize = 16 * 1024;
const MAX_BODY: usize = 256 * 1024;
const MAX_CONNECTIONS: usize = 32;
const EXPORT_MAX: usize = 100_000;

/// What the API asks the main loop (the single writer) to record.
pub enum ApiCmd {
    Triage {
        alert_seq: u64,
        status: TriageStatus,
        note: Option<String>,
        uid: u32,
    },
    Access(ApiAccess),
}

#[derive(Clone)]
pub struct ApiConfig {
    pub socket: PathBuf,
    pub group: String,
    pub admin_group: String,
    pub data_dir: PathBuf,
    pub rules_dir: PathBuf,
}

pub struct Api {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    rx: Receiver<ApiCmd>,
    socket: PathBuf,
}

struct Shared {
    cfg: ApiConfig,
    started: Instant,
    tx: Mutex<Sender<ApiCmd>>,
    stop: Arc<AtomicBool>,
    verify: Arc<Mutex<Value>>,
    seen: Mutex<HashMap<(u32, u32), Instant>>,
    live: AtomicUsize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
enum Tier {
    One,
    Two,
}

struct Peer {
    uid: u32,
    gid: u32,
    pid: u32,
    tier: Tier,
}

/// Produces a chunked body by calling the sink per piece; the sink returns `false` once the
/// client has gone away.
type StreamFn = Box<dyn FnOnce(&mut dyn FnMut(&[u8]) -> bool) + Send>;

enum Reply {
    Json(u16, Value),
    Text(u16, &'static str, String),
    /// A chunked NDJSON body produced by the closure, which writes lines until it returns.
    Stream(StreamFn),
}

type Res = Result<Reply, (u16, &'static str, String)>;

fn bad(detail: impl Into<String>) -> (u16, &'static str, String) {
    (400, "bad request", detail.into())
}

fn ok(v: Value) -> Res {
    Ok(Reply::Json(200, v))
}

// ---- lifecycle ------------------------------------------------------------------------

fn gid_of(group: &str) -> Option<u32> {
    let t = std::fs::read_to_string("/etc/group").ok()?;
    crate::accounts::parse_group(&t).get(group).map(|e| e.id)
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn members_of(group: &str) -> Vec<String> {
    let Ok(t) = std::fs::read_to_string("/etc/group") else {
        return Vec::new();
    };
    t.lines()
        .find(|l| l.split(':').next() == Some(group))
        .and_then(|l| l.split(':').nth(3))
        .map(|m| {
            m.split(',')
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

impl Api {
    pub fn start(cfg: ApiConfig) -> std::io::Result<Api> {
        if let Some(dir) = cfg.socket.parent() {
            std::fs::create_dir_all(dir)?;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o750));
        }
        let _ = std::fs::remove_file(&cfg.socket);
        let listener = UnixListener::bind(&cfg.socket)?;
        listener.set_nonblocking(true)?;
        // Group-accessible if the group exists; otherwise root only, never world-accessible.
        let gid = gid_of(&cfg.group);
        let mode = if gid.is_some() { 0o660 } else { 0o600 };
        std::fs::set_permissions(&cfg.socket, std::fs::Permissions::from_mode(mode))?;
        if let Some(g) = gid {
            let _ = rustix::fs::chown(&cfg.socket, None, Some(rustix::fs::Gid::from_raw(g)));
            if let Some(dir) = cfg.socket.parent() {
                let _ = rustix::fs::chown(dir, None, Some(rustix::fs::Gid::from_raw(g)));
            }
        } else {
            tracing::warn!(group = %cfg.group, "api group not found; the socket is root-only");
        }
        let (tx, rx) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let shared = Arc::new(Shared {
            started: Instant::now(),
            tx: Mutex::new(tx),
            stop: stop.clone(),
            verify: Arc::new(Mutex::new(json!({"state": "never_run"}))),
            seen: Mutex::new(HashMap::new()),
            live: AtomicUsize::new(0),
            cfg: cfg.clone(),
        });
        let thread = std::thread::spawn(move || accept_loop(listener, shared));
        Ok(Api {
            stop,
            thread: Some(thread),
            rx,
            socket: cfg.socket,
        })
    }

    /// Requests from clients that the single writer must record.
    pub fn drain(&self) -> Vec<ApiCmd> {
        self.rx.try_iter().collect()
    }

    pub fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        let _ = std::fs::remove_file(&self.socket);
    }
}

fn accept_loop(listener: UnixListener, shared: Arc<Shared>) {
    while !shared.stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((conn, _)) => {
                if shared.live.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                    shared.live.fetch_sub(1, Ordering::SeqCst);
                    let _ = respond_error(&conn, 503, "busy", "too many connections");
                    continue;
                }
                let sh = shared.clone();
                std::thread::spawn(move || {
                    let _ = serve(conn, &sh);
                    sh.live.fetch_sub(1, Ordering::SeqCst);
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
    }
}

// ---- HTTP -----------------------------------------------------------------------------

struct Request {
    method: String,
    path: String,
    query: HashMap<String, Vec<String>>,
    body: Vec<u8>,
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                let h = std::str::from_utf8(&b[i + 1..i + 3])
                    .ok()
                    .and_then(|h| u8::from_str_radix(h, 16).ok());
                match h {
                    Some(v) => {
                        out.push(v);
                        i += 2;
                    }
                    None => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn read_request(r: &mut BufReader<&UnixStream>) -> Result<Request, (u16, &'static str, String)> {
    let mut line = String::new();
    let mut total = 0;
    r.read_line(&mut line).map_err(|e| bad(e.to_string()))?;
    total += line.len();
    let mut parts = line.split_whitespace();
    let (method, target) = match (parts.next(), parts.next()) {
        (Some(m), Some(t)) => (m.to_string(), t.to_string()),
        _ => return Err(bad("malformed request line")),
    };
    let mut length = 0usize;
    loop {
        let mut h = String::new();
        let n = r.read_line(&mut h).map_err(|e| bad(e.to_string()))?;
        total += n;
        if n == 0 || total > MAX_HEADER {
            return Err(bad("headers too long or truncated"));
        }
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                length = v.trim().parse().map_err(|_| bad("bad content-length"))?;
            }
        }
    }
    if length > MAX_BODY {
        return Err((
            413,
            "payload too large",
            format!("body over {MAX_BODY} bytes"),
        ));
    }
    let mut body = vec![0u8; length];
    r.read_exact(&mut body).map_err(|e| bad(e.to_string()))?;
    let (path, qs) = target.split_once('?').unwrap_or((&target, ""));
    let mut query: HashMap<String, Vec<String>> = HashMap::new();
    for kv in qs.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        query.entry(pct_decode(k)).or_default().push(pct_decode(v));
    }
    Ok(Request {
        method,
        path: pct_decode(path),
        query,
        body,
    })
}

fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

fn respond(mut s: &UnixStream, code: u16, ctype: &str, body: &[u8]) -> std::io::Result<()> {
    write!(
        s,
        "HTTP/1.1 {code} {}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        status_text(code),
        body.len()
    )?;
    s.write_all(body)
}

fn respond_error(s: &UnixStream, code: u16, title: &str, detail: &str) -> std::io::Result<()> {
    let body = json!({"type": "about:blank", "title": title, "detail": detail});
    respond(
        s,
        code,
        "application/problem+json",
        body.to_string().as_bytes(),
    )
}

#[cfg(target_os = "linux")]
fn peer_of(s: &UnixStream, cfg: &ApiConfig) -> Option<Peer> {
    let c = rustix::net::sockopt::socket_peercred(s).ok()?;
    let (uid, gid, pid) = (
        c.uid.as_raw(),
        c.gid.as_raw(),
        c.pid.as_raw_nonzero().get() as u32,
    );
    let admin_gid = gid_of(&cfg.admin_group);
    let name = std::fs::read_to_string("/etc/passwd")
        .ok()
        .and_then(|t| {
            t.lines().find_map(|l| {
                let f: Vec<&str> = l.split(':').collect();
                (f.get(2).and_then(|u| u.parse::<u32>().ok()) == Some(uid))
                    .then(|| f[0].to_string())
            })
        })
        .unwrap_or_default();
    let admin = uid == 0
        || admin_gid == Some(gid)
        || members_of(&cfg.admin_group).iter().any(|m| *m == name);
    Some(Peer {
        uid,
        gid,
        pid,
        tier: if admin { Tier::Two } else { Tier::One },
    })
}

#[cfg(not(target_os = "linux"))]
fn peer_of(_s: &UnixStream, _cfg: &ApiConfig) -> Option<Peer> {
    Some(Peer {
        uid: 0,
        gid: 0,
        pid: 0,
        tier: Tier::Two,
    })
}

fn serve(conn: UnixStream, sh: &Shared) -> std::io::Result<()> {
    conn.set_read_timeout(Some(Duration::from_secs(10)))?;
    let Some(peer) = peer_of(&conn, &sh.cfg) else {
        return respond_error(&conn, 403, "forbidden", "cannot identify the caller");
    };
    let req = match read_request(&mut BufReader::new(&conn)) {
        Ok(r) => r,
        Err((c, t, d)) => return respond_error(&conn, c, t, &d),
    };
    note_access(sh, &peer, &req);
    match route(sh, &peer, &req) {
        Ok(Reply::Json(code, v)) => {
            respond(&conn, code, "application/json", v.to_string().as_bytes())
        }
        Ok(Reply::Text(code, ctype, t)) => respond(&conn, code, ctype, t.as_bytes()),
        Ok(Reply::Stream(f)) => {
            conn.set_write_timeout(Some(Duration::from_secs(10)))?;
            let mut w = &conn;
            write!(
                w,
                "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"
            )?;
            f(&mut |bytes: &[u8]| {
                write!(w, "{:x}\r\n", bytes.len()).is_ok()
                    && w.write_all(bytes).is_ok()
                    && w.write_all(b"\r\n").is_ok()
            });
            let _ = w.write_all(b"0\r\n\r\n");
            Ok(())
        }
        Err((c, t, d)) => respond_error(&conn, c, t, &d),
    }
}

/// Who looked at what is itself evidence: one `api_access` record per caller per minute.
fn note_access(sh: &Shared, p: &Peer, req: &Request) {
    if req.path == "/v1/health" {
        return;
    }
    let key = (p.uid, p.pid);
    let now = Instant::now();
    let Ok(mut seen) = sh.seen.lock() else { return };
    if seen.len() > 1000 {
        seen.retain(|_, t| now.duration_since(*t) < Duration::from_secs(60));
    }
    if seen
        .get(&key)
        .is_some_and(|t| now.duration_since(*t) < Duration::from_secs(60))
    {
        return;
    }
    seen.insert(key, now);
    if let Ok(tx) = sh.tx.lock() {
        let _ = tx.send(ApiCmd::Access(ApiAccess {
            uid: p.uid,
            gid: p.gid,
            pid: p.pid,
            tier: if p.tier == Tier::Two { "admin" } else { "read" }.into(),
            endpoint: format!("{} {}", req.method, req.path),
        }));
    }
}

// ---- routing --------------------------------------------------------------------------

fn param<'a>(r: &'a Request, k: &str) -> Option<&'a str> {
    r.query.get(k).and_then(|v| v.first()).map(String::as_str)
}

fn num<T: std::str::FromStr>(
    r: &Request,
    k: &str,
) -> Result<Option<T>, (u16, &'static str, String)> {
    match param(r, k) {
        None | Some("") => Ok(None),
        Some(v) => v
            .parse()
            .map(Some)
            .map_err(|_| bad(format!("`{k}` must be a number"))),
    }
}

fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

fn filter_of(r: &Request) -> Result<Filter, (u16, &'static str, String)> {
    let mut f = Filter {
        kinds: r.query.get("kind").cloned().unwrap_or_default(),
        wall_from: num(r, "from")?,
        wall_to: num(r, "to")?,
        pid: num(r, "pid")?,
        uid: num(r, "uid")?,
        puid: param(r, "puid").map(String::from),
        ses: num(r, "ses")?,
        text: param(r, "q").filter(|s| !s.is_empty()).map(String::from),
        before_seq: num(r, "cursor")?,
        after_seq: num(r, "since_seq")?,
        limit: num::<usize>(r, "limit")?.unwrap_or(100).clamp(1, 1000),
    };
    if let Some(secs) = num::<u64>(r, "last_secs")? {
        f.wall_from = Some(now_ns().saturating_sub(secs.saturating_mul(1_000_000_000)));
    }
    Ok(f)
}

fn open_index(sh: &Shared) -> Result<Index, (u16, &'static str, String)> {
    Index::open(&sh.cfg.data_dir.join("index.db"))
        .map_err(|e| (503, "index unavailable", e.to_string()))
}

fn segs(sh: &Shared) -> PathBuf {
    sh.cfg.data_dir.join("segments")
}

/// The stored record for `seq`, decoded, with its chain hash as `h` (already in the record).
fn record(ix: &Index, sh: &Shared, seq: u64) -> Result<Value, (u16, &'static str, String)> {
    let raw = ix
        .raw(&segs(sh), seq)
        .map_err(|e| (404, "not found", format!("event {seq}: {e}")))?;
    let (body, _) = chain::decode_line(&raw).map_err(|e| (500, "corrupt record", e.to_string()))?;
    let mut v: Value =
        serde_json::from_slice(&body).map_err(|e| (500, "corrupt record", e.to_string()))?;
    if let Some(h) = raw.rsplit(|&b| b == b'"').nth(1) {
        v["h"] = json!(String::from_utf8_lossy(h));
    }
    Ok(v)
}

fn route(sh: &Shared, peer: &Peer, r: &Request) -> Res {
    let parts: Vec<&str> = r.path.trim_matches('/').split('/').collect();
    let m = r.method.as_str();
    let admin_only = || {
        if peer.tier == Tier::Two {
            Ok(())
        } else {
            Err((
                403,
                "forbidden",
                "this needs the witness-admin group or root".to_string(),
            ))
        }
    };
    match (m, parts.as_slice()) {
        ("GET", ["v1", "health"]) => ok(json!({"ok": true})),
        ("GET", ["v1", "status"]) => status(sh, peer),
        ("GET", ["v1", "events"]) => events(sh, r),
        ("GET", ["v1", "events", seq]) => {
            let seq = seq.parse().map_err(|_| bad("seq must be a number"))?;
            ok(record(&open_index(sh)?, sh, seq)?)
        }
        ("GET", ["v1", "events", seq, "raw"]) => {
            let seq = seq.parse().map_err(|_| bad("seq must be a number"))?;
            let raw = open_index(sh)?
                .raw(&segs(sh), seq)
                .map_err(|e| (404, "not found", e.to_string()))?;
            Ok(Reply::Text(
                200,
                "application/x-ndjson",
                String::from_utf8_lossy(&raw).into_owned(),
            ))
        }
        ("GET", ["v1", "stream"]) => stream(sh, r),
        ("GET", ["v1", "timeline"]) => timeline(sh, r),
        ("GET", ["v1", "dashboard"]) => dashboard(sh),
        ("GET", ["v1", "alerts"]) => alerts(sh, r),
        ("POST", ["v1", "alerts", seq, "triage"]) => triage(sh, peer, seq, r),
        ("GET", ["v1", "sessions"]) => {
            let mut f = filter_of(r)?;
            f.kinds = vec!["login".into(), "logout".into()];
            list(sh, &f)
        }
        ("GET", ["v1", "sessions", ses]) => {
            let mut f = filter_of(r)?;
            f.ses = Some(ses.parse().map_err(|_| bad("ses must be a number"))?);
            list(sh, &f)
        }
        ("GET", ["v1", "processes", puid]) => {
            let mut f = filter_of(r)?;
            f.puid = Some((*puid).into());
            list(sh, &f)
        }
        ("GET", ["v1", "integrity"]) => {
            ok(sh.verify.lock().map(|v| v.clone()).unwrap_or(Value::Null))
        }
        ("POST", ["v1", "integrity", "verify"]) => start_verify(sh),
        ("GET", ["v1", "export"]) => export(sh, r),
        ("GET", ["v1", "rules"]) => rules_list(sh),
        ("POST", ["v1", "rules", "validate"]) => rules_validate(r),
        ("PUT", ["v1", "rules", id]) => {
            admin_only()?;
            rules_put(sh, id, r)
        }
        ("DELETE", ["v1", "rules", id]) => {
            admin_only()?;
            rules_delete(sh, id)
        }
        ("POST", ["v1", "rules", id, act @ ("enable" | "disable")]) => {
            admin_only()?;
            rules_toggle(sh, id, *act == "enable")
        }
        (_, ["v1", ..]) => Err((
            404,
            "not found",
            format!("no such endpoint: {m} {}", r.path),
        )),
        _ => Err((404, "not found", "the API lives under /v1".into())),
    }
}

fn status(sh: &Shared, peer: &Peer) -> Res {
    let head = read_head(&segs(sh)).map_err(|e| (500, "store unreadable", e.to_string()))?;
    let indexed = Index::open(&sh.cfg.data_dir.join("index.db"))
        .ok()
        .and_then(|i| i.position().ok())
        .map(|p| p.0);
    ok(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_secs": sh.started.elapsed().as_secs(),
        "head_seq": head.0,
        "head_hash": chain::to_hex(&head.1),
        "indexed_seq": indexed,
        "tier": if peer.tier == Tier::Two { "admin" } else { "read" },
        "wall_ns": now_ns(),
    }))
}

fn rows_json(sh: &Shared, ix: &Index, f: &Filter) -> Result<Value, (u16, &'static str, String)> {
    let rows = ix
        .query(f)
        .map_err(|e| (500, "query failed", e.to_string()))?;
    let next = if f.after_seq.is_some() {
        rows.last().map(|r| r.seq)
    } else {
        rows.last().map(|r| r.seq).filter(|_| rows.len() >= f.limit)
    };
    let mut events = Vec::with_capacity(rows.len());
    for r in &rows {
        events.push(record(ix, sh, r.seq)?);
    }
    Ok(json!({"events": events, "next_cursor": next}))
}

fn list(sh: &Shared, f: &Filter) -> Res {
    ok(rows_json(sh, &open_index(sh)?, f)?)
}

fn events(sh: &Shared, r: &Request) -> Res {
    list(sh, &filter_of(r)?)
}

fn stream(sh: &Shared, r: &Request) -> Res {
    let mut f = filter_of(r)?;
    let ix = open_index(sh)?;
    let head = ix.position().map(|p| p.0).unwrap_or(0);
    let mut cursor = f.after_seq.unwrap_or(head);
    f.before_seq = None;
    f.limit = 500;
    let stop = sh.stop.clone();
    let dir = segs(sh);
    Ok(Reply::Stream(Box::new(move |out| {
        let mut last_beat = Instant::now();
        while !stop.load(Ordering::SeqCst) {
            f.after_seq = Some(cursor);
            let rows = ix.query(&f).unwrap_or_default();
            for row in &rows {
                let line = ix
                    .raw(&dir, row.seq)
                    .ok()
                    .and_then(|raw| chain::decode_line(&raw).ok())
                    .map(|(b, _)| b);
                if let Some(mut b) = line {
                    b.push(b'\n');
                    if !out(&b) {
                        return;
                    }
                }
                cursor = row.seq;
            }
            if rows.is_empty() {
                if last_beat.elapsed() >= Duration::from_secs(5) {
                    let b = format!("{{\"heartbeat\":true,\"cursor\":{cursor}}}\n");
                    if !out(b.as_bytes()) {
                        return;
                    }
                    last_beat = Instant::now();
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    })))
}

fn timeline(sh: &Shared, r: &Request) -> Res {
    let to = num::<u64>(r, "to")?.unwrap_or_else(now_ns);
    let from = num::<u64>(r, "from")?.unwrap_or(to.saturating_sub(3_600_000_000_000));
    if to <= from {
        return Err(bad("`to` must be after `from`"));
    }
    if to - from > 30 * 86_400_000_000_000 {
        return Err(bad("the range may span at most 30 days"));
    }
    let buckets = num::<u32>(r, "buckets")?.unwrap_or(60).clamp(1, 500);
    let rows = open_index(sh)?
        .timeline(from, to, buckets)
        .map_err(|e| (500, "query failed", e.to_string()))?;
    let mut series: serde_json::Map<String, Value> = serde_json::Map::new();
    for (b, kind, n) in rows {
        let arr = series
            .entry(kind)
            .or_insert_with(|| json!(vec![0u64; buckets as usize]));
        if let Some(slot) = arr.get_mut(b as usize) {
            *slot = json!(n);
        }
    }
    ok(
        json!({"from": from, "to": to, "buckets": buckets, "step_ns": (to - from) / buckets as u64, "series": series}),
    )
}

fn dashboard(sh: &Shared) -> Res {
    let ix = open_index(sh)?;
    let to = now_ns();
    let window = 900u64;
    let counts = ix
        .kind_counts(to.saturating_sub(window * 1_000_000_000), to)
        .map_err(|e| (500, "query failed", e.to_string()))?;
    let total: u64 = counts.iter().map(|(_, n)| n).sum();
    let f = Filter {
        kinds: vec!["alert".into()],
        limit: 10,
        ..Filter::default()
    };
    let recent = rows_json(sh, &ix, &f)?;
    let head = read_head(&segs(sh)).map_err(|e| (500, "store unreadable", e.to_string()))?;
    let health = rows_json(
        sh,
        &ix,
        &Filter {
            kinds: vec!["source_health".into()],
            limit: 50,
            ..Filter::default()
        },
    )?;
    ok(json!({
        "window_secs": window,
        "events_per_sec": total as f64 / window as f64,
        "by_kind": counts.iter().map(|(k, n)| json!({"kind": k, "count": n})).collect::<Vec<_>>(),
        "recent_alerts": recent["events"],
        "source_health": health["events"],
        "head_seq": head.0,
        "uptime_secs": sh.started.elapsed().as_secs(),
    }))
}

fn alerts(sh: &Shared, r: &Request) -> Res {
    let ix = open_index(sh)?;
    let mut f = filter_of(r)?;
    f.kinds = vec!["alert".into()];
    let mut out = rows_json(sh, &ix, &f)?;
    // Latest triage state per alert.
    let t = rows_json(
        sh,
        &ix,
        &Filter {
            kinds: vec!["triage_action".into()],
            limit: 1000,
            ..Filter::default()
        },
    )?;
    let mut state: HashMap<u64, (u64, Value)> = HashMap::new();
    for e in t["events"].as_array().into_iter().flatten() {
        let (Some(a), Some(s)) = (e["data"]["alert_seq"].as_u64(), e["seq"].as_u64()) else {
            continue;
        };
        if state.get(&a).is_none_or(|(old, _)| s > *old) {
            state.insert(
                a,
                (
                    s,
                    json!({"status": e["data"]["status"], "note": e["data"]["note"]}),
                ),
            );
        }
    }
    if let Some(list) = out["events"].as_array_mut() {
        for e in list {
            let seq = e["seq"].as_u64().unwrap_or(0);
            e["triage"] = state
                .get(&seq)
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| json!({"status": "new"}));
        }
    }
    ok(out)
}

fn triage(sh: &Shared, peer: &Peer, seq: &str, r: &Request) -> Res {
    let alert_seq: u64 = seq.parse().map_err(|_| bad("seq must be a number"))?;
    let body: Value = serde_json::from_slice(&r.body).map_err(|e| bad(format!("bad JSON: {e}")))?;
    let status = match body["status"].as_str() {
        Some("new") => TriageStatus::New,
        Some("acknowledged") => TriageStatus::Acknowledged,
        Some("false_positive") => TriageStatus::FalsePositive,
        _ => return Err(bad("status must be new, acknowledged or false_positive")),
    };
    let ix = open_index(sh)?;
    let target = record(&ix, sh, alert_seq)?;
    if target["type"] != "alert" {
        return Err(bad(format!("event {alert_seq} is not an alert")));
    }
    let note = body["note"]
        .as_str()
        .map(|s| s.chars().take(2000).collect::<String>());
    if let Ok(tx) = sh.tx.lock() {
        let _ = tx.send(ApiCmd::Triage {
            alert_seq,
            status,
            note,
            uid: peer.uid,
        });
    }
    Ok(Reply::Json(202, json!({"accepted": true})))
}

fn start_verify(sh: &Shared) -> Res {
    {
        let mut v = sh
            .verify
            .lock()
            .map_err(|_| (500, "internal", "lock".into()))?;
        if v["state"] == "running" {
            return Ok(Reply::Json(202, v.clone()));
        }
        *v = json!({"state": "running", "started_wall_ns": now_ns()});
    }
    let dir = segs(sh);
    let slot = sh.verify.clone();
    std::thread::spawn(move || {
        let result = match verify_dirs(
            &[dir],
            &Options {
                allow_partial: true,
                ..Options::default()
            },
        ) {
            Ok(rep) => json!({
                "state": if rep.is_ok() { "ok" } else { "broken" },
                "segments": rep.segments,
                "records": rep.records,
                "head_seq": rep.head_seq,
                "head_hash": chain::to_hex(&rep.head_hash),
                "seals": rep.seals,
                "anchors_checked": rep.anchors_checked,
                "partial_start": rep.partial_start,
                "macs_checked": rep.macs_checked,
                "broken": rep.broken.map(|b| format!("{b:?}")),
                "finished_wall_ns": now_ns(),
            }),
            Err(e) => {
                json!({"state": "error", "detail": e.to_string(), "finished_wall_ns": now_ns()})
            }
        };
        if let Ok(mut v) = slot.lock() {
            *v = result;
        }
    });
    Ok(Reply::Json(202, json!({"state": "running"})))
}

fn export(sh: &Shared, r: &Request) -> Res {
    let mut f = filter_of(r)?;
    let format = param(r, "format").unwrap_or("ndjson").to_string();
    if !["ndjson", "json", "csv"].contains(&format.as_str()) {
        return Err(bad("format must be ndjson, json or csv"));
    }
    let max = num::<usize>(r, "max")?.unwrap_or(10_000).min(EXPORT_MAX);
    f.limit = 1000;
    let ix = open_index(sh)?;
    let dir = segs(sh);
    Ok(Reply::Stream(Box::new(move |out| {
        let mut sent = 0usize;
        let mut cursor = f.before_seq;
        if format == "csv" && !out(b"seq,wall_ns,type,pid,exe,summary\n") {
            return;
        }
        if format == "json" && !out(b"[") {
            return;
        }
        while sent < max {
            f.before_seq = cursor;
            let rows = ix.query(&f).unwrap_or_default();
            if rows.is_empty() {
                break;
            }
            for row in rows {
                if sent >= max {
                    break;
                }
                cursor = Some(row.seq);
                let Ok(raw) = ix.raw(&dir, row.seq) else {
                    continue;
                };
                let line = match format.as_str() {
                    "ndjson" => {
                        let mut l = raw.clone();
                        if l.last() != Some(&b'\n') {
                            l.push(b'\n');
                        }
                        l
                    }
                    "json" => {
                        let mut l = Vec::new();
                        if sent > 0 {
                            l.push(b',');
                        }
                        l.extend_from_slice(raw.trim_ascii_end());
                        l
                    }
                    _ => {
                        let v: Value = chain::decode_line(&raw)
                            .ok()
                            .and_then(|(b, _)| serde_json::from_slice(&b).ok())
                            .unwrap_or(Value::Null);
                        let cell = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
                        format!(
                            "{},{},{},{},{},{}\n",
                            v["seq"],
                            v["wall_ns"],
                            cell(v["type"].as_str().unwrap_or("")),
                            v["actor"]["pid"],
                            cell(v["actor"]["exe"].as_str().unwrap_or("")),
                            cell(&v["data"].to_string())
                        )
                        .into_bytes()
                    }
                };
                if !out(&line) {
                    return;
                }
                sent += 1;
            }
        }
        if format == "json" {
            let _ = out(b"]\n");
        }
    })))
}

// ---- rules ----------------------------------------------------------------------------

fn rules_list(sh: &Shared) -> Res {
    let loaded = witness_rules::load_dir(&sh.cfg.rules_dir).unwrap_or_default();
    let rules: Vec<Value> = loaded
        .set
        .rules
        .iter()
        .map(|r| {
            json!({
                "id": r.id, "title": r.title, "description": r.description,
                "severity": r.severity, "enabled": r.enabled, "tags": r.tags,
                "file": r.file, "sha256": r.sha256,
            })
        })
        .collect();
    // Files parked by "disable" are not loaded but should still be visible.
    let parked: Vec<String> = std::fs::read_dir(&sh.cfg.rules_dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().to_str().map(String::from))
        .filter(|n| n.ends_with(".yml.off"))
        .collect();
    ok(json!({
        "rules": rules,
        "disabled_files": parked,
        "errors": loaded.errors.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "set_sha256": loaded.set.sha256,
    }))
}

fn rules_validate(r: &Request) -> Res {
    let b: Value = serde_json::from_slice(&r.body).map_err(|e| bad(format!("bad JSON: {e}")))?;
    let text = b["yaml"]
        .as_str()
        .ok_or_else(|| bad("`yaml` is required"))?;
    let res = witness_rules::load_str([("candidate.yml", text)]);
    ok(json!({
        "ok": res.errors.is_empty(),
        "errors": res.errors.iter().map(|e| json!({"line": e.line, "col": e.col, "message": e.msg})).collect::<Vec<_>>(),
        "rule": res.set.rules.first().map(|r| json!({"id": r.id, "title": r.title})),
    }))
}

fn rule_path(sh: &Shared, id: &str, suffix: &str) -> Result<PathBuf, (u16, &'static str, String)> {
    if id.is_empty()
        || !id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        || id.starts_with('.')
    {
        return Err(bad("rule id must match [a-z0-9._-]+"));
    }
    Ok(sh.cfg.rules_dir.join(format!("{id}{suffix}")))
}

fn rules_put(sh: &Shared, id: &str, r: &Request) -> Res {
    let b: Value = serde_json::from_slice(&r.body).map_err(|e| bad(format!("bad JSON: {e}")))?;
    let text = b["yaml"]
        .as_str()
        .ok_or_else(|| bad("`yaml` is required"))?;
    let res = witness_rules::load_str([("candidate.yml", text)]);
    if let Some(e) = res.errors.first() {
        return Err(bad(format!("the rule does not compile: {e}")));
    }
    if res.set.rules.first().map(|r| r.id.as_str()) != Some(id) {
        return Err(bad("the rule's `id` must equal the id in the URL"));
    }
    let path = rule_path(sh, id, ".yml")?;
    // Write then rename, so a reload never sees half a file.
    let tmp = rule_path(sh, id, ".yml.tmp")?;
    std::fs::write(&tmp, text).map_err(|e| (500, "write failed", e.to_string()))?;
    std::fs::rename(&tmp, &path).map_err(|e| (500, "write failed", e.to_string()))?;
    let _ = std::fs::remove_file(rule_path(sh, id, ".yml.off")?);
    ok(json!({"saved": path.file_name().and_then(|n| n.to_str())}))
}

fn rules_delete(sh: &Shared, id: &str) -> Res {
    for s in [".yml", ".yml.off"] {
        let _ = std::fs::remove_file(rule_path(sh, id, s)?);
    }
    ok(json!({"deleted": id}))
}

fn rules_toggle(sh: &Shared, id: &str, enable: bool) -> Res {
    let (on, off) = (rule_path(sh, id, ".yml")?, rule_path(sh, id, ".yml.off")?);
    let (from, to) = if enable { (off, on) } else { (on, off) };
    std::fs::rename(&from, &to)
        .map_err(|e| (404, "not found", format!("{}: {e}", from.display())))?;
    ok(json!({"id": id, "enabled": enable}))
}
