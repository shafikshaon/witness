//! Userspace event schema (DESIGN.md §4). Serialized form is one JSON object per record:
//! the common envelope, `actor`, then `type` + `data` for the body. `seq` and `h` are
//! assigned by the store.

use std::net::IpAddr;

use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u16 = 1;

// ---- OsBytes ---------------------------------------------------------------------------

/// Bytes that are normally UTF-8 (paths, argv). Serialized as a JSON string when valid
/// UTF-8, else as `{"b64": "..."}`, so non-UTF-8 paths survive unchanged.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct OsBytes(pub Vec<u8>);

impl OsBytes {
    pub fn to_string_lossy(&self) -> String {
        String::from_utf8_lossy(&self.0).into_owned()
    }
}

impl From<&str> for OsBytes {
    fn from(s: &str) -> Self {
        OsBytes(s.as_bytes().to_vec())
    }
}

impl From<Vec<u8>> for OsBytes {
    fn from(v: Vec<u8>) -> Self {
        OsBytes(v)
    }
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.as_bytes();
    if s.len() % 4 != 0 {
        return None;
    }
    let val = |c: u8| B64.iter().position(|&b| b == c).map(|p| p as u32);
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for (i, q) in s.chunks(4).enumerate() {
        let last = (i + 1) * 4 == s.len();
        let pad = q.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for (j, &c) in q.iter().enumerate() {
            n = n << 6 | if j >= 4 - pad { 0 } else { val(c)? };
        }
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
}

impl Serialize for OsBytes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match std::str::from_utf8(&self.0) {
            Ok(text) => s.serialize_str(text),
            Err(_) => {
                let mut m = s.serialize_map(Some(1))?;
                m.serialize_entry("b64", &b64_encode(&self.0))?;
                m.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for OsBytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = OsBytes;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a string or {\"b64\": \"...\"}")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<OsBytes, E> {
                Ok(OsBytes(v.as_bytes().to_vec()))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<OsBytes, A::Error> {
                match m.next_entry::<String, String>()? {
                    Some((k, v)) if k == "b64" => b64_decode(&v)
                        .map(OsBytes)
                        .ok_or_else(|| de::Error::custom("invalid base64")),
                    _ => Err(de::Error::custom("expected {\"b64\": ...}")),
                }
            }
        }
        d.deserialize_any(V)
    }
}

// ---- Envelope --------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Ebpf,
    Fanotify,
    Journald,
    Logind,
    Systemd,
    Uevent,
    Audit,
    Utmp,
    Daemon,
    RuleEngine,
    Baseline,
}

/// Importance class used by the disk-full policy (DESIGN.md §5.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    P0 = 0,
    P1 = 1,
    P2 = 2,
    P3 = 3,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    /// `<boot id prefix>-<pid>-<start_boot_ns>`; unique across pid reuse.
    pub puid: String,
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Login uid; `None` when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ses: Option<u32>,
    pub cgroup_id: u64,
    pub comm: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe: Option<OsBytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmdline: Option<Vec<OsBytes>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tty: Option<String>,
}

/// Resolution of the process start time in `/proc/<pid>/stat` (`USER_HZ` = 100, fixed by
/// the kernel ABI), in nanoseconds.
const START_TICK_NS: u64 = 10_000_000;

/// Process identity: `<boot id prefix>-<pid>-<start time in 10 ms ticks since boot>`.
///
/// The start time is quantized to the 10 ms that `/proc` exposes, so a process found by the
/// baseline scan (which can only read ticks) and the same process seen later by the eBPF
/// programs (which read exact nanoseconds) get the **same** identity. A pid is reused only
/// after the counter wraps, which cannot happen twice within 10 ms.
pub fn puid(boot_id: &str, pid: u32, start_boot_ns: u64) -> String {
    let short: String = boot_id.chars().filter(|c| *c != '-').take(8).collect();
    format!("{short}-{pid}-{}", start_boot_ns / START_TICK_NS)
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// One stored record, minus the store-assigned `seq`/`h` (kept when reading).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub v: u16,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub seq: u64,
    pub boot_id: String,
    pub boot_ns: u64,
    pub wall_ns: u64,
    #[serde(default, skip_serializing_if = "is_false")]
    pub wall_uncertain: bool,
    pub src: Source,
    pub prio: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<Actor>,
    #[serde(flatten)]
    pub body: Body,
    #[serde(default, skip_serializing)]
    pub h: Option<String>,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

impl Event {
    /// The record as the field map the store's `append` expects (no `seq`/`h`).
    pub fn to_fields(
        &self,
    ) -> Result<serde_json::Map<String, serde_json::Value>, serde_json::Error> {
        let mut e = self.clone();
        e.seq = 0;
        match serde_json::to_value(&e)? {
            serde_json::Value::Object(m) => Ok(m),
            _ => Err(serde::ser::Error::custom(
                "event did not serialize to an object",
            )),
        }
    }
}

// ---- Shared small types ----------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookResult {
    Allowed,
    Denied,
    /// The operation was attempted; its outcome was not observed (kprobe-sourced events).
    Attempted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FdKind {
    Tty,
    Pipe,
    Socket,
    File,
    Null,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Proto {
    Tcp,
    Udp,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Creds {
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
    pub suid: u32,
    pub sgid: u32,
    pub fsuid: u32,
    pub cap_effective: u64,
    pub cap_permitted: u64,
}

// ---- Bodies ----------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProcExec {
    pub filename: OsBytes,
    pub exe: OsBytes,
    pub argv: Vec<OsBytes>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub argv_truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<OsBytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<Vec<OsBytes>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdio: Option<[FdKind; 3]>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub interactive: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcFork {
    pub child_pid: u32,
    pub child_puid: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_thread: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcExit {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<u8>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub core_dumped: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_ns: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredChange {
    pub old: Creds,
    pub new: Creds,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ShellCommand {
    pub shell: OsBytes,
    pub command: Vec<OsBytes>,
    pub tty: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FileOp {
    pub path: OsBytes,
    pub path_resolved: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub path_truncated: bool,
    pub dev: u64,
    pub ino: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flags: Option<u32>,
    pub result: HookResult,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FileRename {
    pub old: OsBytes,
    pub new: OsBytes,
    pub dev: u64,
    pub ino: u64,
    pub result: HookResult,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttrOp {
    Chmod,
    Chown,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FileAttr {
    pub op: AttrOp,
    pub path: OsBytes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_mode: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_mode: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_uid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_gid: Option<u32>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub suid_set: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub sgid_set: bool,
    pub result: HookResult,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkKind {
    Hard,
    Symbolic,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FileLink {
    pub kind: LinkKind,
    pub path: OsBytes,
    pub target: OsBytes,
    pub result: HookResult,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileHash {
    pub path: OsBytes,
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub mtime_ns: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_sha256: Option<String>,
    /// Why no hash was taken (too large, vanished, unreadable, rate-limited).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileActivitySummary {
    pub dir: OsBytes,
    pub opens_for_write: u64,
    pub creates: u64,
    pub deletes: u64,
    pub interval_ns: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnOutcome {
    Established,
    Failed,
    Accepted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetConn {
    pub proto: Proto,
    pub laddr: IpAddr,
    pub lport: u16,
    pub raddr: IpAddr,
    pub rport: u16,
    pub outcome: ConnOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub errno: Option<i32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetClose {
    pub conn: NetConn,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_sent: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_recv: Option<u64>,
    pub duration_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetListen {
    pub proto: Proto,
    pub addr: IpAddr,
    pub port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdpFlow {
    pub laddr: IpAddr,
    pub lport: u16,
    pub raddr: IpAddr,
    pub rport: u16,
    pub packets_tx: u64,
    pub bytes_tx: u64,
    pub packets_rx: u64,
    pub bytes_rx: u64,
    pub interval_ns: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsDir {
    Query,
    Response,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsAnswer {
    pub name: String,
    pub rtype: String,
    pub ttl: u32,
    pub data: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsEvent {
    pub direction: DnsDir,
    pub server: IpAddr,
    pub server_port: u16,
    pub id: u16,
    pub qname: String,
    pub qtype: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rcode: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub answers: Vec<DnsAnswer>,
    pub transport: Proto,
    #[serde(default, skip_serializing_if = "is_false")]
    pub truncated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Login {
    pub user: String,
    pub service: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_addr: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tty: Option<String>,
    pub session_id: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Logout {
    pub user: String,
    pub session_id: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthFail {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    pub service: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_addr: Option<IpAddr>,
    /// The log line the fields were parsed from, kept verbatim.
    pub raw: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sudo {
    pub user: String,
    pub target_user: String,
    pub command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tty: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    pub allowed: bool,
    pub raw: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceAction {
    Add,
    Remove,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsbDevice {
    pub action: DeviceAction,
    pub devpath: String,
    pub vendor_id: String,
    pub product_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockDevice {
    pub action: DeviceAction,
    pub name: String,
    pub devpath: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub removable: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Module {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<OsBytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub taints: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceAction {
    Start,
    Stop,
    Restart,
    Reload,
    Enable,
    Disable,
    Mask,
    Unmask,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceChange {
    pub unit: String,
    pub action: ServiceAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Created,
    Modified,
    Deleted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerChange {
    /// `cron`, `systemd_timer`, `at`.
    pub scheduler: String,
    pub change: ChangeKind,
    pub path: OsBytes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageChange {
    pub manager: String,
    /// `install`, `remove`, `upgrade`.
    pub action: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_version: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountChange {
    /// `user` or `group`.
    pub kind: String,
    pub change: ChangeKind,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home: Option<String>,
    /// The password hash itself is never stored, only that it changed.
    #[serde(default, skip_serializing_if = "is_false")]
    pub password_changed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_field_sha256: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyChange {
    pub user: String,
    pub path: OsBytes,
    pub change: ChangeKind,
    pub key_type: String,
    pub fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options_sha256: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClockKind {
    Step,
    Slew,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClockChange {
    pub kind: ClockKind,
    pub delta_ns: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub syscall: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Boot {
    pub kernel: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmdline: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Shutdown {
    /// `poweroff`, `reboot`, `halt`, or `unknown`.
    pub kind: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonStart {
    pub version: String,
    pub pid: u32,
    pub kernel: String,
    pub btf: bool,
    pub config_sha256: String,
    pub rules_sha256: String,
    pub bpf_object_sha256: String,
    pub prev_shutdown: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonStop {
    pub reason: String,
    pub clean: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_pid: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureGap {
    /// `restart_same_boot`, `new_boot`, `overflow`, `source_down`, `disk_full`.
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_boot_ns: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_wall_ns: Option<u64>,
    pub to_boot_ns: u64,
    pub to_wall_ns: u64,
    pub prev_shutdown: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureDrop {
    pub reason: String,
    pub from_ns: u64,
    pub to_ns: u64,
    /// Per priority class `[p0, p1, p2, p3]`.
    pub dropped: [u64; 4],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceHealth {
    pub source: String,
    /// `active`, `degraded`, `unavailable`, `disabled`.
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A torn tail removed when the store was reopened; the bytes are kept in `quarantined_to`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recovery {
    pub segment: String,
    pub bytes: u64,
    pub sha256: String,
    pub quarantined_to: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigChange {
    pub old_sha256: String,
    pub new_sha256: String,
    pub changes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleSetChange {
    pub set_sha256: String,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub modified: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Alert {
    pub alert_id: String,
    pub rule_id: String,
    pub rule_sha256: String,
    pub title: String,
    pub severity: Severity,
    pub trigger_seqs: Vec<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<u32>,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub detail: serde_json::Value,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriageStatus {
    New,
    Acknowledged,
    FalsePositive,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriageAction {
    pub alert_seq: u64,
    pub status: TriageStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub actor_uid: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BaselineItem {
    /// `process`, `listen_socket`, `session`, `module`, `mount`, `device`.
    pub item: String,
    pub detail: serde_json::Value,
    #[serde(default, skip_serializing_if = "is_false")]
    pub discovered_in_gap: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClockSync {
    /// `CLOCK_REALTIME - CLOCK_BOOTTIME` in ns.
    pub offset_ns: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiAccess {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub tier: String,
    pub endpoint: String,
}

/// Declares the body enum once; `KnownBody` mirrors it for deserialization so that an
/// unrecognized `type` can fall back to [`Body::Other`] instead of failing the reader.
macro_rules! bodies {
    ($($v:ident($t:ty)),+ $(,)?) => {
        #[derive(Clone, Debug, PartialEq, Serialize)]
        #[serde(tag = "type", content = "data", rename_all = "snake_case")]
        pub enum Body {
            $($v($t),)+
            /// Store-level records (`segment_open`, `seal`, `anchor`, `archive`, ...) and
            /// record types newer than this build. Their payload is not interpreted here.
            Other,
        }

        #[derive(Deserialize)]
        #[serde(tag = "type", content = "data", rename_all = "snake_case")]
        enum KnownBody {
            $($v($t),)+
        }

        impl From<KnownBody> for Body {
            fn from(k: KnownBody) -> Self {
                match k {
                    $(KnownBody::$v(x) => Body::$v(x),)+
                }
            }
        }
    };
}

bodies! {
    ProcExec(ProcExec),
    ProcFork(ProcFork),
    ProcExit(ProcExit),
    CredChange(CredChange),
    ShellCommand(ShellCommand),
    FileCreate(FileOp),
    FileOpenWrite(FileOp),
    FileOpenRead(FileOp),
    FileCloseWrite(FileOp),
    FileDelete(FileOp),
    FileTruncate(FileOp),
    FileRename(FileRename),
    FileAttr(FileAttr),
    FileLink(FileLink),
    FileHash(FileHash),
    FileActivitySummary(FileActivitySummary),
    NetConnect(NetConn),
    NetAccept(NetConn),
    NetClose(NetClose),
    NetListen(NetListen),
    NetListenClose(NetListen),
    UdpFlow(UdpFlow),
    Dns(DnsEvent),
    Login(Login),
    Logout(Logout),
    AuthFail(AuthFail),
    Sudo(Sudo),
    Su(Sudo),
    UsbDevice(UsbDevice),
    BlockDevice(BlockDevice),
    ModuleLoad(Module),
    ModuleUnload(Module),
    ServiceChange(ServiceChange),
    SchedulerChange(SchedulerChange),
    PackageChange(PackageChange),
    AccountChange(AccountChange),
    AuthorizedKeyChange(KeyChange),
    ClockChange(ClockChange),
    SystemBoot(Boot),
    SystemShutdown(Shutdown),
    DaemonStart(DaemonStart),
    DaemonStop(DaemonStop),
    CaptureGap(CaptureGap),
    CaptureDrop(CaptureDrop),
    SourceHealth(SourceHealth),
    ConfigChange(ConfigChange),
    Recovery(Recovery),
    RuleSetChange(RuleSetChange),
    Alert(Alert),
    TriageAction(TriageAction),
    Baseline(BaselineItem),
    ClockSync(ClockSync),
    ApiAccess(ApiAccess),
}

impl<'de> Deserialize<'de> for Body {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = serde_json::Value::deserialize(d)?;
        match serde_json::from_value::<KnownBody>(v) {
            Ok(k) => Ok(k.into()),
            Err(e) if e.to_string().starts_with("unknown variant") => Ok(Body::Other),
            Err(e) => Err(de::Error::custom(e)),
        }
    }
}

impl Body {
    /// Importance class for the disk-full policy. Everything not listed is P0.
    pub fn priority(&self) -> Priority {
        use Body::*;
        match self {
            FileActivitySummary(_) | UdpFlow(_) | FileOpenRead(_) => Priority::P3,
            FileHash(_) | FileCloseWrite(_) | NetClose(_) | NetListenClose(_) | Dns(_) => {
                Priority::P2
            }
            FileCreate(_) | FileOpenWrite(_) | FileDelete(_) | FileTruncate(_) | FileRename(_)
            | FileAttr(_) | FileLink(_) | NetConnect(_) | NetAccept(_) | NetListen(_)
            | ProcFork(_) | ClockSync(_) => Priority::P1,
            _ => Priority::P0,
        }
    }
}
