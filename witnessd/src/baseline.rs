//! Baseline snapshot (DESIGN.md §6.6): what already exists when the daemon starts, so
//! activity of pre-existing processes can be attributed. Reads `/proc`, `/sys` and `/run`
//! through configurable roots so it can be tested against fixture trees.
//!
//! Every record is a [`Body::Baseline`] event (`src: baseline`); process records also carry
//! a full [`Actor`], so the process tree can be rebuilt from them.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use witness_common::schema::{
    puid, Actor, BaselineItem, Body, Event, OsBytes, Source, SCHEMA_VERSION,
};

/// `/proc/<pid>/stat` reports start times in `USER_HZ` ticks (fixed at 100 by the kernel ABI).
const TICK_NS: u64 = 10_000_000;

#[derive(Debug, Clone)]
pub struct Roots {
    pub proc_: PathBuf,
    pub sys: PathBuf,
    pub run: PathBuf,
}

impl Default for Roots {
    fn default() -> Self {
        Roots {
            proc_: "/proc".into(),
            sys: "/sys".into(),
            run: "/run".into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Context {
    pub boot_id: String,
    pub boot_ns: u64,
    pub wall_ns: u64,
    /// Start of the capture gap on this boot (if the daemon restarted): processes that began
    /// after it were started while nothing was watching.
    pub gap_from_boot_ns: Option<u64>,
}

/// Counts reported in the closing `summary` record.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Counts {
    pub processes: usize,
    pub listen_sockets: usize,
    pub sessions: usize,
    pub modules: usize,
    pub mounts: usize,
    pub block_devices: usize,
    pub usb_devices: usize,
}

fn envelope(ctx: &Context, actor: Option<Actor>, item: &str, detail: Value, in_gap: bool) -> Event {
    let body = Body::Baseline(BaselineItem {
        item: item.into(),
        detail,
        discovered_in_gap: in_gap,
    });
    Event {
        v: SCHEMA_VERSION,
        seq: 0,
        boot_id: ctx.boot_id.clone(),
        boot_ns: ctx.boot_ns,
        wall_ns: ctx.wall_ns,
        wall_uncertain: false,
        src: Source::Baseline,
        prio: body.priority() as u8,
        actor,
        body,
        h: None,
    }
}

/// Everything present now, ending with a `summary` record.
pub fn collect(roots: &Roots, ctx: &Context) -> Vec<Event> {
    let mut out = Vec::new();
    let mut c = Counts::default();

    let procs = processes(roots, ctx);
    c.processes = procs.len();
    out.extend(procs);

    let socks = listen_sockets(roots, ctx);
    c.listen_sockets = socks.len();
    out.extend(socks);

    for (n, items) in [
        (&mut c.sessions, sessions(roots, ctx)),
        (&mut c.modules, modules(roots, ctx)),
        (&mut c.mounts, mounts(roots, ctx)),
        (&mut c.block_devices, block_devices(roots, ctx)),
        (&mut c.usb_devices, usb_devices(roots, ctx)),
    ] {
        *n = items.len();
        out.extend(items);
    }

    out.push(envelope(
        ctx,
        None,
        "summary",
        json!({
            "processes": c.processes, "listen_sockets": c.listen_sockets,
            "sessions": c.sessions, "modules": c.modules, "mounts": c.mounts,
            "block_devices": c.block_devices, "usb_devices": c.usb_devices,
        }),
        false,
    ));
    out
}

// ---- processes -------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Stat {
    pub comm: String,
    pub ppid: u32,
    pub start_ticks: u64,
}

/// Parses `/proc/<pid>/stat`. The command name is parenthesised and may itself contain
/// spaces and parentheses, so fields are located relative to the *last* `)`.
pub(crate) fn parse_stat(text: &str) -> Option<Stat> {
    let open = text.find('(')?;
    let close = text.rfind(')')?;
    let comm = text.get(open + 1..close)?.to_string();
    let rest: Vec<&str> = text.get(close + 1..)?.split_whitespace().collect();
    // rest[0] is field 3 (state); ppid is field 4, starttime is field 22.
    Some(Stat {
        comm,
        ppid: rest.get(1)?.parse().ok()?,
        start_ticks: rest.get(19)?.parse().ok()?,
    })
}

fn status_ids(status: &str, key: &str) -> Option<(u32, u32)> {
    let line = status.lines().find(|l| l.starts_with(key))?;
    let mut f = line.split_whitespace().skip(1);
    Some((f.next()?.parse().ok()?, f.next()?.parse().ok()?))
}

fn cgroup_id(roots: &Roots, pid_dir: &Path) -> u64 {
    let Ok(text) = fs::read_to_string(pid_dir.join("cgroup")) else {
        return 0;
    };
    let Some(path) = text.lines().find_map(|l| l.strip_prefix("0::")) else {
        return 0;
    };
    fs::metadata(
        roots
            .sys
            .join("fs/cgroup")
            .join(path.trim_start_matches('/')),
    )
    .map(|m| m.ino())
    .unwrap_or(0)
}

fn processes(roots: &Roots, ctx: &Context) -> Vec<Event> {
    let Ok(rd) = fs::read_dir(&roots.proc_) else {
        return Vec::new();
    };
    let mut pids: Vec<u32> = rd
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse().ok())
        .collect();
    pids.sort_unstable();

    let mut out = Vec::new();
    for pid in pids {
        let dir = roots.proc_.join(pid.to_string());
        // A process can exit mid-scan; anything unreadable is simply skipped.
        let Some(stat) = fs::read_to_string(dir.join("stat"))
            .ok()
            .as_deref()
            .and_then(parse_stat)
        else {
            continue;
        };
        let status = fs::read_to_string(dir.join("status")).unwrap_or_default();
        let (uid, euid) = status_ids(&status, "Uid:").unwrap_or((0, 0));
        let (gid, egid) = status_ids(&status, "Gid:").unwrap_or((0, 0));
        let cmdline: Vec<OsBytes> = fs::read(dir.join("cmdline"))
            .map(|b| {
                let mut parts: Vec<OsBytes> =
                    b.split(|&c| c == 0).map(|a| OsBytes(a.to_vec())).collect();
                if b.last() == Some(&0) {
                    parts.pop();
                }
                parts
            })
            .unwrap_or_default();
        let exe = fs::read_link(dir.join("exe"))
            .ok()
            .map(|p| OsBytes(p.as_os_str().as_bytes().to_vec()));
        let rd_u32 = |name: &str| {
            fs::read_to_string(dir.join(name))
                .ok()
                .and_then(|s| s.trim().parse::<u32>().ok())
                .filter(|&v| v != u32::MAX)
        };
        let start_boot_ns = stat.start_ticks.saturating_mul(TICK_NS);
        let kernel_thread = pid == 2 || stat.ppid == 2 || (cmdline.is_empty() && exe.is_none());
        let in_gap = ctx
            .gap_from_boot_ns
            .is_some_and(|from| start_boot_ns >= from);
        let actor = Actor {
            puid: puid(&ctx.boot_id, pid, start_boot_ns),
            pid,
            tid: pid,
            ppid: stat.ppid,
            uid,
            gid,
            euid,
            egid,
            user: None,
            auid: rd_u32("loginuid"),
            ses: rd_u32("sessionid"),
            cgroup_id: cgroup_id(roots, &dir),
            comm: stat.comm.clone(),
            exe: exe.clone(),
            cmdline: (!cmdline.is_empty()).then_some(cmdline),
            tty: None,
        };
        out.push(envelope(
            ctx,
            Some(actor),
            "process",
            json!({
                "start_boot_ns": start_boot_ns,
                "kernel_thread": kernel_thread,
                "parent_puid": parent_puid(roots, ctx, stat.ppid),
            }),
            in_gap,
        ));
    }
    out
}

/// Identity of a parent, from its own `stat`, so the tree can be linked without a second pass.
fn parent_puid(roots: &Roots, ctx: &Context, ppid: u32) -> Option<String> {
    if ppid == 0 {
        return None;
    }
    let stat = fs::read_to_string(roots.proc_.join(ppid.to_string()).join("stat")).ok()?;
    let s = parse_stat(&stat)?;
    Some(puid(
        &ctx.boot_id,
        ppid,
        s.start_ticks.saturating_mul(TICK_NS),
    ))
}

// ---- listening sockets -----------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Sock {
    pub addr: IpAddr,
    pub port: u16,
    pub state: u8,
    pub remote_unset: bool,
    pub uid: u32,
    pub inode: u64,
}

fn parse_addr(hex: &str) -> Option<IpAddr> {
    match hex.len() {
        8 => {
            let v = u32::from_str_radix(hex, 16).ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(v.to_ne_bytes())))
        }
        32 => {
            let mut b = [0u8; 16];
            for i in 0..4 {
                let w = u32::from_str_radix(hex.get(i * 8..i * 8 + 8)?, 16).ok()?;
                b[i * 4..i * 4 + 4].copy_from_slice(&w.to_ne_bytes());
            }
            Some(IpAddr::V6(Ipv6Addr::from(b)))
        }
        _ => None,
    }
}

/// One data line of `/proc/net/{tcp,tcp6,udp,udp6}`.
pub(crate) fn parse_net_line(line: &str) -> Option<Sock> {
    let f: Vec<&str> = line.split_whitespace().collect();
    let (la, lp) = f.get(1)?.split_once(':')?;
    let (ra, rp) = f.get(2)?.split_once(':')?;
    Some(Sock {
        addr: parse_addr(la)?,
        port: u16::from_str_radix(lp, 16).ok()?,
        state: u8::from_str_radix(f.get(3)?, 16).ok()?,
        remote_unset: ra.chars().all(|c| c == '0') && rp.chars().all(|c| c == '0'),
        uid: f.get(7)?.parse().ok()?,
        inode: f.get(9)?.parse().ok()?,
    })
}

/// socket inode -> owning (pid, comm), found through `/proc/<pid>/fd`.
fn socket_owners(roots: &Roots, wanted: &HashSet<u64>) -> HashMap<u64, (u32, String)> {
    let mut found = HashMap::new();
    let Ok(rd) = fs::read_dir(&roots.proc_) else {
        return found;
    };
    for e in rd.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(fds) = fs::read_dir(e.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(t) = fs::read_link(fd.path()) else {
                continue;
            };
            let t = t.to_string_lossy();
            let Some(n) = t.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')) else {
                continue;
            };
            let Ok(inode) = n.parse::<u64>() else {
                continue;
            };
            if wanted.contains(&inode) && !found.contains_key(&inode) {
                let comm = fs::read_to_string(e.path().join("comm"))
                    .map(|c| c.trim().to_string())
                    .unwrap_or_default();
                found.insert(inode, (pid, comm));
            }
        }
    }
    found
}

fn listen_sockets(roots: &Roots, ctx: &Context) -> Vec<Event> {
    let mut socks: Vec<(&str, Sock)> = Vec::new();
    for (proto, file) in [
        ("tcp", "net/tcp"),
        ("tcp", "net/tcp6"),
        ("udp", "net/udp"),
        ("udp", "net/udp6"),
    ] {
        let Ok(text) = fs::read_to_string(roots.proc_.join(file)) else {
            continue;
        };
        for s in text.lines().skip(1).filter_map(parse_net_line) {
            // TCP: LISTEN (0x0A). UDP has no listen state: take bound, unconnected sockets.
            let listening = if proto == "tcp" {
                s.state == 0x0a
            } else {
                s.remote_unset && s.port != 0
            };
            if listening {
                socks.push((proto, s));
            }
        }
    }
    let wanted: HashSet<u64> = socks.iter().map(|(_, s)| s.inode).collect();
    let owners = socket_owners(roots, &wanted);
    socks
        .into_iter()
        .map(|(proto, s)| {
            let owner = owners.get(&s.inode);
            envelope(
                ctx,
                None,
                "listen_socket",
                json!({
                    "proto": proto, "addr": s.addr.to_string(), "port": s.port,
                    "uid": s.uid, "inode": s.inode,
                    "pid": owner.map(|o| o.0), "comm": owner.map(|o| o.1.clone()),
                }),
                false,
            )
        })
        .collect()
}

// ---- sessions, modules, mounts, devices ------------------------------------------------

/// logind's per-session state files (`/run/systemd/sessions/<id>`, `KEY=value` lines).
fn sessions(roots: &Roots, ctx: &Context) -> Vec<Event> {
    let dir = roots.run.join("systemd/sessions");
    let Ok(rd) = fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut names: Vec<_> = rd.flatten().map(|e| e.file_name()).collect();
    names.sort();
    names
        .into_iter()
        .filter(|n| !n.to_string_lossy().ends_with(".ref"))
        .filter_map(|n| {
            let text = fs::read_to_string(dir.join(&n)).ok()?;
            let kv: HashMap<&str, &str> = text.lines().filter_map(|l| l.split_once('=')).collect();
            let g = |k: &str| kv.get(k).map(|v| v.to_string());
            Some(envelope(
                ctx,
                None,
                "session",
                json!({
                    "id": n.to_string_lossy(), "user": g("USER"), "uid": g("UID"),
                    "state": g("STATE"), "active": g("ACTIVE"), "remote": g("REMOTE"),
                    "remote_host": g("REMOTE_HOST"), "service": g("SERVICE"),
                    "tty": g("TTY"), "leader": g("LEADER"), "type": g("TYPE"),
                }),
                false,
            ))
        })
        .collect()
}

fn modules(roots: &Roots, ctx: &Context) -> Vec<Event> {
    let Ok(text) = fs::read_to_string(roots.proc_.join("modules")) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let used_by: Vec<&str> = f
                .get(3)?
                .trim_end_matches(',')
                .split(',')
                .filter(|s| !s.is_empty() && *s != "-")
                .collect();
            Some(envelope(
                ctx,
                None,
                "module",
                json!({
                    "name": f.first()?, "size": f.get(1)?.parse::<u64>().ok()?,
                    "refcount": f.get(2)?.parse::<i64>().ok(), "used_by": used_by,
                    "state": f.get(4),
                }),
                false,
            ))
        })
        .collect()
}

/// Decodes the octal escapes (`\040`) mountinfo uses for spaces and other awkward bytes.
fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 3 < b.len()
            && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c))
        {
            let v = (b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0');
            out.push(v);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn mounts(roots: &Roots, ctx: &Context) -> Vec<Event> {
    let Ok(text) = fs::read_to_string(roots.proc_.join("self/mountinfo")) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|l| {
            let (left, right) = l.split_once(" - ")?;
            let lf: Vec<&str> = left.split_whitespace().collect();
            let rf: Vec<&str> = right.split_whitespace().collect();
            Some(envelope(
                ctx,
                None,
                "mount",
                json!({
                    "mount_point": unescape(lf.get(4)?), "options": lf.get(5)?,
                    "major_minor": lf.get(2)?, "root": unescape(lf.get(3)?),
                    "fstype": rf.first()?, "source": unescape(rf.get(1)?),
                }),
                false,
            ))
        })
        .collect()
}

fn read_trim(p: &Path) -> Option<String> {
    let s = fs::read_to_string(p).ok()?;
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_string())
}

fn block_devices(roots: &Roots, ctx: &Context) -> Vec<Event> {
    let Ok(rd) = fs::read_dir(roots.sys.join("block")) else {
        return Vec::new();
    };
    let mut names: Vec<String> = rd
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| !n.starts_with("loop") && !n.starts_with("ram") && !n.starts_with("zram"))
        .collect();
    names.sort();
    names
        .into_iter()
        .map(|n| {
            let d = roots.sys.join("block").join(&n);
            let sectors = read_trim(&d.join("size")).and_then(|s| s.parse::<u64>().ok());
            envelope(
                ctx,
                None,
                "block_device",
                json!({
                    "name": n, "size_bytes": sectors.map(|s| s.saturating_mul(512)),
                    "removable": read_trim(&d.join("removable")).as_deref() == Some("1"),
                    "model": read_trim(&d.join("device/model")),
                    "serial": read_trim(&d.join("device/serial")),
                }),
                false,
            )
        })
        .collect()
}

fn usb_devices(roots: &Roots, ctx: &Context) -> Vec<Event> {
    let dir = roots.sys.join("bus/usb/devices");
    let Ok(rd) = fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = rd
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    names.sort();
    names
        .into_iter()
        .filter_map(|n| {
            let d = dir.join(&n);
            let vendor = read_trim(&d.join("idVendor"))?;
            Some(envelope(
                ctx,
                None,
                "usb_device",
                json!({
                    "busid": n, "vendor_id": vendor, "product_id": read_trim(&d.join("idProduct")),
                    "manufacturer": read_trim(&d.join("manufacturer")),
                    "product": read_trim(&d.join("product")),
                    "serial": read_trim(&d.join("serial")),
                }),
                false,
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_with_awkward_command_names() {
        // comm contains spaces and a ')' — fields must be located from the last ')'.
        let line = "4242 (my (weird) app) S 100 4242 4242 0 -1 4194560 1 0 0 0 1 2 0 0 20 0 3 0 987654 123456 78 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0";
        let s = parse_stat(line).unwrap();
        assert_eq!(s.comm, "my (weird) app");
        assert_eq!(s.ppid, 100);
        assert_eq!(s.start_ticks, 987_654);
        assert_eq!(parse_stat("garbage"), None);
        assert_eq!(parse_stat("1 (x) S 0"), None);
    }

    #[test]
    fn net_lines_decode_addresses_on_this_endianness() {
        // 127.0.0.1:53, LISTEN, inode 12345 (the hex form is the host-order printing of be32)
        let v4 = format!(
            "   0: {:08X}:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 12345 1 0 100 0 0 10 0",
            u32::from_ne_bytes([127, 0, 0, 1])
        );
        let s = parse_net_line(&v4).unwrap();
        assert_eq!(
            (s.addr, s.port, s.state, s.uid, s.inode),
            ("127.0.0.1".parse().unwrap(), 53, 0x0a, 101, 12345)
        );
        assert!(s.remote_unset);
        // ::1 port 22
        let words: String = Ipv6Addr::LOCALHOST
            .octets()
            .chunks(4)
            .map(|c| format!("{:08X}", u32::from_ne_bytes([c[0], c[1], c[2], c[3]])))
            .collect();
        let v6 = format!(
            "   1: {words}:0016 {}:0000 0A 0:0 0:0 0 0 0 777 1 0",
            "0".repeat(32)
        );
        let s = parse_net_line(&v6).unwrap();
        assert_eq!(
            (s.addr, s.port, s.inode),
            (IpAddr::V6(Ipv6Addr::LOCALHOST), 22, 777)
        );
        assert!(parse_net_line("sl local rem").is_none());
    }

    #[test]
    fn mountinfo_escapes() {
        assert_eq!(unescape("/mnt/with\\040space"), "/mnt/with space");
        assert_eq!(unescape("/plain"), "/plain");
        assert_eq!(unescape("/trailing\\04"), "/trailing\\04");
    }
}
