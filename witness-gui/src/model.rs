//! View models for the GUI: everything here is plain data and pure functions, so it is
//! tested without a window.

use std::collections::HashMap;

use serde_json::Value;

/// Seconds east of UTC added to every displayed time (0 = UTC).
static TZ_OFFSET_SECS: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

pub fn set_tz_offset(secs: i64) {
    TZ_OFFSET_SECS.store(secs, std::sync::atomic::Ordering::Relaxed);
}

/// The machine's current UTC offset in seconds, from `date +%z` (`+0600` → 21600).
pub fn local_offset_secs() -> i64 {
    std::process::Command::new("date")
        .arg("+%z")
        .output()
        .ok()
        .and_then(|o| parse_zone(String::from_utf8_lossy(&o.stdout).trim()))
        .unwrap_or(0)
}

/// `+0530` / `-0800` → seconds east of UTC.
pub fn parse_zone(z: &str) -> Option<i64> {
    let sign = match z.as_bytes().first()? {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let d = z.get(1..)?;
    if d.len() != 4 || !d.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let (h, m): (i64, i64) = (d[..2].parse().ok()?, d[2..].parse().ok()?);
    Some(sign * (h * 3600 + m * 60))
}

/// `2026-11-18 14:03:22.417` from nanoseconds since the Unix epoch, in UTC unless a local
/// offset has been set with [`set_tz_offset`].
pub fn fmt_time(wall_ns: u64) -> String {
    let secs = (wall_ns / 1_000_000_000) as i64
        + TZ_OFFSET_SECS.load(std::sync::atomic::Ordering::Relaxed);
    let ms = (wall_ns / 1_000_000) % 1000;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Howard Hinnant's civil-from-days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}.{ms:03}",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

fn join_argv(v: &Value) -> String {
    v.as_array()
        .map(|a| a.iter().map(s).collect::<Vec<_>>().join(" "))
        .unwrap_or_default()
}

/// Bytes with a unit: `90 B`, `1.5 KiB`, `2.0 MiB`.
pub fn fmt_bytes(n: u64) -> String {
    const U: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let (mut v, mut i) = (n as f64, 0);
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

/// When an event happened: `wall_ns`, or `ts_wall_ns` on anchor records.
pub fn wall(e: &Value) -> u64 {
    e["wall_ns"]
        .as_u64()
        .or_else(|| e["ts_wall_ns"].as_u64())
        .unwrap_or(0)
}

/// A short human description of a stored event.
pub fn describe(e: &Value) -> String {
    let d = &e["data"];
    let a = &e["actor"];
    match s(&e["type"]) {
        "proc_exec" => format!("exec {}", join_argv(&d["argv"]).trim()),
        "proc_exit" => {
            let how = match (d["exit_code"].as_i64(), d["signal"].as_i64()) {
                (_, Some(sig)) => format!("killed by signal {sig}"),
                (Some(c), _) => format!("exit {c}"),
                _ => "exit".to_string(),
            };
            format!("{how} {}", s(&a["comm"]))
        }
        "proc_fork" => format!("fork child={}", d["child_pid"]),
        "file_create" | "file_open_write" | "file_open_read" | "file_delete" | "file_truncate"
        | "file_close_write" => format!("{} {}", s(&a["comm"]), s(&d["path"])),
        "file_rename" => format!("{} → {}", s(&d["old"]), s(&d["new"])),
        "file_hash" => format!(
            "{} {}",
            s(&d["path"]),
            d["sha256"]
                .as_str()
                .map(|h| &h[..12.min(h.len())])
                .unwrap_or("(skipped)")
        ),
        "file_attr" => format!("{} {} mode={}", s(&d["op"]), s(&d["path"]), d["new_mode"]),
        "net_connect" | "net_accept" => format!(
            "{}:{} → {}:{} {}",
            s(&d["laddr"]),
            d["lport"],
            s(&d["raddr"]),
            d["rport"],
            s(&d["outcome"])
        ),
        "net_close" => format!(
            "{}:{} → {}:{} sent={} recv={}",
            s(&d["conn"]["laddr"]),
            d["conn"]["lport"],
            s(&d["conn"]["raddr"]),
            d["conn"]["rport"],
            d["bytes_sent"],
            d["bytes_recv"]
        ),
        "net_listen" | "net_listen_close" => format!("{}:{}", s(&d["addr"]), d["port"]),
        "dns" => format!(
            "{} {} {} {}",
            s(&d["direction"]),
            s(&d["qtype"]),
            s(&d["qname"]),
            d["answers"]
                .as_array()
                .map(|a| a
                    .iter()
                    .map(|x| s(&x["data"]))
                    .collect::<Vec<_>>()
                    .join(","))
                .unwrap_or_default()
        ),
        "login" => format!(
            "{} via {} from {}",
            s(&d["user"]),
            s(&d["service"]),
            s(&d["remote_addr"])
        ),
        "auth_fail" => format!(
            "{} {} from {}",
            s(&d["service"]),
            s(&d["user"]),
            s(&d["remote_addr"])
        ),
        "sudo" | "su" => format!(
            "{} → {} {} {}",
            s(&d["user"]),
            s(&d["target_user"]),
            s(&d["command"]),
            if d["allowed"] == false {
                "(refused)"
            } else {
                ""
            }
        ),
        "alert" => format!("[{}] {}", s(&d["severity"]), s(&d["title"])),
        "module_load" | "module_unload" => s(&d["name"]).to_string(),
        "usb_device" => format!(
            "{} {}:{} {}",
            s(&d["action"]),
            s(&d["vendor_id"]),
            s(&d["product_id"]),
            s(&d["product"])
        ),
        "block_device" => format!("{} {}", s(&d["action"]), s(&d["name"])),
        "account_change" => format!("{} {} {}", s(&d["kind"]), s(&d["name"]), s(&d["change"])),
        "authorized_key_change" => format!(
            "{} {} {}",
            s(&d["user"]),
            s(&d["change"]),
            s(&d["fingerprint"])
        ),
        "package_change" => format!("{} {} {}", s(&d["action"]), s(&d["name"]), s(&d["version"])),
        "udp_flow" => format!(
            "{}:{} ↔ {}:{}  sent {} ({} pkts)  received {} ({} pkts)",
            s(&d["laddr"]),
            d["lport"],
            s(&d["raddr"]),
            d["rport"],
            fmt_bytes(d["bytes_tx"].as_u64().unwrap_or(0)),
            d["packets_tx"],
            fmt_bytes(d["bytes_rx"].as_u64().unwrap_or(0)),
            d["packets_rx"]
        ),
        "integrity_check" => format!(
            "chain {} ({} records, {} ms, {})",
            s(&d["state"]),
            d["records"],
            d["duration_ms"],
            s(&d["trigger"])
        ),
        "file_activity_summary" => format!(
            "{}: {} writes, {} created, {} deleted",
            s(&d["dir"]),
            d["opens_for_write"],
            d["creates"],
            d["deletes"]
        ),
        "api_access" => format!("uid {} ({}) {}", d["uid"], s(&d["tier"]), s(&d["endpoint"])),
        "daemon_start" => format!(
            "witnessd {} started on kernel {}",
            s(&d["version"]),
            s(&d["kernel"])
        ),
        "daemon_stop" => format!("witnessd stopped ({})", s(&d["reason"])),
        "anchor" => format!(
            "chain head #{} {}",
            e["head_seq"],
            e["head_hash"]
                .as_str()
                .map(|h| &h[..12.min(h.len())])
                .unwrap_or("")
        ),
        "service_change" => format!(
            "{} {} ({})",
            s(&d["action"]),
            s(&d["unit"]),
            s(&d["result"])
        ),
        "logout" => format!("{} session {}", s(&d["user"]), d["session_id"]),
        "clock_change" => format!("{} {} ns", s(&d["kind"]), d["delta_ns"]),
        "source_health" => format!(
            "{} {} {}",
            s(&d["source"]),
            s(&d["status"]),
            s(&d["reason"])
        ),
        "capture_gap" | "capture_drop" => d.to_string(),
        other => {
            let t = d.to_string();
            format!("{other} {}", t.chars().take(160).collect::<String>())
        }
    }
}

/// How prominent a row is: alerts and capture loss stand out, chatter fades.
pub fn tone(e: &Value) -> &'static str {
    match s(&e["type"]) {
        "alert" => match s(&e["data"]["severity"]) {
            "critical" | "high" => "bad",
            "medium" => "warn",
            _ => "note",
        },
        "capture_gap" | "capture_drop" => "warn",
        "auth_fail" => "warn",
        _ => match e["prio"].as_u64() {
            Some(3) => "faint",
            _ => "",
        },
    }
}

/// One process in the tree.
#[derive(Debug, Clone, PartialEq)]
pub struct ProcNode {
    pub puid: String,
    pub pid: u64,
    pub ppid: u64,
    pub comm: String,
    pub cmd: String,
    pub user: String,
    pub started: u64,
    pub exited: Option<u64>,
    pub children: Vec<ProcNode>,
}

/// Builds a forest from `proc_exec`/`proc_exit` events (any order). A process is attached to
/// the most recent process that had its `ppid` as of its own start.
pub fn process_forest(events: &[Value]) -> Vec<ProcNode> {
    let mut sorted: Vec<&Value> = events
        .iter()
        .filter(|e| matches!(s(&e["type"]), "proc_exec" | "proc_exit"))
        .collect();
    sorted.sort_by_key(|e| e["seq"].as_u64().unwrap_or(0));
    let mut nodes: Vec<ProcNode> = Vec::new();
    let mut by_puid: HashMap<String, usize> = HashMap::new();
    let mut live_pid: HashMap<u64, usize> = HashMap::new();
    let mut parent_of: Vec<Option<usize>> = Vec::new();
    for e in sorted {
        let a = &e["actor"];
        let puid = s(&a["puid"]).to_string();
        let wall = e["wall_ns"].as_u64().unwrap_or(0);
        if s(&e["type"]) == "proc_exit" {
            if let Some(&i) = by_puid.get(&puid) {
                nodes[i].exited = Some(wall);
                live_pid.remove(&nodes[i].pid);
            }
            continue;
        }
        let pid = a["pid"].as_u64().unwrap_or(0);
        let ppid = a["ppid"].as_u64().unwrap_or(0);
        if let Some(&i) = by_puid.get(&puid) {
            // A re-exec in the same process: keep one node, show the latest command.
            nodes[i].cmd = join_argv(&e["data"]["argv"]);
            nodes[i].comm = s(&a["comm"]).to_string();
            continue;
        }
        let idx = nodes.len();
        nodes.push(ProcNode {
            puid: puid.clone(),
            pid,
            ppid,
            comm: s(&a["comm"]).to_string(),
            cmd: join_argv(&e["data"]["argv"]),
            user: s(&a["user"]).to_string(),
            started: wall,
            exited: None,
            children: Vec::new(),
        });
        parent_of.push(live_pid.get(&ppid).copied());
        by_puid.insert(puid, idx);
        live_pid.insert(pid, idx);
    }
    // Assemble bottom-up: indexes only grow, so a parent always precedes its child.
    let mut slots: Vec<Option<ProcNode>> = nodes.into_iter().map(Some).collect();
    for i in (0..slots.len()).rev() {
        if let Some(p) = parent_of[i] {
            if let Some(n) = slots[i].take() {
                if let Some(parent) = slots[p].as_mut() {
                    parent.children.insert(0, n);
                }
            }
        }
    }
    slots.into_iter().flatten().collect()
}

/// A login session and what happened in it.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionRow {
    pub ses: u64,
    pub user: String,
    pub first: u64,
    pub last: u64,
    pub events: usize,
    pub commands: usize,
}

/// Groups events by `actor.ses`, newest session first. Events without a session are skipped.
pub fn sessions(events: &[Value]) -> Vec<SessionRow> {
    let mut m: HashMap<u64, SessionRow> = HashMap::new();
    for e in events {
        let Some(ses) = e["actor"]["ses"].as_u64() else {
            continue;
        };
        let wall = e["wall_ns"].as_u64().unwrap_or(0);
        let r = m.entry(ses).or_insert_with(|| SessionRow {
            ses,
            user: s(&e["actor"]["user"]).to_string(),
            first: wall,
            last: wall,
            events: 0,
            commands: 0,
        });
        r.first = r.first.min(wall);
        r.last = r.last.max(wall);
        r.events += 1;
        if s(&e["type"]) == "proc_exec" {
            r.commands += 1;
        }
        if r.user.is_empty() {
            r.user = s(&e["actor"]["user"]).to_string();
        }
    }
    let mut v: Vec<SessionRow> = m.into_values().collect();
    v.sort_by_key(|r| std::cmp::Reverse(r.last));
    v
}

/// Heights in `0..=100` for a series, scaled to its maximum.
pub fn scale_bars(series: &[u64]) -> Vec<u32> {
    let max = series.iter().copied().max().unwrap_or(0).max(1);
    series.iter().map(|v| (v * 100 / max) as u32).collect()
}

/// A command line split for display: the program's base name (or `comm` if the command line
/// is empty) and the arguments, cut to `max` characters with an ellipsis.
pub fn split_command(cmd: &str, comm: &str, max: usize) -> (String, String) {
    let cmd = cmd.trim();
    let (first, rest) = cmd.split_once(' ').unwrap_or((cmd, ""));
    let head = first
        .rsplit('/')
        .next()
        .filter(|h| !h.is_empty())
        .unwrap_or(comm);
    let rest = if rest.chars().count() > max {
        let cut: String = rest.chars().take(max).collect();
        format!("{cut}…")
    } else {
        rest.to_string()
    };
    (head.to_string(), rest)
}

/// A named search, as stored: `{name, q, kind, last_secs}`. Process and session filters are
/// not saved (they refer to one particular process or session).
pub type SavedSearch = Value;

/// Where saved searches live: `$XDG_CONFIG_HOME/witness-gui/searches.json`, else
/// `~/.config/witness-gui/searches.json`.
pub fn searches_path() -> std::path::PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    base.join("witness-gui").join("searches.json")
}

/// Reads the saved searches; a missing or unreadable file is simply "none saved".
pub fn load_searches(path: &std::path::Path) -> Vec<SavedSearch> {
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice::<Vec<Value>>(&b).ok())
        .map(|v| {
            v.into_iter()
                .filter(|s| s["name"].as_str().is_some_and(|n| !n.is_empty()))
                .collect()
        })
        .unwrap_or_default()
}

/// Writes the list atomically (temp file then rename), creating the directory.
pub fn save_searches(path: &std::path::Path, list: &[SavedSearch]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(list).unwrap_or_default())?;
    std::fs::rename(&tmp, path)
}

/// Adds `s` or replaces the saved search with the same name.
pub fn upsert_search(list: &mut Vec<SavedSearch>, s: SavedSearch) {
    match list.iter().position(|x| x["name"] == s["name"]) {
        Some(i) => list[i] = s,
        None => list.push(s),
    }
    list.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
}

/// The event after (`delta` = 1) or before (`-1`) `current` in `list`, by `seq`; the first
/// event when nothing is selected. Stays on the end of the list rather than wrapping.
pub fn step(list: &[Value], current: Option<&Value>, delta: i32) -> Option<Value> {
    if list.is_empty() {
        return None;
    }
    let at = current
        .and_then(|c| list.iter().position(|e| e["seq"] == c["seq"]))
        .map(|i| i as i64);
    let next = match at {
        Some(i) => (i + delta as i64).clamp(0, list.len() as i64 - 1),
        None => 0,
    };
    list.get(next as usize).cloned()
}

/// Event kinds the daemon produces, for the Search kind picker.
pub const KINDS: &[&str] = &[
    "proc_exec",
    "proc_exit",
    "proc_fork",
    "file_create",
    "file_open_write",
    "file_open_read",
    "file_delete",
    "file_truncate",
    "file_rename",
    "file_attr",
    "file_link",
    "file_hash",
    "file_activity_summary",
    "net_connect",
    "net_accept",
    "net_close",
    "net_listen",
    "net_listen_close",
    "udp_flow",
    "dns",
    "login",
    "logout",
    "auth_fail",
    "sudo",
    "su",
    "usb_device",
    "block_device",
    "module_load",
    "module_unload",
    "service_change",
    "package_change",
    "account_change",
    "authorized_key_change",
    "clock_change",
    "alert",
    "triage_action",
    "rule_set_change",
    "integrity_check",
    "api_access",
    "capture_gap",
    "capture_drop",
    "source_health",
    "daemon_start",
    "daemon_stop",
    "baseline",
];

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// The displayed time zone is global; tests that read or change it take this lock.
    static TZ_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn commands_split_into_a_program_and_trimmed_arguments() {
        assert_eq!(
            split_command("/usr/bin/sudo -n /usr/bin/id -u", "sudo", 80),
            ("sudo".into(), "-n /usr/bin/id -u".into())
        );
        assert_eq!(
            split_command("", "kworker", 80),
            ("kworker".into(), String::new())
        );
        assert_eq!(split_command("ls", "ls", 80), ("ls".into(), String::new()));
        let long = format!("sh -c {}", "x".repeat(300));
        let (h, r) = split_command(&long, "sh", 20);
        assert_eq!(h, "sh");
        assert_eq!(r.chars().count(), 21, "20 characters and an ellipsis");
        assert!(r.ends_with('…'));
        // Multi-byte text is cut on a character boundary, never in the middle of one.
        assert!(split_command("a ééééééééé", "a", 3).1.starts_with("ééé"));
    }

    #[test]
    fn saved_searches_round_trip_replace_by_name_and_survive_bad_files() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("cfg/witness-gui/searches.json");
        assert!(load_searches(&f).is_empty(), "no file: none saved");
        let mut list = Vec::new();
        upsert_search(
            &mut list,
            json!({"name":"b","q":"x","kind":"","last_secs":null}),
        );
        upsert_search(
            &mut list,
            json!({"name":"a","q":"y","kind":"dns","last_secs":3600}),
        );
        upsert_search(
            &mut list,
            json!({"name":"b","q":"changed","kind":"","last_secs":null}),
        );
        assert_eq!(list.len(), 2, "same name replaces");
        assert_eq!(list[0]["name"], "a", "kept sorted by name");
        save_searches(&f, &list).unwrap();
        let back = load_searches(&f);
        assert_eq!(back, list);
        assert_eq!(back[1]["q"], "changed");
        // A corrupt file, and entries with no name, are ignored rather than fatal.
        std::fs::write(&f, b"{ not json").unwrap();
        assert!(load_searches(&f).is_empty());
        std::fs::write(
            &f,
            br#"[{"name":"ok","q":"1"},{"q":"nameless"},{"name":""}]"#,
        )
        .unwrap();
        assert_eq!(load_searches(&f).len(), 1);
    }

    #[test]
    fn stepping_moves_by_seq_and_stops_at_the_ends() {
        let l: Vec<Value> = (1..=3).map(|n| json!({"seq": n})).collect();
        assert_eq!(
            step(&l, None, 1).unwrap()["seq"],
            1,
            "nothing selected: start at the top"
        );
        assert_eq!(step(&l, Some(&l[0]), 1).unwrap()["seq"], 2);
        assert_eq!(
            step(&l, Some(&l[2]), 1).unwrap()["seq"],
            3,
            "no wrap past the end"
        );
        assert_eq!(
            step(&l, Some(&l[0]), -1).unwrap()["seq"],
            1,
            "no wrap past the start"
        );
        // A selection that is no longer in the list restarts from the top.
        assert_eq!(step(&l, Some(&json!({"seq": 99})), 1).unwrap()["seq"], 1);
        assert!(step(&[], None, 1).is_none());
    }

    #[test]
    fn zones_parse_and_shift_displayed_times() {
        let _guard = TZ_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(parse_zone("+0600"), Some(21_600));
        assert_eq!(parse_zone("-0830"), Some(-30_600));
        assert_eq!(parse_zone("+0000"), Some(0));
        assert_eq!(parse_zone("UTC"), None);
        assert_eq!(parse_zone("+06"), None);
        set_tz_offset(21_600);
        let shifted = fmt_time(1_795_010_975_165_861_169);
        set_tz_offset(0);
        assert_eq!(shifted, "2026-11-18 20:09:35.165");
        assert_eq!(
            fmt_time(1_795_010_975_165_861_169),
            "2026-11-18 14:09:35.165"
        );
    }

    #[test]
    fn times_format_in_utc() {
        let _guard = TZ_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(fmt_time(0), "1970-01-01 00:00:00.000");
        assert_eq!(
            fmt_time(1_795_010_975_165_861_169),
            "2026-11-18 14:09:35.165"
        );
        // Leap day and a year boundary.
        assert_eq!(fmt_time(951_782_400_000_000_000), "2000-02-29 00:00:00.000");
        assert_eq!(
            fmt_time(1_767_225_599_999_000_000),
            "2025-12-31 23:59:59.999"
        );
    }

    #[test]
    fn descriptions_read_naturally() {
        let e = json!({"type":"proc_exec","data":{"argv":["ls","-l","/tmp"]},"actor":{}});
        assert_eq!(describe(&e), "exec ls -l /tmp");
        let n = json!({"type":"net_close","data":{"conn":{"laddr":"1.1.1.1","lport":1,"raddr":"2.2.2.2","rport":443},"bytes_sent":5,"bytes_recv":8},"actor":{}});
        assert_eq!(describe(&n), "1.1.1.1:1 → 2.2.2.2:443 sent=5 recv=8");
        let s = json!({"type":"sudo","data":{"user":"a","target_user":"root","command":"/bin/id","allowed":false},"actor":{}});
        assert!(describe(&s).ends_with("(refused)"));
        // Unknown kinds still show something rather than nothing.
        let u = json!({"type":"future_kind","data":{"x":1},"actor":{}});
        assert!(describe(&u).starts_with("future_kind"));
    }

    #[test]
    fn newly_described_kinds_read_naturally_and_anchors_have_a_time() {
        let exit = json!({"type":"proc_exit","data":{"exit_code":0},"actor":{"comm":"ls"}});
        assert_eq!(describe(&exit), "exit 0 ls");
        let killed = json!({"type":"proc_exit","data":{"signal":9},"actor":{"comm":"x"}});
        assert_eq!(describe(&killed), "killed by signal 9 x");
        let udp = json!({"type":"udp_flow","data":{"laddr":"1.1.1.1","lport":5,"raddr":"2.2.2.2","rport":9,"bytes_tx":1536,"packets_tx":3,"bytes_rx":90,"packets_rx":2},"actor":{}});
        assert_eq!(
            describe(&udp),
            "1.1.1.1:5 ↔ 2.2.2.2:9  sent 1.5 KiB (3 pkts)  received 90 B (2 pkts)"
        );
        let ic = json!({"type":"integrity_check","data":{"state":"ok","records":884,"duration_ms":49,"trigger":"schedule"},"actor":{}});
        assert_eq!(describe(&ic), "chain ok (884 records, 49 ms, schedule)");
        let anchor = json!({"type":"anchor","head_seq":883,"head_hash":"cac8dc6da6cc2629","ts_wall_ns":1_795_101_623_087_195_911u64});
        assert_eq!(describe(&anchor), "chain head #883 cac8dc6da6cc");
        assert_eq!(wall(&anchor), 1_795_101_623_087_195_911);
        assert_eq!(wall(&json!({"wall_ns": 5})), 5);
        assert_eq!(fmt_bytes(0), "0 B");
        assert_eq!(fmt_bytes(2_097_152), "2.0 MiB");
    }

    #[test]
    fn tone_follows_alert_severity() {
        assert_eq!(
            tone(&json!({"type":"alert","data":{"severity":"high"}})),
            "bad"
        );
        assert_eq!(
            tone(&json!({"type":"alert","data":{"severity":"medium"}})),
            "warn"
        );
        assert_eq!(tone(&json!({"type":"proc_exec","prio":3})), "faint");
    }

    fn exec(seq: u64, puid: &str, pid: u64, ppid: u64, cmd: &str) -> Value {
        json!({"seq":seq,"type":"proc_exec","wall_ns":seq*1000,"actor":{"puid":puid,"pid":pid,"ppid":ppid,"comm":cmd,"user":"u","ses":3},"data":{"argv":[cmd]}})
    }

    #[test]
    fn the_process_tree_nests_by_parent_and_survives_pid_reuse() {
        let ev = vec![
            exec(1, "a", 10, 1, "bash"),
            exec(2, "b", 20, 10, "ls"),
            exec(3, "c", 21, 10, "cat"),
            json!({"seq":4,"type":"proc_exit","wall_ns":4000,"actor":{"puid":"b","pid":20}}),
            // pid 20 is reused by an unrelated process whose parent is 1 (not 10).
            exec(5, "d", 20, 1, "later"),
        ];
        let f = process_forest(&ev);
        let bash = f.iter().find(|n| n.puid == "a").unwrap();
        assert_eq!(
            bash.children
                .iter()
                .map(|c| c.puid.as_str())
                .collect::<Vec<_>>(),
            ["b", "c"]
        );
        assert_eq!(bash.children[0].exited, Some(4000));
        assert!(
            f.iter().any(|n| n.puid == "d"),
            "the reused pid is its own root"
        );
        assert!(!bash.children.iter().any(|c| c.puid == "d"));
    }

    #[test]
    fn re_exec_keeps_one_node_with_the_latest_command() {
        let mut second = exec(2, "a", 10, 1, "ls");
        second["actor"]["comm"] = json!("ls");
        let f = process_forest(&[exec(1, "a", 10, 1, "bash"), second]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].cmd, "ls");
    }

    #[test]
    fn sessions_aggregate_and_sort_newest_first() {
        let mk = |seq: u64, ses: u64, ty: &str| json!({"seq":seq,"type":ty,"wall_ns":seq*10,"actor":{"ses":ses,"user":"u"}});
        let ev = vec![
            mk(1, 1, "proc_exec"),
            mk(5, 2, "proc_exec"),
            mk(6, 2, "file_create"),
            mk(2, 1, "proc_exec"),
            json!({"type":"x","actor":{}}),
        ];
        let s = sessions(&ev);
        assert_eq!(s.iter().map(|r| r.ses).collect::<Vec<_>>(), [2, 1]);
        assert_eq!(
            (s[1].events, s[1].commands, s[1].first, s[1].last),
            (2, 2, 10, 20)
        );
    }

    #[test]
    fn bars_scale_to_the_largest_value_and_handle_empty() {
        assert_eq!(scale_bars(&[0, 5, 10]), vec![0, 50, 100]);
        assert_eq!(scale_bars(&[]), Vec::<u32>::new());
        assert_eq!(scale_bars(&[0, 0]), vec![0, 0]);
    }
}

/// A plain-language name for an event type, for places aimed at people who do not know the
/// internal names. Unknown types fall back to the name with spaces, never to nothing.
pub fn kind_label(kind: &str) -> String {
    match kind {
        "proc_exec" => "Program started",
        "proc_fork" => "Process created",
        "proc_exit" => "Program ended",
        "cred_change" => "Privileges changed",
        "shell_command" => "Shell command",
        "file_create" => "File created",
        "file_open_write" => "File opened for writing",
        "file_open_read" => "Sensitive file read",
        "file_close_write" => "File written and closed",
        "file_delete" => "File deleted",
        "file_truncate" => "File emptied",
        "file_rename" => "File renamed",
        "file_attr" => "Permissions or owner changed",
        "file_link" => "Link created",
        "file_hash" => "Important file fingerprinted",
        "file_activity_summary" => "File activity summary",
        "net_connect" => "Outgoing connection",
        "net_accept" => "Incoming connection",
        "net_close" => "Connection closed",
        "net_listen" => "Started listening",
        "net_listen_close" => "Stopped listening",
        "udp_flow" => "UDP traffic",
        "dns" => "DNS lookup",
        "login" => "Login",
        "logout" => "Logout",
        "auth_fail" => "Failed login",
        "sudo" => "sudo command",
        "su" => "su (switch user)",
        "usb_device" => "USB device",
        "block_device" => "Disk attached or removed",
        "module_load" => "Kernel module loaded",
        "module_unload" => "Kernel module removed",
        "service_change" => "Service started or stopped",
        "scheduler_change" => "Scheduled job changed",
        "package_change" => "Software installed or removed",
        "account_change" => "User account changed",
        "authorized_key_change" => "SSH key changed",
        "clock_change" => "Clock changed",
        "system_boot" => "System started",
        "system_shutdown" => "System shutting down",
        "daemon_start" => "Witness started",
        "daemon_stop" => "Witness stopped",
        "capture_gap" => "Recording gap",
        "capture_drop" => "Events lost under load",
        "source_health" => "Source status check",
        "config_change" => "Configuration changed",
        "recovery" => "Store recovered after a crash",
        "rule_set_change" => "Rules changed",
        "alert" => "Alert",
        "triage_action" => "Alert reviewed",
        "baseline" => "Starting snapshot",
        "clock_sync" => "Clock synchronised",
        "api_access" => "Someone used the API",
        "integrity_check" => "Evidence check",
        other => return other.replace('_', " "),
    }
    .to_string()
}

#[cfg(test)]
mod kind_label_tests {
    use super::kind_label;

    #[test]
    fn known_kinds_read_as_sentences_and_unknown_ones_degrade_gracefully() {
        assert_eq!(kind_label("proc_exec"), "Program started");
        assert_eq!(kind_label("baseline"), "Starting snapshot");
        assert_eq!(kind_label("some_new_kind"), "some new kind");
        assert_eq!(kind_label(""), "");
    }
}
