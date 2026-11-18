//! View models for the GUI: everything here is plain data and pure functions, so it is
//! tested without a window.

use std::collections::HashMap;

use serde_json::Value;

/// `2026-11-18 14:03:22.417` in UTC from nanoseconds since the Unix epoch.
pub fn fmt_time(wall_ns: u64) -> String {
    let secs = (wall_ns / 1_000_000_000) as i64;
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

/// A short human description of a stored event.
pub fn describe(e: &Value) -> String {
    let d = &e["data"];
    let a = &e["actor"];
    match s(&e["type"]) {
        "proc_exec" => format!("exec {}", join_argv(&d["argv"]).trim()),
        "proc_exit" => format!("exit code={} {}", d["code"], s(&a["comm"])),
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
            Some(0) => "strong",
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn times_format_in_utc() {
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
