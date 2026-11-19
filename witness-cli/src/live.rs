//! `witness status` and `witness alerts`: plain answers from the running daemon.
//!
//! The rendering functions take parsed JSON and return text, so they are tested on fixed
//! responses; only `status`/`alerts` touch the socket.

use std::path::Path;

use serde_json::Value;
use witness_client::{Client, ClientError};

/// How many alerts `status` looks at. A count that reaches it is shown as `N+`.
pub const STATUS_ALERT_LIMIT: usize = 500;

/// Writes to stdout and stops quietly if the reader went away (`witness alerts | head`).
fn out(s: &str) {
    use std::io::Write;
    let _ = std::io::stdout().write_all(s.as_bytes());
}

/// `2026-11-20 09:15:02 UTC` for nanoseconds since the epoch.
pub fn fmt_utc(wall_ns: u64) -> String {
    let secs = (wall_ns / 1_000_000_000) as i64;
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
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// `5 min ago`, `3 h ago`, `2 d ago`; `just now` under a minute.
pub fn ago(now_ns: u64, then_ns: u64) -> String {
    let s = now_ns.saturating_sub(then_ns) / 1_000_000_000;
    match s {
        0..=59 => "just now".into(),
        60..=3599 => format!("{} min ago", s / 60),
        3600..=86_399 => format!("{} h ago", s / 3600),
        _ => format!("{} d ago", s / 86_400),
    }
}

/// `2 h 5 min`, `3 d 4 h`, `45 s`.
pub fn duration(secs: u64) -> String {
    match secs {
        0..=59 => format!("{secs} s"),
        60..=3599 => format!("{} min", secs / 60),
        3600..=86_399 => format!("{} h {} min", secs / 3600, secs % 3600 / 60),
        _ => format!("{} d {} h", secs / 86_400, secs % 86_400 / 3600),
    }
}

/// `12345` -> `12,345`.
pub fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// The overview: is it running, is the evidence intact, does anything need attention.
pub fn render_status(status: &Value, integrity: &Value, alerts: &Value) -> String {
    let now = status["wall_ns"].as_u64().unwrap_or(0);
    let mut o = String::new();
    o.push_str(&format!(
        "Witness is running (version {}, up {}).\n",
        status["version"].as_str().unwrap_or("?"),
        duration(status["uptime_secs"].as_u64().unwrap_or(0))
    ));
    let head = status["head_seq"].as_u64().unwrap_or(0);
    let behind = status["indexed_seq"]
        .as_u64()
        .map(|i| head.saturating_sub(i))
        .unwrap_or(head);
    o.push_str(&format!(
        "  Records stored:      {}{}\n",
        thousands(head),
        if behind > 100 {
            format!("  (search is catching up: {} behind)", thousands(behind))
        } else {
            String::new()
        }
    ));
    let when = integrity["finished_wall_ns"]
        .as_u64()
        .map(|t| format!(", checked {}", ago(now, t)))
        .unwrap_or_default();
    let line = match integrity["state"].as_str().unwrap_or("never_run") {
        "ok" => format!("OK: every record verifies{when}"),
        "broken" => format!(
            "PROBLEM: the evidence does not verify{when}. {}\n\
             {:23}Run `sudo witness verify` for the exact location.",
            integrity["broken"]
                .as_str()
                .or(integrity["detail"].as_str())
                .unwrap_or(""),
            ""
        ),
        "running" => "a check is running now".into(),
        "error" => format!(
            "the last check could not run{when}: {}",
            integrity["detail"].as_str().unwrap_or("see the daemon log")
        ),
        _ => "not checked yet (the first check runs shortly after start)".into(),
    };
    o.push_str(&format!("  Evidence integrity:  {line}\n"));

    let open: Vec<&Value> = alerts["events"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|a| a["triage"]["status"].as_str().unwrap_or("new") == "new")
        .collect();
    if open.is_empty() {
        o.push_str("  Alerts to review:    none\n");
    } else {
        let mut by: Vec<(&str, usize)> = Vec::new();
        for sev in ["critical", "high", "medium", "low", "info"] {
            let n = open.iter().filter(|a| a["data"]["severity"] == sev).count();
            if n > 0 {
                by.push((sev, n));
            }
        }
        let parts: Vec<String> = by.iter().map(|(s, n)| format!("{n} {s}")).collect();
        o.push_str(&format!(
            "  Alerts to review:    {}{} ({}). Run `witness alerts`.\n",
            open.len(),
            if alerts["events"].as_array().map_or(0, Vec::len) >= STATUS_ALERT_LIMIT {
                "+"
            } else {
                ""
            },
            parts.join(", ")
        ));
    }
    o.push_str(&format!(
        "  Your access:         {}\n",
        if status["tier"] == "admin" {
            "administrator"
        } else {
            "read-only (use sudo to acknowledge alerts or run checks)"
        }
    ));
    o
}

/// One line per alert, newest last, with what to do next.
pub fn render_alerts(alerts: &Value, all: bool, now_ns: u64) -> String {
    let mut list: Vec<&Value> = alerts["events"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|a| all || a["triage"]["status"].as_str().unwrap_or("new") == "new")
        .collect();
    // The API returns newest first; read oldest to newest so the latest is at the bottom.
    list.sort_by_key(|a| a["seq"].as_u64().unwrap_or(0));
    if list.is_empty() {
        return if all {
            "No alerts have been raised.\n".into()
        } else {
            "No alerts to review. The rules are watching. (`witness alerts --all` shows reviewed ones too.)\n".into()
        };
    }
    let mut o = String::new();
    for a in &list {
        let d = &a["data"];
        let status = a["triage"]["status"].as_str().unwrap_or("new");
        o.push_str(&format!(
            "#{:<6} {:<8} {}  {}{}\n        {} ({})\n",
            a["seq"].as_u64().unwrap_or(0),
            d["severity"].as_str().unwrap_or("?").to_uppercase(),
            fmt_utc(a["wall_ns"].as_u64().unwrap_or(0)),
            d["title"].as_str().unwrap_or(""),
            if status == "new" {
                String::new()
            } else {
                format!("  [{}]", status.replace('_', " "))
            },
            ago(now_ns, a["wall_ns"].as_u64().unwrap_or(0)),
            d["rule_id"].as_str().unwrap_or(""),
        ));
    }
    o.push_str(&format!(
        "\n{} shown. Full detail and the records that triggered each: `witness alerts --json`, or the Alerts page of witness-gui.\n",
        list.len()
    ));
    o
}

fn explain(e: ClientError) -> anyhow::Error {
    anyhow::anyhow!("{}", e.hint())
}

pub fn status(socket: &Path, json: bool) -> anyhow::Result<()> {
    let c = Client::new(socket);
    let st = c.get("/v1/status").map_err(explain)?;
    let integ = c.get("/v1/integrity").unwrap_or(Value::Null);
    let alerts = c
        .get(&format!("/v1/alerts?limit={STATUS_ALERT_LIMIT}"))
        .unwrap_or_else(|_| serde_json::json!({"events": []}));
    if json {
        out(&format!(
            "{}\n",
            serde_json::json!({"status": st, "integrity": integ, "alerts": alerts})
        ));
    } else {
        out(&render_status(&st, &integ, &alerts));
    }
    Ok(())
}

pub fn alerts(socket: &Path, all: bool, limit: usize, json: bool) -> anyhow::Result<()> {
    let c = Client::new(socket);
    let st = c.get("/v1/status").map_err(explain)?;
    let a = c
        .get(&format!("/v1/alerts?limit={limit}"))
        .map_err(explain)?;
    if json {
        out(&format!("{a}\n"));
    } else {
        out(&render_alerts(&a, all, st["wall_ns"].as_u64().unwrap_or(0)));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn times_and_numbers_read_naturally() {
        // Expected value from `date -u -r 1795114190` (independent source).
        assert_eq!(
            fmt_utc(1_795_114_190_000_000_000),
            "2026-11-19 18:49:50 UTC"
        );
        assert_eq!(fmt_utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(12_345), "12,345");
        assert_eq!(thousands(1_234_567), "1,234,567");
        assert_eq!(duration(45), "45 s");
        assert_eq!(duration(7500), "2 h 5 min");
        assert_eq!(duration(3 * 86_400 + 4 * 3600), "3 d 4 h");
        let n = 10_000_000_000_000u64;
        assert_eq!(ago(n, n - 30_000_000_000), "just now");
        assert_eq!(ago(n, n - 300_000_000_000), "5 min ago");
    }

    fn status_json() -> Value {
        json!({"version":"0.1.0","uptime_secs":7500,"head_seq":12345,"indexed_seq":12345,
               "tier":"read","wall_ns":1_795_114_190_000_000_000u64})
    }

    #[test]
    fn status_says_what_matters_in_plain_words() {
        let integ = json!({"state":"ok","finished_wall_ns":1_795_113_890_000_000_000u64});
        let alerts = json!({"events":[
            {"seq":5,"data":{"severity":"high"},"triage":{"status":"new"}},
            {"seq":6,"data":{"severity":"medium"},"triage":{"status":"new"}},
            {"seq":7,"data":{"severity":"high"},"triage":{"status":"acknowledged"}}]});
        let t = render_status(&status_json(), &integ, &alerts);
        assert!(t.contains("up 2 h 5 min"), "{t}");
        assert!(t.contains("12,345"), "{t}");
        assert!(
            t.contains("OK: every record verifies, checked 5 min ago"),
            "{t}"
        );
        assert!(
            t.contains("2 (1 high, 1 medium)"),
            "reviewed alerts are not counted: {t}"
        );
        assert!(t.contains("read-only"), "{t}");
    }

    #[test]
    fn a_broken_chain_is_not_buried() {
        let integ = json!({"state":"broken","broken":"segment 3 hash mismatch","finished_wall_ns":1_795_114_000_000_000_000u64});
        let t = render_status(&status_json(), &integ, &json!({"events":[]}));
        assert!(t.contains("PROBLEM"), "{t}");
        assert!(t.contains("segment 3 hash mismatch"), "{t}");
        assert!(t.contains("witness verify"), "{t}");
        assert!(t.contains("Alerts to review:    none"), "{t}");
        let never = render_status(
            &status_json(),
            &json!({"state":"never_run"}),
            &json!({"events":[]}),
        );
        assert!(never.contains("not checked yet"), "{never}");
    }

    #[test]
    fn alerts_list_shows_what_happened_and_hides_reviewed_ones() {
        let a = json!({"events":[
            {"seq":41,"wall_ns":1_795_114_000_000_000_000u64,"data":{"severity":"high","title":"Shell with a network socket as stdin","rule_id":"witness.exec.shell-on-socket"},"triage":{"status":"new"}},
            {"seq":42,"wall_ns":1_795_114_100_000_000_000u64,"data":{"severity":"low","title":"Service stopped","rule_id":"witness.service.stopped"},"triage":{"status":"false_positive"}}]});
        let now = 1_795_114_190_000_000_000u64;
        let open = render_alerts(&a, false, now);
        assert!(
            open.contains("#41")
                && open.contains("HIGH")
                && open.contains("Shell with a network socket"),
            "{open}"
        );
        assert!(
            open.contains("witness.exec.shell-on-socket") && !open.contains("#42"),
            "{open}"
        );
        let all = render_alerts(&a, true, now);
        assert!(
            all.contains("#42") && all.contains("[false positive]"),
            "{all}"
        );
        assert!(render_alerts(&json!({"events":[]}), false, now).contains("No alerts to review"));
        // Oldest first, so the newest ends up next to the prompt.
        let two = json!({"events":[
            {"seq":9,"wall_ns":1,"data":{"severity":"low","title":"newer","rule_id":"r"}},
            {"seq":3,"wall_ns":1,"data":{"severity":"low","title":"older","rule_id":"r"}}]});
        let t = render_alerts(&two, false, now);
        assert!(t.find("older").unwrap() < t.find("newer").unwrap(), "{t}");
    }

    #[test]
    fn a_count_that_hit_the_query_limit_says_so() {
        let events: Vec<Value> = (0..STATUS_ALERT_LIMIT)
            .map(|i| json!({"seq":i,"data":{"severity":"medium"},"triage":{"status":"new"}}))
            .collect();
        let t = render_status(
            &status_json(),
            &json!({"state":"ok"}),
            &json!({ "events": events }),
        );
        assert!(t.contains("500+ (500 medium)"), "{t}");
    }
}
