//! Parses sshd / sudo / su log messages into schema bodies (DESIGN.md §2.4).
//!
//! These are free-text messages and differ across versions, so every body keeps the raw line.
//! A message that matches nothing returns `None` and is simply not turned into an event.

use std::net::IpAddr;

use serde_json::Value;
use witness_common::schema::{
    AuthFail, Body, Login, Logout, ServiceAction, ServiceChange, Shutdown, Sudo,
};

/// Ids of logind sessions of class `manager`: systemd's per-user service manager, which logind
/// opens beside every login on newer systemd. They are not logins, and the matching
/// "Removed session" line does not say the class, so the ids are remembered (bounded).
static MANAGER_SESSIONS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

fn is_manager_class(msg: &str) -> bool {
    msg.contains("with class 'manager")
}

/// Structured journal records from systemd and logind (their fields are more reliable than
/// their text): service start/stop with the job result, and session open/close.
pub fn parse_fields(v: &Value) -> Option<Body> {
    let field = |k: &str| v.get(k).and_then(Value::as_str);
    let ident = field("SYSLOG_IDENTIFIER").or_else(|| field("_COMM"))?;
    match ident {
        "systemd-logind" => {
            let msg = journal_text(v)?;
            // Shutdown records carry no session. The kind is what logind says it is doing.
            let shutdown = if msg.starts_with("System is powering down") {
                Some("poweroff")
            } else if msg.starts_with("System is rebooting") {
                Some("reboot")
            } else if msg.starts_with("System is halting") {
                Some("halt")
            } else {
                None
            };
            if let Some(kind) = shutdown {
                return Some(Body::SystemShutdown(Shutdown { kind: kind.into() }));
            }
            let sid = field("SESSION_ID")?;
            // Numeric ids are logins; others (`c1`) are kept as a label with id 0.
            let (session_id, session) = match sid.parse::<u32>() {
                Ok(n) => (n, None),
                Err(_) => (0, Some(sid.to_string())),
            };
            let user = field("USER_ID")?.to_string();
            // A poisoned lock only costs the filter, never the event.
            let mut managers = MANAGER_SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
            if msg.starts_with("New session ") && is_manager_class(&msg) {
                if managers.len() >= 256 {
                    managers.remove(0);
                }
                managers.push(sid.to_string());
                return None;
            }
            if msg.starts_with("Removed session ") {
                if let Some(i) = managers.iter().position(|m| m == sid) {
                    managers.remove(i);
                    return None;
                }
            }
            drop(managers);
            if msg.starts_with("New session ") {
                Some(Body::Login(Login {
                    user,
                    service: "logind".into(),
                    method: None,
                    remote_addr: None,
                    remote_port: None,
                    tty: None,
                    session_id,
                    session,
                }))
            } else if msg.starts_with("Removed session ") {
                Some(Body::Logout(Logout {
                    user,
                    session_id,
                    session,
                }))
            } else {
                None
            }
        }
        "systemd" => {
            // Only job-completion records carry both fields: "Started X.", "Stopped X.", etc.
            let (job, result, unit) = (field("JOB_TYPE")?, field("JOB_RESULT")?, field("UNIT")?);
            if !["service", "timer", "socket", "path", "target"]
                .iter()
                .any(|k| unit.ends_with(&format!(".{k}")))
            {
                return None;
            }
            // A restart is reported as a stop and a start; use what each record says happened.
            let msg = journal_text(v).unwrap_or_default();
            let action = match job {
                "reload" | "reload-or-restart" if msg.starts_with("Reloaded") => {
                    ServiceAction::Reload
                }
                _ if msg.starts_with("Started") || msg.starts_with("Starting") => {
                    ServiceAction::Start
                }
                _ if msg.starts_with("Stopped") || msg.starts_with("Stopping") => {
                    ServiceAction::Stop
                }
                "start" => ServiceAction::Start,
                "stop" => ServiceAction::Stop,
                "restart" | "try-restart" => ServiceAction::Restart,
                "reload" => ServiceAction::Reload,
                _ => return None,
            };
            Some(Body::ServiceChange(ServiceChange {
                unit: unit.to_string(),
                action,
                result: Some(result.to_string()),
                job_id: field("JOB_ID").and_then(|j| j.parse().ok()),
            }))
        }
        _ => None,
    }
}

/// `MESSAGE` as text; journald encodes non-UTF-8 messages as a byte array.
pub fn journal_text(v: &Value) -> Option<String> {
    match v.get("MESSAGE")? {
        Value::String(s) => Some(s.clone()),
        Value::Array(a) => {
            let bytes: Vec<u8> = a
                .iter()
                .filter_map(|x| x.as_u64().map(|n| n as u8))
                .collect();
            Some(String::from_utf8_lossy(&bytes).into_owned())
        }
        _ => None,
    }
}

/// `ident` is the syslog identifier of the emitter (`sshd`, `sudo`, `su`, `login`).
pub fn parse(ident: &str, msg: &str) -> Option<Body> {
    // sudo left-pads its messages with spaces when it has no TTY (seen on Ubuntu 22.04).
    let msg = msg.trim();
    match ident {
        "sshd" | "sshd-session" => sshd(msg),
        "sudo" => sudo(msg),
        "su" | "su-l" => su(msg),
        _ => None,
    }
}

/// `x from 1.2.3.4 port 22 ssh2` → (addr, port).
fn from_port(s: &str) -> (Option<IpAddr>, Option<u16>) {
    let mut it = s.split_whitespace();
    while let Some(w) = it.next() {
        if w == "from" {
            let addr = it.next().and_then(|a| a.parse().ok());
            let port = match (it.next(), it.next()) {
                (Some("port"), Some(p)) => p.parse().ok(),
                _ => None,
            };
            return (addr, port);
        }
    }
    (None, None)
}

fn sshd(msg: &str) -> Option<Body> {
    if let Some(rest) = msg.strip_prefix("Accepted ") {
        // Accepted publickey for alice from 10.0.0.5 port 5222 ssh2: ED25519 SHA256:...
        let (method, rest) = rest.split_once(" for ")?;
        let user = rest.split_whitespace().next()?;
        let (remote_addr, remote_port) = from_port(rest);
        return Some(Body::Login(Login {
            user: user.into(),
            service: "sshd".into(),
            method: Some(method.into()),
            remote_addr,
            remote_port,
            tty: None,
            session_id: 0,
            session: None,
        }));
    }
    let fail = |user: Option<&str>, method: Option<&str>, tail: &str| {
        Some(Body::AuthFail(AuthFail {
            user: user.map(String::from),
            service: "sshd".into(),
            method: method.map(String::from),
            remote_addr: from_port(tail).0,
            raw: msg.into(),
        }))
    };
    if let Some(rest) = msg.strip_prefix("Failed ") {
        // Failed password for [invalid user ]bob from 1.2.3.4 port 22 ssh2
        let (method, rest) = rest.split_once(" for ")?;
        let rest2 = rest.strip_prefix("invalid user ").unwrap_or(rest);
        let user = rest2.split_whitespace().next()?;
        return fail(Some(user), Some(method), rest2);
    }
    if let Some(rest) = msg.strip_prefix("Invalid user ") {
        let user = rest.split_whitespace().next()?;
        return fail(Some(user), None, rest);
    }
    None
}

fn sudo(msg: &str) -> Option<Body> {
    // alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id
    // alice : command not allowed ; TTY=... ; COMMAND=...
    // alice : 3 incorrect password attempts ; TTY=... ; COMMAND=...
    let (user, rest) = msg.split_once(" : ")?;
    if user.contains(' ') || !rest.contains("COMMAND=") {
        return None;
    }
    let mut tty = None;
    let mut cwd = None;
    let mut target = None;
    let mut command = None;
    let mut allowed = true;
    for part in rest.split(" ; ") {
        if let Some(v) = part.strip_prefix("TTY=") {
            tty = Some(v.to_string());
        } else if let Some(v) = part.strip_prefix("PWD=") {
            cwd = Some(v.to_string());
        } else if let Some(v) = part.strip_prefix("USER=") {
            target = Some(v.to_string());
        } else if let Some(v) = part.strip_prefix("COMMAND=") {
            command = Some(v.to_string());
        } else {
            // "command not allowed", "N incorrect password attempts", "user NOT in sudoers"
            allowed = false;
        }
    }
    Some(Body::Sudo(Sudo {
        user: user.into(),
        target_user: target.unwrap_or_else(|| "root".into()),
        command: command?,
        tty,
        cwd,
        allowed,
        raw: msg.into(),
    }))
}

fn su(msg: &str) -> Option<Body> {
    // (to root) alice on pts/0
    // FAILED SU (to root) alice on pts/0
    let (failed, rest) = match msg.strip_prefix("FAILED SU ") {
        Some(r) => (true, r),
        None => (false, msg),
    };
    let rest = rest.strip_prefix("(to ")?;
    let (target, rest) = rest.split_once(") ")?;
    let (user, tty) = rest.split_once(" on ")?;
    Some(Body::Su(Sudo {
        user: user.into(),
        target_user: target.into(),
        command: String::new(),
        tty: Some(tty.trim().into()),
        cwd: None,
        allowed: !failed,
        raw: msg.into(),
    }))
}

#[cfg(test)]
mod journal_tests {
    use serde_json::json;

    use super::*;

    // Records copied from journald on Ubuntu 22.04 (fields trimmed to the relevant ones).
    #[test]
    fn logind_sessions_open_and_close_with_the_user() {
        let open = json!({"SYSLOG_IDENTIFIER":"systemd-logind","MESSAGE":"New session 3 of user shafikshaon.","SESSION_ID":"3","USER_ID":"shafikshaon"});
        let Some(Body::Login(l)) = parse_fields(&open) else {
            panic!()
        };
        assert_eq!(
            (l.user.as_str(), l.session_id, l.service.as_str()),
            ("shafikshaon", 3, "logind")
        );
        let close = json!({"SYSLOG_IDENTIFIER":"systemd-logind","MESSAGE":"Removed session 3.","SESSION_ID":"3","USER_ID":"shafikshaon"});
        let Some(Body::Logout(o)) = parse_fields(&close) else {
            panic!()
        };
        assert_eq!((o.user.as_str(), o.session_id), ("shafikshaon", 3));
        // "logged out" is a precursor, not the end of the session: not reported twice.
        let pre = json!({"SYSLOG_IDENTIFIER":"systemd-logind","MESSAGE":"Session 3 logged out. Waiting for processes to exit.","SESSION_ID":"3","USER_ID":"shafikshaon"});
        assert!(parse_fields(&pre).is_none());
    }

    #[test]
    fn manager_sessions_are_not_logins() {
        // Text from journald on Fedora 45 (systemd 259): one ssh login opens session 14 (user)
        // and 15 (manager). Ids are unusual so parallel tests cannot collide with them.
        let user = json!({"SYSLOG_IDENTIFIER":"systemd-logind","MESSAGE":"New session '9014' of user 'ws1' with class 'user' and type 'tty'.","SESSION_ID":"9014","USER_ID":"ws1"});
        assert!(matches!(parse_fields(&user), Some(Body::Login(_))));
        let mgr = json!({"SYSLOG_IDENTIFIER":"systemd-logind","MESSAGE":"New session '9015' of user 'ws1' with class 'manager' and type 'unspecified'.","SESSION_ID":"9015","USER_ID":"ws1"});
        assert!(parse_fields(&mgr).is_none());
        let gone = json!({"SYSLOG_IDENTIFIER":"systemd-logind","MESSAGE":"Removed session 9015.","SESSION_ID":"9015","USER_ID":"ws1"});
        assert!(parse_fields(&gone).is_none(), "its removal is skipped too");
        let gone_user = json!({"SYSLOG_IDENTIFIER":"systemd-logind","MESSAGE":"Removed session 9014.","SESSION_ID":"9014","USER_ID":"ws1"});
        assert!(matches!(parse_fields(&gone_user), Some(Body::Logout(_))));
    }

    #[test]
    fn shutdown_and_non_numeric_sessions() {
        // Verbatim from journald on Ubuntu 22.04.
        let down = json!({"SYSLOG_IDENTIFIER":"systemd-logind","MESSAGE":"System is powering down.","MESSAGE_ID":"98268866d1d54a499c4e98921d93bc40"});
        let Some(Body::SystemShutdown(s)) = parse_fields(&down) else {
            panic!()
        };
        assert_eq!(s.kind, "poweroff");
        let reboot = json!({"SYSLOG_IDENTIFIER":"systemd-logind","MESSAGE":"System is rebooting."});
        assert!(
            matches!(parse_fields(&reboot), Some(Body::SystemShutdown(s)) if s.kind == "reboot")
        );
        // A session that is not a login has a non-numeric id: kept as a label.
        let open = json!({"SYSLOG_IDENTIFIER":"systemd-logind","MESSAGE":"New session c1 of user gdm.","SESSION_ID":"c1","USER_ID":"gdm"});
        let Some(Body::Login(l)) = parse_fields(&open) else {
            panic!()
        };
        assert_eq!((l.session_id, l.session.as_deref()), (0, Some("c1")));
        let close = json!({"SYSLOG_IDENTIFIER":"systemd-logind","MESSAGE":"Removed session c1.","SESSION_ID":"c1","USER_ID":"gdm"});
        assert!(
            matches!(parse_fields(&close), Some(Body::Logout(o)) if o.session.as_deref() == Some("c1"))
        );
    }

    #[test]
    fn systemd_job_results_become_service_changes() {
        let started = json!({"_COMM":"systemd","SYSLOG_IDENTIFIER":"systemd","MESSAGE":"Started Regular background program processing daemon.","UNIT":"cron.service","JOB_TYPE":"start","JOB_RESULT":"done"});
        let Some(Body::ServiceChange(c)) = parse_fields(&started) else {
            panic!()
        };
        assert_eq!(
            (c.unit.as_str(), c.action, c.result.as_deref()),
            ("cron.service", ServiceAction::Start, Some("done"))
        );
        // The stop half of a restart is a Stop, not a Restart.
        let stopped = json!({"SYSLOG_IDENTIFIER":"systemd","MESSAGE":"Stopped Regular background program processing daemon.","UNIT":"cron.service","JOB_TYPE":"restart","JOB_RESULT":"done"});
        let Some(Body::ServiceChange(c)) = parse_fields(&stopped) else {
            panic!()
        };
        assert_eq!(c.action, ServiceAction::Stop);
        // A failed start keeps its result.
        let failed = json!({"SYSLOG_IDENTIFIER":"systemd","MESSAGE":"Failed to start X.","UNIT":"x.service","JOB_TYPE":"start","JOB_RESULT":"failed"});
        let Some(Body::ServiceChange(c)) = parse_fields(&failed) else {
            panic!()
        };
        assert_eq!(
            (c.action, c.result.as_deref()),
            (ServiceAction::Start, Some("failed"))
        );
        // Not job completions, or not services: ignored.
        let deact = json!({"SYSLOG_IDENTIFIER":"systemd","MESSAGE":"cron.service: Deactivated successfully.","UNIT":"cron.service"});
        assert!(parse_fields(&deact).is_none());
        let mount = json!({"SYSLOG_IDENTIFIER":"systemd","MESSAGE":"Mounted /x.","UNIT":"x.mount","JOB_TYPE":"start","JOB_RESULT":"done"});
        assert!(parse_fields(&mount).is_none());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_accept() {
        let Some(Body::Login(l)) = parse(
            "sshd",
            "Accepted publickey for alice from 10.0.0.5 port 5222 ssh2: ED25519 SHA256:abc",
        ) else {
            panic!()
        };
        assert_eq!(l.user, "alice");
        assert_eq!(l.method.as_deref(), Some("publickey"));
        assert_eq!(l.remote_addr, "10.0.0.5".parse().ok());
        assert_eq!(l.remote_port, Some(5222));
    }

    #[test]
    fn ssh_failures() {
        let Some(Body::AuthFail(f)) = parse(
            "sshd",
            "Failed password for invalid user bob from 2001:db8::1 port 22 ssh2",
        ) else {
            panic!()
        };
        assert_eq!(f.user.as_deref(), Some("bob"));
        assert_eq!(f.method.as_deref(), Some("password"));
        assert_eq!(f.remote_addr, "2001:db8::1".parse().ok());
        assert!(matches!(
            parse("sshd", "Invalid user x from 1.2.3.4 port 4"),
            Some(Body::AuthFail(_))
        ));
        assert!(parse("sshd", "Connection closed by 1.2.3.4").is_none());
    }

    #[test]
    fn sudo_allowed_and_denied() {
        let Some(Body::Sudo(s)) = parse(
            "sudo",
            "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id -u",
        ) else {
            panic!()
        };
        assert!(s.allowed);
        assert_eq!(
            (s.user.as_str(), s.target_user.as_str(), s.command.as_str()),
            ("alice", "root", "/usr/bin/id -u")
        );
        assert_eq!(s.cwd.as_deref(), Some("/home/alice"));
        let Some(Body::Sudo(d)) = parse(
            "sudo",
            "bob : command not allowed ; TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/sh",
        ) else {
            panic!()
        };
        assert!(!d.allowed);
        assert!(parse("sudo", "pam_unix(sudo:session): session opened").is_none());
    }

    #[test]
    fn sudo_messages_with_leading_padding_and_no_tty() {
        // Verbatim from journald on Ubuntu 22.04.
        let Some(Body::Sudo(s)) = parse(
            "sudo",
            "    root : PWD=/Users/x/Witness ; USER=root ; COMMAND=/usr/bin/id -u",
        ) else {
            panic!()
        };
        assert!(s.allowed && s.tty.is_none() && s.command == "/usr/bin/id -u");
    }

    #[test]
    fn su_ok_and_failed() {
        let Some(Body::Su(s)) = parse("su", "(to root) alice on pts/0") else {
            panic!()
        };
        assert!(s.allowed && s.target_user == "root" && s.tty.as_deref() == Some("pts/0"));
        let Some(Body::Su(f)) = parse("su", "FAILED SU (to root) alice on pts/0") else {
            panic!()
        };
        assert!(!f.allowed);
    }
}
