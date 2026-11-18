//! Parses sshd / sudo / su log messages into schema bodies (DESIGN.md §2.4).
//!
//! These are free-text messages and differ across versions, so every body keeps the raw line.
//! A message that matches nothing returns `None` and is simply not turned into an event.

use std::net::IpAddr;

use witness_common::schema::{AuthFail, Body, Login, Sudo};

/// `ident` is the syslog identifier of the emitter (`sshd`, `sudo`, `su`, `login`).
pub fn parse(ident: &str, msg: &str) -> Option<Body> {
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
