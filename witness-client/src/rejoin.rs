//! Use the `witness` group right after being added to it, without logging out and in.
//!
//! Group membership is read once at login, so a user the package just added to `witness`
//! still gets "permission denied" on the API socket until the next login. `sg` starts a
//! command with a group the user is listed in, no password needed, so the CLI and GUI
//! re-run themselves through it once.

use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

const GROUP: &str = "witness";
/// Set on the re-run so a failed `sg` can never loop.
const GUARD: &str = "WITNESS_REEXEC";

/// True when `uid`'s user is listed in group `witness` in `/etc/group` but the process
/// (`status` = `/proc/self/status`) does not carry that group yet.
fn needs_rejoin(group_db: &str, passwd_db: &str, status: &str, uid: u32) -> bool {
    let Some(user) = user_name(passwd_db, uid) else {
        return false;
    };
    let Some((gid, members)) = group_db.lines().find_map(|l| {
        let mut f = l.split(':');
        (f.next()? == GROUP).then_some(())?;
        let gid: u32 = f.nth(1)?.parse().ok()?;
        Some((gid, f.next().unwrap_or("")))
    }) else {
        return false;
    };
    if !members.split(',').any(|m| m == user) {
        return false;
    }
    let carried = status
        .lines()
        .find_map(|l| l.strip_prefix("Groups:"))
        .map(|g| {
            g.split_whitespace()
                .filter_map(|x| x.parse::<u32>().ok())
                .any(|x| x == gid)
        });
    carried == Some(false)
}

fn user_name(passwd_db: &str, uid: u32) -> Option<&str> {
    passwd_db.lines().find_map(|l| {
        let mut f = l.split(':');
        let name = f.next()?;
        let id: u32 = f.nth(1)?.parse().ok()?;
        (id == uid).then_some(name)
    })
}

fn real_uid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// Name of the user running this process (real uid looked up in `/etc/passwd`).
pub fn current_user() -> Option<String> {
    let uid = real_uid(&std::fs::read_to_string("/proc/self/status").ok()?)?;
    user_name(&std::fs::read_to_string("/etc/passwd").ok()?, uid).map(str::to_owned)
}

/// Ask the desktop for an administrator's password (polkit) to put this user in the
/// `witness` group, then re-run through `sg` so it takes effect at once. Returns only on
/// failure, with a message to show; on success the process is replaced.
pub fn grant_access(socket: &Path) -> String {
    let Some(user) = current_user() else {
        return "could not tell which user this is".into();
    };
    match Command::new("pkexec")
        .args(["/usr/sbin/usermod", "-aG", GROUP, &user])
        .status()
    {
        Ok(s) if s.success() => {
            rejoin_group_if_needed(socket);
            "Access was granted, but the window could not restart itself: close it and open Witness again.".into()
        }
        Ok(s) if s.code() == Some(126) || s.code() == Some(127) => {
            "The password prompt was cancelled or not allowed.".into()
        }
        Ok(s) => format!("Granting access failed ({s})."),
        Err(e) => {
            format!("Could not ask for permission ({e}). Run:  sudo usermod -aG {GROUP} {user}")
        }
    }
}

/// Single-quote one argument for `sh -c`.
fn quote(a: &str) -> String {
    format!("'{}'", a.replace('\'', r"'\''"))
}

/// If the socket refuses this process only because its login predates the group change,
/// replace the process with itself running under `sg witness`. Returns (does nothing)
/// in every other case, including when `sg` is unavailable.
pub fn rejoin_group_if_needed(socket: &Path) {
    if std::env::var_os(GUARD).is_some() {
        return;
    }
    match UnixStream::connect(socket) {
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {}
        _ => return,
    }
    let (Ok(status), Ok(group_db), Ok(passwd_db)) = (
        std::fs::read_to_string("/proc/self/status"),
        std::fs::read_to_string("/etc/group"),
        std::fs::read_to_string("/etc/passwd"),
    ) else {
        return;
    };
    let Some(uid) = real_uid(&status) else { return };
    if !needs_rejoin(&group_db, &passwd_db, &status, uid) {
        return;
    }
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let line = std::iter::once(exe.to_string_lossy().into_owned())
        .chain(std::env::args().skip(1))
        .map(|a| quote(&a))
        .collect::<Vec<_>>()
        .join(" ");
    // exec only returns on failure; then the caller shows its normal hint.
    let _ = Command::new("sg")
        .args([GROUP, "-c", &line])
        .env(GUARD, "1")
        .exec();
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWD: &str = "root:x:0:0::/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/bash\n";
    const GROUP_DB: &str = "adm:x:4:\nwitness:x:990:bob,alice\n";
    const STATUS_NO: &str = "Name:\tx\nUid:\t1000\t1000\t1000\t1000\nGroups:\t4 24 1000\n";
    const STATUS_YES: &str = "Uid:\t1000\t1000\t1000\t1000\nGroups:\t4 990 1000\n";

    #[test]
    fn listed_but_not_carried_needs_rejoin() {
        assert_eq!(real_uid(STATUS_NO), Some(1000));
        assert!(needs_rejoin(GROUP_DB, PASSWD, STATUS_NO, 1000));
    }

    #[test]
    fn already_carried_or_not_listed_does_not() {
        assert!(!needs_rejoin(GROUP_DB, PASSWD, STATUS_YES, 1000));
        assert!(!needs_rejoin(
            "witness:x:990:bob\n",
            PASSWD,
            STATUS_NO,
            1000
        ));
        assert!(!needs_rejoin("adm:x:4:alice\n", PASSWD, STATUS_NO, 1000));
        assert!(!needs_rejoin(GROUP_DB, PASSWD, STATUS_NO, 4242));
        // A prefix of a member name is not the member.
        assert!(!needs_rejoin(
            "witness:x:990:alice2\n",
            PASSWD,
            STATUS_NO,
            1000
        ));
    }

    #[test]
    fn arguments_are_quoted_for_the_shell() {
        assert_eq!(quote("a b"), "'a b'");
        assert_eq!(quote("it's"), r"'it'\''s'");
        assert_eq!(quote("$(x);"), "'$(x);'");
    }
}
