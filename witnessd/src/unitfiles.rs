//! Derives systemd unit enable/disable/mask changes from file events (DESIGN.md §2.4).
//!
//! `systemctl enable` creates a symlink `/etc/systemd/system/<target>.wants/<unit>`, `disable`
//! removes it, and `mask` links `/etc/systemd/system/<unit>` to `/dev/null`. The daemon already
//! sees those file operations (with the actor), so no D-Bus connection is needed. Only changes
//! under `/etc/systemd/system` are covered.

use std::collections::HashSet;

use witness_common::schema::{Body, Event, LinkKind, ServiceAction, ServiceChange, Source};

const ROOT: &str = "/etc/systemd/system/";
const SUFFIXES: [&str; 5] = [".service", ".timer", ".socket", ".path", ".target"];

fn unit_name(file: &str) -> Option<&str> {
    SUFFIXES.iter().any(|s| file.ends_with(s)).then_some(file)
}

/// `(directory name, unit)` for a path directly inside a `*.wants` / `*.requires` directory.
fn in_wants(path: &str) -> Option<&str> {
    let rest = path.strip_prefix(ROOT)?;
    let (dir, unit) = rest.split_once('/')?;
    if unit.contains('/') || !(dir.ends_with(".wants") || dir.ends_with(".requires")) {
        return None;
    }
    unit_name(unit)
}

/// The unit for a path directly inside `/etc/systemd/system` (where masks live).
fn top_level(path: &str) -> Option<&str> {
    let rest = path.strip_prefix(ROOT)?;
    (!rest.contains('/')).then_some(rest).and_then(unit_name)
}

/// The change implied by `ev`, as a new event with the same actor and time, or `None`.
/// `masked` remembers units seen masked, so removing the link can be reported as an unmask.
pub fn derive(ev: &Event, masked: &mut HashSet<String>) -> Option<Event> {
    let (unit, action) = match &ev.body {
        Body::FileLink(l) if l.kind == LinkKind::Symbolic => {
            let path = std::str::from_utf8(&l.path.0).ok()?;
            let target = std::str::from_utf8(&l.target.0).ok()?;
            if let Some(u) = in_wants(path) {
                (u.to_string(), ServiceAction::Enable)
            } else if let (Some(u), "/dev/null") = (top_level(path), target) {
                masked.insert(u.to_string());
                (u.to_string(), ServiceAction::Mask)
            } else {
                return None;
            }
        }
        Body::FileDelete(d) => {
            let path = std::str::from_utf8(&d.path.0).ok()?;
            if let Some(u) = in_wants(path) {
                (u.to_string(), ServiceAction::Disable)
            } else {
                let u = top_level(path).filter(|u| masked.remove(*u))?;
                (u.to_string(), ServiceAction::Unmask)
            }
        }
        _ => return None,
    };
    let body = Body::ServiceChange(ServiceChange {
        unit,
        action,
        result: None,
        job_id: None,
    });
    Some(Event {
        src: Source::Daemon,
        prio: body.priority() as u8,
        body,
        seq: 0,
        h: None,
        ..ev.clone()
    })
}

#[cfg(test)]
mod tests {
    use witness_common::schema::{FileLink, FileOp, HookResult, OsBytes};

    use super::*;

    fn base(body: Body) -> Event {
        Event {
            v: 1,
            seq: 9,
            boot_id: "b".into(),
            boot_ns: 5,
            wall_ns: 7,
            wall_uncertain: false,
            src: Source::Ebpf,
            prio: 1,
            actor: None,
            body,
            h: None,
        }
    }

    fn link(path: &str, target: &str) -> Event {
        base(Body::FileLink(FileLink {
            kind: LinkKind::Symbolic,
            path: OsBytes(path.as_bytes().to_vec()),
            target: OsBytes(target.as_bytes().to_vec()),
            result: HookResult::Attempted,
        }))
    }

    fn delete(path: &str) -> Event {
        base(Body::FileDelete(FileOp {
            path: OsBytes(path.as_bytes().to_vec()),
            path_resolved: true,
            path_truncated: false,
            dev: 0,
            ino: 0,
            mode: None,
            flags: None,
            result: HookResult::Attempted,
        }))
    }

    fn change(e: Option<Event>) -> Option<(String, ServiceAction)> {
        match e?.body {
            Body::ServiceChange(c) => Some((c.unit, c.action)),
            _ => None,
        }
    }

    #[test]
    fn enable_disable_mask_unmask_are_derived_from_symlinks() {
        let mut masked = HashSet::new();
        let en = derive(
            &link(
                "/etc/systemd/system/multi-user.target.wants/foo.service",
                "/etc/systemd/system/foo.service",
            ),
            &mut masked,
        );
        assert_eq!(
            change(en.clone()),
            Some(("foo.service".into(), ServiceAction::Enable))
        );
        // The derived event keeps the original's time and actor, and is a daemon record.
        let en = en.unwrap();
        assert_eq!((en.boot_ns, en.wall_ns, en.seq), (5, 7, 0));
        assert_eq!(en.src, Source::Daemon);
        assert_eq!(
            change(derive(
                &delete("/etc/systemd/system/multi-user.target.wants/foo.service"),
                &mut masked
            )),
            Some(("foo.service".into(), ServiceAction::Disable))
        );
        assert_eq!(
            change(derive(
                &link("/etc/systemd/system/bar.service", "/dev/null"),
                &mut masked
            )),
            Some(("bar.service".into(), ServiceAction::Mask))
        );
        assert_eq!(
            change(derive(
                &delete("/etc/systemd/system/bar.service"),
                &mut masked
            )),
            Some(("bar.service".into(), ServiceAction::Unmask))
        );
    }

    #[test]
    fn unrelated_files_and_unknown_deletions_are_ignored() {
        let mut masked = HashSet::new();
        assert!(derive(&link("/etc/other/x.service", "/dev/null"), &mut masked).is_none());
        assert!(derive(
            &link("/etc/systemd/system/x.conf", "/dev/null"),
            &mut masked
        )
        .is_none());
        assert!(derive(
            &link("/etc/systemd/system/a.wants/not-a-unit", "/x"),
            &mut masked
        )
        .is_none());
        // Deleting a plain unit file we never saw masked is not an unmask.
        assert!(derive(&delete("/etc/systemd/system/baz.service"), &mut masked).is_none());
        // Nested paths are not unit links.
        assert!(derive(
            &delete("/etc/systemd/system/a.wants/sub/x.service"),
            &mut masked
        )
        .is_none());
        // A hard link is not an enable.
        let mut hard = link("/etc/systemd/system/a.wants/x.service", "/x");
        if let Body::FileLink(l) = &mut hard.body {
            l.kind = LinkKind::Hard;
        }
        assert!(derive(&hard, &mut masked).is_none());
    }
}
