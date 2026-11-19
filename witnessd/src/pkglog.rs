//! Parses `/var/log/dpkg.log` lines into package changes (DESIGN.md §2.4).

use witness_common::schema::{Body, PackageChange};

/// `2026-11-18 10:00:01 install foo:arm64 <none> 1.0-1` and the `upgrade`/`remove`/`purge`
/// variants. Status and trigger lines are ignored.
pub fn parse_dpkg(line: &str) -> Option<Body> {
    let mut f = line.split_whitespace();
    let (_date, _time, action, name, old, new) = (
        f.next()?,
        f.next()?,
        f.next()?,
        f.next()?,
        f.next()?,
        f.next()?,
    );
    let action = match action {
        "install" | "upgrade" | "remove" | "purge" => action,
        _ => return None,
    };
    let none = |v: &str| (v != "<none>").then(|| v.to_string());
    let (old_version, version) = match action {
        "install" | "upgrade" => (none(old), none(new)),
        // For removals the columns are the installed version and the same again.
        _ => (None, none(old)),
    };
    Some(Body::PackageChange(PackageChange {
        manager: "dpkg".into(),
        action: action.into(),
        name: name.split(':').next()?.into(),
        version,
        old_version,
    }))
}

/// Splits an RPM NEVRA-ish string `name-[epoch:]version-release.arch` into `(name, version)`.
/// The name may itself contain dashes, so split from the right.
fn split_nevra(s: &str) -> Option<(String, String)> {
    let s = s.trim();
    let (rest, _arch) = s.rsplit_once('.')?;
    let (rest, release) = rest.rsplit_once('-')?;
    let (name, version) = rest.rsplit_once('-')?;
    (!name.is_empty()).then(|| (name.to_string(), format!("{version}-{release}")))
}

/// RPM's `rpmvercmp` for one version or release string: alternating digit and letter runs,
/// digits compare numerically (more digits wins after leading zeros), a digit run beats a
/// letter run, `~` sorts before everything (even the end), `^` just after the end.
pub fn rpmvercmp(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering::*;
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0, 0);
    let skip = |s: &[u8], mut k: usize| {
        while k < s.len() && !s[k].is_ascii_alphanumeric() && s[k] != b'~' && s[k] != b'^' {
            k += 1;
        }
        k
    };
    loop {
        i = skip(a, i);
        j = skip(b, j);
        // Tilde: sorts before anything, even the end of the string.
        match (a.get(i) == Some(&b'~'), b.get(j) == Some(&b'~')) {
            (true, true) => {
                i += 1;
                j += 1;
                continue;
            }
            (true, false) => return Less,
            (false, true) => return Greater,
            _ => {}
        }
        // Caret: sorts after the end of the string but before anything else.
        match (a.get(i) == Some(&b'^'), b.get(j) == Some(&b'^')) {
            (true, true) => {
                i += 1;
                j += 1;
                continue;
            }
            (true, false) => return if j >= b.len() { Greater } else { Less },
            (false, true) => return if i >= a.len() { Less } else { Greater },
            _ => {}
        }
        if i >= a.len() || j >= b.len() {
            break;
        }
        let numeric = a[i].is_ascii_digit();
        let run = |s: &[u8], k: usize| {
            let mut e = k;
            while e < s.len()
                && if numeric {
                    s[e].is_ascii_digit()
                } else {
                    s[e].is_ascii_alphabetic()
                }
            {
                e += 1;
            }
            e
        };
        let (ei, ej) = (run(a, i), run(b, j));
        let (sa, sb) = (&a[i..ei], &b[j..ej]);
        if sb.is_empty() {
            // The other side has the other kind of run here: a number beats letters.
            return if numeric { Greater } else { Less };
        }
        let ord = if numeric {
            let (ta, tb) = (
                std::str::from_utf8(sa)
                    .unwrap_or("")
                    .trim_start_matches('0'),
                std::str::from_utf8(sb)
                    .unwrap_or("")
                    .trim_start_matches('0'),
            );
            ta.len().cmp(&tb.len()).then_with(|| ta.cmp(tb))
        } else {
            sa.cmp(sb)
        };
        if ord != Equal {
            return ord;
        }
        i = ei;
        j = ej;
    }
    match (i >= a.len(), j >= b.len()) {
        (true, true) => Equal,
        (true, false) => Less,
        (false, true) => Greater,
        _ => Equal,
    }
}

/// Compares `[epoch:]version-release` strings the way rpm does.
pub fn rpm_evr_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let split = |s: &str| {
        let (e, rest) = s.split_once(':').unwrap_or(("0", s));
        let (v, r) = rest.rsplit_once('-').unwrap_or((rest, ""));
        (e.parse::<u64>().unwrap_or(0), v.to_string(), r.to_string())
    };
    let ((ea, va, ra), (eb, vb, rb)) = (split(a), split(b));
    ea.cmp(&eb)
        .then_with(|| rpmvercmp(&va, &vb))
        .then_with(|| rpmvercmp(&ra, &rb))
}

/// Reads dnf5's `/var/log/dnf5.log` (Fedora 41 and later). Real lines look like
/// `2026-11-19T17:59:43+0000 [5285] INFO RPM callback install stop "nmap-ncat-4:7.92-12.fc45.aarch64" amount 1 total 1`.
/// A transaction is collected between its callbacks and reported at `transaction stop`: a
/// package with only an install is an install, only an uninstall a removal, and both (the new
/// version installed and the old removed) an upgrade, a downgrade or a reinstall by comparing
/// the two versions. Verified against logs written by dnf5 on Fedora 45.
#[derive(Default)]
pub struct Dnf5Parser {
    installed: Vec<(String, String)>,
    removed: Vec<(String, String)>,
    /// When the last package callback arrived, for the idle flush.
    last: Option<std::time::Instant>,
}

/// A transaction with no callback for this long is finished. (dnf5 writes `transaction stop`
/// *before* the uninstall callbacks of a removal, so that line alone cannot end one.)
const DNF5_IDLE: std::time::Duration = std::time::Duration::from_secs(2);

impl Dnf5Parser {
    pub fn feed(&mut self, line: &str) -> Vec<Body> {
        self.feed_at(line, std::time::Instant::now())
    }

    /// Reports a transaction that has gone quiet. Call periodically, also when there are no
    /// new lines.
    pub fn idle(&mut self) -> Vec<Body> {
        self.idle_at(std::time::Instant::now())
    }

    pub fn idle_at(&mut self, now: std::time::Instant) -> Vec<Body> {
        match self.last {
            Some(t) if now.duration_since(t) >= DNF5_IDLE => self.flush(),
            _ => Vec::new(),
        }
    }

    pub fn feed_at(&mut self, line: &str, now: std::time::Instant) -> Vec<Body> {
        let Some((_, msg)) = line.split_once(" INFO RPM callback ") else {
            return Vec::new();
        };
        let quoted = |m: &str| {
            let a = m.find('"')? + 1;
            let b = m[a..].find('"')? + a;
            split_nevra(&m[a..b])
        };
        if msg.starts_with("install stop ") {
            self.installed.extend(quoted(msg));
            self.last = Some(now);
        } else if msg.starts_with("uninstall stop ") {
            self.removed.extend(quoted(msg));
            self.last = Some(now);
        }
        // A transaction is reported when it goes quiet (`idle`), because `transaction stop` is
        // not at the end of a removal.
        Vec::new()
    }

    fn flush(&mut self) -> Vec<Body> {
        let mut out = Vec::new();
        let mut names: Vec<&String> = self
            .installed
            .iter()
            .chain(self.removed.iter())
            .map(|(n, _)| n)
            .collect();
        names.sort();
        names.dedup();
        for name in names {
            let new = self
                .installed
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.clone());
            let old = self
                .removed
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.clone());
            let (action, version, old_version) = match (new, old) {
                (Some(n), Some(o)) => match rpm_evr_cmp(&n, &o) {
                    std::cmp::Ordering::Equal => ("reinstall", Some(n), None),
                    std::cmp::Ordering::Greater => ("upgrade", Some(n), Some(o)),
                    std::cmp::Ordering::Less => ("downgrade", Some(n), Some(o)),
                },
                (Some(n), None) => ("install", Some(n), None),
                (None, Some(o)) => ("remove", Some(o), None),
                (None, None) => continue,
            };
            out.push(Body::PackageChange(PackageChange {
                manager: "dnf".into(),
                action: action.into(),
                name: name.clone(),
                version,
                old_version,
            }));
        }
        self.installed.clear();
        self.removed.clear();
        self.last = None;
        out
    }
}

/// One line of dnf's `dnf.rpm.log` (`2024-03-12T10:21:45Z SUBDEBUG Installed: nginx-1:1.24.0-1.fc39.x86_64`).
///
/// **Not verified against a real Fedora/RHEL system** (none was available): the format is taken
/// from dnf 4 documentation and sample logs. `Upgrade:`/`Erase:` rows are the transaction
/// actions; `Upgraded:`/`Cleanup:` (the old package) are ignored so a change is reported once.
pub fn parse_dnf(line: &str) -> Option<Body> {
    let (_, rest) = line.split_once(" SUBDEBUG ")?;
    let (verb, pkg) = rest.split_once(": ")?;
    let action = match verb {
        "Installed" => "install",
        "Upgrade" => "upgrade",
        "Erase" => "remove",
        _ => return None,
    };
    let (name, version) = split_nevra(pkg)?;
    Some(Body::PackageChange(PackageChange {
        manager: "dnf".into(),
        action: action.into(),
        name,
        version: Some(version),
        old_version: None,
    }))
}

#[cfg(test)]
mod dnf5_tests {
    use std::cmp::Ordering::*;

    use super::*;

    // Lines copied from /var/log/dnf5.log on Fedora 45 (kernel 7.2.11).
    const INST: &str = "2026-11-19T17:59:43+0000 [5285] INFO RPM callback install stop \"nmap-ncat-4:7.92-12.fc45.aarch64\" amount 529712 total 529712";
    const UNINST: &str = "2026-11-19T17:59:54+0000 [5383] INFO RPM callback uninstall stop \"nmap-ncat-4:7.92-12.fc45.aarch64\" amount 28 total 28";
    const TX: &str = "2026-11-19T17:59:43+0000 [5285] INFO RPM callback transaction stop";

    /// Feeds the lines, then lets the transaction go quiet.
    fn changes(lines: &[&str]) -> Vec<(String, String, Option<String>, Option<String>)> {
        let t0 = std::time::Instant::now();
        let mut p = Dnf5Parser::default();
        let mut out: Vec<Body> = lines.iter().flat_map(|l| p.feed_at(l, t0)).collect();
        out.extend(p.idle_at(t0 + std::time::Duration::from_secs(3)));
        out.into_iter()
            .map(|b| match b {
                Body::PackageChange(c) => (c.action, c.name, c.version, c.old_version),
                _ => panic!(),
            })
            .collect()
    }

    #[test]
    fn install_remove_and_reinstall_from_real_dnf5_lines() {
        let i = changes(&[INST, TX]);
        assert_eq!(
            i,
            [(
                "install".into(),
                "nmap-ncat".into(),
                Some("4:7.92-12.fc45".into()),
                None
            )]
        );
        let r = changes(&[UNINST, TX]);
        assert_eq!(r[0].0, "remove");
        // Same version installed and removed in one transaction is a reinstall.
        assert_eq!(changes(&[UNINST, INST, TX])[0].0, "reinstall");
        // Nothing is reported while the transaction is still active, and a bare callback is ignored.
        let mut p = Dnf5Parser::default();
        let t0 = std::time::Instant::now();
        assert!(p.feed_at(INST, t0).is_empty());
        assert!(p
            .idle_at(t0 + std::time::Duration::from_millis(500))
            .is_empty());
        assert_eq!(p.idle_at(t0 + std::time::Duration::from_secs(3)).len(), 1);
        assert!(
            p.idle_at(t0 + std::time::Duration::from_secs(9)).is_empty(),
            "reported once"
        );
        assert!(changes(&[
            "2026-11-19T17:59:43+0000 [5285] INFO RPM callback open file \"/x.rpm\""
        ])
        .is_empty());
        assert!(changes(&["garbage", ""]).is_empty());
    }

    #[test]
    fn a_removal_is_reported_although_transaction_stop_comes_first() {
        // The order dnf5 really writes for `dnf remove hello` (Fedora 45).
        let lines = [
            "2026-11-19T18:42:33+0000 [51951] INFO RPM callback transaction start, total 2",
            "2026-11-19T18:42:33+0000 [51951] INFO RPM callback transaction stop, total 2",
            "2026-11-19T18:42:33+0000 [51951] INFO RPM callback uninstall start \"info-0:7.3-3.fc45.aarch64\" total 16",
            "2026-11-19T18:42:33+0000 [51951] INFO RPM callback uninstall stop \"info-0:7.3-3.fc45.aarch64\" amount 16 total 16",
            "2026-11-19T18:42:33+0000 [51951] INFO RPM callback uninstall stop \"hello-0:2.12.3-2.fc45.aarch64\" amount 54 total 54",
        ];
        let r = changes(&lines);
        assert_eq!(
            r.iter()
                .map(|c| (c.0.as_str(), c.1.as_str()))
                .collect::<Vec<_>>(),
            [("remove", "hello"), ("remove", "info")]
        );
    }

    #[test]
    fn upgrade_and_downgrade_are_told_apart_by_version() {
        let old = "2026-01-01T00:00:00+0000 [9] INFO RPM callback uninstall stop \"curl-0:8.5.0-1.fc45.aarch64\" amount 1 total 1";
        let new = "2026-01-01T00:00:00+0000 [9] INFO RPM callback install stop \"curl-0:8.10.1-2.fc45.aarch64\" amount 1 total 1";
        let up = changes(&[old, new, TX]);
        assert_eq!(up[0].0, "upgrade");
        assert_eq!(up[0].3.as_deref(), Some("0:8.5.0-1.fc45"));
        assert_eq!(
            changes(&[
                new.replace("install", "uninstall").as_str(),
                old.replace("uninstall", "install").as_str(),
                TX
            ])[0]
                .0,
            "downgrade"
        );
        // Several packages in one transaction come out together, in name order.
        let two = changes(&[INST, new, TX]);
        assert_eq!(
            two.iter().map(|c| c.1.as_str()).collect::<Vec<_>>(),
            ["curl", "nmap-ncat"]
        );
    }

    #[test]
    fn rpm_version_comparison_follows_rpmvercmp() {
        assert_eq!(rpmvercmp("1.0", "1.0"), Equal);
        assert_eq!(rpmvercmp("1.10", "1.9"), Greater, "numeric, not text");
        assert_eq!(rpmvercmp("1.0a", "1.0"), Greater);
        assert_eq!(rpmvercmp("1.0", "1.0a"), Less);
        assert_eq!(
            rpmvercmp("1.0~rc1", "1.0"),
            Less,
            "tilde sorts before the release"
        );
        assert_eq!(
            rpmvercmp("1.0^git1", "1.0"),
            Greater,
            "caret sorts after the base"
        );
        assert_eq!(rpmvercmp("1.0^git1", "1.0.1"), Less);
        assert_eq!(rpmvercmp("2a", "2.0"), Less, "letters sort before numbers");
        assert_eq!(rpmvercmp("a", "1"), Less);
        assert_eq!(rpmvercmp("010", "10"), Equal, "leading zeros are ignored");
        assert_eq!(rpm_evr_cmp("1:1.0-1", "2.0-1"), Greater, "epoch wins");
        assert_eq!(rpm_evr_cmp("1.0-2.fc45", "1.0-10.fc45"), Less);
        assert_eq!(
            rpm_evr_cmp("0:1.0-1", "1.0-1"),
            Equal,
            "a missing epoch is 0"
        );
    }
}

#[cfg(test)]
mod dnf_tests {
    use super::*;

    #[test]
    fn dnf_lines_become_package_changes() {
        let Some(Body::PackageChange(i)) =
            parse_dnf("2024-03-12T10:21:45Z SUBDEBUG Installed: nginx-1:1.24.0-1.fc39.x86_64")
        else {
            panic!()
        };
        assert_eq!(
            (i.manager.as_str(), i.action.as_str(), i.name.as_str()),
            ("dnf", "install", "nginx")
        );
        assert_eq!(i.version.as_deref(), Some("1:1.24.0-1.fc39"));
        let Some(Body::PackageChange(u)) =
            parse_dnf("2024-03-12T10:22:00Z SUBDEBUG Upgrade: python3-libs-3.12.1-2.fc39.x86_64")
        else {
            panic!()
        };
        assert_eq!(
            (u.name.as_str(), u.action.as_str()),
            ("python3-libs", "upgrade")
        );
        assert!(matches!(
            parse_dnf("2024-03-12T10:22:30Z SUBDEBUG Erase: foo-1.0-1.fc39.noarch"),
            Some(Body::PackageChange(p)) if p.action == "remove"
        ));
        // The old half of an upgrade and unrelated lines are ignored.
        assert!(parse_dnf(
            "2024-03-12T10:22:00Z SUBDEBUG Upgraded: python3-libs-3.11-1.fc39.x86_64"
        )
        .is_none());
        assert!(parse_dnf("2024-03-12T10:22:00Z INFO --- logging initialized ---").is_none());
        assert!(parse_dnf("garbage").is_none());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_upgrade_remove() {
        let Some(Body::PackageChange(i)) =
            parse_dpkg("2026-11-18 10:00:01 install nginx:arm64 <none> 1.18.0-6")
        else {
            panic!()
        };
        assert_eq!(
            (
                i.name.as_str(),
                i.version.as_deref(),
                i.old_version.as_deref()
            ),
            ("nginx", Some("1.18.0-6"), None)
        );
        let Some(Body::PackageChange(u)) =
            parse_dpkg("2026-11-18 10:00:02 upgrade nginx:arm64 1.18.0-6 1.18.0-7")
        else {
            panic!()
        };
        assert_eq!(u.old_version.as_deref(), Some("1.18.0-6"));
        assert_eq!(u.version.as_deref(), Some("1.18.0-7"));
        let Some(Body::PackageChange(r)) =
            parse_dpkg("2026-11-18 10:00:03 remove nginx:arm64 1.18.0-7 1.18.0-7")
        else {
            panic!()
        };
        assert_eq!(r.action, "remove");
        assert!(parse_dpkg("2026-11-18 10:00:03 status installed nginx:arm64 1.18.0-7").is_none());
        assert!(parse_dpkg("garbage").is_none());
    }
}
