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
