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
