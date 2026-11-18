//! Account and SSH-key change detection by diffing snapshots (DESIGN.md §2.4).
//!
//! Password hashes are never stored: only a SHA-256 of the shadow password field, so a change
//! is provable without revealing the hash.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use witness_common::schema::{AccountChange, Body, ChangeKind, KeyChange, OsBytes};

/// One `/etc/passwd` or `/etc/group` entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub id: u32,
    pub home: Option<String>,
    pub shell: Option<String>,
}

/// Snapshot of users, groups and password-field digests.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Accounts {
    pub users: BTreeMap<String, Entry>,
    pub groups: BTreeMap<String, Entry>,
    /// user → SHA-256 (hex) of the shadow password field.
    pub shadow: BTreeMap<String, String>,
}

pub fn parse_passwd(text: &str) -> BTreeMap<String, Entry> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() < 7 || l.starts_with('#') {
                return None;
            }
            Some((
                f[0].to_string(),
                Entry {
                    id: f[2].parse().ok()?,
                    home: Some(f[5].to_string()),
                    shell: Some(f[6].to_string()),
                },
            ))
        })
        .collect()
}

pub fn parse_group(text: &str) -> BTreeMap<String, Entry> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() < 3 || l.starts_with('#') {
                return None;
            }
            Some((
                f[0].to_string(),
                Entry {
                    id: f[2].parse().ok()?,
                    home: None,
                    shell: None,
                },
            ))
        })
        .collect()
}

pub fn parse_shadow(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|l| {
            let mut f = l.split(':');
            let (name, pw) = (f.next()?, f.next()?);
            (!name.is_empty() && !l.starts_with('#'))
                .then(|| (name.to_string(), hex(&Sha256::digest(pw.as_bytes()))))
        })
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Events describing how `new` differs from `old`.
pub fn diff(old: &Accounts, new: &Accounts) -> Vec<Body> {
    let mut out = Vec::new();
    for (kind, o, n) in [
        ("user", &old.users, &new.users),
        ("group", &old.groups, &new.groups),
    ] {
        for (name, e) in n {
            let change = match o.get(name) {
                None => ChangeKind::Created,
                Some(prev) if prev != e => ChangeKind::Modified,
                Some(_) => continue,
            };
            out.push(Body::AccountChange(AccountChange {
                kind: kind.into(),
                change,
                name: name.clone(),
                id: Some(e.id),
                shell: e.shell.clone(),
                home: e.home.clone(),
                password_changed: false,
                password_field_sha256: None,
            }));
        }
        for (name, e) in o {
            if !n.contains_key(name) {
                out.push(Body::AccountChange(AccountChange {
                    kind: kind.into(),
                    change: ChangeKind::Deleted,
                    name: name.clone(),
                    id: Some(e.id),
                    shell: e.shell.clone(),
                    home: e.home.clone(),
                    password_changed: false,
                    password_field_sha256: None,
                }));
            }
        }
    }
    for (name, digest) in &new.shadow {
        if old.shadow.get(name).is_some_and(|d| d != digest) {
            out.push(Body::AccountChange(AccountChange {
                kind: "user".into(),
                change: ChangeKind::Modified,
                name: name.clone(),
                id: new.users.get(name).map(|e| e.id),
                shell: None,
                home: None,
                password_changed: true,
                password_field_sha256: Some(digest.clone()),
            }));
        }
    }
    out
}

// ---- authorized_keys ------------------------------------------------------------------

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for c in s.bytes().take_while(|&c| c != b'=') {
        acc = (acc << 6) | B64.iter().position(|&x| x == c)? as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn b64_encode_unpadded(b: &[u8]) -> String {
    let mut out = String::new();
    for chunk in b.chunks(3) {
        let n = chunk.iter().fold(0u32, |a, &x| (a << 8) | x as u32) << (8 * (3 - chunk.len()));
        for i in 0..=chunk.len() {
            out.push(B64[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

/// One authorized key: type, OpenSSH-style fingerprint, digest of any options.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key {
    pub key_type: String,
    pub fingerprint: String,
    pub options_sha256: Option<String>,
}

const KEY_TYPES: [&str; 8] = [
    "ssh-rsa",
    "ssh-ed25519",
    "ssh-dss",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

/// Splits off a leading options field (which may contain quoted spaces).
fn split_options(line: &str) -> (Option<&str>, &str) {
    let first = line.split_whitespace().next().unwrap_or("");
    if KEY_TYPES.contains(&first) {
        return (None, line);
    }
    let mut quoted = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => return (Some(&line[..i]), line[i..].trim_start()),
            _ => {}
        }
    }
    (None, line)
}

pub fn parse_authorized_keys(text: &str) -> Vec<Key> {
    let mut keys: Vec<Key> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let (options, rest) = split_options(l);
            let mut f = rest.split_whitespace();
            let (kt, blob) = (f.next()?, f.next()?);
            let raw = b64_decode(blob)?;
            Some(Key {
                key_type: kt.into(),
                fingerprint: format!("SHA256:{}", b64_encode_unpadded(&Sha256::digest(&raw))),
                options_sha256: options.map(|o| hex(&Sha256::digest(o.as_bytes()))),
            })
        })
        .collect();
    keys.sort();
    keys
}

/// Key additions and removals between two versions of one user's file.
pub fn diff_keys(user: &str, path: &[u8], old: &[Key], new: &[Key]) -> Vec<Body> {
    let mk = |k: &Key, change| {
        Body::AuthorizedKeyChange(KeyChange {
            user: user.into(),
            path: OsBytes(path.to_vec()),
            change,
            key_type: k.key_type.clone(),
            fingerprint: k.fingerprint.clone(),
            options_sha256: k.options_sha256.clone(),
        })
    };
    let mut out: Vec<Body> = new
        .iter()
        .filter(|k| !old.contains(k))
        .map(|k| mk(k, ChangeKind::Created))
        .collect();
    out.extend(
        old.iter()
            .filter(|k| !new.contains(k))
            .map(|k| mk(k, ChangeKind::Deleted)),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWD: &str =
        "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n";

    #[test]
    fn new_user_and_shell_change_are_reported() {
        let old = Accounts {
            users: parse_passwd(PASSWD),
            ..Default::default()
        };
        let mut new = old.clone();
        new.users.insert(
            "mallory".into(),
            Entry {
                id: 0,
                home: Some("/root".into()),
                shell: Some("/bin/sh".into()),
            },
        );
        new.users.get_mut("alice").unwrap().shell = Some("/bin/zsh".into());
        let d = diff(&old, &new);
        assert_eq!(d.len(), 2);
        let names: Vec<_> = d
            .iter()
            .map(|b| match b {
                Body::AccountChange(a) => (a.name.as_str(), a.change),
                _ => panic!(),
            })
            .collect();
        assert!(names.contains(&("mallory", ChangeKind::Created)));
        assert!(names.contains(&("alice", ChangeKind::Modified)));
    }

    #[test]
    fn password_change_reports_digest_not_hash() {
        let old = Accounts {
            shadow: parse_shadow("alice:$6$old:19000:0:99999:7:::\n"),
            ..Default::default()
        };
        let new = Accounts {
            shadow: parse_shadow("alice:$6$new:19001:0:99999:7:::\n"),
            ..Default::default()
        };
        let d = diff(&old, &new);
        let Body::AccountChange(a) = &d[0] else {
            panic!()
        };
        assert!(a.password_changed);
        let digest = a.password_field_sha256.as_deref().unwrap();
        assert_eq!(digest.len(), 64);
        assert!(!format!("{a:?}").contains("$6$new"));
        // Locking vs unchanged fields: an identical file reports nothing.
        assert!(diff(&new, &new).is_empty());
    }

    #[test]
    fn fingerprints_match_openssh() {
        // Expected value is the output of `ssh-keygen -lf` for this key.
        let line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@host";
        let k = parse_authorized_keys(line);
        assert_eq!(k.len(), 1);
        assert_eq!(k[0].key_type, "ssh-ed25519");
        assert_eq!(
            k[0].fingerprint,
            "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"
        );
    }

    #[test]
    fn options_are_digested_and_quoted_spaces_survive() {
        let line = r#"command="echo hi there",no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"#;
        let k = parse_authorized_keys(line);
        assert_eq!(k.len(), 1);
        assert!(k[0].options_sha256.is_some());
        let plain = parse_authorized_keys(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
        );
        assert_eq!(plain[0].fingerprint, k[0].fingerprint);
        let d = diff_keys("alice", b"/home/alice/.ssh/authorized_keys", &plain, &k);
        assert_eq!(d.len(), 2); // options changed: old identity removed, new one added
    }
}
