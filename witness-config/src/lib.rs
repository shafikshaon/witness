//! `/etc/witness/config.toml` (DESIGN.md §7): one file, strict parsing, every key defaulted,
//! and every problem reported at once so an admin fixes them in a single pass.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const DEFAULT_PATH: &str = "/etc/witness/config.toml";

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("syntax error: {0}")]
    Parse(String),
    #[error("invalid configuration:\n  - {}", .0.join("\n  - "))]
    Invalid(Vec<String>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OnFull {
    Shed,
    Stop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Capture {
    /// Record process environments on exec (off: environments often hold secrets).
    pub env_capture: bool,
    /// Longest argv recorded per exec before it is flagged truncated.
    pub argv_max_bytes: u32,
    /// Ring buffer sizes; the kernel requires a power of two (in MiB here).
    pub ring_critical_mib: u32,
    pub ring_volume_mib: u32,
    pub files: bool,
    pub network: bool,
    pub dns: bool,
    pub auth: bool,
    /// Listen passively to the audit multicast group if an auditd is already running.
    pub audit_passive: bool,
}

impl Default for Capture {
    fn default() -> Self {
        Capture {
            env_capture: false,
            argv_max_bytes: 65_536,
            ring_critical_mib: 8,
            ring_volume_mib: 32,
            files: true,
            network: true,
            dns: true,
            auth: true,
            audit_passive: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Files {
    /// Extra paths to watch (prefixes or globs) on top of the built-in critical set.
    pub watch: Vec<String>,
    pub exclude: Vec<String>,
    /// Extra paths hashed on change, in addition to the built-in critical set.
    pub critical_extra: Vec<String>,
    /// Paths whose *reads* are also recorded.
    pub sensitive_read: Vec<String>,
    pub hash_max_mib: u64,
    pub hash_rate_mib_per_sec: u64,
    pub hash_debounce_ms: u64,
    pub path_max_bytes: u32,
}

impl Default for Files {
    fn default() -> Self {
        Files {
            watch: Vec::new(),
            exclude: Vec::new(),
            critical_extra: Vec::new(),
            sensitive_read: vec![
                "/etc/shadow".into(),
                "/etc/gshadow".into(),
                "/etc/sudoers".into(),
            ],
            hash_max_mib: 256,
            hash_rate_mib_per_sec: 50,
            hash_debounce_ms: 2_000,
            path_max_bytes: 4_096,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Network {
    pub udp_summary_interval_secs: u64,
    /// Bytes of each DNS packet copied out of the kernel.
    pub dns_max_payload: u32,
}

impl Default for Network {
    fn default() -> Self {
        Network {
            udp_summary_interval_secs: 5,
            dns_max_payload: 512,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Storage {
    pub segment_max_mib: u64,
    pub segment_max_hours: u64,
    pub zstd_level: i32,
    pub group_commit_ms: u64,
    /// Used-space percentages that raise a warning, ascending.
    pub warn_pcts: Vec<u8>,
    /// Below this much free space the disk-full policy engages.
    pub min_free_mib: u64,
    /// Preallocated space released only to write the final records.
    pub reserve_mib: u64,
    pub on_full: OnFull,
    /// Put the SQLite index elsewhere (default: next to the segments).
    pub index_dir: Option<PathBuf>,
    pub anchor_interval_secs: u64,
    /// Program and arguments run with the anchor in `WITNESS_ANCHOR_SEQ` / `_HASH`.
    pub anchor_command: Option<Vec<String>>,
}

impl Default for Storage {
    fn default() -> Self {
        Storage {
            segment_max_mib: 256,
            segment_max_hours: 24,
            zstd_level: 3,
            group_commit_ms: 500,
            warn_pcts: vec![80, 90],
            min_free_mib: 1_024,
            reserve_mib: 256,
            on_full: OnFull::Shed,
            index_dir: None,
            anchor_interval_secs: 60,
            anchor_command: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Seal {
    /// Forward-secure sealing; needs `witness init --seal` first.
    pub enabled: bool,
    pub interval_secs: u64,
}

impl Default for Seal {
    fn default() -> Self {
        Seal {
            enabled: false,
            interval_secs: 60,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Rules {
    pub dir: PathBuf,
    /// Alerts at or above this severity trigger desktop notifications.
    pub notify_min_severity: Severity,
}

impl Default for Rules {
    fn default() -> Self {
        Rules {
            dir: "/etc/witness/rules.d".into(),
            notify_min_severity: Severity::High,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Api {
    pub socket: PathBuf,
    /// May read events and triage alerts.
    pub group: String,
    /// May also change rules (root always may).
    pub admin_group: String,
}

impl Default for Api {
    fn default() -> Self {
        Api {
            socket: "/run/witness/witness.sock".into(),
            group: "witness".into(),
            admin_group: "witness-admin".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Daemon {
    pub data_dir: PathBuf,
    pub log_level: String,
}

impl Default for Daemon {
    fn default() -> Self {
        Daemon {
            data_dir: "/var/lib/witness".into(),
            log_level: "info".into(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub capture: Capture,
    pub files: Files,
    pub network: Network,
    pub storage: Storage,
    pub seal: Seal,
    pub rules: Rules,
    pub api: Api,
    pub daemon: Daemon,
}

impl Config {
    /// Parses and validates `text`. Unknown keys and every rule violation are errors.
    pub fn parse(text: &str) -> Result<Config, ConfigError> {
        let cfg: Config = toml::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Loads a config file; a missing file at `path` is an error (use `Config::default()`
    /// explicitly to run on defaults). Returns the SHA-256 of the exact file bytes, which
    /// `config_change` and `daemon_start` records carry.
    pub fn load(path: &Path) -> Result<(Config, [u8; 32]), ConfigError> {
        let bytes = std::fs::read(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let text = String::from_utf8(bytes.clone())
            .map_err(|_| ConfigError::Parse("file is not valid UTF-8".into()))?;
        Ok((Config::parse(&text)?, Sha256::digest(&bytes).into()))
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut e: Vec<String> = Vec::new();
        let mut need = |ok: bool, msg: &str| {
            if !ok {
                e.push(msg.to_string());
            }
        };
        let c = &self.capture;
        need(
            (1_024..=1 << 20).contains(&c.argv_max_bytes),
            "capture.argv_max_bytes must be between 1024 and 1048576",
        );
        need(
            c.ring_critical_mib.is_power_of_two() && c.ring_critical_mib <= 1_024,
            "capture.ring_critical_mib must be a power of two (1..=1024): the kernel requires it",
        );
        need(
            c.ring_volume_mib.is_power_of_two() && c.ring_volume_mib <= 1_024,
            "capture.ring_volume_mib must be a power of two (1..=1024): the kernel requires it",
        );

        let f = &self.files;
        need(f.hash_max_mib >= 1, "files.hash_max_mib must be at least 1");
        need(
            f.hash_rate_mib_per_sec >= 1,
            "files.hash_rate_mib_per_sec must be at least 1",
        );
        need(
            (256..=65_536).contains(&f.path_max_bytes),
            "files.path_max_bytes must be between 256 and 65536",
        );
        for (name, list) in [
            ("files.watch", &f.watch),
            ("files.exclude", &f.exclude),
            ("files.critical_extra", &f.critical_extra),
            ("files.sensitive_read", &f.sensitive_read),
        ] {
            for p in list {
                need(
                    p.starts_with('/') && !p.contains('\0'),
                    &format!("{name}: {p:?} must be an absolute path or glob"),
                );
            }
        }

        let n = &self.network;
        need(
            n.udp_summary_interval_secs >= 1,
            "network.udp_summary_interval_secs must be at least 1",
        );
        need(
            (64..=4_096).contains(&n.dns_max_payload),
            "network.dns_max_payload must be between 64 and 4096",
        );

        let s = &self.storage;
        need(
            s.segment_max_mib >= 1,
            "storage.segment_max_mib must be at least 1",
        );
        need(
            s.segment_max_hours >= 1,
            "storage.segment_max_hours must be at least 1",
        );
        need(
            (1..=19).contains(&s.zstd_level),
            "storage.zstd_level must be between 1 and 19",
        );
        need(
            (10..=60_000).contains(&s.group_commit_ms),
            "storage.group_commit_ms must be between 10 and 60000",
        );
        need(
            s.warn_pcts.iter().all(|&p| (1..=100).contains(&p))
                && s.warn_pcts.windows(2).all(|w| w[0] < w[1]),
            "storage.warn_pcts must be strictly ascending values within 1..=100",
        );
        need(
            s.anchor_interval_secs >= 1,
            "storage.anchor_interval_secs must be at least 1",
        );
        if let Some(d) = &s.index_dir {
            need(
                d.is_absolute(),
                "storage.index_dir must be an absolute path",
            );
        }
        if let Some(cmd) = &s.anchor_command {
            need(
                cmd.first().is_some_and(|p| p.starts_with('/')),
                "storage.anchor_command must start with an absolute program path",
            );
        }

        need(
            self.seal.interval_secs >= 1,
            "seal.interval_secs must be at least 1",
        );
        need(
            self.rules.dir.is_absolute(),
            "rules.dir must be an absolute path",
        );
        need(
            self.api.socket.is_absolute(),
            "api.socket must be an absolute path",
        );
        need(
            self.daemon.data_dir.is_absolute(),
            "daemon.data_dir must be an absolute path",
        );
        for (name, g) in [
            ("api.group", &self.api.group),
            ("api.admin_group", &self.api.admin_group),
        ] {
            let ok = !g.is_empty()
                && g.len() <= 32
                && g.starts_with(|c: char| c.is_ascii_lowercase() || c == '_')
                && g.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
            need(ok, &format!("{name}: {g:?} is not a valid group name"));
        }
        need(
            ["error", "warn", "info", "debug", "trace"].contains(&self.daemon.log_level.as_str()),
            "daemon.log_level must be one of error, warn, info, debug, trace",
        );

        if e.is_empty() {
            Ok(())
        } else {
            Err(ConfigError::Invalid(e))
        }
    }

    /// The effective configuration as TOML (what `witness config show` prints).
    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).unwrap_or_default()
    }

    /// Dotted-path differences from `old` to `self`, for `config_change` records.
    pub fn diff(&self, old: &Config) -> Vec<String> {
        let (a, b) = (to_value(old), to_value(self));
        let mut out = Vec::new();
        walk("", &a, &b, &mut out);
        out
    }

    /// Settings the store crate consumes.
    pub fn store_config(&self) -> witness_store::Config {
        witness_store::Config {
            max_segment_bytes: self.storage.segment_max_mib << 20,
            disk: witness_store::disk::DiskPolicy {
                warn_pcts: self.storage.warn_pcts.clone(),
                min_free_bytes: self.storage.min_free_mib << 20,
                reserve_bytes: self.storage.reserve_mib << 20,
                on_full: match self.storage.on_full {
                    OnFull::Shed => witness_store::disk::OnFull::Shed,
                    OnFull::Stop => witness_store::disk::OnFull::Stop,
                },
                ..Default::default()
            },
        }
    }
}

fn to_value(c: &Config) -> serde_json::Value {
    serde_json::to_value(c).unwrap_or(serde_json::Value::Null)
}

fn walk(prefix: &str, a: &serde_json::Value, b: &serde_json::Value, out: &mut Vec<String>) {
    use serde_json::Value::Object;
    match (a, b) {
        (Object(x), Object(y)) => {
            let mut keys: Vec<&String> = x.keys().chain(y.keys()).collect();
            keys.sort();
            keys.dedup();
            for k in keys {
                let path = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                walk(
                    &path,
                    x.get(k).unwrap_or(&serde_json::Value::Null),
                    y.get(k).unwrap_or(&serde_json::Value::Null),
                    out,
                );
            }
        }
        _ if a != b => out.push(format!("{prefix}: {a} -> {b}")),
        _ => {}
    }
}
