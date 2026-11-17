#![allow(clippy::unwrap_used, clippy::expect_used)]

use witness_config::{Config, ConfigError, OnFull, Severity};

#[test]
fn defaults_are_valid_and_empty_file_means_defaults() {
    Config::default().validate().unwrap();
    assert_eq!(Config::parse("").unwrap(), Config::default());
    assert_eq!(
        Config::parse("# only a comment\n").unwrap(),
        Config::default()
    );
}

#[test]
fn defaults_roundtrip_through_toml() {
    let d = Config::default();
    assert_eq!(Config::parse(&d.to_toml()).unwrap(), d);
}

#[test]
fn partial_overrides_keep_other_defaults() {
    let c = Config::parse(
        r#"
        [storage]
        on_full = "stop"
        warn_pcts = [70, 85, 95]

        [rules]
        notify_min_severity = "medium"
        "#,
    )
    .unwrap();
    assert_eq!(c.storage.on_full, OnFull::Stop);
    assert_eq!(c.storage.warn_pcts, vec![70, 85, 95]);
    assert_eq!(c.rules.notify_min_severity, Severity::Medium);
    assert_eq!(c.storage.segment_max_mib, 256);
}

#[test]
fn unknown_keys_and_sections_are_rejected() {
    assert!(matches!(
        Config::parse("[storage]\nretention_days = 30\n"),
        Err(ConfigError::Parse(m)) if m.contains("retention_days")
    ));
    assert!(matches!(
        Config::parse("[bogus]\nx = 1\n"),
        Err(ConfigError::Parse(_))
    ));
}

#[test]
fn all_problems_are_reported_together() {
    let err = Config::parse(
        r#"
        [capture]
        ring_volume_mib = 33
        argv_max_bytes = 10
        [storage]
        warn_pcts = [90, 80]
        anchor_command = ["relative/prog"]
        [api]
        group = "Bad Group"
        [daemon]
        log_level = "loud"
        data_dir = "var/lib/witness"
        "#,
    )
    .unwrap_err();
    let ConfigError::Invalid(list) = err else {
        panic!("{err}")
    };
    assert_eq!(list.len(), 7, "{list:#?}");
    assert!(list.iter().any(|m| m.contains("power of two")));
    assert!(list.iter().any(|m| m.contains("api.group")));
}

#[test]
fn wrong_types_are_syntax_errors() {
    assert!(matches!(
        Config::parse("[storage]\non_full = \"explode\"\n"),
        Err(ConfigError::Parse(_))
    ));
    assert!(matches!(
        Config::parse("[capture]\ndns = \"yes\"\n"),
        Err(ConfigError::Parse(_))
    ));
}

#[test]
fn load_returns_the_hash_of_the_exact_bytes() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("config.toml");
    std::fs::write(&p, "[daemon]\nlog_level = \"debug\"\n").unwrap();
    let (c, sha) = Config::load(&p).unwrap();
    assert_eq!(c.daemon.log_level, "debug");
    // Changing a byte (even whitespace) changes the recorded hash.
    std::fs::write(&p, "[daemon]\nlog_level = \"debug\"\n\n").unwrap();
    assert_ne!(Config::load(&p).unwrap().1, sha);
    assert!(matches!(
        Config::load(&d.path().join("missing.toml")),
        Err(ConfigError::Io { .. })
    ));
}

#[test]
fn diff_lists_dotted_paths() {
    let old = Config::default();
    let new =
        Config::parse("[storage]\non_full = \"stop\"\nzstd_level = 9\n[seal]\nenabled = true\n")
            .unwrap();
    let d = new.diff(&old);
    assert_eq!(
        d,
        vec![
            "seal.enabled: false -> true".to_string(),
            "storage.on_full: \"shed\" -> \"stop\"".into(),
            "storage.zstd_level: 3 -> 9".into(),
        ]
    );
    assert!(old.diff(&old).is_empty());
}

#[test]
fn store_config_converts_units() {
    let c = Config::parse(
        "[storage]\nsegment_max_mib = 2\nmin_free_mib = 10\nreserve_mib = 1\non_full = \"stop\"\n",
    )
    .unwrap();
    let s = c.store_config();
    assert_eq!(s.max_segment_bytes, 2 << 20);
    assert_eq!(s.disk.min_free_bytes, 10 << 20);
    assert_eq!(s.disk.reserve_bytes, 1 << 20);
    assert_eq!(s.disk.on_full, witness_store::disk::OnFull::Stop);
    s.disk.validate().unwrap();
}
