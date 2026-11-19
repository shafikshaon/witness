#![allow(clippy::unwrap_used, clippy::expect_used)]
use serde_json::{json, Value};
use witness_rules::{load_str, Engine};

const EXEC_FROM_TMP: &str = r#"
id: witness.exec.from-tmp
title: Execution from /tmp, /dev/shm or /var/tmp
severity: medium
event: proc_exec
match:
  all:
    - { field: data.exe, op: glob, value: ["/tmp/**", "/dev/shm/**", "/var/tmp/**"] }
    - not: { field: data.exe, op: glob, value: ["/tmp/.X11-unix/**", "/tmp/.mount_*/**"] }
"#;

const BRUTE: &str = r#"
id: witness.auth.bruteforce
title: Repeated failed logins from one source
severity: high
event: auth_fail
correlate:
  type: count
  group_by: [data.remote_addr]
  window: 60s
  threshold: 3
match:
  all:
    - { field: data.service, op: in, value: [sshd, login] }
alert:
  fields: [data.remote_addr]
"#;

const DROPPER: &str = r#"
id: witness.seq.drop-chmod-exec
title: File written, made executable, then executed
severity: high
correlate:
  type: sequence
  scope: same_tree
  window: 5m
  steps:
    - id: write
      event: file_create
      match: { all: [ { field: data.path, op: glob, value: ["/tmp/**"] } ] }
    - id: chmod
      event: file_attr
      match: { all: [ { field: data.new_mode, op: exists }, { field: data.path, op: eq, value: "$write.data.path" } ] }
    - id: exec
      event: proc_exec
      match: { all: [ { field: data.exe, op: eq, value: "$write.data.path" } ] }
"#;

fn engine(rules: &[(&str, &str)]) -> Engine {
    let r = load_str(rules.iter().map(|(n, t)| (*n, *t)));
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    Engine::new(r.set)
}

fn ev(kind: &str, ns: u64, ses: u32, data: Value) -> Value {
    json!({"type": kind, "boot_ns": ns, "actor": {"puid": format!("p{ses}"), "ses": ses}, "data": data})
}

const S: u64 = 1_000_000_000;

#[test]
fn exec_from_tmp_matches_only_unexcluded_paths() {
    let mut e = engine(&[("a.yml", EXEC_FROM_TMP)]);
    let hit = e.process_value(1, &ev("proc_exec", S, 1, json!({"exe": "/tmp/x/payload"})));
    assert_eq!(hit.len(), 1);
    assert_eq!(hit[0].rule_id, "witness.exec.from-tmp");
    assert_eq!(hit[0].trigger_seqs, vec![1]);
    for exe in ["/usr/bin/ls", "/tmp/.mount_abc/app", "/tmp/.X11-unix/x"] {
        assert!(
            e.process_value(2, &ev("proc_exec", S, 1, json!({"exe": exe})))
                .is_empty(),
            "{exe}"
        );
    }
    // Wrong event kind never reaches the rule.
    assert!(e
        .process_value(3, &ev("file_create", S, 1, json!({"exe": "/tmp/x"})))
        .is_empty());
}

#[test]
fn count_correlation_groups_by_address_and_respects_the_window() {
    let mut e = engine(&[("b.yml", BRUTE)]);
    let fail = |ns, addr: &str| {
        ev(
            "auth_fail",
            ns,
            0,
            json!({"service": "sshd", "remote_addr": addr}),
        )
    };
    assert!(e.process_value(1, &fail(S, "1.1.1.1")).is_empty());
    assert!(e.process_value(2, &fail(2 * S, "2.2.2.2")).is_empty());
    assert!(e.process_value(3, &fail(3 * S, "1.1.1.1")).is_empty());
    let a = e.process_value(4, &fail(4 * S, "1.1.1.1"));
    assert_eq!(a.len(), 1, "third failure from 1.1.1.1 within 60s");
    assert_eq!(a[0].trigger_seqs, vec![1, 3, 4]);
    assert_eq!(a[0].detail["data.remote_addr"], "1.1.1.1");
    // Spread over more than the window: no alert.
    let mut e = engine(&[("b.yml", BRUTE)]);
    for (i, ns) in [10, 80, 150].iter().enumerate() {
        assert!(e
            .process_value(i as u64, &fail(ns * S, "9.9.9.9"))
            .is_empty());
    }
    // Other services do not count.
    let other = ev(
        "auth_fail",
        S,
        0,
        json!({"service": "gdm", "remote_addr": "1.1.1.1"}),
    );
    assert!(e.process_value(9, &other).is_empty());
}

#[test]
fn sequence_requires_order_the_same_session_and_back_references() {
    let mut e = engine(&[("c.yml", DROPPER)]);
    let p = "/tmp/dropper";
    let w = ev("file_create", S, 7, json!({"path": p}));
    let c = ev("file_attr", 2 * S, 7, json!({"path": p, "new_mode": 493}));
    let x = ev("proc_exec", 3 * S, 7, json!({"exe": p}));
    assert!(e.process_value(10, &w).is_empty());
    assert!(e.process_value(11, &c).is_empty());
    let a = e.process_value(12, &x);
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].trigger_seqs, vec![10, 11, 12]);
    assert_eq!(a[0].session, Some(7));

    // Same events but the chmod touches a different file: the back reference stops it.
    let mut e = engine(&[("c.yml", DROPPER)]);
    e.process_value(1, &w);
    e.process_value(
        2,
        &ev(
            "file_attr",
            2 * S,
            7,
            json!({"path": "/tmp/other", "new_mode": 493}),
        ),
    );
    assert!(e.process_value(3, &x).is_empty());

    // Same events from another session: not tied together.
    let mut e = engine(&[("c.yml", DROPPER)]);
    e.process_value(1, &w);
    e.process_value(2, &c);
    assert!(e
        .process_value(3, &ev("proc_exec", 3 * S, 8, json!({"exe": p})))
        .is_empty());

    // Too slow: the window is five minutes.
    let mut e = engine(&[("c.yml", DROPPER)]);
    e.process_value(1, &w);
    e.process_value(2, &c);
    assert!(e
        .process_value(3, &ev("proc_exec", 400 * S, 7, json!({"exe": p})))
        .is_empty());
}

#[test]
fn suppression_swallows_repeats_and_reports_the_count() {
    let rule = r#"
id: s.rule
title: t
severity: low
event: proc_exec
alert: { suppress: 60s }
"#;
    let mut e = engine(&[("s.yml", rule)]);
    let x = |ns| ev("proc_exec", ns, 1, json!({"exe": "/bin/a"}));
    assert_eq!(e.process_value(1, &x(S)).len(), 1);
    assert!(e.process_value(2, &x(2 * S)).is_empty());
    assert!(e.process_value(3, &x(3 * S)).is_empty());
    let a = e.process_value(4, &x(100 * S));
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].detail["suppressed_since_last"], 2);
    assert_eq!(e.stats.suppressed, 2);
}

#[test]
fn operators_behave() {
    let rule = |cond: &str| {
        format!("id: r\ntitle: t\nseverity: info\nevent: x\nmatch: {{ all: [ {cond} ] }}\n")
    };
    let check = |cond: &str, data: Value| {
        let text = rule(cond);
        let mut e = engine(&[("r.yml", &text)]);
        !e.process_value(1, &ev("x", S, 1, data)).is_empty()
    };
    assert!(check(
        "{ field: data.a, op: contains, value: BAD, ci: true }",
        json!({"a": "xxbadxx"})
    ));
    assert!(!check(
        "{ field: data.a, op: contains, value: BAD }",
        json!({"a": "xxbadxx"})
    ));
    assert!(check(
        "{ field: data.a, op: startswith, value: /etc }",
        json!({"a": "/etc/passwd"})
    ));
    assert!(check(
        "{ field: data.a, op: endswith, value: .sh }",
        json!({"a": "run.sh"})
    ));
    assert!(check(
        "{ field: data.a, op: regex, value: '^/home/[a-z]+/\\.ssh/' }",
        json!({"a": "/home/bob/.ssh/id"})
    ));
    assert!(check(
        "{ field: data.a, op: cidr, value: 10.0.0.0/8 }",
        json!({"a": "10.1.2.3"})
    ));
    assert!(!check(
        "{ field: data.a, op: cidr, value: 10.0.0.0/8 }",
        json!({"a": "11.1.2.3"})
    ));
    assert!(check(
        "{ field: data.n, op: gte, value: 5 }",
        json!({"n": 5})
    ));
    assert!(!check(
        "{ field: data.n, op: lt, value: 5 }",
        json!({"n": 5})
    ));
    assert!(check("{ field: data.a, op: exists }", json!({"a": 1})));
    assert!(check(
        "{ field: data.a, op: exists, value: false }",
        json!({"b": 1})
    ));
    // An array field matches when any element does; `ne` needs all of them to differ.
    assert!(check(
        "{ field: data.argv, op: eq, value: -e }",
        json!({"argv": ["nc", "-e", "/bin/sh"]})
    ));
    assert!(!check(
        "{ field: data.argv, op: ne, value: -e }",
        json!({"argv": ["nc", "-e"]})
    ));
    assert!(check(
        "{ field: data.a, op: ne, value: x }",
        json!({"b": 1})
    ));
}

#[test]
fn bad_rules_are_rejected_with_where_and_why_and_good_ones_still_load() {
    let bad_yaml = "id: a\ntitle: t\nseverity: nonsense\nevent: x\n";
    let bad_field =
        "id: b\ntitle: t\nseverity: low\nevent: x\nmatch: { field: nope.x, op: eq, value: 1 }\n";
    let bad_op =
        "id: c\ntitle: t\nseverity: low\nevent: x\nmatch: { field: data.x, op: wat, value: 1 }\n";
    let bad_re = "id: d\ntitle: t\nseverity: low\nevent: x\nmatch: { field: data.x, op: regex, value: '(' }\n";
    let bad_ref = "id: e\ntitle: t\nseverity: low\ncorrelate:\n  type: sequence\n  window: 1m\n  steps:\n    - { id: a, event: x, match: { field: data.p, op: eq, value: '$b.data.p' } }\n    - { id: b, event: y }\n";
    let no_event = "id: f\ntitle: t\nseverity: low\n";
    let bad_id = "id: Bad Id\ntitle: t\nseverity: low\nevent: x\n";
    let r = load_str([
        ("1.yml", bad_yaml),
        ("2.yml", bad_field),
        ("3.yml", bad_op),
        ("4.yml", bad_re),
        ("5.yml", bad_ref),
        ("6.yml", no_event),
        ("7.yml", bad_id),
        ("ok.yml", EXEC_FROM_TMP),
        ("dup.yml", EXEC_FROM_TMP),
    ]);
    assert_eq!(r.set.rules.len(), 1, "only the one valid rule loads");
    assert_eq!(r.errors.len(), 8);
    let msg = |f: &str| r.errors.iter().find(|e| e.file == f).unwrap().to_string();
    assert!(msg("1.yml").starts_with("1.yml:3:"), "{}", msg("1.yml"));
    assert!(msg("2.yml").contains("unknown field `nope.x`"));
    assert!(msg("3.yml").contains("unknown operator `wat`"));
    assert!(msg("4.yml").contains("bad regex"));
    assert!(msg("5.yml").contains("unknown or later step"));
    assert!(msg("6.yml").contains("needs an `event`"));
    assert!(msg("7.yml").contains("[a-z0-9._-]+"));
    assert!(msg("dup.yml").contains("duplicate rule id"));
}

#[test]
fn disabled_rules_load_but_never_fire_and_hot_swap_keeps_unchanged_state() {
    let off = EXEC_FROM_TMP.replace("severity: medium", "severity: medium\nenabled: false");
    let mut e = engine(&[("a.yml", &off)]);
    assert!(e
        .process_value(1, &ev("proc_exec", S, 1, json!({"exe": "/tmp/x"})))
        .is_empty());

    let mut e = engine(&[("b.yml", BRUTE)]);
    let fail = |ns| {
        ev(
            "auth_fail",
            ns,
            0,
            json!({"service": "sshd", "remote_addr": "1.1.1.1"}),
        )
    };
    e.process_value(1, &fail(S));
    e.process_value(2, &fail(2 * S));
    // Reload with an unrelated extra rule: the brute-force counters survive.
    let r = load_str([("b.yml", BRUTE), ("a.yml", EXEC_FROM_TMP)]);
    e.swap(r.set);
    assert_eq!(e.process_value(3, &fail(3 * S)).len(), 1);
    assert_ne!(e.rules().sha256, "");
}

fn proc_ev(kind: &str, ns: u64, puid: &str, pid: u64, ppid: u64, ses: u64, data: Value) -> Value {
    json!({"type": kind, "boot_ns": ns, "actor": {"puid": puid, "pid": pid, "ppid": ppid, "ses": ses}, "data": data})
}

#[test]
fn same_tree_follows_ancestry_across_sessions_and_excludes_strangers() {
    let mut e = engine(&[("c.yml", DROPPER)]);
    let p = "/tmp/dropper";
    // A shell (pid 100) is seen, then its child (pid 101) writes the file, and a different
    // child (pid 102) of the same shell chmods and runs it. The children carry *different*
    // session ids, so only real ancestry can tie them together.
    e.process_value(
        1,
        &proc_ev("proc_exec", S, "sh", 100, 1, 1, json!({"exe": "/bin/sh"})),
    );
    assert!(e
        .process_value(
            2,
            &proc_ev("file_create", 2 * S, "c1", 101, 100, 7, json!({"path": p}))
        )
        .is_empty());
    assert!(e
        .process_value(
            3,
            &proc_ev(
                "file_attr",
                3 * S,
                "c2",
                102,
                100,
                8,
                json!({"path": p, "new_mode": 493})
            )
        )
        .is_empty());
    let a = e.process_value(
        4,
        &proc_ev("proc_exec", 4 * S, "c3", 103, 100, 9, json!({"exe": p})),
    );
    assert_eq!(a.len(), 1, "the three steps came from one tree");
    assert_eq!(a[0].trigger_seqs, vec![2, 3, 4]);

    // The same steps under unrelated parents never complete.
    let mut e = engine(&[("c.yml", DROPPER)]);
    e.process_value(
        1,
        &proc_ev("proc_exec", S, "sh", 100, 1, 1, json!({"exe": "/bin/sh"})),
    );
    e.process_value(
        2,
        &proc_ev(
            "proc_exec",
            S,
            "other",
            200,
            1,
            1,
            json!({"exe": "/bin/sh"}),
        ),
    );
    e.process_value(
        3,
        &proc_ev("file_create", 2 * S, "c1", 101, 100, 7, json!({"path": p})),
    );
    e.process_value(
        4,
        &proc_ev(
            "file_attr",
            3 * S,
            "c2",
            201,
            200,
            7,
            json!({"path": p, "new_mode": 493}),
        ),
    );
    assert!(e
        .process_value(
            5,
            &proc_ev("proc_exec", 4 * S, "c3", 202, 200, 7, json!({"exe": p}))
        )
        .is_empty());
}

#[test]
fn grandchildren_share_the_root_and_a_reused_pid_does_not_inherit() {
    let rule = r#"
id: tree.seq
title: t
severity: low
correlate:
  type: sequence
  scope: same_tree
  window: 5m
  steps:
    - { id: a, event: file_create }
    - { id: b, event: proc_exec }
"#;
    let mut e = engine(&[("t.yml", rule)]);
    // root(100) -> child(110) -> grandchild(111) writes; sibling branch child(120) execs.
    e.process_value(1, &proc_ev("proc_exec", S, "r", 100, 1, 1, json!({})));
    e.process_value(2, &proc_ev("proc_exec", S, "k1", 110, 100, 1, json!({})));
    e.process_value(3, &proc_ev("file_create", S, "g", 111, 110, 1, json!({})));
    let hit = e.process_value(
        4,
        &proc_ev("proc_exec", 2 * S, "k2", 120, 100, 1, json!({})),
    );
    assert_eq!(hit.len(), 1, "cousins are in one tree");

    // After the root exits, its pid is reused by an unrelated process: it must not join.
    let mut e = engine(&[("t.yml", rule)]);
    e.process_value(1, &proc_ev("proc_exec", S, "r", 100, 1, 1, json!({})));
    e.process_value(2, &proc_ev("file_create", S, "g", 111, 100, 1, json!({})));
    e.process_value(3, &json!({"type": "proc_exit", "boot_ns": S, "actor": {"puid": "r", "pid": 100, "ppid": 1}, "data": {}}));
    e.process_value(4, &proc_ev("proc_exec", S, "new", 100, 1, 1, json!({})));
    assert!(e
        .process_value(
            5,
            &proc_ev("proc_exec", 2 * S, "kid", 130, 100, 1, json!({}))
        )
        .is_empty());
}

const USB_UNKNOWN: &str = r#"
id: usb.unknown
title: Unknown USB device
severity: medium
event: usb_device
correlate:
  type: first_seen
  group_by: [data.vendor_id, data.product_id, data.serial]
match:
  all:
    - { field: data.action, op: eq, value: add }
"#;

fn usb(action: &str, vid: &str, serial: &str) -> Value {
    json!({"type":"usb_device","boot_ns":S,"actor":{"puid":"k"},"data":{"action":action,"vendor_id":vid,"product_id":"5581","serial":serial}})
}

#[test]
fn first_seen_alerts_once_per_device_and_survives_a_restart() {
    let mut e = engine(&[("u.yml", USB_UNKNOWN)]);
    assert_eq!(
        e.process_value(1, &usb("add", "0781", "A")).len(),
        1,
        "new device"
    );
    assert!(
        e.process_value(2, &usb("add", "0781", "A")).is_empty(),
        "same device again"
    );
    assert!(
        e.process_value(3, &usb("remove", "0781", "B")).is_empty(),
        "a removal is not a first sight"
    );
    assert_eq!(
        e.process_value(4, &usb("add", "0781", "B")).len(),
        1,
        "same model, other serial"
    );
    assert_eq!(
        e.process_value(5, &usb("add", "0951", "A")).len(),
        1,
        "other vendor"
    );
    assert!(e.take_seen_dirty());
    assert!(!e.take_seen_dirty(), "the flag clears once read");

    // A "restart": a fresh engine given the exported set knows these devices already.
    let learned = e.export_seen();
    assert_eq!(learned["usb.unknown"].len(), 3);
    let mut e2 = engine(&[("u.yml", USB_UNKNOWN)]);
    e2.import_seen(&learned);
    assert!(e2.process_value(10, &usb("add", "0781", "A")).is_empty());
    assert_eq!(e2.process_value(11, &usb("add", "dead", "Z")).len(), 1);

    // Editing the rule keeps what it learned.
    let edited = USB_UNKNOWN.replace("severity: medium", "severity: high");
    let r = load_str([("u.yml", edited.as_str())]);
    e.swap(r.set);
    assert!(e.process_value(20, &usb("add", "0781", "A")).is_empty());
}

#[test]
fn first_seen_needs_group_by_and_other_types_need_a_window() {
    let no_group = "id: a\ntitle: t\nseverity: low\nevent: x\ncorrelate: { type: first_seen }\n";
    let no_window = "id: b\ntitle: t\nseverity: low\nevent: x\ncorrelate: { type: count, group_by: [data.a], threshold: 2 }\n";
    let r = load_str([("a.yml", no_group), ("b.yml", no_window)]);
    assert_eq!(r.errors.len(), 2);
    assert!(r
        .errors
        .iter()
        .any(|e| e.to_string().contains("needs `group_by`")));
    assert!(r
        .errors
        .iter()
        .any(|e| e.to_string().contains("`window` is required")));
}
