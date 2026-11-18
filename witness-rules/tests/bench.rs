#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Throughput of the full built-in pack over a synthetic mixed stream (DESIGN.md §8.3).
//! Run with: cargo test -p witness-rules --release --test bench -- --ignored --nocapture

use std::time::Instant;

use serde_json::{json, Value};
use witness_rules::{load_dir, Engine};

fn stream(n: usize) -> Vec<Value> {
    (0..n)
        .map(|i| {
            let ns = 1_000_000_000u64 + i as u64 * 20_000; // 50k events per second
            let actor = json!({"puid": format!("p{}", i % 500), "ses": i % 7, "exe": "/usr/bin/x", "user": "u"});
            let (ty, data) = match i % 10 {
                0 => ("proc_exec", json!({"exe": format!("/usr/bin/tool{}", i % 50), "argv": ["tool", "--flag", "value"]})),
                1 => ("file_create", json!({"path": format!("/home/u/work/f{i}")})),
                2 => ("file_open_read", json!({"path": format!("/etc/conf{}", i % 40)})),
                3 => ("file_open_write", json!({"path": format!("/var/log/app{}.log", i % 20)})),
                4 => ("net_connect", json!({"raddr": "93.184.216.34", "rport": 443})),
                5 => ("file_attr", json!({"path": "/home/u/a", "new_mode": 420, "suid_set": false})),
                6 => ("dns", json!({"qname": "example.com"})),
                7 => ("auth_fail", json!({"service": "sshd", "remote_addr": format!("10.0.{}.{}", i % 200, i % 250)})),
                8 => ("file_delete", json!({"path": format!("/tmp/x{i}")})),
                _ => ("net_close", json!({"bytes_sent": 10})),
            };
            json!({"type": ty, "boot_ns": ns, "actor": actor, "data": data})
        })
        .collect()
}

#[test]
#[ignore = "benchmark"]
fn the_pack_keeps_up_with_50k_events_per_second() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../rules");
    let r = load_dir(&dir).unwrap();
    assert!(r.errors.is_empty());
    let rules = r.set.rules.len();
    let mut e = Engine::new(r.set);
    let events = stream(500_000);
    let t = Instant::now();
    let mut alerts = 0;
    for (i, v) in events.iter().enumerate() {
        alerts += e.process_value(i as u64, v).len();
    }
    let secs = t.elapsed().as_secs_f64();
    let rate = events.len() as f64 / secs;
    println!(
        "{rules} rules, {} events in {secs:.2}s = {rate:.0} events/s on one core ({:.1}% of a core at 50k/s), {alerts} alerts",
        events.len(),
        50_000.0 / rate * 100.0
    );
    assert!(
        rate > 50_000.0,
        "the pack cannot sustain 50k events/s on one core: {rate:.0}/s"
    );
}
