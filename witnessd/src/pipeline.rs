//! Moves decoded events into the tamper-evident store and keeps its housekeeping going:
//! group commit, disk-policy ticks, periodic anchors and seals, start/stop/gap records.
//! Kernel-independent so it can be tested without eBPF.

use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::Value;
use witness_common::schema::{
    Body, CaptureDrop, CaptureGap, DaemonStart, DaemonStop, Event, Recovery, Source, SCHEMA_VERSION,
};
use witness_store::anchor::AnchorSink;
use witness_store::disk::Priority;
use witness_store::store::{Append, DiskEvent, Recovery as StoreRecovery};
use witness_store::{Store, StoreError};

pub trait Clock: Send {
    /// `CLOCK_BOOTTIME` (includes suspend), the authoritative ordering clock.
    fn boot_ns(&self) -> u64;
    /// Wall clock, ns since the Unix epoch.
    fn wall_ns(&self) -> u64;
    /// Monotonic time for scheduling.
    fn mono(&self) -> Duration;
}

pub struct SystemClock {
    start: std::time::Instant,
}

impl Default for SystemClock {
    fn default() -> Self {
        SystemClock {
            start: std::time::Instant::now(),
        }
    }
}

impl Clock for SystemClock {
    fn boot_ns(&self) -> u64 {
        #[cfg(target_os = "linux")]
        {
            let t = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
            t.tv_sec as u64 * 1_000_000_000 + t.tv_nsec as u64
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.start.elapsed().as_nanos() as u64
        }
    }

    fn wall_ns(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }

    fn mono(&self) -> Duration {
        self.start.elapsed()
    }
}

#[derive(Debug, Clone)]
pub struct Settings {
    pub boot_id: String,
    pub version: String,
    pub kernel: String,
    pub btf: bool,
    pub pid: u32,
    pub config_sha256: String,
    pub bpf_object_sha256: String,
    pub group_commit: Duration,
    pub anchor_interval: Duration,
    pub seal_interval: Duration,
    pub sealing: bool,
}

/// What the store says about the previous run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Previous {
    pub clean: bool,
    /// `Some(true/false)` when a recent record names its boot; `None` if undeterminable.
    pub same_boot: Option<bool>,
    pub from_boot_ns: Option<u64>,
    pub from_wall_ns: Option<u64>,
}

/// Interprets the last (up to two) records of an existing store. `None` for a new store.
pub fn classify_previous(recent: &[Value], boot_id: &str) -> Option<Previous> {
    if recent.is_empty() {
        return None;
    }
    let clean = recent
        .iter()
        .any(|r| r["type"] == "daemon_stop" && r["data"]["clean"] == true);
    let with_boot = recent.iter().rev().find(|r| r["boot_id"].is_string());
    let same_boot = with_boot.map(|r| r["boot_id"] == boot_id);
    let from_boot_ns = with_boot
        .filter(|_| same_boot == Some(true))
        .and_then(|r| r["boot_ns"].as_u64());
    // Prefer a real event/daemon record's time over a store-internal note (seal, anchor).
    let from_wall_ns = recent
        .iter()
        .rev()
        .find_map(|r| r["wall_ns"].as_u64())
        .or_else(|| recent.iter().rev().find_map(|r| r["ts_wall_ns"].as_u64()));
    Some(Previous {
        clean,
        same_boot,
        from_boot_ns,
        from_wall_ns,
    })
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Stats {
    pub ingested: u64,
    /// Events the disk-full policy declined to write.
    pub shed: u64,
    pub kernel_drops: u64,
}

pub struct Pipeline {
    store: Store,
    clock: Box<dyn Clock>,
    sinks: Vec<Box<dyn AnchorSink>>,
    set: Settings,
    dirty: bool,
    /// Start (boot-relative ns) of the capture gap just recorded, if this restart was on the
    /// same boot as the previous run.
    gap_from_boot_ns: Option<u64>,
    last_sync: Duration,
    last_disk: Duration,
    last_anchor: Duration,
    last_seal: Duration,
    rules: Option<crate::rules::RuleRunner>,
    last_rules_check: Duration,
    pub stats: Stats,
}

/// The event's own priority (set by the decoder, possibly lowered by the file policy).
fn priority_of(p: u8) -> Priority {
    match p {
        0 => Priority::P0,
        1 => Priority::P1,
        2 => Priority::P2,
        _ => Priority::P3,
    }
}

impl Pipeline {
    /// Opens the data directory and starts the pipeline: takes the writer lock, repairs a
    /// torn tail, reads what the previous run left, then writes the restart records.
    pub fn open(
        data_dir: &std::path::Path,
        cfg: witness_store::Config,
        sinks: Vec<Box<dyn AnchorSink>>,
        set: Settings,
        clock: Box<dyn Clock>,
    ) -> Result<Pipeline> {
        let (mut store, recoveries) = match Store::open(data_dir, cfg) {
            Ok(x) => x,
            Err(StoreError::Locked) => anyhow::bail!(
                "another witnessd already holds {} (is the service running?)",
                data_dir.display()
            ),
            Err(e) => return Err(e).with_context(|| format!("opening {}", data_dir.display())),
        };
        if set.sealing {
            store.enable_sealing(&data_dir.join("seal.key")).context(
                "sealing is enabled but seal.key is unusable (run `witness init --seal`)",
            )?;
        }
        let recent = witness_store::store::read_recent_records(store.segment_dir())?;
        let previous = classify_previous(&recent, &set.boot_id);
        Pipeline::start(store, &recoveries, previous, sinks, set, clock)
    }

    /// Writes the restart bookkeeping (recoveries, capture gap, daemon start) and returns a
    /// pipeline ready to ingest. `previous` comes from [`classify_previous`] and must be
    /// computed *before* anything new is appended.
    pub fn start(
        store: Store,
        recoveries: &[StoreRecovery],
        previous: Option<Previous>,
        sinks: Vec<Box<dyn AnchorSink>>,
        set: Settings,
        clock: Box<dyn Clock>,
    ) -> Result<Pipeline> {
        let now = clock.mono();
        let mut p = Pipeline {
            store,
            clock,
            sinks,
            set,
            dirty: false,
            gap_from_boot_ns: previous.as_ref().and_then(|p| p.from_boot_ns),
            last_sync: now,
            last_disk: now,
            last_anchor: now,
            last_seal: now,
            rules: None,
            last_rules_check: now,
            stats: Stats::default(),
        };
        for r in recoveries {
            p.write(Body::Recovery(Recovery {
                segment: r.segment.display().to_string(),
                bytes: r.bytes,
                sha256: witness_store::chain::to_hex(&r.sha256),
                quarantined_to: r.quarantined_to.display().to_string(),
            }))?;
        }
        let prev_shutdown = match &previous {
            None => "none",
            Some(pr) if pr.clean => "clean",
            Some(_) => "unclean",
        };
        if let Some(pr) = &previous {
            let kind = match pr.same_boot {
                Some(true) => "restart_same_boot",
                Some(false) => "new_boot",
                None => "restart_unknown_boot",
            };
            p.write(Body::CaptureGap(CaptureGap {
                kind: kind.into(),
                from_boot_ns: pr.from_boot_ns,
                from_wall_ns: pr.from_wall_ns,
                to_boot_ns: p.clock.boot_ns(),
                to_wall_ns: p.clock.wall_ns(),
                prev_shutdown: prev_shutdown.into(),
                source: None,
            }))?;
        }
        let s = &p.set;
        let start = Body::DaemonStart(DaemonStart {
            version: s.version.clone(),
            pid: s.pid,
            kernel: s.kernel.clone(),
            btf: s.btf,
            config_sha256: s.config_sha256.clone(),
            rules_sha256: String::new(),
            bpf_object_sha256: s.bpf_object_sha256.clone(),
            prev_shutdown: prev_shutdown.into(),
        });
        p.write(start)?;
        p.store.sync()?;
        Ok(p)
    }

    fn envelope(&self, body: Body) -> Event {
        Event {
            v: SCHEMA_VERSION,
            seq: 0,
            boot_id: self.set.boot_id.clone(),
            boot_ns: self.clock.boot_ns(),
            wall_ns: self.clock.wall_ns(),
            wall_uncertain: false,
            src: Source::Daemon,
            prio: 0,
            actor: None,
            body,
            h: None,
        }
    }

    /// Writes a daemon-originated record (P0). A full disk is tolerated and counted by the
    /// store; any other storage error is fatal.
    fn write(&mut self, body: Body) -> Result<()> {
        let fields = self.envelope(body).to_fields()?;
        match self.store.append(fields) {
            Ok(_) => {
                self.dirty = true;
                Ok(())
            }
            Err(StoreError::DiskFull) => Ok(()),
            Err(e) => Err(e).context("writing a daemon record"),
        }
    }

    /// Starts evaluating rules over every stored event. Records the initial rule set (and any
    /// rejected files) in the chain.
    pub fn set_rules(&mut self, dir: &std::path::Path) -> Result<usize> {
        let (runner, change) = crate::rules::RuleRunner::start(dir);
        let n = runner.rule_count();
        self.rules = Some(runner);
        self.write(Body::RuleSetChange(change))?;
        Ok(n)
    }

    /// Records a daemon-originated body (triage actions, API access) in the chain.
    pub fn record(&mut self, body: Body) -> Result<()> {
        self.write(body)
    }

    /// Stores one captured event, subject to the disk-full policy, then evaluates the rules
    /// over it. Alerts are chained records of their own.
    pub fn ingest(&mut self, ev: &Event) -> Result<()> {
        let fields = ev.to_fields()?;
        match self
            .store
            .append_prio(priority_of(ev.prio), fields)
            .context("storing an event")?
        {
            Append::Written(a) => {
                self.dirty = true;
                let alerts = match &mut self.rules {
                    Some(r) => r.process(a.seq, ev),
                    None => Vec::new(),
                };
                for al in alerts {
                    tracing::warn!(rule = %al.rule_id, severity = ?al.severity, "ALERT: {}", al.title);
                    self.write(Body::Alert(al))?;
                }
            }
            Append::Dropped => self.stats.shed += 1,
        }
        self.stats.ingested += 1;
        Ok(())
    }

    /// Records events the kernel could not queue because ring buffer `class` was full
    /// (0 = process lifecycle, 1 = high-volume file/network).
    pub fn kernel_drops(&mut self, class: usize, n: u64, from_ns: u64, to_ns: u64) -> Result<()> {
        self.stats.kernel_drops += n;
        let mut dropped = [0u64; 4];
        dropped[class.min(3)] = n;
        let source = if class == 0 {
            "ebpf.critical"
        } else {
            "ebpf.volume"
        };
        self.write(Body::CaptureDrop(CaptureDrop {
            reason: "ring_overflow".into(),
            from_ns,
            to_ns,
            dropped,
            source: Some(source.into()),
        }))
    }

    /// Records that a capture source is active, degraded or unavailable (and why).
    pub fn source_health(
        &mut self,
        source: &str,
        status: &str,
        reason: Option<String>,
    ) -> Result<()> {
        self.write(Body::SourceHealth(witness_common::schema::SourceHealth {
            source: source.into(),
            status: status.into(),
            reason,
        }))
    }

    /// Housekeeping; call at least once a second. Returns what the disk policy did.
    pub fn tick(&mut self) -> Result<Vec<DiskEvent>> {
        let now = self.clock.mono();
        let mut disk_events = Vec::new();
        if now.saturating_sub(self.last_rules_check) >= crate::rules::RELOAD_EVERY {
            self.last_rules_check = now;
            let change = self.rules.as_mut().and_then(|r| r.reload_if_changed());
            if let Some(ch) = change {
                tracing::info!(
                    added = ch.added.len(),
                    removed = ch.removed.len(),
                    modified = ch.modified.len(),
                    rejected = ch.rejected.len(),
                    "rule set reloaded"
                );
                self.write(Body::RuleSetChange(ch))?;
            }
        }
        if now.saturating_sub(self.last_disk) >= Duration::from_secs(1) {
            disk_events = self.store.tick().context("disk policy tick")?;
            self.last_disk = now;
        }
        if self.set.sealing && now.saturating_sub(self.last_seal) >= self.set.seal_interval {
            self.store.seal_now().context("sealing")?;
            self.last_seal = now;
            self.dirty = false;
        }
        if now.saturating_sub(self.last_anchor) >= self.set.anchor_interval {
            let (_, failures) = self
                .store
                .anchor_now(&mut self.sinks)
                .context("writing an anchor")?;
            for (sink, e) in failures {
                tracing::error!(%sink, error = %e, "anchor sink failed");
            }
            self.last_anchor = now;
            self.dirty = false;
        }
        if self.dirty && now.saturating_sub(self.last_sync) >= self.set.group_commit {
            self.store.sync().context("group commit")?;
            self.last_sync = now;
            self.dirty = false;
        }
        Ok(disk_events)
    }

    /// Orderly shutdown: final seal and anchor, a `daemon_stop` record, then seal the
    /// segment. The stop record is deliberately the last data record so the next start can
    /// tell a clean shutdown from a crash.
    pub fn stop(mut self, reason: &str, signal: Option<u8>) -> Result<Stats> {
        if self.set.sealing {
            self.store.seal_now().context("final seal")?;
        }
        let (_, failures) = self
            .store
            .anchor_now(&mut self.sinks)
            .context("final anchor")?;
        for (sink, e) in failures {
            tracing::error!(%sink, error = %e, "anchor sink failed");
        }
        self.write(Body::DaemonStop(DaemonStop {
            reason: reason.into(),
            clean: true,
            signal,
            sender_pid: None,
        }))?;
        self.store.rotate().context("sealing the segment")?;
        self.store.sync()?;
        Ok(self.stats.clone())
    }

    /// Where the capture gap before this start began (same boot only).
    pub fn gap_from_boot_ns(&self) -> Option<u64> {
        self.gap_from_boot_ns
    }

    pub fn boot_ns(&self) -> u64 {
        self.clock.boot_ns()
    }

    pub fn wall_ns(&self) -> u64 {
        self.clock.wall_ns()
    }

    pub fn store(&self) -> &Store {
        &self.store
    }
}
