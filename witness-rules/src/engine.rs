//! Evaluation and correlation (DESIGN.md §8.3).
//!
//! Time is the *event clock* (`boot_ns` of the events themselves), never the wall clock, so
//! replaying stored events gives the same alerts as running live.

use std::collections::{HashMap, VecDeque};

use serde_json::{json, Value};
use witness_common::schema::{Alert, Event};

use crate::compile::{Correlation, Node, Rule, RuleSet, Scope, Step};
use crate::ops::{candidates, lookup, Binds, Op};

/// Entries kept per rule for correlation before the oldest groups are dropped.
const MAX_GROUPS: usize = 50_000;
const MAX_PARTIALS: usize = 64;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub events: u64,
    pub alerts: u64,
    pub suppressed: u64,
    /// Correlation groups discarded because a rule's state hit its cap.
    pub state_evicted: u64,
}

struct Partial {
    next: usize,
    started_ns: u64,
    events: Vec<Value>,
    seqs: Vec<u64>,
}

#[derive(Default)]
struct RuleState {
    counts: HashMap<String, VecDeque<(u64, u64)>>,
    partials: HashMap<String, Vec<Partial>>,
    /// `group → (last alert time, alerts swallowed since)`.
    suppress: HashMap<String, (u64, u64)>,
}

/// Process ancestry learned from the events themselves (`actor.pid`, `actor.ppid`).
#[derive(Default)]
struct Tree {
    /// Live pid → puid (so a child's `ppid` can be resolved to the parent process).
    pid_puid: HashMap<u64, String>,
    /// puid → the root of its tree, fixed when the process is first seen.
    root: HashMap<String, String>,
}

/// Entries kept before the maps are cleared wholesale (ancestry is then re-learned).
const MAX_TREE: usize = 200_000;

impl Tree {
    /// Records the actor of `v` and returns its tree root. A process whose parent has not been
    /// seen is grouped under `pid:<ppid>`, so siblings of an unseen parent still share a root.
    fn observe(&mut self, v: &Value) -> Option<String> {
        let a = v.get("actor")?;
        let puid = a.get("puid")?.as_str()?;
        let pid = a.get("pid").and_then(Value::as_u64);
        let ppid = a.get("ppid").and_then(Value::as_u64);
        if self.root.len() >= MAX_TREE {
            self.root.clear();
            self.pid_puid.clear();
        }
        let root = match self.root.get(puid) {
            Some(r) => r.clone(),
            None => {
                let r = ppid
                    .and_then(|pp| self.pid_puid.get(&pp))
                    .and_then(|pu| self.root.get(pu))
                    .cloned()
                    .or_else(|| ppid.filter(|p| *p > 1).map(|p| format!("pid:{p}")))
                    .unwrap_or_else(|| puid.to_string());
                self.root.insert(puid.to_string(), r.clone());
                r
            }
        };
        if let Some(pid) = pid {
            if v.get("type").and_then(Value::as_str) == Some("proc_exit") {
                self.pid_puid.remove(&pid);
            } else {
                self.pid_puid.insert(pid, puid.to_string());
            }
        }
        Some(root)
    }
}

pub struct Engine {
    set: RuleSet,
    tree: Tree,
    state: Vec<RuleState>,
    pub stats: Stats,
}

fn eval_node(n: &Node, ev: &Value, binds: Binds<'_>) -> bool {
    match n {
        Node::All(v) => v.iter().all(|x| eval_node(x, ev, binds)),
        Node::Any(v) => v.iter().any(|x| eval_node(x, ev, binds)),
        Node::Not(x) => !eval_node(x, ev, binds),
        Node::Cond(c) => {
            let found = lookup(ev, &c.path);
            if let Op::Exists(want) = &c.op {
                return found.is_some() == *want;
            }
            // `ne` on a missing field is true (nothing equals it); every other op needs a value.
            match found {
                None => matches!(c.op, Op::Ne(_)),
                Some(v) => {
                    let mut it = candidates(v).into_iter();
                    if matches!(c.op, Op::Ne(_)) {
                        it.all(|x| c.op.test(x, c.ci, binds))
                    } else {
                        it.any(|x| c.op.test(x, c.ci, binds))
                    }
                }
            }
        }
    }
}

fn kind_of(ev: &Value) -> &str {
    ev.get("type").and_then(Value::as_str).unwrap_or("")
}

fn text_at(ev: &Value, path: &[String]) -> String {
    lookup(ev, path)
        .and_then(crate::ops::as_text)
        .unwrap_or_default()
}

impl Engine {
    pub fn new(set: RuleSet) -> Engine {
        let state = set.rules.iter().map(|_| RuleState::default()).collect();
        Engine {
            set,
            tree: Tree::default(),
            state,
            stats: Stats::default(),
        }
    }

    pub fn rules(&self) -> &RuleSet {
        &self.set
    }

    /// Replaces the rule set. Correlation state for rules whose text did not change is kept.
    pub fn swap(&mut self, set: RuleSet) {
        let mut old: HashMap<String, (String, RuleState)> = self
            .set
            .rules
            .iter()
            .zip(self.state.drain(..))
            .map(|(r, s)| (r.id.clone(), (r.sha256.clone(), s)))
            .collect();
        self.state = set
            .rules
            .iter()
            .map(|r| match old.remove(&r.id) {
                Some((sha, st)) if sha == r.sha256 => st,
                _ => RuleState::default(),
            })
            .collect();
        self.set = set;
    }

    /// Evaluates one stored event (`seq` is its position in the chain) and returns any alerts.
    pub fn process(&mut self, seq: u64, ev: &Event) -> Vec<Alert> {
        let Ok(v) = serde_json::to_value(ev) else {
            return Vec::new();
        };
        self.process_value(seq, &v)
    }

    pub fn process_value(&mut self, seq: u64, v: &Value) -> Vec<Alert> {
        self.stats.events += 1;
        // Ancestry is learned from every event, including ones no rule looks at.
        let root = self.tree.observe(v);
        let Some(idx) = self.set.by_kind.get(kind_of(v)) else {
            return Vec::new();
        };
        let idx = idx.clone();
        let now = v.get("boot_ns").and_then(Value::as_u64).unwrap_or(0);
        let mut out = Vec::new();
        for i in idx {
            let hit = match &self.set.rules[i].correlation {
                None => self
                    .simple(i, v)
                    .then(|| (String::new(), vec![seq], 1, v.clone())),
                Some(Correlation::Count { .. }) => self.count(i, v, seq, now),
                Some(Correlation::Sequence { .. }) => {
                    self.sequence(i, v, seq, now, root.as_deref())
                }
            };
            if let Some((group, seqs, n, last)) = hit {
                if let Some(a) = self.alert(i, &group, seqs, n, &last, now) {
                    out.push(a);
                }
            }
        }
        out
    }

    fn simple(&self, i: usize, v: &Value) -> bool {
        let r = &self.set.rules[i];
        r.kinds.iter().any(|k| k == kind_of(v))
            && r.node
                .as_ref()
                .is_none_or(|n| eval_node(n, v, Binds::default()))
    }

    fn count(
        &mut self,
        i: usize,
        v: &Value,
        seq: u64,
        now: u64,
    ) -> Option<(String, Vec<u64>, usize, Value)> {
        let r = &self.set.rules[i];
        if !self.simple(i, v) {
            return None;
        }
        let Some(Correlation::Count {
            group_by,
            window_ns,
            threshold,
        }) = &r.correlation
        else {
            return None;
        };
        let group = group_by
            .iter()
            .map(|g| text_at(v, g))
            .collect::<Vec<_>>()
            .join("\u{1f}");
        let st = &mut self.state[i];
        if st.counts.len() >= MAX_GROUPS && !st.counts.contains_key(&group) {
            st.counts.clear();
            self.stats.state_evicted += 1;
        }
        let q = st.counts.entry(group.clone()).or_default();
        q.push_back((now, seq));
        while q
            .front()
            .is_some_and(|(t, _)| now.saturating_sub(*t) > *window_ns)
        {
            q.pop_front();
        }
        if q.len() >= *threshold as usize {
            let seqs: Vec<u64> = q.iter().map(|(_, s)| *s).collect();
            let n = seqs.len();
            q.clear();
            return Some((group, seqs, n, v.clone()));
        }
        None
    }

    fn sequence(
        &mut self,
        i: usize,
        v: &Value,
        seq: u64,
        now: u64,
        root: Option<&str>,
    ) -> Option<(String, Vec<u64>, usize, Value)> {
        let r = &self.set.rules[i];
        let Some(Correlation::Sequence {
            steps,
            scope,
            window_ns,
        }) = &r.correlation
        else {
            return None;
        };
        let kind = kind_of(v);
        let group = match scope {
            Scope::Host => String::new(),
            Scope::Session => {
                let ses = text_at(v, &["actor".into(), "ses".into()]);
                if ses.is_empty() {
                    text_at(v, &["actor".into(), "puid".into()])
                } else {
                    format!("ses:{ses}")
                }
            }
            Scope::Process => text_at(v, &["actor".into(), "puid".into()]),
            Scope::Tree => format!("tree:{}", root.unwrap_or_default()),
        };
        let st = &mut self.state[i];
        if st.partials.len() >= MAX_GROUPS && !st.partials.contains_key(&group) {
            st.partials.clear();
            self.stats.state_evicted += 1;
        }
        let list = st.partials.entry(group.clone()).or_default();
        list.retain(|p| now.saturating_sub(p.started_ns) <= *window_ns);

        let step_matches = |step: &Step, p: Option<&Partial>| -> bool {
            if !step.kinds.iter().any(|k| k == kind) {
                return false;
            }
            let Some(n) = step.node.as_ref() else {
                return true;
            };
            let pairs: Vec<(&str, &Value)> = p
                .map(|p| {
                    steps
                        .iter()
                        .zip(p.events.iter())
                        .map(|(s, e)| (s.id.as_str(), e))
                        .collect()
                })
                .unwrap_or_default();
            eval_node(n, v, Binds(&pairs))
        };

        // Advance existing partials first so one event cannot both advance and start a match.
        let mut done: Option<Partial> = None;
        for p in list.iter_mut() {
            if p.next < steps.len() && step_matches(&steps[p.next], Some(p)) {
                p.events.push(v.clone());
                p.seqs.push(seq);
                p.next += 1;
                if p.next == steps.len() {
                    done = Some(Partial {
                        next: p.next,
                        started_ns: p.started_ns,
                        events: p.events.clone(),
                        seqs: p.seqs.clone(),
                    });
                    break;
                }
            }
        }
        if let Some(d) = done {
            list.retain(|p| p.next < steps.len());
            return Some((group, d.seqs, steps.len(), v.clone()));
        }
        if step_matches(&steps[0], None) && list.len() < MAX_PARTIALS {
            list.push(Partial {
                next: 1,
                started_ns: now,
                events: vec![v.clone()],
                seqs: vec![seq],
            });
        }
        None
    }

    fn alert(
        &mut self,
        i: usize,
        group: &str,
        seqs: Vec<u64>,
        n: usize,
        last: &Value,
        now: u64,
    ) -> Option<Alert> {
        let r: &Rule = &self.set.rules[i];
        let st = &mut self.state[i];
        let key = if group.is_empty() {
            lookup(last, &["actor".into(), "puid".into()])
                .and_then(crate::ops::as_text)
                .unwrap_or_default()
        } else {
            group.to_string()
        };
        let mut swallowed = 0;
        if let Some((t, c)) = st.suppress.get_mut(&key) {
            if now.saturating_sub(*t) < r.suppress_ns {
                *c += 1;
                self.stats.suppressed += 1;
                return None;
            }
            swallowed = *c;
        }
        if st.suppress.len() >= MAX_GROUPS {
            st.suppress.clear();
        }
        st.suppress.insert(key, (now, 0));

        let mut detail = serde_json::Map::new();
        detail.insert("matches".into(), json!(n));
        if !group.is_empty() {
            detail.insert("group".into(), json!(group.replace('\u{1f}', " | ")));
        }
        if swallowed > 0 {
            detail.insert("suppressed_since_last".into(), json!(swallowed));
        }
        for f in &r.alert_fields {
            if let Some(x) = lookup(last, f) {
                detail.insert(f.join("."), x.clone());
            }
        }
        self.stats.alerts += 1;
        let trigger = seqs.last().copied().unwrap_or(0);
        Some(Alert {
            alert_id: format!("{}-{}", r.id, trigger),
            rule_id: r.id.clone(),
            rule_sha256: r.sha256.clone(),
            title: r.title.clone(),
            severity: r.severity,
            trigger_seqs: seqs,
            session: lookup(last, &["actor".into(), "ses".into()])
                .and_then(Value::as_u64)
                .map(|s| s as u32),
            detail: Value::Object(detail),
        })
    }
}
