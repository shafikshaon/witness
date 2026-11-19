//! YAML → typed rule tree, with load-time validation (DESIGN.md §8.1, §8.3).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use globset::{GlobBuilder, GlobSetBuilder};
use regex::RegexSetBuilder;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use witness_common::schema::Severity;

use crate::ops::{Cidr, CmpOp, Op, Operand};

/// A rule that could not be loaded, with where and why.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{file}{loc}: {msg}", loc = location(*.line, *.col))]
pub struct RuleError {
    pub file: String,
    pub line: Option<usize>,
    pub col: Option<usize>,
    pub msg: String,
}

fn location(line: Option<usize>, col: Option<usize>) -> String {
    match (line, col) {
        (Some(l), Some(c)) => format!(":{l}:{c}"),
        (Some(l), None) => format!(":{l}"),
        _ => String::new(),
    }
}

// ---- raw (YAML) form -------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    id: String,
    title: String,
    #[serde(default)]
    description: String,
    severity: Severity,
    #[serde(default = "yes")]
    enabled: bool,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    event: Option<OneOrMany>,
    #[serde(default, rename = "match")]
    matcher: Option<RawNode>,
    #[serde(default)]
    correlate: Option<RawCorrelate>,
    #[serde(default)]
    alert: Option<RawAlert>,
}

fn yes() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    fn into_vec(self) -> Vec<String> {
        match self {
            OneOrMany::One(s) => vec![s],
            OneOrMany::Many(v) => v,
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawNode {
    All { all: Vec<RawNode> },
    Any { any: Vec<RawNode> },
    Not { not: Box<RawNode> },
    Cond(RawCond),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCond {
    field: String,
    op: String,
    #[serde(default)]
    value: Option<Value>,
    #[serde(default)]
    ci: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCorrelate {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    group_by: Vec<String>,
    window: String,
    #[serde(default)]
    threshold: Option<u32>,
    #[serde(default)]
    steps: Vec<RawStep>,
    #[serde(default)]
    scope: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStep {
    id: String,
    event: OneOrMany,
    #[serde(default, rename = "match")]
    matcher: Option<RawNode>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawAlert {
    #[serde(default)]
    fields: Vec<String>,
    #[serde(default)]
    suppress: Option<String>,
}

// ---- compiled form ---------------------------------------------------------------------

#[derive(Debug)]
pub struct Cond {
    pub path: Vec<String>,
    pub op: Op,
    pub ci: bool,
}

#[derive(Debug)]
pub enum Node {
    All(Vec<Node>),
    Any(Vec<Node>),
    Not(Box<Node>),
    Cond(Cond),
}

#[derive(Debug)]
pub struct Step {
    pub id: String,
    pub kinds: Vec<String>,
    pub node: Option<Node>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Steps must come from the same process (`actor.puid`).
    Process,
    /// Steps must come from the same login session (`actor.ses`), falling back to the process.
    Session,
    /// Steps must come from the same process tree: the engine follows `pid`/`ppid` across
    /// events and ties a process to its topmost known ancestor.
    Tree,
    /// No tie: any events on the host within the window.
    Host,
}

#[derive(Debug)]
pub enum Correlation {
    Count {
        group_by: Vec<Vec<String>>,
        window_ns: u64,
        threshold: u32,
    },
    Sequence {
        steps: Vec<Step>,
        scope: Scope,
        window_ns: u64,
    },
}

#[derive(Debug)]
pub struct Rule {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub tags: Vec<String>,
    pub enabled: bool,
    pub kinds: Vec<String>,
    pub node: Option<Node>,
    pub correlation: Option<Correlation>,
    pub alert_fields: Vec<Vec<String>>,
    pub suppress_ns: u64,
    /// SHA-256 of the rule file's exact bytes.
    pub sha256: String,
    pub file: String,
}

/// The rules in force, indexed by the event kinds they evaluate.
#[derive(Debug, Default)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
    pub by_kind: HashMap<String, Vec<usize>>,
    /// Rules with no `event` filter (sequences index their steps instead).
    pub sha256: String,
}

#[derive(Debug, Default)]
pub struct LoadResult {
    pub set: RuleSet,
    pub errors: Vec<RuleError>,
}

const ROOTS: [&str; 9] = [
    "actor", "data", "type", "prio", "src", "seq", "boot_ns", "wall_ns", "boot_id",
];

fn path_of(field: &str) -> Result<Vec<String>, String> {
    let p: Vec<String> = field.split('.').map(String::from).collect();
    if p.iter().any(String::is_empty) || !ROOTS.contains(&p[0].as_str()) {
        return Err(format!(
            "unknown field `{field}` (fields start with one of: {})",
            ROOTS.join(", ")
        ));
    }
    Ok(p)
}

/// Parses `60s`, `5m`, `2h`, `1d`.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    let (n, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u64 = n.parse().map_err(|_| format!("bad duration `{s}`"))?;
    let secs = match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        "d" => n * 86_400,
        _ => return Err(format!("bad duration `{s}` (use 30s, 5m, 2h or 1d)")),
    };
    Ok(Duration::from_secs(secs))
}

fn strings(v: &Value, what: &str) -> Result<Vec<String>, String> {
    let items = match v {
        Value::Array(a) => a.clone(),
        other => vec![other.clone()],
    };
    items
        .iter()
        .map(|i| crate::ops::as_text(i).ok_or_else(|| format!("`{what}` takes text or numbers")))
        .collect()
}

fn operand(v: &Value, steps: &[String]) -> Result<Operand, String> {
    if let Value::String(s) = v {
        if let Some(r) = s.strip_prefix('$') {
            let mut parts = r.split('.');
            let step = parts.next().unwrap_or_default().to_string();
            if !steps.contains(&step) {
                return Err(format!(
                    "`${r}` refers to an unknown or later step `{step}`"
                ));
            }
            let path: Vec<String> = parts.map(String::from).collect();
            path_of(&path.join("."))?;
            return Ok(Operand::Ref { step, path });
        }
    }
    Ok(Operand::Lit(v.clone()))
}

fn compile_cond(c: RawCond, steps: &[String]) -> Result<Cond, String> {
    let path = path_of(&c.field)?;
    let need = |v: &Option<Value>| {
        v.clone()
            .ok_or_else(|| format!("operator `{}` needs a `value`", c.op))
    };
    let ci = c.ci;
    let op = match c.op.as_str() {
        "eq" | "ne" | "in" => {
            let v = need(&c.value)?;
            let list = match &v {
                Value::Array(a) => a.clone(),
                other => vec![other.clone()],
            };
            let ops = list
                .iter()
                .map(|x| operand(x, steps))
                .collect::<Result<Vec<_>, _>>()?;
            match c.op.as_str() {
                "eq" => Op::Eq(ops),
                "ne" => Op::Ne(ops),
                _ => Op::In(ops),
            }
        }
        "contains" | "startswith" | "endswith" => {
            let mut l = strings(&need(&c.value)?, &c.op)?;
            if ci {
                l.iter_mut().for_each(|s| *s = s.to_lowercase());
            }
            match c.op.as_str() {
                "contains" => Op::Contains(l),
                "startswith" => Op::StartsWith(l),
                _ => Op::EndsWith(l),
            }
        }
        "regex" => {
            let pats = strings(&need(&c.value)?, "regex")?;
            let set = RegexSetBuilder::new(&pats)
                .case_insensitive(ci)
                .size_limit(1 << 22)
                .build()
                .map_err(|e| format!("bad regex: {e}"))?;
            Op::Regex(set)
        }
        "glob" => {
            let pats = strings(&need(&c.value)?, "glob")?;
            let mut b = GlobSetBuilder::new();
            for p in &pats {
                let g = GlobBuilder::new(p)
                    .literal_separator(true)
                    .case_insensitive(ci)
                    .build()
                    .map_err(|e| format!("bad glob `{p}`: {e}"))?;
                b.add(g);
            }
            Op::Glob(b.build().map_err(|e| format!("bad glob set: {e}"))?)
        }
        "cidr" => {
            let nets = strings(&need(&c.value)?, "cidr")?
                .iter()
                .map(|s| Cidr::parse(s).ok_or_else(|| format!("bad network `{s}`")))
                .collect::<Result<Vec<_>, _>>()?;
            Op::Cidr(nets)
        }
        "gt" | "gte" | "lt" | "lte" => {
            let n = need(&c.value)?
                .as_f64()
                .ok_or_else(|| format!("`{}` needs a number", c.op))?;
            let cmp = match c.op.as_str() {
                "gt" => CmpOp::Gt,
                "gte" => CmpOp::Gte,
                "lt" => CmpOp::Lt,
                _ => CmpOp::Lte,
            };
            Op::Cmp(cmp, n)
        }
        "exists" => Op::Exists(c.value.as_ref().and_then(Value::as_bool).unwrap_or(true)),
        other => return Err(format!("unknown operator `{other}`")),
    };
    Ok(Cond { path, op, ci })
}

fn compile_node(n: RawNode, steps: &[String]) -> Result<Node, String> {
    Ok(match n {
        RawNode::All { all } => Node::All(
            all.into_iter()
                .map(|x| compile_node(x, steps))
                .collect::<Result<_, _>>()?,
        ),
        RawNode::Any { any } => Node::Any(
            any.into_iter()
                .map(|x| compile_node(x, steps))
                .collect::<Result<_, _>>()?,
        ),
        RawNode::Not { not } => Node::Not(Box::new(compile_node(*not, steps)?)),
        RawNode::Cond(c) => Node::Cond(compile_cond(c, steps)?),
    })
}

fn compile_correlate(c: RawCorrelate) -> Result<Correlation, String> {
    let window_ns = parse_duration(&c.window)?.as_nanos() as u64;
    match c.kind.as_str() {
        "count" => {
            let threshold = c
                .threshold
                .filter(|t| *t >= 1)
                .ok_or("`count` needs a `threshold` of at least 1")?;
            let group_by = c
                .group_by
                .iter()
                .map(|g| path_of(g))
                .collect::<Result<_, _>>()?;
            Ok(Correlation::Count {
                group_by,
                window_ns,
                threshold,
            })
        }
        "sequence" => {
            if c.steps.len() < 2 {
                return Err("a `sequence` needs at least two steps".into());
            }
            let scope = match c.scope.as_deref().unwrap_or("same_session") {
                "same_process" => Scope::Process,
                "same_session" => Scope::Session,
                "same_tree" => Scope::Tree,
                "same_host" => Scope::Host,
                other => return Err(format!("unknown scope `{other}`")),
            };
            let mut seen: Vec<String> = Vec::new();
            let mut steps = Vec::new();
            for s in c.steps {
                if seen.contains(&s.id) {
                    return Err(format!("duplicate step id `{}`", s.id));
                }
                let node = s.matcher.map(|m| compile_node(m, &seen)).transpose()?;
                seen.push(s.id.clone());
                steps.push(Step {
                    id: s.id,
                    kinds: s.event.into_vec(),
                    node,
                });
            }
            Ok(Correlation::Sequence {
                steps,
                scope,
                window_ns,
            })
        }
        other => Err(format!("unknown correlation type `{other}`")),
    }
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}

/// Compiles one rule file's text. `file` is only used for messages.
pub fn compile_rule(text: &str, file: &str) -> Result<Rule, RuleError> {
    let err = |line: Option<usize>, col: Option<usize>, msg: String| RuleError {
        file: file.into(),
        line,
        col,
        msg,
    };
    let raw: RawRule = serde_yaml_ng::from_str(text).map_err(|e| {
        let loc = e.location();
        err(
            loc.as_ref().map(|l| l.line()),
            loc.as_ref().map(|l| l.column()),
            e.to_string(),
        )
    })?;
    let fail = |m: String| err(None, None, m);
    if !valid_id(&raw.id) {
        return Err(fail(format!("id `{}` must match [a-z0-9._-]+", raw.id)));
    }
    let kinds = raw.event.map(OneOrMany::into_vec).unwrap_or_default();
    let node = raw
        .matcher
        .map(|m| compile_node(m, &[]))
        .transpose()
        .map_err(fail)?;
    let correlation = raw
        .correlate
        .map(compile_correlate)
        .transpose()
        .map_err(fail)?;
    let is_sequence = matches!(correlation, Some(Correlation::Sequence { .. }));
    if kinds.is_empty() && !is_sequence {
        return Err(fail(
            "the rule needs an `event` (one kind or a list)".into(),
        ));
    }
    if is_sequence && (!kinds.is_empty() || node.is_some()) {
        return Err(fail(
            "a sequence rule puts `event` and `match` on its steps, not on the rule".into(),
        ));
    }
    let alert = raw.alert.unwrap_or_default();
    let alert_fields = alert
        .fields
        .iter()
        .map(|f| path_of(f))
        .collect::<Result<_, _>>()
        .map_err(fail)?;
    let suppress_ns = match alert.suppress {
        Some(s) => parse_duration(&s).map_err(fail)?.as_nanos() as u64,
        None => 0,
    };
    Ok(Rule {
        id: raw.id,
        title: raw.title,
        description: raw.description,
        severity: raw.severity,
        tags: raw.tags,
        enabled: raw.enabled,
        kinds,
        node,
        correlation,
        alert_fields,
        suppress_ns,
        sha256: hex(&Sha256::digest(text.as_bytes())),
        file: file.into(),
    })
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn build_set(mut rules: Vec<Rule>) -> RuleSet {
    rules.sort_by(|a, b| a.id.cmp(&b.id));
    let mut by_kind: HashMap<String, Vec<usize>> = HashMap::new();
    let mut h = Sha256::new();
    for (i, r) in rules.iter().enumerate() {
        h.update(r.id.as_bytes());
        h.update(r.sha256.as_bytes());
        if !r.enabled {
            continue;
        }
        let mut kinds: Vec<&String> = r.kinds.iter().collect();
        if let Some(Correlation::Sequence { steps, .. }) = &r.correlation {
            kinds.extend(steps.iter().flat_map(|s| s.kinds.iter()));
        }
        for k in kinds {
            let v = by_kind.entry(k.clone()).or_default();
            if !v.contains(&i) {
                v.push(i);
            }
        }
    }
    RuleSet {
        rules,
        by_kind,
        sha256: hex(&h.finalize()),
    }
}

/// Loads rules from `(file name, text)` pairs. A bad file is reported and skipped; the rest
/// still load. Duplicate ids reject the later file.
pub fn load_str<'a>(files: impl IntoIterator<Item = (&'a str, &'a str)>) -> LoadResult {
    let mut rules: Vec<Rule> = Vec::new();
    let mut errors = Vec::new();
    for (name, text) in files {
        match compile_rule(text, name) {
            Ok(r) if rules.iter().any(|x| x.id == r.id) => errors.push(RuleError {
                file: name.into(),
                line: None,
                col: None,
                msg: format!("duplicate rule id `{}`", r.id),
            }),
            Ok(r) => rules.push(r),
            Err(e) => errors.push(e),
        }
    }
    LoadResult {
        set: build_set(rules),
        errors,
    }
}

/// Loads every `*.yml`/`*.yaml` file under `dir` (non-recursive, sorted).
pub fn load_dir(dir: &Path) -> std::io::Result<LoadResult> {
    let mut files: Vec<(PathBuf, String)> = Vec::new();
    for e in std::fs::read_dir(dir)? {
        let p = e?.path();
        let ok = p
            .extension()
            .and_then(|x| x.to_str())
            .is_some_and(|x| x == "yml" || x == "yaml");
        if ok && p.is_file() {
            if let Ok(t) = std::fs::read_to_string(&p) {
                files.push((p, t));
            }
        }
    }
    files.sort();
    let names: Vec<String> = files
        .iter()
        .map(|(p, _)| {
            p.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        })
        .collect();
    Ok(load_str(
        names
            .iter()
            .map(String::as_str)
            .zip(files.iter().map(|(_, t)| t.as_str())),
    ))
}
