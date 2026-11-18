//! Condition operators and the values they compare.

use std::net::IpAddr;

use globset::GlobSet;
use regex::RegexSet;
use serde_json::Value;

/// An IP network, `addr/len`.
#[derive(Clone, Debug)]
pub struct Cidr {
    addr: IpAddr,
    len: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Option<Cidr> {
        let (a, l) = match s.split_once('/') {
            Some((a, l)) => (a, Some(l)),
            None => (s, None),
        };
        let addr: IpAddr = a.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let len = match l {
            Some(l) => l.parse().ok().filter(|n| *n <= max)?,
            None => max,
        };
        Some(Cidr { addr, len })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let (a, b): (u128, u128) = match (self.addr, ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) => (u32::from(a) as u128, u32::from(b) as u128),
            (IpAddr::V6(a), IpAddr::V6(b)) => (u128::from(a), u128::from(b)),
            _ => return false,
        };
        let bits: u32 = if self.addr.is_ipv4() { 32 } else { 128 };
        let shift = bits - self.len as u32;
        shift >= 128 || (a >> shift) == (b >> shift)
    }
}

/// A comparison operand: a literal, or a `$step.field` reference to an earlier sequence step.
#[derive(Clone, Debug)]
pub enum Operand {
    Lit(Value),
    Ref { step: String, path: Vec<String> },
}

#[derive(Debug)]
pub enum Op {
    Eq(Vec<Operand>),
    Ne(Vec<Operand>),
    In(Vec<Operand>),
    Contains(Vec<String>),
    StartsWith(Vec<String>),
    EndsWith(Vec<String>),
    Regex(RegexSet),
    Glob(GlobSet),
    Cidr(Vec<Cidr>),
    Cmp(CmpOp, f64),
    Exists(bool),
}

#[derive(Clone, Copy, Debug)]
pub enum CmpOp {
    Gt,
    Gte,
    Lt,
    Lte,
}

/// A scalar rendered as text for string operators. Arrays are handled by the caller.
pub fn as_text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

pub fn lookup<'a>(root: &'a Value, path: &[String]) -> Option<&'a Value> {
    let mut v = root;
    for p in path {
        v = match v {
            Value::Object(m) => m.get(p)?,
            Value::Array(a) => a.get(p.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    (!v.is_null()).then_some(v)
}

/// Values a condition is tested against: an array field is tested element by element.
pub fn candidates(v: &Value) -> Vec<&Value> {
    match v {
        Value::Array(a) => a.iter().collect(),
        other => vec![other],
    }
}

fn same(a: &Value, b: &Value, ci: bool) -> bool {
    if a == b {
        return true;
    }
    match (as_text(a), as_text(b)) {
        (Some(x), Some(y)) => {
            if ci {
                x.to_lowercase() == y.to_lowercase()
            } else {
                x == y
            }
        }
        _ => false,
    }
}

/// Events already matched by earlier sequence steps, by step id.
#[derive(Clone, Copy, Default)]
pub struct Binds<'a>(pub &'a [(&'a str, &'a Value)]);

impl<'a> Binds<'a> {
    fn get(&self, name: &str) -> Option<&'a Value> {
        self.0.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
    }
}

/// Resolves operands: literals as themselves, `$step.field` from the bound events.
pub fn resolve<'a>(ops: &'a [Operand], binds: Binds<'a>) -> Vec<&'a Value> {
    ops.iter()
        .filter_map(|o| match o {
            Operand::Lit(v) => Some(v),
            Operand::Ref { step, path } => lookup(binds.get(step)?, path),
        })
        .collect()
}

impl Op {
    /// Tests one scalar value.
    pub fn test(&self, v: &Value, ci: bool, binds: Binds<'_>) -> bool {
        let text = |s: &String| if ci { s.to_lowercase() } else { s.clone() };
        match self {
            Op::Eq(o) | Op::In(o) => resolve(o, binds).into_iter().any(|x| same(v, x, ci)),
            Op::Ne(o) => !resolve(o, binds).into_iter().any(|x| same(v, x, ci)),
            Op::Contains(l) => as_text(v).is_some_and(|s| {
                let s = text(&s);
                l.iter().any(|n| s.contains(n.as_str()))
            }),
            Op::StartsWith(l) => as_text(v).is_some_and(|s| {
                let s = text(&s);
                l.iter().any(|n| s.starts_with(n.as_str()))
            }),
            Op::EndsWith(l) => as_text(v).is_some_and(|s| {
                let s = text(&s);
                l.iter().any(|n| s.ends_with(n.as_str()))
            }),
            Op::Regex(r) => as_text(v).is_some_and(|s| r.is_match(&s)),
            Op::Glob(g) => as_text(v).is_some_and(|s| g.is_match(&s)),
            Op::Cidr(nets) => as_text(v)
                .and_then(|s| s.parse::<IpAddr>().ok())
                .is_some_and(|ip| nets.iter().any(|n| n.contains(ip))),
            Op::Cmp(c, n) => v.as_f64().is_some_and(|x| match c {
                CmpOp::Gt => x > *n,
                CmpOp::Gte => x >= *n,
                CmpOp::Lt => x < *n,
                CmpOp::Lte => x <= *n,
            }),
            Op::Exists(_) => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_membership() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains("10.9.8.7".parse().unwrap()));
        assert!(!c.contains("11.0.0.1".parse().unwrap()));
        assert!(!c.contains("::1".parse().unwrap()));
        assert!(Cidr::parse("fe80::/10")
            .unwrap()
            .contains("fe80::1".parse().unwrap()));
        assert!(Cidr::parse("1.2.3.4")
            .unwrap()
            .contains("1.2.3.4".parse().unwrap()));
        assert!(Cidr::parse("0.0.0.0/0")
            .unwrap()
            .contains("8.8.8.8".parse().unwrap()));
        assert!(Cidr::parse("1.2.3.4/33").is_none());
    }
}
