//! DNS wire-format parsing for packets captured in the kernel (RFC 1035, with RFC 3596 AAAA).
//!
//! The parser is total: malformed or truncated input yields whatever was readable, never a
//! panic. Name compression pointers are followed with a hop limit so loops cannot spin.

use std::net::{Ipv4Addr, Ipv6Addr};

use witness_common::schema::DnsAnswer;

/// What was read out of one packet.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Parsed {
    pub id: u16,
    pub is_response: bool,
    pub rcode: Option<String>,
    pub qname: String,
    pub qtype: String,
    pub answers: Vec<DnsAnswer>,
}

const MAX_HOPS: usize = 16;
const MAX_ANSWERS: usize = 32;

fn rtype_name(t: u16) -> String {
    match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        64 => "SVCB",
        65 => "HTTPS",
        255 => "ANY",
        other => return format!("TYPE{other}"),
    }
    .to_string()
}

fn rcode_name(c: u8) -> String {
    match c {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        other => return format!("RCODE{other}"),
    }
    .to_string()
}

/// Reads a possibly compressed name starting at `pos`; returns it and the offset just past
/// its in-place encoding.
fn name_at(pkt: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut out = String::new();
    let mut end = None;
    let mut hops = 0;
    loop {
        let len = *pkt.get(pos)? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            let low = *pkt.get(pos + 1)? as usize;
            end.get_or_insert(pos + 2);
            hops += 1;
            if hops > MAX_HOPS {
                return None;
            }
            pos = ((len & 0x3F) << 8) | low;
            continue;
        }
        if len > 63 {
            return None;
        }
        let label = pkt.get(pos + 1..pos + 1 + len)?;
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(&String::from_utf8_lossy(label).to_ascii_lowercase());
        pos += 1 + len;
        if out.len() > 255 {
            return None;
        }
    }
    Some((out, end.unwrap_or(pos)))
}

fn rdata(pkt: &[u8], rtype: u16, at: usize, len: usize) -> String {
    let Some(data) = pkt.get(at..at + len) else {
        return String::new();
    };
    match (rtype, len) {
        (1, 4) => Ipv4Addr::new(data[0], data[1], data[2], data[3]).to_string(),
        (28, 16) => {
            let mut b = [0u8; 16];
            b.copy_from_slice(data);
            Ipv6Addr::from(b).to_string()
        }
        (2 | 5 | 12, _) => name_at(pkt, at).map(|(n, _)| n).unwrap_or_default(),
        (15, _) if len > 2 => name_at(pkt, at + 2).map(|(n, _)| n).unwrap_or_default(),
        (16, _) => {
            // TXT: length-prefixed strings; show them joined.
            let mut s = String::new();
            let mut i = 0;
            while i < data.len() {
                let n = data[i] as usize;
                if let Some(chunk) = data.get(i + 1..i + 1 + n) {
                    s.push_str(&String::from_utf8_lossy(chunk));
                }
                i += 1 + n;
            }
            s
        }
        _ => String::new(),
    }
}

/// Parses one DNS packet. Returns `None` only when there is not even a header.
pub fn parse(pkt: &[u8]) -> Option<Parsed> {
    if pkt.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([pkt[0], pkt[1]]);
    let flags = u16::from_be_bytes([pkt[2], pkt[3]]);
    let qd = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    let an = u16::from_be_bytes([pkt[6], pkt[7]]) as usize;
    let is_response = flags & 0x8000 != 0;
    let mut p = Parsed {
        id,
        is_response,
        rcode: is_response.then(|| rcode_name((flags & 0xF) as u8)),
        ..Parsed::default()
    };

    let mut pos = 12;
    for i in 0..qd.min(1) {
        let Some((name, next)) = name_at(pkt, pos) else {
            return Some(p);
        };
        let Some(t) = pkt.get(next..next + 4) else {
            return Some(p);
        };
        if i == 0 {
            p.qname = name;
            p.qtype = rtype_name(u16::from_be_bytes([t[0], t[1]]));
        }
        pos = next + 4;
    }
    for _ in 0..an.min(MAX_ANSWERS) {
        let Some((name, next)) = name_at(pkt, pos) else {
            break;
        };
        let Some(h) = pkt.get(next..next + 10) else {
            break;
        };
        let rtype = u16::from_be_bytes([h[0], h[1]]);
        let ttl = u32::from_be_bytes([h[4], h[5], h[6], h[7]]);
        let rdlen = u16::from_be_bytes([h[8], h[9]]) as usize;
        let at = next + 10;
        if pkt.len() < at + rdlen {
            break;
        }
        p.answers.push(DnsAnswer {
            name,
            rtype: rtype_name(rtype),
            ttl,
            data: rdata(pkt, rtype, at, rdlen),
        });
        pos = at + rdlen;
    }
    Some(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut v = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in name.split('.') {
            v.push(l.len() as u8);
            v.extend(l.as_bytes());
        }
        v.push(0);
        v.extend(qtype.to_be_bytes());
        v.extend([0, 1]);
        v
    }

    #[test]
    fn parses_a_query() {
        let p = parse(&query("Example.COM", 1)).unwrap();
        assert_eq!((p.id, p.is_response), (0x1234, false));
        assert_eq!((p.qname.as_str(), p.qtype.as_str()), ("example.com", "A"));
        assert!(p.answers.is_empty() && p.rcode.is_none());
    }

    #[test]
    fn parses_a_compressed_answer() {
        let mut v = query("example.com", 1);
        v[2] = 0x81;
        v[3] = 0x80;
        v[7] = 1;
        v.extend([0xC0, 12, 0, 1, 0, 1, 0, 0, 1, 0x2C, 0, 4, 93, 184, 216, 34]);
        let p = parse(&v).unwrap();
        assert_eq!(p.rcode.as_deref(), Some("NOERROR"));
        assert_eq!(p.answers.len(), 1);
        let a = &p.answers[0];
        assert_eq!(
            (a.name.as_str(), a.rtype.as_str(), a.ttl, a.data.as_str()),
            ("example.com", "A", 300, "93.184.216.34")
        );
    }

    #[test]
    fn nxdomain_is_reported() {
        let mut v = query("nope.invalid", 28);
        v[2] = 0x81;
        v[3] = 0x83;
        let p = parse(&v).unwrap();
        assert_eq!(p.rcode.as_deref(), Some("NXDOMAIN"));
        assert_eq!(p.qtype, "AAAA");
    }

    #[test]
    fn hostile_input_never_panics() {
        assert!(parse(&[1, 2, 3]).is_none());
        // A compression pointer pointing at itself.
        let mut v = query("a.b", 1);
        v[12] = 0xC0;
        v[13] = 12;
        assert!(parse(&v).is_some());
        // Truncated at every length.
        let full = query("example.com", 1);
        for n in 0..full.len() {
            let _ = parse(&full[..n]);
        }
    }
}
