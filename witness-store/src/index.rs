//! SQLite query index (DESIGN.md §5.5). Always rebuildable from the segments; if the two
//! ever disagree, the segments (the chain) win.

use std::io::BufRead;
use std::path::{Path, PathBuf};

use rusqlite::{params, params_from_iter, types::Value as Sql, Connection, OptionalExtension};
use serde_json::Value;

use crate::chain::{self, Hash, GENESIS};
use crate::error::{Result, StoreError};
use crate::segment::{self, SegmentInfo};

const BATCH: u64 = 5000;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events(
  seq INTEGER PRIMARY KEY,
  kind TEXT NOT NULL,
  boot_ns INTEGER, wall_ns INTEGER,
  pid INTEGER, tid INTEGER, ppid INTEGER,
  uid INTEGER, euid INTEGER, auid INTEGER, ses INTEGER,
  cgroup_id INTEGER, puid TEXT,
  seg_id INTEGER NOT NULL, seg_off INTEGER NOT NULL, len INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS events_wall ON events(wall_ns);
CREATE INDEX IF NOT EXISTS events_kind ON events(kind, seq);
CREATE INDEX IF NOT EXISTS events_puid ON events(puid, seq);
CREATE INDEX IF NOT EXISTS events_uid  ON events(uid, seq);
CREATE INDEX IF NOT EXISTS events_ses  ON events(ses, seq);
CREATE VIRTUAL TABLE IF NOT EXISTS fts USING fts5(cmdline, path, name, content='');
";

#[derive(Debug, Clone, Default)]
pub struct Filter {
    pub kinds: Vec<String>,
    pub wall_from: Option<u64>,
    pub wall_to: Option<u64>,
    pub pid: Option<u32>,
    pub uid: Option<u32>,
    pub puid: Option<String>,
    pub ses: Option<u32>,
    /// Plain-text search over cmdline, path and name. Whitespace-separated words must all
    /// match; a trailing `*` makes a word a prefix. Characters such as `-` or `"` are
    /// literal text, never query syntax.
    pub text: Option<String>,
    /// Keyset cursor: return events with `seq` strictly below this (newest-first order).
    pub before_seq: Option<u64>,
    /// Return events with `seq` strictly above this, oldest first (for following live data).
    pub after_seq: Option<u64>,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRow {
    pub seq: u64,
    pub kind: String,
    pub boot_ns: Option<u64>,
    pub wall_ns: Option<u64>,
    pub pid: Option<u32>,
    pub uid: Option<u32>,
    pub puid: Option<String>,
    pub seg_id: u64,
    pub seg_off: u64,
    pub len: u64,
}

pub struct Index {
    conn: Connection,
}

impl Index {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).map_err(db)?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(db)?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(db)?;
        conn.execute_batch(SCHEMA).map_err(db)?;
        Ok(Index { conn })
    }

    /// `(last indexed seq, chain head at that seq)`; `(0, GENESIS)` when empty.
    pub fn position(&self) -> Result<(u64, Hash)> {
        let get = |k: &str| -> Result<Option<String>> {
            self.conn
                .query_row("SELECT value FROM meta WHERE key=?1", [k], |r| r.get(0))
                .optional()
                .map_err(db)
        };
        let seq = get("last_seq")?.and_then(|s| s.parse().ok()).unwrap_or(0);
        let head = get("last_head")?
            .and_then(|s| chain::from_hex(s.as_bytes()))
            .unwrap_or(GENESIS);
        Ok((seq, head))
    }

    /// Indexes everything after the current position. Verifies the hash chain as it goes
    /// and fails (without advancing past the problem) if the segments do not continue it.
    pub fn catch_up(&mut self, seg_dir: &Path) -> Result<u64> {
        self.catch_up_dirs(&[seg_dir.to_path_buf()])
    }

    /// Like [`Index::catch_up`] over live data plus archive directories.
    pub fn catch_up_dirs(&mut self, dirs: &[PathBuf]) -> Result<u64> {
        let (mut last, mut head) = self.position()?;
        let segs = segment::list_segments_in(dirs)?;
        let start = segs
            .iter()
            .rposition(|s| s.first_seq <= last + 1)
            .unwrap_or(0);
        let mut indexed = 0u64;
        let mut tx = self.conn.transaction().map_err(db)?;
        let mut pending = 0u64;
        for seg in &segs[start..] {
            let mut reader = segment::open_reader(seg)?;
            let mut buf = Vec::new();
            let mut offset = 0u64;
            loop {
                buf.clear();
                let n = reader.read_until(b'\n', &mut buf)?;
                if n == 0 {
                    break;
                }
                let line_off = offset;
                offset += n as u64;
                if buf.last() != Some(&b'\n') {
                    break; // torn tail: not yet a record
                }
                let line = &buf[..buf.len() - 1];
                let (body, h) = chain::decode_line(line)?;
                let v: Value = serde_json::from_slice(&body)?;
                let seq = v["seq"]
                    .as_u64()
                    .ok_or_else(|| StoreError::Corrupt("record without seq".into()))?;
                if seq <= last {
                    continue;
                }
                if last == 0 && seq != 1 {
                    // Pruned history: take the recorded predecessor head on trust.
                    if let Some(p) = v["prev_head"]
                        .as_str()
                        .and_then(|s| chain::from_hex(s.as_bytes()))
                    {
                        head = p;
                    }
                } else if seq != last + 1 {
                    return Err(StoreError::Corrupt(format!(
                        "index expected seq {} but segments continue at {seq}",
                        last + 1
                    )));
                }
                if chain::link(&head, &body) != h {
                    return Err(StoreError::Corrupt(format!(
                        "hash chain break at seq {seq} while indexing"
                    )));
                }
                insert_event(&tx, &v, seq, seg, line_off, line.len() as u64)?;
                last = seq;
                head = h;
                indexed += 1;
                pending += 1;
                if pending >= BATCH {
                    save_position(&tx, last, &head)?;
                    tx.commit().map_err(db)?;
                    tx = self.conn.transaction().map_err(db)?;
                    pending = 0;
                }
            }
        }
        save_position(&tx, last, &head)?;
        tx.commit().map_err(db)?;
        Ok(indexed)
    }

    /// Keyset-paginated query, newest first.
    pub fn query(&self, f: &Filter) -> Result<Vec<EventRow>> {
        let mut clauses: Vec<String> = Vec::new();
        let mut args: Vec<Sql> = Vec::new();
        if !f.kinds.is_empty() {
            let marks = vec!["?"; f.kinds.len()].join(",");
            clauses.push(format!("kind IN ({marks})"));
            args.extend(f.kinds.iter().cloned().map(Sql::Text));
        }
        let mut and = |clause: &str, v: Sql| {
            clauses.push(clause.to_string());
            args.push(v);
        };
        if let Some(v) = f.wall_from {
            and("wall_ns >= ?", Sql::Integer(v as i64));
        }
        if let Some(v) = f.wall_to {
            and("wall_ns < ?", Sql::Integer(v as i64));
        }
        if let Some(v) = f.pid {
            and("pid = ?", Sql::Integer(v.into()));
        }
        if let Some(v) = f.uid {
            and("uid = ?", Sql::Integer(v.into()));
        }
        if let Some(v) = &f.puid {
            and("puid = ?", Sql::Text(v.clone()));
        }
        if let Some(v) = f.ses {
            and("ses = ?", Sql::Integer(v.into()));
        }
        if let Some(v) = f.text.as_deref().and_then(fts_query) {
            and(
                "seq IN (SELECT rowid FROM fts WHERE fts MATCH ?)",
                Sql::Text(v),
            );
        }
        if let Some(v) = f.before_seq {
            and("seq < ?", Sql::Integer(v as i64));
        }
        if let Some(v) = f.after_seq {
            and("seq > ?", Sql::Integer(v as i64));
        }
        let mut sql = String::from(
            "SELECT seq,kind,boot_ns,wall_ns,pid,uid,puid,seg_id,seg_off,len FROM events",
        );
        if !clauses.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&clauses.join(" AND "));
        }
        sql.push_str(if f.after_seq.is_some() {
            " ORDER BY seq ASC LIMIT ?"
        } else {
            " ORDER BY seq DESC LIMIT ?"
        });
        args.push(Sql::Integer(f.limit.clamp(1, 1000) as i64));

        let mut stmt = self.conn.prepare(&sql).map_err(db)?;
        let rows = stmt
            .query_map(params_from_iter(args), |r| {
                Ok(EventRow {
                    seq: r.get::<_, i64>(0)? as u64,
                    kind: r.get(1)?,
                    boot_ns: r.get::<_, Option<i64>>(2)?.map(|v| v as u64),
                    wall_ns: r.get::<_, Option<i64>>(3)?.map(|v| v as u64),
                    pid: r.get::<_, Option<i64>>(4)?.map(|v| v as u32),
                    uid: r.get::<_, Option<i64>>(5)?.map(|v| v as u32),
                    puid: r.get(6)?,
                    seg_id: r.get::<_, i64>(7)? as u64,
                    seg_off: r.get::<_, i64>(8)? as u64,
                    len: r.get::<_, i64>(9)? as u64,
                })
            })
            .map_err(db)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db)?;
        Ok(rows)
    }

    /// Event counts per `(bucket, kind)` over `[from, to)` (wall-clock ns), `buckets` equal
    /// slices. The caller bounds the range; bucket indexes are `0..buckets`.
    pub fn timeline(&self, from: u64, to: u64, buckets: u32) -> Result<Vec<(u32, String, u64)>> {
        if to <= from || buckets == 0 {
            return Ok(Vec::new());
        }
        let buckets = buckets.min(1000);
        let mut stmt = self
            .conn
            .prepare(
                "SELECT ((wall_ns - ?1) * ?3 / (?2 - ?1)) AS b, kind, COUNT(*) FROM events \
                 WHERE wall_ns >= ?1 AND wall_ns < ?2 GROUP BY b, kind ORDER BY b",
            )
            .map_err(db)?;
        let rows = stmt
            .query_map([from as i64, to as i64, buckets as i64], |r| {
                Ok((
                    r.get::<_, i64>(0)? as u32,
                    r.get(1)?,
                    r.get::<_, i64>(2)? as u64,
                ))
            })
            .map_err(db)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db)?;
        Ok(rows)
    }

    /// Total events per kind over `[from, to)`.
    pub fn kind_counts(&self, from: u64, to: u64) -> Result<Vec<(String, u64)>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT kind, COUNT(*) FROM events WHERE wall_ns >= ?1 AND wall_ns < ?2 \
                 GROUP BY kind ORDER BY 2 DESC",
            )
            .map_err(db)?;
        let rows = stmt
            .query_map([from as i64, to as i64], |r| {
                Ok((r.get(0)?, r.get::<_, i64>(1)? as u64))
            })
            .map_err(db)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db)?;
        Ok(rows)
    }

    /// Fetches the exact stored line for `seq`, straight from the segment.
    pub fn raw(&self, seg_dir: &Path, seq: u64) -> Result<Vec<u8>> {
        self.raw_in(&[seg_dir.to_path_buf()], seq)
    }

    /// Like [`Index::raw`], searching live data and archive directories.
    pub fn raw_in(&self, dirs: &[PathBuf], seq: u64) -> Result<Vec<u8>> {
        let (id, off, len): (i64, i64, i64) = self
            .conn
            .query_row(
                "SELECT seg_id,seg_off,len FROM events WHERE seq=?1",
                [seq as i64],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map_err(db)?;
        let seg = segment::list_segments_in(dirs)?
            .into_iter()
            .find(|s| s.id == id as u64)
            .ok_or_else(|| StoreError::Corrupt(format!("segment {id} is missing")))?;
        segment::read_range(&seg, off as u64, len as usize)
    }
}

fn save_position(tx: &rusqlite::Transaction<'_>, seq: u64, head: &Hash) -> Result<()> {
    for (k, v) in [
        ("last_seq", seq.to_string()),
        ("last_head", chain::to_hex(head)),
    ] {
        tx.execute(
            "INSERT INTO meta(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![k, v],
        )
        .map_err(db)?;
    }
    Ok(())
}

fn insert_event(
    tx: &rusqlite::Transaction<'_>,
    v: &Value,
    seq: u64,
    seg: &SegmentInfo,
    off: u64,
    len: u64,
) -> Result<()> {
    let a = &v["actor"];
    let int = |x: &Value| x.as_u64().map(|n| n as i64);
    let kind = v["type"].as_str().unwrap_or("unknown");
    tx.execute(
        "INSERT INTO events(seq,kind,boot_ns,wall_ns,pid,tid,ppid,uid,euid,auid,ses,cgroup_id,puid,seg_id,seg_off,len)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
        params![
            seq as i64,
            kind,
            int(&v["boot_ns"]),
            int(&v["wall_ns"]),
            int(&a["pid"]),
            int(&a["tid"]),
            int(&a["ppid"]),
            int(&a["uid"]),
            int(&a["euid"]),
            int(&a["auid"]),
            int(&a["ses"]),
            int(&a["cgroup_id"]),
            a["puid"].as_str(),
            seg.id as i64,
            off as i64,
            len as i64
        ],
    )
    .map_err(db)?;

    let cmdline = join_strings(&a["cmdline"]).or_else(|| join_strings(&v["data"]["argv"]));
    // Files by path; network events by the remote (or listening) address, so a search for an
    // IP finds the connections to it.
    let path = v["data"]["path"]
        .as_str()
        .or_else(|| v["data"]["raddr"].as_str())
        .or_else(|| v["data"]["conn"]["raddr"].as_str())
        .or_else(|| v["data"]["addr"].as_str())
        .map(str::to_owned);
    let name = v["data"]["qname"]
        .as_str()
        .or_else(|| a["comm"].as_str())
        .map(str::to_owned);
    if cmdline.is_some() || path.is_some() || name.is_some() {
        tx.execute(
            "INSERT INTO fts(rowid,cmdline,path,name) VALUES(?1,?2,?3,?4)",
            params![seq as i64, cmdline, path, name],
        )
        .map_err(db)?;
    }
    Ok(())
}

fn join_strings(v: &Value) -> Option<String> {
    let arr = v.as_array()?;
    let parts: Vec<&str> = arr.iter().filter_map(Value::as_str).collect();
    (!parts.is_empty()).then(|| parts.join(" "))
}

fn db(e: rusqlite::Error) -> StoreError {
    StoreError::Corrupt(format!("index database error: {e}"))
}

/// Turns user text into a safe FTS5 expression: every word becomes a quoted phrase, so
/// operators and punctuation in the input cannot change the meaning of the query.
fn fts_query(text: &str) -> Option<String> {
    let parts: Vec<String> = text
        .split_whitespace()
        .filter_map(|w| {
            let (word, prefix) = match w.strip_suffix('*') {
                Some(x) => (x, true),
                None => (w, false),
            };
            if word.is_empty() {
                return None;
            }
            let quoted = format!("\"{}\"", word.replace('"', "\"\""));
            Some(if prefix { format!("{quoted}*") } else { quoted })
        })
        .collect();
    (!parts.is_empty()).then(|| parts.join(" "))
}

#[cfg(test)]
mod tests {
    use super::fts_query;

    #[test]
    fn user_text_is_quoted() {
        assert_eq!(fts_query("job-77").as_deref(), Some("\"job-77\""));
        assert_eq!(
            fts_query("curl  http://x").as_deref(),
            Some("\"curl\" \"http://x\"")
        );
        assert_eq!(fts_query("pay*").as_deref(), Some("\"pay\"*"));
        assert_eq!(
            fts_query("say \"hi\"").as_deref(),
            Some("\"say\" \"\"\"hi\"\"\"")
        );
        assert_eq!(
            fts_query("NOT OR AND").as_deref(),
            Some("\"NOT\" \"OR\" \"AND\"")
        );
        assert_eq!(fts_query("   *  "), None);
    }
}
