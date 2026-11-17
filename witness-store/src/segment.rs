//! Segment files: naming, listing, reading, and compression of sealed segments.

use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::chain::Hash;
use crate::error::{Result, StoreError};

/// Uncompressed size of each independent zstd frame in a sealed segment.
pub const FRAME_BYTES: usize = 1 << 20;
const ZST_LEVEL: i32 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentInfo {
    pub id: u64,
    pub first_seq: u64,
    pub path: PathBuf,
    pub compressed: bool,
}

pub fn file_name(id: u64, first_seq: u64, compressed: bool) -> String {
    let ext = if compressed { "ndjson.zst" } else { "ndjson" };
    format!("seg-{id:08}-{first_seq:020}.{ext}")
}

fn parse_name(name: &str) -> Option<(u64, u64, bool)> {
    let rest = name.strip_prefix("seg-")?;
    let (compressed, stem) = if let Some(s) = rest.strip_suffix(".ndjson.zst") {
        (true, s)
    } else {
        (false, rest.strip_suffix(".ndjson")?)
    };
    let (id, first) = stem.split_once('-')?;
    Some((id.parse().ok()?, first.parse().ok()?, compressed))
}

/// Lists segments in `dir`, ordered by id. A missing directory yields an empty list.
pub fn list_segments(dir: &Path) -> Result<Vec<SegmentInfo>> {
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut out = Vec::new();
    for entry in rd {
        let entry = entry?;
        let name = entry.file_name();
        if let Some((id, first_seq, compressed)) = name.to_str().and_then(parse_name) {
            out.push(SegmentInfo {
                id,
                first_seq,
                path: entry.path(),
                compressed,
            });
        }
    }
    out.sort_by_key(|s| s.id);
    Ok(out)
}

/// Opens a segment for line-oriented reading of its *uncompressed* bytes.
pub fn open_reader(info: &SegmentInfo) -> io::Result<Box<dyn BufRead>> {
    let f = File::open(&info.path)?;
    if info.compressed {
        Ok(Box::new(BufReader::new(zstd::Decoder::new(f)?)))
    } else {
        Ok(Box::new(BufReader::new(f)))
    }
}

/// SHA-256 of a segment's complete uncompressed bytes.
pub fn file_sha256(info: &SegmentInfo) -> io::Result<Hash> {
    let mut r = open_reader(info)?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().into())
}

pub fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Compresses a sealed plain segment into independent ~1 MiB zstd frames, verifies the
/// result byte-for-byte via SHA-256, and only then removes the plain file.
pub fn compress_segment(info: &SegmentInfo) -> Result<SegmentInfo> {
    if info.compressed {
        return Err(StoreError::Invalid("segment is already compressed"));
    }
    let dir = info
        .path
        .parent()
        .ok_or(StoreError::Invalid("segment path has no parent"))?;
    let dest = dir.join(file_name(info.id, info.first_seq, true));
    let tmp = dir.join(format!("{}.tmp", file_name(info.id, info.first_seq, true)));
    let want = file_sha256(info)?;

    let mut src = File::open(&info.path)?;
    let mut out = File::create(&tmp)?;
    let mut buf = vec![0u8; FRAME_BYTES];
    loop {
        let n = read_full(&mut src, &mut buf)?;
        if n == 0 {
            break;
        }
        out.write_all(&zstd::encode_all(&buf[..n], ZST_LEVEL)?)?;
    }
    out.sync_all()?;
    drop(out);

    let packed = SegmentInfo {
        compressed: true,
        path: tmp.clone(),
        ..info.clone()
    };
    if file_sha256(&packed)? != want {
        let _ = fs::remove_file(&tmp);
        return Err(StoreError::Corrupt(
            "compressed segment failed round-trip verification".into(),
        ));
    }
    fs::rename(&tmp, &dest)?;
    sync_dir(dir)?;
    fs::remove_file(&info.path)?;
    sync_dir(dir)?;
    Ok(SegmentInfo {
        path: dest,
        compressed: true,
        ..info.clone()
    })
}

fn read_full(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_roundtrip() {
        let n = file_name(3, 42, false);
        assert_eq!(parse_name(&n), Some((3, 42, false)));
        let n = file_name(3, 42, true);
        assert_eq!(parse_name(&n), Some((3, 42, true)));
        assert_eq!(parse_name("other.txt"), None);
        assert_eq!(parse_name("seg-1-2.ndjson.zst.tmp"), None);
    }
}
