//! Forward-secure sealing (DESIGN.md §5.4).
//!
//! The admin holds a verification key `K_0` that is never stored on the host. The daemon
//! holds only the *current* evolving key `K_i`. Each epoch it writes a `seal` record whose
//! MAC covers the chain head, then replaces `K_i` with `K_{i+1} = SHA256(tag || K_i)` and
//! erases `K_i`. An attacker who takes over at epoch `j` cannot forge a MAC for any epoch
//! below `j`, so history sealed before the compromise stays verifiable with `K_0`.
//!
//! `K_0` itself is never written to disk by the daemon: `init` persists `K_1` (epoch 1).

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::chain::{self, Hash};
use crate::error::{Result, StoreError};

pub const TYPE_SEAL_MAC: &str = "seal";
const EVOLVE_TAG: &[u8] = b"witness-evolve-v1";
const MAC_TAG: &[u8] = b"witness-seal-v1";

type HmacSha256 = Hmac<Sha256>;

/// Evolves a key one epoch forward.
pub fn evolve(key: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update(EVOLVE_TAG);
    h.update(key);
    h.finalize().into()
}

/// The authenticated message: epoch, last covered seq, and the chain head hash.
fn message(epoch: u64, covers_seq: u64, head: &Hash) -> Vec<u8> {
    let mut m = Vec::with_capacity(MAC_TAG.len() + 48);
    m.extend_from_slice(MAC_TAG);
    m.extend_from_slice(&epoch.to_be_bytes());
    m.extend_from_slice(&covers_seq.to_be_bytes());
    m.extend_from_slice(head);
    m
}

fn hmac_for(key: &Hash, epoch: u64, covers_seq: u64, head: &Hash) -> Result<HmacSha256> {
    let mut m = <HmacSha256 as KeyInit>::new_from_slice(key)
        .map_err(|e| StoreError::Corrupt(format!("invalid seal key: {e}")))?;
    m.update(&message(epoch, covers_seq, head));
    Ok(m)
}

pub fn mac(key: &Hash, epoch: u64, covers_seq: u64, head: &Hash) -> Result<Hash> {
    Ok(hmac_for(key, epoch, covers_seq, head)?
        .finalize()
        .into_bytes()
        .into())
}

/// Constant-time check of a seal MAC.
pub fn mac_ok(key: &Hash, epoch: u64, covers_seq: u64, head: &Hash, tag: &Hash) -> bool {
    hmac_for(key, epoch, covers_seq, head)
        .map(|m| m.verify_slice(tag).is_ok())
        .unwrap_or(false)
}

/// Advances `key` from `from_epoch` to `to_epoch` (`to_epoch >= from_epoch`).
pub fn evolve_to(key: &Hash, from_epoch: u64, to_epoch: u64) -> Hash {
    let mut k = *key;
    for _ in from_epoch..to_epoch {
        k = evolve(&k);
    }
    k
}

/// The evolving key the daemon holds. Erased from memory on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SealState {
    #[zeroize(skip)]
    epoch: u64,
    key: Hash,
    #[zeroize(skip)]
    path: PathBuf,
}

impl SealState {
    /// Creates a fresh key. Returns `K_0` (to be given to the admin, never stored) and
    /// persists only `K_1` at epoch 1 to `path`.
    pub fn init(path: &Path) -> Result<Hash> {
        if path.exists() {
            return Err(StoreError::Invalid("seal key already exists"));
        }
        let mut k0 = [0u8; 32];
        getrandom::fill(&mut k0)
            .map_err(|e| StoreError::Corrupt(format!("no randomness available: {e}")))?;
        let mut st = SealState {
            epoch: 1,
            key: evolve(&k0),
            path: path.to_path_buf(),
        };
        st.persist()?;
        Ok(k0)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let v: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
        let epoch = v["epoch"]
            .as_u64()
            .ok_or_else(|| StoreError::Corrupt("seal key file has no epoch".into()))?;
        let key = v["key"]
            .as_str()
            .and_then(|s| chain::from_hex(s.as_bytes()))
            .ok_or_else(|| StoreError::Corrupt("seal key file has no valid key".into()))?;
        Ok(SealState {
            epoch,
            key,
            path: path.to_path_buf(),
        })
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// MAC for the current epoch.
    pub fn mac(&self, covers_seq: u64, head: &Hash) -> Result<Hash> {
        mac(&self.key, self.epoch, covers_seq, head)
    }

    /// Moves to `epoch + n`, persisting before the old key is discarded in memory.
    pub fn advance(&mut self, n: u64) -> Result<()> {
        let old_epoch = self.epoch;
        let new_key = evolve_to(&self.key, 0, n);
        self.epoch = old_epoch + n;
        self.key.zeroize();
        self.key = new_key;
        self.persist()
    }

    fn persist(&mut self) -> Result<()> {
        let body = serde_json::json!({"epoch": self.epoch, "key": chain::to_hex(&self.key)});
        let tmp = self.path.with_extension("tmp");
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        restrict(&tmp)?;
        f.write_all(serde_json::to_string(&body)?.as_bytes())?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, &self.path)?;
        if let Some(dir) = self.path.parent() {
            File::open(dir)?.sync_all()?;
        }
        Ok(())
    }
}

#[cfg(unix)]
fn restrict(p: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(p, fs::Permissions::from_mode(0o600))?;
    Ok(())
}
#[cfg(not(unix))]
fn restrict(_: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_binds_all_inputs() {
        let k = [7u8; 32];
        let head = [9u8; 32];
        let t = mac(&k, 3, 10, &head).unwrap();
        assert!(mac_ok(&k, 3, 10, &head, &t));
        assert!(!mac_ok(&k, 4, 10, &head, &t));
        assert!(!mac_ok(&k, 3, 11, &head, &t));
        assert!(!mac_ok(&k, 3, 10, &[8u8; 32], &t));
        assert!(!mac_ok(&[6u8; 32], 3, 10, &head, &t));
    }

    #[test]
    fn evolution_is_one_way_and_composable() {
        let k0 = [1u8; 32];
        let k2 = evolve(&evolve(&k0));
        assert_eq!(evolve_to(&k0, 0, 2), k2);
        assert_ne!(evolve(&k0), k0);
    }
}
