//! Minimal reader for the kernel's BTF type information (`/sys/kernel/btf/vmlinux`).
//!
//! `aya` keeps BTF struct members private, and `aya-ebpf` has no way to emit CO-RE field
//! accesses from Rust, so Witness resolves the few struct offsets it needs here and hands
//! them to the eBPF programs as a global (DESIGN.md §3.2). The parser also answers "does
//! this kernel function exist?", which decides which `fentry` hooks are usable.

use std::collections::HashMap;

use witness_common::{Offsets, UNAVAILABLE};

const MAGIC: u16 = 0xeb9f;
const HDR_MIN: usize = 24;

const KIND_INT: u8 = 1;
const KIND_ARRAY: u8 = 3;
const KIND_STRUCT: u8 = 4;
const KIND_UNION: u8 = 5;
const KIND_ENUM: u8 = 6;
const KIND_TYPEDEF: u8 = 8;
const KIND_VOLATILE: u8 = 9;
const KIND_CONST: u8 = 10;
const KIND_RESTRICT: u8 = 11;
const KIND_FUNC: u8 = 12;
const KIND_FUNC_PROTO: u8 = 13;
const KIND_VAR: u8 = 14;
const KIND_DATASEC: u8 = 15;
const KIND_DECL_TAG: u8 = 17;
const KIND_ENUM64: u8 = 19;

#[derive(Debug, thiserror::Error)]
pub enum BtfError {
    #[error("cannot read BTF: {0}")]
    Io(#[from] std::io::Error),
    #[error("not little-endian BTF (magic {0:#06x})")]
    BadMagic(u16),
    #[error("BTF is truncated or malformed: {0}")]
    Malformed(&'static str),
    #[error("kernel lacks required field: {0}")]
    Missing(String),
}

#[derive(Debug, Clone, Copy)]
struct Rec {
    name_off: u32,
    kind: u8,
    kind_flag: bool,
    vlen: u16,
    /// `size` for struct/union/int, `type` for typedef/ptr/const/...
    size_or_type: u32,
    /// Byte offset of this record's extra data within the type section.
    extra: usize,
}

pub struct Btf {
    types: Vec<u8>,
    strings: Vec<u8>,
    recs: Vec<Rec>,
    by_struct: HashMap<String, u32>,
}

fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}

impl Btf {
    pub fn from_sys_fs() -> Result<Btf, BtfError> {
        Btf::parse(&std::fs::read("/sys/kernel/btf/vmlinux")?)
    }

    pub fn parse(data: &[u8]) -> Result<Btf, BtfError> {
        let mal = BtfError::Malformed;
        let magic = u16::from_le_bytes(
            data.get(..2)
                .ok_or(mal("header"))?
                .try_into()
                .map_err(|_| mal("header"))?,
        );
        if magic != MAGIC {
            return Err(BtfError::BadMagic(magic));
        }
        let hdr_len = u32_at(data, 4).ok_or(mal("header"))? as usize;
        let type_off = u32_at(data, 8).ok_or(mal("header"))? as usize;
        let type_len = u32_at(data, 12).ok_or(mal("header"))? as usize;
        let str_off = u32_at(data, 16).ok_or(mal("header"))? as usize;
        let str_len = u32_at(data, 20).ok_or(mal("header"))? as usize;
        if hdr_len < HDR_MIN {
            return Err(mal("header length"));
        }
        let types = data
            .get(hdr_len + type_off..hdr_len + type_off + type_len)
            .ok_or(mal("type section"))?
            .to_vec();
        let strings = data
            .get(hdr_len + str_off..hdr_len + str_off + str_len)
            .ok_or(mal("string section"))?
            .to_vec();

        let mut recs = Vec::new();
        let mut pos = 0usize;
        while pos < types.len() {
            let name_off = u32_at(&types, pos).ok_or(mal("type record"))?;
            let info = u32_at(&types, pos + 4).ok_or(mal("type record"))?;
            let size_or_type = u32_at(&types, pos + 8).ok_or(mal("type record"))?;
            let kind = ((info >> 24) & 0x1f) as u8;
            let vlen = (info & 0xffff) as u16;
            let extra = pos + 12;
            let extra_len = match kind {
                KIND_INT | KIND_VAR | KIND_DECL_TAG => 4,
                KIND_ARRAY => 12,
                KIND_STRUCT | KIND_UNION | KIND_DATASEC | KIND_ENUM64 => vlen as usize * 12,
                KIND_ENUM | KIND_FUNC_PROTO => vlen as usize * 8,
                _ => 0,
            };
            recs.push(Rec {
                name_off,
                kind,
                kind_flag: info >> 31 != 0,
                vlen,
                size_or_type,
                extra,
            });
            pos = extra + extra_len;
        }
        if pos != types.len() {
            return Err(mal("type section does not end on a record boundary"));
        }

        let mut btf = Btf {
            types,
            strings,
            recs,
            by_struct: HashMap::new(),
        };
        let mut by_struct = HashMap::new();
        for (i, r) in btf.recs.iter().enumerate() {
            if r.kind == KIND_STRUCT && r.size_or_type > 0 {
                if let Some(n) = btf.name(r.name_off) {
                    by_struct.entry(n.to_string()).or_insert(i as u32 + 1);
                }
            }
        }
        btf.by_struct = by_struct;
        Ok(btf)
    }

    fn name(&self, off: u32) -> Option<&str> {
        let s = self.strings.get(off as usize..)?;
        let end = s.iter().position(|&b| b == 0)?;
        std::str::from_utf8(&s[..end]).ok()
    }

    fn rec(&self, id: u32) -> Option<&Rec> {
        self.recs.get(id.checked_sub(1)? as usize)
    }

    /// Follows typedef/const/volatile/restrict to the underlying type.
    fn strip(&self, mut id: u32) -> Option<u32> {
        for _ in 0..16 {
            let r = self.rec(id)?;
            match r.kind {
                KIND_TYPEDEF | KIND_CONST | KIND_VOLATILE | KIND_RESTRICT => id = r.size_or_type,
                _ => return Some(id),
            }
        }
        None
    }

    /// Byte offset of `field` in `struct_name`, searching into anonymous structs/unions.
    pub fn field_offset(&self, struct_name: &str, field: &str) -> Option<u32> {
        let id = *self.by_struct.get(struct_name)?;
        self.find_member(id, field, 0, 0)
    }

    fn find_member(&self, id: u32, field: &str, base_bits: u32, depth: u8) -> Option<u32> {
        if depth > 6 {
            return None;
        }
        let r = self.rec(id)?;
        if r.kind != KIND_STRUCT && r.kind != KIND_UNION {
            return None;
        }
        for i in 0..r.vlen as usize {
            let m = r.extra + i * 12;
            let name_off = u32_at(&self.types, m)?;
            let ty = u32_at(&self.types, m + 4)?;
            let raw_off = u32_at(&self.types, m + 8)?;
            // With kind_flag the top 8 bits are a bitfield size; plain members have 0.
            let (bit_off, bitfield) = if r.kind_flag {
                (raw_off & 0x00ff_ffff, raw_off >> 24 != 0)
            } else {
                (raw_off, false)
            };
            let abs = base_bits.checked_add(bit_off)?;
            if name_off == 0 {
                if let Some(inner) = self.strip(ty) {
                    if let Some(found) = self.find_member(inner, field, abs, depth + 1) {
                        return Some(found);
                    }
                }
            } else if self.name(name_off) == Some(field) {
                return (!bitfield && abs % 8 == 0).then_some(abs / 8);
            }
        }
        None
    }

    /// Whether a function named `name` is described in BTF (so `fentry`/`fexit` can target it).
    pub fn has_func(&self, name: &str) -> bool {
        self.recs
            .iter()
            .any(|r| r.kind == KIND_FUNC && self.name(r.name_off) == Some(name))
    }

    /// Number of parameters of kernel function `name`, from its BTF prototype. Used to refuse
    /// a hook whose signature differs from what the program reads (a wrong argument index
    /// would silently read garbage).
    pub fn func_param_count(&self, name: &str) -> Option<usize> {
        let f = self
            .recs
            .iter()
            .find(|r| r.kind == KIND_FUNC && self.name(r.name_off) == Some(name))?;
        let proto = self.rec(f.size_or_type)?;
        (proto.kind == KIND_FUNC_PROTO).then_some(proto.vlen as usize)
    }

    /// Names of the requested functions that are missing from BTF.
    pub fn missing_funcs<'a>(&self, names: &[&'a str]) -> Vec<&'a str> {
        let have: std::collections::HashSet<&str> = self
            .recs
            .iter()
            .filter(|r| r.kind == KIND_FUNC)
            .filter_map(|r| self.name(r.name_off))
            .collect();
        names
            .iter()
            .copied()
            .filter(|n| !have.contains(n))
            .collect()
    }

    /// Resolves every offset the programs use. Required fields missing from the kernel are
    /// an error; optional ones become [`UNAVAILABLE`] and are listed in `Resolved::notes`.
    pub fn resolve_offsets(&self) -> Result<Resolved, BtfError> {
        let mut notes = Vec::new();
        let need = |s: &str, f: &str| -> Result<u32, BtfError> {
            self.field_offset(s, f)
                .ok_or_else(|| BtfError::Missing(format!("{s}.{f}")))
        };
        let offsets_required = (
            need("task_struct", "pid")?,
            need("task_struct", "tgid")?,
            need("task_struct", "real_parent")?,
            need("task_struct", "group_leader")?,
            need("task_struct", "cred")?,
            need("task_struct", "mm")?,
            need("task_struct", "start_boottime")?,
            need("task_struct", "exit_code")?,
            need("cred", "euid")?,
            need("cred", "egid")?,
            need("mm_struct", "arg_start")?,
            need("mm_struct", "arg_end")?,
            need("linux_binprm", "filename")?,
        );
        let mut opt = |s: &str, f: &str| -> u32 {
            self.field_offset(s, f).unwrap_or_else(|| {
                notes.push(format!("{s}.{f} not available"));
                UNAVAILABLE
            })
        };
        let (
            pid,
            tgid,
            real_parent,
            group_leader,
            cred,
            mm,
            start_boottime,
            exit_code,
            euid,
            egid,
            arg_start,
            arg_end,
            filename,
        ) = offsets_required;
        let offsets = Offsets {
            task_pid: pid,
            task_tgid: tgid,
            task_real_parent: real_parent,
            task_group_leader: group_leader,
            task_cred: cred,
            task_mm: mm,
            task_signal: opt("task_struct", "signal"),
            task_loginuid: opt("task_struct", "loginuid"),
            task_sessionid: opt("task_struct", "sessionid"),
            task_start_boottime: start_boottime,
            task_exit_code: exit_code,
            cred_euid: euid,
            cred_egid: egid,
            mm_arg_start: arg_start,
            mm_arg_end: arg_end,
            signal_tty: opt("signal_struct", "tty"),
            tty_name: opt("tty_struct", "name"),
            binprm_filename: filename,
            file_f_path: opt("file", "f_path"),
            file_f_mode: opt("file", "f_mode"),
            file_f_flags: opt("file", "f_flags"),
            path_mnt: opt("path", "mnt"),
            path_dentry: opt("path", "dentry"),
            dentry_d_parent: opt("dentry", "d_parent"),
            dentry_d_name: opt("dentry", "d_name"),
            dentry_d_inode: opt("dentry", "d_inode"),
            dentry_d_sb: opt("dentry", "d_sb"),
            qstr_name: opt("qstr", "name"),
            qstr_len: opt("qstr", "len"),
            mount_mnt_parent: opt("mount", "mnt_parent"),
            mount_mnt_mountpoint: opt("mount", "mnt_mountpoint"),
            mount_mnt: opt("mount", "mnt"),
            inode_i_mode: opt("inode", "i_mode"),
            inode_i_ino: opt("inode", "i_ino"),
            sb_s_dev: opt("super_block", "s_dev"),
            sb_s_magic: opt("super_block", "s_magic"),
            sock_skc_daddr: opt("sock_common", "skc_daddr"),
            sock_skc_rcv_saddr: opt("sock_common", "skc_rcv_saddr"),
            sock_skc_dport: opt("sock_common", "skc_dport"),
            sock_skc_num: opt("sock_common", "skc_num"),
            sock_skc_family: opt("sock_common", "skc_family"),
            sock_skc_v6_daddr: opt("sock_common", "skc_v6_daddr"),
            sock_skc_v6_rcv_saddr: opt("sock_common", "skc_v6_rcv_saddr"),
            tcp_bytes_sent: opt("tcp_sock", "bytes_sent"),
            tcp_bytes_received: opt("tcp_sock", "bytes_received"),
            sock_sk_shutdown: opt("sock", "sk_shutdown"),
            msghdr_msg_name: opt("msghdr", "msg_name"),
            msghdr_msg_namelen: opt("msghdr", "msg_namelen"),
            msghdr_msg_iter: opt("msghdr", "msg_iter"),
            // The iterator kind field was `type` before it became `iter_type`.
            iov_iter_type: self
                .field_offset("iov_iter", "iter_type")
                .or_else(|| self.field_offset("iov_iter", "type"))
                .unwrap_or(UNAVAILABLE),
            iov_iter_iov: self
                .field_offset("iov_iter", "iov")
                .or_else(|| self.field_offset("iov_iter", "__iov"))
                .unwrap_or(UNAVAILABLE),
            // Present only on kernels with ITER_UBUF (6.0+).
            iov_iter_ubuf: self.field_offset("iov_iter", "ubuf").unwrap_or(UNAVAILABLE),
        };
        Ok(Resolved { offsets, notes })
    }
}

#[derive(Debug, Clone)]
pub struct Resolved {
    pub offsets: Offsets,
    /// Optional fields the kernel lacks (the matching event fields are left unset).
    pub notes: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a tiny BTF blob: strings, ints, structs and typedefs.
    struct B {
        strings: Vec<u8>,
        types: Vec<u8>,
        n: u32,
    }

    impl B {
        fn new() -> Self {
            B {
                strings: vec![0],
                types: Vec::new(),
                n: 0,
            }
        }
        fn s(&mut self, s: &str) -> u32 {
            if s.is_empty() {
                return 0;
            }
            let off = self.strings.len() as u32;
            self.strings.extend_from_slice(s.as_bytes());
            self.strings.push(0);
            off
        }
        fn push(
            &mut self,
            name: &str,
            kind: u8,
            vlen: u16,
            kind_flag: bool,
            size_or_type: u32,
            extra: &[u8],
        ) -> u32 {
            let name_off = self.s(name);
            let info = (vlen as u32) | ((kind as u32) << 24) | ((kind_flag as u32) << 31);
            for w in [name_off, info, size_or_type] {
                self.types.extend_from_slice(&w.to_le_bytes());
            }
            self.types.extend_from_slice(extra);
            self.n += 1;
            self.n
        }
        fn int(&mut self, name: &str, size: u32) -> u32 {
            self.push(name, KIND_INT, 0, false, size, &0u32.to_le_bytes())
        }
        /// members: (name, type, bit offset)
        fn strukt(&mut self, name: &str, kind: u8, size: u32, members: &[(&str, u32, u32)]) -> u32 {
            let mut extra = Vec::new();
            for (n, t, off) in members {
                let no = self.s(n);
                for w in [no, *t, *off] {
                    extra.extend_from_slice(&w.to_le_bytes());
                }
            }
            self.push(name, kind, members.len() as u16, false, size, &extra)
        }
        fn func(&mut self, name: &str) -> u32 {
            self.push(name, KIND_FUNC, 0, false, 0, &[])
        }
        fn build(self) -> Vec<u8> {
            let mut out = Vec::new();
            out.extend_from_slice(&MAGIC.to_le_bytes());
            out.extend_from_slice(&[1, 0]);
            for w in [
                24u32,
                0,
                self.types.len() as u32,
                self.types.len() as u32,
                self.strings.len() as u32,
            ] {
                out.extend_from_slice(&w.to_le_bytes());
            }
            out.extend_from_slice(&self.types);
            out.extend_from_slice(&self.strings);
            out
        }
    }

    #[test]
    fn finds_plain_and_nested_members() {
        let mut b = B::new();
        let u32t = b.int("unsigned int", 4);
        let u64t = b.int("unsigned long", 8);
        // anonymous union { u32 a; struct { u64 deep; } inner; } at byte 8 of `outer`
        let inner = b.strukt("", KIND_STRUCT, 8, &[("deep", u64t, 0)]);
        let anon = b.strukt("", KIND_UNION, 8, &[("a", u32t, 0), ("", inner, 0)]);
        let td = b.push("anon_t", KIND_TYPEDEF, 0, false, anon, &[]);
        let cst = b.push("", KIND_CONST, 0, false, td, &[]);
        b.strukt(
            "outer",
            KIND_STRUCT,
            24,
            &[("first", u32t, 0), ("", cst, 64), ("last", u64t, 128)],
        );
        let btf = Btf::parse(&b.build()).unwrap();
        assert_eq!(btf.field_offset("outer", "first"), Some(0));
        assert_eq!(btf.field_offset("outer", "last"), Some(16));
        assert_eq!(
            btf.field_offset("outer", "a"),
            Some(8),
            "through const -> typedef -> union"
        );
        assert_eq!(
            btf.field_offset("outer", "deep"),
            Some(8),
            "through a nested anonymous struct"
        );
        assert_eq!(btf.field_offset("outer", "nope"), None);
        assert_eq!(btf.field_offset("missing", "first"), None);
    }

    #[test]
    fn bitfields_and_unaligned_members_are_not_offsets() {
        let mut b = B::new();
        let u32t = b.int("unsigned int", 4);
        b.strukt(
            "bits",
            KIND_STRUCT,
            8,
            &[("odd", u32t, 3), ("ok", u32t, 32)],
        );
        let btf = Btf::parse(&b.build()).unwrap();
        assert_eq!(btf.field_offset("bits", "odd"), None);
        assert_eq!(btf.field_offset("bits", "ok"), Some(4));
    }

    #[test]
    fn function_presence() {
        let mut b = B::new();
        b.func("security_path_unlink");
        b.func("vfs_open");
        let btf = Btf::parse(&b.build()).unwrap();
        assert!(btf.has_func("vfs_open"));
        assert!(!btf.has_func("tcp_v4_connect"));
        assert_eq!(
            btf.missing_funcs(&["vfs_open", "tcp_v4_connect", "security_path_unlink"]),
            vec!["tcp_v4_connect"]
        );
    }

    #[test]
    fn function_parameter_counts() {
        let mut b = B::new();
        let int = b.int("int", 4);
        // proto with 3 params: name_off(0) + type per param
        let mut extra = Vec::new();
        for _ in 0..3 {
            extra.extend_from_slice(&0u32.to_le_bytes());
            extra.extend_from_slice(&int.to_le_bytes());
        }
        let proto = b.push("", KIND_FUNC_PROTO, 3, false, int, &extra);
        b.push("security_path_mkdir", KIND_FUNC, 0, false, proto, &[]);
        let btf = Btf::parse(&b.build()).unwrap();
        assert_eq!(btf.func_param_count("security_path_mkdir"), Some(3));
        assert_eq!(btf.func_param_count("nope"), None);
    }

    #[test]
    fn rejects_garbage() {
        assert!(matches!(Btf::parse(&[]), Err(BtfError::Malformed(_))));
        assert!(matches!(
            Btf::parse(&[0x9f, 0xeb, 1, 0, 24, 0, 0, 0]),
            Err(BtfError::BadMagic(_)) | Err(BtfError::Malformed(_))
        ));
        let mut b = B::new();
        b.int("x", 4);
        let mut blob = b.build();
        blob.truncate(blob.len() - 6);
        assert!(Btf::parse(&blob).is_err());
    }

    /// Runs against the real kernel BTF when present (Linux with CONFIG_DEBUG_INFO_BTF).
    #[test]
    fn real_kernel_offsets_resolve() {
        let Ok(btf) = Btf::from_sys_fs() else {
            eprintln!("skipped: no /sys/kernel/btf/vmlinux");
            return;
        };
        let r = btf.resolve_offsets().unwrap();
        eprintln!("{:#?}\nnotes: {:?}", r.offsets, r.notes);
        assert_ne!(r.offsets.task_tgid, UNAVAILABLE);
        assert_ne!(r.offsets.mm_arg_start, UNAVAILABLE);
        assert!(r.offsets.mm_arg_end > r.offsets.mm_arg_start);
    }
}
