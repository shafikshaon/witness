# Witness — Design Document

Status: **DRAFT for review. No code has been written.**
Date: 2026-11-17

## 0. How to read this document

Every technical claim carries a confidence tag. I could not run anything on a Linux kernel while writing this (the dev machine is macOS), and I did only light web verification.

| Tag | Meaning |
|-----|---------|
| ✅ | Verified during this design session via web search (docs.rs / lib.rs / dioxuslabs). Still re-check on crates.io before pinning. |
| 📘 | From my prior knowledge of the kernel/crates; I am confident but did **not** look it up. Must be verified in the named milestone. |
| ❓ | I am unsure. Treated as an open item; a spike is planned. |

Verified this session (✅):
- ~~`aya` latest is 0.14.0~~ — **superseded at M1**: crates.io actually had `aya` **0.16.0**, `aya-ebpf` 0.3.0, `aya-log` 0.4.0 (the web search had returned a stale page). M1 uses `aya` 0.16.0 + `aya-ebpf` 0.3.0.
- Dioxus **0.7.x** is the current stable line (docs.rs showed `dioxus 0.7.9` and `dioxus-desktop 0.7.10`); `0.8.0-alpha.1` exists and is a pre-release. Desktop uses `wry` with the system webview (`os-webview`).
- Search results did **not** confirm exact crates.io latest patch numbers, WebKitGTK package names, or `aya-ebpf` versions. Those are ❓ until M1.

Nothing about kernel hooks was verified against a running kernel. Section 14 lists the test environment I need from you.

---

## 1. Summary: where the spec is wrong, weak, or needs a decision

I follow the spec's architecture. These are the concrete problems I found. Items 1–5 need your decision (also listed in §15).

1. **A plain hash chain does not deliver the stated threat model.** Anyone with root can rewrite a segment, recompute every later hash, and `witness verify` passes. A chain only detects *partial*, *inconsistent* tampering. To make "any modification, deletion, truncation is provable" true, the chain must be anchored in something the attacker cannot rewrite. Proposal (§5.4): a **forward-secure sealed MAC** (journald-FSS style) plus periodic **head-hash anchors** the admin can store off-host (a 32-byte value, not log shipping). Without either, the guarantee is only "detects accidents and naive tampering". Even with sealing, **tail truncation** after the last anchor and **deletion of the newest segments** cannot be proven. I document that limit instead of hiding it.
2. **"Rust stable everywhere" is not possible for the eBPF crate.** 📘 `aya` eBPF programs compile for `bpfel-unknown-none` with `-Z build-std=core` and need `bpf-linker`. That requires a **pinned nightly** toolchain for `witness-ebpf` only. The userspace workspace stays on stable. The compiled BPF object is built in CI and embedded with `include_bytes!`, so end users and packagers never need nightly.
3. **CO-RE in Rust/aya is the largest technical risk.** ❓ The loader can relocate against `/sys/kernel/btf/vmlinux`, but I am not certain Rust-authored programs get reliable *field-offset* relocations the way clang's `preserve_access_index` does. Direct typed field accesses in tracing programs are compiled with fixed offsets. Proposed design (§3.2): the eBPF side reads kernel structs only with `bpf_probe_read_kernel(base + offset)`, where **offsets are resolved at load time in userspace from the running kernel's BTF** and passed in as read-only globals. It is portable, testable, and independent of compiler relocation support. This is a deviation from "CO-RE" in the strict sense; the goal (one binary, many kernels) is preserved. M1 starts with a spike to confirm whether native relocations work. If they do, I'll use them.
4. **"Read-only API" conflicts with the GUI requirements.** Triage status (new/ack/false-positive) and the rule editor/enable/disable are writes, and the GUI must be unprivileged. Proposal (§9): API tiers by `SO_PEERCRED`. Tier 1, group `witness`, can read and triage. Tier 2, root or group `witness-admin`, can change rules. Triage and rule changes are written to the evidence chain as audit events (with the actor's uid), never edited in place.
5. **"No reading file contents beyond hashing" conflicts with several detections.** "New SSH authorized key" and "user/group account changes" need to parse `authorized_keys`, `/etc/passwd`, `/etc/group` and `/etc/shadow`. Proposal: a narrow exemption. Witness parses these specific structured files, stores only *derived* facts (key fingerprint + type + options hash; account name/uid/shell/home; for shadow only "hash field changed" plus the SHA-256 of the hash field, never the hash itself), and never stores raw contents. Any other file is hashed only.
6. **Pipeline order.** The spec says capture → enrichment → rules → storage. An alert must reference the triggering event's sequence number, so the event must be assigned a `seq` and stored first. Real order: capture → enrichment → **seq assignment + storage**, with the rule engine consuming a tee of the stored stream and writing alerts back as new events. This also guarantees the rule engine can never stall storage.
7. **Linux audit netlink is not a reliable primary source.** Only one process can be the audit daemon; a running `auditd` owns it. Witness can join the read-only multicast group (`AUDIT_NLGRP_READLOG`, needs `CAP_AUDIT_READ`) and receive whatever events exist, but it cannot assume audit is enabled or has rules, and enabling it would fight `auditd`. Audit is therefore **optional, passive, off by default**. Primary auth sources are eBPF + logind (D-Bus) + journald + utmp/wtmp/btmp (§2).
8. **Notifications need a long-running per-user process.** A root daemon cannot cleanly post to each user's session bus, and the GUI only notifies while running. Recommend a tiny `witness-notify` user service (or GUI-in-tray autostart). Needs your decision (§15).
9. **"Keep forever" is expensive.** Estimates in §5.7 suggest ~0.4–1 GB/day compressed segments plus ~2–3 GB/day index on a busy desktop. File events dominate. The defaults (priority classes, in-kernel path policy) matter a lot. The index is rebuildable, so `witness archive` can also offload old index ranges.
10. **Boot coverage cannot be total.** Witness cannot observe the kernel/initramfs/early-boot window before the unit starts. §10 documents what is covered and how that window is made *visible* (a `boot_to_start` gap record) rather than invisible.
11. **`witnessd` cannot record its own SIGKILL.** A killed process writes nothing. What we can prove is the *absence*: unclean-shutdown detection on next start plus a gap record. Optional improvement (§10.4): pin BPF links so the kernel keeps capturing into the ring buffer while the daemon restarts.

---

## 2. Hook selection table

Notation: `tp_btf` = BTF-enabled raw tracepoint (aya `BtfTracePoint`), `fentry`/`fexit` = BPF tracing programs on kernel functions (aya `FEntry`/`FExit`), `tracepoint` = classic tracepoint. Min kernel = minimum needed for the *mechanism*; all of these are ≤ 5.15 📘 unless noted, except where noted.

Kernel feature floor used by the design 📘: BPF ring buffer 5.8; `bpf_ktime_get_boot_ns` 5.8; `tp_btf` and `fentry/fexit` 5.5 (x86_64); `bpf_d_path` 5.10 (only callable from an allowlist of attach points — **❓ must verify each target function against the 5.15 allowlist; fallback is a manual dentry walk**); `CAP_BPF`/`CAP_PERFMON` 5.8; read-only/bss globals 5.2. **Not usable on 5.15**: `bpf_loop` (5.17), `FAN_RENAME` (5.17), BPF LSM is not a floor (needs `lsm=bpf`).

Program-side rule: no sleepable programs, no LSM programs required. Optional BPF-LSM is probed at startup and reported; nothing depends on it.

### 2.1 Processes

| Event | Program / attach point | Min kernel | Notes and known gaps |
|---|---|---|---|
| exec | `tp_btf/sched_process_exec` (args: task, old_pid, `linux_binprm*`) | 5.5 | argv/cwd read from the *new* mm (`mm->arg_start..arg_end`, via `bpf_probe_read_user`) **after** exec completes, which avoids the TOCTOU you get from reading `sys_enter_execve` user pointers. exe path from `bprm->file` (resolved), plus the as-given filename. argv is emitted as header + **chunks** (verifier needs bounded sizes); cap 64 KiB/exec with a `truncated` flag. Env capture optional, off by default. |
| exec failures | `tracepoint/syscalls/sys_exit_execve{,at}` (ret < 0) | 4.x | Low priority; useful for probing detection. Path from entry stash in a per-task map. |
| fork/clone | `tp_btf/sched_process_fork` (parent, child) | 5.5 | Emit for processes (`tgid` differs); thread creation is counted, not stored by default. |
| exit | `tp_btf/sched_process_exit` (task) | 5.5 | Fires per *thread*. Emit once per process when the last thread exits (check `signal->live`/thread-group state ❓ verify in M1). Exit code and signal from `task->exit_code`. |
| setuid/setgid/capset | `fentry/commit_creds` (old/new `cred`) | 5.5 | One hook catches every credential change (setuid family, `capset`, setuid-exec, `setresuid`) and records old vs new uid/gid/euid/egid/suid/fsuid and cap sets. Gap: kernel-internal `override_creds` (overlayfs, nfsd) is a different path and is intentionally not hooked. ❓ confirm `commit_creds` is not inlined/is present in BTF on all four target distros. |
| TTY shell commands | derived from exec | — | Interactive = exec where `task->signal->tty` is set (tty name captured) and parent is an interactive shell (parent comm/exe in configured shell list). Never reads history files. Gaps: shell builtins (no exec), commands run by `ssh host cmd` without a TTY are still captured as plain exec with session info but not tagged "interactive". |
| process tree | enrichment from fork/exec/exit | — | See §4.4. Unique key = `puid` = (boot_id, pid, start_boot_ns). |

### 2.2 Files

All file events use **`fexit`** on LSM-hook *call sites in the VFS* (`security_path_*`, `security_file_open`). These are ordinary, non-LSM functions attachable by fentry even when no BPF LSM is enabled. 📘 They give `struct path`, so a full path can be built. Because they run at the security-check stage, **"result" means "the security check passed", not "the operation succeeded"**; this is documented in the schema (`result: Allowed|Denied`).

❓ Each function must be present in BTF on every target kernel (inlining/renames). Fallback per function: kprobe on the `vfs_*` function, or the syscall tracepoint (path as given, not resolved, flagged `path_resolved=false`). M3 includes a `witnessd doctor` check that prints the active mechanism per hook.

| Event | Attach point | Notes |
|---|---|---|
| create | `fexit/security_path_mknod`, `security_path_mkdir` | `open(O_CREAT)` reaches `security_path_mknod` via `may_o_create` 📘 (verify). |
| open for write | `fexit/security_file_open` with `f_mode & FMODE_WRITE` or `O_TRUNC/O_APPEND` | The highest-volume hook. Gated by policy (below). Read-opens are emitted only for the configured sensitive-read list (`/etc/shadow`, SSH keys, etc.). |
| modify | derived (see below) | Deliberately **not** hooking `vfs_write` (hot path). |
| delete | `fexit/security_path_unlink`, `security_path_rmdir` | |
| rename | `fexit/security_path_rename` | Records old and new path. |
| chmod / chown | `fexit/security_path_chmod`, `security_path_chown` | SUID/SGID bit detection: new mode has `S_ISUID`/`S_ISGID` and old mode did not → `suid_set=true`. Also check on create (mode argument). |
| link / symlink | `fexit/security_path_link`, `security_path_symlink` | Target string recorded for symlinks. |
| truncate | `fexit/security_path_truncate` | |
| close after write | `fentry/security_file_free` (only for `struct file*` previously marked in an LRU map) | Emits `file_close_write`; triggers async hashing for critical paths. Cost is one map lookup per file free system-wide; ❓ benchmark in M3. Alternative: fanotify `FAN_CLOSE_WRITE` on critical directory marks (gives an fd, hashing is TOCTOU-free). |

**Modify semantics (stated plainly):** Witness records *open-for-write* and *close-after-write* by process, plus truncate. For critical paths it additionally hashes after close (debounced) and records whether the hash changed. "Modified" is therefore a *derived, hash-confirmed* fact for critical files and *"opened for write and closed"* for everything else. mmap-based writes are covered by the open-for-write. Writes through an fd inherited or passed to another process are attributed to the opener at open time; the later writer is not distinguished. 

**Filtering strategy:** (a) in-kernel exclusions by filesystem magic (proc, sysfs, devpts, cgroup, bpf, tracefs), non-regular files, and Witness's own tgid; (b) policy match on the resolved path. Plan A: an LPM trie of path prefixes in-kernel. Plan B: userspace glob match before enrichment. M3 decides by measurement. Non-matching writes are *counted* per directory bucket (a `file_activity_summary` event every 60 s), never silently ignored.

Gaps: paths are relative to the process's mount namespace/root (fine for bare host; noted for future container work). Path components longer than the in-kernel limit are truncated with a flag (limit configurable, default 4096 bytes). Files on network filesystems are attributed to the local process only.

### 2.3 Network

| Event | Attach point | Min kernel | Notes and known gaps |
|---|---|---|---|
| TCP connect (active open) | `fentry/tcp_v4_connect`, `tcp_v6_connect` (stash `sock* → process` in a map) + `tracepoint/sock/inet_sock_set_state` for outcome | 4.16 (tp) / 5.5 | State change to `ESTABLISHED` for an active open happens in softirq context, where `current` is not the owner, hence the stash. Failed connects (`SYN_SENT → CLOSE`) are recorded (scan detection). |
| TCP accept | `fexit/inet_csk_accept` (returns `struct sock*`) | 5.5 | `current` is the accepting process. Peer addr/port from the sock. |
| TCP close + bytes | `inet_sock_set_state` → `CLOSE`/`TIME_WAIT` and read `tcp_sock->bytes_sent/bytes_received` ❓ (verify field presence per kernel) | 4.19+ | `bytes_*` may be absent on odd configs → `null`, not 0. |
| Listen open/close | `inet_sock_set_state` to/from `TCP_LISTEN` | 4.16 | `listen()` is in process context; close of a listener may not be (record process if known, else last owner from the map). |
| UDP send/recv summaries | `fentry/udp_sendmsg`, `udpv6_sendmsg`; `fexit/udp_recvmsg`, `udpv6_recvmsg` | 5.5 | Aggregated in-kernel per (puid, proto, laddr, lport, raddr, rport) in a per-CPU hash map; flushed every N seconds (default 5) as `udp_flow_summary`. Unconnected sockets: remote from `msghdr->msg_name`. |
| DNS query/response | Same UDP hooks, `dport/sport == 53`: copy first ≤ 512 B of the payload from `msghdr` iovecs into a per-CPU scratch buffer and emit a raw `dns_packet` record; **userspace parses** the wire format. TCP/53 best-effort from `tcp_sendmsg`/`tcp_recvmsg`. | 5.5 | `iov_iter` layout changed in 6.0 (`ITER_UBUF`); ❓ must handle both. Gaps — **be aware**: queries to `systemd-resolved` through its stub on 127.0.0.53 are captured (attributed to the app), and resolved's upstream queries are separately attributed to resolved; but **nss-resolve/varlink/D-Bus lookups that never touch port 53 are invisible**, and DoT/DoH are not decodable (only the TLS connection to the resolver is seen). Responses use `fexit` of recvmsg to read the copied-in data; large (EDNS) responses are capped and flagged `truncated`. |
| Per-process connection history | enrichment/index | — | Table keyed by `puid`. |

Not captured: AF_UNIX, raw/packet sockets, ICMP, SCTP.

### 2.4 Auth and system

| Event | Source | Min kernel | Notes and known gaps |
|---|---|---|---|
| Login/logout (local, SSH) | **systemd-logind D-Bus** (`SessionNew`/`SessionRemoved`, via `zbus` on the system bus) + **utmp/wtmp** (inotify + struct parse) | n/a | Session `auid`/`sessionid` also come from the kernel task fields on every event. Gap: systems without logind. |
| Failed logins | **journald** (sshd/login/gdm/PAM messages) + **btmp** | n/a | sshd text messages (`Failed password for…`) are parsed by regex; fragile across OpenSSH versions → raw message always stored too. |
| sudo / su with command | exec events (`sudo`/`su` and the child with the same session) + journald (`sudo: … COMMAND=…`, `su[…]:`) | n/a | The privileged child's exec carries the real command; journald supplies the policy decision and target user. Optional: audit `USER_CMD` if audit multicast is available. |
| USB/block attach/detach | **raw kernel uevent netlink** (`NETLINK_KOBJECT_UEVENT`, group 1) + sysfs read for vendor/product/serial/manufacturer | n/a | Group 1 (kernel) avoids a libudev dependency. ❓ confirm group 1 bind needs no more than the caps we hold. Attach = `add` of `usb`/`block` subsystems. |
| Kernel module load/unload | `tp_btf/module_load`, `tp_btf/module_free` (tracepoints `module:module_load`/`module_free`) + `tracepoint/syscalls/sys_enter_{init,finit,delete}_module` for attribution and failures | 5.5 | `module_load` fires in the loading process's context → attribution is exact. |
| systemd service start/stop/enable/disable | **systemd D-Bus** signals (`org.freedesktop.systemd1.Manager`: `JobNew`, `JobRemoved`, `UnitNew`, `UnitFilesChanged`) + file events on unit dirs (an `enable` is a symlink create) | n/a | Actor = exec of `systemctl` in the same session/ancestry (enrichment), not the D-Bus sender (which is systemd/PID 1 for job results). |
| cron/timer changes | file events on `/etc/cron*`, `/var/spool/cron`, unit dirs; `.timer` via D-Bus | — | |
| Package install/remove | exec of `apt/apt-get/dpkg/dnf/rpm` + tail of `/var/log/dpkg.log`, `/var/log/dnf.log` / `dnf5.log` (❓ names/formats differ per Fedora release; verify on current Fedora) | — | Package log lines give name+version+action reliably; the exec gives *who*. |
| Account changes | file events on `/etc/{passwd,shadow,group,gshadow}` + structured diff (see §1.5) | — | |
| Boot / shutdown | boot ID (`/proc/sys/kernel/random/boot_id`), daemon start record, logind `PrepareForShutdown` | n/a | |
| Clock changes | `timerfd` on `CLOCK_REALTIME` with `TFD_TIMER_ABSTIME|TFD_TIMER_CANCEL_ON_SET` (returns `ECANCELED` immediately on a clock *step*) 📘 + `tracepoint/syscalls/sys_enter_{settimeofday,clock_settime,adjtimex,clock_adjtime}` for attribution | 2.6.39 | Slewing via `adjtimex` is normal NTP and logged at low priority; **steps** above a threshold are alerts. |

### 2.5 Capture-source health

Each source (every eBPF program group, each ring buffer, fanotify, D-Bus, journald, uevent, audit) reports `Active | Degraded(reason) | Unavailable(reason) | Disabled` and per-source counters (events, drops, last event time). Reported at startup (`witnessd doctor`), stored as `source_health` events on change, and shown in the GUI.

---

### 2.6 M1 as built and verified (Ubuntu 22.04, kernel 5.15.0-198-generic, aarch64)

**Spike A — CO-RE from Rust (resolved).** `aya`'s loader (`aya-obj`) implements CO-RE relocations and `bpf-linker` knows the LLVM `preserve_access_index` intrinsics, but `aya-ebpf` 0.3.0 offers Rust code **no way to emit a field access that carries a relocation** (no macro or helper), and `aya-obj` keeps BTF struct members private. So the design's fallback is what ships: `witnessd/src/btf.rs` parses `/sys/kernel/btf/vmlinux` itself and resolves 18 `(struct, field)` offsets (recursing into anonymous structs/unions, rejecting bitfields), passed to the programs as the read-only `OFFSETS` global; programs read with `bpf_probe_read_kernel`. All 18 resolved on this kernel with no gaps. Required fields missing → startup error; optional ones (`loginuid`, `sessionid`, `signal.tty`, `tty.name`) degrade individually.

**Spike B — `fentry`/`fexit` targets (resolved for this kernel).** `witnessd doctor` checks BTF for every planned target. On 5.15.0-198 **all 22 exist**: `commit_creds`, `security_file_open`, `security_file_free`, `security_path_{mknod,mkdir,unlink,rmdir,rename,chmod,chown,link,symlink,truncate}`, `tcp_v4_connect`, `tcp_v6_connect`, `inet_csk_accept`, `tcp_{send,recv}msg`, `udp{,v6}_{send,recv}msg`. Not yet checked: other kernels/arch (Debian 12, Ubuntu 24.04, Fedora, x86_64) — `doctor` is the tool for that.

**Programs (`witness-ebpf`):** `tp_btf` on `sched_process_exec`, `sched_process_fork`, `sched_process_exit`, writing fixed-size records into a P0 ring buffer; drops are counted in a per-CPU `DROPS` map and surfaced as a warning (not yet stored as a `capture_drop` event). The verifier accepted all three on the first load. Self-exclusion by `SELF_TGID`.

**Build.** `witness-ebpf` is its own cargo workspace and is compiled by `witnessd/build.rs` with a pinned nightly (`nightly-2026-11-17`, `-Z build-std=core`, `bpf-linker` 0.13.0) and embedded with `include_bytes_aligned!`. `aya-build` was *not* used: it requires the eBPF crate to be a member of the main workspace, which would make `cargo clippy --workspace` try to build a `no_std` BPF binary for the host. Off Linux or with `WITNESS_SKIP_EBPF=1` an empty placeholder is embedded.

**Verified on the real kernel** (`witnessd/tests/integration.rs`, root-only, `--ignored`): fork → exec → exit are linked by one process identity (`puid`) and ordered by kernel time; exit codes and death-by-signal; an 8 KB argument is truncated and flagged; the daemon's own processes are excluded; a burst of 500 execs loses none.

**Known gaps (M1, to be closed):**
- `argv` is capped at 3 KiB in a single record (flagged `argv_truncated`); the designed 64 KiB chunked records are not built yet.
- `exe` is resolved by `readlink /proc/<pid>/exe` right after the event and falls back to the as-passed filename; this can race with a very short-lived process. A kernel-side dentry walk arrives with the file hooks (M3).
- `exit` is emitted for the thread-group **leader** only; a multithreaded process whose leader exits first is reported at leader exit.
- `fork` events carry no parent `comm`; `cwd`, environment and `stdio` kinds are not captured yet.
- Wall-clock time uses one offset sample per poll cycle, not the 100 ms sampling in §3.4.

### 2.7 The storing daemon, as built (verified on Ubuntu 22.04 / 5.15.0-198 / aarch64)

`witnessd run [--config F] [--data-dir D]` is the daemon; `witnessd tail` prints events without storing (debugging); `witnessd doctor` reports kernel support. The pipeline (`witnessd/src/pipeline.rs`) is kernel-independent and unit-tested with a fake clock.

- **Start:** take the writer lock (a second daemon is refused with a clear message), repair a torn tail (bytes quarantined, a `recovery` record written), read what the previous run left, then write `capture_gap` (always, on any restart) and `daemon_start`. The previous run is classed **clean** only if a `daemon_stop{clean:true}` is among the last two records; otherwise **unclean**. The gap's start time comes from the last real event/daemon record. A different `boot_id` is `new_boot`; boot-relative times are not carried across boots.
- **Run:** events are stored in arrival order through the disk-full policy (priority from the event type); kernel ring-buffer overflows become `capture_drop{reason:"ring_overflow"}` records; group commit (`storage.group_commit_ms`); a seal every `seal.interval_secs` (if enabled) and an anchor every `storage.anchor_interval_secs`, published to `anchors.log` and the optional admin command; the SQLite index is maintained by a separate thread that only reads the segments.
- **Stop (SIGTERM/SIGINT):** detach from the kernel, final seal and anchor, `daemon_stop{clean:true, signal}`, seal the segment. `daemon_stop` is intentionally the last *data* record so the next start can recognise a clean shutdown. SIGKILL leaves no stop record; the next start records an `unclean` gap and the events already written survive (tested).
- **Fixed along the way:** user search text was handed to FTS5 as query syntax, so a plain search for `job-77` failed (`-` is NOT); it is now quoted word by word (trailing `*` = prefix).
- Not yet done (M6): systemd unit and `sd_notify`/watchdog, baseline snapshot, the API socket, and the journald anchor sink.

### 2.8 The service, as built and verified (Ubuntu 22.04 / 5.15.0-198 / aarch64, real reboots)

`packaging/systemd/witnessd.service` (`Type=notify`, `READY=1` only after the eBPF programs attach; `WatchdogSec=30` with pings from the main loop only; `Restart=always`, `RestartSec=1`) and `packaging/dev-install.sh`. Verified on the VM:

- **Boot ordering (monotonic µs since boot):** `witnessd` active at 3.13 s, before `network-pre.target` 3.39 s, `network.target` 3.44 s, `systemd-user-sessions` 5.01 s, `ssh` 5.04 s. Not claimed: anything before `local-fs.target` (kernel, initramfs) — that window is only made visible, via the `new_boot` gap.
- **Graceful power cycle:** `daemon_stop{clean, signal 15}` at shutdown; at boot `capture_gap{new_boot, prev_shutdown:clean}` + `daemon_start`. **Hard power-off:** `capture_gap{new_boot, prev_shutdown:unclean}`; the chain verifies (no torn tail needed repair in this run).
- **`kill -9`:** systemd restarted it within the 1 s `RestartSec`; unclean gap recorded; events captured before the kill survived.
- **Watchdog:** a SIGSTOP'd (frozen but alive) daemon was replaced by systemd at ~30 s; the recorded gap covered the ~29 s freeze.
- **`systemctl stop`:** `Result=success`, exit 0, `reason: signal`.
- **Capabilities, measured:** capture works with only `CAP_BPF` + `CAP_PERFMON`; dropping either (with `CAP_SYS_PTRACE` alone) prevents startup. The unit keeps `CAP_SYS_PTRACE` (other users' `/proc/<pid>/exe`, `cwd`) and `CAP_DAC_READ_SEARCH` (hashing, M3) and **omits `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_AUDIT_READ`** until a tested feature needs them. The doc's earlier draft list (§6.1) was a starting point; this supersedes it.
- **Bugs found only by real shutdowns, now fixed and regression-tested:** (1) systemd's SIGTERM interrupted `poll()` (`EINTR`) and the loop treated it as fatal, so every stop exited 1 and showed "Failed"; (2) a SIGTERM arriving during `signal-hook`'s own registration was silently swallowed and the daemon ran on. Both are gone: SIGTERM/SIGINT are blocked first thing (before any thread) and read from a `signalfd`, so a signal can neither be lost nor kill the process mid-startup. The only remaining window is before `main()` runs its first line, when nothing has been written yet.

### 2.9 The baseline snapshot, as built and verified

`witnessd/src/baseline.rs`, run right after `READY=1` (so it never delays services ordered after the daemon) and after the programs attach (so nothing falls between snapshot and live capture; duplicates are harmless). On the VM under the hardened unit: **270 records in 10 ms** (116 processes, 8 listening sockets, 1 session, 93 modules, 45 mounts, 2 block devices, 4 USB devices).

- **Records:** `baseline` events (`src: baseline`, **P0 — never shed**) of kind `process` (with a full `actor`, so the tree can be rebuilt; `parent_puid` links it; kernel threads flagged), `listen_socket`, `session`, `module`, `mount`, `block_device`, `usb_device`, closed by a `summary` with counts.
- **Identity across baseline and live capture (important):** `/proc/<pid>/stat` only exposes start time in 10 ms ticks, while the eBPF programs read exact nanoseconds. `puid` is therefore `<boot>-<pid>-<start ns / 10 ms>`, which is exactly what `/proc` reports, so the baseline record of a process that predates the daemon and the live `proc_exit` for it name it **identically**. Tested on the real kernel (a `sleep` started before the daemon, killed after baseline; same `puid`, and its parent link resolves). A pid cannot be reused twice within 10 ms.
- **`discovered_in_gap`:** after a same-boot restart, processes that began after the last record before the gap are flagged: they started while nothing was watching.
- **Deviations from the draft (§6.6), deliberately:** listening sockets come from `/proc/net/{tcp,tcp6,udp,udp6}` mapped to owners through `/proc/<pid>/fd` instead of `sock_diag` netlink (no new capability, trivially testable; UDP "listeners" are bound, unconnected sockets); sessions come from logind's state files in `/run/systemd/sessions/` instead of D-Bus (no D-Bus dependency yet; the file format is logind-internal, so utmp is the planned fallback in M5). Both are covered by fixture-tree tests, and `Roots` makes the paths injectable.
- **Not captured yet:** a process's `tty`, `cwd`, and environment; established connections; open files.

### 2.10 File events, as built and verified (Ubuntu 22.04 / 5.15.0-198 / aarch64)

Eleven kernel hooks report create, mkdir, open-for-write, unlink, rmdir, chmod, chown, truncate, rename, hard link and symlink with the **absolute path built in the kernel** (walking dentries, stepping over mount points), the actor, and `dev`/`ino`. Verified by root integration tests: a file's whole life is captured with correct paths, SUID chmod is detected (`old 0664 -> new 04755`), a path through a separate mount (`/dev/shm`) and a 23-level path are exact, a 255-byte name and a non-UTF-8 name survive, procfs writes are filtered in the kernel, a burst of 500 creations loses none, and the daemon's own writes are not recorded. Under the hardened unit it stores, for example, `mkdir/tee/chmod/mv/rm` on `/etc/...` with `uid=0` **and `auid=501`** (the real login behind a sudo).

**Hooks are kprobes, not fentry/fexit (deviation from §2.2).** BPF trampolines do not exist on arm64 before Linux 6.0, so `fexit` programs load but fail to attach on this 5.15 aarch64 VM; and `security_path_chown` takes `kuid_t`/`kgid_t` structs by value, which trampolines cannot carry on 5.15 anyway. Kprobes work on both architectures. The cost: a kprobe sees the call but not its return value, so file events carry `result: "attempted"` rather than `allowed`/`denied` (kernel side `RESULT_UNKNOWN`). On x86_64, `fexit` could restore the real result later. Each hook's BTF parameter count is checked against the running kernel at load; a mismatch degrades that hook and is recorded as `source_health`, never read as the wrong argument.

**Path walk.** The walker assembles the path right-to-left in a per-CPU 16 KiB scratch buffer (sized so 40 levels of 256-byte names can never wrap), then does one bounded copy of at most 1 KiB into the record, left-aligned with an explicit length. `path_truncated` means the walk stopped before the namespace root (more than 40 levels) or a name was oversized or the path exceeded 1 KiB; a truncated path keeps its leaf end. Filesystems that are not host activity (proc, sys, devpts, cgroup, debugfs, tracefs, bpf, ...) and non-regular files (for opens) are dropped in the kernel. Layout assumptions (`d_name` directly after `d_parent`, `qstr.len` at +4 and `name` at +8, `mnt_mountpoint` after `mnt_parent`) are validated against BTF at load, otherwise file capture is degraded with a reason.

**What the verifier taught us (so nobody repeats it).** Getting these programs through the 5.15 verifier took most of this milestone. The rules that mattered:
1. *A branch whose two outcomes both stay live multiplies the verifier's work.* Every `read(...).unwrap_or(default)` is one; a dozen in a row meant thousands of paths. All kernel reads are now **branch-free** (`rd_or`: store the default, let the helper overwrite it, never test its result).
2. *Do not compare two variables that have ranges.* `if off < len + 1` made every path distinct. The offset is masked instead, and the buffer is large enough that wrapping is impossible.
3. *Remove clamp branches that cannot trigger.* `if len > 255 { len = 255 }` (names cannot exceed `NAME_MAX`) cost a factor of ~3 per loop level, giving a cliff between depth 6 and 8. Replaced by a mask, with oversize evidence OR-ed into a flag tested once after the loop. With that change the depth went from "fails at 8" to **40 levels, linear cost**.
4. *`MaybeUninit::zeroed()` and struct zero-init can compile to `compiler_builtins`' byte-loop `memset`*, which the verifier then explores iteration by iteration. Initialise small structs with field stores.
5. *Diagnose from data, not intuition:* `WITNESS_VERIFIER_LOG=verbose` dumps the full trace; `WITNESS_ONLY_HOOK=<func>` loads one hook; aya's default retry-with-bigger-log loop turns a rejection into minutes, so stats-only logging is the default.

**Startup.** The eleven file programs are verified **concurrently** (the verifier is CPU-bound and per-program): 5.7 s serial became 2.5 s on 4 CPUs. Loading checks for a pending stop request between batches, so SIGTERM during a slow start is honoured within about a batch.

**Path policy and attribution (`filepolicy.rs`, `decode.rs`).** Built-in *critical* paths (`/etc`, `/usr/bin`, `/boot`, `/root/.ssh`, `/home/*/.ssh`, cron and systemd unit dirs, kernel modules, dpkg/rpm databases, Witness's own data dir) keep every operation; *watched* paths (`/tmp`, `/var/tmp`, `/dev/shm`, plus `files.watch`) keep creates/deletes/attribute changes and treat plain writes as the first thing shed (P2); everything else is **counted per directory** and emitted as a `file_activity_summary` every 60 s, never silently ignored. `files.exclude` always wins. A process table (filled from exec events and the baseline; a forked child inherits its parent's image until it execs) gives file events the actor's `comm`, `exe` and command line, since the kernel record carries only identity.

**Measured on the VM (service running, file hooks on):** 0.79% of one core idle, 0.67 CPU-seconds for a burst of 2,000 spawns plus 3,000 file creations with zero ring-buffer loss, 94 MiB RSS.

**Critical-file hashing (`hasher.rs`).** A content-changing event (write-open, create, truncate, rename destination) under a *critical* path starts that file's quiet period (`files.hash_debounce_ms`, default 2 s; each new write restarts it, so a burst costs one hash). A worker thread then hashes it under a byte-rate limit (`files.hash_rate_mib_per_sec`) and size cap (`files.hash_max_mib`), opening with `O_NOFOLLOW|O_NONBLOCK` so a symlink is never followed and a FIFO cannot block it. A `file_hash` event is stored only when the content **differs from the last hash taken**: it carries `sha256`, `prev_sha256`, size, mtime, and the **actor of the change that triggered it**; an identical rewrite produces nothing, and a file that cannot be hashed (vanished, too large, not regular) is recorded with the reason. Tracked paths and remembered hashes are bounded. Verified on the real kernel: first sighting, one real change naming the previous hash, nothing for an identical rewrite, nothing for a watched-but-not-critical path.

**Sensitive reads.** A read-only open is reported only for files on `files.sensitive_read` (default `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers`). The kernel matches by **`(dev, inode)` in a BPF hash map** that userspace fills from the configured paths (converting glibc's `st_dev` to the kernel's `major<<20|minor`), so an ordinary open costs one map lookup and no path walk. The set is re-resolved when a file event touches a listed path and every 30 s, because tools like `passwd` replace the file (a new inode): verified by replacing a sensitive file with a rename and seeing reads of the *new* file reported. These events are P1: never the first thing shed. **Measured cost:** about 0.5 µs per open (`open`+`close` in a tight loop: 2.78 µs without the daemon, 3.3 µs with it), the worst case since that loop does nothing else.

**Not done:** no `close`-after-write event (a write is a write-open followed, once quiet, by a hash); extended-attribute changes; the real hook result on x86_64; `files.sensitive_read` takes literal paths, not globs; the 60-second per-directory summaries are unit-tested but not yet observed end to end; x86_64 and other kernels are unverified (`witnessd doctor` is the tool).

### 2.11 TCP and DNS events, as built and verified (Ubuntu 22.04 / 5.15.0-198 / aarch64)

**TCP lifecycle.** `tcp_v4_connect`/`tcp_v6_connect` (kprobe) record the owner (pid, comm) in an LRU map keyed by `struct sock *`; `inet_csk_accept` (kretprobe) records accepted sockets; `inet_sock_set_state` (tp_btf, two programs: `tcp_state` for ESTABLISHED/CLOSE, `tcp_listen` for LISTEN) emits `net_connect`, `net_connect_failed`, `net_accept`, `net_listen`, `net_close`, `net_listen_close`. Sockets are attributed to the process that created them, not to whichever context runs the close (often a softirq).

Lessons, all hit on the real kernel:
- **The kernel clears `skc_num` (local port) when a socket closes.** Addresses are therefore snapshotted into the map record while the socket is live (`NetAddrs`) and the close event uses the snapshot.
- **BPF stack is 512 bytes.** The 136-byte owner record cannot be copied around; it is filled in place (`fill_owner`, `read_addrs_into`) or used through `get_ptr_mut`. Every byte must be initialised before `insert`, or the verifier rejects the read of uninitialised stack. One program with listen + established + close exceeded the limit, hence the split.
- **`tcp_bytes_received` includes the peer's FIN.** The kernel records `sk_shutdown & RCV_SHUTDOWN` in `flags`; userspace subtracts one byte. Verified: client 5 sent / 8 recv, server 8 / 5.
- **Two rings are not ordered.** Exit records (critical ring) and network/file records (volume ring) are merged per poll batch by kernel timestamp, and the decoder keeps exited processes for a 30 s grace so late events still carry exe/cmdline.

**UDP and DNS.** `udp_sendmsg`/`udpv6_sendmsg` (kprobe) capture the first iovec when the destination port is 53 (taken from `msg_name` or the connected socket). For answers, `udp_recvmsg`/`udpv6_recvmsg` kprobes save the receive buffer address in a map keyed by `pid_tgid` at entry, and the kretprobes copy the returned bytes (the iterator has moved on by then). Up to 512 bytes of each packet are copied (`DNS_CAP`); the wire format is parsed in userspace (`witnessd/src/dns.rs`: compression pointers with a hop limit, total on malformed input, tested against truncation at every length). `iov_iter` handling covers both the pre-6.0 layout (`ITER_IOVEC = 0`) and 6.0+ (`ITER_UBUF` first); only the 5.15 layout is **verified on a real kernel**, the 6.x path is *compiled only*.

Not done: TCP/53 and DoT/DoH (not visible this way), per-flow UDP summaries for non-DNS traffic, per-process connection history views.

**Measured.** All 22 programs verify on 5.15.0-198 aarch64 with no rejections. Startup with every hook is about 4.9 s since loading uses a work queue (heaviest verifier jobs first) instead of fixed batches (was 6.8 s); `security_path_rename` alone takes about 3.7 s in the verifier. Privileged suite: 23 tests pass, including TCP lifecycle with byte counts, child-process attribution and DNS query/response with parsed answers. x86_64 is still unverified.

### 2.12 Auth and system events, as built (Ubuntu 22.04 / 5.15 / aarch64)

Userspace sources run on their own threads (`witnessd/src/sources.rs`) and are stamped by the main loop; each reports to `source_health` as `auth`.

| Event | How it is actually captured | Verified on a real kernel |
|---|---|---|
| sshd login/failure, sudo/su | `journalctl -f -o json` child filtered on `_COMM`, parsed by `authlog.rs`; the journal's own timestamp is kept | yes (`sudo`, failed ssh against the local sshd) |
| Account changes | polled diff of `/etc/passwd`, `group`, `shadow` (1 s, stat-gated); only a SHA-256 of the shadow password field is stored | yes (useradd, `usermod -p`, userdel) |
| `authorized_keys` | polled diff per home directory; OpenSSH-style `SHA256:` fingerprints (checked against `ssh-keygen -l`); options stored as a digest; files opened `O_NOFOLLOW`, capped at 4 MiB | yes |
| Package changes | tail of `/var/log/dpkg.log` (whole lines only, rotation-aware) and `/var/log/dnf.rpm.log` | dpkg: yes (observed during `apt install`). **dnf: parser and tail tested against hand-written samples only; the format is from documentation and has never been checked on a real Fedora/RHEL system** |
| USB / block devices | raw `NETLINK_KOBJECT_UEVENT` group 1; vendor/product/serial read from sysfs | block: yes (loop device add/remove). **USB: parsed and unit-tested, never run against real USB hardware** |
| Kernel modules | `tp_btf` `module_load`/`module_free`, actor = the loading process | yes (`modprobe dummy` is attributed to `modprobe`) |
| Clock steps | `timerfd` on `CLOCK_REALTIME` with `TFD_TIMER_CANCEL_ON_SET` (as §2.4 specified); each wake reports the change in the realtime/boottime offset. A 250 ms offset poll remains only as a fallback and cannot see a step that is undone within one interval | yes (`date -s` both ways). **A first implementation that polled missed steps entirely once the VM's host time sync started reverting them within 20 ms**; the timerfd version sees them. **The step's size is measured when the daemon next runs**, so a step undone before that (observed on emulated x86_64, where the delta then reads tens of ms) is recorded as a step with a small or wrong delta; the *fact* of the step is not lost. Slewing is not reported; the changing syscall is not attributed |

**Service and session events come from the journal's structured fields, not D-Bus** (a deviation from §2.4; D-Bus/`zbus` was not used): systemd's job-completion records (`UNIT`, `JOB_TYPE`, `JOB_RESULT`) become `service_change` (a restart is reported as a stop then a start; a failed job keeps its result), and logind's `New session` / `Removed session` records (`SESSION_ID`, `USER_ID`) become `login` (service `logind`) and `logout`. Verified on a real kernel with `systemctl restart cron` and a real ssh login/logout. Not produced: enable/disable/mask of units, `PrepareForShutdown`/shutdown reasons, non-numeric (`c1`) logind session ids, logind events on systems without journald.

Other gaps from §2.4: ssh `Accepted` lines still produce their own `login` with `session_id` 0, so one ssh login yields two login records (sshd's and logind's); the sshd/sudo parsers are regexes over free text and keep the raw line; sudo escapes newlines as `#012` and that is left as is. A real-journal test found sudo left-pads messages with spaces; that is now handled and covered by a regression test.

**Startup and stop.** All 24 programs load in about 4-5 s on an idle 4-CPU VM (work queue, heaviest verifier jobs first). A SIGTERM during startup is honoured between jobs but cannot interrupt a verifier run already in flight, so a stop during startup takes a few seconds when idle and roughly 30 s with the CPUs saturated (measured); the unit's `TimeoutStopSec` is 60 s for that reason. Nothing is written before attach, so a kill in this window loses no evidence.

### 2.12b Additions after the first final build

- **stdio and cwd at exec.** The decoder reads `/proc/<pid>/fd/{0,1,2}` and `/proc/<pid>/cwd` right after an exec (best effort: the process may already have changed them or exited) and classifies descriptors as tty/pipe/socket/file/null. The rule `witness.exec.shell-on-socket` uses it. Not verified against a real reverse shell; covered by unit tests and the classifier.
- **`actor.user`** is filled from `/etc/passwd` (reloaded on change); a uid with no entry has no name. LDAP/SSSD users are not resolved.
- **UDP flow summaries.** `udp_sendmsg`/`udp_recvmsg` update a per-process, per-socket-pair counter table in the kernel (the owner's header is captured on first sight); the daemon reads and clears it every 10 s into `udp_flow` events. DNS (port 53) traffic is excluded from the flow table. Counters are not atomic across CPUs, so they are approximate under heavy concurrent load. Verified on a real kernel: five 100-byte datagrams and five 40-byte replies gave exactly 500/5/200/5 on the client flow and the mirrored figures on the server flow.
- **DNS over TCP/53.** `tcp_sendmsg`/`tcp_recvmsg` probes return after one port comparison unless the peer is port 53; the 2-byte length prefix is removed, `transport: tcp` is recorded. A query split across several `send` calls, or a response read in pieces, is captured only from its first buffer. DoT (853) and DoH are visible only as TCP connections, not as DNS. Measured cost of the two hot-path probes: a 1 GiB loopback transfer in 64 KiB sends ran at about 11.5 GB/s without the daemon and 10.9 GB/s with it (about 5%, within a 3% run-to-run spread); small-message workloads were not measured.
- **Integrity checks.** The daemon re-verifies the whole chain 5 minutes after start and every 6 hours (`WITNESS_VERIFY_EVERY_SECS` overrides, used by tests) and on `POST /v1/integrity/verify`; each result is an `integrity_check` record, and `witness.self.integrity-failed` alerts on any state other than `ok`. Verified on a real kernel: a flipped bit in a stored record produces a `broken` check and a critical alert. This also exposed that daemon-originated records bypassed the rule engine; `Pipeline::record` now evaluates rules too.
- **Incident bundle** (`witness bundle`, `GET /v1/export?format=bundle`, GUI export): a tar with the verbatim stored lines of a *contiguous* range, `chain-proof.json` (the hash before the range plus every record's hash, self-checked at build time), `alerts.json` with triage state, `anchors.json`, `verify-report.json` and a `manifest.json` of SHA-256s. It refuses a store that does not verify. No signature is produced. Tests extract it with the system `tar` and re-derive every hash independently.
- **`first_seen` rules** alert the first time a field combination is ever seen; the learned set is kept in `learned.json` in the data directory (written atomically, mode 0600, restored at start, flushed at stop). `witness.device.usb-unknown` uses it. Real USB hardware has still not been attached to this code; devices already plugged in at first start produce no event until re-attached.

### 2.13 The rule engine, as built

`witness-rules` implements §8 with these differences, all deliberate:

- **Fields are checked by prefix only** at load time (`actor`, `data`, `type`, `prio`, `src`, `seq`, `boot_ns`, `wall_ns`, `boot_id`). An unknown field under `data.` simply never matches; it is not rejected. Operators, regexes, globs, CIDRs, durations, step references and ids *are* validated, with `file:line:col` for YAML errors.
- `same_tree` is a **real process-tree scope**: the engine learns ancestry from the `pid`/`ppid` of every event and ties a process to its topmost known ancestor (a process whose parent was never seen is grouped under `pid:<ppid>`, so siblings of an unseen parent still share a tree; a reused pid does not inherit the old tree). A process that existed before the daemon started and never emitted an event is not in the map. Verified on a real kernel: the drop/chmod/exec sequence alerted from a real shell. `same_session` and `same_process` are separate scopes.
- Evaluation is **inline** after storage, not on worker threads with drop-oldest. Measured cost (`witness-rules/tests/bench.rs`, release, 500k synthetic mixed events, 21 rules, process-ancestry tracking on every event): 509k events/s on one aarch64 core in the VM (9.8% of a core at 50k ev/s; 492k/s with the earlier 17 rules). The Mac figure varied between 0.65M and 1.5M/s across runs, so it is not quoted as a result. The stream is synthetic and mostly non-matching, so treat this as an upper bound for matching cost, not a guarantee.
- Correlation state is capped (50k groups per rule, 64 partials per group) and evicted wholesale, counted in `Stats::state_evicted`. Same-rule alerts are suppressed per `alert.suppress`, and the swallowed count rides on the next alert.
- Disabled rules are loaded (so they list) but not indexed. Reload (2 s directory poll, not inotify) keeps correlation state of unchanged rules, records a `rule_set_change` with `added/removed/modified/rejected`, and a bad file never blocks the others.
- Alerts are chained records naming the stored `trigger_seqs`; verified on a real kernel that an `exec` from `/dev/shm` produces an alert whose trigger resolves to that exact `proc_exec` record, that a rule added while running fires, and that a broken file is reported as rejected.
- The shipped pack (`rules/`, now 21 rules) was tuned against a real system: `shadow-read` first alerted on `newgrp`, then on debconf, cloud-init and man-db's `getpwnam`. Those are excluded by program and command line. Expect to tune it for your machine. The pack is now 21 rules including shell-on-socket, service-stopped, integrity-failed and usb-unknown. Not shipped: anything that needs data the daemon does not capture.
- `witness rules lint` and `witness rules test <file|dir> --dir <data>` replay stored events on the event clock and write nothing.

### 2.14 The API, as built

Deviation from §9.1: a **hand-written HTTP/1.1 server over the Unix socket** (std threads, `Connection: close`), not axum/hyper. It keeps the daemon's dependency tree and attack surface small for a local, low-rate API; the cost is that HTTP handling is ours, so it is deliberately minimal (16 KiB headers, 256 KiB bodies, 32 connections, 10 s read timeout). `witness-client` is the shared blocking client.

Implemented: `health, status, events (filters + keyset cursor), events/{seq}, events/{seq}/raw, stream (NDJSON with heartbeats and since_seq), timeline, dashboard, alerts (+ triage state), alerts/{seq}/triage, sessions, processes/{puid}, integrity (+ background verify), export (ndjson/json/csv), rules (list, validate, put, delete, enable/disable)`. Not implemented: a server-side process *tree* endpoint (the GUI builds the tree from `proc_exec`/`proc_exit`), signed exports, `lagged` markers on the stream.

Security: socket `0660 root:witness` in a `0750` directory; `SO_PEERCRED` picks the tier (root or `witness-admin` members may write rules; everyone else reads and triages); one `api_access` record per caller per minute and every triage is chained. `CAP_CHOWN` is in the unit's bounding set solely to hand the socket to the group. Verified: a group member reads, a rule write is refused with 403, a non-member cannot connect. **A bug found by accident:** the first version `chmod`ed and `chgrp`ed whatever directory held the socket, so a test config putting the socket in `/tmp` turned `/tmp` into `root:witness 0750` and broke the VM. The daemon now manages only a directory named `witness` (the default `/run/witness`), creates any other missing directory with default permissions and never changes it, and removes only a stale *socket* at the configured path, never another file. Covered by unit tests.

### 2.15 The GUI, as built

`witness-gui` (Dioxus 0.7.10 desktop, pinned) has pages for Dashboard, Live (stream, pause, filter), Search (text/kind/time, paging, export), Alerts (detail with trigger events and triage), Timeline (click a bar to see its events), Processes (tree), Sessions, Integrity (run and show verification), and Rules (list, enable/disable, validate, save). The pure logic (summaries, time formatting, process tree incl. pid reuse, sessions, bar scaling) is unit-tested in `witness-gui/src/model.rs`.

**Visual verification.** I ran it on macOS against the VM daemon (socket forwarded over SSH) with real captured data and looked at a screenshot of **every page** (`--page <name>` opens a page directly). That review found and fixed: crowded columns, `exit code=null` text, a 1970 anchor row, everything bold, raw JSON for flow/integrity records, overflowing process command lines, an empty user column (the daemon now resolves names), an Integrity page that ignored the scheduled checks, and a scheduler that labelled every check `startup`. Added: local-time toggle, a kind picker, arrow-key/j/k list navigation, a wrap toggle, a Live page that starts with recent events, and Rules controls disabled for read-only callers. **Not checked:** clicking through interactions (Search paging, triage buttons, enable/disable, export) and window resizing were not exercised by hand; their API calls are covered by the API test. Screen readers, contrast, text scaling and HiDPI were not reviewed. Linux was viewed under Xvfb for the Dashboard only; dark/light follows the OS.

### 2.16 Packaging, as built

`packaging/build-deb.sh` builds `witness_<ver>_<arch>.deb` (daemon, CLI, unit, rule pack as conffiles, default config) and `witness-gui_<ver>_<arch>.deb` with `dpkg-deb` only. The postinst creates the `witness` and `witness-admin` groups and `/var/lib/witness` (0700) and starts the service; **removal and purge never delete `/var/lib/witness`**. Verified on the VM: fresh install, in-place upgrade (a changed conffile replaced), service active under the hardened unit with every source working, and a full reboot (new kernel 5.15.0-203; `new_boot` gap recorded; chain verified with 1042 anchors). **Not done:** RPM packaging, x86_64 builds, a signed repository, a bundled GPL-2.0 text. `.github/workflows/ci.yml` is written but has never run.

## 3. Kernel side and daemon internals

### 3.1 Programs, maps, buffers

- **Two ring buffers**: `RB_CRITICAL` (exec/exit/fork/creds/auth/module/clock; default 8 MiB) and `RB_VOLUME` (file, network, DNS, UDP summaries; default 32 MiB). A flood in file or network events cannot evict process-execution events. Sizes are configurable.
- `bpf_ringbuf_reserve` failure ⇒ increment a per-CPU `drops[class]` counter and return. **Kernel never blocks.** Userspace reads the counters each second and records `capture_drop` events (per class, with interval).
- Per-event class priority is carried to userspace for the shedding policy (§5.6).
- Self-exclusion: a `SELF_TGIDS` array map holds witnessd's tgid(s); programs return early. Exclusion is by tgid, never by comm/name, so an attacker cannot hide by naming a process like us.
- Timestamps: `bpf_ktime_get_boot_ns()` (CLOCK_BOOTTIME, includes suspend). I use this, not CLOCK_MONOTONIC, so suspend does not corrupt ordering across a suspend/resume.
- Large strings (cmdline, paths) are emitted as chunk sequences with `(event_key, chunk_idx, last)`; userspace reassembles with a bounded, timed reassembly table. A missing chunk yields a record flagged `truncated=true` (never a silent partial).
- Kernel structs are `#[repr(C)]` types in `witness-common`, `no_std`, with explicit size/align asserts and a `ABI_VERSION` constant that the loader checks against the object.

### 3.2 Reading kernel structs (CO-RE strategy, see §1.3)

1. At load, userspace parses `/sys/kernel/btf/vmlinux` and resolves a short fixed list of `(struct, field) → offset` pairs: `task_struct{real_parent, tgid, pid, group_leader, loginuid, sessionid, cred, mm, signal, start_boot_time, exit_code}`, `mm_struct{arg_start, arg_end}`, `cred{uid,gid,euid,egid,suid,fsuid,cap_*}`, `signal_struct{tty}`, `tty_struct{name}`, `dentry{d_name, d_parent, d_inode}`, `inode{i_mode, i_ino, i_sb}`, `file{f_path, f_mode, f_flags}`, `sock`/`inet_sock`/`tcp_sock` network fields, `linux_binprm{file, filename}`.
2. Offsets are written to read-only globals via the aya loader (`EbpfLoader::set_global`) 📘 (verify API in M1).
3. The program reads with `bpf_probe_read_kernel(base + OFF_X)`.
4. If a required offset is missing (renamed/removed field, e.g. `loginuid` when `CONFIG_AUDIT=n`), the dependent field is flagged unavailable and the source is `Degraded`, not an abort. Optional fields (`tty`, `bytes_*`) degrade individually.

Cost: a few `probe_read` calls per event; acceptable. Benefit: no dependency on rustc/LLVM emitting correct CO-RE relocations; one build works across all four target distros.

### 3.3 Threading model (witnessd)

- **Ring-buffer readers**: one OS thread per ring buffer (epoll on the map fd via `aya::maps::RingBuf` 📘), decode raw → `RawEvent`, push into a bounded `crossbeam` channel. Never `tokio` for this path.
- **Enrichment stage** (single thread, ordered): process table update, user/group names, path normalization, session/tty linking, chunk reassembly, clock-offset tagging, `seq` assignment.
- **Storage writer** (dedicated thread): serialize, hash, append, group-commit `fsync` (default ≤ 500 ms or 4096 events), then publish to subscribers.
- **Index writer** (dedicated thread): batched SQLite transactions from the stored stream.
- **Rule engine** (own thread pool, separate bounded channel fed by a tee after storage; §8).
- **Tokio runtime** for: API server, D-Bus, journald, uevent netlink, timers, hash worker pool coordination.
- Every inter-stage channel is bounded; on full, the stage applies the policy for that priority class and **counts** the drop (`stage_drop{stage,class}` events).

### 3.4 Enrichment details

- **Wall clock** = `boot_ns + (realtime - boottime)` offset sampled every 100 ms by the enrichment thread. The offset samples are stored as `clock_sync` records; both `boot_ns` and derived `wall_ns` are on every event. The authoritative ordering field is `(boot_id, boot_ns)`; `wall_ns` is derived and can be re-derived or corrected from `clock_sync` records. After a detected clock step, events queued across the step carry `wall_ns_uncertain=true`.
- **User/group names**: parsed directly from `/etc/passwd` and `/etc/group` and cached (invalidated by inotify). **No NSS calls** (sssd/LDAP can block or fork inside a hardened daemon). Uids not resolvable stay numeric.
- **Paths**: store as bytes; UTF-8 where valid, otherwise a `{"b64":…}` form (Linux paths are not guaranteed UTF-8; forensic tools must not lose them).
- **Optional (off by default):** exe SHA-256 at first exec per (dev, inode, mtime), to detect replaced binaries.

---

## 4. Event schema

### 4.1 Common context

Every event carries (spec requirement → field):

| Spec | Field |
|---|---|
| monotonic + wall-clock (UTC ns) | `boot_ns: u64` (CLOCK_BOOTTIME), `wall_ns: u64` (ns since Unix epoch UTC) |
| boot ID | `boot_id: Uuid` |
| event type | `kind` (enum tag) |
| PID, PPID, TID | `actor.pid`, `actor.ppid`, `actor.tid` |
| UID/GID/EUID | `actor.uid`, `gid`, `euid`, `egid` |
| auid, session ID | `actor.auid: Option<u32>` (None = unset, `u32::MAX`), `actor.ses: Option<u32>` |
| exe, cmdline | `actor.exe`, `actor.cmdline: Vec<OsBytes>` |
| cgroup ID | `actor.cgroup_id: u64` |

Plus: `seq` (gapless, global), `puid` (process identity), `prio`, `src` (source), `v` (schema version).

### 4.2 Rust types (userspace; serde)

```rust
pub const SCHEMA_VERSION: u16 = 1;

/// Bytes that are usually UTF-8. Serializes as a JSON string when valid,
/// else as {"b64": "..."} so non-UTF-8 paths survive unchanged.
pub struct OsBytes(pub Vec<u8>);

pub struct Event {
    pub v: u16,
    pub seq: u64,                 // gapless, assigned at storage
    pub boot_id: Uuid,
    pub boot_ns: u64,
    pub wall_ns: u64,
    pub wall_uncertain: bool,     // omitted when false
    pub src: Source,              // Ebpf | Fanotify | Journald | Logind | Systemd | Uevent | Audit | Utmp | Daemon | RuleEngine | Baseline
    pub prio: Priority,           // P0 critical .. P3 low-value
    pub actor: Option<Actor>,     // None for daemon-internal events
    pub body: Body,               // #[serde(tag = "type", content = "data")]
}

pub struct Actor {
    pub puid: ProcessUid,         // (boot_id, pid, start_boot_ns), stable string/hash form
    pub pid: u32, pub tid: u32, pub ppid: u32,
    pub uid: u32, pub gid: u32, pub euid: u32, pub egid: u32,
    pub user: Option<String>,
    pub auid: Option<u32>, pub ses: Option<u32>,
    pub cgroup_id: u64,
    pub comm: String,
    pub exe: Option<OsBytes>,
    pub cmdline: Option<Vec<OsBytes>>,
    pub tty: Option<String>,
}

pub enum Body {
    // Processes
    ProcExec(ProcExec), ProcFork(ProcFork), ProcExit(ProcExit),
    CredChange(CredChange), ShellCommand(ShellCommand),
    // Files
    FileCreate(FileOp), FileOpenWrite(FileOp), FileOpenRead(FileOp), FileCloseWrite(FileOp),
    FileDelete(FileOp), FileRename(FileRename), FileAttr(FileAttr), FileLink(FileLink),
    FileTruncate(FileOp), FileHash(FileHash), FileActivitySummary(FileActivitySummary),
    // Network
    NetConnect(NetConn), NetAccept(NetConn), NetClose(NetClose),
    NetListen(NetListen), NetListenClose(NetListen),
    UdpFlow(UdpFlow), Dns(DnsEvent),
    // Auth & system
    Login(Login), Logout(Logout), AuthFail(AuthFail), Sudo(Sudo), Su(Sudo),
    UsbDevice(UsbDevice), BlockDevice(BlockDevice),
    ModuleLoad(Module), ModuleUnload(Module),
    ServiceChange(ServiceChange), SchedulerChange(SchedulerChange),
    PackageChange(PackageChange), AccountChange(AccountChange), AuthorizedKeyChange(KeyChange),
    ClockChange(ClockChange), SystemBoot(Boot), SystemShutdown(Shutdown),
    // Witness itself
    DaemonStart(DaemonStart), DaemonStop(DaemonStop), CaptureGap(CaptureGap),
    CaptureDrop(CaptureDrop), SourceHealth(SourceHealth), ConfigChange(ConfigChange),
    RuleSetChange(RuleSetChange), Alert(Alert), TriageAction(TriageAction),
    Baseline(BaselineItem), ClockSync(ClockSync), SegmentSeal(SegmentSeal),
    Anchor(Anchor), ApiAccess(ApiAccess),
}

pub struct ProcExec {
    pub filename: OsBytes,        // as passed to execve
    pub exe: OsBytes,             // resolved
    pub argv: Vec<OsBytes>, pub argv_truncated: bool,
    pub cwd: Option<OsBytes>,
    pub env: Option<Vec<OsBytes>>, // off by default
    pub stdio: [FdKind; 3],       // Tty|Pipe|Socket|File|Null|Unknown; stretch (M1), enables reverse-shell rule
    pub interactive: bool,
}
pub struct FileOp {
    pub path: OsBytes, pub path_resolved: bool, pub path_truncated: bool,
    pub dev: u64, pub ino: u64, pub mode: Option<u32>,
    pub flags: Option<u32>, pub result: HookResult, // Allowed | Denied(errno)
}
pub struct FileAttr { pub op: AttrOp, pub path: OsBytes, pub old_mode: Option<u32>, pub new_mode: Option<u32>,
                      pub old_uid: Option<u32>, pub new_uid: Option<u32>, pub old_gid: Option<u32>, pub new_gid: Option<u32>,
                      pub suid_set: bool, pub sgid_set: bool }
pub struct FileHash { pub path: OsBytes, pub dev: u64, pub ino: u64, pub size: u64, pub mtime_ns: i64,
                      pub sha256: Option<[u8; 32]>, pub prev_sha256: Option<[u8; 32]>, pub skipped: Option<HashSkip> }
pub struct NetConn { pub proto: Proto, pub family: Family, pub laddr: IpAddr, pub lport: u16,
                     pub raddr: IpAddr, pub rport: u16, pub outcome: ConnOutcome /* Established|Failed(errno)|Accepted */ }
pub struct NetClose { pub conn: NetConn, pub bytes_sent: Option<u64>, pub bytes_recv: Option<u64>, pub duration_ns: u64 }
pub struct UdpFlow { /* 5-tuple */ pub packets_tx: u64, pub bytes_tx: u64, pub packets_rx: u64, pub bytes_rx: u64, pub interval_ns: u64 }
pub struct DnsEvent { pub direction: DnsDir, pub server: SocketAddr, pub id: u16,
                      pub qname: String, pub qtype: String, pub rcode: Option<String>,
                      pub answers: Vec<DnsAnswer>, pub transport: Proto, pub truncated: bool }
pub struct CaptureGap { pub kind: GapKind /* RestartSameBoot|NewBoot|Overflow|SourceDown|DiskFull */,
                        pub from_boot_ns: Option<u64>, pub from_wall_ns: Option<u64>,
                        pub to_boot_ns: u64, pub to_wall_ns: u64,
                        pub prev_shutdown: ShutdownKind /* Clean|Signal|Unclean|Unknown */, pub source: Option<String> }
pub struct Alert { pub alert_id: Uuid, pub rule_id: String, pub rule_hash: [u8; 32],
                   pub title: String, pub severity: Severity, pub trigger_seqs: Vec<u64>,
                   pub puid: Option<ProcessUid>, pub session: Option<u32>, pub detail: serde_json::Value }
```

(The remaining payload structs follow the same pattern; they are fully specified in the M1/M2 schema crate, and enumerated by field in the table in §4.5.)

### 4.3 Kernel→userspace wire format

Fixed header `#[repr(C)]` (no padding, explicit `_pad` fields):

```rust
#[repr(C)] pub struct RawHdr {
    pub kind: u16, pub flags: u16,   // flags: TRUNCATED, CHUNKED, DENIED...
    pub len: u32,                    // total record bytes
    pub boot_ns: u64,
    pub pid: u32, pub tid: u32, pub ppid: u32, pub _pad0: u32,
    pub uid: u32, pub gid: u32, pub euid: u32, pub egid: u32,
    pub auid: u32, pub ses: u32,
    pub cgroup_id: u64,
    pub start_boot_ns: u64,          // actor start time → puid
}
```

Followed by a kind-specific `#[repr(C)]` body. All structs live in `witness-common` with compile-time size asserts and are decoded in userspace with checked parsing (no transmute from unaligned memory; `zerocopy`-style or manual `from_le_bytes`).

### 4.4 Process identity and tree reconstruction

- `puid = (boot_id, pid, start_boot_ns)`; pid reuse cannot alias.
- The index stores a `processes` table: `puid, parent_puid, start_seq, end_seq, start_boot_ns, end_boot_ns, exit_code, exe, first_cmdline`, plus an `exec_history` table (a process may exec repeatedly).
- **Tree at time T** = rows with `start_boot_ns ≤ T < end_boot_ns (or open)`, linked by `parent_puid` (lineage at fork time; reparenting to init is noted but doesn't rewrite lineage — the lineage is what forensics wants).
- Processes that predate the daemon come from the baseline snapshot with `synthetic=true` and an inferred start from `/proc/<pid>/stat` ❓ (clock-tick conversion needs care; stored with `start_approx=true`).

### 4.5 On-disk format: **NDJSON, zstd-compressed when sealed** (decision and justification)

| | NDJSON | Binary (CBOR/postcard/protobuf) |
|---|---|---|
| Forensic longevity / readable with `zcat \| jq` | **Yes** | Needs the schema and our tool |
| Evidence admissibility argument ("anyone can read it") | **Strong** | Weaker |
| Size | ~5–10× larger raw, **~8–12× smaller after zstd** (repeated keys compress extremely well) | Smaller raw |
| Write/parse speed | Fine at our rates (≤ ~50k ev/s; serde_json ~hundreds MB/s) | Faster |
| Hashing canonicalization problem | **None**: we hash the *exact stored bytes* | Same |
| Schema evolution | Additive keys, `v` field, unknown keys preserved | Harder |

Decision: NDJSON. The active segment is plain text (so it is robust against partial writes: a torn tail is one invalid line, never a corrupt block). Sealed segments are compressed as **independent zstd frames of ~1 MiB uncompressed** with a rebuildable `.fidx` sidecar (frame → offset table), so a single record can be fetched by `(segment, offset)` without decompressing the file.

**Record line format** (each line is valid JSON):

```
{"v":1,"seq":1042,"boot_id":"…","boot_ns":…,"wall_ns":…,"src":"ebpf","prio":0,"actor":{…},"type":"proc_exec","data":{…},"h":"<64 hex>"}
```

`h` is always the last key, fixed width. The hashed payload `B` is the line with the `,"h":"<64 hex>"` suffix removed (a fixed 72-byte tail strip, then re-append `}`): `h_n = SHA256(h_{n-1} || B_n)`. Verification does not re-serialize anything; no canonical-JSON ambiguity. 

**Segment layout** in `/var/lib/witness/segments/`:

```
seg-00000001-<first_seq>.ndjson          (active)
seg-00000001-<first_seq>.ndjson.zst      (sealed)  + .fidx
```
- First line: `segment_open` record `{seg, first_seq, prev_seg_file_sha256, prev_head_h, witness_version, schema_v, boot_id, seal_key_id?}`.
- Last line (when sealed): `segment_seal` `{last_seq, count, head_h, file_sha256_uncompressed}`.
- `prev_seg_file_sha256` = SHA-256 of the previous segment's full uncompressed bytes (spec requirement), **in addition to** the record-level chain continuing across segments (`h` of the first line chains from the last `h` of the previous segment).

Rotation: size (default 256 MiB) or time (default 24 h) or at daemon stop/boot (so each boot starts a new segment).

---

## 5. Storage, hash chain, indexing, disk-full

### 5.1 Write path

`Event → serialize → SHA-256 chain → append to active segment (O_APPEND, single writer) → group commit (fsync) → publish`.
- Segment files are created `0600 root`; directory `0700`.
- Active file also gets `chattr +a` (append-only) on supporting filesystems as defense in depth ❓ (best-effort; ext4/xfs/btrfs support it; root can remove it; documented as *not* a security boundary).
- Crash recovery on start: scan the last active segment; a torn final line is truncated *only if* it fails JSON parse and chain check, the truncation is recorded in a `recovery` event with the byte count and the removed bytes' SHA-256, and the original bytes are preserved in `quarantine/`.

### 5.2 Tamper evidence — what is detected

`witness verify` (streaming; resumable; reports exact `seq`/byte offset/segment of the first break):
- **Modification**: record hash mismatch ⇒ break at that `seq`.
- **Deletion in the middle** / missing segment: `seq` gap or `prev_seg_file_sha256`/chain mismatch at the neighbor.
- **Reordering**: chain break + `boot_ns` regression within a boot.
- **Truncation**: detected if a later anchor, seal record, or later segment says there should be more; **not detectable for a tail truncated after the last anchor with no later evidence** (see §5.4).
- Also verifies: segment header/seal consistency, `.zst` decompress integrity, sequence gaplessness, anchor records vs. computed heads.
- Output formats: human, JSON; exit code non-zero on any break. Results are recorded in the chain (`verify` run records) and in the index for the GUI Integrity view.

### 5.3 The unkeyed-chain problem

Restating §1.1: root can rewrite everything after seq N and recompute hashes. The chain alone proves *consistency*, not *authenticity*.

### 5.4 Proposal: forward-secure sealing + anchors (recommended for v1)

1. **Forward-secure MAC.** At `witness init --seal`, generate `K_0` (32 B). The *verification key* `K_0` is printed once for the admin to store off-host/off-machine (password manager, paper, another box). The daemon keeps only the current evolving key `K_i` in memory and a copy in `/var/lib/witness/seal.key` (0600). Every epoch (default 1 hour or segment boundary): write a `seal` record `MAC_{K_i}(head_h)`, then `K_{i+1} = H("witness-seal" || K_i)` and **erase `K_i`**. An attacker who gains root at time *T* gets `K_j (j ≥ i)` and **cannot forge MACs for epochs before *i***, so history sealed before the compromise remains verifiable by anyone holding `K_0`. (Same principle as journald Forward Secure Sealing.)
2. **Anchors.** Every checkpoint (default 60 s, and at every seal/rotation/stop) emit `anchor {seq, head_h}` to: the chain itself, the system journal (`journald` entry with `SYSLOG_IDENTIFIER=witness-anchor`), `/var/lib/witness/anchors.log`, and an optional `anchor_command` hook in config (admin may send it to email/Git/etc.). `witness anchor` prints the current head for manual record-keeping.
3. **Honest limits.** With sealing, a root attacker can still (a) delete/truncate the *tail after the last anchor/seal not held elsewhere*, (b) delete newest whole segments, (c) stop the daemon (visible as a gap), (d) forge/alter records *after* the compromise time (that's capture integrity, not storage integrity; and it's why the gap/baseline/clock records exist). Without a stored `K_0`, `verify` falls back to chain+anchor consistency only and prints that explicitly.

**Implemented in M2 (as built; supersedes the sketch above where they differ):**
- `witness init --seal` prints `K_0` once and persists only `K_1` at epoch 1, so `K_0` is never on the host. Epochs start at 1.
- A `seal` record carries `epoch`, `covers_seq` and `mac = HMAC-SHA256(K_epoch, "witness-seal-v1" || epoch || covers_seq || head_hash)`. The seal is fsynced **before** the key is evolved and the old key is erased, so an epoch is never skipped. If the process dies in between, `enable_sealing` finds the seal in the chain tail and advances the key; a key file *older* than the chain (restored backup) is refused.
- Epochs must be consecutive, so removing a seal is a `SealEpochGap` even **without** `K_0`; with `K_0`, any rewrite of sealed history is a `BadSealMac`. Records after the last seal are the *unsealed tail* and are reported as such.
- Anchors: an `anchor` record in the chain plus published `(seq, hash)` of that record to sinks (`anchors.log`, an admin command with the anchor in `WITNESS_ANCHOR_SEQ`/`WITNESS_ANCHOR_HASH`, no shell). Sink failures are returned, never block evidence. `verify` reports `AnchorMismatch`, and an anchor *beyond* the chain head as proof of tail truncation. The journald sink is added with the daemon (M6).
- Tests demonstrate both the limit and the fix: a consistent rewrite with recomputed hashes passes the bare chain but fails with `K_0`; a clean tail cut passes without anchors and fails with them.

Decision needed from you: include sealing in v1 (my recommendation) or document it as future work.

### 5.5 SQLite query index (rebuildable)

- File: `/var/lib/witness/index.db`, WAL, `synchronous=NORMAL`, `rusqlite` (bundled SQLite; ❓ confirm FTS5 is compiled in by the `bundled` feature — I believe so — in M2).
- Single writer thread, batched transactions (≤ 5000 events or 200 ms).
- Tables (abridged):
  - `events(seq PK, boot_ns, wall_ns, kind, prio, pid, tid, ppid, uid, euid, auid, ses, cgroup_id, puid, seg_id, seg_off, len, sev_hint)`
  - `event_net(seq PK, laddr, lport, raddr, rport, proto, bytes_tx, bytes_rx)` (rows only for net events), `event_file(seq PK, path_id, op, dev, ino)`, `paths(id, path)` (deduped)
  - `fts_events` (FTS5 over `cmdline`, `path`, `qname`, `comm`, `extra`) `content=''` external-content style to avoid storing text twice
  - `processes`, `exec_history`, `sessions`, `alerts` (seq, rule_id, severity, trigger_seqs), `alert_triage` (alert seq, status, updated_seq), `segments`, `integrity_runs`, `meta(last_indexed_seq, last_head_h, schema)`
  - Indexes: `(wall_ns)`, `(kind, seq)`, `(puid, seq)`, `(uid, seq)`, `(ses, seq)`, `(raddr, rport)` partial on net kinds, `(path_id, seq)`.
- Pagination is **keyset** (`WHERE seq < ? ORDER BY seq DESC LIMIT n`), never OFFSET.
- `witness reindex`: rebuild from segments, verifying chain continuity while reading; resumable from `last_indexed_seq`. If the index disagrees with the chain, the chain wins.
- Triage state is **not** only in SQLite: every triage change is a `triage_action` event in the chain, so `reindex` reproduces it.

### 5.6 Disk-full behavior (documented, configurable)

Config `[storage]`: `warn_pct = [80, 90]`, `min_free_bytes` (default 1 GiB), `on_full = "shed" | "stop"` (default `"shed"`).

- Always keep a **reserve** (default 256 MiB, preallocated via `fallocate`) used only for seal records, gap records and sealing the current segment.
- Free space below `min_free`:
  - `shed`: drop events by priority: **P3 (file-activity summaries, UDP flows, low-value file opens) → P2 (reads, hash records) → P1 (net/file mutations)**. **P0 never shed**: process exec/exit/creds, auth, alerts, integrity, daemon records. Each interval emits a `capture_drop {class, count, reason: disk}` record.
  - `stop`: stop writing all events, seal the segment using the reserve, write a `capture_gap{kind:DiskFull}` start, keep counting in memory, and write the gap's end and counts when space returns.
- **Never** truncate, rewrite, or compress-in-place unsealed existing data to make space. Sealing compresses *into a new file* and removes the plain file only after a verified, fsynced `.zst`.
- The index lives under the same `/var/lib/witness` by default; a separate `index_dir` option is supported. Index failure never blocks evidence writing.
- Disk usage is polled every 30 s (`statvfs`), exposed in the API/GUI, logged to the journal at thresholds.

**Implemented in M2 (as built; refines the list above):**
- Priorities `P0..P3`; `append` is P0, `append_prio` takes the class. Free space is polled by `tick()` (daemon: ~1 s) and every `probe_every_bytes` (default 8 MiB) of appended data, so a fast fill cannot outrun the check.
- `shed` mode grades by free space against `min_free_bytes`: below 100 % sheds P3, below 2/3 also P2, below 1/3 also P1. P0 is never shed. A level is left only after 10 % of `min_free` extra headroom (no flapping). Shed events are counted per class and written as `capture_drop {reason:"disk", from_ns, to_ns, dropped:[p0,p1,p2,p3]}` (at most every `drop_report_interval`, and immediately when space recovers).
- `stop` mode: below `min_free` the reserve is released, a `capture_gap` start record is written, the segment is sealed, and all appends are refused (counted). Capture resumes only when free space reaches `reserve + min_free + 10 %`; the reserve is recreated first, then a `capture_gap` end record carries the per-class counts and whether the start was recorded.
- **Write failures are rolled back.** If a write hits ENOSPC/quota partway, the file is truncated back to the last good length, so a partial line can never enter the chain. A failed segment open removes its empty file. In `shed` mode a failed P0 write retries once into the released reserve; if that fails too, capture stops and records a gap. Policy records that cannot be written are counted (`unrecorded_notes`) and still returned as events for the caller to log.
- Warnings fire once per threshold crossing (`disk_warning`) and again after recovery and re-crossing.
- Compression is deferred while free space is too low to hold the new file; the plain segment is never removed first.
- Known limits: the reserve is a real reservation only where `fallocate` allocates (Linux ext4/xfs); on copy-on-write or compressing filesystems it may not guarantee space. The SQLite index is not yet governed by this policy (it can fail independently and is rebuildable). Real ENOSPC was exercised on a 1 MiB tmpfs on Ubuntu 22.04 / kernel 5.15.0-198 (aarch64): P3 was shed first, P0 kept being written, the reserve was released and exhausted, shed mode escalated to a recorded stop, the chain verified with no torn lines, and capture resumed after space returned (`witness-store/tests/real_enospc.rs`, run with `--ignored --test-threads=1`). ext4/xfs/btrfs and x86_64 are not yet covered.

### 5.7 Size estimates (to be measured, not promised)

For a busy desktop at ~100 events/s avg (file events dominate): ~8.6 M events/day × ~500 B JSON ≈ **4.3 GB/day raw → ~0.4 GB/day sealed**; index (rows + FTS) ≈ **2–3 GB/day**. A quiet server is 10–100× less. These drive defaults for P3 summarization. M2/M10 include real measurements.

### 5.8 Archive / prune

Both operate only on the **oldest contiguous run of sealed segments** and never on the newest segment, so the chain always keeps a well-defined start and its head. Both need the single-writer lock (`store.lock`, `flock`), so they refuse to run while `witnessd` holds the store; daemon-mediated versions arrive with the API (M6).

- `witness archive --to <dir> [--before <date>] [--move]`: copies each segment (and its `.fidx`) to `<dir>/segments/`, proves the copy (raw bytes and decompressed content hash identically to the source; an existing, differing destination file aborts), then appends an `archive` record (per-segment id, seq range, file name, SHA-256 of the file and of the uncompressed bytes, actor uid) and fsyncs it. Only with `--move` are the originals removed, and only after the record is durable. Re-running is idempotent.
- `witness prune --before <date> [--yes-delete-evidence --expect N]`: a **dry run by default**. Deleting needs both the flag and `--expect N`, the segment count from the dry run; a mismatch aborts with nothing deleted. A `prune` record (same per-segment hashes, actor) is made durable **before** the first file is removed.
- **How `verify` tells deliberate removal from tampering:** if the oldest segments are absent, the chain is `HistoryMissing` unless a chained `prune` or moving `archive` record accounts for exactly that prefix (`partial_explained`). `witness verify --include <archive-dir>` verifies live data plus archives as one chain from seq 1; `--allow-partial` accepts an arbitrary slice on purpose. The same `--include` works for `witness reindex`.
- Limits: deleting the *newest* segments is still only provable with anchors (§5.4); a prune record proves intent and content hashes, not that the deleter was authorized.
- Sealed compressed segments carry a derived `.fidx` frame table (rebuilt on demand if missing) so one record can be read without decoding the file.

---

## 6. Boot persistence

### 6.1 `witnessd.service` (draft; final in M6)

```ini
[Unit]
Description=Witness forensic activity monitor
Documentation=https://github.com/<org>/witness
DefaultDependencies=no
After=local-fs.target systemd-journald.socket dbus.socket
Requires=local-fs.target
Before=network-pre.target sshd.service ssh.service systemd-user-sessions.service
Conflicts=shutdown.target
Before=shutdown.target
StartLimitIntervalSec=60
StartLimitBurst=20

[Service]
Type=notify
NotifyAccess=main
ExecStart=/usr/sbin/witnessd --config /etc/witness/config.toml
Restart=always
RestartSec=1
WatchdogSec=30
TimeoutStartSec=60
TimeoutStopSec=30
OOMScoreAdjust=-900
LimitMEMLOCK=infinity
MemoryHigh=384M
MemoryMax=768M
CPUWeight=200
IOWeight=200
# --- hardening (each justified in §6.3; validated empirically in M6/M10) ---
User=root
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_DAC_READ_SEARCH CAP_SYS_PTRACE CAP_AUDIT_READ CAP_NET_ADMIN CAP_CHOWN CAP_FOWNER
AmbientCapabilities=
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/witness /run/witness
ProtectHome=read-only
PrivateTmp=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service bpf perf_event_open fanotify_init fanotify_mark
RuntimeDirectory=witness
RuntimeDirectoryMode=0750
StateDirectory=witness
StateDirectoryMode=0700

[Install]
WantedBy=multi-user.target
```

Caps/options are a **starting list** ❓. M6 reduces them empirically (run under each restricted set, observe failures). `ProtectProc`/`hidepid` are *not* set — we must see all processes.

### 6.2 Ordering: what is and is not guaranteed

- `Before=network-pre.target sshd.service systemd-user-sessions.service` + `Type=notify` (READY only after eBPF attach) ⇒ **no login or network service is started until capture is attached**, *provided those units are ordered normally*.
- `DefaultDependencies=no` is needed to start this early. Stop order is the reverse of start order, so Witness stops after the services it started before, i.e. it outlives them at shutdown.
- **Not guaranteed**: anything in the kernel, initramfs, and `sysinit.target` units that run before our `After=` set; services that declare no ordering relative to us and are not `After=` anything of ours (e.g. units started in parallel in `sysinit.target`); processes spawned by the initrd and left running. These are covered by the **baseline snapshot** (what *exists* at start, with inferred start times) and a `boot_to_start` gap record (kernel boot time → first event) so the blind window is explicit.
- Masking/disabling the unit or boot with `systemd.mask=witnessd.service` on the kernel command line defeats start-at-boot; that is detectable only *after the fact* (new boot with no `daemon_start` for that boot ID → recorded at the next start as `boot_without_capture` using journald/`wtmp` boot evidence). ❓ confirm how reliably this can be inferred from `wtmp`/journal on all four distros.

### 6.3 Hardening rationale (each option)

| Setting | Why / constraint |
|---|---|
| `CAP_BPF`, `CAP_PERFMON` | Load/attach tracing programs and use `bpf_probe_read_kernel` (5.8+). |
| `CAP_SYS_ADMIN` | **Unavoidable ❓ check**: fanotify marks on filesystems and some uevent/netlink operations; also needed if the build must support kernels where BPF capabilities were split differently. Will try to drop in M6; if not droppable, documented. |
| `CAP_DAC_READ_SEARCH`, `CAP_SYS_PTRACE` | Hash arbitrary files; read `/proc/<pid>/{exe,cwd,fd}` of other users' processes (baseline, enrichment). Read-only; no write capabilities beyond our dirs. |
| `CAP_AUDIT_READ` | Only for the optional audit-multicast source. |
| `CAP_NET_ADMIN` | ❓ only if uevent group bind needs it; drop if not. |
| `NoNewPrivileges` | We never exec setuid binaries. Compatible. |
| `ProtectSystem=strict` + `ReadWritePaths` | Daemon can write only its state/run dirs. |
| `ProtectHome=read-only` | Need to *hash* `~/.ssh` etc.; no write. |
| `ProtectKernelTunables/Modules`, `ProtectClock` | We never write sysctls, load modules, or set the clock. |
| `MemoryDenyWriteExecute` | No JIT in userspace. (The BPF JIT is kernel-side.) ❓ regex/crate compatibility. |
| `RestrictAddressFamilies=AF_UNIX AF_NETLINK` | Sockets we need: API socket, D-Bus, netlink (uevent/audit/sock_diag). |
| `SystemCallFilter` | Allowlist; must include `bpf`, `perf_event_open`, `fanotify_*`; verified with `strace` in M6. |
| `MemoryHigh/Max` | Targets <200 MB RSS; hard cap protects the host; **an OOM kill is itself a recorded gap**. |
| `OOMScoreAdjust=-900` | Prefer killing other things first. |

### 6.4 Gap tracking, restart, and state

- `/var/lib/witness/state.json` (atomic replace) holds `{boot_id, last_seq, last_head_h, last_boot_ns, clean_shutdown}`; **evidence does not depend on it** — the authoritative values are read back from the segments at start (state is a hint only).
- **Clean stop** (`SIGTERM`): final `daemon_stop {reason, signal sender if known}`, seal record, mark clean.
- **Start** compares: same boot ID with `clean=false` ⇒ `capture_gap{RestartSameBoot, prev_shutdown: Unclean|Signal}` from `last_boot_ns` to the first new event; different boot ⇒ `capture_gap{NewBoot}` (offline interval) + `boot_to_start`.
- Processes discovered at baseline whose `/proc` start time falls *inside a gap* are emitted as `baseline` items with `discovered_in_gap=true` — activity during a gap is not recoverable, but its *existence* often is.
- **Who stopped/disabled/masked us**: (1) systemd D-Bus `JobNew` for our unit, (2) exec of `systemctl`/`kill` in ancestry before `SIGTERM`, (3) `tracepoint/signal/signal_generate` filtered to our tgid records *sender pid, uid, signal* (SIGKILL: we likely die before writing it, but the ring buffer record remains for the next incarnation only if links are pinned, §10.4); (4) file events on `/etc/systemd/system/witnessd.service` (mask = symlink to `/dev/null`) and the `*.wants` symlink removal (disable). 

### 6.5 Startup sequence

1. Parse/validate config (invalid ⇒ exit non-zero; previous behavior documented). 2. Read BTF, resolve offsets, load BPF programs. 3. Attach (per-source; failures degrade, not abort; fatal only if *zero* process-exec capture is possible). 4. Write `daemon_start` + gap record. 5. `sd_notify READY=1`. 6. Take baseline snapshot **asynchronously** (so READY never waits for it, and nothing starts without capture). 7. Start API.
Watchdog pings come from the *pipeline loop*, only if reader/enrichment/storage heartbeats are fresh — a stalled pipeline gets restarted by systemd.

### 6.6 Baseline snapshot

Process list + tree (`/proc`), listening sockets (netlink `sock_diag`, mapped to pids via `/proc/*/fd`), logged-in sessions (logind `ListSessions`, utmp), loaded modules (`/proc/modules`), mounts and block/USB devices (`/proc/self/mountinfo`, `/sys/block`, `/sys/bus/usb`). Taken *after* attach, so there is no blind spot between snapshot and live capture; duplicates between the two are harmless and deduped by `puid`. All items are `baseline` events with `synthetic=true`.

### 6.7 GUI autostart

Per-user `~/.config/autostart/witness-gui.desktop` (XDG), created/removed by a settings toggle; default off. (Recommendation on notifications in §1.8/§12.)

---

## 7. Config: `/etc/witness/config.toml`

Single file, strict parse (`deny_unknown_fields`), every key defaulted, validated at start and on reload; `witness config check` validates offline. Sections: `[capture]` (per-source enable, env capture, argv cap, ring sizes), `[files]` (`watch = []`, `exclude = []`, `critical` built-in + additions, hashing limits and rate), `[network]` (dns on/off, udp summary interval), `[storage]` (rotation size/time, zstd level, thresholds, `on_full`, reserve, `index_dir`, `anchor_command`), `[seal]`, `[rules]` (`dir`, `notify_min_severity`), `[api]` (`socket`, `group`, `admin_group`), `[daemon]` (log level, watchdog). Config changes are recorded as `config_change` with the SHA-256 of old/new files and a field-level diff (no secrets exist in it).

Reload is by `SIGHUP` / `witness config reload`; options that need program reattach are flagged "restart required".

---

## 8. Rule engine

### 8.1 Language (Sigma-inspired — **not** Sigma-compatible)

I will not claim Sigma compatibility: field names are Witness's own, there is no `logsource` mapping, no Sigma modifiers or condition grammar, and correlation uses a different syntax. YAML schema:

```yaml
id: <string, unique, [a-z0-9._-]+>
title: <string>
description: <string>
severity: info | low | medium | high | critical
enabled: true
tags: [ ... ]                 # free-form; e.g. attack.t1059
event: <kind> | [ <kind>, ... ]     # which event types are evaluated
match:                        # boolean tree
  all: [ <cond>... ]          # AND
  any: [ <cond>... ]          # OR
  not: <cond>
cond: { field: <name>, op: <op>, value: <v> | [v...], ci: true|false }
correlate:                    # optional
  type: count | sequence
  group_by: [ actor.puid | actor.ses | net.raddr | ... ]
  window: 60s
  # type: count
  threshold: 5
  # type: sequence
  steps:
    - { id: s1, event: file_create, match: {...} }
    - { id: s2, event: file_attr,   match: {...} }
  scope: same_process | same_tree | same_session   # how steps are tied together
alert:
  fields: [ ... ]             # extra fields copied into the alert detail
```

Ops: `eq`, `ne`, `contains`, `startswith`, `endswith`, `regex` (RE2-style, `regex` crate: guaranteed linear time), `in` (list), `cidr` (`ipnet`), `glob` (`globset`, path-aware: `**`), `gt/gte/lt/lte`, `exists`. Case-insensitive via `ci: true`. Fields are the dotted paths of the schema (`actor.exe`, `data.argv`, `data.path`, `net.raddr`…), type-checked at load time: unknown field or incompatible op/type = **rule rejected with file:line:col** error.

### 8.2 Three example rules

**1. Execution from a world-writable location**
```yaml
id: witness.exec.from-tmp
title: Execution from /tmp, /dev/shm or /var/tmp
description: A process was started from a world-writable, non-persistent directory.
severity: medium
tags: [attack.execution, attack.t1059]
event: proc_exec
match:
  all:
    - { field: data.exe, op: glob, value: ["/tmp/**", "/dev/shm/**", "/var/tmp/**"] }
    - not: { field: data.exe, op: glob, value: ["/tmp/.X11-unix/**", "/tmp/.mount_*/**"] }   # e.g. AppImage mounts
```

**2. Burst of failed logins from one address (count correlation)**
```yaml
id: witness.auth.bruteforce
title: Repeated failed logins from one source
severity: high
tags: [attack.credential-access, attack.t1110]
event: auth_fail
correlate:
  type: count
  group_by: [data.remote_addr]
  window: 60s
  threshold: 10
match:
  all:
    - { field: data.service, op: in, value: [sshd, login, gdm] }
```

**3. Dropped binary made executable then run (sequence correlation)**
```yaml
id: witness.seq.drop-chmod-exec
title: File written, made executable, then executed
severity: high
tags: [attack.execution]
correlate:
  type: sequence
  scope: same_tree
  window: 5m
  steps:
    - id: write
      event: file_create
      match: { all: [ { field: data.path, op: glob, value: ["/tmp/**", "/dev/shm/**", "/home/*/**"] } ] }
    - id: chmod
      event: file_attr
      match: { all: [ { field: data.new_mode, op: exists }, { field: data.path, op: eq, value: "$write.data.path" } ] }
    - id: exec
      event: proc_exec
      match: { all: [ { field: data.exe, op: eq, value: "$write.data.path" } ] }
```
(`$step.field` back-references are limited to equality joins; the engine documents and tests them.)

### 8.3 Evaluation design

- **Compile** YAML → typed AST. Field accessors are resolved to function pointers at compile time (no string lookups at eval time). `regex` is compiled once; same-field regex alternations are merged into a `RegexSet`; globs into `GlobSet`; CIDR lists into a sorted/prefix structure.
- **Dispatch**: `HashMap<Kind, Vec<RuleRef>>` — an event only touches rules for its kind. Cheapest-first condition ordering (eq/in before regex).
- **Correlation state**: per-rule `HashMap<GroupKey, Window>` with time-ordered `VecDeque`; eviction by the *event clock* (not wall time) so replay is deterministic; a global cap (memory + entries per rule) with LRU eviction and a `rule_state_evicted` counter in the stats.
- **Execution**: dedicated worker threads fed from a bounded channel *after* storage. If the engine lags, it **drops the oldest unevaluated events and records `rule_engine_lag{dropped}`** as a chain event — missing detections are visible, storage is never slowed.
- **Alerts** are `Alert` events written through the normal path (hash-chained) with `trigger_seqs`; same-rule/same-group alerts are rate-limited with a configurable suppress window, and the suppressed count is included in the next alert.
- **Hot reload**: `inotify` on `/etc/witness/rules.d/` (debounced) → parse+compile whole set into a staging `RuleSet` → on success `ArcSwap` it in, record `rule_set_change{added, removed, modified, set_hash, file_hashes}`; on any error the previous set stays active and a `rule_set_change{rejected, errors}` event records file:line errors. A single bad file never disables the others? **Decision**: per-file isolation — a bad file is rejected and the rest are applied (the rejection is recorded and alerted at `medium`).
- **`witness rules test <rule> --against <range>`**: runs the same engine library offline over segments/index with the *event clock*, emits matches, never writes alerts. Also `witness rules lint`.
- **Benchmark plan** (M7): synthetic and replayed event streams at 50k/200k ev/s, 100 rules; report CPU and p99 latency per event; acceptance: engine ≤ 1 core at 50k ev/s with the built-in pack.
- **Built-in rule pack** (`rules/`): reverse shell (cmdline patterns `/dev/tcp/`, `nc -e`, `mkfifo … nc`, **and** a shell exec whose `stdio` includes `Socket`), `/etc/shadow` read by a non-allowlisted exe, new SUID/SGID file, unknown USB device (not in a learned/allowed device list), kernel module load, sudoers change, new authorized key, cron/systemd persistence, exec from `/tmp`/`/dev/shm`, clock step, Witness service stopped/disabled/masked, segment/log tampering (`verify` failure, unexpected writes to `/var/lib/witness` by any process other than witnessd/CLI — only visible if a file event for that path is allowed through the self-exclusion, which is by tgid, so other processes touching it *are* seen).

---

## 9. Daemon ↔ GUI/CLI API

### 9.1 Transport and security

- **HTTP/1.1 over a Unix domain socket** (`axum`/`hyper`), JSON bodies, versioned under `/v1`. Live streams use **chunked NDJSON** (or SSE). Reason: debuggable with `curl --unix-socket`, no codegen, trivial for the CLI to reuse, and no protobuf toolchain. (gRPC/tonic over UDS is a defensible alternative; I judge it unnecessary at single-host scale.)
- Socket `/run/witness/witness.sock`, mode `0660`, `root:witness`, in a `0750 root:witness` directory.
- `SO_PEERCRED` on every connection → `(pid, uid, gid)`. **Tier 1** (group `witness`): all reads + triage. **Tier 2** (uid 0 or group `witness-admin`): rule create/edit/enable and config reads. Mutations and **API connections with queries/exports** produce chain events (`api_access` for connects, `triage_action`, `rule_set_change` with the actor). Who looked at what is itself evidence.
- Privacy note for README: members of `witness` can read every user's command lines (including secrets typed as arguments). It is root-equivalent for confidentiality of activity data.
- Auth-free by design (the OS enforces access); the socket never leaves the host. No TCP listener exists.

### 9.2 Endpoints (v1)

| Method & path | Purpose |
|---|---|
| `GET /v1/status` | version, boot_id, uptime, head seq/hash, source health, drops, disk, gaps summary, capabilities (tier) |
| `GET /v1/events` | filtered, **keyset-paginated** list. Params: `from`,`to` (wall or boot_ns), `kind[]`, `uid`, `pid`, `puid`, `ses`, `path` (glob), `ip` (CIDR), `port`, `severity`, `q` (FTS5), `cursor`, `limit` (≤ 1000), `order` |
| `GET /v1/events/{seq}` | decoded event + related (parent chain, alerts) |
| `GET /v1/events/{seq}/raw` | exact stored line + position + chain hash |
| `GET /v1/stream` | live NDJSON stream with the same filter parameters; `since_seq` for lossless resume; server sends heartbeat and `lagged{missed}` markers if a slow client is skipped (never blocks the daemon) |
| `GET /v1/timeline` | bucketed counts by kind/severity over a range; `bucket=auto` chooses resolution for the zoom |
| `GET /v1/processes/tree?at=<ts>&root=<puid>` | tree snapshot at time T, lazy children |
| `GET /v1/processes/{puid}` | detail, exec history, children, file/net summaries and event pages |
| `GET /v1/sessions`, `/v1/sessions/{ses}` | sessions (login → actions → logout) |
| `GET /v1/alerts`, `GET /v1/alerts/{seq}` | list/detail with triage |
| `POST /v1/alerts/{seq}/triage` | `{status: new|acknowledged|false_positive, note}` (tier 1) |
| `GET /v1/rules`, `POST /v1/rules/validate`, `PUT /v1/rules/{id}`, `POST /v1/rules/{id}/enable|disable`, `DELETE /v1/rules/{id}` | rule management (writes: tier 2) |
| `GET /v1/dashboard` | rates, tops, source health, drops, disk, gaps |
| `GET /v1/integrity`, `POST /v1/integrity/verify`, `GET /v1/integrity/runs` | status/history/start a background verify |
| `POST /v1/export` | `{filter, format: json|csv|bundle}` → job id; `GET /v1/export/{id}` streams the file |
| `GET /v1/health` | liveness for the GUI's reconnect loop |

Errors: RFC 7807-style JSON `{type,title,detail}`; stable error codes. The GUI reconnects with exponential backoff and resumes the live stream with `since_seq`. If the daemon was down, the GUI shows the `capture_gap` between `since_seq` and the next event.

### 9.3 Incident bundle

`witness export --bundle` / GUI export: a tar containing `events.ndjson` (verbatim stored lines for the selection), `alerts.json`, the relevant `segment_open`/`segment_seal`/`anchor` records, `chain-proof.json` (hashes needed to verify the slice: the lines' `h` values plus boundary hashes), `verify-report.json`, `manifest.json` (SHA-256 of each file, tool version, time of export), and optionally a detached signature if the admin configures a signing key.

---

## 10. Reliability, performance, graceful degradation

### 10.1 Targets and how they're met
- **< 3 % CPU, < 200 MB RSS** under "normal desktop/server load". Main costs: path resolution on file-open-for-write, DNS payload copying, SHA-256 hashing, SQLite indexing, enrichment. Mitigations: priority classes, in-kernel exclusions, hash rate limiting, batched index writes, bounded process table (LRU of exited processes, since the index keeps history), `MemoryHigh`.
- **Measured, not claimed**: M10 includes a load harness (exec storm, file churn, connect storm, DNS spam) with CPU/RSS/drop numbers on each target kernel. I will report numbers even if they miss the target.

### 10.2 Drops are never silent
Per class: kernel drop counters → `capture_drop` events; stage channel drops → `stage_drop`; rule-engine lag; API subscriber lag. All are counted in the dashboard and written to the chain.

### 10.3 Graceful degradation
Each source degrades independently (e.g. no `bpf_d_path` target ⇒ manual path walk; no BTF for a function ⇒ kprobe or syscall-tracepoint fallback with `path_resolved=false`; no `loginuid` ⇒ auid unset; no logind ⇒ utmp + journald). BPF-LSM presence is probed and reported but unused. Startup prints the matrix (`witnessd doctor`).

### 10.4 Optional: capture continuity across restarts
Pin BPF links in bpffs so programs keep running between a crash and the restart (ring buffers retain what fits). A restarted daemon drains the leftover records first, shrinking the gap. Risks: stale programs after an *intentional* stop (must unpin on clean stop; leave pinned on crash/`Restart=`), version skew between the pinned programs and a new binary (ABI check). **Proposal: not in v1; design leaves hooks for it.** Mention here because it directly addresses weakness 1.11.

---

## 11. Storage of evidence about the daemon itself

Recorded as chain events: `daemon_start/stop` (with PID, version, config hash, rule-set hash, BPF object hash, kernel version, BTF availability), unclean-shutdown detection, `capture_gap`, `capture_drop`, `source_health`, `config_change`, `rule_set_change`, `triage_action`, `anchor`, `segment_seal`, `verify` runs, `archive`/`prune`, `recovery`, `api_access`.

---

## 12. GUI (Dioxus Desktop) — feasibility

### 12.1 Version and Linux requirements
- **Dioxus 0.7.x** is the current stable line ✅ (0.8 is alpha-only). Pin one exact 0.7.x (decide at M8 after checking crates.io).
- Desktop = `dioxus-desktop` → `wry` + `tao` → **system WebKitGTK** ✅(system webview confirmed; the *package names* below are 📘). Build deps (Debian/Ubuntu): `libwebkit2gtk-4.1-dev libgtk-3-dev libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev`; runtime: `libwebkit2gtk-4.1-0`, GTK3. Fedora: `webkit2gtk4.1-devel gtk3-devel libxdo-devel openssl-devel`. ❓ Verify that WebKitGTK **4.1** (not 4.0) is what `wry` links on Ubuntu 22.04/Debian 12/Fedora, and that it is packaged there (I believe so for all three).
- Requires a graphical session (Wayland/X11). Works as an ordinary user. Known class of issue: WebKitGTK compositing/DMABUF rendering bugs on some GPU/driver combos give a blank/black window; mitigations are environment toggles (`WEBKIT_DISABLE_DMABUF_RENDERER`, `WEBKIT_DISABLE_COMPOSITING_MODE`) exposed in a documented "Troubleshooting" and a settings option. ❓ exact variable behavior to be tested in M8.
- The "no JS framework" rule is met: app code is Rust/RSX. Dioxus's own tiny JS shim is internal. I avoid `eval`/custom JS for app logic.

### 12.2 Millions of rows
- DOM holds ~50–80 rows. **Custom virtual list component** (Dioxus 0.7 doesn't ship a production one ❓ re-check before building): fixed row height, a spacer element for scroll height, rows positioned by `translateY`. WebKit's maximum element height (~33 M px) caps naive scroll heights at ~1.4 M rows of 24 px, so the list uses **scaled scrollbar mapping** (scroll fraction ↔ position in the total result set) beyond a threshold, with keyset cursors + an in-memory page cache (LRU of pages) and prefetch.
- **Server-side pagination only**; the GUI never holds the full set. Counts come from `COUNT` with caps (`≥ 1,000,000`) or approximate from the timeline buckets.
- Live view: ring-buffered (default 10 k rows) client side, batched at ≤ 10 render updates/s regardless of event rate; pause freezes the view and buffers by `seq` (resume shows `n new`).
- Timeline: SVG from **server-bucketed** counts (≤ ~2000 elements), zoom triggers re-query at finer buckets; alert markers from the alerts table. Process tree: lazy-loaded children (expand on demand), virtualized when > ~2k nodes visible.
- GUI process owns the socket client in Rust (no serialization hop to a JS frontend for data), so large result handling is just async Rust + RSX diffing.

### 12.3 Responsiveness risks
RSX diffing cost with large lists, WebKitGTK memory use (~150–300 MB typical), and scroll jank are real. M8 begins with a **spike**: 5 M-row synthetic dataset, scroll/filter benchmarks; if the spike fails the success criteria (60 fps scroll on a mid laptop, < 150 ms filter response), I will report it and propose changes (smaller DOM window, canvas-based table via pure-Rust `dioxus-native`/Blitz ❓ experimental, or egui) *before* continuing — I will not silently swap.

### 12.4 Screens → data
Live view (`/stream`), Timeline (`/timeline`), Process tree (`/processes/*`), Sessions, Search (`/events` + FTS), Event detail (`/events/{seq}`, `/raw`), Alerts + rules, Dashboard, Integrity, Export — matching §9.

### 12.5 Notifications
`notify-rust` (session D-Bus) is easy, but only when a process runs in the user's session. Options: (a) GUI in tray via autostart (tray requires an extension on GNOME), (b) a tiny `witness-notify` user systemd service subscribing to `/v1/stream?kind=alert&severity>=X`. **Recommend (b)** plus the GUI doing it too when open. Needs your approval since it adds a binary.

---

## 13. Engineering standards, testing, CI

- Workspace as specified (`witness-ebpf`, `witness-common`, `witnessd`, `witness-cli`, `witness-gui`, `rules`, `xtask`). Rust edition/MSRV pinned in `rust-toolchain.toml` (stable for userspace, separate pinned nightly in `witness-ebpf/rust-toolchain.toml` ✅ per §1.2).
- `clippy -D warnings`, `rustfmt`, `#![forbid(unsafe_code)]` in all crates except the minimal modules that need it (BPF loader glue, mmap'd ring reads, `libc` calls), each `unsafe` block carrying `// SAFETY:` invariants. No `unwrap`/`expect` outside tests (enforced by `clippy::unwrap_used`, `clippy::expect_used` deny).
- `thiserror` for library errors, `anyhow` at binaries, `tracing` + `tracing-journald` for logs.
- Unit tests: parsers (DNS, utmp, uevent, journald, package logs), segment writer/reader, hash chain (property tests: any single-byte flip, line deletion, swap, truncation ⇒ detected at the right place), rule engine (golden tests, correlation edge cases, replay determinism), query layer.
- Integration tests (Linux VM, root): spawn real activity (exec, file write/chmod/rename, TCP connect, DNS lookup, sudo, `insmod` of a dummy module, USB via `dummy_hcd`/`udevadm trigger` ❓) and assert events/alerts. Boot test: restart service and **reboot a VM**, assert `daemon_start`, `capture_gap`, baseline.
- Kernel matrix (VM-based, e.g. `virtme-ng`/QEMU or Lima): Ubuntu 22.04 (5.15 GA — the minimum), Debian 12 (6.1), Ubuntu 24.04 (6.8), current Fedora. GitHub-hosted runners cannot load BPF with arbitrary kernels, so CI uses nested QEMU/KVM where available ❓ (hosted runners' KVM availability varies; may need a self-hosted runner for the matrix; the cheap jobs — fmt, clippy, unit tests, eBPF *build* — run on hosted).
- Versions: every crate pinned (`=x.y.z` for core deps) after checking crates.io and docs.rs at the time it is added. The initial list below is **candidates**, not verified pins:

| Purpose | Candidate | Status |
|---|---|---|
| eBPF loader | `aya` 0.14.0 | ✅ docs.rs shows 0.14.0 |
| eBPF programs | `aya-ebpf`, `aya-log-ebpf` (version matching `aya`) | ❓ |
| eBPF build | `aya-build` (exists) or `xtask` + `cargo +nightly` | ✅ exists / ❓ API |
| Async | `tokio`, `tokio-util` | ❓ |
| HTTP/UDS | `axum`, `hyper`, `hyper-util` | ❓ |
| D-Bus | `zbus` | ❓ |
| Journald | `systemd` bindings vs. `journalctl -o json -f` subprocess; pure-Rust reader preferred | ❓ decide in M5 |
| SQLite | `rusqlite` (bundled) | ❓ FTS5 included? |
| Hashing / zstd | `sha2`, `zstd` | ❓ |
| Rules | `serde_yaml`-successor (check maintenance status; `serde_yaml` is archived/unmaintained 📘 — evaluate `serde_yml`/`yaml-rust2`-based alternatives), `regex`, `globset`, `ipnet`, `arc-swap` | ❓ |
| DNS parsing | `hickory-proto` (or `simple-dns`) | ❓ |
| GUI | `dioxus` 0.7.x, `dioxus-desktop` | ✅ |
| Notifications | `notify-rust` | ❓ |
| sd_notify | `sd-notify` | ❓ |

---

## 14. What is verified

I develop on macOS and cannot load eBPF there, so every claim below says where it was run. "Real kernel" means Ubuntu 22.04.5 under Lima, **aarch64**, kernel 5.15.0-198 (and 5.15.0-203 after the final reboot), BTF on.

| Area | State |
|---|---|
| Storage, hash chain, seals, anchors, disk-full policy, verify, index | unit + real-kernel tests (including real ENOSPC on a 1 MiB tmpfs) |
| Process, file, network, DNS eBPF capture | real kernel, 24 programs verified by the kernel verifier, privileged suite passes |
| Auth/system sources | real kernel, except USB hardware (see §2.12) |
| Rule engine and pack | unit, benchmark, real-kernel alert + hot reload |
| API | real-kernel end-to-end test; tiers checked with real group membership |
| GUI | compiled on macOS and Linux; Dashboard viewed on both; other pages not visually checked |
| .deb install, upgrade, reboot persistence | real VM |
| x86_64 | cross-built from the arm64 VM and run under QEMU emulation (Ubuntu 22.04, kernel 5.15.0-198): the 24 programs of that build passed the verifier; 26 of 29 privileged tests passed first time and the other three passed after fixing test-setup problems and one over-strict assertion; the amd64 `.deb` installs and runs under the hardened unit. **Emulated, not native hardware, and the UDP-flow/TCP-DNS/service/integrity work was not re-run on x86_64.** |
| Kernels other than 5.15 (incl. 6.x `ITER_UBUF` DNS path, fentry) | **not run** |
| RPM, other distros, SELinux/AppArmor interaction | **not done** |
| Load: sustained high event rates, many-user hosts, `authorized_keys` at scale | **not measured** beyond the rule benchmark and the file/open overhead measured earlier |

Known gaps are listed in each as-built section above; the largest are: no systemd D-Bus/logind source, `same_tree` approximated by session, GUI pages other than the Dashboard not visually checked, argv longer than 3 KiB not chunked, exit events only for thread-group leaders, file events are "attempted" not confirmed.

---

## 15. Decisions I need from you (with my recommendation)

1. **Test environment**: can I get shell access to a Linux x86_64 VM (Ubuntu 22.04, kernel 5.15, root, BTF on)? *Strongly recommended; without it I can't verify any kernel behavior.*
2. **Tamper-evidence strength** (§5.4): include forward-secure sealing + anchors in v1? *Recommend yes; otherwise, the "provable" claim is weaker than the spec implies.*
3. **API write tiers** (§9.1): group `witness` = read + triage; root/`witness-admin` = rule changes. *Recommend yes.*
4. **Structured-parse exemption** for `authorized_keys`, `passwd/group/shadow` (§1.5). *Recommend yes, derived facts only.*
5. **Notifications** via a small `witness-notify` user service (§12.5). *Recommend yes.*
6. **eBPF crate on pinned nightly** with prebuilt, embedded object (§1.2). *No real alternative; confirming.*
7. **CO-RE approach**: runtime BTF-resolved offsets (§3.2), after an M1 spike on whether native relocation works in aya. *Recommend yes.*
8. **Defaults for "keep forever"** (§5.7): accept P3 summarization (file activity, UDP flows) as default so index growth is bounded? *Recommend yes.*

---

## 16. Licensing

- Userspace crates (`witnessd`, `witness-cli`, `witness-gui`, `xtask`): `MIT OR Apache-2.0`.
- **eBPF programs** declare their kernel-side license string `"Dual MIT/GPL"` 📘 (the kernel's `license_is_gpl_compatible()` accepts `GPL`, `GPL v2`, `GPL and additional rights`, `Dual BSD/GPL`, `Dual MIT/GPL`, `Dual MPL/GPL`). GPL-only helpers (e.g. `bpf_probe_read_kernel`, `bpf_d_path`, `bpf_ringbuf_*`'s GPL-restricted siblings) are refused by the verifier for non-GPL-compatible declarations. In aya: `#[link_section = "license"] #[no_mangle] static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";`.
- **Crate-level licensing nuance**: `witness-ebpf` source is `MIT OR GPL-2.0-only` (Apache-2.0 is GPLv2-incompatible, so the Apache option is not offered for the object that declares `Dual MIT/GPL`). `witness-common` is compiled into both sides, so it is `MIT` (as `MIT OR Apache-2.0` where the Apache path is simply unused on the eBPF side). I will document this in `LICENSE-*`/README. *This is engineering guidance, not legal advice.*
- The compiled BPF object is embedded in the userspace binary; the combined package license text states that the BPF object is separately available under `GPL-2.0-only` or `MIT`.

---

## 17. What happens next

I stop here for your review. After approval: `CLAUDE.md` (build/test commands and conventions), then M1 (workspace + eBPF build pipeline + exec/exit → stdout), starting with the two spikes: (a) native CO-RE vs runtime offsets in aya, (b) `fentry`/`fexit` target availability matrix on the real test kernel.
