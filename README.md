# Witness

A Linux forensic activity monitor. It records what happens on one machine (processes,
files, network and DNS, logins, devices, modules) into a **tamper-evident** store, runs
detection rules over it, and lets you search it from a CLI or a desktop app.

**It detects tampering. It does not prevent it.** Someone with root can stop the daemon or
rewrite the files; what Witness gives you is evidence of that, through a SHA-256 hash chain,
forward-secure sealing and anchors you keep elsewhere. Read [Threat model](#threat-model)
before relying on it.

## Quick start

```sh
witness status     # is it running? is the evidence intact? anything to review?
witness alerts     # what the rules flagged, newest last
witness-gui        # the same, with search, live feed and timelines
```

`witness status` is the one command to remember. If Witness is not running it says so and
tells you how to start it; if your user may not read it, it says that too. Everything below
is detail.

**Where to look when something happens:** *Alerts* (the rules' verdicts) → *Search* (find the
command, file or address) → *Sessions* (who was logged in). *Integrity* proves the evidence
was not changed afterwards.

## What it records

| Area | Events | Source |
|---|---|---|
| Processes | exec (argv, exe, cwd), fork, exit | eBPF `sched_process_*` |
| Files | create, open (write), delete, rename, link, chmod/chown, truncate, sensitive reads, SHA-256 of critical files | eBPF kprobes |
| Network | TCP connect/accept/listen/close with byte counts, attributed to the owning process | eBPF kprobes + `inet_sock_set_state` |
| DNS | queries and answers over UDP/53 and TCP/53, parsed | eBPF kprobes |
| UDP | per-process flow summaries (packets and bytes each way), every 10 s | eBPF kprobes |
| Auth | sshd logins and failures, sudo/su decisions, logind session open/close | journald |
| System | account and `authorized_keys` changes, package installs and removals (dpkg, dnf5; dnf 4 unverified), USB and block devices, kernel module load/unload, clock steps, service start/stop | passwd/shadow diffs, package logs, uevent netlink, eBPF, journald |
| Daemon | start/stop, capture gaps and drops, source health, rule changes, API access, triage | the daemon |

## Install (Debian/Ubuntu)

Download the packages for your CPU from the [Releases](https://github.com/shafikshaon/witness/releases)
page (`amd64` for Intel/AMD PCs, `arm64` for ARM) and install them from the terminal. Do not
double-click the `.deb`: the software app may just say "installed" and not upgrade.

```sh
cd ~/Downloads
sudo apt install ./witness_VERSION_amd64.deb         # daemon, CLI, rule pack
sudo apt install ./witness-gui_VERSION_amd64.deb     # optional desktop viewer
witness status                                       # confirm it works
```

Replace `VERSION` and the architecture with the file names you downloaded.

If apt prints `Download is performed unsandboxed as root ... couldn't be accessed by user '_apt'
(13: Permission denied)`, that is only a notice: apt cannot read files inside your home folder,
so it reads the package as root instead, and the install still completes. To avoid it, install
from a folder it can read:

```sh
cp ~/Downloads/witness*.deb /tmp/ && sudo apt install /tmp/witness_VERSION_amd64.deb /tmp/witness-gui_VERSION_amd64.deb
```

## Update

Install the newer files the same way. There is no need to uninstall first.

```sh
dpkg -l witness witness-gui | grep ^ii               # version installed now
sudo apt install ./witness_NEWVERSION_amd64.deb ./witness-gui_NEWVERSION_amd64.deb
witness status                                       # should show the new version
```

The upgrade replaces the old version in place: same service, and your evidence and settings are
kept. The service restarts, which leaves a short, recorded gap in capture.

## Uninstall

```sh
sudo apt remove witness-gui witness      # removes the programs; keeps settings and evidence
sudo apt purge witness-gui witness       # also removes the settings in /etc/witness
sudo gpasswd -d "$USER" witness          # optional: leave the witness group
sudo rm -rf /var/lib/witness             # optional and permanent: deletes the recorded evidence
```

Fedora: no prebuilt RPM is shipped with this build. `packaging/build-rpm.sh` builds one (the daemon was verified on Fedora 45; the GUI package is Debian/Ubuntu only for now).

The installer adds the user who ran it to the `witness` group, and `witness`/`witness-gui` use it right away (no logout). Other users: `sudo usermod -aG witness NAME`. If the app still says it may not open the socket, its **Grant access** button (or `sudo usermod -aG witness $USER`) fixes that. Installing a newer `.deb` over an old one upgrades it in place: same service, evidence and settings kept.

The service starts at boot, before networking and SSH. Evidence lives in
`/var/lib/witness` and is **never deleted automatically**, not even by `apt purge`.

## Use

```sh
witness status                               # overview: running? intact? alerts?
witness alerts [--all]                       # what needs review
witness show --last 20                       # recent records
witness show --type alert --last 10
sudo witness verify --dir /var/lib/witness   # check the hash chain
witness anchor                               # print the head to store off-host
witness rules lint                           # check /etc/witness/rules.d
witness rules test rules/exec-from-tmp.yml   # replay stored events through a rule
sudo witness bundle --from-seq 1000 --to-seq 2000 -o incident.tar   # evidence for a range, with proofs
witness-gui                                  # desktop app
```

The API is JSON over HTTP on `/run/witness/witness.sock` (`curl --unix-socket … /v1/status`).
Members of group `witness` can read and triage; `witness-admin` (or root) can change rules.

## Rules

YAML, Sigma-inspired but **not** Sigma-compatible. Field names are Witness's own: the same
dotted paths you see in stored records (`actor.exe`, `data.path`, …). Operators: `eq ne in
contains startswith endswith regex glob cidr gt gte lt lte exists`; correlation by `count`
and `sequence`. A bad rule file is rejected with `file:line:col` and the others still load.
Correlation also includes `first_seen` (alert once per new value, remembered across restarts) and process-tree scoped sequences. The built-in pack (21 rules) is in [`rules/`](rules/). Edits are picked up without a restart.

## Threat model

- **In scope:** detecting modification, deletion, reordering or truncation of evidence on
  disk; detecting that capture stopped or lost events (`capture_gap`, `capture_drop`).
- **Not in scope:** preventing a root attacker from disabling capture, or from rewriting
  the chain *and* its seals before you take an anchor elsewhere. Run `witness anchor` from
  another machine, or configure an anchor sink, to make rewrites provable.
- **Blind spots:** activity before the daemon started; events dropped by a full kernel
  ring (reported, not recovered); processes that exit faster than `/proc` can be read may
  lack `exe`; file events are *attempted* operations, not confirmed results; DNS over
  TCP/TLS/HTTPS is not seen.
- **Privacy:** members of `witness` can read every user's command lines, including secrets
  typed as arguments. Treat the group as root-equivalent for confidentiality.

## Build from source

```sh
rustup toolchain install nightly-2026-11-17 --component rust-src   # eBPF object
cargo install bpf-linker --locked
cargo build --release -p witnessd -p witness-cli                   # builds the eBPF object too
cargo build --release -p witness-gui    # Linux needs libwebkit2gtk-4.1-dev libgtk-3-dev libxdo-dev
packaging/build-deb.sh                  # writes dist/*.deb
```

Linux 5.15+ with BTF (`/sys/kernel/btf/vmlinux`). eBPF code never runs on macOS; set
`WITNESS_SKIP_EBPF=1` to build the userspace crates there. See [CLAUDE.md](CLAUDE.md) for
the test workflow and [docs/DESIGN.md](docs/DESIGN.md) for the design, deviations and
measurements.

## Status

The full privileged test suite passes on Ubuntu 22.04 (kernel 5.15, final code); Ubuntu 24.04 (6.8) and Fedora 45 (7.2, SELinux enforcing) passed on code that differs only in the CLI/GUI. **All of this ran on aarch64 virtual machines.** x86_64 was last run under emulation on older code and is not current; native Intel/AMD hardware was never tested. What was and was not verified is itemised in "What is verified" in [docs/DESIGN.md](docs/DESIGN.md) §14.

## License

Userspace: `MIT OR Apache-2.0` ([LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE)).
The eBPF programs declare `Dual MIT/GPL`; `witness-ebpf` source is `MIT OR GPL-2.0-only`
 The compiled BPF object embedded in the binary is available
under `GPL-2.0-only` or `MIT`; the GPL text is in [LICENSE-GPL-2.0](LICENSE-GPL-2.0). This is engineering guidance, not legal advice.
