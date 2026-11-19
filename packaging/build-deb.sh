#!/bin/sh
# Builds witness_<version>_<arch>.deb from already-built binaries (dpkg-deb only).
#   packaging/build-deb.sh [bin_dir] [out_dir]
# Cross-packaging: ARCH=amd64 WITNESS_HOST_BIN=<native witness binary> packaging/build-deb.sh <cross bin dir> <out>
# Build first on the target machine: cargo build --release -p witnessd -p witness-cli
# (add -p witness-gui for the desktop viewer package).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
BIN=${1:-$ROOT/target/release}
OUT=${2:-$ROOT/dist}
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)
# ARCH may be set to package cross-built binaries (e.g. ARCH=amd64 on an arm64 host).
ARCH=${ARCH:-$(dpkg --print-architecture)}
mkdir -p "$OUT"

stage() { # stage <dir> : fresh DEBIAN tree (0755 root dir, as dpkg expects)
    rm -rf "$1"; mkdir -p "$1/DEBIAN"; chmod 0755 "$1"
}

# ---- witness (daemon + CLI + rules) ----
S="$OUT/stage-witness"
stage "$S"
install -d "$S/usr/sbin" "$S/usr/bin" "$S/lib/systemd/system" "$S/etc/witness/rules.d" \
    "$S/usr/share/witness/rules" "$S/usr/share/doc/witness"
install -m 0755 "$BIN/witnessd" "$S/usr/sbin/witnessd"
install -m 0755 "$BIN/witness" "$S/usr/bin/witness"
install -m 0644 "$HERE/systemd/witnessd.service" "$S/lib/systemd/system/witnessd.service"
for r in "$ROOT"/rules/*.yml; do
    install -m 0644 "$r" "$S/etc/witness/rules.d/"
    install -m 0644 "$r" "$S/usr/share/witness/rules/"
done
"${WITNESS_HOST_BIN:-$BIN/witness}" config show --file /nonexistent/none.toml > "$S/etc/witness/config.toml"
chmod 0644 "$S/etc/witness/config.toml"
install -m 0644 "$ROOT/README.md" "$S/usr/share/doc/witness/README.md"
install -m 0644 "$ROOT/docs/DESIGN.md" "$S/usr/share/doc/witness/DESIGN.md"
install -m 0644 "$ROOT/LICENSE-MIT" "$S/usr/share/doc/witness/copyright"
for f in postinst prerm postrm; do install -m 0755 "$HERE/debian/$f" "$S/DEBIAN/$f"; done
( cd "$S" && find etc -type f | sed 's|^|/|' > DEBIAN/conffiles )
SIZE=$(du -sk "$S" | cut -f1)
cat > "$S/DEBIAN/control" <<CTL
Package: witness
Version: $VERSION
Architecture: $ARCH
Maintainer: Witness contributors <noreply@example.invalid>
Depends: libc6, systemd
Installed-Size: $SIZE
Section: admin
Priority: optional
Homepage: https://github.com/shafikshaon/witness
Description: Linux forensic activity monitor (tamper-evident)
 Records process, file, network, DNS and authentication activity with eBPF into a
 hash-chained store, evaluates detection rules, and serves a local API. It detects
 tampering with its own evidence; it does not prevent it.
CTL
dpkg-deb --root-owner-group --build "$S" "$OUT/witness_${VERSION}_${ARCH}.deb"

# ---- witness-gui (optional) ----
if [ -x "$BIN/witness-gui" ]; then
    G="$OUT/stage-gui"
    stage "$G"
    install -d "$G/usr/bin" "$G/usr/share/applications"
    install -m 0755 "$BIN/witness-gui" "$G/usr/bin/witness-gui"
    cat > "$G/usr/share/applications/witness.desktop" <<DSK
[Desktop Entry]
Type=Application
Name=Witness
Comment=Forensic activity viewer
Exec=witness-gui
Categories=System;Security;
DSK
    cat > "$G/DEBIAN/control" <<CTL
Package: witness-gui
Version: $VERSION
Architecture: $ARCH
Maintainer: Witness contributors <noreply@example.invalid>
Depends: witness (= $VERSION), libwebkit2gtk-4.1-0, libgtk-3-0
Section: admin
Priority: optional
Description: Desktop viewer for Witness
 Live view, search, alerts, timeline, process tree, sessions and integrity status.
 Connects to the local witnessd API; the user must be in the 'witness' group.
CTL
    dpkg-deb --root-owner-group --build "$G" "$OUT/witness-gui_${VERSION}_${ARCH}.deb"
fi
rm -rf "$OUT"/stage-*
ls -l "$OUT"/*.deb
