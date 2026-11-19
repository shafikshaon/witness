#!/bin/sh
# Builds witness-<ver>-1.<dist>.<arch>.rpm and witness-gui-... from already-built binaries.
#   packaging/build-rpm.sh [bin_dir] [out_dir]
# Run on an RPM-based machine with rpm-build installed, after:
#   cargo build --release -p witnessd -p witness-cli [-p witness-gui]
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
BIN=${1:-$ROOT/target/release}
OUT=${2:-$ROOT/dist}
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)
mkdir -p "$OUT"
TOP=$(mktemp -d)
S="$TOP/stage"
mkdir -p "$S/usr/sbin" "$S/usr/bin" "$S/usr/lib/systemd/system" "$S/etc/witness/rules.d" \
    "$S/usr/share/witness/rules" "$S/usr/share/applications"
install -m 0755 "$BIN/witnessd" "$S/usr/sbin/witnessd"
install -m 0755 "$BIN/witness" "$S/usr/bin/witness"
[ -x "$BIN/witness-gui" ] && install -m 0755 "$BIN/witness-gui" "$S/usr/bin/witness-gui"
install -m 0644 "$HERE/systemd/witnessd.service" "$S/usr/lib/systemd/system/witnessd.service"
for r in "$ROOT"/rules/*.yml; do
    install -m 0644 "$r" "$S/etc/witness/rules.d/"
    install -m 0644 "$r" "$S/usr/share/witness/rules/"
done
"${WITNESS_HOST_BIN:-$BIN/witness}" config show --file /nonexistent/none.toml > "$S/etc/witness/config.toml"
chmod 0644 "$S/etc/witness/config.toml"
cp "$ROOT/README.md" "$ROOT/docs/DESIGN.md" "$ROOT"/LICENSE-* "$S/"
printf '[Desktop Entry]\nType=Application\nName=Witness\nComment=Forensic activity viewer\nExec=witness-gui\nCategories=System;Security;\n' > "$S/usr/share/applications/witness.desktop"
# A package without the GUI binary must not list its files.
if [ ! -x "$S/usr/bin/witness-gui" ]; then rm -f "$S/usr/share/applications/witness.desktop"; fi
mkdir -p "$TOP/SOURCES" "$TOP/SPECS"
( cd "$S" && tar czf "$TOP/SOURCES/witness-stage.tar.gz" . )
SPEC="$TOP/SPECS/witness.spec"
cp "$HERE/rpm/witness.spec" "$SPEC"
if [ ! -x "$S/usr/bin/witness-gui" ]; then
    # Drop the gui subpackage entirely.
    python3 - "$SPEC" <<'PY'
import re,sys
p=sys.argv[1]; s=open(p).read()
s=re.sub(r'%package gui.*?(?=%prep)','',s,flags=re.S)
s=re.sub(r'%files gui.*','',s,flags=re.S)
open(p,'w').write(s)
PY
fi
rpmbuild -bb --define "_topdir $TOP" --define "witness_version $VERSION" "$SPEC" >/dev/null
find "$TOP/RPMS" -name '*.rpm' -exec cp {} "$OUT/" \;
rm -rf "$TOP"
ls -l "$OUT"/*.rpm
