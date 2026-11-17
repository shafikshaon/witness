#!/bin/sh
# Development installer: puts the built binaries and the unit in place and starts the
# service. Real .deb/.rpm packaging (M10) replaces this. Run as root:
#   sudo packaging/dev-install.sh [target/debug|target/release]
set -eu
BIN_DIR=${1:-target/release}
HERE=$(cd "$(dirname "$0")" && pwd)

getent group witness >/dev/null || groupadd --system witness
getent group witness-admin >/dev/null || groupadd --system witness-admin

install -d -m 0755 /etc/witness /etc/witness/rules.d
install -d -m 0700 /var/lib/witness
install -m 0755 "$BIN_DIR/witnessd" /usr/sbin/witnessd
install -m 0755 "$BIN_DIR/witness" /usr/bin/witness
install -m 0644 "$HERE/systemd/witnessd.service" /etc/systemd/system/witnessd.service

# Keep an existing config; otherwise write the effective defaults.
if [ ! -f /etc/witness/config.toml ]; then
    /usr/bin/witness config show --file /nonexistent/none.toml > /etc/witness/config.toml 2>/dev/null
    chmod 0644 /etc/witness/config.toml
fi
/usr/bin/witness config check --file /etc/witness/config.toml

systemctl daemon-reload
systemctl enable witnessd.service
systemctl restart witnessd.service
systemctl --no-pager --lines=0 status witnessd.service || true
