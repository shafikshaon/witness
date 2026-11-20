#!/bin/sh
# Checks which users the postinst adds to the `witness` group, with a fake `loginctl`.
# Run: sh packaging/tests/postinst-users.sh   (no root needed; uses the real passwd database)
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
sed -n '/^# BEGIN witness_installers/,/^# END witness_installers/p' "$HERE/../debian/postinst" > "$T/fn.sh"

# Real accounts to play the parts: uid 0 (root), and the current user if uid >= 1000.
ME=$(id -un); MYID=$(id -u)
mkdir -p "$T/bin"
cat > "$T/bin/loginctl" <<'F'
#!/bin/sh
case "$1" in
list-sessions) printf 'c1 120 gdm seat0 tty1\n2 1000 %s seat0 tty2\n3 1000 %s - pts/0\n4 0 root seat0 tty3\n' "$ME" "$ME" ;;
show-session)
  case "$2" in
  c1) printf 'Name=gdm\nClass=greeter\nActive=yes\nRemote=no\n' ;;
  2)  printf 'Name=%s\nClass=user\nActive=yes\nRemote=no\n' "$ME" ;;
  3)  printf 'Name=%s\nClass=user\nActive=yes\nRemote=yes\n' "$ME" ;;
  4)  printf 'Name=root\nClass=user\nActive=yes\nRemote=no\n' ;;
  esac ;;
esac
F
chmod +x "$T/bin/loginctl"
export ME PATH="$T/bin:$PATH"
. "$T/fn.sh"
fail=0
check() { # name expected actual
    if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: expected '$2' got '$3'"; fail=1; fi
}
check "sudo user is used as given" "$ME" "$(SUDO_USER=$ME witness_installers 2>/dev/null || true)"
check "root is never added" "" "$(SUDO_USER=root witness_installers)"
check "unknown user is ignored" "" "$(SUDO_USER=no-such-user-xyz witness_installers)"
if [ "$MYID" -ge 1000 ]; then
    check "software centre: the seat's login, not the greeter, root or a remote session" "$ME" "$(env -u SUDO_USER -u PKEXEC_UID witness_installers)"
    check "pkexec user is used" "$ME" "$(PKEXEC_UID=$MYID witness_installers)"
else
    echo "skip: run as a normal user (uid >= 1000) for the seat and pkexec checks"
fi
exit $fail
