# Binary RPM assembled from already-built binaries (see packaging/build-rpm.sh). The staged
# tree in Source0 has the final file layout; nothing is compiled here.
%global debug_package %{nil}
%global __strip /bin/true
%global __brp_strip %{nil}

Name:           witness
Version:        %{witness_version}
Release:        1%{?dist}
Summary:        Linux forensic activity monitor (tamper-evident)
License:        MIT OR Apache-2.0
URL:            https://github.com/shafikshaon/witness
Source0:        witness-stage.tar.gz
Requires:       systemd
%{?systemd_requires}

%description
Records process, file, network, DNS and authentication activity with eBPF into a hash-chained
store, evaluates detection rules, and serves a local API. It detects tampering with its own
evidence; it does not prevent it.

%package gui
Summary:        Desktop viewer for Witness
Requires:       %{name} = %{version}-%{release}
Requires:       webkit2gtk4.1
Requires:       gtk3

%description gui
Live view, search, alerts, timeline, process tree, sessions and integrity status. Connects to
the local witnessd API; the user must be in the 'witness' group.

%prep
%setup -q -c -T
tar xzf %{SOURCE0}

%build
# Nothing to build: the binaries were produced by cargo.

%install
mkdir -p %{buildroot}%{_sbindir}
# %{_sbindir} is /usr/bin on merged-/usr systems (Fedora) and /usr/sbin elsewhere.
mv usr/sbin/witnessd %{buildroot}%{_sbindir}/witnessd
rmdir usr/sbin
mkdir -p %{buildroot}
cp -a . %{buildroot}/
rm -f %{buildroot}/witness-stage.tar.gz

%pre
getent group witness >/dev/null || groupadd -r witness
getent group witness-admin >/dev/null || groupadd -r witness-admin
exit 0

%post
install -d -m 0700 /var/lib/witness
install -d -m 0755 /etc/witness/rules.d
%systemd_post witnessd.service
# Start on a fresh install; an upgrade restarts through %postun below.
if [ $1 -eq 1 ] && [ -d /run/systemd/system ]; then
    systemctl start witnessd.service >/dev/null 2>&1 || :
fi

%preun
%systemd_preun witnessd.service

%postun
%systemd_postun_with_restart witnessd.service
# The evidence directory /var/lib/witness is never removed, not even on erase.

%files
%license LICENSE-MIT LICENSE-APACHE LICENSE-GPL-2.0
%doc README.md DESIGN.md
%{_sbindir}/witnessd
%{_bindir}/witness
%{_prefix}/lib/systemd/system/witnessd.service
%dir %{_sysconfdir}/witness
%dir %{_sysconfdir}/witness/rules.d
%config(noreplace) %{_sysconfdir}/witness/config.toml
%config(noreplace) %{_sysconfdir}/witness/rules.d/*.yml
%{_datadir}/witness

%files gui
%{_bindir}/witness-gui
%{_datadir}/applications/witness.desktop

%changelog
* Thu Nov 19 2026 Witness contributors <noreply@example.invalid> - %{version}-1
- Binary package built from release binaries.

