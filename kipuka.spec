%global crate kipuka

Name:           %{crate}
Version:        0.2.0
Release:        1%{?dist}
Summary:        EST/CMP/CMC enrollment server with Multi-CA HA and HSM support

License:        GPL-3.0-or-later
URL:            https://codeberg.org/czinda/kipuka
Source0:        %{crate}-%{version}.tar.gz
# cargo vendor output — all dependencies bundled
Source1:        %{crate}-%{version}-vendor.tar.gz

ExclusiveArch:  %{rust_arches}

BuildRequires:  rust >= 1.88
BuildRequires:  cargo
BuildRequires:  openssl-devel
BuildRequires:  pkg-config
BuildRequires:  clang-devel
BuildRequires:  cmake
BuildRequires:  gcc

Requires:       openssl-libs

%description
kipuka is a Registration Authority (RA) and enrollment protocol server
implementing EST (RFC 7030), CMP (RFC 4210), CMC (RFC 5272), CMS-EST
(RFC 8295), STAR (RFC 8739), and CoAP/DTLS (RFC 9148). It authenticates
clients via mTLS, OTP, or GSSAPI/Kerberos, validates CSRs against CA/B
Forum Baseline Requirements, and routes approved requests to a Certificate
Authority (standalone signing or Dogtag PKI backend).

Features include post-quantum readiness (ML-DSA/ML-KEM per FIPS 204/203),
HSM support (Entrust, Utimaco, Thales, Kryoptic via PKCS#11), multi-CA
high availability with failover strategies, NIAP CA Protection Profile
v2.0 compliance, and FIPS 140-3 capability through HSM integration.

%prep
%autosetup -n %{crate}-%{version}

# Unpack vendored dependencies
tar xf %{SOURCE1}

# Configure cargo to use vendored deps
mkdir -p .cargo
cat > .cargo/config.toml << 'EOF'
[source.crates-io]
replace-with = "vendored-sources"

[source."git+https://codeberg.org/abbra/synta.git"]
replace-with = "vendored-sources"

[source."git+https://codeberg.org/czinda/synta.git"]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
EOF

%build
cargo build --release --features default

%install
install -D -m 0755 target/release/%{crate} %{buildroot}%{_bindir}/%{crate}
install -D -m 0644 contrib/beaker/kipuka.service %{buildroot}%{_unitdir}/%{crate}.service
install -D -m 0640 kipuka.toml.example %{buildroot}%{_sysconfdir}/%{crate}/%{crate}.toml
install -d -m 0750 %{buildroot}%{_sharedstatedir}/%{crate}
install -d -m 0750 %{buildroot}%{_localstatedir}/log/%{crate}

%pre
getent group %{crate} >/dev/null || groupadd -r %{crate}
getent passwd %{crate} >/dev/null || \
    useradd -r -g %{crate} -d %{_sharedstatedir}/%{crate} \
    -s /sbin/nologin -c "kipuka EST server" %{crate}

%post
%systemd_post %{crate}.service

%preun
%systemd_preun %{crate}.service

%postun
%systemd_postun_with_restart %{crate}.service

%files
%license LICENSE
%doc README.md docs/
%{_bindir}/%{crate}
%{_unitdir}/%{crate}.service
%dir %attr(0750,%{crate},%{crate}) %{_sysconfdir}/%{crate}
%config(noreplace) %attr(0640,%{crate},%{crate}) %{_sysconfdir}/%{crate}/%{crate}.toml
%dir %attr(0750,%{crate},%{crate}) %{_sharedstatedir}/%{crate}
%dir %attr(0750,%{crate},%{crate}) %{_localstatedir}/log/%{crate}

%changelog
* Sun Jul 06 2026 Chris Zinda <czinda@redhat.com> - 0.1.0-1
- Initial package for Fedora COPR
- EST/CMP/CMC/STAR/CoAP enrollment server
- 26 RFC implementations, 4 HSM backends
- CA/B Forum T0 audit blockers fixed
- Unified secret management (SecretRef with 6 backends)
