%global crate kipuka

Name:           %{crate}
Version:        0.2.0
Release:        1%{?dist}
Summary:        EST/CMP/CMC enrollment server with Multi-CA HA and HSM support

License:        GPL-3.0-or-later
URL:            https://github.com/czinda/kipuka
Source0:        %{crate}-%{version}.tar.gz
# cargo vendor output — all dependencies bundled
Source1:        %{crate}-%{version}-vendor.tar.gz
Source2:        vendor-config.toml

ExclusiveArch:  %{rust_arches}

BuildRequires:  rust >= 1.97.1
BuildRequires:  cargo
BuildRequires:  openssl-devel
BuildRequires:  pkg-config
BuildRequires:  clang-devel
BuildRequires:  cmake
BuildRequires:  gcc
BuildRequires:  krb5-devel
BuildRequires:  systemd-rpm-macros

Requires:       openssl-libs

%description
kipuka is a Registration Authority (RA) and enrollment protocol server
providing EST, CMP, CMC, custom CMS/renewal extensions and CoAP/DTLS
enrollment. See the shipped support boundaries for implementation scope. It authenticates
clients via mTLS, OTP, or GSSAPI/Kerberos, validates CSRs against CA/B
Forum Baseline Requirements, and routes approved requests to a Certificate
Authority (standalone signing or Dogtag PKI backend).

Features include post-quantum readiness (ML-DSA/ML-KEM per FIPS 204/203),
HSM support (Entrust, Utimaco, Thales, Kryoptic via PKCS#11), multi-CA
high availability with failover strategies and PKCS#11 integration.
No NIAP or FIPS certification is established by this package.

%prep
%autosetup -n %{crate}-%{version}

# Unpack vendored dependencies
tar xf %{SOURCE1}

# Use Cargo's generated source replacement, including pinned Git dependencies.
mkdir -p .cargo
cp %{SOURCE2} .cargo/config.toml

%build
cargo build --frozen --release --all-features

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
