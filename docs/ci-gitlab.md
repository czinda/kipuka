# GitLab pipeline

Every branch, merge request, tag, and scheduled branch pipeline runs the same
Rust verification jobs. Push pipelines are suppressed when an open merge request
already provides a pipeline for that branch. Rust 1.97.1 is pinned in the image
and checked against `rust-toolchain.toml`; native dependencies include OpenSSL,
Clang, and Kerberos headers. Both default-feature and all-feature tests cover the
whole workspace. Formatting, Clippy, audit exceptions, licenses, sources, and
bans are blocking checks. Dependency installation failures are not suppressed.

## Runner and publication requirements

Rust jobs use the shared Kubernetes runner tagged `itup-alm-x86`, with registry
and Cargo dependency access. `container-verify` uses the same runner and pinned
`moby/buildkit:v0.33.0-rootless` (official release and registry tag verified). It
starts immediately alongside lint to expose runner capability failures early.
The job copies the submitted Containerfile to a temporary directory and appends
an exec-form `RUN` of `kipuka --version` to its final stage. This exercises the
final filesystem and configured USER without requiring a runtime shell. It builds
a temporary OCI archive, then deletes it; it never authenticates or publishes.

Rootless BuildKit still needs user namespaces and mount syscalls permitted by
the runner's security policy. `--oci-worker-no-process-sandbox` follows
[GitLab's BuildKit setup](https://docs.gitlab.com/ci/docker/using_buildkit/).
AppArmor or namespace denial is an infrastructure failure, not a passing smoke
test; a runner administrator must resolve it. This capability has not yet been
established on the shared runner by a completed build.

`container-publish` retains Podman build and runtime `--version` verification on
a dedicated runner tagged `shell`. The existing project runner (63617) is stale
and has no such tag; publication remains blocked until an administrator provides
a working shell runner with Podman. It is excluded entirely from verification
branches, merge requests, schedules, and manually started pipelines.

Only a push pipeline on a protected default branch or protected tag publishes to
`quay.io/czinda/kipuka`. Configure protected, masked `QUAY_USERNAME` and
`QUAY_PASSWORD` variables. The default branch publishes the full commit SHA and
`latest`; tags publish the SHA and exact tag, never move `latest`. TLS validation
remains enabled. The temporary login file is deleted at job exit. Protect release
tags and restrict who can push to the default branch before enabling publication.

Pages publishes only on the protected default branch after the previous stages
succeed. Source RPM assembly is distinct from binary RPM verification: the job
runs `cargo vendor --locked` and `rpmbuild -bs`, retaining the source RPM and Cargo
vendor configuration. COPR submission is an explicit manual gate for protected
tags with protected `COPR_CONFIG` configured. No COPR write occurs on branches.

## Optional external checks

The internal Mantis scanner runs only with `ENABLE_MANTIS=true`; its failures then
fail that job. SARIF is a downloadable artifact, not a GitLab SAST report (which
requires a different JSON schema).

The former RPM placeholder, ahdapa placeholder, EST client setup placeholder, and
FIPS-name filter have been removed. They provided no evidence of the advertised
verification. OpenSSL/CMS and transport regression tests run in the workspace test
jobs; these do not establish independent interoperability or FIPS certification.

Dogtag, FreeIPA, and Beaker scripts remain under `contrib/beaker/` for disposable
lab hosts. Their existing setup assumes RHEL/systemd and can clone `main` instead
of the pipeline commit. They are not run inside a UBI container as CI checks.
Before adding those jobs back, provide a dedicated disposable runner, provision
its external services, make setup consume `CI_COMMIT_SHA`, and copy sanitized logs
into the checkout for artifact upload. Keytabs, passwords, and generated secret
environment files must not be uploaded as artifacts.
