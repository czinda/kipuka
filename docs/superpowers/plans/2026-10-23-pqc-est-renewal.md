# Restore authenticated PQC EST renewal

Part of the approved CLI/EST/SIEM→KRA lab repair, executed inline. Baseline: `f61a4c95ee7b8937f3026c92a8409dc55fd63014`.

## Confirmed boundaries

- Live `/simplereenroll` returns 401 because the TLS listener does not request ML-DSA client signatures. Native `openssl s_client` confirms this; the full issuing chain is trusted.
- `src/tls/mod.rs` uses the ring/WebPKI client verifier, which does not verify ML-DSA chains or handshake signatures.
- `rustls-native-ossl` 0.1.13 supports ML-DSA signatures and matches the existing native-ossl dependency. Its generic chain verifier omits TLS-client EKU policy; use Synta's existing PQ-aware TLS-client policy, pinned to the repository's existing Synta revision.
- `simplereenroll.rs` currently always selects local signing even when a Dogtag backend is configured. Confirm with a failing handler test, then share the existing Dogtag enrollment path after renewal authentication, subject binding, revocation, and CSR PoP checks.

## Requirements and proof

- [x] Read project guidance, TLS/authentication/issuer paths, existing tests, and provider documentation.
- [x] Add real TLS handshake tests: trusted ML-DSA client accepted; missing, untrusted, expired, wrong-purpose, and tampered certificates rejected; optional unauthenticated TLS and classical mTLS remain functional.
- [x] Observe the PQ handshake regression fail against the original code.
- [x] Integrate the native handshake verifier and Synta chain policy in the existing TLS module; retain required/optional/none semantics and separate admin trust.
- [x] Add a failing Dogtag reenrollment contract test. Share existing issuer forwarding after all authorization/PoP checks; cover backend failure and pending approval.
- [x] Run focused tests, project test suite, format, all-features check, and clippy.
- [x] Build a traceable candidate image, preserve the existing database/volume and image for rollback, verify compatibility before replacing the live service.
- [x] Prove native ML-DSA enrollment, renewal with a matching returned key, and rejection of revoked/unauthenticated clients on the RHEL host.
- [x] Local whole-change review and handoff to KRA investigation; KRA correction and native verification completed.
- [ ] Independent review — the dispatched review service returned a platform policy error and no findings; remains outstanding.

On 24 October 2026, the user authorized local commits of these repairs. Runtime credentials are never copied into source or evidence.
