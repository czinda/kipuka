# Support and assurance boundaries

This is an implementation under development, not a certified CA appliance.
No NIAP, FIPS module validation, CA/B Forum compliance or complete RFC conformance
is established by unit tests, algorithm names, source checks or this documentation.
Deployment controls and independent interoperability evidence remain necessary.

* RFC 9148 specifies EST over CoAP/DTLS. RFC 9483 is the Lightweight CMP Profile.
* RFC 8739 specifies the ACME STAR extension. Kipuka's custom EST renewal routes
  are not the ACME protocol and must not be represented as RFC 8739 conformance.
* RFC 8295 specifies EST extensions for PAL packages. Custom CMS-wrapped EST
  routes do not establish its implementation.
* Local CMC, CMS and CMP support must be assessed against actual returned
  certificates, protection, authentication and authorization. An unsupported
  operation returns an error rather than a synthetic success.
* HA requires explicit label CA pools. Selecting a different issuer is an
  authorization decision; global failover must not override label restrictions.
  Ambiguous remote writes must be reconciled, not retried against another CA.
* STAR restores committed orders and renews using their persisted enrollment
  policy. Legacy orders without that policy require re-admission. Run one
  renewal worker per database; cross-process worker leasing is not implemented.
* Audit signing is unsupported and rejected at configuration validation. Audit
  row bounds and halt policies use database persistence; operation admission
  must record a durable request before signing. The syslog alarm action sends
  LOG_AUTHPRIV/LOG_ALERT datagrams to the system logger; failures are reported.
* File audit rotation/backup is not implemented by the database audit writer;
  use external logging and retention. No tamper-evident chain is claimed.

Tests with ignored bodies or source-only assertions are development aids, not
end-to-end protocol certification. Hardware PKCS#11 and live remote database /
Dogtag integration require their respective environments.
