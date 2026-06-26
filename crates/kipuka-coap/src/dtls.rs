//! DTLS session management for EST-coaps transport security.
//!
//! RFC 9483 §5 mandates DTLS to secure all EST-coaps exchanges. This module
//! provides session tracking, caching abstractions, and a concrete OpenSSL-based
//! DTLS implementation using memory BIOs for UDP transport.
//!
//! # Session Resumption
//!
//! Constrained devices benefit significantly from DTLS session resumption
//! (RFC 6347 §4.2.8, RFC 9147 §5) because the full handshake involves
//! multiple round trips and is computationally expensive, especially with
//! post-quantum key exchange (ML-KEM).
//!
//! The [`DtlsSessionCache`] provides a bounded, TTL-expiring cache of
//! established sessions keyed by peer address.
//!
//! # OpenSSL DTLS Integration
//!
//! The [`DtlsContext`] wraps an `openssl::ssl::SslContext` configured for
//! DTLS server operation with optional client certificate authentication.
//! [`DtlsConnection`] handles individual peer sessions using memory BIOs
//! for non-blocking UDP I/O.

use crate::CoapError;
use openssl::pkey::PKey;
use openssl::ssl::{SslContext, SslMethod, SslVerifyMode};
use openssl::x509::X509;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// DTLS protocol version.
///
/// RFC 9483 §5 supports both DTLS 1.2 (RFC 6347) and DTLS 1.3 (RFC 9147).
/// DTLS 1.3 is preferred when both peers support it, as it reduces
/// handshake round trips and provides improved security properties.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DtlsVersion {
    /// DTLS 1.2 per RFC 6347.
    V1_2,
    /// DTLS 1.3 per RFC 9147.
    V1_3,
}

impl DtlsVersion {
    /// Returns the human-readable version string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V1_2 => "DTLS 1.2",
            Self::V1_3 => "DTLS 1.3",
        }
    }
}

/// An established DTLS session for a CoAP/EST-coaps connection.
///
/// RFC 9483 §5: EST-coaps uses DTLS to secure the CoAP transport.
/// DTLS 1.2 (RFC 6347) and DTLS 1.3 (RFC 9147) are supported.
///
/// This struct tracks the session state needed for EST operations:
/// the peer identity (from the client certificate or PSK), the session
/// identifier for resumption, and protocol version.
#[derive(Debug, Clone)]
pub struct DtlsSession {
    /// Opaque session identifier for resumption.
    session_id: Vec<u8>,
    /// Peer network address.
    peer_addr: SocketAddr,
    /// Client certificate presented during handshake (DER-encoded), if any.
    ///
    /// For certificate-based EST enrollment, the client may present an
    /// existing certificate for re-enrollment (RFC 9483 §5.3).
    client_cert: Option<Vec<u8>>,
    /// Timestamp when the session was established.
    created_at: Instant,
    /// Negotiated DTLS protocol version.
    protocol_version: DtlsVersion,
}

impl DtlsSession {
    /// Creates a new DTLS session record.
    pub fn new(session_id: Vec<u8>, peer_addr: SocketAddr, protocol_version: DtlsVersion) -> Self {
        Self {
            session_id,
            peer_addr,
            client_cert: None,
            created_at: Instant::now(),
            protocol_version,
        }
    }

    /// Creates a new DTLS session with a client certificate.
    pub fn with_client_cert(
        session_id: Vec<u8>,
        peer_addr: SocketAddr,
        protocol_version: DtlsVersion,
        client_cert_der: Vec<u8>,
    ) -> Self {
        Self {
            session_id,
            peer_addr,
            client_cert: Some(client_cert_der),
            created_at: Instant::now(),
            protocol_version,
        }
    }

    /// Returns the opaque session identifier.
    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }

    /// Returns the peer network address.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Returns the DER-encoded client certificate, if presented.
    pub fn client_cert(&self) -> Option<&[u8]> {
        self.client_cert.as_deref()
    }

    /// Returns when the session was established.
    pub fn created_at(&self) -> Instant {
        self.created_at
    }

    /// Returns the negotiated DTLS version.
    pub fn protocol_version(&self) -> DtlsVersion {
        self.protocol_version
    }

    /// Checks whether the session has exceeded the given TTL.
    pub fn is_expired(&self, ttl: Duration) -> bool {
        self.created_at.elapsed() > ttl
    }

    /// Extracts client certificate information from this session.
    ///
    /// Parses the DER-encoded client certificate using `synta_certificate`
    /// to extract the subject DN (RFC 4514 string form) and serial number.
    ///
    /// Returns `None` if no client certificate was presented or if the
    /// certificate cannot be parsed.
    pub fn client_cert_info(&self) -> Option<ClientCertInfo> {
        let der = self.client_cert.as_ref()?;
        ClientCertInfo::from_der(der)
    }
}

/// Client certificate information extracted from a DTLS handshake.
///
/// Used to identify the enrolling client for EST operations that require
/// mTLS authentication (simpleenroll, simplereenroll, serverkeygen).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCertInfo {
    /// Subject distinguished name (RFC 4514 string form).
    pub subject_dn: String,
    /// Certificate serial number (big-endian unsigned integer).
    pub serial: Vec<u8>,
    /// Full DER-encoded certificate.
    pub der_bytes: Vec<u8>,
}

impl ClientCertInfo {
    /// Parses a DER-encoded X.509 certificate and extracts identity fields.
    ///
    /// Uses `synta_certificate::Certificate::from_der()` for ASN.1 parsing
    /// and `synta_certificate::format_dn()` for RFC 4514 DN formatting.
    ///
    /// Returns `None` if the DER bytes cannot be parsed as a valid certificate.
    pub fn from_der(der: &[u8]) -> Option<Self> {
        let cert = synta_certificate::Certificate::from_der(der).ok()?;
        let subject_dn = synta_certificate::format_dn(cert.tbs_certificate.subject.0);
        let serial = cert.tbs_certificate.serial_number.as_bytes().to_vec();

        Some(Self {
            subject_dn,
            serial,
            der_bytes: der.to_vec(),
        })
    }
}

/// A bounded, TTL-expiring cache of DTLS sessions keyed by peer address.
///
/// Constrained devices perform expensive handshakes (especially with
/// post-quantum key exchange), so session resumption significantly
/// reduces latency and power consumption for repeated EST operations.
///
/// # Capacity Management
///
/// The cache enforces a maximum number of sessions. When full, expired
/// sessions are purged first. If still full, the oldest session is evicted.
#[derive(Debug)]
pub struct DtlsSessionCache {
    /// Active sessions indexed by peer address.
    sessions: HashMap<SocketAddr, DtlsSession>,
    /// Maximum number of cached sessions.
    max_sessions: usize,
    /// Time-to-live for cached sessions.
    ttl: Duration,
}

impl DtlsSessionCache {
    /// Creates a new session cache.
    ///
    /// # Arguments
    ///
    /// * `max_sessions` - Maximum number of sessions to cache.
    /// * `ttl` - Duration after which sessions expire and become eligible
    ///   for eviction.
    pub fn new(max_sessions: usize, ttl: Duration) -> Self {
        Self {
            sessions: HashMap::with_capacity(max_sessions),
            max_sessions,
            ttl,
        }
    }

    /// Inserts a session into the cache.
    ///
    /// If the cache is at capacity, expired sessions are purged first.
    /// If still full, the oldest session is evicted to make room.
    pub fn insert(&mut self, session: DtlsSession) {
        if self.sessions.len() >= self.max_sessions
            && !self.sessions.contains_key(&session.peer_addr)
        {
            self.cleanup_expired();

            // If still full after cleanup, evict the oldest session.
            if self.sessions.len() >= self.max_sessions
                && let Some(oldest_addr) = self.oldest_session_addr()
            {
                self.sessions.remove(&oldest_addr);
            }
        }

        self.sessions.insert(session.peer_addr, session);
    }

    /// Retrieves a cached session for the given peer address.
    ///
    /// Returns `None` if no session exists or if the session has expired.
    /// Expired sessions are removed on access.
    pub fn get(&mut self, peer_addr: &SocketAddr) -> Option<&DtlsSession> {
        // Check expiry and remove if stale.
        if let Some(session) = self.sessions.get(peer_addr)
            && session.is_expired(self.ttl)
        {
            self.sessions.remove(peer_addr);
            return None;
        }

        self.sessions.get(peer_addr)
    }

    /// Removes a session from the cache.
    ///
    /// Returns the removed session, or `None` if no session existed for
    /// the given address.
    pub fn remove(&mut self, peer_addr: &SocketAddr) -> Option<DtlsSession> {
        self.sessions.remove(peer_addr)
    }

    /// Removes all expired sessions from the cache.
    ///
    /// Returns the number of sessions removed.
    pub fn cleanup_expired(&mut self) -> usize {
        let ttl = self.ttl;
        let before = self.sessions.len();
        self.sessions.retain(|_, session| !session.is_expired(ttl));
        before - self.sessions.len()
    }

    /// Returns the number of currently cached sessions.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Returns whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Returns the configured maximum number of sessions.
    pub fn max_sessions(&self) -> usize {
        self.max_sessions
    }

    /// Returns the configured TTL.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Finds the address of the oldest session in the cache.
    fn oldest_session_addr(&self) -> Option<SocketAddr> {
        self.sessions
            .iter()
            .min_by_key(|(_, session)| session.created_at)
            .map(|(addr, _)| *addr)
    }
}

/// OpenSSL DTLS server context for EST-coaps.
///
/// Wraps an `openssl::ssl::SslContext` configured with the server certificate,
/// private key, and trusted CA for optional client certificate verification.
///
/// RFC 9483 §5 requires DTLS for all EST-coaps exchanges. The server presents
/// its certificate during the handshake and optionally requests a client
/// certificate for mTLS-based enrollment authentication.
///
/// # Example
///
/// ```no_run
/// # use kipuka_coap::dtls::DtlsContext;
/// let cert_pem = std::fs::read("server.crt").unwrap();
/// let key_pem = std::fs::read("server.key").unwrap();
/// let ca_pem = std::fs::read("ca.crt").unwrap();
/// let ctx = DtlsContext::new(&cert_pem, &key_pem, &ca_pem).unwrap();
/// ```
pub struct DtlsContext {
    ctx: SslContext,
}

impl DtlsContext {
    /// Creates a new DTLS server context.
    ///
    /// # Arguments
    ///
    /// * `cert_pem` - PEM-encoded server certificate.
    /// * `key_pem` - PEM-encoded server private key.
    /// * `ca_pem` - PEM-encoded CA certificate for verifying client certificates.
    ///
    /// The context is configured to request (but not require) a client certificate
    /// during the DTLS handshake. EST operations that need mTLS authentication
    /// should check `DtlsConnection::client_cert()` after the handshake completes.
    pub fn new(cert_pem: &[u8], key_pem: &[u8], ca_pem: &[u8]) -> Result<Self, CoapError> {
        let mut ctx_builder = SslContext::builder(SslMethod::dtls())
            .map_err(|e| CoapError::DtlsError(format!("Failed to create DTLS context: {e}")))?;

        let cert = X509::from_pem(cert_pem).map_err(|e| {
            CoapError::DtlsError(format!("Failed to parse server certificate PEM: {e}"))
        })?;
        ctx_builder
            .set_certificate(&cert)
            .map_err(|e| CoapError::DtlsError(format!("Failed to set server certificate: {e}")))?;

        let key = PKey::private_key_from_pem(key_pem).map_err(|e| {
            CoapError::DtlsError(format!("Failed to parse server private key PEM: {e}"))
        })?;
        ctx_builder
            .set_private_key(&key)
            .map_err(|e| CoapError::DtlsError(format!("Failed to set server private key: {e}")))?;

        ctx_builder
            .check_private_key()
            .map_err(|e| CoapError::DtlsError(format!("Server certificate/key mismatch: {e}")))?;

        // Request client certificate but do not require it — EST operations
        // that need mTLS will check the certificate after handshake.
        ctx_builder.set_verify(SslVerifyMode::PEER);

        // Load the CA certificate for client certificate verification.
        let ca = X509::from_pem(ca_pem).map_err(|e| {
            CoapError::DtlsError(format!("Failed to parse CA certificate PEM: {e}"))
        })?;
        ctx_builder
            .cert_store_mut()
            .add_cert(ca)
            .map_err(|e| CoapError::DtlsError(format!("Failed to add CA to trust store: {e}")))?;

        Ok(Self {
            ctx: ctx_builder.build(),
        })
    }

    /// Returns a reference to the underlying `SslContext`.
    ///
    /// Used by [`DtlsConnection`] to create per-peer SSL instances.
    pub fn ssl_context(&self) -> &SslContext {
        &self.ctx
    }
}

impl std::fmt::Debug for DtlsContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DtlsContext")
            .field("ctx", &"<SslContext>")
            .finish()
    }
}

/// An established DTLS connection to a single CoAP peer.
///
/// Wraps an OpenSSL `Ssl` instance with memory BIOs for non-blocking UDP I/O.
/// The connection tracks the peer address and the client certificate presented
/// during the DTLS handshake (if any).
///
/// # Memory BIO Architecture
///
/// OpenSSL's DTLS API uses BIO (Basic I/O) abstractions. For UDP transport,
/// we use memory BIOs instead of socket BIOs:
///
/// 1. Write received UDP datagram into the read BIO.
/// 2. Call `SSL_read` to get decrypted application data.
/// 3. Call `SSL_write` to encrypt response data.
/// 4. Read from the write BIO to get the encrypted datagram.
/// 5. Send the encrypted datagram via UDP socket.
#[derive(Debug)]
pub struct DtlsConnection {
    /// OpenSSL SSL instance for this peer.
    ssl: openssl::ssl::Ssl,
    /// Peer network address.
    peer_addr: SocketAddr,
    /// Client certificate extracted after successful handshake.
    client_cert: Option<ClientCertInfo>,
    /// Whether the DTLS handshake has completed.
    handshake_complete: bool,
}

impl DtlsConnection {
    /// Creates a new DTLS connection for the given peer.
    ///
    /// The connection is in the pre-handshake state. Call [`accept_handshake`]
    /// to begin the DTLS server-side handshake.
    pub fn new(ctx: &DtlsContext, peer_addr: SocketAddr) -> Result<Self, CoapError> {
        let ssl = openssl::ssl::Ssl::new(ctx.ssl_context())
            .map_err(|e| CoapError::DtlsError(format!("Failed to create SSL instance: {e}")))?;

        Ok(Self {
            ssl,
            peer_addr,
            client_cert: None,
            handshake_complete: false,
        })
    }

    /// Returns the peer network address.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Returns client certificate information, if a client certificate was
    /// presented and successfully parsed during the DTLS handshake.
    pub fn client_cert(&self) -> Option<&ClientCertInfo> {
        self.client_cert.as_ref()
    }

    /// Returns whether the DTLS handshake has completed successfully.
    pub fn is_handshake_complete(&self) -> bool {
        self.handshake_complete
    }

    /// Extracts and caches the client certificate from the SSL session.
    ///
    /// Called after the handshake completes to parse the peer certificate
    /// (if any) into a [`ClientCertInfo`].
    fn extract_client_cert(&mut self) {
        if let Some(peer_cert) = self.ssl.peer_certificate()
            && let Ok(der) = peer_cert.to_der()
        {
            self.client_cert = ClientCertInfo::from_der(&der);
        }
    }

    /// Marks the handshake as complete and extracts the client certificate.
    ///
    /// This should be called by the server loop once the DTLS handshake
    /// has finished successfully.
    pub fn complete_handshake(&mut self) {
        self.handshake_complete = true;
        self.extract_client_cert();
    }

    /// Returns a reference to the underlying `Ssl` instance.
    ///
    /// Used by the server implementation for memory BIO operations.
    pub fn ssl(&self) -> &openssl::ssl::Ssl {
        &self.ssl
    }

    /// Returns a mutable reference to the underlying `Ssl` instance.
    ///
    /// Used by the server implementation for memory BIO operations.
    pub fn ssl_mut(&mut self) -> &mut openssl::ssl::Ssl {
        &mut self.ssl
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, port as u8)), port)
    }

    #[test]
    fn test_dtls_version_as_str() {
        assert_eq!(DtlsVersion::V1_2.as_str(), "DTLS 1.2");
        assert_eq!(DtlsVersion::V1_3.as_str(), "DTLS 1.3");
    }

    #[test]
    fn test_session_creation() {
        let addr = test_addr(5683);
        let session = DtlsSession::new(vec![1, 2, 3], addr, DtlsVersion::V1_3);

        assert_eq!(session.session_id(), &[1, 2, 3]);
        assert_eq!(session.peer_addr(), addr);
        assert!(session.client_cert().is_none());
        assert_eq!(session.protocol_version(), DtlsVersion::V1_3);
    }

    #[test]
    fn test_session_with_client_cert_raw_access() {
        let addr = test_addr(5683);
        let cert_der = vec![0x30, 0x82, 0x01, 0x00];
        let session =
            DtlsSession::with_client_cert(vec![1, 2, 3], addr, DtlsVersion::V1_2, cert_der.clone());

        // Raw DER bytes are always accessible.
        assert_eq!(session.client_cert(), Some(cert_der.as_slice()));
        // But parsing dummy bytes as an X.509 certificate correctly returns None.
        assert!(session.client_cert_info().is_none());
    }

    #[test]
    fn test_session_with_real_client_cert() {
        // Generate a real self-signed certificate for testing.
        use openssl::asn1::Asn1Time;
        use openssl::bn::BigNum;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::x509::{X509Builder, X509NameBuilder};

        let rsa = Rsa::generate(2048).unwrap();
        let key = PKey::from_rsa(rsa).unwrap();

        let mut name_builder = X509NameBuilder::new().unwrap();
        name_builder
            .append_entry_by_text("CN", "test-client")
            .unwrap();
        let name = name_builder.build();

        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();

        let serial = BigNum::from_u32(42).unwrap();
        builder
            .set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();

        let not_before = Asn1Time::days_from_now(0).unwrap();
        let not_after = Asn1Time::days_from_now(365).unwrap();
        builder.set_not_before(&not_before).unwrap();
        builder.set_not_after(&not_after).unwrap();

        builder.sign(&key, MessageDigest::sha256()).unwrap();
        let cert = builder.build();
        let cert_der = cert.to_der().unwrap();

        let addr = test_addr(5683);
        let session =
            DtlsSession::with_client_cert(vec![1, 2, 3], addr, DtlsVersion::V1_2, cert_der.clone());

        assert_eq!(session.client_cert(), Some(cert_der.as_slice()));
        let info = session.client_cert_info().unwrap();
        assert!(
            info.subject_dn.contains("test-client"),
            "Expected subject DN to contain 'test-client', got: {}",
            info.subject_dn
        );
        assert!(!info.serial.is_empty());
        assert_eq!(info.der_bytes, cert_der);
    }

    #[test]
    fn test_client_cert_info_from_der_invalid() {
        // Invalid DER should return None, not panic.
        assert!(ClientCertInfo::from_der(&[0x00, 0x01]).is_none());
        assert!(ClientCertInfo::from_der(&[]).is_none());
    }

    #[test]
    fn test_session_expiry() {
        let addr = test_addr(5683);
        let session = DtlsSession::new(vec![1], addr, DtlsVersion::V1_3);

        // Session just created should not be expired with a long TTL.
        assert!(!session.is_expired(Duration::from_secs(3600)));

        // Session should be expired with a zero TTL.
        assert!(session.is_expired(Duration::ZERO));
    }

    #[test]
    fn test_cache_insert_and_get() {
        let mut cache = DtlsSessionCache::new(10, Duration::from_secs(3600));
        let addr = test_addr(5683);
        let session = DtlsSession::new(vec![1, 2, 3], addr, DtlsVersion::V1_3);

        cache.insert(session);
        assert_eq!(cache.len(), 1);
        assert!(!cache.is_empty());

        let retrieved = cache.get(&addr);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().session_id(), &[1, 2, 3]);
    }

    #[test]
    fn test_cache_remove() {
        let mut cache = DtlsSessionCache::new(10, Duration::from_secs(3600));
        let addr = test_addr(5683);
        let session = DtlsSession::new(vec![1], addr, DtlsVersion::V1_3);

        cache.insert(session);
        assert_eq!(cache.len(), 1);

        let removed = cache.remove(&addr);
        assert!(removed.is_some());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_cache_eviction_on_capacity() {
        let mut cache = DtlsSessionCache::new(2, Duration::from_secs(3600));

        cache.insert(DtlsSession::new(vec![1], test_addr(1), DtlsVersion::V1_3));
        cache.insert(DtlsSession::new(vec![2], test_addr(2), DtlsVersion::V1_3));
        assert_eq!(cache.len(), 2);

        // Third insert should evict the oldest.
        cache.insert(DtlsSession::new(vec![3], test_addr(3), DtlsVersion::V1_3));
        assert_eq!(cache.len(), 2);

        // The first session (oldest) should have been evicted.
        assert!(cache.get(&test_addr(1)).is_none());
        assert!(cache.get(&test_addr(3)).is_some());
    }

    #[test]
    fn test_cache_expired_not_returned() {
        let mut cache = DtlsSessionCache::new(10, Duration::ZERO);
        let addr = test_addr(5683);
        let session = DtlsSession::new(vec![1], addr, DtlsVersion::V1_3);

        cache.insert(session);
        // With zero TTL, session should be expired immediately.
        assert!(cache.get(&addr).is_none());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_cache_cleanup_expired() {
        let mut cache = DtlsSessionCache::new(10, Duration::ZERO);
        cache.insert(DtlsSession::new(vec![1], test_addr(1), DtlsVersion::V1_3));
        cache.insert(DtlsSession::new(vec![2], test_addr(2), DtlsVersion::V1_3));

        // With zero TTL, all sessions are already expired.
        let removed = cache.cleanup_expired();
        assert_eq!(removed, 2);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cache_update_existing() {
        let mut cache = DtlsSessionCache::new(10, Duration::from_secs(3600));
        let addr = test_addr(5683);

        cache.insert(DtlsSession::new(vec![1], addr, DtlsVersion::V1_2));
        cache.insert(DtlsSession::new(vec![2], addr, DtlsVersion::V1_3));

        assert_eq!(cache.len(), 1);
        let session = cache.get(&addr).unwrap();
        assert_eq!(session.session_id(), &[2]);
        assert_eq!(session.protocol_version(), DtlsVersion::V1_3);
    }
}
