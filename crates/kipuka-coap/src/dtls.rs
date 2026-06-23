//! DTLS session management for EST-coaps transport security.
//!
//! RFC 9483 §5 mandates DTLS to secure all EST-coaps exchanges. This module
//! provides session tracking and caching abstractions that a concrete DTLS
//! implementation (e.g., OpenSSL, mbedTLS, or `rustls` with DTLS support)
//! would integrate with.
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
    /// Returns `None` if no client certificate was presented or if the
    /// certificate cannot be parsed.
    pub fn client_cert_info(&self) -> Option<ClientCertInfo> {
        let der = self.client_cert.as_ref()?;
        // In production, this would parse the DER certificate to extract
        // the subject DN and serial number. For now, return the raw bytes.
        Some(ClientCertInfo {
            subject_dn: String::new(),
            serial: Vec::new(),
            der_bytes: der.clone(),
        })
    }
}

/// Client certificate information extracted from a DTLS handshake.
///
/// Used to identify the enrolling client for EST operations that require
/// mTLS authentication (simpleenroll, simplereenroll, serverkeygen).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCertInfo {
    /// Subject distinguished name (RFC 4514 string form).
    ///
    /// Empty if the DN could not be parsed from the DER certificate.
    pub subject_dn: String,
    /// Certificate serial number (big-endian unsigned integer).
    pub serial: Vec<u8>,
    /// Full DER-encoded certificate.
    pub der_bytes: Vec<u8>,
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
            if self.sessions.len() >= self.max_sessions {
                if let Some(oldest_addr) = self.oldest_session_addr() {
                    self.sessions.remove(&oldest_addr);
                }
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
        if let Some(session) = self.sessions.get(peer_addr) {
            if session.is_expired(self.ttl) {
                self.sessions.remove(peer_addr);
                return None;
            }
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
    fn test_session_with_client_cert() {
        let addr = test_addr(5683);
        let cert_der = vec![0x30, 0x82, 0x01, 0x00];
        let session =
            DtlsSession::with_client_cert(vec![1, 2, 3], addr, DtlsVersion::V1_2, cert_der.clone());

        assert_eq!(session.client_cert(), Some(cert_der.as_slice()));
        assert!(session.client_cert_info().is_some());
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
