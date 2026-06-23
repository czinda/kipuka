//! Certificate Authority operations.
//!
//! This module handles CA initialization, certificate issuance, server-side
//! key generation, and the CA backend connection pool for HA routing.
//!
//! Implements:
//! - RFC 7030 §4.2 (simpleenroll/simplereenroll)
//! - RFC 7030 §4.4 (serverkeygen)
//! - CA/B Forum Baseline Requirements for validity and key constraints
//! - NIAP CA PP FCS_CKM.1 for key generation methods

pub mod init;
pub mod issue;
pub mod keygen;
pub mod pool;

pub use init::{CaInstance, CaInitError};
pub use issue::{IssuanceError, IssuanceResult};
pub use keygen::{KeyGenError, KeyGenResult, KeyType};
pub use pool::CaBackendPool;
