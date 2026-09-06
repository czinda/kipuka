//! STAR (Short-Term Automatic Renewal) certificate management (RFC 8739).
//!
//! STAR issues short-lived certificates that auto-renew without client
//! interaction.  The server pre-generates renewal certificates before the
//! current one expires, so clients just fetch the latest.
//!
//! This is the server-side answer to the CA/B Forum 47-day certificate
//! validity mandate taking effect March 2029.

pub mod renewal;

use std::time::Duration;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Errors from STAR order and certificate operations.
///
/// Maps to the problem document types defined in RFC 8739 §3.4.
#[derive(Debug, Error)]
pub enum StarError {
    /// The requested STAR order does not exist.
    #[error("STAR order not found: {0}")]
    OrderNotFound(String),

    /// The STAR order has been cancelled by the subscriber or IdO.
    ///
    /// RFC 8739 §3.1.1: a cancelled order MUST NOT issue further certificates.
    #[error("STAR order cancelled: {0}")]
    OrderCancelled(String),

    /// The STAR order has exceeded its lifetime window.
    #[error("STAR order expired: {0}")]
    OrderExpired(String),

    /// The maximum number of renewals for this order has been reached.
    ///
    /// RFC 8739 §3.1: `auto-renewal-end-date` determines when renewals stop.
    #[error("STAR order {order_id} reached maximum renewals ({max})")]
    MaxRenewalsReached { order_id: String, max: u32 },

    /// The server has reached its maximum number of active STAR orders.
    ///
    /// This is a resource-exhaustion guard configured via `[star].max_active_orders`.
    #[error("maximum active STAR orders reached ({limit})")]
    MaxOrdersReached { limit: usize },

    /// The requested renewal interval is outside the configured bounds.
    ///
    /// RFC 8739 §3.1: the server advertises acceptable interval ranges.
    #[error("invalid renewal interval: {requested}s (allowed {min}s–{max}s)")]
    InvalidInterval { requested: u64, min: u64, max: u64 },

    /// Certificate issuance failed during renewal.
    #[error("issuance error: {0}")]
    IssuanceError(String),

    /// Database or storage operation failed.
    #[error("database error: {0}")]
    DatabaseError(String),
}

/// A certificate issued as part of a STAR renewal cycle.
///
/// Each renewal produces a new `StarCertificate` that replaces the previous
/// one.  Clients fetch the latest via the STAR certificate URL
/// (RFC 8739 §3.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarCertificate {
    /// DER-encoded X.509 certificate (current renewal).
    pub certificate_der: Vec<u8>,
    /// Serial number of this certificate (hex string).
    pub serial_number: String,
    /// Validity start (Not Before).
    pub not_before: DateTime<Utc>,
    /// Validity end (Not After).
    pub not_after: DateTime<Utc>,
    /// Which renewal produced this certificate (0 = initial).
    pub renewal_number: u32,
    /// Parent STAR order identifier.
    pub star_order_id: String,
}

/// Lifecycle status of a STAR order.
///
/// RFC 8739 §3.1.1 defines the order state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StarOrderStatus {
    /// The order is actively renewing certificates.
    Active,
    /// The subscriber or IdO cancelled the order; no further renewals.
    Cancelled,
    /// The current certificate covers the complete order lifetime.
    Completed,
    /// The order's `lifetime_end` has passed.
    Expired,
}

impl StarOrderStatus {
    /// Return a lowercase string representation for logging and API responses.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Cancelled => "cancelled",
            Self::Completed => "completed",
            Self::Expired => "expired",
        }
    }
}

/// A STAR order representing a recurring certificate renewal agreement.
///
/// RFC 8739 §3.1: the order captures the renewal interval, total lifetime,
/// subject identity, and the CA responsible for issuance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarOrder {
    /// Unique order identifier (UUID v4).
    pub id: String,
    /// Subject distinguished name for issued certificates.
    pub subject_dn: String,
    /// Key algorithm, e.g., `"ec:P-256"` or `"rsa:2048"`.
    pub key_type: String,
    /// Enrollment profile name (maps to `EnrollmentProfile`).
    pub profile: String,
    /// How often to renew the certificate.
    ///
    /// RFC 8739 §3.1: `auto-renewal-lifetime` in the order resource.
    #[serde(with = "humantime_serde")]
    pub renewal_interval: Duration,
    /// When the STAR order expires and no more renewals are issued.
    ///
    /// RFC 8739 §3.1: `auto-renewal-end-date`.
    pub lifetime_end: DateTime<Utc>,
    /// Maximum number of certificates this order will produce.
    pub max_renewals: u32,
    /// How many renewals have been issued so far.
    pub current_renewals: u32,
    /// Current lifecycle status.
    pub status: StarOrderStatus,
    /// DN of the entity that requested this order (from TLS client cert).
    pub requestor_dn: Option<String>,
    /// CA identifier that signs renewal certificates.
    pub ca_id: String,
    /// DER-encoded PKCS#10 CSR used for each renewal.
    pub csr_der: Vec<u8>,
    /// Most recently issued certificate (if any).
    pub current_certificate: Option<StarCertificate>,
    /// When the order was created.
    pub created_at: DateTime<Utc>,
    /// When the order was cancelled (only set for `Cancelled` status).
    pub cancelled_at: Option<DateTime<Utc>>,
}

/// Manages STAR orders and certificate renewal state.
///
/// `StarManager` is the server-side implementation of the STAR protocol
/// (RFC 8739).  It tracks active orders in a concurrent map and provides
/// methods for the renewal loop to query which orders need new certificates.
pub struct StarManager {
    /// Active STAR orders keyed by order ID.
    orders: DashMap<String, StarOrder>,
    operation_lock: tokio::sync::Mutex<()>,
    /// STAR subsystem configuration.
    config: crate::config::StarConfig,
}

impl StarManager {
    /// Serialize admission, cancellation and renewal across awaits.
    pub async fn operation_guard(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.operation_lock.lock().await
    }

    /// Restore committed orders and their latest certificates before serving requests.
    pub async fn restore(&self, db: &sqlx::AnyPool) -> Result<(), StarError> {
        use sqlx::Row;
        let rows = sqlx::query("SELECT id, subject_dn, key_type, profile, renewal_interval_secs, lifetime_end, max_renewals, current_renewals, CASE WHEN status = 'active' THEN 'active' WHEN status = 'completed' THEN 'completed' WHEN status = 'cancelled' THEN 'cancelled' ELSE 'expired' END AS status, requestor_dn, ca_id, csr_der, created_at, cancelled_at FROM star_orders").fetch_all(db).await.map_err(|e| StarError::DatabaseError(e.to_string()))?;
        let parse = |s: String| {
            DateTime::parse_from_rfc3339(&s)
                .map(|v| v.with_timezone(&Utc))
                .map_err(|e| StarError::DatabaseError(e.to_string()))
        };
        let mut restored = Vec::new();
        for row in rows {
            let get = |key: &str| {
                row.try_get::<String, _>(key)
                    .map_err(|e| StarError::DatabaseError(e.to_string()))
            };
            let num = |key: &str| {
                row.try_get::<i64, _>(key)
                    .map_err(|e| StarError::DatabaseError(e.to_string()))
            };
            let id = get("id")?;
            let status = match get("status")?.as_str() {
                "active" => StarOrderStatus::Active,
                "completed" => StarOrderStatus::Completed,
                "cancelled" => StarOrderStatus::Cancelled,
                "expired" => StarOrderStatus::Expired,
                _ => {
                    return Err(StarError::DatabaseError(
                        "invalid stored order status".into(),
                    ));
                }
            };
            let latest = sqlx::query(crate::db::pg_sql("SELECT serial_number, certificate_der, not_before, not_after, renewal_number FROM star_certificates WHERE star_order_id = ? ORDER BY renewal_number DESC LIMIT 1")).bind(&id).fetch_optional(db).await.map_err(|e| StarError::DatabaseError(e.to_string()))?;
            let certificate = if let Some(c) = latest {
                Some(StarCertificate {
                    serial_number: c
                        .try_get("serial_number")
                        .map_err(|e| StarError::DatabaseError(e.to_string()))?,
                    certificate_der: c
                        .try_get("certificate_der")
                        .map_err(|e| StarError::DatabaseError(e.to_string()))?,
                    not_before: parse(
                        c.try_get("not_before")
                            .map_err(|e| StarError::DatabaseError(e.to_string()))?,
                    )?,
                    not_after: parse(
                        c.try_get("not_after")
                            .map_err(|e| StarError::DatabaseError(e.to_string()))?,
                    )?,
                    renewal_number: c
                        .try_get::<i64, _>("renewal_number")
                        .map_err(|e| StarError::DatabaseError(e.to_string()))?
                        as u32,
                    star_order_id: id.clone(),
                })
            } else {
                None
            };
            let cancelled: Option<String> = row
                .try_get("cancelled_at")
                .map_err(|e| StarError::DatabaseError(e.to_string()))?;
            restored.push(StarOrder {
                id,
                subject_dn: get("subject_dn")?,
                key_type: get("key_type")?,
                profile: get("profile")?,
                renewal_interval: Duration::from_secs(num("renewal_interval_secs")? as u64),
                lifetime_end: parse(get("lifetime_end")?)?,
                max_renewals: num("max_renewals")? as u32,
                current_renewals: num("current_renewals")? as u32,
                status,
                requestor_dn: row
                    .try_get("requestor_dn")
                    .map_err(|e| StarError::DatabaseError(e.to_string()))?,
                ca_id: get("ca_id")?,
                csr_der: row
                    .try_get("csr_der")
                    .map_err(|e| StarError::DatabaseError(e.to_string()))?,
                created_at: parse(get("created_at")?)?,
                cancelled_at: cancelled.map(parse).transpose()?,
                current_certificate: certificate,
            });
        }
        self.orders.clear();
        for mut order in restored {
            if order.status == StarOrderStatus::Completed
                && order.lifetime_end > Utc::now()
                && order
                    .current_certificate
                    .as_ref()
                    .is_none_or(|cert| cert.not_after.timestamp() < order.lifetime_end.timestamp())
            {
                sqlx::query(crate::db::pg_sql("UPDATE star_orders SET status = 'active' WHERE id = ? AND status = 'completed'"))
                    .bind(&order.id).execute(db).await.map_err(|e| StarError::DatabaseError(e.to_string()))?;
                order.status = StarOrderStatus::Active;
            }
            self.orders.insert(order.id.clone(), order);
        }
        self.cleanup_expired();
        Ok(())
    }

    /// Remove a provisional admission after its database transaction fails.
    pub fn remove_order(&self, id: &str) {
        self.orders.remove(id);
    }

    /// Create a new `StarManager` with the given configuration.
    pub fn new(config: crate::config::StarConfig) -> Self {
        info!(
            min_interval = config.min_renewal_interval_secs,
            max_interval = config.max_renewal_interval_secs,
            max_orders = config.max_active_orders,
            pre_renewal = config.pre_renewal_factor,
            "STAR manager initialised"
        );
        Self {
            orders: DashMap::new(),
            operation_lock: tokio::sync::Mutex::new(()),
            config,
        }
    }

    /// Create a new STAR order.
    ///
    /// Validates the renewal interval against configured bounds, checks the
    /// active-order limit, and computes the total number of renewals from
    /// the requested lifetime.
    ///
    /// RFC 8739 §3.1: the server MUST validate `auto-renewal-lifetime` and
    /// `auto-renewal-end-date` against its policy before accepting the order.
    #[allow(clippy::too_many_arguments)]
    pub fn create_order(
        &self,
        subject_dn: String,
        key_type: String,
        profile: String,
        renewal_interval_secs: u64,
        lifetime_days: u32,
        ca_id: String,
        csr_der: Vec<u8>,
        requestor_dn: Option<String>,
    ) -> Result<StarOrder, StarError> {
        if lifetime_days == 0 || lifetime_days > self.config.max_lifetime_days {
            return Err(StarError::IssuanceError(
                "STAR lifetime is outside configured bounds".into(),
            ));
        }
        // Validate renewal interval against configured bounds.
        if renewal_interval_secs < self.config.min_renewal_interval_secs
            || renewal_interval_secs > self.config.max_renewal_interval_secs
        {
            warn!(
                requested = renewal_interval_secs,
                min = self.config.min_renewal_interval_secs,
                max = self.config.max_renewal_interval_secs,
                "STAR renewal interval out of bounds"
            );
            return Err(StarError::InvalidInterval {
                requested: renewal_interval_secs,
                min: self.config.min_renewal_interval_secs,
                max: self.config.max_renewal_interval_secs,
            });
        }

        // Check resource-exhaustion limit.
        let active_count = self.active_order_count();
        if active_count >= self.config.max_active_orders {
            warn!(
                active = active_count,
                limit = self.config.max_active_orders,
                "STAR order limit reached"
            );
            return Err(StarError::MaxOrdersReached {
                limit: self.config.max_active_orders,
            });
        }

        let now = Utc::now();
        let lifetime_end = now + chrono::Duration::days(i64::from(lifetime_days));
        let total_lifetime_secs = (lifetime_end - now).num_seconds().max(0) as u64;
        // Informational estimate includes overlap. Completion is governed by
        // certificate coverage of lifetime_end, never this estimate.
        let cadence = ((renewal_interval_secs as f64) * (1.0 - self.config.pre_renewal_factor))
            .floor()
            .max(1.0) as u64;
        let max_renewals = total_lifetime_secs
            .div_ceil(cadence)
            .saturating_add(1)
            .min(u32::MAX as u64) as u32;

        let id = Uuid::new_v4().to_string();
        let order = StarOrder {
            id: id.clone(),
            subject_dn: subject_dn.clone(),
            key_type,
            profile,
            renewal_interval: Duration::from_secs(renewal_interval_secs),
            lifetime_end,
            max_renewals,
            current_renewals: 0,
            status: StarOrderStatus::Active,
            requestor_dn,
            ca_id,
            csr_der,
            current_certificate: None,
            created_at: now,
            cancelled_at: None,
        };

        info!(
            order_id = %id,
            subject = %subject_dn,
            interval_secs = renewal_interval_secs,
            max_renewals = max_renewals,
            lifetime_end = %lifetime_end,
            "STAR order created"
        );

        self.orders.insert(id, order.clone());
        Ok(order)
    }

    /// Retrieve the current certificate for a STAR order.
    ///
    /// RFC 8739 §3.3: clients GET the STAR certificate URL to obtain
    /// the latest renewal.
    pub fn get_current_certificate(&self, star_id: &str) -> Result<StarCertificate, StarError> {
        let order = self
            .orders
            .get(star_id)
            .ok_or_else(|| StarError::OrderNotFound(star_id.to_owned()))?;

        if order.lifetime_end <= Utc::now() {
            return Err(StarError::OrderExpired(star_id.to_owned()));
        }

        match order.status {
            StarOrderStatus::Cancelled => {
                return Err(StarError::OrderCancelled(star_id.to_owned()));
            }
            StarOrderStatus::Expired => {
                return Err(StarError::OrderExpired(star_id.to_owned()));
            }
            StarOrderStatus::Active | StarOrderStatus::Completed => {}
        }

        order
            .current_certificate
            .clone()
            .ok_or_else(|| StarError::OrderNotFound(star_id.to_owned()))
    }

    /// Store a newly renewed certificate in the order.
    ///
    /// Increments the renewal counter and transitions the order to
    /// `Completed` once the certificate covers the complete order lifetime.
    pub fn store_renewed_certificate(
        &self,
        star_id: &str,
        cert: StarCertificate,
    ) -> Result<(), StarError> {
        let mut order = self
            .orders
            .get_mut(star_id)
            .ok_or_else(|| StarError::OrderNotFound(star_id.to_owned()))?;

        if order.status == StarOrderStatus::Cancelled {
            return Err(StarError::OrderCancelled(star_id.to_owned()));
        }
        if order.status == StarOrderStatus::Expired {
            return Err(StarError::OrderExpired(star_id.to_owned()));
        }

        order.current_renewals += 1;
        let renewal_num = order.current_renewals;

        debug!(
            order_id = %star_id,
            renewal = renewal_num,
            serial = %cert.serial_number,
            not_after = %cert.not_after,
            "stored renewed STAR certificate"
        );

        let covers_lifetime = cert.not_after.timestamp() >= order.lifetime_end.timestamp();
        order.current_certificate = Some(cert);

        if covers_lifetime {
            info!(
                order_id = %star_id,
                renewals = order.current_renewals,
                "STAR order completed (certificate covers lifetime)"
            );
            order.status = StarOrderStatus::Completed;
        }

        Ok(())
    }

    /// Cancel a STAR order.
    ///
    /// RFC 8739 §3.1.2: the subscriber or IdO may cancel an active order.
    /// After cancellation, no further certificates are issued.
    pub fn cancel_order(&self, star_id: &str) -> Result<(), StarError> {
        let mut order = self
            .orders
            .get_mut(star_id)
            .ok_or_else(|| StarError::OrderNotFound(star_id.to_owned()))?;

        if order.status != StarOrderStatus::Active {
            warn!(
                order_id = %star_id,
                status = order.status.as_str(),
                "cannot cancel non-active STAR order"
            );
            // Idempotent: cancelling an already-cancelled order is fine.
            if order.status == StarOrderStatus::Cancelled {
                return Ok(());
            }
        }

        info!(order_id = %star_id, "STAR order cancelled");
        order.status = StarOrderStatus::Cancelled;
        order.cancelled_at = Some(Utc::now());
        Ok(())
    }

    /// Remove orders whose `lifetime_end` has passed.
    ///
    /// Should be called periodically (e.g., from a background task) to
    /// reclaim memory.  Orders past their lifetime are marked `Expired`
    /// first, then removed entirely.
    ///
    /// Returns the number of orders that were cleaned up.
    pub fn cleanup_expired(&self) -> usize {
        let now = Utc::now();
        let mut expired_ids = Vec::new();

        for entry in self.orders.iter() {
            if entry.lifetime_end <= now {
                expired_ids.push(entry.id.clone());
            }
        }

        for id in &expired_ids {
            // Mark expired before removal so any concurrent reader sees the
            // terminal state rather than a vanished order.
            if let Some(mut order) = self.orders.get_mut(id)
                && order.status == StarOrderStatus::Active
            {
                order.status = StarOrderStatus::Expired;
            }
            self.orders.remove(id);
        }

        let count = expired_ids.len();
        if count > 0 {
            info!(count, "cleaned up expired STAR orders");
        }
        count
    }

    /// Count of currently active (not cancelled/completed/expired) orders.
    pub fn active_order_count(&self) -> usize {
        self.orders
            .iter()
            .filter(|e| e.status == StarOrderStatus::Active)
            .count()
    }

    /// Return order IDs that need a renewal certificate issued.
    ///
    /// An order needs renewal when:
    /// 1. Its status is `Active`.
    /// 2. It has not completed coverage of the order lifetime.
    /// 3. The current certificate's expiry minus the pre-renewal window
    ///    is in the past (or no certificate has been issued yet).
    ///
    /// The pre-renewal window is `renewal_interval * pre_renewal_factor`.
    /// For example, with a 24-hour interval and factor 0.5, renewal
    /// triggers when 12 hours remain on the current certificate.
    pub fn orders_needing_renewal(&self) -> Vec<String> {
        self.orders_needing_renewal_at(Utc::now())
    }

    fn orders_needing_renewal_at(&self, now: DateTime<Utc>) -> Vec<String> {
        let factor = self.config.pre_renewal_factor;
        let mut needs_renewal = Vec::new();

        for entry in self.orders.iter() {
            let order = entry.value();

            if order.status != StarOrderStatus::Active || order.lifetime_end <= now {
                continue;
            }

            let should_renew = match &order.current_certificate {
                None => {
                    // No certificate issued yet — renew immediately.
                    true
                }
                Some(cert) => {
                    // Renew when the remaining validity drops below the
                    // pre-renewal threshold.
                    let interval_secs = order.renewal_interval.as_secs() as f64;
                    let pre_renewal_secs = (interval_secs * factor) as i64;
                    let renewal_deadline =
                        cert.not_after - chrono::Duration::seconds(pre_renewal_secs);
                    now >= renewal_deadline
                }
            };

            if should_renew {
                needs_renewal.push(order.id.clone());
            }
        }

        debug!(
            count = needs_renewal.len(),
            total_active = self.active_order_count(),
            "scanned orders needing renewal"
        );

        needs_renewal
    }

    /// Retrieve a clone of a STAR order by ID.
    ///
    /// Returns `None` if the order does not exist.
    pub fn get_order(&self, star_id: &str) -> Option<StarOrder> {
        self.orders.get(star_id).map(|entry| entry.clone())
    }
}

/// Serde helper for `std::time::Duration` via `humantime`.
///
/// Serializes durations as human-readable strings (e.g., "24h", "7d")
/// and deserializes them back.  Used for the `renewal_interval` field
/// in `StarOrder`.
mod humantime_serde {
    use serde::{self, Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(duration.as_secs())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        Ok(Duration::from_secs(secs))
    }
}

#[cfg(test)]
mod review13_tests {
    use super::*;

    #[test]
    fn overlapping_renewals_cover_the_entire_order_lifetime() {
        for factor in [0.1, 0.5, 0.9] {
            let manager = StarManager::new(crate::config::StarConfig {
                pre_renewal_factor: factor,
                ..Default::default()
            });
            let order = manager
                .create_order(
                    "synthetic".into(),
                    "rsa".into(),
                    "{}".into(),
                    3600,
                    1,
                    "default".into(),
                    vec![],
                    None,
                )
                .unwrap();
            let mut start = order.created_at;
            let mut issued = 0;
            loop {
                let end = (start + chrono::Duration::hours(1)).min(order.lifetime_end);
                issued += 1;
                manager
                    .store_renewed_certificate(
                        &order.id,
                        StarCertificate {
                            certificate_der: vec![],
                            serial_number: issued.to_string(),
                            not_before: start,
                            not_after: end,
                            renewal_number: issued,
                            star_order_id: order.id.clone(),
                        },
                    )
                    .unwrap();
                if end >= order.lifetime_end {
                    assert_eq!(
                        manager.get_order(&order.id).unwrap().status,
                        StarOrderStatus::Completed
                    );
                    break;
                }
                start = end - chrono::Duration::seconds((3600.0 * factor) as i64);
                assert_eq!(
                    manager.orders_needing_renewal_at(start),
                    vec![order.id.clone()]
                );
                assert!(issued < 300, "renewal horizon must terminate");
            }
            assert!(
                issued > 24,
                "overlap requires more than 24 hourly certificates"
            );
            assert_eq!(
                manager
                    .get_current_certificate(&order.id)
                    .unwrap()
                    .not_after,
                order.lifetime_end
            );
        }
    }
}
