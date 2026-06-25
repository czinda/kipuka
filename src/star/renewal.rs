//! Background renewal task for STAR certificates (RFC 8739).
//!
//! Spawns a tokio task that checks every 60 seconds for STAR orders
//! with certificates approaching expiry.  When a certificate needs
//! renewal, the task pre-generates the next certificate in the series
//! via the CA subsystem and stores it for client retrieval.
//!
//! The renewal threshold is configurable via `pre_renewal_factor` in
//! `[star]` config.  For example, with a 24-hour interval and factor
//! 0.5, renewal happens when 12 hours remain on the current certificate.
//!
//! Failures are handled gracefully — a failed renewal is retried on the
//! next 60-second cycle.  The task respects `max_renewals` limits and
//! marks orders as `Completed` when the series is exhausted.

use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, error, info, warn};

use crate::audit::{AuditEvent, AuditEventType, AuditState};
use crate::ca::issue::{self, EnrollmentProfile};
use crate::config::CaConfig;
use crate::star::{StarCertificate, StarManager, StarOrderStatus};
use crate::state::CaState;

/// Spawn the background STAR certificate renewal task.
///
/// The returned [`JoinHandle`] can be used to abort the task during
/// graceful shutdown.  The task runs indefinitely, ticking every 60
/// seconds.
///
/// # Arguments
///
/// * `star_manager` - Shared STAR order manager
/// * `db` - Database pool for persisting renewed certificates
/// * `cas` - Map of CA states keyed by CA identifier
/// * `ca_configs` - CA configurations for key material access
/// * `hsm` - Optional HSM context for HSM-backed signing
/// * `audit` - Shared audit state for event recording
pub async fn spawn_renewal_task(
    star_manager: Arc<StarManager>,
    db: sqlx::AnyPool,
    cas: Arc<indexmap::IndexMap<String, Arc<CaState>>>,
    ca_configs: Arc<Vec<CaConfig>>,
    hsm: Option<Arc<kipuka_hsm::HsmContext>>,
    audit: Arc<AuditState>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));

        loop {
            interval.tick().await;
            renewal_cycle(&star_manager, &db, &cas, &ca_configs, hsm.as_ref(), &audit).await;
        }
    })
}

/// Execute a single renewal cycle: cleanup, then renew.
async fn renewal_cycle(
    star_manager: &StarManager,
    db: &sqlx::AnyPool,
    cas: &indexmap::IndexMap<String, Arc<CaState>>,
    ca_configs: &[CaConfig],
    hsm: Option<&Arc<kipuka_hsm::HsmContext>>,
    audit: &AuditState,
) {
    let span = tracing::info_span!("star_renewal_cycle");
    let _enter = span.enter();

    // Phase 1: Remove expired orders.
    let expired_count = star_manager.cleanup_expired();

    // Phase 2: Find orders that need renewal.
    let order_ids = star_manager.orders_needing_renewal();
    if order_ids.is_empty() && expired_count == 0 {
        debug!("no STAR orders need attention");
        return;
    }

    let mut renewed = 0u32;
    let mut failed = 0u32;

    // Phase 3: Renew each eligible order.
    for id in &order_ids {
        let order = match star_manager.get_order(id) {
            Some(o) => o,
            None => {
                debug!(order_id = %id, "order disappeared before renewal");
                continue;
            }
        };

        if order.status != StarOrderStatus::Active {
            debug!(
                order_id = %id,
                status = ?order.status,
                "skipping non-active order"
            );
            continue;
        }

        // Look up the issuing CA.
        let ca = match cas.get(&order.ca_id) {
            Some(ca) => ca,
            None => {
                warn!(
                    order_id = %id,
                    ca_id = %order.ca_id,
                    "CA not found for STAR order — skipping"
                );
                failed += 1;
                continue;
            }
        };

        // Build an enrollment profile scoped to this renewal interval.
        let validity_days = (order.renewal_interval.as_secs() as u32 / 86400).max(1);
        let profile = EnrollmentProfile {
            max_validity_days: validity_days,
            ..EnrollmentProfile::default()
        };

        // Resolve key material — HSM-backed or PEM from disk.
        let ca_cfg = match ca_configs.iter().find(|c| c.id == order.ca_id) {
            Some(cfg) => cfg,
            None => {
                warn!(
                    order_id = %id,
                    ca_id = %order.ca_id,
                    "CA config not found for STAR renewal — skipping"
                );
                failed += 1;
                continue;
            }
        };

        let resolved_key = match issue::resolve_signing_key_sync(ca_cfg, hsm) {
            Ok(k) => k,
            Err(e) => {
                warn!(
                    order_id = %id,
                    ca_id = %order.ca_id,
                    error = %e,
                    "failed to resolve signing key for STAR renewal — skipping"
                );
                failed += 1;
                continue;
            }
        };

        // Issue the renewed certificate.
        match issue::issue_certificate(
            &order.csr_der,
            &profile,
            &ca.cert_der,
            resolved_key.as_signing_key(),
            &ca.hash_algorithm,
        ) {
            Ok(result) => {
                let cert = StarCertificate {
                    serial_number: result.serial_number.clone(),
                    certificate_der: result.certificate_der.clone(),
                    not_before: result.not_before,
                    not_after: result.not_after,
                    renewal_number: order.current_renewals + 1,
                    star_order_id: id.clone(),
                };

                // Store the renewed certificate in the manager.
                if let Err(e) = star_manager.store_renewed_certificate(id, cert.clone()) {
                    warn!(
                        order_id = %id,
                        error = %e,
                        "failed to store renewed certificate in manager"
                    );
                    failed += 1;
                    continue;
                }

                // Persist to the database.
                if let Err(e) = persist_certificate(db, id, &cert).await {
                    error!(
                        order_id = %id,
                        serial = %cert.serial_number,
                        error = %e,
                        "failed to persist renewed certificate to database"
                    );
                    // Don't fail the renewal — the in-memory state is
                    // already updated.  The DB will catch up on the next
                    // successful write or via a reconciliation pass.
                }

                // Update the renewal counter in the database.
                if let Err(e) = update_renewal_count(db, id, order.current_renewals + 1).await {
                    error!(
                        order_id = %id,
                        error = %e,
                        "failed to update renewal count in database"
                    );
                }

                // Record the audit event.
                crate::audit::record(
                    db,
                    audit,
                    AuditEvent::new(AuditEventType::CertIssue)
                        .with_ca_id(&order.ca_id)
                        .with_detail(format!(
                            "STAR renewal #{} for order {id}, serial={}, validity={validity_days}d",
                            order.current_renewals + 1,
                            result.serial_number,
                        )),
                )
                .await;

                info!(
                    order_id = %id,
                    serial = %result.serial_number,
                    renewal = order.current_renewals + 1,
                    validity_days,
                    "STAR certificate renewed"
                );
                renewed += 1;
            }
            Err(e) => {
                warn!(
                    order_id = %id,
                    ca_id = %order.ca_id,
                    error = %e,
                    "STAR certificate issuance failed — will retry next cycle"
                );
                failed += 1;
            }
        }
    }

    info!(
        renewed,
        failed,
        expired = expired_count,
        "STAR renewal cycle complete"
    );
}

/// Insert a renewed certificate into the `star_certificates` table.
async fn persist_certificate(
    db: &sqlx::AnyPool,
    order_id: &str,
    cert: &StarCertificate,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO star_certificates \
         (star_order_id, serial_number, certificate_der, not_before, not_after, renewal_number) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(order_id)
    .bind(&cert.serial_number)
    .bind(&cert.certificate_der)
    .bind(cert.not_before.to_rfc3339())
    .bind(cert.not_after.to_rfc3339())
    .bind(cert.renewal_number as i64)
    .execute(db)
    .await?;

    Ok(())
}

/// Update the current renewal count on a STAR order row.
async fn update_renewal_count(
    db: &sqlx::AnyPool,
    order_id: &str,
    count: u32,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE star_orders SET current_renewals = ? WHERE id = ?")
        .bind(count as i64)
        .bind(order_id)
        .execute(db)
        .await?;

    Ok(())
}
