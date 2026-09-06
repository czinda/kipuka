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
/// The returned [`tokio::task::JoinHandle`] can be used to abort the task during
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

    let _guard = star_manager.operation_guard().await;
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
        let validity_secs = order.renewal_interval.as_secs();
        let mut profile: EnrollmentProfile = match serde_json::from_str(&order.profile) {
            Ok(profile) => profile,
            Err(error) => {
                warn!(order_id = %id, %error, "STAR order lacks persisted authorization policy");
                failed += 1;
                continue;
            }
        };
        profile.max_validity_seconds = Some(validity_secs);
        profile.max_not_after = Some(order.lifetime_end);
        if let Err(error) = crate::audit::record_checked(
            db,
            audit,
            AuditEvent::new(AuditEventType::EnrollRequest)
                .with_ca_id(&order.ca_id)
                .with_detail(format!("STAR renewal for {id}")),
        )
        .await
        {
            warn!(%error, "STAR renewal rejected by audit policy");
            failed += 1;
            continue;
        }

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
            ca.ocsp_url.as_deref(),
            ca.crl_url.as_deref(),
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

                let issuer_dn = match synta_certificate::Certificate::from_der(&ca.cert_der) {
                    Ok(parsed) => synta_certificate::format_dn(parsed.tbs_certificate.subject.0),
                    Err(error) => {
                        warn!(%error, "cannot parse STAR issuer");
                        failed += 1;
                        continue;
                    }
                };
                // Commit inventory, renewal and order progress atomically before publication.
                if let Err(error) =
                    persist_renewal(db, &order, &cert, &issuer_dn, &profile.name, audit).await
                {
                    error!(order_id = %id, %error, "STAR renewal transaction failed");
                    failed += 1;
                    continue;
                }
                if let Err(error) = star_manager.store_renewed_certificate(id, cert.clone()) {
                    error!(order_id = %id, %error, "committed STAR renewal could not be published");
                    failed += 1;
                    continue;
                }

                info!(
                    order_id = %id,
                    serial = %result.serial_number,
                    renewal = order.current_renewals + 1,
                    validity_secs,
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

/// Commit one renewal with compare-and-set progress to prevent duplicate publication.
async fn persist_renewal(
    db: &sqlx::AnyPool,
    order: &crate::star::StarOrder,
    cert: &StarCertificate,
    issuer_dn: &str,
    profile_name: &str,
    audit: &AuditState,
) -> Result<(), crate::error::KipukaError> {
    let mut tx = db.begin().await?;
    let sql = if cert.not_after.timestamp() >= order.lifetime_end.timestamp() {
        "UPDATE star_orders SET current_renewals = ?, status = 'completed' WHERE id = ? AND current_renewals = ? AND status = 'active'"
    } else {
        "UPDATE star_orders SET current_renewals = ?, status = 'active' WHERE id = ? AND current_renewals = ? AND status = 'active'"
    };
    let updated = sqlx::query(crate::db::pg_sql(sql))
        .bind(cert.renewal_number as i64)
        .bind(&order.id)
        .bind(order.current_renewals as i64)
        .execute(&mut *tx)
        .await?;
    if updated.rows_affected() != 1 {
        return Err(sqlx::Error::RowNotFound.into());
    }
    sqlx::query(crate::db::pg_sql(
        "INSERT INTO star_certificates (star_order_id, serial_number, certificate_der, not_before, not_after, renewal_number) VALUES (?, ?, ?, ?, ?, ?)"))
        .bind(&order.id).bind(&cert.serial_number).bind(&cert.certificate_der)
        .bind(cert.not_before.to_rfc3339()).bind(cert.not_after.to_rfc3339())
        .bind(cert.renewal_number as i64).execute(&mut *tx).await?;
    sqlx::query(crate::db::pg_sql(
        "INSERT INTO certificates (serial, subject_dn, issuer_dn, not_before, not_after, der_encoded, ca_id, profile, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active')"))
        .bind(&cert.serial_number).bind(&order.subject_dn).bind(issuer_dn)
        .bind(cert.not_before.to_rfc3339()).bind(cert.not_after.to_rfc3339())
        .bind(&cert.certificate_der).bind(&order.ca_id).bind(profile_name)
        .execute(&mut *tx).await?;
    crate::audit::record_issuance_in_transaction(
        &mut tx,
        audit,
        &order.ca_id,
        format!(
            "STAR renewal #{} for order {}, serial={}",
            cert.renewal_number, order.id, cert.serial_number
        ),
    )
    .await?;
    crate::audit::commit_issuance(tx, audit).await?;
    Ok(())
}
