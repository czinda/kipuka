use kipuka::{
    audit::{self, AuditEvent, AuditEventType, AuditState},
    config::{AuditConfig, DbConfig, OverflowPolicy},
    db,
};

async fn database() -> (db::Db, db::DbKind) {
    let (pool, kind) = db::init_pool(&DbConfig::default(), "sqlite::memory:")
        .await
        .unwrap();
    db::run_migrations(&pool, kind).await.unwrap();
    (pool, kind)
}

#[tokio::test]
async fn production_read_pool_shares_in_memory_schema_and_transaction_rollback() {
    let (pool, kind) = database().await;
    let ro = db::init_ro_pool(&pool, &DbConfig::default(), kind, "sqlite::memory:")
        .await
        .unwrap();
    let mut tx = db::begin_write(&pool, kind).await.unwrap();
    sqlx::query("INSERT INTO audit_events (event_type) VALUES ('test')")
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
        .fetch_one(&ro)
        .await
        .unwrap();
    assert_eq!(count, 0);
    let mut tx = db::begin_write(&pool, kind).await.unwrap();
    sqlx::query("INSERT INTO audit_events (event_type) VALUES ('committed')")
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
        .fetch_one(&ro)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn audit_halt_and_drop_policies_bound_actual_storage() {
    let (pool, _) = database().await;
    let state = AuditState::with_config(AuditConfig {
        max_rows: Some(1),
        overflow_policy: OverflowPolicy::Halt,
        ..Default::default()
    });
    audit::record_checked(
        &pool,
        &state,
        AuditEvent::new(AuditEventType::EnrollRequest),
    )
    .await
    .unwrap();
    assert!(
        audit::record_checked(
            &pool,
            &state,
            AuditEvent::new(AuditEventType::EnrollRequest)
        )
        .await
        .is_err()
    );
    assert!(state.is_halted());
    let state = AuditState::with_config(AuditConfig {
        max_rows: Some(1),
        ..Default::default()
    });
    audit::record_checked(&pool, &state, AuditEvent::new(AuditEventType::CertIssue))
        .await
        .unwrap();
    let events: Vec<String> = sqlx::query_scalar("SELECT event_type FROM audit_events")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(events, ["cert.issue"]);
}

#[tokio::test]
async fn audit_storage_failure_and_security_alarm_halt_admission() {
    let (pool, _) = database().await;
    let state = AuditState::with_config(AuditConfig {
        alarm_threshold: 1,
        alarm_action: "halt".into(),
        ..Default::default()
    });
    audit::record_checked(
        &pool,
        &state,
        AuditEvent::new(AuditEventType::SecurityViolation),
    )
    .await
    .unwrap();
    assert!(state.is_halted());
    let state = AuditState::with_config(AuditConfig {
        overflow_policy: OverflowPolicy::Halt,
        ..Default::default()
    });
    sqlx::query("DROP TABLE audit_events")
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        audit::record_checked(
            &pool,
            &state,
            AuditEvent::new(AuditEventType::EnrollRequest)
        )
        .await
        .is_err()
    );
    assert!(state.is_halted());
}

#[tokio::test]
async fn star_restores_only_committed_progress_and_certificate() {
    let (pool, _) = database().await;
    let end = (chrono::Utc::now() + chrono::Duration::days(1)).to_rfc3339();
    sqlx::query("INSERT INTO star_orders (id, subject_dn, key_type, profile, renewal_interval_secs, lifetime_end, max_renewals, current_renewals, ca_id, csr_der) VALUES ('order-1', 'CN=example.test', 'ec:P-256', '{}', 3600, ?, 24, 1, 'ca-1', ?)")
        .bind(&end).bind(vec![1u8]).execute(&pool).await.unwrap();
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query("INSERT INTO star_certificates (star_order_id, serial_number, certificate_der, not_before, not_after, renewal_number) VALUES ('order-1', '1234', ?, ?, ?, 1)")
        .bind(vec![2u8]).bind(&now).bind(&end).execute(&pool).await.unwrap();
    let manager = kipuka::star::StarManager::new(kipuka::config::StarConfig::default());
    manager.restore(&pool).await.unwrap();
    let order = manager.get_order("order-1").unwrap();
    assert_eq!(order.current_renewals, 1);
    assert_eq!(order.renewal_interval.as_secs(), 3600);
    assert_eq!(
        manager
            .get_current_certificate("order-1")
            .unwrap()
            .certificate_der,
        vec![2]
    );
    sqlx::query("UPDATE star_orders SET status = 'cancelled' WHERE id = 'order-1'")
        .execute(&pool)
        .await
        .unwrap();
    manager.restore(&pool).await.unwrap();
    assert!(manager.orders_needing_renewal().is_empty());
    assert!(manager.get_current_certificate("order-1").is_err());
    // Upgrade an order prematurely completed by the old overlap budget.
    sqlx::query("UPDATE star_orders SET status = 'completed' WHERE id = 'order-1'")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE star_certificates SET not_after = ? WHERE star_order_id = 'order-1'")
        .bind((chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339())
        .execute(&pool)
        .await
        .unwrap();
    manager.restore(&pool).await.unwrap();
    assert_eq!(
        manager.get_order("order-1").unwrap().status,
        kipuka::star::StarOrderStatus::Active
    );
    let status: String = sqlx::query_scalar("SELECT status FROM star_orders WHERE id = 'order-1'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "active");
}

#[test]
fn readme_minimal_configuration_deserializes() {
    let readme = include_str!("../README.md");
    let section = readme.split("Minimal configuration").nth(1).unwrap();
    let snippet = section
        .split("```toml\n")
        .nth(1)
        .unwrap()
        .split("```")
        .next()
        .unwrap();
    let _: kipuka::config::Config = toml::from_str(snippet).unwrap();
}

#[test]
fn distributed_example_configuration_deserializes() {
    let _: kipuka::config::Config = toml::from_str(include_str!("../kipuka.toml.example")).unwrap();
}
