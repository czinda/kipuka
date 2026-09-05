//! Exercise the production HTTP router, OTP authentication and durable STAR lifecycle.
#[allow(dead_code)]
mod common;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tower::ServiceExt;

#[tokio::test]
async fn star_http_issuance_renewal_restart_and_owner_cancellation() {
    let ca = common::TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("ca.key");
    std::fs::write(&key, &ca.key_pem).unwrap();
    let mut config = common::test_config();
    config.cas[0].key_file = key.to_str().unwrap().into();
    config.star = Some(kipuka::config::StarConfig {
        enabled: true,
        default_renewal_interval_secs: 3600,
        ..Default::default()
    });
    let config = Arc::new(config);
    let (db, kind) = kipuka::db::init_pool(&config.database, "sqlite::memory:")
        .await
        .unwrap();
    kipuka::db::run_migrations(&db, kind).await.unwrap();
    let mut cas = indexmap::IndexMap::new();
    cas.insert("default".into(), Arc::new(ca.to_ca_state("default")));
    let manager = Arc::new(kipuka::star::StarManager::new(config.star.clone().unwrap()));
    let secrets = Arc::new(
        kipuka::config::SecretResolver::new()
            .resolve_config(&config)
            .unwrap(),
    );
    let state = Arc::new(
        kipuka::state::AppStateBuilder::new()
            .config(config.clone())
            .secrets(secrets)
            .audit(Arc::new(kipuka::audit::AuditState::with_config(
                config.audit.clone(),
            )))
            .db(db.clone())
            .db_ro(db.clone())
            .db_kind(kind)
            .cas(cas)
            .default_ca_id("default".into())
            .star_manager(manager.clone())
            .build(),
    );
    for identity in ["owner", "other"] {
        sqlx::query(
            "INSERT INTO otp_tokens (token_hash,entity_id,max_uses,expires_at) VALUES (?,?,10,?)",
        )
        .bind(hex::encode(Sha256::digest(b"synthetic-token")))
        .bind(identity)
        .bind((chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339())
        .execute(&db)
        .await
        .unwrap();
    }
    let router = kipuka::routes::build_router(state.clone());
    let (csr, _) = common::generate_test_csr("CN=star.example.test", "rsa:2048");
    let auth = |identity: &str| {
        format!(
            "Basic {}",
            STANDARD.encode(format!("{identity}:synthetic-token"))
        )
    };
    let response = router
        .clone()
        .oneshot(
            Request::post("/.well-known/est/star")
                .header("authorization", auth("owner"))
                .header("content-type", "application/pkcs10")
                .header("star-renewal-interval", "3600")
                .header("star-lifetime", "1")
                .body(Body::from(STANDARD.encode(csr)))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let id = response
        .headers()
        .get("star-order-id")
        .map(|h| h.to_str().unwrap().to_string());
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    assert_eq!(
        status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    let id = id.unwrap();
    let der = STANDARD
        .decode(
            bytes
                .iter()
                .copied()
                .filter(|b| !b.is_ascii_whitespace())
                .collect::<Vec<_>>(),
        )
        .unwrap();
    let p7 = openssl::pkcs7::Pkcs7::from_der(&der).unwrap();
    let cert = &p7.signed().unwrap().certificates().unwrap()[0];
    assert_eq!(cert.not_before().diff(cert.not_after()).unwrap().secs, 3600);
    assert!(
        cert.verify(
            &openssl::x509::X509::from_der(&ca.cert_der)
                .unwrap()
                .public_key()
                .unwrap()
        )
        .unwrap()
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM certificates")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(count, 1);
    let restored = Arc::new(kipuka::star::StarManager::new(config.star.clone().unwrap()));
    restored.restore(&db).await.unwrap();
    assert_eq!(restored.get_order(&id).unwrap().current_renewals, 1);
    // Make renewal due in durable storage, then run the same worker startup uses.
    sqlx::query("UPDATE star_certificates SET not_after = ? WHERE star_order_id = ?")
        .bind(chrono::Utc::now().to_rfc3339())
        .bind(&id)
        .execute(&db)
        .await
        .unwrap();
    restored.restore(&db).await.unwrap();
    let worker = kipuka::star::renewal::spawn_renewal_task(
        restored.clone(),
        db.clone(),
        state.cas.clone(),
        Arc::new(config.cas.clone()),
        None,
        state.audit.clone(),
    )
    .await;
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if restored.get_order(&id).unwrap().current_renewals == 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    worker.abort();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM certificates")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(count, 2);
    let profiles: Vec<String> = sqlx::query_scalar("SELECT profile FROM certificates")
        .fetch_all(&db)
        .await
        .unwrap();
    assert!(profiles.iter().all(|profile| profile == "default"));

    // Admission consumes the final available audit row: the worker must not
    // publish, persist inventory, or advance the order without its issue record.
    sqlx::query("UPDATE star_certificates SET not_after = ? WHERE star_order_id = ?")
        .bind(chrono::Utc::now().to_rfc3339())
        .bind(&id)
        .execute(&db)
        .await
        .unwrap();
    restored.restore(&db).await.unwrap();
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
        .fetch_one(&db)
        .await
        .unwrap();
    let full_audit = Arc::new(kipuka::audit::AuditState::with_config(
        kipuka::config::AuditConfig {
            max_rows: Some((rows + 1) as u64),
            overflow_policy: kipuka::config::OverflowPolicy::Halt,
            ..Default::default()
        },
    ));
    let blocked_worker = kipuka::star::renewal::spawn_renewal_task(
        restored.clone(),
        db.clone(),
        state.cas.clone(),
        Arc::new(config.cas.clone()),
        None,
        full_audit.clone(),
    )
    .await;
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while !full_audit.is_halted() {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    blocked_worker.abort();
    assert_eq!(restored.get_order(&id).unwrap().current_renewals, 2);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM certificates")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(count, 2);
    let count: i64 = sqlx::query_scalar("SELECT current_renewals FROM star_orders WHERE id = ?")
        .bind(&id)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(count, 2);
    // The same audit-capacity failure must roll back initial issuance too.
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
        .fetch_one(&db)
        .await
        .unwrap();
    let mut blocked_state = (*state).clone();
    blocked_state.audit = Arc::new(kipuka::audit::AuditState::with_config(
        kipuka::config::AuditConfig {
            max_rows: Some((rows + 1) as u64),
            overflow_policy: kipuka::config::OverflowPolicy::Halt,
            ..Default::default()
        },
    ));
    let blocked_state = Arc::new(blocked_state);
    let (csr, _) = common::generate_test_csr("CN=star-blocked.example.test", "rsa:2048");
    let mut owner = kipuka::auth::AuthResult::anonymous();
    owner.identity = "owner".into();
    let result = kipuka::routes::star::post_star_order(
        kipuka::auth::EstAuth(owner),
        kipuka::routes::LabelExtractor::resolve(&blocked_state, None).unwrap(),
        axum::extract::State(blocked_state.clone()),
        Default::default(),
        STANDARD.encode(csr).into(),
    )
    .await;
    assert!(result.is_err());
    assert!(blocked_state.audit.is_halted());
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM certificates")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(count, 2);
    let orders: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM star_orders")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(orders, 1);
    assert_eq!(manager.active_order_count(), 1);
    manager.restore(&db).await.unwrap();
    let response = router
        .clone()
        .oneshot(
            Request::delete(format!("/.well-known/est/star/{id}"))
                .header("authorization", auth("other"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = router
        .clone()
        .oneshot(
            Request::delete(format!("/.well-known/est/star/{id}"))
                .header("authorization", auth("owner"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    restored.restore(&db).await.unwrap();
    assert!(restored.orders_needing_renewal().is_empty());
    let response = router
        .oneshot(
            Request::get(format!("/.well-known/est/star/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::GONE);
}
