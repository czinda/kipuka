//! Multi-CA High Availability integration tests.
//!
//! Verifies:
//! - Request distribution across healthy CA backends
//! - Active-passive failover when primary CA becomes unhealthy
//! - Round-robin distribution across healthy CAs
//! - Recovery: CA transitions back to healthy after health check success
//! - Health check state transitions recorded in database
//! - All-CAs-unhealthy returns 503 Service Unavailable

#[allow(dead_code)]
mod common;

#[allow(unused_imports)]
use common::TestServer;

// ── Active-Passive Failover ─────────────────────────────────────────────────

/// Active-passive routes all requests to primary when healthy.
#[tokio::test]
#[ignore = "requires multi-CA configuration with HA manager"]
async fn active_passive_uses_primary_when_healthy() {
    // Setup: 2 CA backends (primary + secondary) with active-passive strategy
    //
    // let config = multi_ca_config("active-passive");
    // let server = TestServer::start_with_config(config).await;
    //
    // Verify: 10 consecutive requests all route to the primary CA
    //
    // for _ in 0..10 {
    //     let ca_id = server.state.ha_manager.unwrap().select().await.unwrap();
    //     assert_eq!(ca_id, "ca-primary");
    // }

    todo!("Implement once HA manager is fully wired");
}

/// Active-passive fails over to secondary when primary is unhealthy.
#[tokio::test]
#[ignore = "requires multi-CA configuration with HA manager"]
async fn active_passive_failover_to_secondary() {
    // Setup: mark primary as unhealthy (3 consecutive failures)
    //
    // let config = multi_ca_config("active-passive");
    // let server = TestServer::start_with_config(config).await;
    // let ha = server.state.ha_manager.as_ref().unwrap();
    //
    // // Simulate 3 failures on primary
    // for _ in 0..3 {
    //     ha.record_failure("ca-primary").await;
    // }
    //
    // // Verify failover
    // let selected = ha.select().await.unwrap();
    // assert_eq!(selected, "ca-secondary");

    todo!("Implement once HA manager is fully wired");
}

/// Active-passive returns to primary after recovery.
#[tokio::test]
#[ignore = "requires multi-CA configuration with HA manager"]
async fn active_passive_recovery_returns_to_primary() {
    // Setup: fail primary, verify failover, then simulate recovery
    //
    // let ha = server.state.ha_manager.as_ref().unwrap();
    //
    // // Fail primary
    // for _ in 0..3 {
    //     ha.record_failure("ca-primary").await;
    // }
    // assert_eq!(ha.select().await.unwrap(), "ca-secondary");
    //
    // // Recover primary
    // ha.record_success("ca-primary").await;
    //
    // // Should return to primary
    // assert_eq!(ha.select().await.unwrap(), "ca-primary");

    todo!("Implement once HA manager is fully wired");
}

// ── Round-Robin Distribution ────────────────────────────────────────────────

/// Round-robin distributes requests evenly across healthy CAs.
#[tokio::test]
#[ignore = "requires multi-CA configuration with HA manager"]
async fn round_robin_distributes_evenly() {
    // Setup: 3 CA backends with round-robin strategy
    //
    // let mut counts = std::collections::HashMap::new();
    // for _ in 0..30 {
    //     let ca_id = ha.select().await.unwrap();
    //     *counts.entry(ca_id).or_insert(0) += 1;
    // }
    //
    // assert_eq!(counts.get("ca-1"), Some(&10));
    // assert_eq!(counts.get("ca-2"), Some(&10));
    // assert_eq!(counts.get("ca-3"), Some(&10));

    todo!("Implement once HA manager is fully wired");
}

/// Round-robin skips unhealthy CAs.
#[tokio::test]
#[ignore = "requires multi-CA configuration with HA manager"]
async fn round_robin_skips_unhealthy() {
    // Setup: 3 CAs, mark ca-2 as unhealthy
    //
    // for _ in 0..3 {
    //     ha.record_failure("ca-2").await;
    // }
    //
    // let mut counts = std::collections::HashMap::new();
    // for _ in 0..20 {
    //     let ca_id = ha.select().await.unwrap();
    //     *counts.entry(ca_id).or_insert(0) += 1;
    // }
    //
    // assert_eq!(counts.get("ca-1"), Some(&10));
    // assert_eq!(counts.get("ca-2"), None);
    // assert_eq!(counts.get("ca-3"), Some(&10));

    todo!("Implement once HA manager is fully wired");
}

// ── All CAs Unhealthy ───────────────────────────────────────────────────────

/// When all CAs are unhealthy, enrollment returns 503.
#[tokio::test]
#[ignore = "requires multi-CA configuration with HA manager"]
async fn all_cas_unhealthy_returns_503() {
    // Setup: fail all CAs
    //
    // for ca_id in ["ca-1", "ca-2"] {
    //     for _ in 0..3 {
    //         ha.record_failure(ca_id).await;
    //     }
    // }
    //
    // // Attempt enrollment
    // let (csr_der, _) = generate_test_csr("ha-test.test", "rsa:2048");
    // let resp = client.est_post_csr("simpleenroll", &csr_der, Some(("", otp))).await;
    //
    // assert_eq!(resp.status(), 503);
    //
    // // RFC 7030 S4.2.3: 503 should include Retry-After
    // assert!(resp.headers().get("retry-after").is_some());

    todo!("Implement once HA manager is fully wired");
}

// ── Health Check Database Recording ─────────────────────────────────────────

/// Health checks update the ca_health table.
#[tokio::test]
#[ignore = "requires multi-CA configuration with health check DB recording"]
async fn health_check_updates_db() {
    // Setup: run a health check cycle
    //
    // ha.check_health(&server.state.db).await.unwrap();
    //
    // // Verify ca_health table
    // let row: (String, String, i32) = sqlx::query_as(
    //     "SELECT ca_id, status, consecutive_failures FROM ca_health WHERE ca_id = ?"
    // )
    //     .bind("ca-primary")
    //     .fetch_one(&server.state.db)
    //     .await
    //     .unwrap();
    //
    // assert_eq!(row.0, "ca-primary");
    // assert_eq!(row.1, "healthy");
    // assert_eq!(row.2, 0);

    todo!("Implement once HA health check DB recording is wired");
}

/// Consecutive failures are tracked accurately in the database.
#[tokio::test]
#[ignore = "requires multi-CA configuration with health check DB recording"]
async fn consecutive_failures_tracked() {
    // Setup: fail a CA 5 times, verify counter in DB
    //
    // for _ in 0..5 {
    //     ha.record_failure("ca-primary").await;
    // }
    //
    // let row: (String, i32) = sqlx::query_as(
    //     "SELECT status, consecutive_failures FROM ca_health WHERE ca_id = ?"
    // )
    //     .bind("ca-primary")
    //     .fetch_one(&server.state.db)
    //     .await
    //     .unwrap();
    //
    // assert_eq!(row.0, "unhealthy");
    // assert_eq!(row.1, 5);

    todo!("Implement once HA health check DB recording is wired");
}

// ── Health State Transitions ────────────────────────────────────────────────

/// Verify the full state machine: healthy → degraded → unhealthy → healthy.
#[tokio::test]
#[ignore = "requires multi-CA configuration with HA manager"]
async fn health_state_transitions() {
    // The HA manager should track these state transitions:
    //
    // Initial state: healthy (0 failures)
    // After 1 failure: healthy (1 failure, below threshold)
    // After 2 failures: degraded (if configured) or still healthy
    // After 3 failures: unhealthy (default failure_threshold = 3)
    // After 1 success: healthy (reset)
    //
    // Each transition should:
    // 1. Update the in-memory state
    // 2. Record an audit event (AuditEventType::CaHealthChange)
    // 3. Update the ca_health table

    todo!("Implement once HA state machine is fully wired");
}
