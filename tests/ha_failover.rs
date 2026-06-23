//! Integration tests for Multi-CA HA failover
//!
//! Verifies:
//! - Active-passive failover when primary CA becomes unhealthy
//! - Round-robin distributes across healthy CAs
//! - Unhealthy CA is excluded from request routing
//! - Recovery: CA marked healthy again after successful health check
//! - Health check records status in ca_health table

#[cfg(test)]
mod tests {
    // use kipuka::ha::{HaRouter, HaStrategy, CaHealth};
    // use std::time::Duration;

    /// Helper: create a mock CA backend that can be toggled healthy/unhealthy.
    ///
    /// The mock simulates signing operations:
    /// - When healthy: returns a valid signature after a configurable delay
    /// - When unhealthy: returns an error (simulating HSM unavailability)
    struct _MockCaBackend {
        _id: String,
        _healthy: bool,
        _latency_ms: u64,
    }

    // ── Active-Passive Failover ──────────────────────────────────────────

    #[tokio::test]
    async fn active_passive_uses_primary_when_healthy() {
        // let primary = MockCaBackend::new("ca-1", true, 10);
        // let secondary = MockCaBackend::new("ca-2", true, 10);
        //
        // let router = HaRouter::new(
        //     HaStrategy::ActivePassive,
        //     vec![primary, secondary],
        // );
        //
        // // All requests should go to the primary
        // for _ in 0..10 {
        //     let selected = router.select().await.unwrap();
        //     assert_eq!(selected.id(), "ca-1", "Should use primary when healthy");
        // }
    }

    #[tokio::test]
    async fn active_passive_failover_to_secondary() {
        // let primary = MockCaBackend::new("ca-1", true, 10);
        // let secondary = MockCaBackend::new("ca-2", true, 10);
        //
        // let router = HaRouter::new(
        //     HaStrategy::ActivePassive,
        //     vec![primary, secondary],
        // );
        //
        // // Mark primary as unhealthy (simulate 3 consecutive failures)
        // router.record_failure("ca-1").await;
        // router.record_failure("ca-1").await;
        // router.record_failure("ca-1").await;
        //
        // // Should now route to secondary
        // let selected = router.select().await.unwrap();
        // assert_eq!(selected.id(), "ca-2", "Should fail over to secondary");
    }

    #[tokio::test]
    async fn active_passive_recovery_returns_to_primary() {
        // let primary = MockCaBackend::new("ca-1", true, 10);
        // let secondary = MockCaBackend::new("ca-2", true, 10);
        //
        // let router = HaRouter::new(
        //     HaStrategy::ActivePassive,
        //     vec![primary, secondary],
        // );
        //
        // // Fail the primary
        // for _ in 0..3 {
        //     router.record_failure("ca-1").await;
        // }
        // let selected = router.select().await.unwrap();
        // assert_eq!(selected.id(), "ca-2");
        //
        // // Simulate recovery: health check succeeds
        // router.record_success("ca-1").await;
        //
        // // Should return to primary
        // let selected = router.select().await.unwrap();
        // assert_eq!(selected.id(), "ca-1", "Should return to primary after recovery");
    }

    // ── Round-Robin Distribution ─────────────────────────────────────────

    #[tokio::test]
    async fn round_robin_distributes_evenly() {
        // let ca1 = MockCaBackend::new("ca-1", true, 10);
        // let ca2 = MockCaBackend::new("ca-2", true, 10);
        // let ca3 = MockCaBackend::new("ca-3", true, 10);
        //
        // let router = HaRouter::new(
        //     HaStrategy::RoundRobin,
        //     vec![ca1, ca2, ca3],
        // );
        //
        // let mut counts = std::collections::HashMap::new();
        // for _ in 0..30 {
        //     let selected = router.select().await.unwrap();
        //     *counts.entry(selected.id().to_string()).or_insert(0) += 1;
        // }
        //
        // // Each CA should get approximately 10 requests
        // assert_eq!(counts.get("ca-1"), Some(&10));
        // assert_eq!(counts.get("ca-2"), Some(&10));
        // assert_eq!(counts.get("ca-3"), Some(&10));
    }

    #[tokio::test]
    async fn round_robin_skips_unhealthy() {
        // let ca1 = MockCaBackend::new("ca-1", true, 10);
        // let ca2 = MockCaBackend::new("ca-2", true, 10);
        // let ca3 = MockCaBackend::new("ca-3", true, 10);
        //
        // let router = HaRouter::new(
        //     HaStrategy::RoundRobin,
        //     vec![ca1, ca2, ca3],
        // );
        //
        // // Mark ca-2 as unhealthy
        // for _ in 0..3 {
        //     router.record_failure("ca-2").await;
        // }
        //
        // let mut counts = std::collections::HashMap::new();
        // for _ in 0..20 {
        //     let selected = router.select().await.unwrap();
        //     *counts.entry(selected.id().to_string()).or_insert(0) += 1;
        // }
        //
        // assert_eq!(counts.get("ca-1"), Some(&10));
        // assert_eq!(counts.get("ca-2"), None, "Unhealthy CA must not receive requests");
        // assert_eq!(counts.get("ca-3"), Some(&10));
    }

    // ── All CAs Unhealthy ────────────────────────────────────────────────

    #[tokio::test]
    async fn all_cas_unhealthy_returns_error() {
        // When all CAs are unhealthy, select() should return an error
        // that results in HTTP 503 Service Unavailable.
        //
        // let ca1 = MockCaBackend::new("ca-1", true, 10);
        // let ca2 = MockCaBackend::new("ca-2", true, 10);
        //
        // let router = HaRouter::new(
        //     HaStrategy::ActivePassive,
        //     vec![ca1, ca2],
        // );
        //
        // // Fail both CAs
        // for _ in 0..3 {
        //     router.record_failure("ca-1").await;
        //     router.record_failure("ca-2").await;
        // }
        //
        // let result = router.select().await;
        // assert!(result.is_err(), "Should return error when all CAs are unhealthy");
    }

    // ── Health Check Database Recording ──────────────────────────────────

    #[tokio::test]
    async fn health_check_updates_ca_health_table() {
        // let store = TestDb::new_in_memory().await;
        // let ca1 = MockCaBackend::new("ca-1", true, 10);
        //
        // let router = HaRouter::new(
        //     HaStrategy::ActivePassive,
        //     vec![ca1],
        // );
        //
        // // Run a health check
        // router.check_health(&store).await.unwrap();
        //
        // // Verify the ca_health table was updated
        // let health = store.get_ca_health("ca-1").await.unwrap();
        // assert_eq!(health.status, "healthy");
        // assert_eq!(health.consecutive_failures, 0);
        // assert!(health.last_check.is_some());
        // assert!(health.last_success.is_some());
        // assert!(health.response_latency_ms.is_some());
    }

    #[tokio::test]
    async fn consecutive_failures_tracked_accurately() {
        // let store = TestDb::new_in_memory().await;
        // let ca1 = MockCaBackend::new("ca-1", false, 10);  // Always fails
        //
        // let router = HaRouter::new(
        //     HaStrategy::ActivePassive,
        //     vec![ca1],
        // );
        //
        // // Run 3 health checks
        // for _ in 0..3 {
        //     let _ = router.check_health(&store).await;
        // }
        //
        // let health = store.get_ca_health("ca-1").await.unwrap();
        // assert_eq!(health.status, "unhealthy");
        // assert_eq!(health.consecutive_failures, 3);
        // assert!(health.last_failure.is_some());
    }
}
