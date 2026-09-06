//! HA pool behavior; this is not a live remote-backend interoperability test.
use kipuka::ha::pool::{CircuitBreakerConfig, PoolConfig};
use kipuka::ha::{CaConnection, CaId, CaPool, FailoverStrategy, FallbackBehavior};
use std::time::Duration;

fn pool(strategy: FailoverStrategy) -> CaPool {
    CaPool::new(
        (0..3)
            .map(|n| CaConnection {
                id: CaId(format!("ca-{n}")),
                endpoint: format!("https://ca-{n}.example.test"),
                weight: 1,
                priority: n,
            })
            .collect(),
        PoolConfig {
            strategy,
            fallback: FallbackBehavior::Reject,
            circuit_breaker: CircuitBreakerConfig {
                failure_threshold: 2,
                cooldown: Duration::from_secs(1),
            },
        },
    )
}

#[test]
fn active_passive_failure_and_recovery() {
    let pool = pool(FailoverStrategy::ActivePassive);
    assert_eq!(pool.select().unwrap().id.0, "ca-0");
    pool.record_failure(&CaId("ca-0".into()));
    pool.record_failure(&CaId("ca-0".into()));
    assert_eq!(pool.select().unwrap().id.0, "ca-1");
    pool.record_success(&CaId("ca-0".into()), Duration::from_millis(4));
    assert_eq!(pool.select().unwrap().id.0, "ca-0");
}

#[test]
fn round_robin_excludes_failed_and_unauthorized_issuers() {
    let pool = pool(FailoverStrategy::RoundRobin);
    let allowed = vec!["ca-1".to_owned(), "ca-2".to_owned()];
    let selected: Vec<_> = (0..4)
        .map(|_| pool.select_allowed(&allowed).unwrap().id.0)
        .collect();
    assert_eq!(selected, ["ca-1", "ca-2", "ca-1", "ca-2"]);
    pool.record_failure(&CaId("ca-1".into()));
    pool.record_failure(&CaId("ca-1".into()));
    for _ in 0..4 {
        assert_eq!(pool.select_allowed(&allowed).unwrap().id.0, "ca-2");
    }
    assert!(pool.select_allowed(&[]).is_none());
}

#[test]
fn all_failed_rejects_without_unauthorized_fallback() {
    let pool = pool(FailoverStrategy::ActivePassive);
    let allowed = vec!["ca-1".to_owned()];
    pool.record_failure(&CaId("ca-1".into()));
    pool.record_failure(&CaId("ca-1".into()));
    assert!(pool.select_allowed(&allowed).is_none());
    assert!(pool.select().is_some());
}
