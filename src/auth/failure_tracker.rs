//! Authentication failure tracking and account lockout (NIAP CA PP FIA_AFL.1).
//!
//! FIA_AFL.1 requires the TSF to detect when a configurable number of
//! unsuccessful authentication attempts occur for an authentication event and,
//! on reaching that threshold, take a defined action.  Kipuka's action is a
//! time-boxed lockout: once an identity accumulates `max_failures` failures
//! within `failure_window`, further attempts are refused for
//! `lockout_duration` regardless of whether the presented credential is valid.
//!
//! # Keying
//!
//! The tracker keys on the **claimed identity** (e.g. the HTTP Basic username /
//! OTP entity-id), never on a client-supplied network address.  An attacker
//! can spoof `X-Forwarded-For` at will, so mixing it into the lockout key would
//! let them both evade their own lockout and lock out arbitrary victims.  The
//! claimed identity is the value FIA_AFL.1 is written against ("the user") and
//! is known even when authentication fails, so it is the correct key.
//!
//! # Concurrency and memory
//!
//! State is a single `parking_lot::Mutex<HashMap<..>>`.  Records are pruned
//! opportunistically and capped at 10,000 identities. At capacity, existing
//! counters and lockouts are retained; new identities continue through credential
//! verification without acquiring a tracker entry until capacity becomes available.
//! Capacity exhaustion must never lock out unrelated valid credentials.
//!
//! # Disabled mode
//!
//! `max_failures == 0` disables the control entirely — every call returns
//! [`LockoutStatus::Allowed`] and no state is retained.  This preserves the
//! behavior of deployments that have not opted in.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

/// Lockout policy parameters (from `[auth_lockout]` config).
#[derive(Debug, Clone, Copy)]
pub struct LockoutPolicy {
    /// Consecutive failures within `failure_window` that trigger a lockout.
    /// `0` disables the control.
    pub max_failures: u32,
    /// Sliding window over which failures are counted.  A gap longer than
    /// this resets the counter.
    pub failure_window: Duration,
    /// How long an identity stays locked out once the threshold is reached.
    pub lockout_duration: Duration,
}

impl LockoutPolicy {
    /// Whether the lockout control is active.
    pub fn is_enabled(&self) -> bool {
        self.max_failures > 0
    }
}

/// Outcome of a lockout check or a recorded failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockoutStatus {
    /// Authentication may proceed.
    Allowed,
    /// The identity is locked out; retry after the given duration.
    LockedOut {
        /// Time remaining until the lockout expires.
        retry_after: Duration,
    },
}

impl LockoutStatus {
    /// Whether this status denies the attempt.
    pub fn is_locked(&self) -> bool {
        matches!(self, LockoutStatus::LockedOut { .. })
    }
}

/// Per-identity failure bookkeeping.
struct Record {
    /// Failures counted in the current window.
    failures: u32,
    /// Start of the current failure window.
    window_start: Instant,
    /// When an active lockout expires, if any.
    locked_until: Option<Instant>,
}

impl Record {
    /// Whether this record can be dropped at `now` (not locked, window stale).
    fn is_prunable(&self, now: Instant, window: Duration) -> bool {
        let lock_expired = self.locked_until.is_none_or(|until| now >= until);
        let window_stale = now.duration_since(self.window_start) >= window;
        lock_expired && window_stale
    }
}

/// Tracks authentication failures and enforces FIA_AFL.1 lockout.
pub struct FailureTracker {
    policy: LockoutPolicy,
    records: Mutex<HashMap<String, Record>>,
    last_prune: Mutex<Instant>,
}

impl FailureTracker {
    /// Create a tracker with the given policy.
    pub fn new(policy: LockoutPolicy) -> Self {
        Self {
            policy,
            records: Mutex::new(HashMap::new()),
            last_prune: Mutex::new(Instant::now() - Duration::from_secs(1)),
        }
    }

    /// The active policy.
    pub fn policy(&self) -> &LockoutPolicy {
        &self.policy
    }

    /// Check whether `identity` is currently locked out, without recording an
    /// attempt.  Call this before validating a credential.
    pub fn check(&self, identity: &str) -> LockoutStatus {
        if !self.policy.is_enabled() {
            return LockoutStatus::Allowed;
        }
        let now = Instant::now();
        let mut records = self.records.lock();
        if records.len() >= 10_000 {
            let mut last = self.last_prune.lock();
            if now.duration_since(*last) >= Duration::from_secs(1).min(self.policy.failure_window) {
                self.prune(&mut records, now);
                *last = now;
            }
        }
        if identity.len() > 4096 {
            return LockoutStatus::LockedOut {
                retry_after: Duration::from_secs(1),
            };
        }
        Self::status_at(records.get(identity), now).unwrap_or_else(|| {
            // Not locked — opportunistically prune this entry if stale.
            if let Some(rec) = records.get(identity)
                && rec.is_prunable(now, self.policy.failure_window)
            {
                records.remove(identity);
            }
            LockoutStatus::Allowed
        })
    }

    /// Record a failed authentication attempt for `identity` and return the
    /// resulting status.  A return of [`LockoutStatus::LockedOut`] means this
    /// failure reached (or was already past) the threshold — the caller should
    /// emit the FIA_AFL security-violation audit event.
    pub fn record_failure(&self, identity: &str) -> LockoutStatus {
        if !self.policy.is_enabled() {
            return LockoutStatus::Allowed;
        }
        let now = Instant::now();
        let mut records = self.records.lock();
        let mut last = self.last_prune.lock();
        if now.duration_since(*last) >= Duration::from_secs(1).min(self.policy.failure_window) {
            self.prune(&mut records, now);
            *last = now;
        }
        if identity.len() > 4096 {
            return LockoutStatus::LockedOut {
                retry_after: Duration::from_secs(1),
            };
        }
        if records.len() >= 10_000 && !records.contains_key(identity) {
            // The credential has already failed verification. Skipping a new
            // tracker entry bounds memory without denying unrelated valid users
            // or evicting active targeted lockouts and pending counters.
            return LockoutStatus::Allowed;
        }

        let rec = records.entry(identity.to_string()).or_insert(Record {
            failures: 0,
            window_start: now,
            locked_until: None,
        });

        // Already locked and still within the lockout: report remaining time.
        if let Some(until) = rec.locked_until
            && now < until
        {
            return LockoutStatus::LockedOut {
                retry_after: until.duration_since(now),
            };
        }

        // Start a fresh window when the previous one has elapsed, or when a
        // prior lockout has since expired.  Without the lockout-expiry reset, a
        // deployment whose `lockout_duration` is shorter than `failure_window`
        // would re-lock an identity on the very first attempt after the lockout
        // ends — the stale failure count is still at the threshold and the
        // window has not yet aged out — instead of granting a fresh set of
        // attempts.  (Execution only reaches here once any active lockout has
        // expired, since a live lockout returns early above.)
        let window_elapsed = now.duration_since(rec.window_start) >= self.policy.failure_window;
        let lockout_expired = rec.locked_until.is_some_and(|until| now >= until);
        if window_elapsed || lockout_expired {
            rec.failures = 0;
            rec.window_start = now;
            rec.locked_until = None;
        }

        rec.failures += 1;

        if rec.failures >= self.policy.max_failures {
            let until = now + self.policy.lockout_duration;
            rec.locked_until = Some(until);
            LockoutStatus::LockedOut {
                retry_after: self.policy.lockout_duration,
            }
        } else {
            LockoutStatus::Allowed
        }
    }

    /// Record a successful authentication for `identity`, clearing its failure
    /// state.  A success does not lift an active lockout — the credential is
    /// still refused until the lockout expires — so we only drop the record
    /// when it is not currently locked.
    pub fn record_success(&self, identity: &str) {
        if !self.policy.is_enabled() {
            return;
        }
        let now = Instant::now();
        let mut records = self.records.lock();
        if let Some(rec) = records.get(identity) {
            let locked = rec.locked_until.is_some_and(|until| now < until);
            if !locked {
                records.remove(identity);
            }
        }
    }

    /// Compute the lockout status for an existing record at `now`, or `None`
    /// when the identity is not locked.
    fn status_at(rec: Option<&Record>, now: Instant) -> Option<LockoutStatus> {
        let rec = rec?;
        match rec.locked_until {
            Some(until) if now < until => Some(LockoutStatus::LockedOut {
                retry_after: until.duration_since(now),
            }),
            _ => None,
        }
    }

    /// Drop records that are neither locked nor within their failure window.
    fn prune(&self, records: &mut HashMap<String, Record>, now: Instant) {
        records.retain(|_, rec| !rec.is_prunable(now, self.policy.failure_window));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(max: u32) -> LockoutPolicy {
        LockoutPolicy {
            max_failures: max,
            failure_window: Duration::from_secs(60),
            lockout_duration: Duration::from_secs(300),
        }
    }

    #[test]
    fn disabled_policy_never_locks() {
        let t = FailureTracker::new(policy(0));
        for _ in 0..100 {
            assert_eq!(t.record_failure("bob"), LockoutStatus::Allowed);
        }
        assert_eq!(t.check("bob"), LockoutStatus::Allowed);
    }

    #[test]
    fn locks_after_threshold() {
        let t = FailureTracker::new(policy(3));
        assert_eq!(t.record_failure("bob"), LockoutStatus::Allowed);
        assert_eq!(t.record_failure("bob"), LockoutStatus::Allowed);
        // Third failure hits the threshold.
        assert!(t.record_failure("bob").is_locked());
        // Subsequent check reports locked.
        assert!(t.check("bob").is_locked());
    }

    #[test]
    fn other_identities_unaffected() {
        let t = FailureTracker::new(policy(2));
        assert!(t.record_failure("bob").is_locked() || t.record_failure("bob").is_locked());
        // A different identity is independent.
        assert_eq!(t.check("alice"), LockoutStatus::Allowed);
        assert_eq!(t.record_failure("alice"), LockoutStatus::Allowed);
    }

    #[test]
    fn success_clears_failures_before_lockout() {
        let t = FailureTracker::new(policy(3));
        t.record_failure("bob");
        t.record_failure("bob");
        // Success resets the counter, so the next two failures do not lock.
        t.record_success("bob");
        assert_eq!(t.record_failure("bob"), LockoutStatus::Allowed);
        assert_eq!(t.record_failure("bob"), LockoutStatus::Allowed);
        assert!(!t.check("bob").is_locked());
    }

    #[test]
    fn success_does_not_lift_active_lockout() {
        let t = FailureTracker::new(policy(2));
        t.record_failure("bob");
        assert!(t.record_failure("bob").is_locked());
        // A late success (e.g. a racing valid attempt) must not unlock.
        t.record_success("bob");
        assert!(t.check("bob").is_locked());
    }

    #[test]
    fn window_reset_allows_slow_failures() {
        // Tight window so failures age out immediately.
        let pol = LockoutPolicy {
            max_failures: 2,
            failure_window: Duration::from_millis(1),
            lockout_duration: Duration::from_secs(300),
        };
        let t = FailureTracker::new(pol);
        assert_eq!(t.record_failure("bob"), LockoutStatus::Allowed);
        std::thread::sleep(Duration::from_millis(3));
        // Window elapsed — counter resets, so this is failure #1 again.
        assert_eq!(t.record_failure("bob"), LockoutStatus::Allowed);
    }

    #[test]
    fn lockout_expires() {
        let pol = LockoutPolicy {
            max_failures: 1,
            failure_window: Duration::from_secs(60),
            lockout_duration: Duration::from_millis(5),
        };
        let t = FailureTracker::new(pol);
        assert!(t.record_failure("bob").is_locked());
        assert!(t.check("bob").is_locked());
        std::thread::sleep(Duration::from_millis(8));
        // Lockout has expired.
        assert_eq!(t.check("bob"), LockoutStatus::Allowed);
    }

    #[test]
    fn expired_lockout_starts_fresh_window() {
        // Misconfiguration guard: lockout shorter than the failure window.
        // After the lockout expires, the first failure must not immediately
        // re-lock — the identity gets a fresh count within the open window.
        let pol = LockoutPolicy {
            max_failures: 2,
            failure_window: Duration::from_secs(60),
            lockout_duration: Duration::from_millis(5),
        };
        let t = FailureTracker::new(pol);
        assert_eq!(t.record_failure("bob"), LockoutStatus::Allowed);
        assert!(t.record_failure("bob").is_locked());
        std::thread::sleep(Duration::from_millis(8));
        // Lockout expired but the 60s window has not: a fresh count, not a re-lock.
        assert_eq!(t.record_failure("bob"), LockoutStatus::Allowed);
    }

    #[test]
    fn prunes_stale_records() {
        let pol = LockoutPolicy {
            max_failures: 5,
            failure_window: Duration::from_millis(1),
            lockout_duration: Duration::from_secs(300),
        };
        let t = FailureTracker::new(pol);
        t.record_failure("ephemeral");
        std::thread::sleep(Duration::from_millis(3));
        // A mutating call for another identity prunes the stale entry.
        t.record_failure("other");
        assert!(!t.records.lock().contains_key("ephemeral"));
    }
}

#[cfg(test)]
mod capacity_tests {
    use super::*;

    #[test]
    fn saturation_preserves_access_and_existing_targeted_lockouts() {
        let tracker = FailureTracker::new(LockoutPolicy {
            max_failures: 2,
            failure_window: Duration::from_secs(300),
            lockout_duration: Duration::from_secs(900),
        });
        tracker.record_failure("target");
        for i in 1..10_000 {
            tracker.record_failure(&format!("invented-{i}"));
        }
        assert_eq!(tracker.check("valid-user"), LockoutStatus::Allowed);
        assert_eq!(tracker.record_failure("overflow"), LockoutStatus::Allowed);
        assert_eq!(tracker.records.lock().len(), 10_000);
        assert!(tracker.record_failure("target").is_locked());
        assert!(tracker.check("target").is_locked());
        tracker.record_success("target");
        assert!(tracker.check("target").is_locked());
        // Clearing an unlocked record admits new failure tracking again.
        tracker.record_success("invented-1");
        tracker.record_failure("overflow");
        assert!(tracker.record_failure("overflow").is_locked());
        assert_eq!(tracker.records.lock().len(), 10_000);
    }
}
