//! The runner's KeyPackage pool at the host (task-content §4.1, spec §2.7).
//!
//! At least [`ONE_TIME_TARGET`] one-time KeyPackages are kept at the host,
//! topped up when the host reports fewer than [`ONE_TIME_LOW`], plus one
//! current last-resort KeyPackage, replaced when the host holds none or when
//! less than 28 of its 84 days of lifetime remain. One upload is in flight at a
//! time: a status that does not answer it never triggers a publication.

use chrono::{DateTime, TimeDelta, Utc};
use gino_e2ee::{Identity, KeyPackageStore, encode_b64url};

use crate::protocol::frames::{E2eeKeyPackageStatusData, E2eeKeyPackagesData};

/// One-time KeyPackages the runner keeps at the host.
pub(crate) const ONE_TIME_TARGET: u64 = 10;
/// The host count below which the pool is topped up.
pub(crate) const ONE_TIME_LOW: u64 = 5;
/// KeyPackage lifetime (spec §2.7, the OpenMLS default): 84 days.
const LIFETIME: TimeDelta = TimeDelta::seconds(7_257_600);
/// A last-resort KeyPackage is replaced when less than this remains.
const MIN_REMAINING: TimeDelta = TimeDelta::days(28);

/// What a publication generates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Plan {
    pub(crate) one_time: u64,
    pub(crate) last_resort: bool,
}

impl Plan {
    /// The first publication of a runner without KeyPackage state.
    pub(crate) const INITIAL: Self = Self {
        one_time: ONE_TIME_TARGET,
        last_resort: true,
    };

    pub(crate) fn is_empty(self) -> bool {
        self.one_time == 0 && !self.last_resort
    }
}

/// Whether the last-resort KeyPackage generated at `created_at` must be
/// replaced at `now` (or none was ever generated).
pub(crate) fn last_resort_due(created_at: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    created_at.is_none_or(|created| created + (LIFETIME - MIN_REMAINING) <= now)
}

/// The publication a host status calls for.
pub(crate) fn plan_for_status(
    status: &E2eeKeyPackageStatusData,
    last_resort_created_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Plan {
    Plan {
        one_time: if status.one_time < ONE_TIME_LOW {
            ONE_TIME_TARGET - status.one_time
        } else {
            0
        },
        last_resort: !status.last_resort || last_resort_due(last_resort_created_at, now),
    }
}

/// The KeyPackage private keys and the publication state.
pub(crate) struct KeyPackagePool {
    pub(crate) store: KeyPackageStore,
    pub(crate) last_resort_created_at: Option<DateTime<Utc>>,
    /// `outboxId` of the upload the host has not answered yet.
    pub(crate) pending: Option<String>,
}

impl std::fmt::Debug for KeyPackagePool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPackagePool")
            .field("last_resort_created_at", &self.last_resort_created_at)
            .field("pending", &self.pending)
            .finish_non_exhaustive()
    }
}

impl KeyPackagePool {
    pub(crate) fn new(
        store: KeyPackageStore,
        last_resort_created_at: Option<DateTime<Utc>>,
    ) -> Self {
        Self {
            store,
            last_resort_created_at,
            pending: None,
        }
    }

    /// Settle a host status against the in-flight upload and return the
    /// publication it calls for. `unacked(id)` tells whether upload `id` is
    /// still waiting for its outbox ack.
    ///
    /// The answer to the in-flight upload clears it; when that answer
    /// rejected anything, nothing is published until the next status, so a
    /// refusal (for example `key_changed`) never loops. Any other status may
    /// predate the upload (the socket-open status is sent before the host
    /// reads it, yet can be handled after its ack) and is ignored. While the
    /// upload is unacked its answer is still to come; once acked, a status
    /// without its answer means the answer was lost or is still queued behind
    /// it, so the upload is settled and the next status decides.
    pub(crate) fn on_status(
        &mut self,
        id: Option<&str>,
        status: &E2eeKeyPackageStatusData,
        unacked: impl FnOnce(&str) -> bool,
        now: DateTime<Utc>,
    ) -> Plan {
        if let Some(pending) = self.pending.as_deref() {
            if id == Some(pending) {
                self.pending = None;
                if !status.rejected.is_empty() {
                    return Plan::default();
                }
            } else {
                if !unacked(pending) {
                    self.pending = None;
                }
                return Plan::default();
            }
        }
        plan_for_status(status, self.last_resort_created_at, now)
    }

    /// The periodic check: a due last-resort replacement, unless an upload
    /// is in flight.
    pub(crate) fn on_tick(&self, now: DateTime<Utc>) -> Plan {
        Plan {
            one_time: 0,
            last_resort: self.pending.is_none()
                && last_resort_due(self.last_resort_created_at, now),
        }
    }

    /// Generate the KeyPackages of `plan` into the store and return the
    /// upload payload. The caller persists the store before enqueueing it.
    pub(crate) fn generate(
        &self,
        identity: &Identity,
        plan: Plan,
    ) -> Result<E2eeKeyPackagesData, gino_e2ee::Error> {
        let one_time = (0..plan.one_time)
            .map(|_| {
                self.store
                    .generate(identity, false)
                    .map(|kp| encode_b64url(&kp))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let last_resort = plan
            .last_resort
            .then(|| {
                self.store
                    .generate(identity, true)
                    .map(|kp| encode_b64url(&kp))
            })
            .transpose()?;
        Ok(E2eeKeyPackagesData {
            one_time: (!one_time.is_empty()).then_some(one_time),
            last_resort,
        })
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, TimeDelta, Utc};
    use gino_e2ee::{Identity, KeyPackageStore, decode_b64url};

    use super::{KeyPackagePool, Plan, last_resort_due, plan_for_status};
    use crate::protocol::frames::{E2eeKeyPackageStatusData, KeyPackageRejection};

    fn at(days: i64) -> DateTime<Utc> {
        DateTime::<Utc>::UNIX_EPOCH + TimeDelta::days(1000 + days)
    }

    fn status(one_time: u64, last_resort: bool) -> E2eeKeyPackageStatusData {
        E2eeKeyPackageStatusData {
            one_time,
            last_resort,
            rejected: Vec::new(),
        }
    }

    #[test]
    fn last_resort_is_replaced_with_less_than_28_days_left() {
        assert!(last_resort_due(None, at(0)));
        assert!(!last_resort_due(Some(at(0)), at(55)));
        assert!(last_resort_due(Some(at(0)), at(56)));
        assert!(last_resort_due(Some(at(0)), at(90)));
    }

    #[test]
    fn status_tops_up_below_five_to_ten() {
        let fresh = Some(at(0));
        let now = at(1);
        assert_eq!(
            plan_for_status(&status(10, true), fresh, now),
            Plan::default()
        );
        assert_eq!(
            plan_for_status(&status(5, true), fresh, now),
            Plan::default()
        );
        assert_eq!(
            plan_for_status(&status(4, true), fresh, now),
            Plan {
                one_time: 6,
                last_resort: false
            }
        );
        assert_eq!(
            plan_for_status(&status(0, false), fresh, now),
            Plan::INITIAL
        );
        assert_eq!(
            plan_for_status(&status(7, true), fresh, at(60)),
            Plan {
                one_time: 0,
                last_resort: true
            }
        );
    }

    fn pool() -> KeyPackagePool {
        KeyPackagePool::new(KeyPackageStore::new(), Some(at(0)))
    }

    #[test]
    fn only_the_answer_or_a_later_status_follows_an_upload() {
        let mut pool = pool();
        pool.pending = Some("up-1".to_owned());
        // Socket-open status while the upload is still unacked: wait.
        assert_eq!(
            pool.on_status(None, &status(0, true), |_| true, at(1)),
            Plan::default()
        );
        assert_eq!(pool.pending.as_deref(), Some("up-1"));
        // Acked, the answer still queued behind a stale status: settle the
        // upload without acting on that status.
        assert_eq!(
            pool.on_status(None, &status(0, false), |_| false, at(1)),
            Plan::default()
        );
        assert_eq!(pool.pending, None);
        // The late answer is then an ordinary, current status.
        assert_eq!(
            pool.on_status(Some("up-1"), &status(10, true), |_| false, at(1)),
            Plan::default()
        );
        // The next status decides.
        assert_eq!(
            pool.on_status(None, &status(2, true), |_| false, at(1))
                .one_time,
            8
        );
    }

    #[test]
    fn the_answer_clears_the_upload_and_a_rejection_waits_for_the_next_status() {
        let mut pool = pool();
        pool.pending = Some("up-1".to_owned());
        assert_eq!(
            pool.on_status(Some("up-1"), &status(10, true), |_| true, at(1)),
            Plan::default()
        );
        assert_eq!(pool.pending, None);

        pool.pending = Some("up-2".to_owned());
        let rejected = E2eeKeyPackageStatusData {
            one_time: 0,
            last_resort: false,
            rejected: vec![KeyPackageRejection {
                code: "key_changed".to_owned(),
                index: Some(0),
            }],
        };
        assert_eq!(
            pool.on_status(Some("up-2"), &rejected, |_| panic!("not consulted"), at(1)),
            Plan::default()
        );
        assert_eq!(pool.pending, None);
        // The next status retries.
        assert_eq!(
            pool.on_status(None, &status(0, false), |_| false, at(1)),
            Plan::INITIAL
        );
    }

    #[test]
    fn tick_replaces_a_stale_last_resort_only_when_idle() {
        let mut pool = pool();
        assert!(pool.on_tick(at(10)).is_empty());
        assert_eq!(
            pool.on_tick(at(57)),
            Plan {
                one_time: 0,
                last_resort: true
            }
        );
        pool.pending = Some("up-1".to_owned());
        assert!(pool.on_tick(at(57)).is_empty());
    }

    #[test]
    fn generate_produces_key_packages_and_keeps_their_private_keys() {
        let identity = Identity::from_seed(&[3; 32]);
        let pool = pool();
        let data = pool.generate(&identity, Plan::INITIAL).unwrap();
        let one_time = data.one_time.unwrap();
        assert_eq!(one_time.len(), 10);
        assert!(one_time.iter().all(|kp| decode_b64url(kp).is_ok()));
        assert!(data.last_resort.is_some());
        // The snapshot carries the private keys: it grows with each generate
        // and survives a restore.
        let snapshot = pool.store.snapshot().unwrap();
        let restored = KeyPackageStore::restore(&snapshot).unwrap();
        assert_eq!(restored.snapshot().unwrap(), snapshot);
        let only_last_resort = pool
            .generate(
                &identity,
                Plan {
                    one_time: 0,
                    last_resort: true,
                },
            )
            .unwrap();
        assert_eq!(only_last_resort.one_time, None);
        assert!(pool.store.snapshot().unwrap().len() > snapshot.len());
    }
}
