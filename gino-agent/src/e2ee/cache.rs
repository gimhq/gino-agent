//! The per-task epoch-secret cache (spec §7.6), kept in `e2ee_key_cache`
//! sealed at rest. The group state works on the in-memory copy; changed
//! epochs are written back with [`DbKeyCache::flush`].

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use gino_e2ee::{CachedSecrets, KeyCache};

use super::groups::StoreError;
use super::keys::AtRestKey;
use super::lock;
use crate::db::{Db, DbResult, E2eeKeyCacheRow};

/// The at-rest label of one cached epoch.
fn label(task_id: &str, epoch: u64) -> String {
    format!("e2ee_key_cache:{task_id}:{epoch}")
}

/// One task's cached epoch secrets and the epochs not yet written back.
#[derive(Debug, Default)]
pub(super) struct DbKeyCache {
    entries: BTreeMap<u64, CachedSecrets>,
    dirty: Mutex<BTreeSet<u64>>,
}

impl DbKeyCache {
    /// The cached epochs of `task_id`. A row that does not open or parse is
    /// skipped (the walk rebuilds it).
    pub(super) fn load(db: &Db, at_rest: &AtRestKey, task_id: &str) -> DbResult<Self> {
        let mut entries = BTreeMap::new();
        for (epoch, row) in db.list_e2ee_key_cache(task_id)? {
            let Ok(epoch) = u64::try_from(epoch) else {
                continue;
            };
            let secrets = at_rest
                .open(&label(task_id, epoch), &row.secrets)
                .ok()
                .and_then(|bytes| CachedSecrets::from_bytes(&bytes).ok());
            if let Some(secrets) = secrets {
                entries.insert(epoch, secrets);
            }
        }
        Ok(Self {
            entries,
            dirty: Mutex::new(BTreeSet::new()),
        })
    }

    /// Write the changed epochs of `task_id` back, sealed. On failure they
    /// stay marked for the next flush.
    pub(super) fn flush(
        &self,
        db: &Db,
        at_rest: &AtRestKey,
        task_id: &str,
    ) -> Result<(), StoreError> {
        let dirty = std::mem::take(&mut *lock(&self.dirty));
        let written = self.write(db, at_rest, task_id, &dirty);
        if written.is_err() {
            lock(&self.dirty).extend(dirty);
        }
        written
    }

    fn write(
        &self,
        db: &Db,
        at_rest: &AtRestKey,
        task_id: &str,
        epochs: &BTreeSet<u64>,
    ) -> Result<(), StoreError> {
        for &epoch in epochs {
            let column = i64::try_from(epoch).map_err(|_| StoreError::Encode)?;
            match self.entries.get(&epoch) {
                Some(cached) => {
                    let sealed = at_rest.seal(&label(task_id, epoch), &cached.to_bytes())?;
                    let row = E2eeKeyCacheRow {
                        secrets: sealed,
                        verified: cached.verified,
                    };
                    db.put_e2ee_key_cache(task_id, column, &row)?;
                }
                None => db.delete_e2ee_key_cache(task_id, column)?,
            }
        }
        Ok(())
    }
}

impl KeyCache for DbKeyCache {
    fn get(&self, epoch: u64) -> Option<CachedSecrets> {
        self.entries.get(&epoch).cloned()
    }

    fn put(&mut self, epoch: u64, secrets: CachedSecrets) {
        if self.entries.get(&epoch) != Some(&secrets) {
            self.entries.insert(epoch, secrets);
            self.dirty
                .get_mut()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(epoch);
        }
    }

    fn remove(&mut self, epoch: u64) {
        if self.entries.remove(&epoch).is_some() {
            self.dirty
                .get_mut()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(epoch);
        }
    }
}
