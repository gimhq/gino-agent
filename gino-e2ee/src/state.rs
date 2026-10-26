//! Persistence of MLS state: opaque snapshots of the OpenMLS in-memory
//! key-value store and a per-scope byte store the host implements.

use std::collections::{BTreeMap, HashMap};

use openmls_rust_crypto::MemoryStorage;

use crate::GroupError;

/// Opaque snapshot bytes keyed by an id (a scope id, or a name the caller
/// picks for its KeyPackage store). Implementations persist them encrypted
/// at rest; every state-changing operation is followed by a save.
pub trait StateStore {
    /// The stored snapshot of `id`.
    fn load(&self, id: &str) -> Result<Option<Vec<u8>>, GroupError>;
    /// Stores the snapshot of `id`, replacing any previous one.
    fn save(&mut self, id: &str, snapshot: Vec<u8>) -> Result<(), GroupError>;
    /// Removes the snapshot of `id`.
    fn delete(&mut self, id: &str) -> Result<(), GroupError>;
}

/// An in-memory [`StateStore`].
#[derive(Debug, Clone, Default)]
pub struct MemoryStateStore {
    snapshots: BTreeMap<String, Vec<u8>>,
}

impl StateStore for MemoryStateStore {
    fn load(&self, id: &str) -> Result<Option<Vec<u8>>, GroupError> {
        Ok(self.snapshots.get(id).cloned())
    }

    fn save(&mut self, id: &str, snapshot: Vec<u8>) -> Result<(), GroupError> {
        self.snapshots.insert(id.to_owned(), snapshot);
        Ok(())
    }

    fn delete(&mut self, id: &str) -> Result<(), GroupError> {
        self.snapshots.remove(id);
        Ok(())
    }
}

/// Every key-value record of `storage`, sorted by key, as length-prefixed
/// `key || value` pairs.
pub(crate) fn snapshot_storage(storage: &MemoryStorage) -> Result<Vec<u8>, GroupError> {
    let values = storage.values.read().map_err(|_| GroupError::Storage)?;
    let mut entries: Vec<_> = values.iter().collect();
    entries.sort();
    let mut writer = Writer::default();
    for (key, value) in entries {
        writer.bytes(key)?;
        writer.bytes(value)?;
    }
    Ok(writer.finish())
}

/// Replaces the records of `storage` with those of a snapshot.
pub(crate) fn restore_storage(storage: &MemoryStorage, snapshot: &[u8]) -> Result<(), GroupError> {
    let mut reader = Reader::new(snapshot);
    let mut records = HashMap::new();
    while !reader.is_empty() {
        let key = reader.bytes()?;
        records.insert(key, reader.bytes()?);
    }
    *storage.values.write().map_err(|_| GroupError::Storage)? = records;
    Ok(())
}

/// Length-prefixed (`u32`) binary writer of the snapshot formats.
#[derive(Debug, Default)]
pub(crate) struct Writer(Vec<u8>);

impl Writer {
    pub(crate) fn bytes(&mut self, bytes: &[u8]) -> Result<(), GroupError> {
        let len = u32::try_from(bytes.len()).map_err(|_| GroupError::Storage)?;
        self.0.extend_from_slice(&len.to_be_bytes());
        self.0.extend_from_slice(bytes);
        Ok(())
    }

    pub(crate) fn u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        self.0
    }
}

/// Reader of [`Writer`] output; any short or trailing input is a storage
/// error.
#[derive(Debug)]
pub(crate) struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn bytes(&mut self) -> Result<Vec<u8>, GroupError> {
        let (len, rest) = self.0.split_first_chunk::<4>().ok_or(GroupError::Storage)?;
        let len = usize::try_from(u32::from_be_bytes(*len)).map_err(|_| GroupError::Storage)?;
        let (bytes, rest) = rest.split_at_checked(len).ok_or(GroupError::Storage)?;
        self.0 = rest;
        Ok(bytes.to_vec())
    }

    pub(crate) fn u64(&mut self) -> Result<u64, GroupError> {
        let (value, rest) = self.0.split_first_chunk::<8>().ok_or(GroupError::Storage)?;
        self.0 = rest;
        Ok(u64::from_be_bytes(*value))
    }

    pub(crate) fn string(&mut self) -> Result<String, GroupError> {
        String::from_utf8(self.bytes()?).map_err(|_| GroupError::Storage)
    }

    pub(crate) fn finish(self) -> Result<(), GroupError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(GroupError::Storage)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_snapshot_round_trip() {
        let storage = MemoryStorage::default();
        storage
            .values
            .write()
            .unwrap()
            .extend([(b"b".to_vec(), b"2".to_vec()), (b"a".to_vec(), vec![])]);
        let snapshot = snapshot_storage(&storage).unwrap();
        let restored = MemoryStorage::default();
        restore_storage(&restored, &snapshot).unwrap();
        assert_eq!(
            *restored.values.read().unwrap(),
            *storage.values.read().unwrap()
        );
        assert_eq!(snapshot_storage(&restored).unwrap(), snapshot);
        assert_eq!(
            restore_storage(&restored, &snapshot[..snapshot.len() - 1]),
            Err(GroupError::Storage)
        );
    }
}
