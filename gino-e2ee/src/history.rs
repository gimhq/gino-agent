//! History (spec §5.6, §5.7, §7): epoch links, key-history records, the
//! history policy and the backward walk over links.

use std::collections::BTreeMap;

use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::random::OpenMlsRand;

use crate::drops::{ENC_LEN, hpke_open, hpke_seal};
use crate::envelope::{HEADER_LEN, KEY_LEN, MIN_SEALED_LEN, TAG_LEN, open_salted, seal_salted};
use crate::{EnvelopeType, Error, Header, Location, open_content, open_drop, open_file};

/// Exact length of an epoch-link record.
pub(crate) const EPOCH_LINK_LEN: usize = MIN_SEALED_LEN + 2 * KEY_LEN;
/// Length of one key-history entry: `epoch (u64) || k (32) || d (32)`.
const ENTRY_LEN: usize = 8 + 2 * KEY_LEN;
/// Shortest key-history payload: header, count and one entry.
pub(crate) const MIN_KEY_HISTORY_LEN: usize = HEADER_LEN + 4 + ENTRY_LEN;
/// Shortest key-history envelope to a leaf: header, leaf index, `enc`, tag.
pub(crate) const MIN_KEY_HISTORY_SEALED_LEN: usize = HEADER_LEN + 4 + ENC_LEN + TAG_LEN;
/// HPKE info of key-history envelopes to a leaf.
const KEY_HISTORY_INFO: &[u8] = b"gino-e2ee/v1 key-history";

/// The secrets of one epoch: `E_e = (k_e, d_e)`.
#[derive(Clone, PartialEq, Eq)]
pub struct EpochSecrets {
    /// The content key `k_e`.
    pub content_key: [u8; KEY_LEN],
    /// The drop seed `d_e`.
    pub drop_seed: [u8; KEY_LEN],
}

impl std::fmt::Debug for EpochSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EpochSecrets(***)")
    }
}

impl EpochSecrets {
    /// `k_e || d_e`.
    pub(crate) fn to_bytes(&self) -> [u8; 2 * KEY_LEN] {
        let mut bytes = [0u8; 2 * KEY_LEN];
        bytes[..KEY_LEN].copy_from_slice(&self.content_key);
        bytes[KEY_LEN..].copy_from_slice(&self.drop_seed);
        bytes
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (content_key, drop_seed) = bytes.split_first_chunk::<KEY_LEN>()?;
        Some(Self {
            content_key: *content_key,
            drop_seed: drop_seed.try_into().ok()?,
        })
    }
}

/// Seals the epoch link that carries `E_epoch` under `k_next`, the content key
/// of `epoch + 1` (spec §5.6).
pub fn seal_epoch_link(
    scope: &str,
    epoch: u64,
    secrets: &EpochSecrets,
    k_next: &[u8; KEY_LEN],
    rng: &impl OpenMlsRand,
) -> Result<Vec<u8>, Error> {
    let next = epoch.checked_add(1).ok_or(Error::SealFailed)?;
    let location = Location::epoch_link(scope, next)?;
    seal_salted(
        Header::new(EnvelopeType::EpochLink, next),
        k_next,
        &location,
        &secrets.to_bytes(),
        rng,
    )
}

/// Opens the epoch link stored for `epoch + 1` under `k_next` and returns
/// `E_epoch`. Any failed check is `link_invalid` with `epoch`.
pub fn open_epoch_link(
    scope: &str,
    epoch: u64,
    k_next: &[u8; KEY_LEN],
    link: &[u8],
) -> Result<EpochSecrets, Error> {
    let invalid = Error::LinkInvalid { epoch };
    let next = epoch.checked_add(1).ok_or(invalid)?;
    let location = Location::epoch_link(scope, next)?;
    let header = Header::parse(link).map_err(|_| invalid)?;
    if header != Header::new(EnvelopeType::EpochLink, next) || link.len() != EPOCH_LINK_LEN {
        return Err(invalid);
    }
    let plaintext = open_salted(header, k_next, link, &location).map_err(|_| invalid)?;
    EpochSecrets::from_bytes(&plaintext).ok_or(invalid)
}

/// One key-history entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyHistoryEntry {
    /// The epoch of the secrets.
    pub epoch: u64,
    /// `E_epoch`.
    pub secrets: EpochSecrets,
}

/// A key-history record sent in epoch `epoch` (spec §5.7): entries in strictly
/// increasing epoch order, all below `epoch`, at least one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyHistory {
    /// The epoch `n` of the carrying message.
    pub epoch: u64,
    /// The entries.
    pub entries: Vec<KeyHistoryEntry>,
}

impl KeyHistory {
    fn is_valid(&self) -> bool {
        let ascending = self.entries.windows(2).all(|w| w[0].epoch < w[1].epoch);
        let below = self.entries.last().is_some_and(|e| e.epoch < self.epoch);
        ascending && below
    }

    /// `count (u32) || count × (epoch (u64) || k (32) || d (32))`.
    fn entries_bytes(&self) -> Result<Vec<u8>, Error> {
        let count = u32::try_from(self.entries.len()).map_err(|_| Error::SealFailed)?;
        if !self.is_valid() {
            return Err(Error::SealFailed);
        }
        let mut bytes = Vec::with_capacity(4 + self.entries.len() * ENTRY_LEN);
        bytes.extend_from_slice(&count.to_be_bytes());
        for entry in &self.entries {
            bytes.extend_from_slice(&entry.epoch.to_be_bytes());
            bytes.extend_from_slice(&entry.secrets.to_bytes());
        }
        Ok(bytes)
    }

    /// Parses an entry list; a wrong length is `malformed`, broken order or
    /// range `link_invalid`.
    fn parse_entries(epoch: u64, bytes: &[u8]) -> Result<Self, Error> {
        let (count, rest) = bytes.split_first_chunk::<4>().ok_or(Error::Malformed)?;
        let count = usize::try_from(u32::from_be_bytes(*count)).map_err(|_| Error::Malformed)?;
        if count.checked_mul(ENTRY_LEN) != Some(rest.len()) {
            return Err(Error::Malformed);
        }
        let mut entries = Vec::with_capacity(count);
        for chunk in rest.chunks_exact(ENTRY_LEN) {
            let (entry_epoch, secrets) = chunk.split_first_chunk::<8>().ok_or(Error::Malformed)?;
            entries.push(KeyHistoryEntry {
                epoch: u64::from_be_bytes(*entry_epoch),
                secrets: EpochSecrets::from_bytes(secrets).ok_or(Error::Malformed)?,
            });
        }
        let history = Self { epoch, entries };
        if history.is_valid() {
            Ok(history)
        } else {
            Err(Error::LinkInvalid { epoch })
        }
    }

    /// The application data of the MLS message: `header(0x05, n) || entries`.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let header = Header::new(EnvelopeType::KeyHistory, self.epoch);
        Ok([&header.to_bytes()[..], &self.entries_bytes()?].concat())
    }

    /// Parses the application data of a key-history MLS message.
    pub fn decode(payload: &[u8]) -> Result<Self, Error> {
        let header = Header::parse_as(payload, EnvelopeType::KeyHistory)?;
        let entries = payload.get(HEADER_LEN..).ok_or(Error::Malformed)?;
        Self::parse_entries(header.epoch, entries)
    }

    /// Seals the record to the leaf at `leaf_index` with its encryption key
    /// `leaf_pk`: `header(0x06, n) || leaf_index (u32) || enc || ciphertext || tag`.
    pub fn seal_to_leaf(
        &self,
        crypto: &impl OpenMlsCrypto,
        scope: &str,
        leaf_index: u32,
        leaf_pk: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let header = Header::new(EnvelopeType::KeyHistorySealed, self.epoch);
        let location = Location::key_history(scope, self.epoch, leaf_index)?;
        let prefix = [&header.to_bytes()[..], &leaf_index.to_be_bytes()].concat();
        let sealed = hpke_seal(
            crypto,
            leaf_pk,
            KEY_HISTORY_INFO,
            &header.ad(&location),
            &self.entries_bytes()?,
        )?;
        Ok([prefix, sealed].concat())
    }

    /// Opens a record sealed to the leaf at `leaf_index` with the leaf's
    /// private encryption key. A record for another leaf is `malformed`; a
    /// failed open is `open_failed` with the record's epoch.
    pub fn open_sealed(
        crypto: &impl OpenMlsCrypto,
        scope: &str,
        leaf_index: u32,
        leaf_sk: &[u8],
        envelope: &[u8],
    ) -> Result<Self, Error> {
        let header = Header::parse_as(envelope, EnvelopeType::KeyHistorySealed)?;
        let (index, sealed) = envelope
            .get(HEADER_LEN..)
            .and_then(|rest| rest.split_first_chunk::<4>())
            .ok_or(Error::Malformed)?;
        if u32::from_be_bytes(*index) != leaf_index {
            return Err(Error::Malformed);
        }
        let location = Location::key_history(scope, header.epoch, leaf_index)?;
        let entries = hpke_open(
            crypto,
            leaf_sk,
            KEY_HISTORY_INFO,
            &header.ad(&location),
            sealed,
        )
        .map_err(|_| Error::OpenFailed {
            epoch: header.epoch,
        })?;
        Self::parse_entries(header.epoch, &entries)
    }
}

/// The history policy of a group (spec §2.4, §7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryPolicy {
    /// A link for every transition.
    Full,
    /// A link for the transition `e → e + 1` iff `e ≥ N`.
    FromEpoch(u64),
    /// No links.
    FromJoin,
}

impl HistoryPolicy {
    /// The `extension_data` of extension `0xF0E2`.
    pub fn encode(self) -> Vec<u8> {
        match self {
            Self::Full => vec![0x00],
            Self::FromEpoch(n) => [&[0x01][..], &n.to_be_bytes()].concat(),
            Self::FromJoin => vec![0x02],
        }
    }

    /// Parses the `extension_data` of extension `0xF0E2`; anything else is
    /// `malformed`.
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        match data {
            [0x00] => Ok(Self::Full),
            [0x01, n @ ..] => n
                .try_into()
                .map(|n| Self::FromEpoch(u64::from_be_bytes(n)))
                .map_err(|_| Error::Malformed),
            [0x02] => Ok(Self::FromJoin),
            _ => Err(Error::Malformed),
        }
    }

    /// Whether the transition `epoch → epoch + 1`, governed by this policy in
    /// the context of `epoch + 1`, gets an epoch link.
    pub fn links_transition(self, epoch: u64) -> bool {
        match self {
            Self::Full => true,
            Self::FromEpoch(n) => epoch >= n,
            Self::FromJoin => false,
        }
    }
}

/// An envelope opened through [`History::open`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    /// `content`, `file` or `drop`.
    pub envelope_type: EnvelopeType,
    /// The header epoch.
    pub epoch: u64,
    /// The plaintext.
    pub plaintext: Vec<u8>,
}

/// The cached secrets of one epoch and whether they are verified (spec
/// §7.3): an envelope or a link of their epoch opened under them, or they
/// came from the MLS state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedSecrets {
    /// `E_e`.
    pub secrets: EpochSecrets,
    /// Whether `E_e` is verified.
    pub verified: bool,
}

impl CachedSecrets {
    /// Length of [`CachedSecrets::to_bytes`].
    pub const LEN: usize = 2 * KEY_LEN + 1;

    /// `k_e || d_e || verified (1)`.
    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut bytes = [0u8; Self::LEN];
        bytes[..2 * KEY_LEN].copy_from_slice(&self.secrets.to_bytes());
        bytes[2 * KEY_LEN] = u8::from(self.verified);
        bytes
    }

    /// Parses [`CachedSecrets::to_bytes`]; anything else is `malformed`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let (secrets, flag) = bytes
            .split_last_chunk::<1>()
            .filter(|(secrets, _)| secrets.len() == 2 * KEY_LEN)
            .ok_or(Error::Malformed)?;
        let verified = match flag {
            [0] => false,
            [1] => true,
            _ => return Err(Error::Malformed),
        };
        Ok(Self {
            secrets: EpochSecrets::from_bytes(secrets).ok_or(Error::Malformed)?,
            verified,
        })
    }
}

/// A member's key cache of one scope: [`CachedSecrets`] by epoch (spec
/// §7.6). Implementations persist the values encrypted at rest.
pub trait KeyCache {
    /// The cached secrets of `epoch`.
    fn get(&self, epoch: u64) -> Option<CachedSecrets>;
    /// Caches the secrets of `epoch`, replacing any previous value.
    fn put(&mut self, epoch: u64, secrets: CachedSecrets);
    /// Drops the secrets of `epoch`.
    fn remove(&mut self, epoch: u64);
}

/// An in-memory [`KeyCache`].
#[derive(Debug, Clone, Default)]
pub struct MemoryKeyCache {
    entries: BTreeMap<u64, CachedSecrets>,
}

impl MemoryKeyCache {
    /// The cached epochs in ascending order.
    pub fn epochs(&self) -> impl Iterator<Item = u64> + '_ {
        self.entries.keys().copied()
    }
}

impl KeyCache for MemoryKeyCache {
    fn get(&self, epoch: u64) -> Option<CachedSecrets> {
        self.entries.get(&epoch).cloned()
    }

    fn put(&mut self, epoch: u64, secrets: CachedSecrets) {
        self.entries.insert(epoch, secrets);
    }

    fn remove(&mut self, epoch: u64) {
        self.entries.remove(&epoch);
    }
}

/// A member's epoch secrets of one scope and the backward walk over epoch
/// links (spec §7.3).
///
/// The walk does not consult the history policy: a missing link is the
/// cut-off, so links kept from an earlier, wider policy stay usable. A key
/// recovered from a link or a key-history record is unverified until an
/// envelope of its epoch opens under it.
#[derive(Debug, Clone)]
pub struct History<C = MemoryKeyCache> {
    scope: String,
    current: u64,
    cache: C,
}

impl History {
    /// A history at the current epoch with its secrets from the MLS state,
    /// over an in-memory cache.
    pub fn new(scope: &str, epoch: u64, secrets: EpochSecrets) -> Result<Self, Error> {
        Self::with_cache(scope, epoch, secrets, MemoryKeyCache::default())
    }
}

impl<C: KeyCache> History<C> {
    /// A history at the current epoch with its secrets from the MLS state,
    /// over `cache` (which may hold secrets of earlier epochs).
    pub fn with_cache(
        scope: &str,
        epoch: u64,
        secrets: EpochSecrets,
        mut cache: C,
    ) -> Result<Self, Error> {
        Location::new(scope)?;
        cache.put(
            epoch,
            CachedSecrets {
                secrets,
                verified: true,
            },
        );
        Ok(Self {
            scope: scope.to_owned(),
            current: epoch,
            cache,
        })
    }

    /// The scope id.
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// The current epoch.
    pub fn current_epoch(&self) -> u64 {
        self.current
    }

    /// The key cache.
    pub fn cache(&self) -> &C {
        &self.cache
    }

    /// Consumes the history and returns its key cache.
    pub fn into_cache(self) -> C {
        self.cache
    }

    /// Moves to the next epoch with its secrets from the MLS state.
    pub fn advance(&mut self, secrets: EpochSecrets) -> Result<(), Error> {
        self.current = self.current.checked_add(1).ok_or(Error::Malformed)?;
        self.cache.put(
            self.current,
            CachedSecrets {
                secrets,
                verified: true,
            },
        );
        Ok(())
    }

    /// The cached secrets of `epoch`, verified or not.
    pub fn cached(&self, epoch: u64) -> Option<EpochSecrets> {
        self.cache.get(epoch).map(|held| held.secrets)
    }

    /// Caches the entries of a key-history record as unverified keys. Epochs
    /// already held or not below the current epoch are skipped.
    pub fn add_key_history(&mut self, history: &KeyHistory) {
        for entry in &history.entries {
            if entry.epoch < self.current && self.cache.get(entry.epoch).is_none() {
                self.cache.put(
                    entry.epoch,
                    CachedSecrets {
                        secrets: entry.secrets.clone(),
                        verified: false,
                    },
                );
            }
        }
    }

    /// The epoch of the next link the walk to `epoch` needs, or `None` if
    /// `E_epoch` is cached. An epoch above the current one is `epoch_unknown`.
    pub fn needed_link(&self, epoch: u64) -> Result<Option<u64>, Error> {
        if epoch > self.current {
            return Err(Error::EpochUnknown { epoch });
        }
        if self.cache.get(epoch).is_some() {
            return Ok(None);
        }
        Ok((epoch + 1..=self.current).find(|i| self.cache.get(*i).is_some()))
    }

    /// Opens the link stored for `link_epoch` under the cached `k_link_epoch`
    /// and caches `E_{link_epoch - 1}` as unverified. The opening verifies
    /// `k_link_epoch`.
    pub fn apply_link(&mut self, link_epoch: u64, link: &[u8]) -> Result<(), Error> {
        let epoch = link_epoch
            .checked_sub(1)
            .ok_or(Error::LinkInvalid { epoch: 0 })?;
        let mut held = self
            .cache
            .get(link_epoch)
            .ok_or(Error::HistoryUnavailable { epoch })?;
        let secrets = open_epoch_link(&self.scope, epoch, &held.secrets.content_key, link)?;
        if !held.verified {
            held.verified = true;
            self.cache.put(link_epoch, held);
        }
        if self.cache.get(epoch).is_none() {
            self.cache.put(
                epoch,
                CachedSecrets {
                    secrets,
                    verified: false,
                },
            );
        }
        Ok(())
    }

    /// The secrets of `epoch`, walking links fetched with `fetch(link_epoch)`.
    /// A missing link is `history_unavailable`, an invalid one `link_invalid`,
    /// both with `epoch`.
    pub fn secrets(
        &mut self,
        epoch: u64,
        mut fetch: impl FnMut(u64) -> Option<Vec<u8>>,
    ) -> Result<EpochSecrets, Error> {
        while let Some(link_epoch) = self.needed_link(epoch)? {
            let link = fetch(link_epoch).ok_or(Error::HistoryUnavailable { epoch })?;
            self.apply_link(link_epoch, &link)
                .map_err(|_| Error::LinkInvalid { epoch })?;
        }
        self.cached(epoch)
            .ok_or(Error::HistoryUnavailable { epoch })
    }

    /// Opens a content, file or drop envelope at `location`, recovering its
    /// epoch's secrets through [`History::secrets`]. A failure under a verified
    /// key is `open_failed`; under an unverified key the key is discarded and
    /// the walk retried once, then `link_invalid`.
    pub fn open(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        envelope: &[u8],
        location: &Location,
        mut fetch: impl FnMut(u64) -> Option<Vec<u8>>,
    ) -> Result<Opened, Error> {
        let header = Header::parse(envelope)?;
        let envelope_type = header.envelope_type;
        if !matches!(
            envelope_type,
            EnvelopeType::Content | EnvelopeType::File | EnvelopeType::Drop
        ) {
            return Err(Error::Malformed);
        }
        if location.scope() != self.scope {
            return Err(Error::AadMismatch);
        }
        let epoch = header.epoch;
        for retry in [false, true] {
            let secrets = match self.secrets(epoch, &mut fetch) {
                Ok(secrets) => secrets,
                Err(_) if retry => break,
                Err(error) => return Err(error),
            };
            let opened = match envelope_type {
                EnvelopeType::Drop => open_drop(crypto, &secrets.drop_seed, envelope, location),
                EnvelopeType::File => open_file(&secrets.content_key, envelope, location),
                _ => open_content(&secrets.content_key, envelope, location),
            };
            let Some(mut held) = self.cache.get(epoch) else {
                break;
            };
            match opened {
                Ok(plaintext) => {
                    if !held.verified {
                        held.verified = true;
                        self.cache.put(epoch, held);
                    }
                    return Ok(Opened {
                        envelope_type,
                        epoch,
                        plaintext,
                    });
                }
                Err(_) if held.verified => return Err(Error::OpenFailed { epoch }),
                Err(_) => self.cache.remove(epoch),
            }
        }
        Err(Error::LinkInvalid { epoch })
    }
}

#[cfg(test)]
mod tests {
    use openmls_rust_crypto::RustCrypto;

    use super::*;
    use crate::seal_content;

    const SCOPE: &str = "t-1";

    fn secrets(epoch: u8) -> EpochSecrets {
        EpochSecrets {
            content_key: [epoch; 32],
            drop_seed: [epoch | 0x80; 32],
        }
    }

    fn links(rng: &RustCrypto, upto: u8) -> BTreeMap<u64, Vec<u8>> {
        (1..=upto)
            .map(|i| {
                let link =
                    seal_epoch_link(SCOPE, (i - 1).into(), &secrets(i - 1), &[i; 32], rng).unwrap();
                (u64::from(i), link)
            })
            .collect()
    }

    fn content(rng: &RustCrypto, epoch: u8) -> (Vec<u8>, Location) {
        let location = Location::new(SCOPE).unwrap().part("field", "text").unwrap();
        let envelope = seal_content(&[epoch; 32], epoch.into(), &location, b"pt", rng).unwrap();
        (envelope, location)
    }

    #[test]
    fn epoch_link_round_trip_and_checks() {
        let rng = RustCrypto::default();
        let link = seal_epoch_link(SCOPE, 7, &secrets(7), &[8; 32], &rng).unwrap();
        assert_eq!(link.len(), 124);
        assert_eq!(&link[4..12], &8u64.to_be_bytes());
        assert_eq!(
            open_epoch_link(SCOPE, 7, &[8; 32], &link).unwrap(),
            secrets(7)
        );
        let invalid = Err(Error::LinkInvalid { epoch: 7 });
        assert_eq!(open_epoch_link(SCOPE, 7, &[9; 32], &link), invalid);
        assert_eq!(open_epoch_link("t-2", 7, &[8; 32], &link), invalid);
        assert_eq!(open_epoch_link(SCOPE, 7, &[8; 32], &link[..123]), invalid);
        assert_eq!(
            open_epoch_link(SCOPE, 6, &[8; 32], &link),
            Err(Error::LinkInvalid { epoch: 6 })
        );
    }

    #[test]
    fn key_history_round_trip_and_checks() {
        let crypto = RustCrypto::default();
        let history = KeyHistory {
            epoch: 5,
            entries: vec![
                KeyHistoryEntry {
                    epoch: 2,
                    secrets: secrets(2),
                },
                KeyHistoryEntry {
                    epoch: 4,
                    secrets: secrets(4),
                },
            ],
        };
        let payload = history.encode().unwrap();
        assert_eq!(payload.len(), 12 + 4 + 2 * 72);
        assert_eq!(KeyHistory::decode(&payload).unwrap(), history);

        let leaf = crate::DropKeyPair::derive(&crypto, &[1; 32]).unwrap();
        let sealed = history
            .seal_to_leaf(&crypto, SCOPE, 3, leaf.public_key())
            .unwrap();
        assert_eq!(
            KeyHistory::open_sealed(&crypto, SCOPE, 3, leaf.private_key(), &sealed).unwrap(),
            history
        );
        assert_eq!(
            KeyHistory::open_sealed(&crypto, SCOPE, 4, leaf.private_key(), &sealed),
            Err(Error::Malformed)
        );
        assert_eq!(
            KeyHistory::open_sealed(&crypto, "t-2", 3, leaf.private_key(), &sealed),
            Err(Error::OpenFailed { epoch: 5 })
        );

        let mut unordered = history.clone();
        unordered.entries.reverse();
        assert_eq!(unordered.encode(), Err(Error::SealFailed));
        let mut swapped = payload.clone();
        swapped[16..].rotate_left(72);
        assert_eq!(
            KeyHistory::decode(&swapped),
            Err(Error::LinkInvalid { epoch: 5 })
        );
        assert_eq!(
            KeyHistory::decode(&payload[..payload.len() - 1]),
            Err(Error::Malformed)
        );
    }

    #[test]
    fn policy_encoding() {
        for policy in [
            HistoryPolicy::Full,
            HistoryPolicy::FromEpoch(9),
            HistoryPolicy::FromJoin,
        ] {
            assert_eq!(HistoryPolicy::decode(&policy.encode()), Ok(policy));
        }
        for data in [&[][..], &[3], &[0, 0], &[1, 0], &[2, 0]] {
            assert_eq!(HistoryPolicy::decode(data), Err(Error::Malformed));
        }
        assert!(HistoryPolicy::FromEpoch(3).links_transition(3));
        assert!(!HistoryPolicy::FromEpoch(3).links_transition(2));
    }

    #[test]
    fn walk_recovers_older_epochs() {
        let crypto = RustCrypto::default();
        let links = links(&crypto, 4);
        let mut history = History::new(SCOPE, 4, secrets(4)).unwrap();
        let (envelope, location) = content(&crypto, 1);
        let opened = history
            .open(&crypto, &envelope, &location, |i| links.get(&i).cloned())
            .unwrap();
        assert_eq!(opened.plaintext, b"pt");
        assert_eq!(history.cached(2), Some(secrets(2)));

        let (later, location) = content(&crypto, 5);
        assert_eq!(
            history.open(&crypto, &later, &location, |_| None),
            Err(Error::EpochUnknown { epoch: 5 })
        );
        let other = Location::new("t-2").unwrap().part("field", "text").unwrap();
        assert_eq!(
            history.open(&crypto, &envelope, &other, |_| None),
            Err(Error::AadMismatch)
        );
    }

    #[test]
    fn missing_link_cuts_only_older_epochs() {
        let crypto = RustCrypto::default();
        let mut links = links(&crypto, 4);
        links.remove(&2);
        let mut history = History::new(SCOPE, 4, secrets(4)).unwrap();
        let (old, location) = content(&crypto, 0);
        assert_eq!(
            history.open(&crypto, &old, &location, |i| links.get(&i).cloned()),
            Err(Error::HistoryUnavailable { epoch: 0 })
        );
        let (newer, location) = content(&crypto, 2);
        assert!(
            history
                .open(&crypto, &newer, &location, |i| links.get(&i).cloned())
                .is_ok()
        );
    }

    #[test]
    fn wrong_key_in_link_is_link_invalid() {
        let crypto = RustCrypto::default();
        let mut links = links(&crypto, 3);
        let wrong = seal_epoch_link(SCOPE, 1, &secrets(9), &[2; 32], &crypto).unwrap();
        links.insert(2, wrong);
        let mut history = History::new(SCOPE, 3, secrets(3)).unwrap();
        let (envelope, location) = content(&crypto, 1);
        assert_eq!(
            history.open(&crypto, &envelope, &location, |i| links.get(&i).cloned()),
            Err(Error::LinkInvalid { epoch: 1 })
        );
        assert_eq!(history.cached(1), None);

        let mut tampered = links.clone();
        if let Some(link) = tampered.get_mut(&3) {
            link[123] ^= 1;
        }
        let mut history = History::new(SCOPE, 3, secrets(3)).unwrap();
        assert_eq!(
            history.open(&crypto, &envelope, &location, |i| tampered.get(&i).cloned()),
            Err(Error::LinkInvalid { epoch: 1 })
        );

        let mut history = History::new(SCOPE, 3, secrets(3)).unwrap();
        let (current, location) = content(&crypto, 3);
        let mut moved = current.clone();
        moved[20] ^= 1;
        assert_eq!(
            history.open(&crypto, &moved, &location, |_| None),
            Err(Error::OpenFailed { epoch: 3 })
        );
    }

    #[test]
    fn key_history_keys_are_unverified() {
        let crypto = RustCrypto::default();
        let mut history = History::new(SCOPE, 3, secrets(3)).unwrap();
        history.add_key_history(&KeyHistory {
            epoch: 3,
            entries: vec![KeyHistoryEntry {
                epoch: 1,
                secrets: secrets(9),
            }],
        });
        let (envelope, location) = content(&crypto, 1);
        assert_eq!(
            history.open(&crypto, &envelope, &location, |_| None),
            Err(Error::LinkInvalid { epoch: 1 })
        );
        let links = links(&crypto, 3);
        history.add_key_history(&KeyHistory {
            epoch: 3,
            entries: vec![KeyHistoryEntry {
                epoch: 1,
                secrets: secrets(9),
            }],
        });
        assert!(
            history
                .open(&crypto, &envelope, &location, |i| links.get(&i).cloned())
                .is_ok()
        );
    }
}
