//! JavaScript bindings (wasm-bindgen).
//!
//! Binary values cross as `Uint8Array`, epochs and `seq` as `bigint`, and
//! structured values as JSON text with binary members in base64url. A
//! failure throws an `Error` whose message is the JSON object
//! `{"code": <code>, ...}`: the spec §11 `encryption_error`, or one of the
//! local group conditions `log_gap` (with `expected` and `got`),
//! `commit_pending`, `no_pending_commit` and `storage`.
//!
//! Every `random` argument replaces the CSPRNG with preset bytes, for test
//! vectors only.

#![allow(clippy::needless_pass_by_value)]

use std::cell::RefCell;
use std::collections::BTreeMap;

use openmls_rust_crypto::RustCrypto;
use openmls_traits::random::OpenMlsRand;
use serde_json::{Value, json};
use wasm_bindgen::prelude::*;

use crate::field_map::{Direction, FieldRule, FrameRule, KeyedPlain, Kind, When, WhenOp};
use crate::history::{CachedSecrets, KeyCache, MemoryKeyCache};
use crate::state::{Reader, Writer};
use crate::{
    Applied, CommitUnit, DropKeyPair, EntryKind, EnvelopeType, EpochSecrets, Error, FieldMap,
    FileDigest, GroupError, Header, History, HistoryPolicy, Identity, InspectError, KeyHistory,
    KeyHistoryEntry, KeyHistoryOffer, KeyHistoryRecord, KeyPackageStore, Location, LogEntry,
    ScopeGroup, decode_b64url, decode_json, decode_text, encode_b64url, from_sealed_value,
    inspect_key_package, inspect_message, message_key, open_content, open_drop, open_epoch_link,
    open_file, seal_content, seal_drop, seal_epoch_link, seal_file, to_sealed_value,
    verify_drop_public_key, welcome_recipients,
};

type JsResult<T> = Result<T, JsError>;

fn js_error(error: impl Into<GroupError>) -> JsError {
    let detail = match error.into() {
        GroupError::E2ee(error) => error.to_json(),
        GroupError::Gap { expected, got } => {
            json!({ "code": "log_gap", "expected": expected, "got": got })
        }
        GroupError::CommitPending => json!({ "code": "commit_pending" }),
        GroupError::NoPendingCommit => json!({ "code": "no_pending_commit" }),
        GroupError::Storage => json!({ "code": "storage" }),
    };
    JsError::new(&detail.to_string())
}

fn malformed() -> JsError {
    js_error(Error::Malformed)
}

fn key(bytes: &[u8]) -> JsResult<[u8; 32]> {
    bytes.try_into().map_err(|_| malformed())
}

fn secrets(k: &[u8], d: &[u8]) -> JsResult<EpochSecrets> {
    Ok(EpochSecrets {
        content_key: key(k)?,
        drop_seed: key(d)?,
    })
}

fn location(text: &str) -> JsResult<Location> {
    Location::parse(text).map_err(js_error)
}

fn parse_json(text: &str) -> JsResult<Value> {
    serde_json::from_str(text).map_err(|_| malformed())
}

fn member<'a>(value: &'a Value, name: &str) -> JsResult<&'a Value> {
    value.get(name).ok_or_else(malformed)
}

fn member_u64(value: &Value, name: &str) -> JsResult<u64> {
    member(value, name)?.as_u64().ok_or_else(malformed)
}

fn member_str<'a>(value: &'a Value, name: &str) -> JsResult<&'a str> {
    member(value, name)?.as_str().ok_or_else(malformed)
}

fn member_bytes(value: &Value, name: &str) -> JsResult<Vec<u8>> {
    decode_b64url(member_str(value, name)?).map_err(js_error)
}

fn b64(bytes: &[u8]) -> Value {
    encode_b64url(bytes).into()
}

/// The CSPRNG of the provider, or preset bytes.
enum Random {
    Crypto(Box<RustCrypto>),
    Fixed(RefCell<Vec<u8>>),
}

#[derive(Debug, thiserror::Error)]
#[error("randomness unavailable")]
struct RandomError;

impl Random {
    fn new(preset: Option<Vec<u8>>) -> Self {
        match preset {
            Some(bytes) => Self::Fixed(RefCell::new(bytes)),
            None => Self::Crypto(Box::default()),
        }
    }
}

impl OpenMlsRand for Random {
    type Error = RandomError;

    fn random_array<const N: usize>(&self) -> Result<[u8; N], RandomError> {
        self.random_vec(N)?.try_into().map_err(|_| RandomError)
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, RandomError> {
        match self {
            Self::Crypto(crypto) => crypto.random_vec(len).map_err(|_| RandomError),
            Self::Fixed(bytes) => {
                let mut bytes = bytes.borrow_mut();
                if bytes.len() < len {
                    return Err(RandomError);
                }
                Ok(bytes.drain(..len).collect())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Encoding, ids and locations

/// base64url without padding.
#[wasm_bindgen(js_name = encodeB64url)]
pub fn encode_b64url_js(bytes: &[u8]) -> String {
    encode_b64url(bytes)
}

/// Strict base64url without padding (spec §5.1).
#[wasm_bindgen(js_name = decodeB64url)]
pub fn decode_b64url_js(text: &str) -> JsResult<Vec<u8>> {
    decode_b64url(text).map_err(js_error)
}

/// The 32-byte group id of a profile and scope (spec §2.3).
#[wasm_bindgen(js_name = groupId)]
pub fn group_id_js(profile: &str, scope: &str) -> JsResult<Vec<u8>> {
    Ok(crate::group_id(profile, scope).map_err(js_error)?.to_vec())
}

/// The canonical fingerprint of an Ed25519 public key (spec §3.5).
#[wasm_bindgen(js_name = fingerprint)]
pub fn fingerprint_js(public_key: &[u8]) -> JsResult<String> {
    Ok(crate::fingerprint(&key(public_key)?))
}

/// The display form of a fingerprint.
#[wasm_bindgen(js_name = fingerprintDisplay)]
pub fn fingerprint_display_js(public_key: &[u8]) -> JsResult<String> {
    Ok(crate::fingerprint_display(&key(public_key)?))
}

/// Resolves an AAD template against a JSON frame (spec §12.3).
#[wasm_bindgen(js_name = buildLocation)]
pub fn build_location(template: &str, frame: &str, element: Option<u32>) -> JsResult<String> {
    let element = element
        .map(usize::try_from)
        .transpose()
        .map_err(|_| malformed())?;
    let location = Location::from_template(template, &parse_json(frame)?, element);
    Ok(location.map_err(js_error)?.as_str().to_owned())
}

/// Checks a location string (spec §6) and returns it.
#[wasm_bindgen(js_name = parseLocation)]
pub fn parse_location(text: &str) -> JsResult<String> {
    Ok(location(text)?.as_str().to_owned())
}

fn policy_from_json(value: &Value) -> JsResult<HistoryPolicy> {
    match value {
        Value::String(name) if name == "full" => Ok(HistoryPolicy::Full),
        Value::String(name) if name == "from_join" => Ok(HistoryPolicy::FromJoin),
        Value::Object(_) => Ok(HistoryPolicy::FromEpoch(member_u64(value, "from_epoch")?)),
        _ => Err(malformed()),
    }
}

fn policy_to_json(policy: HistoryPolicy) -> String {
    match policy {
        HistoryPolicy::Full => json!("full"),
        HistoryPolicy::FromJoin => json!("from_join"),
        HistoryPolicy::FromEpoch(n) => json!({ "from_epoch": n }),
    }
    .to_string()
}

/// The `extension_data` of a history policy given as JSON (`"full"`,
/// `"from_join"` or `{"from_epoch": N}`).
#[wasm_bindgen(js_name = encodeHistoryPolicy)]
pub fn encode_history_policy(policy: &str) -> JsResult<Vec<u8>> {
    Ok(policy_from_json(&parse_json(policy)?)?.encode())
}

/// The JSON history policy of an `extension_data`.
#[wasm_bindgen(js_name = decodeHistoryPolicy)]
pub fn decode_history_policy(data: &[u8]) -> JsResult<String> {
    Ok(policy_to_json(
        HistoryPolicy::decode(data).map_err(js_error)?,
    ))
}

fn type_name(envelope_type: EnvelopeType) -> &'static str {
    match envelope_type {
        EnvelopeType::Content => "content",
        EnvelopeType::File => "file",
        EnvelopeType::Drop => "drop",
        EnvelopeType::EpochLink => "epoch_link",
        EnvelopeType::KeyHistory => "key_history",
        EnvelopeType::KeyHistorySealed => "key_history_sealed",
    }
}

/// The header of an envelope as JSON `{"type": <name>, "epoch": <integer>}`.
#[wasm_bindgen(js_name = envelopeHeader)]
pub fn envelope_header(envelope: &[u8]) -> JsResult<String> {
    let header = Header::parse(envelope).map_err(js_error)?;
    Ok(json!({ "type": type_name(header.envelope_type), "epoch": header.epoch }).to_string())
}

/// The sealed form `{"e2ee": "<base64url>"}` of an envelope, as JSON.
#[wasm_bindgen(js_name = toSealedValue)]
pub fn to_sealed_value_js(envelope: &[u8]) -> String {
    to_sealed_value(envelope).to_string()
}

/// The envelope of a JSON mapped value (spec §12.4).
#[wasm_bindgen(js_name = fromSealedValue)]
pub fn from_sealed_value_js(value: &str) -> JsResult<Vec<u8>> {
    from_sealed_value(&parse_json(value)?).map_err(js_error)
}

/// Decodes an opened plaintext of kind `text` or `json` (spec §12.4) and
/// returns the value as JSON.
#[wasm_bindgen(js_name = decodePlaintext)]
pub fn decode_plaintext(plaintext: Vec<u8>, kind: &str) -> JsResult<String> {
    let value = match kind {
        "text" => Value::String(decode_text(plaintext).map_err(js_error)?),
        "json" => decode_json(&plaintext).map_err(js_error)?,
        _ => return Err(malformed()),
    };
    Ok(value.to_string())
}

// ---------------------------------------------------------------------------
// Envelopes

/// The per-envelope key `k_msg` (spec §4.3).
#[wasm_bindgen(js_name = messageKey)]
pub fn message_key_js(k_e: &[u8], salt: &[u8]) -> JsResult<Vec<u8>> {
    Ok(message_key(&key(k_e)?, &key(salt)?)
        .map_err(js_error)?
        .to_vec())
}

/// Seals a content envelope (spec §5.3).
#[wasm_bindgen(js_name = sealContent)]
pub fn seal_content_js(
    k_e: &[u8],
    epoch: u64,
    location_text: &str,
    plaintext: &[u8],
    random: Option<Vec<u8>>,
) -> JsResult<Vec<u8>> {
    let rng = Random::new(random);
    seal_content(
        &key(k_e)?,
        epoch,
        &location(location_text)?,
        plaintext,
        &rng,
    )
    .map_err(js_error)
}

/// Opens a content envelope.
#[wasm_bindgen(js_name = openContent)]
pub fn open_content_js(k_e: &[u8], envelope: &[u8], location_text: &str) -> JsResult<Vec<u8>> {
    open_content(&key(k_e)?, envelope, &location(location_text)?).map_err(js_error)
}

/// Seals a file envelope (spec §5.4).
#[wasm_bindgen(js_name = sealFile)]
pub fn seal_file_js(
    k_e: &[u8],
    epoch: u64,
    location_text: &str,
    bytes: &[u8],
    random: Option<Vec<u8>>,
) -> JsResult<Vec<u8>> {
    let rng = Random::new(random);
    let sealed = seal_file(&key(k_e)?, epoch, &location(location_text)?, bytes, &rng);
    Ok(sealed.map_err(js_error)?.envelope)
}

/// The lower-case hex SHA-256 of a file envelope (the descriptor `sha256`).
#[wasm_bindgen(js_name = fileSha256)]
pub fn file_sha256(envelope: &[u8]) -> String {
    FileDigest::of(envelope).sha256
}

/// Opens a file envelope.
#[wasm_bindgen(js_name = openFile)]
pub fn open_file_js(k_e: &[u8], envelope: &[u8], location_text: &str) -> JsResult<Vec<u8>> {
    open_file(&key(k_e)?, envelope, &location(location_text)?).map_err(js_error)
}

/// A drop key pair derived from a drop seed `d_e` (spec §4.4).
#[derive(Debug)]
#[wasm_bindgen(js_name = DropKeyPair)]
pub struct JsDropKeyPair(DropKeyPair);

#[wasm_bindgen(js_class = DropKeyPair)]
impl JsDropKeyPair {
    /// Derives the pair of `d_e`.
    pub fn derive(d_e: &[u8]) -> JsResult<JsDropKeyPair> {
        let pair = DropKeyPair::derive(&RustCrypto::default(), &key(d_e)?).map_err(js_error)?;
        Ok(Self(pair))
    }

    /// The 32-byte X25519 public key.
    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> Vec<u8> {
        self.0.public_key().to_vec()
    }

    /// The private key.
    #[wasm_bindgen(getter, js_name = privateKey)]
    pub fn private_key(&self) -> Vec<u8> {
        self.0.private_key().to_vec()
    }
}

/// Seals a drop envelope to the drop public key of `epoch` (spec §5.5).
#[wasm_bindgen(js_name = sealDrop)]
pub fn seal_drop_js(
    public_key: &[u8],
    epoch: u64,
    location_text: &str,
    plaintext: &[u8],
) -> JsResult<Vec<u8>> {
    let crypto = RustCrypto::default();
    seal_drop(
        &crypto,
        public_key,
        epoch,
        &location(location_text)?,
        plaintext,
    )
    .map_err(js_error)
}

/// Opens a drop envelope with the drop seed of its epoch.
#[wasm_bindgen(js_name = openDrop)]
pub fn open_drop_js(d_e: &[u8], envelope: &[u8], location_text: &str) -> JsResult<Vec<u8>> {
    let crypto = RustCrypto::default();
    open_drop(&crypto, &key(d_e)?, envelope, &location(location_text)?).map_err(js_error)
}

/// Compares a logged drop public key of `epoch` with the one derived from
/// `d_e` (`drop_key_mismatch`).
#[wasm_bindgen(js_name = verifyDropPublicKey)]
pub fn verify_drop_public_key_js(d_e: &[u8], epoch: u64, public_key: &[u8]) -> JsResult<()> {
    verify_drop_public_key(&RustCrypto::default(), &key(d_e)?, epoch, public_key).map_err(js_error)
}

/// Seals the epoch link carrying `E_epoch` under `k_next` (spec §5.6).
#[wasm_bindgen(js_name = sealEpochLink)]
pub fn seal_epoch_link_js(
    scope: &str,
    epoch: u64,
    k_e: &[u8],
    d_e: &[u8],
    k_next: &[u8],
    random: Option<Vec<u8>>,
) -> JsResult<Vec<u8>> {
    let rng = Random::new(random);
    seal_epoch_link(scope, epoch, &secrets(k_e, d_e)?, &key(k_next)?, &rng).map_err(js_error)
}

/// Opens the epoch link stored for `epoch + 1` and returns `k_e || d_e`.
#[wasm_bindgen(js_name = openEpochLink)]
pub fn open_epoch_link_js(
    scope: &str,
    epoch: u64,
    k_next: &[u8],
    link: &[u8],
) -> JsResult<Vec<u8>> {
    let secrets = open_epoch_link(scope, epoch, &key(k_next)?, link).map_err(js_error)?;
    Ok(secrets.to_bytes().to_vec())
}

fn key_history_from_json(text: &str) -> JsResult<KeyHistory> {
    let value = parse_json(text)?;
    let entries = member(&value, "entries")?
        .as_array()
        .ok_or_else(malformed)?
        .iter()
        .map(|entry| {
            Ok(KeyHistoryEntry {
                epoch: member_u64(entry, "epoch")?,
                secrets: secrets(&member_bytes(entry, "k")?, &member_bytes(entry, "d")?)?,
            })
        })
        .collect::<JsResult<_>>()?;
    Ok(KeyHistory {
        epoch: member_u64(&value, "epoch")?,
        entries,
    })
}

fn key_history_to_json(history: &KeyHistory) -> String {
    let entries: Vec<Value> = history
        .entries
        .iter()
        .map(|entry| {
            json!({
                "epoch": entry.epoch,
                "k": b64(&entry.secrets.content_key),
                "d": b64(&entry.secrets.drop_seed),
            })
        })
        .collect();
    json!({ "epoch": history.epoch, "entries": entries }).to_string()
}

/// The MLS application data of a key-history record given as JSON
/// `{"epoch", "entries": [{"epoch", "k", "d"}]}` (spec §5.7).
#[wasm_bindgen(js_name = encodeKeyHistory)]
pub fn encode_key_history(history: &str) -> JsResult<Vec<u8>> {
    key_history_from_json(history)?.encode().map_err(js_error)
}

/// The JSON key-history record of an MLS application data payload.
#[wasm_bindgen(js_name = decodeKeyHistory)]
pub fn decode_key_history(payload: &[u8]) -> JsResult<String> {
    Ok(key_history_to_json(
        &KeyHistory::decode(payload).map_err(js_error)?,
    ))
}

/// Seals a JSON key-history record to the leaf at `leaf_index` with its
/// encryption key.
#[wasm_bindgen(js_name = sealKeyHistoryToLeaf)]
pub fn seal_key_history_to_leaf(
    history: &str,
    scope: &str,
    leaf_index: u32,
    leaf_public_key: &[u8],
) -> JsResult<Vec<u8>> {
    key_history_from_json(history)?
        .seal_to_leaf(&RustCrypto::default(), scope, leaf_index, leaf_public_key)
        .map_err(js_error)
}

/// Opens a key-history envelope sealed to the leaf at `leaf_index` and
/// returns the JSON record.
#[wasm_bindgen(js_name = openKeyHistorySealed)]
pub fn open_key_history_sealed(
    scope: &str,
    leaf_index: u32,
    leaf_private_key: &[u8],
    envelope: &[u8],
) -> JsResult<String> {
    let crypto = RustCrypto::default();
    let history = KeyHistory::open_sealed(&crypto, scope, leaf_index, leaf_private_key, envelope)
        .map_err(js_error)?;
    Ok(key_history_to_json(&history))
}

// ---------------------------------------------------------------------------
// History and field maps

/// Epoch links supplied by the caller, consulted by the backward walk.
#[derive(Debug, Default)]
struct Links(BTreeMap<u64, Vec<u8>>);

impl Links {
    fn fetch(&self) -> impl FnMut(u64) -> Option<Vec<u8>> + '_ {
        |epoch| self.0.get(&epoch).cloned()
    }
}

/// The epoch secrets of one scope over an in-memory key cache, with the
/// backward walk over the epoch links added with `addLink` (spec §7.3).
#[derive(Debug)]
#[wasm_bindgen(js_name = History)]
pub struct JsHistory {
    history: History,
    links: Links,
}

#[wasm_bindgen(js_class = History)]
impl JsHistory {
    /// A history at the current `epoch` with its secrets.
    #[wasm_bindgen(constructor)]
    pub fn new(scope: &str, epoch: u64, k_e: &[u8], d_e: &[u8]) -> JsResult<JsHistory> {
        let history = History::new(scope, epoch, secrets(k_e, d_e)?).map_err(js_error)?;
        Ok(Self {
            history,
            links: Links::default(),
        })
    }

    /// The current epoch.
    #[wasm_bindgen(getter, js_name = currentEpoch)]
    pub fn current_epoch(&self) -> u64 {
        self.history.current_epoch()
    }

    /// Caches the secrets of an epoch below the current one.
    #[wasm_bindgen(js_name = cacheSecrets)]
    pub fn cache_secrets(
        &mut self,
        epoch: u64,
        k_e: &[u8],
        d_e: &[u8],
        verified: bool,
    ) -> JsResult<()> {
        let held = CachedSecrets {
            secrets: secrets(k_e, d_e)?,
            verified,
        };
        let current = self.history.current_epoch();
        if epoch >= current {
            return Err(malformed());
        }
        let scope = self.history.scope().to_owned();
        let current_secrets = self.history.cached(current).ok_or_else(malformed)?;
        let mut cache = self.history.clone().into_cache();
        cache.put(epoch, held);
        self.history =
            History::with_cache(&scope, current, current_secrets, cache).map_err(js_error)?;
        Ok(())
    }

    /// Adds the epoch link stored for `epoch`.
    #[wasm_bindgen(js_name = addLink)]
    pub fn add_link(&mut self, epoch: u64, link: Vec<u8>) {
        self.links.0.insert(epoch, link);
    }

    /// The epoch of the next link the walk to `epoch` needs, or `undefined`
    /// if the secrets of `epoch` are cached.
    #[wasm_bindgen(js_name = neededLink)]
    pub fn needed_link(&self, epoch: u64) -> JsResult<Option<u64>> {
        self.history.needed_link(epoch).map_err(js_error)
    }

    /// `k_e || d_e` of `epoch`, from the cache or the walk.
    pub fn secrets(&mut self, epoch: u64) -> JsResult<Vec<u8>> {
        let secrets = self.history.secrets(epoch, self.links.fetch());
        Ok(secrets.map_err(js_error)?.to_bytes().to_vec())
    }

    /// Opens a content, file or drop envelope at `location`.
    pub fn open(&mut self, envelope: &[u8], location_text: &str) -> JsResult<Vec<u8>> {
        let crypto = RustCrypto::default();
        let opened = self.history.open(
            &crypto,
            envelope,
            &location(location_text)?,
            self.links.fetch(),
        );
        Ok(opened.map_err(js_error)?.plaintext)
    }

    /// Opens every mapped value of a JSON frame.
    #[wasm_bindgen(js_name = openFrame)]
    pub fn open_frame(
        &mut self,
        map: &JsFieldMap,
        frame_type: &str,
        frame: &str,
    ) -> JsResult<String> {
        let crypto = RustCrypto::default();
        let frame = parse_json(frame)?;
        let opened = map.0.open_frame(frame_type, &frame, |envelope, location| {
            self.history
                .open(&crypto, envelope, location, self.links.fetch())
        });
        Ok(opened.map_err(js_error)?.to_string())
    }
}

/// A field map (spec §12): a generated profile map, or an inline one.
#[derive(Debug)]
#[wasm_bindgen(js_name = FieldMap)]
pub struct JsFieldMap(&'static FieldMap);

#[wasm_bindgen(js_class = FieldMap)]
impl JsFieldMap {
    /// The generated map of `profile`, or `undefined`.
    #[wasm_bindgen(js_name = forProfile)]
    pub fn for_profile(profile: &str) -> Option<JsFieldMap> {
        FieldMap::for_profile(profile).map(Self)
    }

    /// A map from field-map JSON (spec §12.1), for inline maps of test
    /// vectors. The map is never freed.
    #[wasm_bindgen(js_name = fromJson)]
    pub fn from_json(json: &str) -> JsResult<JsFieldMap> {
        parse_field_map(&parse_json(json)?).map(Self)
    }

    /// The profile id.
    #[wasm_bindgen(getter)]
    pub fn profile(&self) -> String {
        self.0.profile.to_owned()
    }

    /// Seals every mapped value of a JSON frame under `k_e` of `epoch` and
    /// returns the JSON frame with the sealed forms in place.
    #[wasm_bindgen(js_name = sealFrame)]
    pub fn seal_frame(
        &self,
        frame_type: &str,
        frame: &str,
        epoch: u64,
        k_e: &[u8],
        random: Option<Vec<u8>>,
    ) -> JsResult<String> {
        let rng = Random::new(random);
        let sealed = self
            .0
            .seal_frame(frame_type, &parse_json(frame)?, epoch, &key(k_e)?, &rng);
        Ok(sealed.map_err(js_error)?.to_string())
    }
}

fn leak_str(value: &Value) -> JsResult<&'static str> {
    let text = value.as_str().ok_or_else(malformed)?;
    Ok(Box::leak(text.to_owned().into_boxed_str()))
}

fn leak_slice<T>(items: Vec<T>) -> &'static [T] {
    Box::leak(items.into_boxed_slice())
}

fn parse_rule(value: &Value) -> JsResult<FieldRule> {
    let kind = match member_str(value, "kind")? {
        "text" => Kind::Text,
        "json" => Kind::Json,
        "blob" => Kind::Blob,
        _ => return Err(malformed()),
    };
    let envelopes = member(value, "envelopes")?
        .as_array()
        .ok_or_else(malformed)?
        .iter()
        .map(|envelope| match envelope.as_str() {
            Some("content") => Ok(EnvelopeType::Content),
            Some("drop") => Ok(EnvelopeType::Drop),
            Some("file") => Ok(EnvelopeType::File),
            _ => Err(malformed()),
        })
        .collect::<JsResult<_>>()?;
    let when = match value.get("when") {
        None => None,
        Some(when) => Some(When {
            path: leak_str(member(when, "path")?)?,
            op: match member_str(when, "op")? {
                "eq" => WhenOp::Eq,
                "ne" => WhenOp::Ne,
                _ => return Err(malformed()),
            },
            value: leak_str(member(when, "value")?)?,
        }),
    };
    let keyed_plain = match value.get("keyed_plain") {
        None => None,
        Some(keyed) => {
            let table = member(keyed, "table")?
                .as_object()
                .ok_or_else(malformed)?
                .iter()
                .map(|(discriminator, paths)| {
                    let paths = paths
                        .as_array()
                        .ok_or_else(malformed)?
                        .iter()
                        .map(leak_str)
                        .collect::<JsResult<_>>()?;
                    let discriminator: &'static str =
                        Box::leak(discriminator.clone().into_boxed_str());
                    Ok((discriminator, leak_slice(paths)))
                })
                .collect::<JsResult<_>>()?;
            Some(KeyedPlain {
                key: leak_str(member(keyed, "key")?)?,
                table: leak_slice(table),
            })
        }
    };
    Ok(FieldRule {
        path: leak_str(member(value, "path")?)?,
        kind,
        envelopes: leak_slice(envelopes),
        aad: leak_str(member(value, "aad")?)?,
        when,
        keyed_plain,
    })
}

fn parse_field_map(value: &Value) -> JsResult<&'static FieldMap> {
    if member_str(value, "format")? != "gino-e2ee/field-map/v1" {
        return Err(malformed());
    }
    let frames = member(value, "frames")?
        .as_object()
        .ok_or_else(malformed)?
        .iter()
        .map(|(frame_type, frame)| {
            let fields = member(frame, "fields")?
                .as_array()
                .ok_or_else(malformed)?
                .iter()
                .map(parse_rule)
                .collect::<JsResult<_>>()?;
            Ok(FrameRule {
                frame_type: Box::leak(frame_type.clone().into_boxed_str()),
                direction: match member_str(frame, "direction")? {
                    "host_to_agent" => Direction::HostToAgent,
                    "agent_to_host" => Direction::AgentToHost,
                    _ => return Err(malformed()),
                },
                scope: leak_str(member(frame, "scope")?)?,
                fields: leak_slice(fields),
            })
        })
        .collect::<JsResult<_>>()?;
    Ok(Box::leak(Box::new(FieldMap {
        profile: leak_str(member(value, "profile")?)?,
        frames: leak_slice(frames),
    })))
}

// ---------------------------------------------------------------------------
// MLS

/// A party's Ed25519 identity (spec §2.2).
#[derive(Debug)]
#[wasm_bindgen(js_name = Identity)]
pub struct JsIdentity(Identity);

#[wasm_bindgen(js_class = Identity)]
impl JsIdentity {
    /// A fresh identity.
    pub fn generate() -> JsResult<JsIdentity> {
        Ok(Self(
            Identity::generate(&RustCrypto::default()).map_err(js_error)?,
        ))
    }

    /// The identity of a 32-byte Ed25519 seed.
    #[wasm_bindgen(js_name = fromSeed)]
    pub fn from_seed(seed: &[u8]) -> JsResult<JsIdentity> {
        Ok(Self(Identity::from_seed(&key(seed)?)))
    }

    /// The 32-byte seed.
    #[wasm_bindgen(getter)]
    pub fn seed(&self) -> Vec<u8> {
        self.0.seed().to_vec()
    }

    /// The raw 32-byte Ed25519 public key.
    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> Vec<u8> {
        self.0.public_key().to_vec()
    }
}

/// A party's KeyPackage private keys (spec §2.7).
#[derive(Debug)]
#[wasm_bindgen(js_name = KeyPackageStore)]
pub struct JsKeyPackageStore(KeyPackageStore);

#[wasm_bindgen(js_class = KeyPackageStore)]
impl JsKeyPackageStore {
    /// An empty store.
    #[wasm_bindgen(constructor)]
    pub fn new() -> JsKeyPackageStore {
        Self(KeyPackageStore::new())
    }

    /// Generates a KeyPackage (TLS-serialized `MLSMessage`) and keeps its
    /// private keys.
    pub fn generate(&self, identity: &JsIdentity, last_resort: bool) -> JsResult<Vec<u8>> {
        self.0.generate(&identity.0, last_resort).map_err(js_error)
    }

    /// The store as opaque bytes.
    pub fn snapshot(&self) -> JsResult<Vec<u8>> {
        self.0.snapshot().map_err(js_error)
    }

    /// A store from `snapshot` bytes.
    pub fn restore(snapshot: &[u8]) -> JsResult<JsKeyPackageStore> {
        Ok(Self(KeyPackageStore::restore(snapshot).map_err(js_error)?))
    }
}

impl Default for JsKeyPackageStore {
    fn default() -> Self {
        Self::new()
    }
}

fn commit_unit_json(unit: &CommitUnit) -> String {
    let key_history: Vec<Value> = unit
        .key_history
        .iter()
        .map(|record| match record {
            KeyHistoryRecord::Message(bytes) => {
                json!({ "kind": "key_history", "bytes": b64(bytes) })
            }
            KeyHistoryRecord::Sealed(bytes) => {
                json!({ "kind": "key_history_sealed", "bytes": b64(bytes) })
            }
        })
        .collect();
    json!({
        "epoch": unit.epoch,
        "commit": b64(&unit.commit),
        "drop_public_key": b64(&unit.drop_public_key),
        "welcome": unit.welcome.as_deref().map(b64),
        "epoch_link": unit.epoch_link.as_deref().map(b64),
        "key_history": key_history,
    })
    .to_string()
}

fn applied_json(applied: Applied) -> String {
    match applied {
        Applied::Replayed => json!({ "type": "replayed" }),
        Applied::Commit {
            epoch,
            self_removed,
        } => json!({ "type": "commit", "epoch": epoch, "self_removed": self_removed }),
        Applied::Proposal => json!({ "type": "proposal" }),
        Applied::KeyHistory => json!({ "type": "key_history" }),
        Applied::Skipped => json!({ "type": "skipped" }),
    }
    .to_string()
}

fn log_entry(text: &str) -> JsResult<LogEntry> {
    let value = parse_json(text)?;
    let kind = match member_str(&value, "kind")? {
        "commit" => EntryKind::Commit,
        "proposal" => EntryKind::Proposal,
        "key_history" => EntryKind::KeyHistory,
        "key_history_sealed" => EntryKind::KeyHistorySealed,
        _ => return Err(malformed()),
    };
    let drop_public_key = match value.get("drop_public_key") {
        None | Some(Value::Null) => None,
        Some(_) => Some(member_bytes(&value, "drop_public_key")?),
    };
    Ok(LogEntry {
        seq: member_u64(&value, "seq")?,
        kind,
        epoch: member_u64(&value, "epoch")?,
        bytes: member_bytes(&value, "bytes")?,
        drop_public_key,
    })
}

/// The MLS group of one scope (spec §2.8, §3, §7) with its key cache and
/// the epoch links added with `addLink`.
#[derive(Debug)]
#[wasm_bindgen(js_name = ScopeGroup)]
pub struct JsScopeGroup {
    group: ScopeGroup,
    links: Links,
}

impl JsScopeGroup {
    fn wrap(group: ScopeGroup) -> Self {
        Self {
            group,
            links: Links::default(),
        }
    }
}

#[wasm_bindgen(js_class = ScopeGroup)]
impl JsScopeGroup {
    /// Creates the group of `scope` at epoch 0 with `identity` as the only
    /// member, under a JSON history policy.
    pub fn create(
        identity: &JsIdentity,
        profile: &str,
        scope: &str,
        policy: &str,
    ) -> JsResult<JsScopeGroup> {
        let policy = policy_from_json(&parse_json(policy)?)?;
        let group = ScopeGroup::create(
            &identity.0,
            profile,
            scope,
            policy,
            MemoryKeyCache::default(),
        );
        Ok(Self::wrap(group.map_err(js_error)?))
    }

    /// Joins from a Welcome delivered with the `seq` of its commit.
    pub fn join(
        key_packages: &JsKeyPackageStore,
        profile: &str,
        scope: &str,
        welcome: &[u8],
        seq: u64,
    ) -> JsResult<JsScopeGroup> {
        let group = ScopeGroup::join(
            &key_packages.0,
            profile,
            scope,
            welcome,
            seq,
            MemoryKeyCache::default(),
        );
        Ok(Self::wrap(group.map_err(js_error)?))
    }

    /// The group state and its key cache as opaque bytes. They hold epoch
    /// secrets: the caller stores them encrypted at rest.
    pub fn snapshot(&self) -> JsResult<Vec<u8>> {
        let mut writer = Writer::default();
        writer
            .bytes(&self.group.snapshot().map_err(js_error)?)
            .map_err(js_error)?;
        let cache = self.group.history().cache();
        for epoch in cache.epochs() {
            let held = cache
                .get(epoch)
                .ok_or_else(|| js_error(GroupError::Storage))?;
            writer.u64(epoch);
            writer.bytes(&held.to_bytes()).map_err(js_error)?;
        }
        Ok(writer.finish())
    }

    /// A group from `snapshot` bytes.
    pub fn restore(snapshot: &[u8]) -> JsResult<JsScopeGroup> {
        let mut reader = Reader::new(snapshot);
        let group = reader.bytes().map_err(js_error)?;
        let mut cache = MemoryKeyCache::default();
        while !reader.is_empty() {
            let epoch = reader.u64().map_err(js_error)?;
            let held = CachedSecrets::from_bytes(&reader.bytes().map_err(js_error)?)
                .map_err(|_| js_error(GroupError::Storage))?;
            cache.put(epoch, held);
        }
        Ok(Self::wrap(
            ScopeGroup::restore(&group, cache).map_err(js_error)?,
        ))
    }

    /// The scope id.
    #[wasm_bindgen(getter)]
    pub fn scope(&self) -> String {
        self.group.scope().to_owned()
    }

    /// The profile id.
    #[wasm_bindgen(getter)]
    pub fn profile(&self) -> String {
        self.group.profile().to_owned()
    }

    /// The 32-byte group id.
    #[wasm_bindgen(getter, js_name = groupId)]
    pub fn group_id(&self) -> Vec<u8> {
        self.group.group_id().to_vec()
    }

    /// The current epoch.
    #[wasm_bindgen(getter)]
    pub fn epoch(&self) -> u64 {
        self.group.epoch()
    }

    /// The `seq` of the last applied log entry.
    #[wasm_bindgen(getter)]
    pub fn seq(&self) -> u64 {
        self.group.seq()
    }

    /// Whether this party still holds a leaf.
    #[wasm_bindgen(getter, js_name = isMember)]
    pub fn is_member(&self) -> bool {
        self.group.is_member()
    }

    /// Whether a commit awaits the DS answer.
    #[wasm_bindgen(getter, js_name = hasPendingCommit)]
    pub fn has_pending_commit(&self) -> bool {
        self.group.has_pending_commit()
    }

    /// The JSON history policy of the current epoch.
    pub fn policy(&self) -> JsResult<String> {
        Ok(policy_to_json(self.group.policy().map_err(js_error)?))
    }

    /// The members' Ed25519 public keys in leaf order, base64url.
    pub fn members(&self) -> Vec<String> {
        self.group
            .members()
            .iter()
            .map(|key| encode_b64url(key))
            .collect()
    }

    /// `k_e || d_e` of the current epoch.
    #[wasm_bindgen(js_name = currentSecrets)]
    pub fn current_secrets(&self) -> JsResult<Vec<u8>> {
        let (_, secrets) = self.group.current().map_err(js_error)?;
        Ok(secrets.to_bytes().to_vec())
    }

    /// The drop public key of the current epoch.
    #[wasm_bindgen(js_name = dropPublicKey)]
    pub fn drop_public_key(&self) -> JsResult<Vec<u8>> {
        Ok(self.group.drop_public_key().map_err(js_error)?.to_vec())
    }

    /// Adds the epoch link stored for `epoch`.
    #[wasm_bindgen(js_name = addLink)]
    pub fn add_link(&mut self, epoch: u64, link: Vec<u8>) {
        self.links.0.insert(epoch, link);
    }

    /// The epoch of the next link the walk to `epoch` needs, or `undefined`
    /// if the secrets of `epoch` are cached.
    #[wasm_bindgen(js_name = neededLink)]
    pub fn needed_link(&self, epoch: u64) -> JsResult<Option<u64>> {
        self.group.history().needed_link(epoch).map_err(js_error)
    }

    /// `k_e || d_e` of `epoch`, from the cache or the walk.
    pub fn secrets(&mut self, epoch: u64) -> JsResult<Vec<u8>> {
        let secrets = self.group.secrets(epoch, self.links.fetch());
        Ok(secrets.map_err(js_error)?.to_bytes().to_vec())
    }

    /// Opens a content, file or drop envelope at `location`.
    pub fn open(&mut self, envelope: &[u8], location_text: &str) -> JsResult<Vec<u8>> {
        let opened = self
            .group
            .open(envelope, &location(location_text)?, self.links.fetch());
        Ok(opened.map_err(js_error)?.plaintext)
    }

    /// Seals every mapped value of a JSON frame under the current epoch.
    #[wasm_bindgen(js_name = sealFrame)]
    pub fn seal_frame(&self, map: &JsFieldMap, frame_type: &str, frame: &str) -> JsResult<String> {
        let (epoch, secrets) = self.group.current().map_err(js_error)?;
        map.seal_frame(frame_type, frame, epoch, &secrets.content_key, None)
    }

    /// Opens every mapped value of a JSON frame.
    #[wasm_bindgen(js_name = openFrame)]
    pub fn open_frame(
        &mut self,
        map: &JsFieldMap,
        frame_type: &str,
        frame: &str,
    ) -> JsResult<String> {
        let frame = parse_json(frame)?;
        let links = &self.links;
        let group = &mut self.group;
        let opened = map.0.open_frame(frame_type, &frame, |envelope, location| {
            group
                .open(envelope, location, links.fetch())
                .map_err(|error| error.encryption_error().unwrap_or(Error::Malformed))
        });
        Ok(opened.map_err(js_error)?.to_string())
    }

    /// Commits the addition of the parties of base64url KeyPackages and
    /// returns the JSON commit unit. With `key_history_from`, key history
    /// from that epoch is attached for the joiners, sealed to each joiner's
    /// leaf if `key_history_sealed`.
    #[wasm_bindgen(js_name = addMembers)]
    pub fn add_members(
        &mut self,
        identity: &JsIdentity,
        key_packages: Vec<String>,
        key_history_from: Option<u64>,
        key_history_sealed: bool,
    ) -> JsResult<String> {
        let key_packages = key_packages
            .iter()
            .map(|text| decode_b64url(text))
            .collect::<Result<Vec<_>, _>>()
            .map_err(js_error)?;
        let offer = key_history_from.map(|from_epoch| KeyHistoryOffer {
            from_epoch,
            sealed: key_history_sealed,
        });
        let unit = self.group.add_members(&identity.0, &key_packages, offer);
        Ok(commit_unit_json(&unit.map_err(js_error)?))
    }

    /// Commits the removal of the members with the given base64url Ed25519
    /// public keys and returns the JSON commit unit.
    #[wasm_bindgen(js_name = removeMembers)]
    pub fn remove_members(
        &mut self,
        identity: &JsIdentity,
        public_keys: Vec<String>,
    ) -> JsResult<String> {
        let public_keys = public_keys
            .iter()
            .map(|text| key(&decode_b64url(text).map_err(js_error)?))
            .collect::<JsResult<Vec<_>>>()?;
        let unit = self.group.remove_members(&identity.0, &public_keys);
        Ok(commit_unit_json(&unit.map_err(js_error)?))
    }

    /// Commits an Update of this member's own leaf.
    #[wasm_bindgen(js_name = selfUpdate)]
    pub fn self_update(&mut self, identity: &JsIdentity) -> JsResult<String> {
        let unit = self.group.self_update(&identity.0);
        Ok(commit_unit_json(&unit.map_err(js_error)?))
    }

    /// Commits a new JSON history policy.
    #[wasm_bindgen(js_name = setPolicy)]
    pub fn set_policy(&mut self, identity: &JsIdentity, policy: &str) -> JsResult<String> {
        let policy = policy_from_json(&parse_json(policy)?)?;
        let unit = self.group.set_policy(&identity.0, policy);
        Ok(commit_unit_json(&unit.map_err(js_error)?))
    }

    /// The DS accepted the pending commit at `seq`: merges it.
    #[wasm_bindgen(js_name = commitAccepted)]
    pub fn commit_accepted(&mut self, seq: u64) -> JsResult<()> {
        self.group.commit_accepted(seq).map_err(js_error)
    }

    /// The DS rejected the pending commit: discards it.
    #[wasm_bindgen(js_name = commitRejected)]
    pub fn commit_rejected(&mut self) -> JsResult<()> {
        self.group.commit_rejected().map_err(js_error)
    }

    /// Applies the next JSON log entry `{"seq", "kind", "epoch", "bytes",
    /// "drop_public_key"?}` and returns the JSON effect.
    pub fn apply(&mut self, entry: &str) -> JsResult<String> {
        let applied = self.group.apply(&log_entry(entry)?);
        Ok(applied_json(applied.map_err(js_error)?))
    }
}

// ---------------------------------------------------------------------------
// Delivery Service inspection

fn inspect_error(error: InspectError) -> JsError {
    let detail = json!({ "code": error.error.code(), "reason": error.reason });
    JsError::new(&detail.to_string())
}

/// Validates an uploaded KeyPackage at `now` (seconds since the Unix epoch)
/// and returns JSON `{"ref", "public_key", "last_resort", "not_before",
/// "not_after"}`.
#[wasm_bindgen(js_name = inspectKeyPackage)]
pub fn inspect_key_package_js(bytes: &[u8], now: u64) -> JsResult<String> {
    let info = inspect_key_package(bytes, now).map_err(inspect_error)?;
    Ok(json!({
        "ref": b64(&info.reference),
        "public_key": b64(&info.public_key),
        "last_resort": info.last_resort,
        "not_before": info.not_before,
        "not_after": info.not_after,
    })
    .to_string())
}

/// Inspects a PublicMessage and returns JSON `{"group_id", "epoch",
/// "content_type", "sender_leaf", "adds", "removes", "proposal_refs",
/// "updates_path"}`.
#[wasm_bindgen(js_name = inspectMessage)]
pub fn inspect_message_js(bytes: &[u8]) -> JsResult<String> {
    let info = inspect_message(bytes).map_err(inspect_error)?;
    let refs = |refs: &[Vec<u8>]| refs.iter().map(|r| b64(r)).collect::<Vec<_>>();
    Ok(json!({
        "group_id": b64(&info.group_id),
        "epoch": info.epoch,
        "content_type": info.content_type.as_str(),
        "sender_leaf": info.sender_leaf,
        "adds": refs(&info.adds),
        "removes": info.removes,
        "proposal_refs": refs(&info.proposal_refs),
        "updates_path": info.updates_path,
    })
    .to_string())
}

/// The base64url `new_member` KeyPackageRefs of a Welcome, in order.
#[wasm_bindgen(js_name = welcomeRecipients)]
pub fn welcome_recipients_js(bytes: &[u8]) -> JsResult<Vec<String>> {
    let refs = welcome_recipients(bytes).map_err(inspect_error)?;
    Ok(refs.iter().map(|r| encode_b64url(r)).collect())
}
