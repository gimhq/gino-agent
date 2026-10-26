//! Canonical test vectors (spec §13).
//!
//! `generate` builds `docs/e2ee/test-vectors.json` from synthetic inputs and
//! injected randomness; `write_test_vectors` (ignored) writes it. The normal
//! tests check that the committed file equals the generator output and that
//! every vector verifies: positive vectors reproduce their envelopes and open
//! to their plaintexts, negative vectors fail with their codes.
//!
//! The crate seals drops with the provider's HPKE, which draws its own
//! ephemeral key. To make drop and key-history envelopes reproducible from
//! `ikm_e`, this file carries an RFC 9180 base-mode seal with an injected
//! ephemeral key; every such envelope is opened by the crate (provider HPKE).

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::too_many_lines
)]

#[path = "common/field_map_json.rs"]
mod field_map_json;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::PathBuf;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use gino_e2ee::{
    CachedSecrets, DropKeyPair, EnvelopeType, EpochSecrets, Error, FieldMap, Header, History,
    HistoryPolicy, KeyCache, KeyHistory, KeyHistoryEntry, Location, MemoryKeyCache, decode_b64url,
    decode_json, decode_text, encode_b64url, fingerprint, fingerprint_display, from_sealed_value,
    group_id, message_key, open_content, open_drop, open_epoch_link, open_file, seal_content,
    seal_epoch_link, seal_file, verify_drop_public_key,
};
use hkdf::Hkdf;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::random::OpenMlsRand;
use openmls_traits::types::{HpkeAeadType, HpkeConfig, HpkeKdfType, HpkeKemType};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

const SCOPE: &str = "t-1";
const PROFILE: &str = "gino.task-content.v1";
const CURRENT: u64 = 5;
const DROP_INFO: &[u8] = b"gino-e2ee/v1 drop";
const KEY_HISTORY_INFO: &[u8] = b"gino-e2ee/v1 key-history";
const HPKE: HpkeConfig = HpkeConfig(
    HpkeKemType::DhKem25519,
    HpkeKdfType::HkdfSha256,
    HpkeAeadType::AesGcm128,
);

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../docs/e2ee/test-vectors.json")
}

fn render(vectors: &Value) -> String {
    let mut text = serde_json::to_string_pretty(vectors).unwrap();
    text.push('\n');
    text
}

#[test]
#[ignore = "writes docs/e2ee/test-vectors.json"]
fn write_test_vectors() {
    std::fs::write(vectors_path(), render(&generate())).unwrap();
}

#[test]
fn committed_vectors_match_the_generator() {
    let committed = std::fs::read_to_string(vectors_path()).expect("committed test vectors");
    assert!(
        committed == render(&generate()),
        "docs/e2ee/test-vectors.json is stale; run `cargo test --test vectors -- --ignored write_test_vectors`"
    );
}

#[test]
fn committed_vectors_verify() {
    let committed = std::fs::read_to_string(vectors_path()).expect("committed test vectors");
    verify(&serde_json::from_str(&committed).unwrap());
}

#[test]
fn generated_vectors_verify() {
    verify(&generate());
}

// ---------------------------------------------------------------------------
// Injected randomness and synthetic inputs.

/// Returns preset bytes in order.
#[derive(Debug)]
struct FixedRandom(RefCell<Vec<u8>>);

#[derive(Debug, thiserror::Error)]
#[error("preset randomness exhausted")]
struct Exhausted;

impl FixedRandom {
    fn new(bytes: &[u8]) -> Self {
        Self(RefCell::new(bytes.to_vec()))
    }
}

impl OpenMlsRand for FixedRandom {
    type Error = Exhausted;

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Exhausted> {
        self.random_vec(N)?.try_into().map_err(|_| Exhausted)
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Exhausted> {
        let mut bytes = self.0.borrow_mut();
        if bytes.len() < len {
            return Err(Exhausted);
        }
        Ok(bytes.drain(..len).collect())
    }
}

fn synth(label: &str) -> [u8; 32] {
    Sha256::digest(format!("gino-e2ee test vector {label}")).into()
}

fn chain(epoch: u64) -> EpochSecrets {
    EpochSecrets {
        content_key: synth(&format!("k/{epoch}")),
        drop_seed: synth(&format!("d/{epoch}")),
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd hex length");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

fn loc(text: &str) -> Location {
    Location::parse(text).expect("valid location")
}

fn flip(bytes: &[u8], index: usize) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[index] ^= 0x01;
    out
}

fn set(bytes: &[u8], index: usize, value: u8) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[index] = value;
    out
}

fn policy_json(policy: HistoryPolicy) -> Value {
    match policy {
        HistoryPolicy::Full => json!("full"),
        HistoryPolicy::FromEpoch(n) => json!({ "from_epoch": n }),
        HistoryPolicy::FromJoin => json!("from_join"),
    }
}

fn secrets_json(epoch: u64, secrets: &EpochSecrets) -> Value {
    json!({ "epoch": epoch, "k": hex(&secrets.content_key), "d": hex(&secrets.drop_seed) })
}

// ---------------------------------------------------------------------------
// RFC 9180 base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM,
// with the ephemeral key pair derived from `ikm_e`.

fn labeled_extract(suite: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> Vec<u8> {
    let input = [b"HPKE-v1".as_slice(), suite, label, ikm].concat();
    Hkdf::<Sha256>::extract(Some(salt), &input).0.to_vec()
}

fn labeled_expand(suite: &[u8], prk: &[u8], label: &[u8], info: &[u8], len: u16) -> Vec<u8> {
    let info = [&len.to_be_bytes()[..], b"HPKE-v1", suite, label, info].concat();
    let mut out = vec![0u8; usize::from(len)];
    Hkdf::<Sha256>::from_prk(prk)
        .unwrap()
        .expand(&info, &mut out)
        .unwrap();
    out
}

/// Returns `enc || ciphertext || tag`.
fn hpke_seal(ikm_e: &[u8; 32], pk_r: &[u8], info: &[u8], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let ephemeral = RustCrypto::default()
        .derive_hpke_keypair(HPKE, ikm_e)
        .unwrap();
    let sk_e: [u8; 32] = ephemeral.private[..].try_into().unwrap();
    let pk_r: [u8; 32] = pk_r.try_into().unwrap();
    let dh = StaticSecret::from(sk_e).diffie_hellman(&PublicKey::from(pk_r));
    let enc = ephemeral.public;

    let kem_suite = b"KEM\x00\x20";
    let eae_prk = labeled_extract(kem_suite, b"", b"eae_prk", dh.as_bytes());
    let kem_context = [&enc[..], &pk_r].concat();
    let shared_secret = labeled_expand(kem_suite, &eae_prk, b"shared_secret", &kem_context, 32);

    let suite = b"HPKE\x00\x20\x00\x01\x00\x01";
    let psk_id_hash = labeled_extract(suite, b"", b"psk_id_hash", b"");
    let info_hash = labeled_extract(suite, b"", b"info_hash", info);
    let context = [&[0x00][..], &psk_id_hash, &info_hash].concat();
    let secret = labeled_extract(suite, &shared_secret, b"secret", b"");
    let key = labeled_expand(suite, &secret, b"key", &context, 16);
    let nonce = labeled_expand(suite, &secret, b"base_nonce", &context, 12);
    let ciphertext = Aes128Gcm::new_from_slice(&key)
        .unwrap()
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .unwrap();
    [enc, ciphertext].concat()
}

fn drop_envelope(
    ikm_e: &[u8; 32],
    pk: &[u8],
    epoch: u64,
    location: &Location,
    plaintext: &[u8],
) -> Vec<u8> {
    let header = Header::new(EnvelopeType::Drop, epoch).to_bytes();
    let aad = [&header[..], location.as_bytes()].concat();
    [
        header.to_vec(),
        hpke_seal(ikm_e, pk, DROP_INFO, &aad, plaintext),
    ]
    .concat()
}

fn key_history_sealed_envelope(
    ikm_e: &[u8; 32],
    history: &KeyHistory,
    scope: &str,
    leaf_index: u32,
    leaf_pk: &[u8],
) -> Vec<u8> {
    let header = Header::new(EnvelopeType::KeyHistorySealed, history.epoch).to_bytes();
    let location = Location::key_history(scope, history.epoch, leaf_index).unwrap();
    let aad = [&header[..], location.as_bytes()].concat();
    let entries = history.encode().unwrap()[12..].to_vec();
    [
        header.to_vec(),
        leaf_index.to_be_bytes().to_vec(),
        hpke_seal(ikm_e, leaf_pk, KEY_HISTORY_INFO, &aad, &entries),
    ]
    .concat()
}

fn drop_key_pair(seed: &[u8; 32]) -> DropKeyPair {
    DropKeyPair::derive(&RustCrypto::default(), seed).unwrap()
}

// ---------------------------------------------------------------------------
// Generator.

fn generate() -> Value {
    let mut negative = Vec::new();
    json!({
        "format": "gino-e2ee/test-vectors/v1",
        "envelope_version": 1,
        "suite": 1,
        "group_id": gen_group_id(),
        "fingerprint": gen_fingerprint(),
        "aad": gen_aad(&mut negative),
        "policy": gen_policy(&mut negative),
        "content": gen_content(&mut negative),
        "file": gen_file(&mut negative),
        "drop": gen_drop(&mut negative),
        "epoch_link": gen_epoch_link(&mut negative),
        "key_history": gen_key_history(&mut negative),
        "history_walk": gen_history_walk(&mut negative),
        "field_map": gen_field_map(),
        "negative": gen_wire_negative(negative),
    })
}

fn neg(section: &str, description: &str, input: Value, error: Error) -> Value {
    let mut vector = json!({
        "section": section,
        "description": description,
        "error": error.to_json(),
    });
    vector["input"] = input;
    vector
}

fn gen_group_id() -> Value {
    let cases = [(PROFILE, SCOPE), (PROFILE, "01jbx0q7m0v3k2m4n5p6q7r8s9")];
    cases
        .iter()
        .map(|(profile, scope)| {
            json!({
                "profile": profile,
                "scope": scope,
                "group_id": hex(&group_id(profile, scope).unwrap()),
            })
        })
        .collect()
}

fn gen_fingerprint() -> Value {
    ["ed25519/runner", "ed25519/client"]
        .iter()
        .map(|label| {
            let public_key = synth(label);
            json!({
                "public_key": hex(&public_key),
                "fingerprint": fingerprint(&public_key),
                "display": fingerprint_display(&public_key),
            })
        })
        .collect()
}

fn gen_aad(negative: &mut Vec<Value>) -> Value {
    let cases = [
        (
            "scope:{task_id}|frame:message|field:text",
            json!({ "type": "message", "task_id": SCOPE, "text": "hello" }),
            None,
        ),
        (
            "scope:{data.task_id}|frame:thread_message|thread:{data.thread_id}|seq:{data.seq}|field:input",
            json!({
                "type": "thread_message",
                "data": {
                    "task_id": SCOPE,
                    "thread_id": "01jbx0q7m0v3k2m4n5p6q7r8s9",
                    "seq": 7,
                    "input": "hello"
                }
            }),
            None,
        ),
        (
            "scope:{task_id}|frame:output|attachment:{data.attachments[].id}|field:bytes",
            json!({
                "type": "output",
                "task_id": SCOPE,
                "data": { "attachments": [ { "id": "a-0" }, { "id": "a-1" } ] }
            }),
            Some(1),
        ),
        (
            "scope:{task_id}|frame:result|delivery:{data.delivery}|seq:{data.seq}",
            json!({ "task_id": "task:42", "data": { "delivery": "d:1", "seq": 0 } }),
            None,
        ),
        (
            "scope:{scope}|epoch_link:8",
            json!({ "scope": SCOPE }),
            None,
        ),
    ];
    let mut vectors = Vec::new();
    for (template, frame, element) in cases {
        let location = Location::from_template(template, &frame, element).unwrap();
        let mut vector = json!({
            "template": template,
            "frame": frame,
            "location": location.as_str(),
        });
        if let Some(element) = element {
            vector["element"] = json!(element);
        }
        vectors.push(vector);
    }

    let frame = json!({
        "task_id": SCOPE,
        "pipe": "a|b",
        "negative": -1,
        "fraction": 1.5,
        "flag": true,
        "data": { "attachments": [ { "id": "a-0" } ] }
    });
    let bad = [
        (
            "a | in a placeholder value",
            "scope:{task_id}|thread:{pipe}",
        ),
        (
            "a missing placeholder value",
            "scope:{task_id}|thread:{absent}",
        ),
        ("an upper-case name", "scope:{task_id}|Field:text"),
        ("a negative integer", "scope:{task_id}|seq:{negative}"),
        ("a non-integer number", "scope:{task_id}|seq:{fraction}"),
        ("a boolean value", "scope:{task_id}|flag:{flag}"),
        ("an empty value", "scope:{task_id}|field:"),
        (
            "a scope part that is not first",
            "field:text|scope:{task_id}",
        ),
        (
            "an array placeholder without an element",
            "scope:{task_id}|attachment:{data.attachments[].id}",
        ),
    ];
    for (description, template) in bad {
        negative.push(neg(
            "aad",
            description,
            json!({ "template": template, "frame": frame }),
            Error::AadMismatch,
        ));
    }
    negative.push(neg(
        "aad",
        "an array element out of range",
        json!({
            "template": "scope:{task_id}|attachment:{data.attachments[].id}",
            "frame": frame,
            "element": 1,
        }),
        Error::AadMismatch,
    ));
    Value::Array(vectors)
}

fn gen_policy(negative: &mut Vec<Value>) -> Value {
    for (description, data) in [
        ("an unknown policy byte", "03"),
        ("from_epoch with a short epoch", "0100"),
        ("full with a trailing byte", "0000"),
        ("empty extension data", ""),
    ] {
        negative.push(neg(
            "policy",
            description,
            json!({ "extension_data": data }),
            Error::Malformed,
        ));
    }
    [
        HistoryPolicy::Full,
        HistoryPolicy::FromEpoch(3),
        HistoryPolicy::FromJoin,
    ]
    .iter()
    .map(|policy| {
        json!({
            "policy": policy_json(*policy),
            "extension_data": hex(&policy.encode()),
        })
    })
    .collect()
}

fn content_vector(
    k_e: &[u8; 32],
    epoch: u64,
    location: &str,
    plaintext: &[u8],
    salt: &[u8; 32],
) -> (Value, Vec<u8>) {
    let envelope = seal_content(
        k_e,
        epoch,
        &loc(location),
        plaintext,
        &FixedRandom::new(salt),
    )
    .unwrap();
    let vector = json!({
        "k_e": hex(k_e),
        "epoch": epoch,
        "salt": hex(salt),
        "location": location,
        "plaintext": hex(plaintext),
        "k_msg": hex(&message_key(k_e, salt).unwrap()),
        "envelope": hex(&envelope),
        "envelope_b64url": encode_b64url(&envelope),
    });
    (vector, envelope)
}

fn gen_content(negative: &mut Vec<Value>) -> Value {
    let message = "scope:t-1|frame:message|field:text";
    let thread =
        "scope:t-1|frame:thread_message|thread:01jbx0q7m0v3k2m4n5p6q7r8s9|seq:7|field:input";
    let k0 = chain(0).content_key;
    let (v1, envelope) = content_vector(&k0, 0, message, b"hello", &synth("salt/content/1"));
    let (v2, _) = content_vector(
        &chain(5).content_key,
        5,
        thread,
        b"",
        &synth("salt/content/2"),
    );
    let (v3, _) = content_vector(
        &synth("k/large"),
        (1 << 40) + 1,
        thread,
        br#"{"a":[1,"b"],"c":null}"#,
        &synth("salt/content/3"),
    );

    let input = |k_e: &[u8; 32], location: &str, envelope: &[u8]| json!({ "k_e": hex(k_e), "location": location, "envelope": hex(envelope) });
    let open_failed = Error::OpenFailed { epoch: 0 };
    let cases: Vec<(&str, Vec<u8>, Error)> = vec![
        (
            "flipped byte in the header epoch",
            flip(&envelope, 11),
            Error::OpenFailed { epoch: 1 },
        ),
        ("flipped byte in the salt", flip(&envelope, 12), open_failed),
        (
            "flipped byte in the ciphertext",
            flip(&envelope, 44),
            open_failed,
        ),
        (
            "flipped byte in the tag",
            flip(&envelope, envelope.len() - 1),
            open_failed,
        ),
        (
            "wrong version byte",
            set(&envelope, 0, 0x02),
            Error::UnsupportedVersion,
        ),
        (
            "reserved type 0x00",
            set(&envelope, 1, 0x00),
            Error::UnsupportedVersion,
        ),
        (
            "unknown type 0x07",
            set(&envelope, 1, 0x07),
            Error::UnsupportedVersion,
        ),
        (
            "wrong suite 0x0002",
            set(&envelope, 3, 0x02),
            Error::UnsupportedSuite,
        ),
        (
            "drop type where content is expected",
            set(&envelope, 1, 0x03),
            Error::Malformed,
        ),
        (
            "truncated below the minimum length",
            envelope[..59].to_vec(),
            Error::Malformed,
        ),
        (
            "truncated inside the header",
            envelope[..11].to_vec(),
            Error::Malformed,
        ),
    ];
    for (description, bytes, error) in cases {
        negative.push(neg(
            "content",
            description,
            input(&k0, message, &bytes),
            error,
        ));
    }
    negative.push(neg(
        "content",
        "wrong location",
        input(&k0, "scope:t-1|frame:message|field:title", &envelope),
        open_failed,
    ));
    negative.push(neg(
        "content",
        "wrong scope in the location",
        input(&k0, "scope:t-2|frame:message|field:text", &envelope),
        open_failed,
    ));
    negative.push(neg(
        "content",
        "key of another epoch",
        input(&chain(1).content_key, message, &envelope),
        open_failed,
    ));

    for (description, kind, plaintext) in [
        (
            "invalid UTF-8 after opening a text field",
            "text",
            &b"\xff\xfe"[..],
        ),
        (
            "invalid JSON after opening a json field",
            "json",
            &b"{\"a\":"[..],
        ),
        (
            "two JSON values after opening a json field",
            "json",
            &b"1 2"[..],
        ),
    ] {
        let sealed = seal_content(
            &k0,
            0,
            &loc(message),
            plaintext,
            &FixedRandom::new(&synth("salt/content/kind")),
        )
        .unwrap();
        let mut input = input(&k0, message, &sealed);
        input["kind"] = json!(kind);
        negative.push(neg("content", description, input, Error::Malformed));
    }
    json!([v1, v2, v3])
}

fn gen_file(negative: &mut Vec<Value>) -> Value {
    let location = "scope:t-1|frame:output|attachment:a-1|field:bytes";
    let mut vectors = Vec::new();
    let mut first = Vec::new();
    for (epoch, plaintext, salt) in [
        (3, (0..=255).collect::<Vec<u8>>(), synth("salt/file/1")),
        (0, Vec::new(), synth("salt/file/2")),
    ] {
        let k_e = chain(epoch).content_key;
        let sealed = seal_file(
            &k_e,
            epoch,
            &loc(location),
            &plaintext,
            &FixedRandom::new(&salt),
        )
        .unwrap();
        if first.is_empty() {
            first.clone_from(&sealed.envelope);
        }
        vectors.push(json!({
            "k_e": hex(&k_e),
            "epoch": epoch,
            "salt": hex(&salt),
            "location": location,
            "plaintext": hex(&plaintext),
            "envelope": hex(&sealed.envelope),
            "sha256": sealed.digest.sha256,
            "size": sealed.digest.size,
        }));
    }
    let k3 = hex(&chain(3).content_key);
    negative.push(neg(
        "file",
        "flipped byte in the tag",
        json!({ "k_e": k3, "location": location, "envelope": hex(&flip(&first, first.len() - 1)) }),
        Error::OpenFailed { epoch: 3 },
    ));
    negative.push(neg(
        "file",
        "content type where a file is expected",
        json!({ "k_e": k3, "location": location, "envelope": hex(&set(&first, 1, 0x01)) }),
        Error::Malformed,
    ));
    Value::Array(vectors)
}

fn gen_drop(negative: &mut Vec<Value>) -> Value {
    let location = "scope:t-1|frame:inbound|field:body";
    let mut vectors = Vec::new();
    let mut first = Vec::new();
    for (epoch, plaintext, ikm_label) in [
        (2, &b"synthetic webhook body"[..], "ikm_e/drop/1"),
        (0, &b""[..], "ikm_e/drop/2"),
    ] {
        let d_e = chain(epoch).drop_seed;
        let pair = drop_key_pair(&d_e);
        let ikm_e = synth(ikm_label);
        let envelope = drop_envelope(&ikm_e, pair.public_key(), epoch, &loc(location), plaintext);
        if first.is_empty() {
            first.clone_from(&envelope);
        }
        vectors.push(json!({
            "d_e": hex(&d_e),
            "sk": hex(pair.private_key()),
            "pk": hex(pair.public_key()),
            "epoch": epoch,
            "location": location,
            "plaintext": hex(plaintext),
            "ikm_e": hex(&ikm_e),
            "envelope": hex(&envelope),
        }));
    }
    let d2 = hex(&chain(2).drop_seed);
    let input = |d_e: &str, location: &str, envelope: &[u8]| json!({ "d_e": d_e, "location": location, "envelope": hex(envelope) });
    let failed = Error::OpenFailed { epoch: 2 };
    negative.push(neg(
        "drop",
        "wrong location",
        input(&d2, "scope:t-1|frame:inbound|field:subject", &first),
        failed,
    ));
    negative.push(neg(
        "drop",
        "seed of another epoch",
        input(&hex(&chain(3).drop_seed), location, &first),
        failed,
    ));
    negative.push(neg(
        "drop",
        "flipped byte in enc",
        input(&d2, location, &flip(&first, 12)),
        failed,
    ));
    negative.push(neg(
        "drop",
        "flipped byte in the tag",
        input(&d2, location, &flip(&first, first.len() - 1)),
        failed,
    ));
    negative.push(neg(
        "drop",
        "truncated below the minimum length",
        input(&d2, location, &first[..59]),
        Error::Malformed,
    ));
    negative.push(neg(
        "drop_key",
        "logged drop public key differs from the derived one",
        json!({
            "d_e": d2,
            "epoch": 2,
            "public_key": hex(drop_key_pair(&chain(3).drop_seed).public_key()),
        }),
        Error::DropKeyMismatch { epoch: 2 },
    ));
    Value::Array(vectors)
}

fn link(epoch: u64) -> Vec<u8> {
    seal_epoch_link(
        SCOPE,
        epoch,
        &chain(epoch),
        &chain(epoch + 1).content_key,
        &FixedRandom::new(&synth(&format!("salt/link/{epoch}"))),
    )
    .unwrap()
}

fn gen_epoch_link(negative: &mut Vec<Value>) -> Value {
    let vectors: Vec<Value> = (0..CURRENT)
        .map(|epoch| {
            let secrets = chain(epoch);
            json!({
                "epoch": epoch,
                "k_e": hex(&secrets.content_key),
                "d_e": hex(&secrets.drop_seed),
                "k_next": hex(&chain(epoch + 1).content_key),
                "salt": hex(&synth(&format!("salt/link/{epoch}"))),
                "scope": SCOPE,
                "envelope": hex(&link(epoch)),
            })
        })
        .collect();

    let link2 = link(2);
    let k3 = chain(3).content_key;
    let input = |scope: &str, epoch: u64, k_next: &[u8; 32], envelope: &[u8]| json!({ "scope": scope, "epoch": epoch, "k_next": hex(k_next), "envelope": hex(envelope) });
    let invalid = Error::LinkInvalid { epoch: 2 };
    let appended = [link2.clone(), vec![0]].concat();
    let cases: Vec<(&str, Value, Error)> = vec![
        (
            "flipped byte in the tag",
            input(SCOPE, 2, &k3, &flip(&link2, 123)),
            invalid,
        ),
        (
            "flipped byte in the salt",
            input(SCOPE, 2, &k3, &flip(&link2, 12)),
            invalid,
        ),
        (
            "one byte too long",
            input(SCOPE, 2, &k3, &appended),
            invalid,
        ),
        ("truncated", input(SCOPE, 2, &k3, &link2[..123]), invalid),
        ("wrong scope", input("t-2", 2, &k3, &link2), invalid),
        (
            "wrong next key",
            input(SCOPE, 2, &chain(4).content_key, &link2),
            invalid,
        ),
        (
            "link of another epoch",
            input(SCOPE, 3, &chain(4).content_key, &link2),
            Error::LinkInvalid { epoch: 3 },
        ),
        (
            "content type instead of epoch_link",
            input(SCOPE, 2, &k3, &set(&link2, 1, 0x01)),
            invalid,
        ),
        (
            "wrong suite",
            input(SCOPE, 2, &k3, &set(&link2, 3, 0x02)),
            invalid,
        ),
    ];
    for (description, input, error) in cases {
        negative.push(neg("epoch_link", description, input, error));
    }
    Value::Array(vectors)
}

fn entries(epochs: &[u64]) -> Vec<KeyHistoryEntry> {
    epochs
        .iter()
        .map(|&epoch| KeyHistoryEntry {
            epoch,
            secrets: chain(epoch),
        })
        .collect()
}

fn entries_json(history: &KeyHistory) -> Value {
    history
        .entries
        .iter()
        .map(|entry| {
            json!({
                "epoch": entry.epoch,
                "k": hex(&entry.secrets.content_key),
                "d": hex(&entry.secrets.drop_seed),
            })
        })
        .collect()
}

fn gen_key_history(negative: &mut Vec<Value>) -> Value {
    let history = KeyHistory {
        epoch: CURRENT,
        entries: entries(&[1, 3]),
    };
    let payload = history.encode().unwrap();
    let leaf = drop_key_pair(&synth("leaf/3"));
    let ikm_e = synth("ikm_e/key_history/1");
    let sealed = key_history_sealed_envelope(&ikm_e, &history, SCOPE, 3, leaf.public_key());
    let single = KeyHistory {
        epoch: 1,
        entries: entries(&[0]),
    };
    let vectors = json!([
        {
            "epoch": history.epoch,
            "entries": entries_json(&history),
            "payload": hex(&payload),
            "sealed": {
                "scope": SCOPE,
                "leaf_index": 3,
                "leaf_sk": hex(leaf.private_key()),
                "leaf_pk": hex(leaf.public_key()),
                "ikm_e": hex(&ikm_e),
                "envelope": hex(&sealed),
            }
        },
        {
            "epoch": single.epoch,
            "entries": entries_json(&single),
            "payload": hex(&single.encode().unwrap()),
        }
    ]);

    let header = Header::new(EnvelopeType::KeyHistory, CURRENT).to_bytes();
    let raw = |count: u32, epochs: &[u64]| {
        let mut bytes = [&header[..], &count.to_be_bytes()].concat();
        for &epoch in epochs {
            bytes.extend_from_slice(&epoch.to_be_bytes());
            bytes.extend_from_slice(&chain(epoch).content_key);
            bytes.extend_from_slice(&chain(epoch).drop_seed);
        }
        bytes
    };
    let cases: Vec<(&str, Vec<u8>, Error)> = vec![
        ("count zero", raw(0, &[]), Error::Malformed),
        (
            "count above the entries present",
            raw(2, &[1]),
            Error::Malformed,
        ),
        (
            "truncated entry",
            payload[..payload.len() - 1].to_vec(),
            Error::Malformed,
        ),
        (
            "epochs not increasing",
            raw(2, &[3, 1]),
            Error::LinkInvalid { epoch: CURRENT },
        ),
        (
            "repeated epoch",
            raw(2, &[1, 1]),
            Error::LinkInvalid { epoch: CURRENT },
        ),
        (
            "entry not below the message epoch",
            raw(1, &[CURRENT]),
            Error::LinkInvalid { epoch: CURRENT },
        ),
        (
            "sealed type where the payload is expected",
            set(&payload, 1, 0x06),
            Error::Malformed,
        ),
    ];
    for (description, bytes, error) in cases {
        negative.push(neg(
            "key_history",
            description,
            json!({ "payload": hex(&bytes) }),
            error,
        ));
    }
    let input = |scope: &str, leaf_index: u32, leaf_sk: &[u8], envelope: &[u8]| {
        json!({
            "scope": scope,
            "leaf_index": leaf_index,
            "leaf_sk": hex(leaf_sk),
            "envelope": hex(envelope),
        })
    };
    let other_leaf = drop_key_pair(&synth("leaf/4"));
    let failed = Error::OpenFailed { epoch: CURRENT };
    negative.push(neg(
        "key_history_sealed",
        "another leaf's private key",
        input(SCOPE, 3, other_leaf.private_key(), &sealed),
        failed,
    ));
    negative.push(neg(
        "key_history_sealed",
        "wrong scope",
        input("t-2", 3, leaf.private_key(), &sealed),
        failed,
    ));
    negative.push(neg(
        "key_history_sealed",
        "addressed to another leaf index",
        input(SCOPE, 4, leaf.private_key(), &sealed),
        Error::Malformed,
    ));
    negative.push(neg(
        "key_history_sealed",
        "flipped byte in the leaf index",
        input(SCOPE, 2, leaf.private_key(), &flip(&sealed, 15)),
        failed,
    ));
    vectors
}

/// Content envelopes of the walk scenarios, one per epoch, a drop of epoch 1
/// and a content envelope of the epoch after the current one.
struct WalkContent {
    epoch: u64,
    location: String,
    envelope: Vec<u8>,
    plaintext: Vec<u8>,
}

fn walk_content(epoch: u64) -> WalkContent {
    let location = format!("scope:t-1|frame:message|seq:{epoch}|field:text");
    let plaintext = format!("message of epoch {epoch}").into_bytes();
    let k_e = if epoch > CURRENT {
        synth(&format!("k/{epoch}"))
    } else {
        chain(epoch).content_key
    };
    let envelope = seal_content(
        &k_e,
        epoch,
        &loc(&location),
        &plaintext,
        &FixedRandom::new(&synth(&format!("salt/walk/{epoch}"))),
    )
    .unwrap();
    WalkContent {
        epoch,
        location,
        envelope,
        plaintext,
    }
}

fn walk_drop() -> WalkContent {
    let location = "scope:t-1|frame:inbound|seq:1|field:body".to_owned();
    let plaintext = b"drop of epoch 1".to_vec();
    let pair = drop_key_pair(&chain(1).drop_seed);
    let envelope = drop_envelope(
        &synth("ikm_e/walk/1"),
        pair.public_key(),
        1,
        &loc(&location),
        &plaintext,
    );
    WalkContent {
        epoch: 1,
        location,
        envelope,
        plaintext,
    }
}

/// Description, policy, stored links and content items with their expected
/// error.
type Scenario = (
    &'static str,
    HistoryPolicy,
    BTreeMap<u64, Vec<u8>>,
    Vec<(WalkContent, Option<Error>)>,
);

fn gen_history_walk(negative: &mut Vec<Value>) -> Value {
    let full: BTreeMap<u64, Vec<u8>> = (1..=CURRENT).map(|i| (i, link(i - 1))).collect();
    let only = |keep: &dyn Fn(u64) -> bool| -> BTreeMap<u64, Vec<u8>> {
        full.iter()
            .filter(|(i, _)| keep(**i))
            .map(|(i, l)| (*i, l.clone()))
            .collect()
    };
    let mut tampered = full.clone();
    tampered.insert(3, flip(&full[&3], 123));
    let mut wrong_secrets = full.clone();
    wrong_secrets.insert(
        3,
        seal_epoch_link(
            SCOPE,
            2,
            &EpochSecrets {
                content_key: synth("k/wrong"),
                drop_seed: synth("d/wrong"),
            },
            &chain(3).content_key,
            &FixedRandom::new(&synth("salt/link/wrong")),
        )
        .unwrap(),
    );

    let ok = |epoch: u64| (walk_content(epoch), None);
    let err = |epoch: u64, error: Error| (walk_content(epoch), Some(error));
    let unavailable = |epoch| Error::HistoryUnavailable { epoch };
    let invalid = |epoch| Error::LinkInvalid { epoch };
    let scenarios: Vec<Scenario> = vec![
        (
            "full: every epoch readable, the next epoch unknown",
            HistoryPolicy::Full,
            full.clone(),
            vec![
                ok(0),
                ok(1),
                ok(2),
                ok(3),
                ok(4),
                ok(5),
                (walk_drop(), None),
                err(6, Error::EpochUnknown { epoch: 6 }),
            ],
        ),
        (
            "from_epoch 3: links for transitions from epoch 3 on",
            HistoryPolicy::FromEpoch(3),
            only(&|i| HistoryPolicy::FromEpoch(3).links_transition(i - 1)),
            vec![
                err(0, unavailable(0)),
                err(2, unavailable(2)),
                ok(3),
                ok(4),
                ok(5),
            ],
        ),
        (
            "from_join: no links",
            HistoryPolicy::FromJoin,
            BTreeMap::new(),
            vec![err(4, unavailable(4)), ok(5)],
        ),
        (
            "full with the link for epoch 3 missing",
            HistoryPolicy::Full,
            only(&|i| i != 3),
            vec![err(1, unavailable(1)), err(2, unavailable(2)), ok(3), ok(5)],
        ),
        (
            "full with the link for epoch 3 tampered",
            HistoryPolicy::Full,
            tampered,
            vec![err(2, invalid(2)), err(0, invalid(0)), ok(3)],
        ),
        (
            "full with the link for epoch 3 carrying wrong secrets",
            HistoryPolicy::Full,
            wrong_secrets,
            vec![err(2, invalid(2)), err(1, invalid(1)), ok(3)],
        ),
    ];

    let mut vectors = Vec::new();
    for (description, policy, links, contents) in scenarios {
        let links_json: serde_json::Map<String, Value> = links
            .iter()
            .map(|(i, l)| (i.to_string(), json!(hex(l))))
            .collect();
        let content: Vec<Value> = contents
            .iter()
            .map(|(item, error)| {
                let mut entry = json!({
                    "epoch": item.epoch,
                    "location": item.location,
                    "envelope": hex(&item.envelope),
                });
                match error {
                    Some(error) => entry["error"] = error.to_json(),
                    None => entry["plaintext"] = json!(hex(&item.plaintext)),
                }
                entry
            })
            .collect();
        let vector = json!({
            "description": description,
            "scope": SCOPE,
            "policy": policy_json(policy),
            "current": secrets_json(CURRENT, &chain(CURRENT)),
            "links": links_json,
            "content": content,
        });
        if description.contains("missing") || description.contains("tampered") {
            let (item, error) = &contents[1];
            negative.push(neg(
                "history_walk",
                description,
                json!({
                    "scope": SCOPE,
                    "current": vector["current"],
                    "links": vector["links"],
                    "location": item.location,
                    "envelope": hex(&item.envelope),
                }),
                error.expect("negative walk entry"),
            ));
        }
        vectors.push(vector);
    }
    Value::Array(vectors)
}

// ---------------------------------------------------------------------------
// Field maps (spec §12): whole frames sealed with the profile's map or an
// inline one.

const THREAD: &str = "01jbx0q7m0v3k2m4n5p6q7r8s9";

/// An inline map with keyed plain paths, since the task-content table is empty.
fn split_map_json() -> Value {
    json!({
        "format": "gino-e2ee/field-map/v1",
        "profile": "test.split.v1",
        "frames": {
            "action": {
                "direction": "agent_to_host",
                "scope": "taskId",
                "fields": [{
                    "path": "data.input.params",
                    "kind": "json",
                    "envelopes": ["content"],
                    "aad": "scope:{taskId}|frame:action|seq:{data.seq}|field:input.params",
                    "keyed_plain": {
                        "key": "data.input.method",
                        "table": {
                            "form.submit": ["fields.title", "labels[]"],
                            "items.tag": ["items[].id"],
                            "noop": []
                        }
                    }
                }]
            }
        }
    })
}

fn fm_attachment(sha: char, name: Option<&str>) -> Value {
    let sha256 = sha.to_string().repeat(64);
    let mut descriptor = json!({
        "id": format!("att-{sha}"),
        "content_type": "application/octet-stream",
        "size": 120,
        "sha256": sha256,
        "ref": format!("{sha256}.bin"),
        "direction": "in",
    });
    if let Some(name) = name {
        descriptor["name"] = json!(name);
    }
    descriptor
}

fn fm_thread_message(seq: u64, mut data: Value) -> Value {
    data["seq"] = json!(seq);
    json!({ "type": "thread_message", "outboxId": "01jab3x7k2m4n5p6q7r8s9t0vw", "taskId": SCOPE, "threadId": THREAD, "data": data })
}

fn fm_thread_result(data: &Value) -> Value {
    json!({ "type": "thread_result", "outboxId": "01jab3x7k2m4n5p6q7r8s9t0vx", "taskId": SCOPE, "threadId": THREAD, "data": data })
}

fn fm_action(method: &str, params: &Value) -> Value {
    json!({ "type": "action", "taskId": SCOPE, "data": { "seq": 3, "input": { "method": method, "params": params } } })
}

/// The secrets of the field-map vectors: the current epoch only.
fn fm_secrets() -> Value {
    let secrets = chain(CURRENT);
    let mut by_epoch = serde_json::Map::new();
    by_epoch.insert(
        CURRENT.to_string(),
        json!({ "k": hex(&secrets.content_key), "d": hex(&secrets.drop_seed) }),
    );
    Value::Object(by_epoch)
}

fn fm_map(map: Option<&Value>) -> &'static FieldMap {
    match map {
        Some(map) => field_map_json::parse(map),
        None => FieldMap::for_profile(PROFILE).expect("profile map"),
    }
}

fn fm_salts(label: &str, count: usize) -> Vec<[u8; 32]> {
    (0..count)
        .map(|i| synth(&format!("field_map/{label}/{i}")))
        .collect()
}

fn fm_seal(map: &FieldMap, frame: &Value, salts: &[[u8; 32]]) -> Result<Value, Error> {
    let rng = FixedRandom::new(&salts.concat());
    let sealed = map.seal_frame(
        text(frame, "type"),
        frame,
        CURRENT,
        &chain(CURRENT).content_key,
        &rng,
    )?;
    assert!(rng.random_vec(1).is_err(), "every salt is consumed");
    Ok(sealed)
}

/// Counts the sealed forms in a value.
fn fm_sealed_count(value: &Value) -> usize {
    match value {
        Value::Object(object)
            if object.len() == 1 && object.get("e2ee").is_some_and(Value::is_string) =>
        {
            1
        }
        Value::Object(object) => object.values().map(fm_sealed_count).sum(),
        Value::Array(items) => items.iter().map(fm_sealed_count).sum(),
        _ => 0,
    }
}

fn gen_field_map() -> Value {
    let split = split_map_json();
    let positive: Vec<(&str, Option<&Value>, Value, usize)> = vec![
        (
            "message with text and attachments, one without a name",
            None,
            json!({
                "type": "message",
                "taskId": SCOPE,
                "data": {
                    "text": "summarize the report",
                    "attachments": [fm_attachment('a', Some("report.pdf")), fm_attachment('b', None), fm_attachment('c', Some("notes.txt"))]
                }
            }),
            3,
        ),
        (
            "message without attachments",
            None,
            json!({ "type": "message", "taskId": SCOPE, "data": { "text": "hello" } }),
            1,
        ),
        (
            "cron_upsert prompt",
            None,
            json!({ "type": "cron_upsert", "taskId": SCOPE, "cronId": "cr-1", "data": { "prompt": "daily digest", "schedule": "0 9 * * *" } }),
            1,
        ),
        (
            "thread_message text",
            None,
            fm_thread_message(
                1,
                json!({ "kind": "text", "role": "assistant", "content": "Done." }),
            ),
            1,
        ),
        (
            "thread_message tool_use input",
            None,
            fm_thread_message(
                2,
                json!({ "kind": "tool_use", "tool": "bash", "tool_use_id": "tu-1", "input": { "command": "ls -la", "timeout": 30 } }),
            ),
            1,
        ),
        (
            "thread_message tool_result output content",
            None,
            fm_thread_message(
                3,
                json!({ "kind": "tool_result", "tool_use_id": "tu-1", "output": { "is_error": false, "content": [{ "type": "text", "text": "a b c" }] } }),
            ),
            1,
        ),
        (
            "thread_message host_action params sealed whole (empty table)",
            None,
            fm_thread_message(
                4,
                json!({ "kind": "host_action", "content": "setting status", "input": { "method": "issue.set_status", "params": { "issue_id": "i-1", "status": "done" } } }),
            ),
            2,
        ),
        (
            "thread_result with result, null error and an attachment",
            None,
            fm_thread_result(
                &json!({ "status": "succeeded", "result": "All tests pass.", "error": null, "duration_ms": 1200, "attachments": [fm_attachment('d', Some("out.log"))] }),
            ),
            2,
        ),
        (
            "thread_result failure",
            None,
            fm_thread_result(
                &json!({ "status": "failed", "failure_reason": "agent.crash", "error": "boom" }),
            ),
            1,
        ),
        (
            "frame type without rules",
            None,
            json!({ "type": "heartbeat", "taskId": SCOPE, "data": { "text": "plain" } }),
            0,
        ),
        (
            "split value with nested plain paths",
            Some(&split),
            fm_action(
                "form.submit",
                &json!({ "fields": { "title": "T", "body": "B" }, "labels": ["a", "b"], "note": "N", "empty": {} }),
            ),
            3,
        ),
        (
            "split value with an element plain path",
            Some(&split),
            fm_action(
                "items.tag",
                &json!({ "items": [{ "id": "1", "x": "y" }, { "id": "2" }] }),
            ),
            1,
        ),
        (
            "split value with a scalar at a descend position",
            Some(&split),
            fm_action("form.submit", &json!({ "fields": "scalar", "labels": {} })),
            2,
        ),
        (
            "non-object value of a split rule sealed whole",
            Some(&split),
            fm_action("form.submit", &json!(["a", "b"])),
            1,
        ),
        (
            "method not in the table sealed whole",
            Some(&split),
            fm_action("unknown", &json!({ "fields": { "title": "T" } })),
            1,
        ),
        (
            "method with no plain paths sealed whole",
            Some(&split),
            fm_action("noop", &json!({ "fields": { "title": "T" } })),
            1,
        ),
    ];

    let mut vectors = Vec::new();
    let mut sealed_by_label = BTreeMap::new();
    for (i, (description, map, frame, count)) in positive.into_iter().enumerate() {
        let salts = fm_salts(&i.to_string(), count);
        let sealed = fm_seal(fm_map(map), &frame, &salts).unwrap();
        assert_eq!(fm_sealed_count(&sealed), count, "{description}");
        let mut vector = json!({
            "description": description,
            "profile": map.map_or(PROFILE, |m| m["profile"].as_str().unwrap()),
            "frame": frame,
            "secrets": fm_secrets(),
            "salts": salts.iter().map(|s| hex(s)).collect::<Vec<_>>(),
            "sealed_frame": sealed,
        });
        if let Some(map) = map {
            vector["map"] = map.clone();
        }
        sealed_by_label.insert(description, (frame, sealed));
        vectors.push(vector);
    }

    let negative = |description: &str,
                    map: Option<&Value>,
                    frame: &Value,
                    sealed: Option<Value>,
                    error: Error| {
        let mut vector = json!({
            "description": description,
            "profile": map.map_or(PROFILE, |m| m["profile"].as_str().unwrap()),
            "frame": frame,
            "secrets": fm_secrets(),
            "salts": [],
            "sealed_frame": sealed,
            "error": error.to_json(),
        });
        if let Some(map) = map {
            vector["map"] = map.clone();
        }
        vector
    };
    let take = |label: &str| sealed_by_label[label].clone();
    let failed = Error::OpenFailed { epoch: CURRENT };

    let (frame, sealed) = take("message without attachments");
    let mut plain = sealed.clone();
    plain["data"]["text"] = json!("hello");
    vectors.push(negative(
        "plaintext in a mapped field",
        None,
        &frame,
        Some(plain),
        Error::PlaintextRejected,
    ));
    let mut extra = sealed.clone();
    extra["data"]["text"]["kind"] = json!("text");
    vectors.push(negative(
        "sealed form with extra members",
        None,
        &frame,
        Some(extra),
        Error::Malformed,
    ));
    let mut tampered = sealed.clone();
    let mut envelope = decode_b64url(sealed["data"]["text"]["e2ee"].as_str().unwrap()).unwrap();
    let last = envelope.len() - 1;
    envelope[last] ^= 1;
    tampered["data"]["text"]["e2ee"] = json!(encode_b64url(&envelope));
    vectors.push(negative(
        "flipped tag byte",
        None,
        &frame,
        Some(tampered),
        failed,
    ));
    let file = seal_file(
        &chain(CURRENT).content_key,
        CURRENT,
        &loc(&format!("scope:{SCOPE}|frame:message|field:text")),
        b"hello",
        &FixedRandom::new(&synth("field_map/file")),
    )
    .unwrap();
    let mut wrong_type = sealed.clone();
    wrong_type["data"]["text"]["e2ee"] = json!(encode_b64url(&file.envelope));
    vectors.push(negative(
        "file envelope at a text field",
        None,
        &frame,
        Some(wrong_type),
        Error::Malformed,
    ));

    let (frame, sealed) = take("thread_message text");
    let mut moved = sealed.clone();
    moved["data"]["seq"] = json!(2);
    let mut moved_frame = frame.clone();
    moved_frame["data"]["seq"] = json!(2);
    vectors.push(negative(
        "ciphertext moved to another seq",
        None,
        &moved_frame,
        Some(moved),
        failed,
    ));
    let mut pipe = frame.clone();
    pipe["threadId"] = json!("c|9");
    vectors.push(negative(
        "a | in a placeholder value",
        None,
        &pipe,
        None,
        Error::AadMismatch,
    ));

    let (frame, _) = take("thread_result failure");
    let mut partial = fm_seal(
        fm_map(None),
        &fm_thread_result(&json!({ "status": "failed", "result": "partial", "error": "boom" })),
        &fm_salts("partial", 2),
    )
    .unwrap();
    let mut envelope = decode_b64url(partial["data"]["error"]["e2ee"].as_str().unwrap()).unwrap();
    envelope[20] ^= 1;
    partial["data"]["error"]["e2ee"] = json!(encode_b64url(&envelope));
    let mut partial_frame = frame.clone();
    partial_frame["data"]["result"] = json!("partial");
    vectors.push(negative(
        "one field fails, nothing is opened",
        None,
        &partial_frame,
        Some(partial),
        failed,
    ));

    let (frame, sealed) = take("split value with nested plain paths");
    let mut plain_part = sealed.clone();
    plain_part["data"]["input"]["params"]["note"] = json!("N");
    vectors.push(negative(
        "plaintext part at a sealed position",
        Some(&split),
        &frame,
        Some(plain_part),
        Error::PlaintextRejected,
    ));
    let mut whole = sealed.clone();
    whole["data"]["input"]["method"] = json!("unknown");
    let mut whole_frame = frame.clone();
    whole_frame["data"]["input"]["method"] = json!("unknown");
    vectors.push(negative(
        "split value for a discriminator that selects whole sealing",
        Some(&split),
        &whole_frame,
        Some(whole),
        Error::PlaintextRejected,
    ));
    let dotted = fm_action(
        "form.submit",
        &json!({ "fields": { "title": "T" }, "a.b": "v" }),
    );
    vectors.push(negative(
        "a key with . on a concrete path (sealing)",
        Some(&split),
        &dotted,
        None,
        Error::AadMismatch,
    ));
    let mut forged = sealed.clone();
    forged["data"]["input"]["params"]["a|b"] = sealed["data"]["input"]["params"]["note"].clone();
    vectors.push(negative(
        "a key with | on a concrete path (reading)",
        Some(&split),
        &frame,
        Some(forged),
        Error::AadMismatch,
    ));

    Value::Array(vectors)
}

fn verify_field_map(v: &Value) {
    let map = fm_map(v.get("map"));
    let frame = get(v, "frame");
    let frame_type = text(frame, "type");
    let scope = map
        .frame(frame_type)
        .and_then(|rule| frame.get(rule.scope))
        .and_then(Value::as_str)
        .unwrap_or(SCOPE);
    let secrets: BTreeMap<u64, EpochSecrets> = get(v, "secrets")
        .as_object()
        .expect("secrets object")
        .iter()
        .map(|(epoch, s)| {
            let secrets = EpochSecrets {
                content_key: key(s, "k"),
                drop_seed: key(s, "d"),
            };
            (epoch.parse().expect("epoch key"), secrets)
        })
        .collect();
    let (&current, current_secrets) = secrets.last_key_value().expect("current epoch");
    let mut cache = MemoryKeyCache::default();
    for (epoch, secrets) in &secrets {
        cache.put(
            *epoch,
            CachedSecrets {
                secrets: secrets.clone(),
                verified: true,
            },
        );
    }
    let mut history = History::with_cache(scope, current, current_secrets.clone(), cache).unwrap();
    let crypto = RustCrypto::default();
    let mut open = |sealed: &Value| {
        map.open_frame(frame_type, sealed, |envelope, location| {
            history.open(&crypto, envelope, location, |_| None)
        })
    };
    let salts: Vec<u8> = array(v, "salts")
        .iter()
        .flat_map(|s| unhex(s.as_str().expect("hex")))
        .collect();
    let sealed = get(v, "sealed_frame");
    let description = text(v, "description");
    match v.get("error") {
        None => {
            let rng = FixedRandom::new(&salts);
            let resealed = map.seal_frame(
                frame_type,
                frame,
                current,
                &current_secrets.content_key,
                &rng,
            );
            assert_eq!(&resealed.unwrap(), sealed, "{description}");
            assert_eq!(&open(sealed).unwrap(), frame, "{description}");
        }
        Some(expected) => {
            let error = if sealed.is_null() {
                let rng = FixedRandom::new(&salts);
                map.seal_frame(
                    frame_type,
                    frame,
                    current,
                    &current_secrets.content_key,
                    &rng,
                )
                .expect_err(description)
            } else {
                open(sealed).expect_err(description)
            };
            assert!(
                error_matches(&error, expected),
                "{description}: got {error}, expected {expected}"
            );
        }
    }
}

fn gen_wire_negative(mut negative: Vec<Value>) -> Value {
    for (description, text) in [
        ("padding", "AQ=="),
        ("non-zero trailing bits", "AR"),
        ("whitespace", "AQ "),
        ("standard-alphabet characters", "+/8"),
        ("impossible length", "AQIDB"),
    ] {
        negative.push(neg(
            "base64url",
            description,
            json!({ "text": text }),
            Error::Malformed,
        ));
    }
    for (description, value, error) in [
        (
            "plaintext string in a mapped field",
            json!("hello"),
            Error::PlaintextRejected,
        ),
        (
            "plaintext object in a mapped field",
            json!({ "text": "hello" }),
            Error::PlaintextRejected,
        ),
        (
            "sealed form with extra members",
            json!({ "e2ee": "AQID", "kind": "text" }),
            Error::Malformed,
        ),
        (
            "sealed form with a non-string e2ee",
            json!({ "e2ee": 1 }),
            Error::Malformed,
        ),
        (
            "sealed form with padded base64url",
            json!({ "e2ee": "AQ==" }),
            Error::Malformed,
        ),
    ] {
        negative.push(neg(
            "sealed_form",
            description,
            json!({ "value": value }),
            error,
        ));
    }
    Value::Array(negative)
}

// ---------------------------------------------------------------------------
// Verifier: reads only the JSON and the crate's public API.

fn get<'a>(value: &'a Value, key: &str) -> &'a Value {
    value
        .get(key)
        .unwrap_or_else(|| panic!("missing `{key}` in {value}"))
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    get(value, key).as_str().expect("string")
}

fn number(value: &Value, key: &str) -> u64 {
    get(value, key).as_u64().expect("integer")
}

fn bytes(value: &Value, key: &str) -> Vec<u8> {
    unhex(text(value, key))
}

fn key(value: &Value, key: &str) -> [u8; 32] {
    bytes(value, key).try_into().expect("32-byte key")
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    get(value, key).as_array().expect("array")
}

fn parse_policy(value: &Value) -> HistoryPolicy {
    match value {
        Value::String(s) if s == "full" => HistoryPolicy::Full,
        Value::String(s) if s == "from_join" => HistoryPolicy::FromJoin,
        Value::Object(_) => HistoryPolicy::FromEpoch(number(value, "from_epoch")),
        _ => panic!("bad policy {value}"),
    }
}

fn error_matches(error: &Error, expected: &Value) -> bool {
    error.to_json() == *expected
}

fn walk_history(vector: &Value) -> (History, BTreeMap<u64, Vec<u8>>) {
    let current = get(vector, "current");
    let history = History::new(
        text(vector, "scope"),
        number(current, "epoch"),
        EpochSecrets {
            content_key: key(current, "k"),
            drop_seed: key(current, "d"),
        },
    )
    .unwrap();
    let links = get(vector, "links")
        .as_object()
        .expect("links object")
        .iter()
        .map(|(epoch, link)| {
            (
                epoch.parse().expect("epoch key"),
                unhex(link.as_str().expect("hex")),
            )
        })
        .collect();
    (history, links)
}

fn verify(vectors: &Value) {
    let crypto = RustCrypto::default();
    assert_eq!(text(vectors, "format"), "gino-e2ee/test-vectors/v1");
    assert_eq!(number(vectors, "envelope_version"), 1);
    assert_eq!(number(vectors, "suite"), 1);

    for v in array(vectors, "group_id") {
        let id = group_id(text(v, "profile"), text(v, "scope")).unwrap();
        assert_eq!(hex(&id), text(v, "group_id"));
    }
    for v in array(vectors, "fingerprint") {
        let public_key = key(v, "public_key");
        assert_eq!(fingerprint(&public_key), text(v, "fingerprint"));
        assert_eq!(fingerprint_display(&public_key), text(v, "display"));
    }
    for v in array(vectors, "aad") {
        let element = v
            .get("element")
            .map(|e| usize::try_from(e.as_u64().unwrap()).unwrap());
        let location = Location::from_template(text(v, "template"), get(v, "frame"), element);
        assert_eq!(location.unwrap().as_str(), text(v, "location"));
    }
    for v in array(vectors, "policy") {
        let policy = parse_policy(get(v, "policy"));
        assert_eq!(policy.encode(), bytes(v, "extension_data"));
        assert_eq!(
            HistoryPolicy::decode(&bytes(v, "extension_data")),
            Ok(policy)
        );
    }
    for v in array(vectors, "content") {
        let (k_e, salt, location) = (key(v, "k_e"), key(v, "salt"), loc(text(v, "location")));
        let envelope = bytes(v, "envelope");
        assert_eq!(
            message_key(&k_e, &salt).unwrap().to_vec(),
            bytes(v, "k_msg")
        );
        let sealed = seal_content(
            &k_e,
            number(v, "epoch"),
            &location,
            &bytes(v, "plaintext"),
            &FixedRandom::new(&salt),
        );
        assert_eq!(sealed.unwrap(), envelope);
        assert_eq!(encode_b64url(&envelope), text(v, "envelope_b64url"));
        assert_eq!(decode_b64url(text(v, "envelope_b64url")).unwrap(), envelope);
        assert_eq!(
            open_content(&k_e, &envelope, &location).unwrap(),
            bytes(v, "plaintext")
        );
    }
    for v in array(vectors, "file") {
        let (k_e, location) = (key(v, "k_e"), loc(text(v, "location")));
        let sealed = seal_file(
            &k_e,
            number(v, "epoch"),
            &location,
            &bytes(v, "plaintext"),
            &FixedRandom::new(&key(v, "salt")),
        )
        .unwrap();
        assert_eq!(sealed.envelope, bytes(v, "envelope"));
        assert_eq!(sealed.digest.sha256, text(v, "sha256"));
        assert_eq!(sealed.digest.size, number(v, "size"));
        assert_eq!(
            open_file(&k_e, &sealed.envelope, &location).unwrap(),
            bytes(v, "plaintext")
        );
    }
    for v in array(vectors, "drop") {
        let (d_e, location) = (key(v, "d_e"), loc(text(v, "location")));
        let pair = DropKeyPair::derive(&crypto, &d_e).unwrap();
        assert_eq!(pair.private_key(), bytes(v, "sk"));
        assert_eq!(pair.public_key().to_vec(), bytes(v, "pk"));
        let envelope = bytes(v, "envelope");
        let reproduced = drop_envelope(
            &key(v, "ikm_e"),
            pair.public_key(),
            number(v, "epoch"),
            &location,
            &bytes(v, "plaintext"),
        );
        assert_eq!(reproduced, envelope);
        assert_eq!(
            open_drop(&crypto, &d_e, &envelope, &location).unwrap(),
            bytes(v, "plaintext")
        );
    }
    for v in array(vectors, "epoch_link") {
        let secrets = EpochSecrets {
            content_key: key(v, "k_e"),
            drop_seed: key(v, "d_e"),
        };
        let (scope, epoch, k_next) = (text(v, "scope"), number(v, "epoch"), key(v, "k_next"));
        let sealed = seal_epoch_link(
            scope,
            epoch,
            &secrets,
            &k_next,
            &FixedRandom::new(&key(v, "salt")),
        );
        assert_eq!(sealed.unwrap(), bytes(v, "envelope"));
        assert_eq!(
            open_epoch_link(scope, epoch, &k_next, &bytes(v, "envelope")).unwrap(),
            secrets
        );
    }
    for v in array(vectors, "key_history") {
        let history = KeyHistory {
            epoch: number(v, "epoch"),
            entries: array(v, "entries")
                .iter()
                .map(|e| KeyHistoryEntry {
                    epoch: number(e, "epoch"),
                    secrets: EpochSecrets {
                        content_key: key(e, "k"),
                        drop_seed: key(e, "d"),
                    },
                })
                .collect(),
        };
        assert_eq!(history.encode().unwrap(), bytes(v, "payload"));
        assert_eq!(KeyHistory::decode(&bytes(v, "payload")).unwrap(), history);
        if let Some(sealed) = v.get("sealed") {
            let (scope, envelope) = (text(sealed, "scope"), bytes(sealed, "envelope"));
            let leaf_index = u32::try_from(number(sealed, "leaf_index")).unwrap();
            let reproduced = key_history_sealed_envelope(
                &key(sealed, "ikm_e"),
                &history,
                scope,
                leaf_index,
                &bytes(sealed, "leaf_pk"),
            );
            assert_eq!(reproduced, envelope);
            let opened = KeyHistory::open_sealed(
                &crypto,
                scope,
                leaf_index,
                &bytes(sealed, "leaf_sk"),
                &envelope,
            );
            assert_eq!(opened.unwrap(), history);
        }
    }
    for v in array(vectors, "history_walk") {
        parse_policy(get(v, "policy"));
        let (mut history, links) = walk_history(v);
        for item in array(v, "content") {
            let envelope = bytes(item, "envelope");
            assert_eq!(
                Header::parse(&envelope).unwrap().epoch,
                number(item, "epoch")
            );
            let result = history.open(&crypto, &envelope, &loc(text(item, "location")), |i| {
                links.get(&i).cloned()
            });
            match (result, item.get("error")) {
                (Ok(opened), None) => assert_eq!(opened.plaintext, bytes(item, "plaintext")),
                (Err(error), Some(expected)) => assert!(
                    error_matches(&error, expected),
                    "{error} vs {expected} in {}",
                    text(v, "description")
                ),
                (result, _) => panic!("unexpected {result:?} for {item}"),
            }
        }
    }
    for v in array(vectors, "field_map") {
        verify_field_map(v);
    }
    for v in array(vectors, "negative") {
        let section = text(v, "section");
        let result = run_negative(&crypto, section, get(v, "input"));
        let expected = get(v, "error");
        match result {
            Err(error) => assert!(
                error_matches(&error, expected),
                "{section}: {}: got {error}, expected {expected}",
                text(v, "description")
            ),
            Ok(()) => panic!("{section}: {} succeeded", text(v, "description")),
        }
    }
}

fn run_negative(crypto: &RustCrypto, section: &str, input: &Value) -> Result<(), Error> {
    let envelope = || bytes(input, "envelope");
    let location = || loc(text(input, "location"));
    match section {
        "aad" => {
            let element = input
                .get("element")
                .map(|e| usize::try_from(e.as_u64().unwrap()).unwrap());
            Location::from_template(text(input, "template"), get(input, "frame"), element)
                .map(|_| ())
        }
        "policy" => HistoryPolicy::decode(&bytes(input, "extension_data")).map(|_| ()),
        "content" => {
            let plaintext = open_content(&key(input, "k_e"), &envelope(), &location())?;
            match input.get("kind").and_then(Value::as_str) {
                Some("text") => decode_text(plaintext).map(|_| ()),
                Some("json") => decode_json(&plaintext).map(|_| ()),
                _ => Ok(()),
            }
        }
        "file" => open_file(&key(input, "k_e"), &envelope(), &location()).map(|_| ()),
        "drop" => open_drop(crypto, &key(input, "d_e"), &envelope(), &location()).map(|_| ()),
        "drop_key" => verify_drop_public_key(
            crypto,
            &key(input, "d_e"),
            number(input, "epoch"),
            &bytes(input, "public_key"),
        ),
        "epoch_link" => open_epoch_link(
            text(input, "scope"),
            number(input, "epoch"),
            &key(input, "k_next"),
            &envelope(),
        )
        .map(|_| ()),
        "key_history" => KeyHistory::decode(&bytes(input, "payload")).map(|_| ()),
        "key_history_sealed" => KeyHistory::open_sealed(
            crypto,
            text(input, "scope"),
            u32::try_from(number(input, "leaf_index")).unwrap(),
            &bytes(input, "leaf_sk"),
            &envelope(),
        )
        .map(|_| ()),
        "history_walk" => {
            let (mut history, links) = walk_history(input);
            history
                .open(crypto, &envelope(), &location(), |i| links.get(&i).cloned())
                .map(|_| ())
        }
        "base64url" => decode_b64url(text(input, "text")).map(|_| ()),
        "sealed_form" => from_sealed_value(get(input, "value")).map(|_| ()),
        other => panic!("unknown negative section {other}"),
    }
}
