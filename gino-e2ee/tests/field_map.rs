//! The field-map engine over the generated task-content map and inline maps.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]

#[path = "common/field_map_json.rs"]
mod field_map_json;

use std::collections::BTreeMap;

use gino_e2ee::field_map::{FrameRule, TASK_CONTENT};
use gino_e2ee::{
    DropKeyPair, EpochSecrets, Error, FieldMap, History, Location, Opened, decode_b64url,
    encode_b64url, seal_drop, seal_epoch_link, seal_file,
};
use openmls_rust_crypto::RustCrypto;
use serde_json::{Value, json};

const SCOPE: &str = "t-1";
const THREAD: &str = "c-9@1718000000";
const CURRENT: u64 = 3;

fn secrets(epoch: u64) -> EpochSecrets {
    let byte = u8::try_from(epoch).unwrap();
    EpochSecrets {
        content_key: [byte + 1; 32],
        drop_seed: [byte | 0x80; 32],
    }
}

/// Links for every transition up to `CURRENT`.
fn links(crypto: &RustCrypto) -> BTreeMap<u64, Vec<u8>> {
    (1..=CURRENT)
        .map(|e| {
            let link = seal_epoch_link(
                SCOPE,
                e - 1,
                &secrets(e - 1),
                &secrets(e).content_key,
                crypto,
            );
            (e, link.unwrap())
        })
        .collect()
}

/// A member at `CURRENT` that recovers older epochs through the links.
struct Member {
    crypto: RustCrypto,
    history: History,
    links: BTreeMap<u64, Vec<u8>>,
}

impl Member {
    fn new() -> Self {
        let crypto = RustCrypto::default();
        let links = links(&crypto);
        let history = History::new(SCOPE, CURRENT, secrets(CURRENT)).unwrap();
        Self {
            crypto,
            history,
            links,
        }
    }

    fn seal(&self, map: &FieldMap, frame: &Value) -> Value {
        self.seal_at(map, frame, CURRENT).unwrap()
    }

    fn seal_at(&self, map: &FieldMap, frame: &Value, epoch: u64) -> Result<Value, Error> {
        let frame_type = frame["type"].as_str().unwrap();
        map.seal_frame(
            frame_type,
            frame,
            epoch,
            &secrets(epoch).content_key,
            &self.crypto,
        )
    }

    fn open(&mut self, map: &FieldMap, frame: &Value) -> Result<Value, Error> {
        let Self {
            crypto,
            history,
            links,
        } = self;
        let frame_type = frame["type"].as_str().unwrap();
        map.open_frame(
            frame_type,
            frame,
            |envelope, location| -> Result<Opened, Error> {
                history.open(crypto, envelope, location, |i| links.get(&i).cloned())
            },
        )
    }
}

fn is_sealed(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|o| o.len() == 1 && o.get("e2ee").is_some_and(Value::is_string))
}

fn envelope_of(value: &Value) -> Vec<u8> {
    decode_b64url(value["e2ee"].as_str().unwrap()).unwrap()
}

fn sealed_of(envelope: &[u8]) -> Value {
    json!({ "e2ee": encode_b64url(envelope) })
}

fn attachment(sha: &str, name: Option<&str>) -> Value {
    let mut descriptor = json!({
        "id": format!("att-{sha}"),
        "content_type": "application/octet-stream",
        "size": 120,
        "sha256": sha.repeat(64),
        "ref": format!("{}.bin", sha.repeat(64)),
    });
    if let Some(name) = name {
        descriptor["name"] = json!(name);
    }
    descriptor
}

fn message(text: Option<&str>, attachments: Option<Vec<Value>>) -> Value {
    let mut data = json!({});
    if let Some(text) = text {
        data["text"] = json!(text);
    }
    if let Some(attachments) = attachments {
        data["attachments"] = Value::Array(attachments);
    }
    json!({ "type": "message", "taskId": SCOPE, "msgId": "m-1", "data": data })
}

fn thread_message(seq: u64, data: Value) -> Value {
    let mut data = data;
    data["seq"] = json!(seq);
    json!({
        "type": "thread_message",
        "outboxId": "o-1",
        "taskId": SCOPE,
        "threadId": THREAD,
        "data": data,
    })
}

fn thread_result(data: Value) -> Value {
    json!({
        "type": "thread_result",
        "outboxId": "o-7",
        "taskId": SCOPE,
        "threadId": THREAD,
        "data": data,
    })
}

/// Representative frames of every frame type in the map.
fn frames() -> Vec<(Value, Vec<&'static str>)> {
    vec![
        (
            message(
                Some("summarize the report"),
                Some(vec![
                    attachment("a", Some("report.pdf")),
                    attachment("b", None),
                    attachment("c", Some("notes.txt")),
                ]),
            ),
            vec![
                "/data/text",
                "/data/attachments/0/name",
                "/data/attachments/2/name",
            ],
        ),
        (message(Some("hello"), None), vec!["/data/text"]),
        (message(None, Some(vec![])), vec![]),
        (
            json!({
                "type": "cron_upsert",
                "taskId": SCOPE,
                "cronId": "cr-1",
                "data": { "prompt": "daily digest", "schedule": "0 9 * * *" }
            }),
            vec!["/data/prompt"],
        ),
        (
            thread_message(
                1,
                json!({ "kind": "text", "role": "assistant", "content": "Done." }),
            ),
            vec!["/data/content"],
        ),
        (
            thread_message(
                2,
                json!({
                    "kind": "tool_use",
                    "tool": "bash",
                    "tool_use_id": "tu-1",
                    "input": { "command": "ls -la", "timeout": 30 }
                }),
            ),
            vec!["/data/input"],
        ),
        (
            thread_message(
                3,
                json!({
                    "kind": "tool_result",
                    "tool_use_id": "tu-1",
                    "output": { "is_error": false, "content": [{ "type": "text", "text": "a b c" }] }
                }),
            ),
            vec!["/data/output/content"],
        ),
        (
            thread_message(
                4,
                json!({
                    "kind": "host_action",
                    "content": "setting status",
                    "input": { "method": "issue.set_status", "params": { "issue_id": "i-1", "status": "done" } }
                }),
            ),
            vec!["/data/content", "/data/input/params"],
        ),
        (
            thread_result(json!({
                "status": "succeeded",
                "result": "All tests pass.",
                "error": null,
                "duration_ms": 1200,
                "attachments": [attachment("d", Some("out.log"))]
            })),
            vec!["/data/result", "/data/attachments/0/name"],
        ),
        (
            thread_result(
                json!({ "status": "failed", "failure_reason": "agent.crash", "error": "boom" }),
            ),
            vec!["/data/error"],
        ),
    ]
}

#[test]
fn generated_map_matches_its_source() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../docs/e2ee/task-content.fieldmap.json"
    );
    let source = field_map_json::parse(
        &serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap(),
    );
    let sorted = |map: &FieldMap| {
        let mut frames: Vec<FrameRule> = map.frames.to_vec();
        frames.sort_by_key(|frame| frame.frame_type);
        (map.profile, frames)
    };
    assert_eq!(sorted(source), sorted(&TASK_CONTENT));
    assert_eq!(
        FieldMap::for_profile("gino.task-content.v1"),
        Some(&TASK_CONTENT)
    );
    assert_eq!(FieldMap::for_profile("other"), None);
}

#[test]
fn every_frame_type_round_trips() {
    let mut member = Member::new();
    let covered: std::collections::BTreeSet<String> = frames()
        .into_iter()
        .map(|(frame, _)| frame["type"].as_str().unwrap().to_owned())
        .collect();
    for rule in TASK_CONTENT.frames {
        assert!(covered.contains(rule.frame_type), "{}", rule.frame_type);
    }
    for (frame, sealed_paths) in frames() {
        let sealed = member.seal(&TASK_CONTENT, &frame);
        let mut expected = frame.clone();
        for path in &sealed_paths {
            assert!(
                is_sealed(sealed.pointer(path).unwrap()),
                "{path} in {sealed}"
            );
            *expected.pointer_mut(path).unwrap() = sealed.pointer(path).unwrap().clone();
        }
        assert_eq!(sealed, expected, "only mapped values change");
        assert_eq!(member.open(&TASK_CONTENT, &sealed).unwrap(), frame);
    }
}

#[test]
fn locations_bind_their_templates() {
    let member = Member::new();
    let frame = thread_message(7, json!({ "kind": "text", "content": "hi" }));
    let sealed = member.seal(&TASK_CONTENT, &frame);
    let location = Location::parse(&format!(
        "scope:{SCOPE}|frame:thread_message|thread:{THREAD}|seq:7|field:content"
    ))
    .unwrap();
    let opened = member
        .history
        .clone()
        .open(
            &member.crypto,
            &envelope_of(&sealed["data"]["content"]),
            &location,
            |_| None,
        )
        .unwrap();
    assert_eq!(opened.plaintext, b"hi");
}

#[test]
fn unmapped_frames_pass_through() {
    let mut member = Member::new();
    let frame = json!({ "type": "heartbeat", "taskId": SCOPE, "data": { "text": "plain" } });
    assert_eq!(member.seal(&TASK_CONTENT, &frame), frame);
    assert_eq!(member.open(&TASK_CONTENT, &frame).unwrap(), frame);
}

#[test]
fn older_epochs_open_through_the_history() {
    let mut member = Member::new();
    let frame = message(Some("from epoch 1"), None);
    let sealed = member.seal_at(&TASK_CONTENT, &frame, 1).unwrap();
    assert_eq!(member.open(&TASK_CONTENT, &sealed).unwrap(), frame);

    let later = member.seal_at(&TASK_CONTENT, &frame, CURRENT + 1).unwrap();
    assert_eq!(
        member.open(&TASK_CONTENT, &later),
        Err(Error::EpochUnknown { epoch: CURRENT + 1 })
    );
}

#[test]
fn moved_ciphertext_fails() {
    let mut member = Member::new();
    let sealed = member.seal(
        &TASK_CONTENT,
        &thread_message(7, json!({ "kind": "text", "content": "secret" })),
    );
    let failed = Err(Error::OpenFailed { epoch: CURRENT });

    let mut other_seq = sealed.clone();
    other_seq["data"]["seq"] = json!(8);
    assert_eq!(member.open(&TASK_CONTENT, &other_seq), failed);

    let mut other_thread = sealed.clone();
    other_thread["threadId"] = json!("c-10@1718000000");
    assert_eq!(member.open(&TASK_CONTENT, &other_thread), failed);

    let mut other_field = thread_message(7, json!({ "kind": "text" }));
    other_field["data"]["output"] = json!({ "content": sealed["data"]["content"].clone() });
    assert_eq!(member.open(&TASK_CONTENT, &other_field), failed);

    let names = member.seal(
        &TASK_CONTENT,
        &message(
            None,
            Some(vec![
                attachment("a", Some("a.txt")),
                attachment("b", Some("b.txt")),
            ]),
        ),
    );
    let mut swapped = names.clone();
    swapped["data"]["attachments"][0]["name"] = names["data"]["attachments"][1]["name"].clone();
    assert_eq!(member.open(&TASK_CONTENT, &swapped), failed);

    let mut other_scope = sealed.clone();
    other_scope["taskId"] = json!("t-2");
    assert_eq!(
        member.open(&TASK_CONTENT, &other_scope),
        Err(Error::AadMismatch)
    );
}

#[test]
fn plaintext_at_a_mapped_path_is_rejected() {
    let mut member = Member::new();
    let frame = message(Some("hello"), Some(vec![attachment("a", Some("a.txt"))]));
    assert_eq!(
        member.open(&TASK_CONTENT, &frame),
        Err(Error::PlaintextRejected)
    );

    let mut sealed = member.seal(&TASK_CONTENT, &frame);
    sealed["data"]["attachments"][0]["name"] = json!("a.txt");
    assert_eq!(
        member.open(&TASK_CONTENT, &sealed),
        Err(Error::PlaintextRejected)
    );

    let mut object = member.seal(&TASK_CONTENT, &frame);
    object["data"]["text"] = json!({ "text": "hello" });
    assert_eq!(
        member.open(&TASK_CONTENT, &object),
        Err(Error::PlaintextRejected)
    );
}

#[test]
fn tampering_fails() {
    let mut member = Member::new();
    let frame = message(Some("hello"), None);
    let sealed = member.seal(&TASK_CONTENT, &frame);
    let envelope = envelope_of(&sealed["data"]["text"]);

    let with = |text: Value| {
        let mut frame = sealed.clone();
        frame["data"]["text"] = text;
        frame
    };
    let mut flipped = envelope.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 1;
    assert_eq!(
        member.open(&TASK_CONTENT, &with(sealed_of(&flipped))),
        Err(Error::OpenFailed { epoch: CURRENT })
    );
    let mut relabeled = envelope.clone();
    relabeled[11] ^= 1;
    assert!(
        member
            .open(&TASK_CONTENT, &with(sealed_of(&relabeled)))
            .is_err()
    );

    let mut extra = sealed_of(&envelope);
    extra["kind"] = json!("text");
    assert_eq!(
        member.open(&TASK_CONTENT, &with(extra)),
        Err(Error::Malformed)
    );
    assert_eq!(
        member.open(&TASK_CONTENT, &with(json!({ "e2ee": 1 }))),
        Err(Error::Malformed)
    );
    assert_eq!(
        member.open(&TASK_CONTENT, &with(json!({ "e2ee": "AQ==" }))),
        Err(Error::Malformed)
    );

    let location = Location::parse("scope:t-1|frame:message|field:text").unwrap();
    let file = seal_file(
        &secrets(CURRENT).content_key,
        CURRENT,
        &location,
        b"x",
        &member.crypto,
    )
    .unwrap();
    assert_eq!(
        member.open(&TASK_CONTENT, &with(sealed_of(&file.envelope))),
        Err(Error::Malformed),
        "a file envelope is not allowed at a text field"
    );
}

#[test]
fn drops_open_where_the_rule_allows_them() {
    let mut member = Member::new();
    let pair = DropKeyPair::derive(&member.crypto, &secrets(CURRENT).drop_seed).unwrap();
    let location = Location::parse("scope:t-1|frame:message|field:text").unwrap();
    let envelope = seal_drop(
        &member.crypto,
        pair.public_key(),
        CURRENT,
        &location,
        b"webhook",
    )
    .unwrap();
    let mut frame = message(None, None);
    frame["data"]["text"] = sealed_of(&envelope);
    assert_eq!(
        member.open(&TASK_CONTENT, &frame).unwrap(),
        message(Some("webhook"), None)
    );

    let location = Location::parse(&format!(
        "scope:t-1|frame:thread_message|thread:{THREAD}|seq:1|field:content"
    ))
    .unwrap();
    let envelope = seal_drop(&member.crypto, pair.public_key(), CURRENT, &location, b"x").unwrap();
    let frame = thread_message(
        1,
        json!({ "kind": "text", "content": sealed_of(&envelope) }),
    );
    assert_eq!(member.open(&TASK_CONTENT, &frame), Err(Error::Malformed));
}

#[test]
fn opening_is_all_or_nothing() {
    let mut member = Member::new();
    let frame = thread_result(json!({ "status": "failed", "result": "partial", "error": "boom" }));
    let mut sealed = member.seal(&TASK_CONTENT, &frame);
    let mut envelope = envelope_of(&sealed["data"]["error"]);
    envelope[20] ^= 1;
    sealed["data"]["error"] = sealed_of(&envelope);
    assert_eq!(
        member.open(&TASK_CONTENT, &sealed),
        Err(Error::OpenFailed { epoch: CURRENT })
    );
}

#[test]
fn sealing_refuses_bad_values() {
    let member = Member::new();
    let frame = thread_message(1, json!({ "kind": "text", "content": 5 }));
    assert_eq!(
        member.seal_at(&TASK_CONTENT, &frame, CURRENT),
        Err(Error::SealFailed)
    );
    let mut no_thread = thread_message(1, json!({ "kind": "text", "content": "x" }));
    no_thread.as_object_mut().unwrap().remove("threadId");
    assert_eq!(
        member.seal_at(&TASK_CONTENT, &no_thread, CURRENT),
        Err(Error::AadMismatch)
    );
    let mut pipe = thread_message(1, json!({ "kind": "text", "content": "x" }));
    pipe["threadId"] = json!("a|b");
    assert_eq!(
        member.seal_at(&TASK_CONTENT, &pipe, CURRENT),
        Err(Error::AadMismatch)
    );
}

// ---------------------------------------------------------------------------
// Keyed plain paths (spec §12.5) over an inline map.

fn split_map() -> &'static FieldMap {
    field_map_json::parse(&json!({
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
    }))
}

fn action(method: &str, params: Value) -> Value {
    json!({
        "type": "action",
        "taskId": SCOPE,
        "data": { "seq": 3, "input": { "method": method, "params": params } }
    })
}

#[test]
fn split_values_keep_plain_paths() {
    let mut member = Member::new();
    let map = split_map();
    let frame = action(
        "form.submit",
        json!({ "fields": { "title": "T", "body": "B" }, "labels": ["a", "b"], "note": "N", "empty": {} }),
    );
    let sealed = member.seal(map, &frame);
    let params = &sealed["data"]["input"]["params"];
    assert_eq!(params["fields"]["title"], "T");
    assert_eq!(params["labels"], json!(["a", "b"]));
    assert!(is_sealed(&params["fields"]["body"]));
    assert!(is_sealed(&params["note"]));
    assert!(is_sealed(&params["empty"]));
    assert_eq!(member.open(map, &sealed).unwrap(), frame);

    let location =
        Location::parse("scope:t-1|frame:action|seq:3|field:input.params.fields.body").unwrap();
    let opened = member
        .history
        .open(
            &member.crypto,
            &envelope_of(&params["fields"]["body"]),
            &location,
            |_| None,
        )
        .unwrap();
    assert_eq!(opened.plaintext, br#""B""#);

    let items = action(
        "items.tag",
        json!({ "items": [{ "id": "1", "x": "y" }, { "id": "2" }] }),
    );
    let sealed = member.seal(map, &items);
    assert_eq!(
        sealed["data"]["input"]["params"]["items"][1],
        json!({ "id": "2" })
    );
    assert!(is_sealed(
        &sealed["data"]["input"]["params"]["items"][0]["x"]
    ));
    assert_eq!(member.open(map, &sealed).unwrap(), items);
}

#[test]
fn split_falls_back_to_whole_sealing() {
    let mut member = Member::new();
    let map = split_map();
    for frame in [
        action("unknown", json!({ "fields": { "title": "T" } })),
        action("noop", json!({ "fields": { "title": "T" } })),
        action("form.submit", json!(["not", "an", "object"])),
        action("form.submit", json!({ "fields": "scalar", "labels": {} })),
    ] {
        let sealed = member.seal(map, &frame);
        assert_eq!(member.open(map, &sealed).unwrap(), frame);
        if frame["data"]["input"]["params"].is_array()
            || frame["data"]["input"]["method"] != "form.submit"
        {
            assert!(is_sealed(&sealed["data"]["input"]["params"]), "{sealed}");
        }
    }
    let descend_scalar = member.seal(
        map,
        &action("form.submit", json!({ "fields": "scalar", "labels": {} })),
    );
    let params = &descend_scalar["data"]["input"]["params"];
    assert!(is_sealed(&params["fields"]));
    assert!(is_sealed(&params["labels"]));
}

#[test]
fn split_reading_rejects_plaintext_and_bad_keys() {
    let mut member = Member::new();
    let map = split_map();
    let frame = action(
        "form.submit",
        json!({ "fields": { "title": "T", "body": "B" }, "note": "N" }),
    );
    let sealed = member.seal(map, &frame);

    let mut plain_part = sealed.clone();
    plain_part["data"]["input"]["params"]["note"] = json!("N");
    assert_eq!(member.open(map, &plain_part), Err(Error::PlaintextRejected));

    let mut whole_method = sealed.clone();
    whole_method["data"]["input"]["method"] = json!("unknown");
    assert_eq!(
        member.open(map, &whole_method),
        Err(Error::PlaintextRejected)
    );

    let mut descend_scalar = sealed.clone();
    descend_scalar["data"]["input"]["params"]["fields"] = json!("x");
    assert_eq!(
        member.open(map, &descend_scalar),
        Err(Error::PlaintextRejected)
    );

    let mut bad_form = sealed.clone();
    bad_form["data"]["input"]["params"]["note"] = json!({ "e2ee": 1 });
    assert_eq!(member.open(map, &bad_form), Err(Error::Malformed));

    let plain_lookalike = action(
        "form.submit",
        json!({ "fields": { "title": { "e2ee": "AQID" } } }),
    );
    let sealed_lookalike = member.seal(map, &plain_lookalike);
    assert_eq!(
        member.open(map, &sealed_lookalike).unwrap(),
        plain_lookalike
    );

    for key in ["a.b", "a|b", ""] {
        let frame = action("form.submit", json!({ key: "v" }));
        assert_eq!(
            member.seal_at(map, &frame, CURRENT),
            Err(Error::AadMismatch),
            "{key:?}"
        );
        let mut forged = sealed.clone();
        forged["data"]["input"]["params"][key] = sealed["data"]["input"]["params"]["note"].clone();
        assert_eq!(
            member.open(map, &forged),
            Err(Error::AadMismatch),
            "{key:?}"
        );
    }

    let mut moved = sealed.clone();
    let params = &mut moved["data"]["input"]["params"];
    params["fields"]["body"] = params["note"].clone();
    assert_eq!(
        member.open(map, &moved),
        Err(Error::OpenFailed { epoch: CURRENT })
    );
}
