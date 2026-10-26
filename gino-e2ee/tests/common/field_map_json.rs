//! Reads a field-map JSON file (spec §12.1) into the crate's static tables,
//! for inline maps in tests and vectors. Leaks its allocations.

#![allow(dead_code, clippy::expect_used, clippy::panic)]

use gino_e2ee::EnvelopeType;
use gino_e2ee::field_map::{
    Direction, FieldMap, FieldRule, FrameRule, KeyedPlain, Kind, When, WhenOp,
};
use serde_json::Value;

fn leak_str(value: &Value) -> &'static str {
    Box::leak(value.as_str().expect("string").to_owned().into_boxed_str())
}

fn leak_slice<T>(items: Vec<T>) -> &'static [T] {
    Box::leak(items.into_boxed_slice())
}

fn rule(value: &Value) -> FieldRule {
    let kind = match value["kind"].as_str() {
        Some("text") => Kind::Text,
        Some("json") => Kind::Json,
        Some("blob") => Kind::Blob,
        other => panic!("bad kind {other:?}"),
    };
    let envelopes = value["envelopes"]
        .as_array()
        .expect("envelopes")
        .iter()
        .map(|e| match e.as_str() {
            Some("content") => EnvelopeType::Content,
            Some("drop") => EnvelopeType::Drop,
            Some("file") => EnvelopeType::File,
            other => panic!("bad envelope {other:?}"),
        })
        .collect();
    let when = value.get("when").map(|when| When {
        path: leak_str(&when["path"]),
        op: match when["op"].as_str() {
            Some("eq") => WhenOp::Eq,
            Some("ne") => WhenOp::Ne,
            other => panic!("bad op {other:?}"),
        },
        value: leak_str(&when["value"]),
    });
    let keyed_plain = value.get("keyed_plain").map(|keyed| KeyedPlain {
        key: leak_str(&keyed["key"]),
        table: leak_slice(
            keyed["table"]
                .as_object()
                .expect("table")
                .iter()
                .map(|(method, paths)| {
                    let method: &'static str = Box::leak(method.clone().into_boxed_str());
                    let paths = paths.as_array().expect("paths").iter().map(leak_str);
                    (method, leak_slice(paths.collect()))
                })
                .collect(),
        ),
    });
    FieldRule {
        path: leak_str(&value["path"]),
        kind,
        envelopes: leak_slice(envelopes),
        aad: leak_str(&value["aad"]),
        when,
        keyed_plain,
    }
}

/// The field map of a parsed `*.fieldmap.json`.
pub fn parse(value: &Value) -> &'static FieldMap {
    assert_eq!(value["format"], "gino-e2ee/field-map/v1");
    let frames = value["frames"]
        .as_object()
        .expect("frames")
        .iter()
        .map(|(frame_type, frame)| FrameRule {
            frame_type: Box::leak(frame_type.clone().into_boxed_str()),
            direction: match frame["direction"].as_str() {
                Some("host_to_agent") => Direction::HostToAgent,
                Some("agent_to_host") => Direction::AgentToHost,
                other => panic!("bad direction {other:?}"),
            },
            scope: leak_str(&frame["scope"]),
            fields: leak_slice(
                frame["fields"]
                    .as_array()
                    .expect("fields")
                    .iter()
                    .map(rule)
                    .collect(),
            ),
        })
        .collect();
    Box::leak(Box::new(FieldMap {
        profile: leak_str(&value["profile"]),
        frames: leak_slice(frames),
    }))
}
