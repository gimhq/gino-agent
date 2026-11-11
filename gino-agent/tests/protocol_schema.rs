//! `docs/protocol.md` §8 against the runner's frame enums: every frame the runner
//! speaks is in the normative schema, and the schema holds no frame it does not.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers: a malformed document is a test failure"
)]

use std::collections::BTreeSet;

use serde_json::Value;

const PROTOCOL_MD: &str = include_str!("../../docs/protocol.md");
const PROTOCOL_RS: &str = include_str!("../src/protocol.rs");

/// Live-only frames: they bypass the durable frame enums.
const LIVE_HOST_FRAMES: [&str; 7] = [
    "e2ee_key_package_status",
    "e2ee_response",
    "fs_request",
    "pty_close",
    "pty_input",
    "pty_open",
    "pty_resize",
];
const LIVE_AGENT_FRAMES: [&str; 4] = ["fs_response", "pty_exit", "pty_output", "pty_ready"];

fn schema() -> Value {
    let section = PROTOCOL_MD
        .split("## 8. Frame JSON Schema (generated)")
        .nth(1)
        .expect("protocol.md has section 8");
    let body = section
        .split("```json\n")
        .nth(1)
        .and_then(|rest| rest.split("\n```").next())
        .expect("section 8 has a JSON block");
    serde_json::from_str(body).expect("section 8 is valid JSON")
}

fn collect_frame_types(node: &Value, types: &mut BTreeSet<String>) {
    match node {
        Value::Object(map) => {
            if let Some(name) = node
                .pointer("/properties/type/const")
                .and_then(Value::as_str)
            {
                types.insert(name.to_owned());
            }
            map.values()
                .for_each(|value| collect_frame_types(value, types));
        }
        Value::Array(items) => items
            .iter()
            .for_each(|value| collect_frame_types(value, types)),
        _ => {}
    }
}

fn schema_types(direction: &str) -> BTreeSet<String> {
    let mut types = BTreeSet::new();
    collect_frame_types(&schema()["$defs"][direction], &mut types);
    types
}

fn snake_case(variant: &str) -> String {
    let mut name = String::new();
    for (index, c) in variant.char_indices() {
        if c.is_ascii_uppercase() && index > 0 {
            name.push('_');
        }
        name.push(c.to_ascii_lowercase());
    }
    name
}

/// The wire `type` of each variant of `enum_name`, minus the catch-all, plus `live`.
fn runner_types(enum_name: &str, live: &[&str]) -> BTreeSet<String> {
    PROTOCOL_RS
        .lines()
        .skip_while(|line| !line.contains(&format!("enum {enum_name} {{")))
        .skip(1)
        .take_while(|line| *line != "    }")
        .filter_map(|line| line.strip_prefix("        "))
        .filter_map(|line| {
            line.split(|c: char| !c.is_ascii_alphanumeric())
                .next()
                .filter(|word| word.starts_with(|c: char| c.is_ascii_uppercase()))
        })
        .filter(|variant| *variant != "Unknown")
        .map(snake_case)
        .chain(live.iter().map(|name| (*name).to_owned()))
        .collect()
}

#[test]
fn the_schema_lists_exactly_the_frames_the_runner_accepts() {
    assert_eq!(
        schema_types("HostFrame"),
        runner_types("InboundFrame", &LIVE_HOST_FRAMES)
    );
}

#[test]
fn the_schema_lists_exactly_the_frames_the_runner_sends() {
    assert_eq!(
        schema_types("AgentFrame"),
        runner_types("OutboundFrame", &LIVE_AGENT_FRAMES)
    );
}

/// The `data` schema of frame `name` in the `direction` catalog.
fn data_schema(direction: &str, name: &str) -> Value {
    fn find(node: &Value, name: &str) -> Option<Value> {
        match node {
            Value::Object(map) => {
                if node
                    .pointer("/properties/type/const")
                    .and_then(Value::as_str)
                    == Some(name)
                {
                    return node.pointer("/properties/data").cloned();
                }
                map.values().find_map(|value| find(value, name))
            }
            Value::Array(items) => items.iter().find_map(|value| find(value, name)),
            _ => None,
        }
    }
    find(&schema()["$defs"][direction], name).expect("the frame is in the schema")
}

#[test]
fn the_schema_carries_every_field_the_runner_reads_or_reports() {
    let cases: [(&str, &str, &[&str]); 4] = [
        (
            "AgentFrame",
            "heartbeat",
            &[
                "activeThreads",
                "capabilities",
                "engines",
                "e2ee",
                "configVersion",
                "defaults",
            ],
        ),
        ("AgentFrame", "thread_result", &["engine", "model", "usage"]),
        ("HostFrame", "task_upsert", &["engine", "model"]),
        ("HostFrame", "fs_request", &["to", "recursive", "exclusive"]),
    ];
    for (direction, frame, fields) in cases {
        let data = data_schema(direction, frame);
        for field in fields {
            assert!(
                data.pointer(&format!("/properties/{field}")).is_some(),
                "{frame}.data.{field}"
            );
        }
    }
    let defaults = data_schema("AgentFrame", "heartbeat")["properties"]["defaults"].clone();
    for field in ["engine", "model", "baseUrlHost"] {
        assert!(
            defaults["properties"].get(field).is_some(),
            "defaults.{field}"
        );
    }
    let engine = data_schema("AgentFrame", "heartbeat")["properties"]["engines"]["items"].clone();
    for field in [
        "name",
        "version",
        "path",
        "auth",
        "models",
        "defaultModel",
        "baseUrlHost",
    ] {
        assert!(
            engine["properties"].get(field).is_some(),
            "engines[].{field}"
        );
    }
    for field in ["id", "name", "description", "isDefault"] {
        assert!(
            engine["properties"]["models"]["items"]["properties"]
                .get(field)
                .is_some(),
            "engines[].models[].{field}"
        );
    }
    let usage = data_schema("AgentFrame", "thread_result")["properties"]["usage"].clone();
    for field in ["inputTokens", "outputTokens", "cacheReadTokens", "costUsd"] {
        assert!(usage["properties"].get(field).is_some(), "usage.{field}");
    }
    let engine = data_schema("HostFrame", "task_upsert")["properties"]["engine"].to_string();
    assert!(
        engine.contains(r#""type":"null""#),
        "task_upsert.engine accepts null"
    );
}
