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

#[test]
fn the_heartbeat_schema_carries_every_reported_field() {
    let text = schema().to_string();
    for field in [
        "activeThreads",
        "capabilities",
        "engines",
        "e2ee",
        "configVersion",
    ] {
        assert!(text.contains(&format!("\"{field}\":")), "{field}");
    }
}
