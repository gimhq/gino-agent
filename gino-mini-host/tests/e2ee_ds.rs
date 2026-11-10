//! The Delivery Service side of protocol §5.3, driven by a runner simulated with `gino-e2ee`:
//! KeyPackage verification and claims, Welcome delivery, every `e2ee_request` operation
//! (`log`, `log_from_epoch`, `link`, `put_link`, `commit`), the client device following a
//! runner's commit, and the refusal of plaintext on an encrypted task.

#![allow(
    clippy::unwrap_used,
    clippy::too_many_lines,
    reason = "one scenario walks the whole DS exchange; a failed step is a test failure"
)]

mod support;

use std::time::Duration;

use gino_e2ee::field_map::FieldMap;
use gino_e2ee::{
    Identity, KeyPackageStore, MemoryKeyCache, ScopeGroup, decode_b64url, encode_b64url,
};
use openmls_rust_crypto::RustCrypto;
use serde_json::{Value, json};
use support::{Ws, api, connect, recv, register_with, send, start};

const PROFILE: &str = "gino.task-content.v1";

/// The next frame of `kind`; other frames (statuses, acks) are skipped.
async fn recv_type(ws: &mut Ws, kind: &str) -> Value {
    loop {
        let frame = recv(ws).await;
        if frame["type"] == kind {
            return frame;
        }
    }
}

async fn ds(ws: &mut Ws, task: &str, req: &str, data: Value) -> Value {
    send(
        ws,
        json!({ "type": "e2ee_request", "taskId": task, "reqId": req, "data": data }),
    )
    .await;
    let response = recv_type(ws, "e2ee_response").await;
    assert_eq!(response["reqId"], req);
    response["data"].clone()
}

#[tokio::test]
async fn a_runner_joins_reads_commits_and_exchanges_sealed_content() {
    let base = start().await;
    let identity = Identity::generate(&RustCrypto::default()).unwrap();
    let key_packages = KeyPackageStore::new();
    let capability = json!({ "versions": [1], "mls_suites": [1],
        "credential": { "type": "basic", "public_key": encode_b64url(&identity.public_key()) } });
    let (agent, token) = register_with(&base, json!({ "e2ee": capability })).await;
    let mut ws = connect(&base, &agent, &token).await;
    let status = recv_type(&mut ws, "e2ee_key_package_status").await;
    assert_eq!(
        status["data"],
        json!({ "one_time": 0, "last_resort": false })
    );

    // Publish: one valid one-time KeyPackage, a malformed one and a last-resort one.
    let one_time = key_packages.generate(&identity, false).unwrap();
    let last_resort = key_packages.generate(&identity, true).unwrap();
    send(
        &mut ws,
        json!({ "type": "e2ee_key_packages", "outboxId": "kp-1", "data": {
            "one_time": [encode_b64url(&one_time), "AAAA"],
            "last_resort": encode_b64url(&last_resort),
        } }),
    )
    .await;
    let status = recv_type(&mut ws, "e2ee_key_package_status").await;
    assert_eq!(status["id"], "kp-1");
    assert_eq!(
        status["data"],
        json!({ "one_time": 1, "last_resort": true, "rejected": [{ "code": "malformed", "index": 1 }] })
    );
    assert_eq!(recv(&mut ws).await, json!({ "type": "ack", "id": "kp-1" }));

    // The client device creates the group and adds the runner from the claimed KeyPackage.
    let (status, created) = api(
        reqwest::Method::POST,
        format!("http://{base}/api/tasks"),
        Some(json!({ "taskId": "t-enc", "encrypted": true })),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    let upsert = recv_type(&mut ws, "task_upsert").await;
    assert_eq!(upsert["data"]["e2ee"]["profile_id"], PROFILE);
    assert_eq!(
        upsert["data"]["e2ee"]["group_id"],
        json!(encode_b64url(
            &gino_e2ee::group_id(PROFILE, "t-enc").unwrap()
        ))
    );
    let welcome = recv_type(&mut ws, "e2ee_welcome").await;
    let seq = welcome["data"]["seq"].as_u64().unwrap();
    let mut group = ScopeGroup::join(
        &key_packages,
        PROFILE,
        "t-enc",
        &decode_b64url(welcome["data"]["welcome"].as_str().unwrap()).unwrap(),
        seq,
        MemoryKeyCache::default(),
    )
    .unwrap();
    assert_eq!(group.epoch(), 1);

    // Reads.
    let log = ds(
        &mut ws,
        "t-enc",
        "r1",
        json!({ "op": "log", "after_seq": 0 }),
    )
    .await;
    assert_eq!(
        (&log["ok"], &log["more"], &log["epoch"]),
        (&json!(true), &json!(false), &json!(1))
    );
    assert_eq!(log["entries"][0]["kind"], "commit");
    assert!(log["entries"][0]["drop_public_key"].is_string());
    let link = ds(&mut ws, "t-enc", "r2", json!({ "op": "link", "epoch": 1 })).await;
    let stored = link["link"]
        .as_str()
        .expect("the committer's epoch link")
        .to_owned();
    let again = ds(
        &mut ws,
        "t-enc",
        "r3",
        json!({ "op": "put_link", "epoch": 1, "link": stored }),
    )
    .await;
    assert_eq!(
        (&again["error"]["code"], &again["link"]),
        (&json!("link_exists"), &json!(stored))
    );
    let other = ds(
        &mut ws,
        "t-other",
        "r4",
        json!({ "op": "log", "after_seq": 0 }),
    )
    .await;
    assert_eq!(other["error"]["code"], "not_member");

    // The runner's own Update: accepted once, the replay is an epoch conflict.
    let unit = group.self_update(&identity).unwrap();
    let commit = json!({
        "op": "commit",
        "commit": encode_b64url(&unit.commit),
        "drop_public_key": encode_b64url(&unit.drop_public_key),
        "epoch_link": unit.epoch_link.as_deref().map(encode_b64url),
    });
    let accepted = ds(&mut ws, "t-enc", "r5", commit.clone()).await;
    assert_eq!(accepted, json!({ "ok": true, "seq": 2, "epoch": 2 }));
    group.commit_accepted(2).unwrap();
    let conflict = ds(&mut ws, "t-enc", "r6", commit).await;
    assert_eq!(
        (&conflict["error"]["code"], &conflict["epoch"]),
        (&json!("epoch_conflict"), &json!(2))
    );
    let from_epoch = ds(
        &mut ws,
        "t-enc",
        "r7",
        json!({ "op": "log_from_epoch", "epoch": 1 }),
    )
    .await;
    let seqs: Vec<&Value> = from_epoch["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| &e["seq"])
        .collect();
    assert_eq!(
        seqs,
        [&json!(2)],
        "the add was sent in epoch 0, the update in epoch 1"
    );

    // The client device followed the runner's commit: the next message is sealed at epoch 2
    // and opens for the runner.
    let map = FieldMap::for_profile(PROFILE).unwrap();
    let (status, sent) = api(
        reqwest::Method::POST,
        format!("http://{base}/api/tasks/t-enc/messages"),
        Some(json!({ "text": "for members only" })),
    )
    .await;
    assert_eq!(status, 202, "{sent}");
    let message = recv_type(&mut ws, "message").await;
    assert!(message["data"]["text"]["e2ee"].is_string(), "{message}");
    let opened = map
        .open_frame("message", &message, |envelope, location| {
            group
                .open(envelope, location, |_| None)
                .map_err(|err| err.encryption_error().unwrap())
        })
        .unwrap();
    assert_eq!(opened["data"]["text"], "for members only");

    // A sealed result is stored as received and opens for the operator; plaintext is refused.
    let thread = sent["threadId"].as_str().unwrap();
    let plain = json!({ "type": "thread_result", "taskId": "t-enc", "threadId": thread, "outboxId": "res-0",
                        "data": { "status": "succeeded", "result": "leaked", "final_seq": 0 } });
    send(&mut ws, plain).await;
    let result = json!({ "type": "thread_result", "taskId": "t-enc", "threadId": thread, "outboxId": "res-1",
                         "data": { "status": "succeeded", "result": "sealed answer", "final_seq": 0 } });
    let (epoch, secrets) = group.current().unwrap();
    let sealed = map
        .seal_frame(
            "thread_result",
            &result,
            epoch,
            &secrets.content_key,
            &RustCrypto::default(),
        )
        .unwrap();
    send(&mut ws, sealed).await;
    assert_eq!(
        recv_type(&mut ws, "ack").await,
        json!({ "type": "ack", "id": "res-1" }),
        "the plaintext result is not acked"
    );
    let (status, view) = api(
        reqwest::Method::GET,
        format!("http://{base}/api/threads/{thread}/wait?timeoutMs=5000"),
        None,
    )
    .await;
    assert_eq!(status, 200, "{view}");
    assert_eq!(view["run"]["result"], "sealed answer");

    tokio::time::sleep(Duration::from_millis(50)).await;
    let (_, task) = api(
        reqwest::Method::GET,
        format!("http://{base}/api/tasks/t-enc"),
        None,
    )
    .await;
    assert_eq!(task["e2ee"]["epoch"], 2);
    assert_eq!(task["e2ee"]["members"], json!([agent]));
}
