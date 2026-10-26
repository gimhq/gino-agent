//! Drives the mini-host as an agent and an operator would: enrollment, the
//! WebSocket outbox with acks and replay, transcripts and the result long-poll.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step is a test failure"
)]

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use gino_mini_host::{Config, Host, router};
use serde_json::{Map, Value, json};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

async fn start() -> String {
    let host: Arc<Host> = Host::open(Config {
        register_token: "secret".into(),
        db_path: ":memory:".into(),
        engine: Map::new(),
    })
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router(host)).await.unwrap() });
    format!("127.0.0.1:{}", addr.port())
}

async fn register(base: &str) -> (String, String) {
    let res = reqwest::Client::new()
        .post(format!("http://{base}/agent/register"))
        .json(&json!({ "registerToken": "secret", "protocolVersion": 1, "name": "t", "capabilities": ["claude"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["config"]["protocolVersion"], 1);
    (
        body["agentId"].as_str().unwrap().into(),
        body["connectToken"].as_str().unwrap().into(),
    )
}

async fn connect(base: &str, agent: &str, token: &str) -> Ws {
    let mut request = format!("ws://{base}/agent/ws/{agent}")
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("x-internal-token", token.parse().unwrap());
    tokio_tungstenite::connect_async(request).await.unwrap().0
}

async fn recv(ws: &mut Ws) -> Value {
    loop {
        let message = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        if let Message::Text(text) = message {
            return serde_json::from_str(&text).unwrap();
        }
    }
}

async fn send(ws: &mut Ws, frame: Value) {
    ws.send(Message::Text(frame.to_string().into()))
        .await
        .unwrap();
}

async fn api(method: reqwest::Method, url: String, body: Option<Value>) -> (u16, Value) {
    let mut req = reqwest::Client::new().request(method, url);
    if let Some(body) = body {
        req = req.json(&body);
    }
    let res = req.send().await.unwrap();
    (res.status().as_u16(), res.json().await.unwrap())
}

#[tokio::test]
async fn enrollment_rejects_bad_token_and_protocol() {
    let base = start().await;
    let client = reqwest::Client::new();
    let url = format!("http://{base}/agent/register");
    let bad_token = client
        .post(&url)
        .json(&json!({ "registerToken": "x", "protocolVersion": 1 }))
        .send()
        .await
        .unwrap();
    assert_eq!(bad_token.status(), 401);
    let bad_protocol = client
        .post(&url)
        .json(&json!({ "registerToken": "secret", "protocolVersion": 9 }))
        .send()
        .await
        .unwrap();
    assert_eq!(bad_protocol.status(), 400);
    let (agent, _) = register(&base).await;
    let config = client
        .get(format!("http://{base}/agent/config/{agent}"))
        .header("x-internal-token", "wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(config.status(), 401);
}

#[tokio::test]
async fn dispatch_transcript_result_and_replay() {
    let base = start().await;
    let (agent, token) = register(&base).await;
    let mut ws = connect(&base, &agent, &token).await;

    let (status, created) = api(
        reqwest::Method::POST,
        format!("http://{base}/api/tasks"),
        Some(json!({ "taskId": "t1", "engine": "claude" })),
    )
    .await;
    assert_eq!(status, 201);
    let upsert = recv(&mut ws).await;
    assert_eq!(upsert["type"], "task_upsert");
    assert_eq!(upsert["data"]["engine"], "claude");
    assert_eq!(upsert["msgId"], created["msgId"]);
    send(
        &mut ws,
        json!({ "type": "msg_ack", "msgId": upsert["msgId"] }),
    )
    .await;

    let (status, sent) = api(
        reqwest::Method::POST,
        format!("http://{base}/api/tasks/t1/messages"),
        Some(json!({ "text": "hi" })),
    )
    .await;
    assert_eq!(status, 202);
    let thread = sent["threadId"].as_str().unwrap().to_owned();
    let message = recv(&mut ws).await;
    assert_eq!(
        (message["type"].as_str(), message["threadId"].as_str()),
        (Some("message"), Some(thread.as_str()))
    );
    assert_eq!(message["data"]["text"], "hi");

    send(&mut ws, json!({ "type": "thread_message", "taskId": "t1", "threadId": thread, "outboxId": "o1", "data": { "seq": 1, "kind": "assistant_text", "content": "hello" } })).await;
    assert_eq!(recv(&mut ws).await, json!({ "type": "ack", "id": "o1" }));
    send(&mut ws, json!({ "type": "thread_result", "taskId": "t1", "threadId": thread, "outboxId": "o2", "data": { "status": "succeeded", "result": "done", "final_seq": 1 } })).await;
    assert_eq!(recv(&mut ws).await, json!({ "type": "ack", "id": "o2" }));

    let (status, view) = api(
        reqwest::Method::GET,
        format!("http://{base}/api/threads/{thread}/wait?timeoutMs=5000"),
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(view["run"]["status"], "succeeded");
    assert_eq!(view["run"]["result"], "done");
    assert_eq!(view["messages"][0]["content"], "hello");

    // Reconnecting replays only the unacked `message` frame, under its msgId.
    drop(ws);
    let mut ws = connect(&base, &agent, &token).await;
    let replayed = recv(&mut ws).await;
    assert_eq!(
        (replayed["type"].as_str(), replayed["msgId"].as_str()),
        (Some("message"), message["msgId"].as_str())
    );

    let (status, interrupted) = api(
        reqwest::Method::POST,
        format!("http://{base}/api/tasks/t1/interrupt"),
        None,
    )
    .await;
    assert_eq!((status, interrupted), (200, json!({ "sent": true })));
    assert_eq!(
        recv(&mut ws).await,
        json!({ "type": "interrupt", "taskId": "t1" })
    );
}

#[tokio::test]
async fn result_wait_times_out_and_unknown_routes_are_json() {
    let base = start().await;
    let (status, view) = api(
        reqwest::Method::GET,
        format!("http://{base}/api/threads/none/wait?timeoutMs=300"),
        None,
    )
    .await;
    assert_eq!((status, &view["timedOut"]), (408, &json!(true)));
    let (status, body) = api(reqwest::Method::GET, format!("http://{base}/nope"), None).await;
    assert_eq!((status, body), (404, json!({ "error": "not found" })));
    let (status, body) = api(
        reqwest::Method::POST,
        format!("http://{base}/api/tasks"),
        Some(json!({})),
    )
    .await;
    assert_eq!(
        (status, body),
        (400, json!({ "error": "no agent registered yet" }))
    );
}
