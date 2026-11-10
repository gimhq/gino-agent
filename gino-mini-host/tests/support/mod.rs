//! Helpers for driving mini-host as an agent (raw WebSocket) and as an operator (HTTP).

#![allow(
    clippy::unwrap_used,
    dead_code,
    reason = "test helpers: a failed setup step is a test failure; each test uses a subset"
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

pub type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub async fn start() -> String {
    let host: Arc<Host> = Host::open(Config {
        register_token: "secret".into(),
        db_path: ":memory:".into(),
        engine: Map::new(),
        heartbeat_interval_ms: gino_mini_host::HEARTBEAT_INTERVAL_MS,
    })
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router(host)).await.unwrap() });
    format!("127.0.0.1:{}", addr.port())
}

pub async fn register(base: &str) -> (String, String) {
    register_with(base, json!({})).await
}

/// Register with `extra` merged into the body (e.g. an `e2ee` capability).
pub async fn register_with(base: &str, extra: Value) -> (String, String) {
    let mut body = json!({ "registerToken": "secret", "protocolVersion": 1, "name": "t", "capabilities": ["claude"] });
    if let (Some(body), Value::Object(extra)) = (body.as_object_mut(), extra) {
        body.extend(extra);
    }
    let res = reqwest::Client::new()
        .post(format!("http://{base}/agent/register"))
        .json(&body)
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

pub async fn connect(base: &str, agent: &str, token: &str) -> Ws {
    let mut request = format!("ws://{base}/agent/ws/{agent}")
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("x-internal-token", token.parse().unwrap());
    tokio_tungstenite::connect_async(request).await.unwrap().0
}

pub async fn recv(ws: &mut Ws) -> Value {
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

pub async fn send(ws: &mut Ws, frame: Value) {
    ws.send(Message::Text(frame.to_string().into()))
        .await
        .unwrap();
}

pub async fn api(method: reqwest::Method, url: String, body: Option<Value>) -> (u16, Value) {
    let mut req = reqwest::Client::new().request(method, url);
    if let Some(body) = body {
        req = req.json(&body);
    }
    let res = req.send().await.unwrap();
    (res.status().as_u16(), res.json().await.unwrap())
}
