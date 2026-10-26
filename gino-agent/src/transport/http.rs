//! HTTP client (agent-architecture §10).
//!
//! The WebSocket is the primary channel; HTTP is retained for the endpoints that
//! sit outside the persistent socket. The terminal output of an execution is a
//! `thread_result` frame over the outbox/WS, not an HTTP post.
//!
//! * `POST /agent/register` — enrollment (§2.1). The bootstrap *register* token
//!   travels in the JSON body; no auth header. Returns the host-assigned
//!   `{agentId, connectToken, config}` or a `{register_error}` envelope.
//! * `GET  /agent/config/:id` — config bootstrap/refresh, authenticated with the
//!   connect token in the `x-internal-token` header.
//!
//! The **attachment proxy** client (`GET /agent/attachments/:id` /
//! `POST /agent/attachments`, agent-architecture §9, Lane F) lives
//! here too — see [`HttpClient::download_attachment`] /
//! [`HttpClient::upload_attachment`]. It is the **host-proxy** byte backend: the
//! same connect-token auth as the endpoints above, but the bytes ride the request
//! body (never a frame). The attachment *layer* (`crate::attachments`) owns
//! integrity, caching and limits; this module is just the byte transfer.
//!
//! All TLS is rustls (the manifest pins `reqwest` to rustls + OS roots); this
//! module never touches the openssl/native-tls path banned by `deny.toml`.

use std::time::Duration;

use reqwest::Client;
use reqwest::header::CONTENT_TYPE;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

use crate::protocol::{RegisterRequest, RegisterResponse};

/// Auth header carrying the connect token (the host reads this exact name).
const INTERNAL_TOKEN_HEADER: &str = "x-internal-token";
/// Original file name of an uploaded attachment (host-proxy upload metadata; the
/// bytes ride the body, so the name travels as a header rather than a frame).
const ATTACHMENT_NAME_HEADER: &str = "x-attachment-name";
/// Content hash of an uploaded attachment, so the host can dedup/verify too.
const ATTACHMENT_SHA256_HEADER: &str = "x-attachment-sha256";
/// Bound on establishing the TCP/TLS connection (the client
/// previously had no timeouts at all, so registration could hang forever).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Idle guard between successive reads of a response (headers or body chunks).
/// DECISION: connect + idle-read timeouts, deliberately NO whole-request
/// `timeout` — attachment transfers stream arbitrarily large bodies, so a total
/// -duration cap would abort legitimate slow transfers, while the idle guard
/// still bounds a stalled response on every endpoint.
const READ_TIMEOUT: Duration = Duration::from_mins(1);

/// Errors raised by the HTTP client. Secrets are never included in any message.
#[derive(Debug, Error)]
pub(crate) enum HttpError {
    /// The underlying `reqwest` client could not be built.
    #[error("build http client: {0}")]
    Build(reqwest::Error),
    /// The request could not be sent (DNS/TLS/connect/timeout).
    #[error("{endpoint} request failed: {source}")]
    Request {
        endpoint: &'static str,
        source: reqwest::Error,
    },
    /// The host returned a non-success status (and no parseable error body).
    #[error("{endpoint} returned HTTP {status}")]
    Status { endpoint: &'static str, status: u16 },
    /// The response body could not be decoded into the expected type.
    #[error("decode {endpoint} response: {source}")]
    Decode {
        endpoint: &'static str,
        source: reqwest::Error,
    },
    /// A streamed body exceeded the caller's byte cap. `size` is the declared
    /// `Content-Length` when the pre-check tripped, or the running count at the
    /// moment the in-flight cap aborted the stream (audit P1-10a).
    #[error("{endpoint} body exceeds the size limit ({size} > {limit} bytes)")]
    TooLarge {
        endpoint: &'static str,
        size: u64,
        limit: u64,
    },
    /// Writing a streamed chunk into the caller's sink failed.
    #[error("{endpoint} sink write failed: {source}")]
    Sink {
        endpoint: &'static str,
        source: std::io::Error,
    },
}

/// Thin wrapper over a shared `reqwest::Client` (the client is internally
/// reference-counted, so cloning is cheap).
#[derive(Clone, Debug)]
pub(crate) struct HttpClient {
    client: Client,
}

impl HttpClient {
    /// Build a client with the default (rustls) TLS stack and the production
    /// [`CONNECT_TIMEOUT`] / [`READ_TIMEOUT`] bounds.
    pub(crate) fn new() -> Result<Self, HttpError> {
        Self::with_timeouts(CONNECT_TIMEOUT, READ_TIMEOUT)
    }

    /// The builder seam behind [`Self::new`]: every production request flows
    /// through a client built here, so a test can exercise the timeout policy
    /// with short bounds. See [`READ_TIMEOUT`] for why there is no
    /// whole-request timeout.
    fn with_timeouts(connect: Duration, read: Duration) -> Result<Self, HttpError> {
        let client = Client::builder()
            .connect_timeout(connect)
            .read_timeout(read)
            .build()
            .map_err(HttpError::Build)?;
        Ok(Self { client })
    }

    /// `POST {url}` with the register request body. The host signals failure via a
    /// `{register_error}` body (possibly under a non-2xx status), so the body is
    /// parsed regardless of status and the typed [`RegisterResponse`] distinguishes
    /// success from rejection. A body that is neither shape surfaces the status.
    pub(crate) async fn register(
        &self,
        url: &str,
        body: &RegisterRequest,
    ) -> Result<RegisterResponse, HttpError> {
        let response = self
            .client
            .post(url)
            .json(body)
            .send()
            .await
            .map_err(|source| HttpError::Request {
                endpoint: "register",
                source,
            })?;
        let status = response.status();
        match response.json::<RegisterResponse>().await {
            Ok(parsed) => Ok(parsed),
            Err(source) if status.is_success() => Err(HttpError::Decode {
                endpoint: "register",
                source,
            }),
            Err(_) => Err(HttpError::Status {
                endpoint: "register",
                status: status.as_u16(),
            }),
        }
    }

    /// `GET {url}` for the host-assigned config overlay (raw JSON).
    pub(crate) async fn fetch_config(
        &self,
        url: &str,
        connect_token: &SecretString,
    ) -> Result<Value, HttpError> {
        let response = self
            .client
            .get(url)
            .header(INTERNAL_TOKEN_HEADER, connect_token.expose_secret())
            .send()
            .await
            .map_err(|source| HttpError::Request {
                endpoint: "config",
                source,
            })?;
        let response = error_for_status(response, "config")?;
        response
            .json::<Value>()
            .await
            .map_err(|source| HttpError::Decode {
                endpoint: "config",
                source,
            })
    }

    /// `GET {url}` — stream an attachment's raw bytes from the host proxy
    /// (`GET /agent/attachments/:id`, agent-architecture §9) into
    /// `sink`, returning the byte count. The body is never buffered whole (audit
    /// P1-10a): a declared `Content-Length` over `max_bytes` aborts before any
    /// body read, and the chunk loop aborts as soon as the running count would
    /// exceed the cap — the sink never receives more than `max_bytes`. The token
    /// is optional so the attachment layer can withhold it from cross-origin
    /// URLs (audit P1-10c). Integrity (`sha256`) is verified by
    /// [`crate::attachments`], not here — this is only byte transfer.
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "the attachment proxy is wired into the executor by Lane G"
        )
    )]
    pub(crate) async fn download_attachment(
        &self,
        url: &str,
        connect_token: Option<&SecretString>,
        max_bytes: u64,
        sink: &mut (dyn std::io::Write + Send),
    ) -> Result<u64, HttpError> {
        const ENDPOINT: &str = "attachment_download";
        let mut request = self.client.get(url);
        if let Some(token) = connect_token {
            request = request.header(INTERNAL_TOKEN_HEADER, token.expose_secret());
        }
        let response = request.send().await.map_err(|source| HttpError::Request {
            endpoint: ENDPOINT,
            source,
        })?;
        let mut response = error_for_status(response, ENDPOINT)?;
        if let Some(declared) = response.content_length()
            && declared > max_bytes
        {
            return Err(HttpError::TooLarge {
                endpoint: ENDPOINT,
                size: declared,
                limit: max_bytes,
            });
        }
        let mut received = 0_u64;
        while let Some(chunk) = response.chunk().await.map_err(|source| HttpError::Decode {
            endpoint: ENDPOINT,
            source,
        })? {
            received = received.saturating_add(chunk.len() as u64);
            if received > max_bytes {
                return Err(HttpError::TooLarge {
                    endpoint: ENDPOINT,
                    size: received,
                    limit: max_bytes,
                });
            }
            sink.write_all(&chunk).map_err(|source| HttpError::Sink {
                endpoint: ENDPOINT,
                source,
            })?;
        }
        Ok(received)
    }

    /// `POST {url}` — upload bytes to the host proxy (`POST /agent/attachments`).
    /// The bytes ride the request body; the name, content type and content hash
    /// ride headers (never a frame). The host owns the registry (A1) and returns
    /// the assigned `{id, ref}`.
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "the attachment proxy is wired into the executor by Lane G"
        )
    )]
    pub(crate) async fn upload_attachment(
        &self,
        url: &str,
        connect_token: &SecretString,
        name: &str,
        content_type: &str,
        sha256: &str,
        bytes: Vec<u8>,
    ) -> Result<UploadedAttachment, HttpError> {
        let response = self
            .client
            .post(url)
            .header(INTERNAL_TOKEN_HEADER, connect_token.expose_secret())
            .header(ATTACHMENT_NAME_HEADER, name)
            .header(ATTACHMENT_SHA256_HEADER, sha256)
            .header(CONTENT_TYPE, content_type)
            .body(bytes)
            .send()
            .await
            .map_err(|source| HttpError::Request {
                endpoint: "attachment_upload",
                source,
            })?;
        let response = error_for_status(response, "attachment_upload")?;
        response
            .json::<UploadedAttachment>()
            .await
            .map_err(|source| HttpError::Decode {
                endpoint: "attachment_upload",
                source,
            })
    }
}

/// The host-assigned identity returned by `POST /agent/attachments`. The host
/// owns the attachment registry (agent-architecture §14 A1): it mints the stable
/// `id` and the backend-specific `ref`; the runner computes `sha256`/`size`
/// locally. `ref` is a Rust keyword, so the wire `ref` maps to `reference`.
#[derive(Clone, Debug, Deserialize)]
pub(crate) struct UploadedAttachment {
    pub(crate) id: String,
    #[serde(rename = "ref")]
    pub(crate) reference: String,
}

/// Map a non-success status to [`HttpError::Status`] (keeping the endpoint label).
fn error_for_status(
    response: reqwest::Response,
    endpoint: &'static str,
) -> Result<reqwest::Response, HttpError> {
    let status = response.status();
    if status.is_success() {
        Ok(response)
    } else {
        Err(HttpError::Status {
            endpoint,
            status: status.as_u16(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use secrecy::SecretString;
    use serde_json::{Value, json};
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::HttpClient;

    /// The production client is built with bounded connect/read
    /// timeouts (through the same seam the test below exercises), so no
    /// endpoint can hang forever.
    #[test]
    fn production_timeouts_are_bounded_and_sane() {
        assert!(super::CONNECT_TIMEOUT >= Duration::from_secs(1));
        assert!(super::CONNECT_TIMEOUT <= Duration::from_secs(30));
        assert!(super::READ_TIMEOUT >= Duration::from_secs(10));
        assert!(super::READ_TIMEOUT <= Duration::from_mins(5));
    }

    /// A host that accepts the request but never answers is bounded by
    /// the idle-read guard — the call errors out instead of hanging forever
    /// (the old client had no timeouts at all).
    #[tokio::test]
    async fn stalled_response_is_bounded_by_the_read_timeout() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/agent/config/agent-1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({}))
                    .set_delay(Duration::from_mins(1)),
            )
            .mount(&server)
            .await;

        let http =
            HttpClient::with_timeouts(Duration::from_secs(5), Duration::from_millis(100)).unwrap();
        let url = format!("{}/agent/config/agent-1", server.uri());
        let started = std::time::Instant::now();
        let err = http
            .fetch_config(&url, &SecretString::from("tok"))
            .await
            .unwrap_err();
        match &err {
            super::HttpError::Request { endpoint, source } => {
                assert_eq!(*endpoint, "config");
                assert!(source.is_timeout(), "expected a timeout, got {source:?}");
            }
            other => panic!("expected a request timeout, got {other:?}"),
        }
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the request must fail fast, not wait out the response delay"
        );
    }

    #[tokio::test]
    async fn fetch_config_sends_token_header_and_returns_json() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/agent/config/agent-1"))
            .and(header("x-internal-token", "connect-xyz"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "engine": { "model": "m" } })),
            )
            .mount(&server)
            .await;

        let http = HttpClient::new().unwrap();
        let url = format!("{}/agent/config/agent-1", server.uri());
        let value: Value = http
            .fetch_config(&url, &SecretString::from("connect-xyz"))
            .await
            .unwrap();
        assert_eq!(value["engine"]["model"], json!("m"));
    }

    #[tokio::test]
    async fn download_attachment_sends_token_and_streams_bytes() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/agent/attachments/a-1"))
            .and(header("x-internal-token", "connect-xyz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"hello-bytes".to_vec()))
            .mount(&server)
            .await;

        let http = HttpClient::new().unwrap();
        let url = format!("{}/agent/attachments/a-1", server.uri());
        let mut sink = Vec::new();
        let received = http
            .download_attachment(
                &url,
                Some(&SecretString::from("connect-xyz")),
                1 << 20,
                &mut sink,
            )
            .await
            .unwrap();
        assert_eq!(sink, b"hello-bytes");
        assert_eq!(received, sink.len() as u64);
    }

    #[tokio::test]
    async fn download_attachment_without_token_sends_no_auth_header() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/agent/attachments/a-2"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"open".to_vec()))
            .mount(&server)
            .await;

        let http = HttpClient::new().unwrap();
        let url = format!("{}/agent/attachments/a-2", server.uri());
        let mut sink = Vec::new();
        http.download_attachment(&url, None, 1 << 20, &mut sink)
            .await
            .unwrap();
        assert_eq!(sink, b"open");

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert!(
            !requests[0].headers.contains_key("x-internal-token"),
            "a token-less download must not carry the auth header"
        );
    }

    #[tokio::test]
    async fn download_attachment_aborts_an_oversized_body_without_buffering_it() {
        // A body far over the cap: the declared Content-Length pre-check (or the
        // in-flight count for a chunked body) aborts, and the sink never receives
        // more than the cap — the whole body is never buffered (P1-10a).
        let server = MockServer::start().await;
        let body = vec![0xAB_u8; 1 << 20]; // 1 MiB served, 1 KiB cap
        Mock::given(method("GET"))
            .and(path("/agent/attachments/huge"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .mount(&server)
            .await;

        let http = HttpClient::new().unwrap();
        let url = format!("{}/agent/attachments/huge", server.uri());
        let mut sink = Vec::new();
        let err = http
            .download_attachment(&url, None, 1024, &mut sink)
            .await
            .unwrap_err();
        assert!(
            matches!(err, super::HttpError::TooLarge { limit: 1024, .. }),
            "expected TooLarge, got {err:?}"
        );
        assert!(
            sink.len() as u64 <= 1024,
            "sink must never receive more than the cap (got {} bytes)",
            sink.len()
        );
    }

    #[tokio::test]
    async fn upload_attachment_sends_bytes_and_metadata_headers() {
        use wiremock::matchers::body_bytes;

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/agent/attachments"))
            .and(header("x-internal-token", "connect-xyz"))
            .and(header("x-attachment-name", "report.txt"))
            .and(header("x-attachment-sha256", "abc123"))
            .and(body_bytes(b"file-body".to_vec()))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "id": "att-9", "ref": "/agent/attachments/att-9" })),
            )
            .mount(&server)
            .await;

        let http = HttpClient::new().unwrap();
        let url = format!("{}/agent/attachments", server.uri());
        let uploaded = http
            .upload_attachment(
                &url,
                &SecretString::from("connect-xyz"),
                "report.txt",
                "text/plain",
                "abc123",
                b"file-body".to_vec(),
            )
            .await
            .unwrap();
        assert_eq!(uploaded.id, "att-9");
        assert_eq!(uploaded.reference, "/agent/attachments/att-9");
    }

    #[tokio::test]
    async fn download_attachment_maps_non_success_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/agent/attachments/missing"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let http = HttpClient::new().unwrap();
        let url = format!("{}/agent/attachments/missing", server.uri());
        let mut sink = Vec::new();
        let err = http
            .download_attachment(
                &url,
                Some(&SecretString::from("connect-xyz")),
                1 << 20,
                &mut sink,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            super::HttpError::Status {
                endpoint: "attachment_download",
                status: 404
            }
        ));
    }

    #[tokio::test]
    async fn fetch_config_maps_non_success_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/agent/config/agent-1"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let http = HttpClient::new().unwrap();
        let url = format!("{}/agent/config/agent-1", server.uri());
        let err = http
            .fetch_config(&url, &SecretString::from("bad"))
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            super::HttpError::Status {
                endpoint: "config",
                status: 401
            }
        ));
    }
}
