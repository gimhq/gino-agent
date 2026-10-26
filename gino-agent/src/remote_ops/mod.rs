//! Host-driven operations that bypass the engine.
//!
//! These frames are live-only: they are answered straight over the socket and
//! never touch the inbox or the outbox, so nothing is replayed after a
//! reconnect. Each group is off until the host-assigned config enables it.
//!
//! While the runner is a member of any end-to-end encrypted task's group,
//! every operation is refused with `denied`, whatever the host enables, unless
//! the runner-local opt-in ([`allow_with_e2ee`]) is set.

pub(crate) mod fs;
pub(crate) mod pty;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use serde::Deserialize;
use serde_json::{Value, json};
use tracing::info;

use self::fs::{ErrorCode, FsError, FsOutput, FsRequest};
use crate::attachments::{AttachmentManager, run_blocking};

const FS_REQUEST: &str = "fs_request";
const FS_RESPONSE: &str = "fs_response";
/// The refusal message while the runner holds an encrypted task.
const E2EE_DENIED: &str =
    "remote operations are refused while this runner holds an end-to-end encrypted task";

/// The runner-local opt-in that serves remote operations while the runner
/// holds an encrypted task. Set only at daemon startup from its CLI flag or
/// environment; no host config or local agent API path reaches it.
static ALLOW_WITH_E2EE: AtomicBool = AtomicBool::new(false);

/// Set the runner-local opt-in for every [`RemoteOps`] built afterwards.
pub(crate) fn allow_with_e2ee() {
    ALLOW_WITH_E2EE.store(true, Ordering::SeqCst);
}

/// A parsed `fs_request` envelope; `data` is validated when it is answered.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Request {
    #[serde(rename = "type")]
    kind: String,
    req_id: String,
    #[serde(default)]
    data: Value,
}

/// Recognize an `fs_request` frame. Anything else — including one with no
/// `reqId`, which cannot be answered — is left to the durable inbound path.
pub(crate) fn parse_request(text: &str) -> Option<Request> {
    // Cheap pre-filter so ordinary frames are not parsed twice.
    if !text.contains(FS_REQUEST) {
        return None;
    }
    serde_json::from_str::<Request>(text)
        .ok()
        .filter(|request| request.kind == FS_REQUEST)
}

/// The `fs_response` refusing `request` while the runner holds an encrypted
/// task.
pub(crate) fn deny(request: &Request) -> String {
    info!(
        op = FS_REQUEST,
        reason = "e2ee",
        "refused a remote operation"
    );
    let error = FsError::new(ErrorCode::Denied, E2EE_DENIED);
    json!({ "type": FS_RESPONSE, "reqId": request.req_id, "data": { "ok": false, "error": error } })
        .to_string()
}

#[derive(Debug)]
struct State {
    fs: bool,
    pty: bool,
    workspace_dir: PathBuf,
    /// The byte channel `put`/`get` transfer file contents over.
    bytes: Option<Arc<AttachmentManager>>,
}

/// The live enablement switches and the base directory for relative paths.
#[derive(Debug)]
pub(crate) struct RemoteOps {
    state: Mutex<State>,
    pty_epoch: tokio::sync::watch::Sender<u64>,
    /// The runner-local opt-in, read once at construction.
    allow_with_e2ee: bool,
}

impl RemoteOps {
    pub(crate) fn new(fs: bool, workspace_dir: &Path) -> Self {
        Self {
            state: Mutex::new(State {
                fs,
                pty: false,
                workspace_dir: workspace_dir.to_path_buf(),
                bytes: None,
            }),
            pty_epoch: tokio::sync::watch::channel(0).0,
            allow_with_e2ee: ALLOW_WITH_E2EE.load(Ordering::SeqCst),
        }
    }

    /// Whether operations are refused because the runner holds an encrypted
    /// task. `holds_encrypted_scope` is asked only without the opt-in.
    pub(crate) fn refused_by_e2ee(&self, holds_encrypted_scope: impl FnOnce() -> bool) -> bool {
        !self.allow_with_e2ee && holds_encrypted_scope()
    }

    /// Attach the byte channel once the attachment plane is built.
    pub(crate) fn set_byte_channel(&self, bytes: Option<Arc<AttachmentManager>>) {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .bytes = bytes;
    }

    /// Apply the current host-assigned config.
    pub(crate) fn configure(&self, fs: bool, pty: bool, workspace_dir: &Path) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.fs = fs;
        if state.pty && !pty {
            self.pty_epoch
                .send_modify(|epoch| *epoch = epoch.wrapping_add(1));
        }
        state.pty = pty;
        workspace_dir.clone_into(&mut state.workspace_dir);
    }

    fn pty_settings(&self) -> (bool, PathBuf, tokio::sync::watch::Receiver<u64>) {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        (
            state.pty,
            state.workspace_dir.clone(),
            self.pty_epoch.subscribe(),
        )
    }

    /// Answer one request with its serialized `fs_response` frame.
    pub(crate) async fn respond(&self, request: Request) -> String {
        let result = self.run(request.data).await;
        let data = match result {
            Ok(output) => {
                let mut data = serde_json::to_value(output).unwrap_or_else(|_| json!({}));
                if let Value::Object(map) = &mut data {
                    map.insert("ok".to_owned(), Value::Bool(true));
                }
                data
            }
            Err(error) => json!({ "ok": false, "error": error }),
        };
        json!({ "type": FS_RESPONSE, "reqId": request.req_id, "data": data }).to_string()
    }

    async fn run(&self, data: Value) -> Result<FsOutput, FsError> {
        let (workspace_dir, bytes) = {
            let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            if !state.fs {
                return Err(FsError::new(
                    ErrorCode::Disabled,
                    "file operations are not enabled for this agent",
                ));
            }
            (state.workspace_dir.clone(), state.bytes.clone())
        };
        let request: FsRequest = serde_json::from_value(data)
            .map_err(|err| FsError::new(ErrorCode::Invalid, err.to_string()))?;
        match request {
            FsRequest::Put {
                path,
                reference,
                sha256,
                size,
            } => {
                let bytes = byte_channel(bytes)?;
                check_size(size, &bytes)?;
                let dest = workspace_dir.join(path);
                bytes
                    .download_file(&reference, &sha256, size, &dest)
                    .await?;
                Ok(FsOutput::default())
            }
            FsRequest::Get { path, upload } => {
                let bytes = byte_channel(bytes)?;
                let source = workspace_dir.join(path);
                let meta = std::fs::metadata(&source)?;
                if !meta.is_file() {
                    return Err(FsError::new(ErrorCode::Invalid, "not a regular file"));
                }
                check_size(meta.len(), &bytes)?;
                let content = run_blocking(move || std::fs::read(source)).await??;
                let size = content.len() as u64;
                let sha256 = bytes.upload_bytes(&upload, content).await?;
                Ok(FsOutput::uploaded(sha256, size))
            }
            request => run_blocking(move || fs::execute(&workspace_dir, request)).await?,
        }
    }
}

fn byte_channel(bytes: Option<Arc<AttachmentManager>>) -> Result<Arc<AttachmentManager>, FsError> {
    bytes.ok_or_else(|| FsError::new(ErrorCode::Io, "the attachment byte channel is unavailable"))
}

fn check_size(size: u64, bytes: &AttachmentManager) -> Result<(), FsError> {
    let limit = bytes.max_single_bytes();
    if size > limit {
        return Err(FsError::new(
            ErrorCode::TooLarge,
            format!("file is {size} bytes; the limit is {limit}"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use serde_json::{Value, json};

    use super::{RemoteOps, deny, parse_request};
    use crate::attachments::{AttachmentBackend, AttachmentError, AttachmentManager, sha256_hex};
    use crate::config::AttachmentsConfig;
    use crate::protocol::frames::AttachmentDescriptor;
    use crate::transport::http::UploadedAttachment;

    /// Blobs by `ref` for downloads; uploads recorded by name.
    #[derive(Default)]
    struct MemChannel {
        blobs: Mutex<HashMap<String, Vec<u8>>>,
        uploads: Mutex<HashMap<String, Vec<u8>>>,
    }

    #[async_trait]
    impl AttachmentBackend for Arc<MemChannel> {
        async fn download(
            &self,
            descriptor: &AttachmentDescriptor,
        ) -> Result<Vec<u8>, AttachmentError> {
            self.blobs
                .lock()
                .unwrap()
                .get(&descriptor.reference)
                .cloned()
                .ok_or(AttachmentError::Unsupported)
        }

        async fn upload(
            &self,
            name: &str,
            _content_type: &str,
            _sha256: &str,
            bytes: Vec<u8>,
        ) -> Result<UploadedAttachment, AttachmentError> {
            self.uploads.lock().unwrap().insert(name.to_owned(), bytes);
            Ok(UploadedAttachment {
                id: name.to_owned(),
                reference: format!("/agent/attachments/{name}"),
            })
        }
    }

    fn enabled(dir: &std::path::Path, max_single_bytes: u64) -> (RemoteOps, Arc<MemChannel>) {
        let channel = Arc::new(MemChannel::default());
        let config = AttachmentsConfig {
            max_single_bytes,
            ..AttachmentsConfig::default()
        };
        let manager = AttachmentManager::new(Box::new(Arc::clone(&channel)), dir, config);
        let ops = RemoteOps::new(true, dir);
        ops.set_byte_channel(Some(Arc::new(manager)));
        (ops, channel)
    }

    async fn ask(ops: &RemoteOps, data: Value) -> Value {
        let frame = json!({"type": "fs_request", "reqId": "r-1", "data": data});
        let request = parse_request(&frame.to_string()).unwrap();
        let response: Value = serde_json::from_str(&ops.respond(request).await).unwrap();
        assert_eq!(response["type"], json!("fs_response"));
        assert_eq!(response["reqId"], json!("r-1"));
        response["data"].clone()
    }

    #[test]
    fn only_an_answerable_fs_request_is_recognized() {
        assert!(parse_request(r#"{"type":"fs_request","reqId":"r","data":{}}"#).is_some());
        // No `reqId`: nothing to correlate a response with.
        assert!(parse_request(r#"{"type":"fs_request","data":{}}"#).is_none());
        // The marker inside another frame's payload is not a request.
        assert!(
            parse_request(r#"{"type":"message","taskId":"t","data":{"text":"fs_request"}}"#)
                .is_none()
        );
        assert!(parse_request(r#"{"type":"ack","id":1}"#).is_none());
    }

    #[tokio::test]
    async fn disabled_until_the_host_enables_the_group() {
        let dir = tempfile::tempdir().unwrap();
        let ops = RemoteOps::new(false, dir.path());
        let request = json!({"op": "mkdir", "path": "d"});

        let refused = ask(&ops, request.clone()).await;
        assert_eq!(refused["ok"], json!(false));
        assert_eq!(refused["error"]["code"], json!("disabled"));
        assert!(!dir.path().join("d").exists());

        ops.configure(true, false, dir.path());
        assert_eq!(ask(&ops, request).await, json!({"ok": true}));
        assert!(dir.path().join("d").is_dir());
    }

    #[test]
    fn an_encrypted_scope_refuses_unless_the_runner_opted_in() {
        let dir = tempfile::tempdir().unwrap();
        let mut ops = RemoteOps::new(true, dir.path());
        assert!(!ops.allow_with_e2ee, "off by default");
        assert!(ops.refused_by_e2ee(|| true));
        assert!(!ops.refused_by_e2ee(|| false));

        ops.allow_with_e2ee = true;
        assert!(!ops.refused_by_e2ee(|| panic!("not consulted with the opt-in")));
    }

    #[test]
    fn a_refusal_answers_denied_without_running_the_operation() {
        let frame =
            json!({"type": "fs_request", "reqId": "r-9", "data": {"op": "list", "path": "/"}});
        let request = parse_request(&frame.to_string()).unwrap();
        let response: Value = serde_json::from_str(&deny(&request)).unwrap();
        assert_eq!(response["type"], json!("fs_response"));
        assert_eq!(response["reqId"], json!("r-9"));
        assert_eq!(response["data"]["ok"], json!(false));
        assert_eq!(response["data"]["error"]["code"], json!("denied"));
        assert!(response["data"].get("entries").is_none());
    }

    #[tokio::test]
    async fn malformed_data_answers_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let ops = RemoteOps::new(true, dir.path());
        let response = ask(&ops, json!({"op": "chmod", "path": "a"})).await;
        assert_eq!(response["error"]["code"], json!("invalid"));
    }

    #[tokio::test]
    async fn relative_paths_follow_the_configured_workspace() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let ops = RemoteOps::new(true, first.path());
        ops.configure(true, false, second.path());
        ask(&ops, json!({"op": "mkdir", "path": "d"})).await;
        assert!(second.path().join("d").is_dir());
        assert!(!first.path().join("d").exists());
    }

    #[tokio::test]
    async fn put_downloads_verifies_and_replaces_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let (ops, channel) = enabled(dir.path(), 1024);
        let content = [0xFF, 0x00, 0xFE, b'x'];
        channel
            .blobs
            .lock()
            .unwrap()
            .insert("/agent/attachments/x1".to_owned(), content.to_vec());
        std::fs::write(dir.path().join("f.bin"), "old").unwrap();

        let done = ask(
            &ops,
            json!({"op": "put", "path": "f.bin", "ref": "/agent/attachments/x1",
                   "sha256": sha256_hex(&content), "size": content.len()}),
        )
        .await;
        assert_eq!(done, json!({"ok": true}));
        assert_eq!(std::fs::read(dir.path().join("f.bin")).unwrap(), content);
        // No temp file is left beside the destination.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn put_keeps_the_mode_of_the_file_it_replaces() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let (ops, channel) = enabled(dir.path(), 1024);
        channel
            .blobs
            .lock()
            .unwrap()
            .insert("r".to_owned(), b"new".to_vec());
        let secret = dir.path().join("secret.env");
        std::fs::write(&secret, "old").unwrap();
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();

        let done = ask(
            &ops,
            json!({"op": "put", "path": "secret.env", "ref": "r", "sha256": sha256_hex(b"new"), "size": 3}),
        )
        .await;
        assert_eq!(done, json!({"ok": true}));
        assert_eq!(std::fs::read(&secret).unwrap(), b"new");
        let mode = std::fs::metadata(&secret).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[tokio::test]
    async fn put_writes_through_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let (ops, channel) = enabled(dir.path(), 1024);
        channel
            .blobs
            .lock()
            .unwrap()
            .insert("r".to_owned(), b"new".to_vec());
        std::fs::create_dir(dir.path().join("real")).unwrap();
        std::fs::write(dir.path().join("real/target.txt"), "old").unwrap();
        std::os::unix::fs::symlink("real/target.txt", dir.path().join("link.txt")).unwrap();

        let done = ask(
            &ops,
            json!({"op": "put", "path": "link.txt", "ref": "r", "sha256": sha256_hex(b"new"), "size": 3}),
        )
        .await;
        assert_eq!(done, json!({"ok": true}));
        assert!(
            std::fs::symlink_metadata(dir.path().join("link.txt"))
                .unwrap()
                .is_symlink()
        );
        assert_eq!(
            std::fs::read(dir.path().join("real/target.txt")).unwrap(),
            b"new"
        );
        // No temp file is left beside the link or its target.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
        assert_eq!(
            std::fs::read_dir(dir.path().join("real")).unwrap().count(),
            1
        );
    }

    #[tokio::test]
    async fn put_with_a_wrong_digest_leaves_the_destination_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let (ops, channel) = enabled(dir.path(), 1024);
        channel
            .blobs
            .lock()
            .unwrap()
            .insert("/agent/attachments/x1".to_owned(), b"new".to_vec());
        std::fs::write(dir.path().join("f.txt"), "old").unwrap();

        let refused = ask(
            &ops,
            json!({"op": "put", "path": "f.txt", "ref": "/agent/attachments/x1",
                   "sha256": sha256_hex(b"other"), "size": 3}),
        )
        .await;
        assert_eq!(refused["error"]["code"], json!("io"));
        assert_eq!(
            std::fs::read_to_string(dir.path().join("f.txt")).unwrap(),
            "old"
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn put_into_a_missing_directory_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let (ops, channel) = enabled(dir.path(), 1024);
        channel
            .blobs
            .lock()
            .unwrap()
            .insert("r".to_owned(), b"x".to_vec());
        let refused = ask(
            &ops,
            json!({"op": "put", "path": "nope/f", "ref": "r", "sha256": sha256_hex(b"x"), "size": 1}),
        )
        .await;
        assert_eq!(refused["error"]["code"], json!("not_found"));
    }

    #[tokio::test]
    async fn get_uploads_the_file_under_the_requested_name() {
        let dir = tempfile::tempdir().unwrap();
        let (ops, channel) = enabled(dir.path(), 1024);
        std::fs::write(dir.path().join("a.txt"), "hello").unwrap();

        let done = ask(
            &ops,
            json!({"op": "get", "path": "a.txt", "upload": "xfer-1"}),
        )
        .await;
        assert_eq!(
            done,
            json!({"ok": true, "sha256": sha256_hex(b"hello"), "size": 5})
        );
        assert_eq!(channel.uploads.lock().unwrap()["xfer-1"], b"hello");
    }

    #[tokio::test]
    async fn get_refuses_a_missing_path_and_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let (ops, channel) = enabled(dir.path(), 1024);
        let missing = ask(&ops, json!({"op": "get", "path": "nope", "upload": "u"})).await;
        assert_eq!(missing["error"]["code"], json!("not_found"));
        let directory = ask(&ops, json!({"op": "get", "path": ".", "upload": "u"})).await;
        assert_eq!(directory["error"]["code"], json!("invalid"));
        assert!(channel.uploads.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn transfers_over_the_size_limit_are_refused_before_any_bytes_move() {
        let dir = tempfile::tempdir().unwrap();
        let (ops, channel) = enabled(dir.path(), 4);
        std::fs::write(dir.path().join("big"), "12345").unwrap();

        let get = ask(&ops, json!({"op": "get", "path": "big", "upload": "u"})).await;
        assert_eq!(get["error"]["code"], json!("too_large"));
        assert!(channel.uploads.lock().unwrap().is_empty());

        let put = ask(
            &ops,
            json!({"op": "put", "path": "new", "ref": "r", "sha256": sha256_hex(b"12345"), "size": 5}),
        )
        .await;
        assert_eq!(put["error"]["code"], json!("too_large"));
        assert!(!dir.path().join("new").exists());
    }

    #[tokio::test]
    async fn transfers_fail_cleanly_without_a_byte_channel() {
        let dir = tempfile::tempdir().unwrap();
        let ops = RemoteOps::new(true, dir.path());
        std::fs::write(dir.path().join("a"), "x").unwrap();
        let response = ask(&ops, json!({"op": "get", "path": "a", "upload": "u"})).await;
        assert_eq!(response["error"]["code"], json!("io"));
    }
}
