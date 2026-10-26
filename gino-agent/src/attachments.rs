//! Out-of-band attachment channel (agent-architecture §9 / §14 A1–A6).
//!
//! Bytes never ride a protocol frame — only **descriptors** do
//! (`{ id, name, content_type, size, sha256, ref, direction? }`, see
//! [`crate::protocol::frames::AttachmentDescriptor`]). This module owns the byte
//! plane:
//!
//! * a **config-selected backend** ([`build_backend`]): **host-proxy** (`GET`/
//!   `POST /agent/attachments`, connect-token auth, bytes through the host) —
//!   currently the only backend; the spec's presigned/CDN arm was never
//!   implemented and its config variant was deleted (A2).
//! * a **content-addressed cache** keyed by `sha256` under the workspace dir,
//!   shared within a workspace, with a size-cap + LRU GC (A4).
//! * the **materialize-inbound / collect-outbound** flow the executor drives:
//!   inbound descriptors → `work_dir/inputs/<name>`; everything under
//!   `work_dir/output/` → uploaded, descriptors returned on `thread_result` (A3).
//!
//! Safety: `sha256` is verified on every download (mismatch rejected), names are
//! sanitized against `../`/absolute paths, and size limits (100 MB single /
//! 500 MB per execution) + an optional content-type allowlist are enforced (A5).
//!
//! Construction (`build_backend`, [`AttachmentManager::new`],
//! [`AttachmentSource`]) is wired by the runner; the executor drives
//! [`AttachmentManager::materialize_inputs`] /
//! [`AttachmentManager::collect_outputs`].

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use async_trait::async_trait;
use reqwest::Url;
use secrecy::SecretString;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::{debug, warn};

use crate::config::{AttachmentBackendKind, AttachmentsConfig};
use crate::db::ThreadRow;
use crate::e2ee::{E2ee, EncryptionFailure};
use crate::protocol::frames::AttachmentDescriptor;
use crate::transport::http::{HttpClient, HttpError, UploadedAttachment};

/// Fixed sub-directory of a thread's `work_dir` for inbound attachments (A3).
const INPUTS_SUBDIR: &str = "inputs";
/// Fixed sub-directory of a thread's `work_dir` scanned for outbound artifacts (A3).
const OUTPUT_SUBDIR: &str = "output";
/// Content-addressed cache directory under the workspace dir (A4).
const CACHE_SUBDIR: &str = "attachments-cache";
/// `direction` marker for an agent-produced (outbound) artifact descriptor.
const DIRECTION_OUTBOUND: &str = "outbound";
/// Upload content type of an encrypted task's file envelope.
const SEALED_CONTENT_TYPE: &str = "application/octet-stream";

/// Run a blocking filesystem/hash closure on the tokio blocking pool, off the
/// async worker threads. The large-byte work in this crate —
/// 100 MB-scale reads/writes, full-buffer hashing, store scans — must not run
/// inline in an async fn; this is the one seam the provisioning/attachment
/// paths hop through. A panic inside `task` is resumed on the caller (same
/// observable behavior as running inline); a cancelled task (runtime shutdown)
/// surfaces as an `io::Error`, which both [`AttachmentError`] and
/// `ProvisioningError` absorb via their `Io` variants.
pub(crate) async fn run_blocking<T: Send + 'static>(
    task: impl FnOnce() -> T + Send + 'static,
) -> std::io::Result<T> {
    match tokio::task::spawn_blocking(task).await {
        Ok(value) => Ok(value),
        Err(err) if err.is_panic() => std::panic::resume_unwind(err.into_panic()),
        Err(err) => Err(std::io::Error::other(err)),
    }
}

/// Errors raised by the attachment layer. Byte content is never included.
#[derive(Debug, Error)]
pub(crate) enum AttachmentError {
    /// A single attachment exceeds the per-file size cap (A5).
    #[error("attachment exceeds the single-file size limit ({size} > {limit} bytes)")]
    SizeLimitExceeded { size: u64, limit: u64 },
    /// A descriptor declared a negative size — rejected explicitly instead of
    /// clamping to 0, which would bypass every declared-size pre-check (P1-10a).
    #[error("attachment declares an invalid size ({size} bytes)")]
    InvalidDeclaredSize { size: i64 },
    /// The inbound attachments for one execution exceed the per-execution cap (A5).
    #[error("attachments exceed the per-execution size limit ({total} > {limit} bytes)")]
    ExecutionLimitExceeded { total: u64, limit: u64 },
    /// The content type is not in the (non-empty) allowlist (A5).
    #[error("content type {content_type:?} is not allowed")]
    ContentTypeNotAllowed { content_type: String },
    /// The downloaded bytes did not hash to the descriptor's `sha256`.
    #[error("sha256 mismatch (expected {expected}, got {actual})")]
    IntegrityMismatch { expected: String, actual: String },
    /// The attachment name is unsafe (path traversal / absolute / separators).
    #[error("unsafe attachment name {name:?}")]
    UnsafeName { name: String },
    /// The selected backend cannot service this operation (e.g. presigned/CDN
    /// is config-selected but not implemented this campaign).
    #[error("attachment backend not configured/supported")]
    Unsupported,
    /// The byte transfer (host-proxy GET/POST) failed.
    #[error("attachment byte transfer failed: {0}")]
    Backend(#[from] HttpError),
    /// A filesystem error while materializing/collecting bytes.
    #[error("attachment filesystem error: {0}")]
    Io(#[from] std::io::Error),
    /// An encrypted task's attachment did not open (or its name is not
    /// opened).
    #[error("attachment could not be opened: {0}")]
    Encryption(EncryptionFailure),
}

/// The kind of an attachment error, for a log line that must not quote an
/// encrypted task's file name.
fn attachment_error_kind(err: &AttachmentError) -> &'static str {
    match err {
        AttachmentError::SizeLimitExceeded { .. }
        | AttachmentError::InvalidDeclaredSize { .. }
        | AttachmentError::ExecutionLimitExceeded { .. } => "size_limit",
        AttachmentError::ContentTypeNotAllowed { .. } => "content_type",
        AttachmentError::IntegrityMismatch { .. } => "integrity",
        AttachmentError::UnsafeName { .. } => "unsafe_name",
        AttachmentError::Unsupported => "unsupported",
        AttachmentError::Backend(_) => "transfer",
        AttachmentError::Io(_) => "io",
        AttachmentError::Encryption(_) => "encryption",
    }
}

impl From<crate::paths::UnsafeName> for AttachmentError {
    fn from(err: crate::paths::UnsafeName) -> Self {
        AttachmentError::UnsafeName { name: err.name }
    }
}

// ---------------------------------------------------------------------------
// Byte backend (A2): host-proxy default; presigned/CDN left unimplemented.
// ---------------------------------------------------------------------------

/// The byte plane: download/upload raw bytes for a descriptor. Integrity,
/// caching, limits and materialization live in [`AttachmentManager`]; an impl
/// only moves bytes.
///
/// Production code downloads exclusively through [`download_to`] (streaming,
/// capped — P1-10a); the buffered [`download`] exists as the simple seam
/// in-memory test backends implement, and the provided [`download_to`] adapts
/// it (the buffer is a small test fixture there, never a network body).
///
/// [`download`]: AttachmentBackend::download
/// [`download_to`]: AttachmentBackend::download_to
#[async_trait]
pub(crate) trait AttachmentBackend: Send + Sync {
    /// Fetch the bytes referenced by `descriptor` (`ref` is backend-specific),
    /// fully buffered. Implemented by in-memory (test) backends; a streaming
    /// backend leaves this unsupported and overrides [`download_to`] instead.
    ///
    /// [`download_to`]: AttachmentBackend::download_to
    async fn download(
        &self,
        _descriptor: &AttachmentDescriptor,
    ) -> Result<Vec<u8>, AttachmentError> {
        Err(AttachmentError::Unsupported)
    }

    /// Stream the bytes referenced by `descriptor` into `sink`, aborting as soon
    /// as the transfer would exceed `max_bytes` (the sink never receives more
    /// than the cap). Returns the byte count. The default adapts a buffered
    /// [`download`] impl and enforces the cap post-buffer — acceptable only for
    /// in-memory backends whose whole store already lives in memory.
    ///
    /// [`download`]: AttachmentBackend::download
    async fn download_to(
        &self,
        descriptor: &AttachmentDescriptor,
        max_bytes: u64,
        sink: &mut (dyn std::io::Write + Send),
    ) -> Result<u64, AttachmentError> {
        let bytes = self.download(descriptor).await?;
        let size = bytes.len() as u64;
        if size > max_bytes {
            return Err(AttachmentError::SizeLimitExceeded {
                size,
                limit: max_bytes,
            });
        }
        sink.write_all(&bytes)?;
        Ok(size)
    }

    /// Upload `bytes`; return the host-assigned `{id, ref}` (A1).
    async fn upload(
        &self,
        name: &str,
        content_type: &str,
        sha256: &str,
        bytes: Vec<u8>,
    ) -> Result<UploadedAttachment, AttachmentError>;
}

/// Select the byte backend from config (A2). Host-proxy is currently the only
/// backend (the unimplemented presigned/CDN variant was deleted).
pub(crate) fn build_backend(
    config: &AttachmentsConfig,
    http: HttpClient,
    http_base: String,
    connect_token: SecretString,
) -> Box<dyn AttachmentBackend> {
    match config.backend {
        AttachmentBackendKind::HostProxy => {
            Box::new(HostProxyBackend::new(http, http_base, connect_token))
        }
    }
}

/// Host-proxy backend (A2 default): the host streams bytes through
/// `GET /agent/attachments/:id` and `POST /agent/attachments`, authenticated
/// with the connect token (the same header as register/config/output).
#[derive(Clone, Debug)]
pub(crate) struct HostProxyBackend {
    http: HttpClient,
    /// Orchestrator HTTP base (no trailing slash), used to resolve a relative
    /// `ref` and to build the upload URL.
    http_base: String,
    connect_token: SecretString,
}

impl HostProxyBackend {
    pub(crate) fn new(
        http: HttpClient,
        mut http_base: String,
        connect_token: SecretString,
    ) -> Self {
        // Trim trailing slashes in place so the owned String is consumed (no
        // needless re-allocation), keeping `{base}{/path}` joins clean.
        http_base.truncate(http_base.trim_end_matches('/').len());
        Self {
            http,
            http_base,
            connect_token,
        }
    }

    /// Resolve a descriptor `ref` to a full download URL. An absolute URL is used
    /// as-is; a host-proxy path (`/agent/attachments/:id`) is joined to the base.
    fn resolve(&self, reference: &str) -> String {
        if reference.starts_with("http://") || reference.starts_with("https://") {
            reference.to_owned()
        } else if let Some(rest) = reference.strip_prefix('/') {
            format!("{}/{rest}", self.http_base)
        } else {
            format!("{}/{reference}", self.http_base)
        }
    }

    fn upload_url(&self) -> String {
        format!("{}/agent/attachments", self.http_base)
    }

    /// Whether `url` shares the configured host base's origin (scheme + host +
    /// port). Unparseable URLs are conservatively NOT same-origin.
    fn same_origin(&self, url: &str) -> bool {
        let (Ok(target), Ok(base)) = (Url::parse(url), Url::parse(&self.http_base)) else {
            return false;
        };
        target.scheme() == base.scheme()
            && target.host() == base.host()
            && target.port_or_known_default() == base.port_or_known_default()
    }
}

#[async_trait]
impl AttachmentBackend for HostProxyBackend {
    // The buffered `download` is deliberately left at its unsupported default:
    // every host-proxy byte transfer must go through the streaming, capped path
    // below — reintroducing a whole-body buffer here would resurrect P1-10a.

    async fn download_to(
        &self,
        descriptor: &AttachmentDescriptor,
        max_bytes: u64,
        sink: &mut (dyn std::io::Write + Send),
    ) -> Result<u64, AttachmentError> {
        let url = self.resolve(&descriptor.reference);
        // DECISION (P1-10c): the connect token authenticates this agent to ITS
        // host only, so it is attached iff the resolved URL is same-origin with
        // the configured host base. An absolute `ref` to any other origin (e.g.
        // a presigned/CDN URL) is fetched WITHOUT credentials rather than
        // rejected — sha256 verification still gates the content, and the token
        // can never travel to an arbitrary origin.
        let token = self.same_origin(&url).then_some(&self.connect_token);
        self.http
            .download_attachment(&url, token, max_bytes, sink)
            .await
            .map_err(|err| match err {
                HttpError::TooLarge { size, limit, .. } => {
                    AttachmentError::SizeLimitExceeded { size, limit }
                }
                other => AttachmentError::Backend(other),
            })
    }

    async fn upload(
        &self,
        name: &str,
        content_type: &str,
        sha256: &str,
        bytes: Vec<u8>,
    ) -> Result<UploadedAttachment, AttachmentError> {
        let url = self.upload_url();
        Ok(self
            .http
            .upload_attachment(&url, &self.connect_token, name, content_type, sha256, bytes)
            .await?)
    }
}

// ---------------------------------------------------------------------------
// Inbound descriptor source (executor seam; mirrors `executor::PromptSource`).
// ---------------------------------------------------------------------------

/// Resolves the inbound attachment descriptors to materialize for a thread. The
/// `threads` row carries no attachment column (they arrive on the inbox
/// `message`), so the executor takes a resolver; Lane G supplies the real one.
pub(crate) trait AttachmentSource: Send + Sync {
    /// Inbound descriptors bound to `thread` (empty if none).
    fn inbound_for(&self, thread: &ThreadRow) -> Vec<AttachmentDescriptor>;
}

// ---------------------------------------------------------------------------
// Manager: integrity, content-addressed cache, limits, materialization.
// ---------------------------------------------------------------------------

/// Owns the attachment byte plane for an executor: a [`AttachmentBackend`], the
/// content-addressed cache directory, and the configured limits.
pub(crate) struct AttachmentManager {
    backend: Box<dyn AttachmentBackend>,
    cache_dir: PathBuf,
    config: AttachmentsConfig,
}

impl std::fmt::Debug for AttachmentManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachmentManager")
            .field("cache_dir", &self.cache_dir)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl AttachmentManager {
    /// Build a manager over `backend`, caching content-addressed bytes under
    /// `<workspace_dir>/attachments-cache` and enforcing `config`'s limits.
    pub(crate) fn new(
        backend: Box<dyn AttachmentBackend>,
        workspace_dir: &Path,
        config: AttachmentsConfig,
    ) -> Self {
        Self {
            backend,
            cache_dir: workspace_dir.join(CACHE_SUBDIR),
            config,
        }
    }

    /// Materialize every inbound `descriptor` into `work_dir/inputs/<name>` (A3),
    /// verifying `sha256`, enforcing the size caps + content-type allowlist, and
    /// sanitizing names against traversal. Outbound descriptors are skipped.
    /// Returns the written paths. The caller fails the thread on `Err`.
    pub(crate) async fn materialize_inputs(
        &self,
        work_dir: &Path,
        descriptors: &[AttachmentDescriptor],
    ) -> Result<Vec<PathBuf>, AttachmentError> {
        self.materialize(work_dir, descriptors, None).await
    }

    /// [`Self::materialize_inputs`] for an encrypted task (task-content §2):
    /// each blob is a file envelope that `sha256`/`size` describe. The
    /// verified envelope (also what the cache keeps) is opened through `e2ee`
    /// and the plaintext written under the descriptor's opened name, the
    /// content type inferred from that name.
    pub(crate) async fn materialize_encrypted_inputs(
        &self,
        work_dir: &Path,
        descriptors: &[AttachmentDescriptor],
        e2ee: &E2ee,
        task_id: &str,
    ) -> Result<Vec<PathBuf>, AttachmentError> {
        self.materialize(work_dir, descriptors, Some((e2ee, task_id)))
            .await
    }

    async fn materialize(
        &self,
        work_dir: &Path,
        descriptors: &[AttachmentDescriptor],
        encrypted: Option<(&E2ee, &str)>,
    ) -> Result<Vec<PathBuf>, AttachmentError> {
        // Pre-check declared sizes against the per-execution budget so a flood of
        // oversized descriptors is rejected before any byte transfer. A negative
        // declared size is rejected explicitly (P1-10a): clamping it to 0 would
        // let the descriptor bypass every declared-size gate.
        let mut declared_total = 0_u64;
        for descriptor in descriptors.iter().filter(|d| !is_outbound(d)) {
            let declared = u64::try_from(descriptor.size).map_err(|_| {
                AttachmentError::InvalidDeclaredSize {
                    size: descriptor.size,
                }
            })?;
            declared_total = declared_total.saturating_add(declared);
        }
        if declared_total > self.config.max_execution_bytes {
            return Err(AttachmentError::ExecutionLimitExceeded {
                total: declared_total,
                limit: self.config.max_execution_bytes,
            });
        }

        let inputs_dir = work_dir.join(INPUTS_SUBDIR);
        let mut written = Vec::new();
        let mut total = 0_u64;
        for descriptor in descriptors {
            if is_outbound(descriptor) {
                continue;
            }
            let name = descriptor.name.as_plain().ok_or_else(|| match encrypted {
                Some(_) => AttachmentError::Encryption(EncryptionFailure::from(
                    gino_e2ee::Error::PlaintextRejected,
                )),
                None => AttachmentError::UnsafeName {
                    name: "(sealed)".to_owned(),
                },
            })?;
            let safe = crate::paths::safe_component(name)?;
            let bytes = match encrypted {
                None => self.fetch(descriptor).await?,
                Some((e2ee, task_id)) => {
                    self.check_content_type(&guess_content_type(safe))?;
                    let envelope = self.fetch_envelope(descriptor).await?;
                    let digest = gino_e2ee::FileDigest {
                        sha256: descriptor.sha256.to_ascii_lowercase(),
                        size: u64::try_from(descriptor.size).unwrap_or(u64::MAX),
                    };
                    e2ee.open_file(task_id, &envelope, &digest)
                        .await
                        .map_err(AttachmentError::Encryption)?
                }
            };
            let size = bytes.len();
            total = total.saturating_add(size as u64);
            if total > self.config.max_execution_bytes {
                return Err(AttachmentError::ExecutionLimitExceeded {
                    total,
                    limit: self.config.max_execution_bytes,
                });
            }
            // 100 MB-scale write → blocking pool, not the async worker.
            let dest = inputs_dir.join(safe);
            let dir = inputs_dir.clone();
            let write_dest = dest.clone();
            run_blocking(move || {
                std::fs::create_dir_all(&dir)?;
                std::fs::write(&write_dest, &bytes)
            })
            .await??;
            if encrypted.is_none() {
                debug!(name = %safe, bytes = size, "materialized inbound attachment");
            }
            written.push(dest);
        }
        Ok(written)
    }

    /// Upload every regular file under `work_dir/output/` (A3) and return the
    /// resulting outbound descriptors. Best-effort per file: a file that exceeds
    /// the single-file cap, fails the allowlist, or fails to upload is logged and
    /// skipped (a partial artifact set must not sink an otherwise-good run); the
    /// per-execution budget caps the total. Symlinks are ignored (no traversal).
    pub(crate) async fn collect_outputs(&self, work_dir: &Path) -> Vec<AttachmentDescriptor> {
        self.collect(work_dir, None).await.unwrap_or_default()
    }

    /// [`Self::collect_outputs`] for an encrypted task (task-content §2):
    /// each file is sealed through `e2ee` as a file envelope, uploaded under
    /// the opaque name `<sha256>.bin` as `application/octet-stream` and
    /// described by the envelope's `sha256`/`size`; the descriptor `name`
    /// carries the real name for the `thread_result` sealer. Only the
    /// envelope is cached. A file that cannot be sealed fails the whole
    /// collection; the real names are never logged.
    pub(crate) async fn collect_encrypted_outputs(
        &self,
        work_dir: &Path,
        e2ee: &E2ee,
        task_id: &str,
    ) -> Result<Vec<AttachmentDescriptor>, EncryptionFailure> {
        self.collect(work_dir, Some((e2ee, task_id))).await
    }

    async fn collect(
        &self,
        work_dir: &Path,
        encrypted: Option<(&E2ee, &str)>,
    ) -> Result<Vec<AttachmentDescriptor>, EncryptionFailure> {
        let output_dir = work_dir.join(OUTPUT_SUBDIR);
        // The recursive dir walk is a filesystem scan → blocking pool.
        let scan = run_blocking(move || list_files(&output_dir))
            .await
            .and_then(|listed| listed);
        let files = match scan {
            Ok(files) => files,
            Err(err) => {
                warn!(error = %err, "failed to scan output dir for attachments");
                return Ok(Vec::new());
            }
        };
        let mut descriptors = Vec::new();
        let mut total = 0_u64;
        for (abs, rel) in files {
            // An encrypted task's file names are content: logged as sealed.
            let file = if encrypted.is_some() {
                "(sealed)"
            } else {
                rel.as_str()
            };
            let size = match std::fs::metadata(&abs) {
                Ok(meta) => meta.len(),
                Err(err) => {
                    warn!(file, error = %err, "skipping output artifact (stat failed)");
                    continue;
                }
            };
            if size > self.config.max_single_bytes {
                warn!(file, size, "skipping oversized output artifact");
                continue;
            }
            if total.saturating_add(size) > self.config.max_execution_bytes {
                warn!(file, "per-execution output budget reached; stopping");
                break;
            }
            match self.upload_one(&abs, &rel, encrypted).await {
                Ok(descriptor) => {
                    total = total.saturating_add(size);
                    descriptors.push(descriptor);
                }
                Err(AttachmentError::Encryption(failure)) => return Err(failure),
                Err(err) if encrypted.is_some() => {
                    warn!(
                        file,
                        kind = attachment_error_kind(&err),
                        "skipping output artifact"
                    );
                }
                Err(err) => warn!(file, error = %err, "skipping output artifact"),
            }
        }
        Ok(descriptors)
    }

    /// The configured single-file size cap (A5). The config/skills provisioner
    /// ([`crate::provisioning`]) picks this as its [`fetch_verified`]
    /// `max_bytes`.
    ///
    /// [`fetch_verified`]: AttachmentManager::fetch_verified
    pub(crate) fn max_single_bytes(&self) -> u64 {
        self.config.max_single_bytes
    }

    /// Fetch the verified bytes for a content-addressed artifact by `reference` +
    /// `sha256`, independent of any attachment **descriptor** — the byte seam the
    /// config/skills provisioner ([`crate::provisioning`]) fetches
    /// through.
    ///
    /// Serves from the content-addressed cache by `sha256` when present (no
    /// download); otherwise **streams** the download into a temp file next to the
    /// cache with an in-flight `max_bytes` cap and incremental hashing (P1-10a —
    /// the body is never buffered whole; an over-cap transfer aborts mid-stream),
    /// verifies the streamed hash against `sha256` (rejecting
    /// [`AttachmentError::IntegrityMismatch`] on a miss), promotes the verified
    /// temp file into the cache, and returns the (cap-bounded) bytes. Unlike
    /// [`fetch`] **no content-type allowlist** is applied — config artifacts carry
    /// no declared content type.
    ///
    /// [`fetch`]: AttachmentManager::fetch
    pub(crate) async fn fetch_verified(
        &self,
        reference: &str,
        sha256: &str,
        max_bytes: u64,
    ) -> Result<Vec<u8>, AttachmentError> {
        // The cache probe re-hashes the whole cached blob (verification sweep) —
        // off the async worker.
        let cached = {
            let cache_dir = self.cache_dir.clone();
            let sha = sha256.to_owned();
            run_blocking(move || cache_get(&cache_dir, &sha)).await?
        };
        if let Some(bytes) = cached {
            debug!(sha256 = %sha256, "content-addressed artifact cache hit");
            return Ok(bytes);
        }
        // A malformed expected hash can never verify — reject before any transfer
        // (and it keeps the validated key safe as a temp/cache path component).
        let Some(key) = cache_key(sha256) else {
            return Err(AttachmentError::IntegrityMismatch {
                expected: sha256.to_owned(),
                actual: "(expected hash is not valid sha256 hex)".to_owned(),
            });
        };
        // Only `ref` + `sha256` matter to the byte backend; the rest is defaulted.
        let descriptor = AttachmentDescriptor {
            id: String::new(),
            name: String::new().into(),
            content_type: String::new(),
            size: 0,
            sha256: sha256.to_owned(),
            reference: reference.to_owned(),
            direction: None,
        };
        std::fs::create_dir_all(&self.cache_dir)?;
        let tmp = self.cache_dir.join(format!(".tmp.dl.{key}"));
        let bytes = match self
            .download_verified_to(&descriptor, &key, max_bytes, &tmp)
            .await
        {
            Ok(bytes) => bytes,
            Err(err) => {
                let _ = std::fs::remove_file(&tmp);
                return Err(err);
            }
        };
        // Promote the verified temp file into the cache by rename (same dir, so
        // same filesystem); an over-cache-cap blob is simply not cached. The
        // rename is cheap but the follow-up LRU pass scans the whole cache dir —
        // run the pair on the blocking pool.
        if bytes.len() as u64 <= self.config.cache_max_bytes {
            let cache_dir = self.cache_dir.clone();
            let cap = self.config.cache_max_bytes;
            let tmp = tmp.clone();
            run_blocking(move || {
                if std::fs::rename(&tmp, cache_dir.join(&key)).is_ok() {
                    cache_gc(&cache_dir, cap);
                } else {
                    let _ = std::fs::remove_file(&tmp);
                }
            })
            .await?;
        } else {
            let _ = std::fs::remove_file(&tmp);
        }
        Ok(bytes)
    }

    /// Stream the blob at `reference` straight into `dest`, bypassing the cache:
    /// the bytes land in a temp file beside `dest` under the in-flight
    /// `max_bytes` cap, are verified against `sha256`, then renamed into place,
    /// so `dest` is never observed half-written. An existing `dest` keeps its
    /// permissions, and a symlink is written through to its target.
    pub(crate) async fn download_file(
        &self,
        reference: &str,
        sha256: &str,
        max_bytes: u64,
        dest: &Path,
    ) -> Result<(), AttachmentError> {
        let descriptor = AttachmentDescriptor {
            id: String::new(),
            name: String::new().into(),
            content_type: String::new(),
            size: 0,
            sha256: sha256.to_owned(),
            reference: reference.to_owned(),
            direction: None,
        };
        let dest = std::fs::canonicalize(dest).unwrap_or_else(|_| dest.to_path_buf());
        let mut tmp = dest.as_os_str().to_owned();
        tmp.push(format!(".{}.part", uuid::Uuid::new_v4()));
        let tmp = PathBuf::from(tmp);
        let result = self.stream_verified(&descriptor, max_bytes, &tmp).await;
        let result = result.and_then(|()| {
            if let Ok(existing) = std::fs::metadata(&dest) {
                std::fs::set_permissions(&tmp, existing.permissions())?;
            }
            Ok(std::fs::rename(&tmp, &dest)?)
        });
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }

    async fn stream_verified(
        &self,
        descriptor: &AttachmentDescriptor,
        max_bytes: u64,
        tmp: &Path,
    ) -> Result<(), AttachmentError> {
        let mut sink = HashingSink {
            inner: std::fs::File::create(tmp)?,
            hasher: Sha256::new(),
        };
        self.backend
            .download_to(descriptor, max_bytes, &mut sink)
            .await?;
        sink.inner.flush()?;
        let actual = hex_digest(sink.hasher);
        if actual != descriptor.sha256.to_ascii_lowercase() {
            return Err(AttachmentError::IntegrityMismatch {
                expected: descriptor.sha256.clone(),
                actual,
            });
        }
        Ok(())
    }

    /// Upload `bytes` under `name` with no content-type allowlist and no cache
    /// copy; returns their sha256.
    pub(crate) async fn upload_bytes(
        &self,
        name: &str,
        bytes: Vec<u8>,
    ) -> Result<String, AttachmentError> {
        let sha256 = sha256_hex(&bytes);
        self.backend
            .upload(name, "application/octet-stream", &sha256, bytes)
            .await?;
        Ok(sha256)
    }

    /// Stream `descriptor` into `tmp` with the in-flight `max_bytes` cap and
    /// incremental hashing, verify the streamed hash equals `key` (the validated
    /// lowercase expected hash), and read the cap-bounded file back. The caller
    /// owns `tmp` cleanup on error.
    async fn download_verified_to(
        &self,
        descriptor: &AttachmentDescriptor,
        key: &str,
        max_bytes: u64,
        tmp: &Path,
    ) -> Result<Vec<u8>, AttachmentError> {
        let mut sink = HashingSink {
            inner: std::fs::File::create(tmp)?,
            hasher: Sha256::new(),
        };
        self.backend
            .download_to(descriptor, max_bytes, &mut sink)
            .await?;
        sink.inner.flush()?;
        drop(sink.inner);
        let actual = hex_digest(sink.hasher);
        if actual != key {
            return Err(AttachmentError::IntegrityMismatch {
                expected: descriptor.sha256.clone(),
                actual,
            });
        }
        // Bounded read-back: the in-flight cap guarantees the file ≤ max_bytes.
        // Still up to 100 MB — read on the blocking pool.
        let tmp = tmp.to_path_buf();
        Ok(run_blocking(move || std::fs::read(&tmp)).await??)
    }

    /// Fetch one descriptor's verified bytes: enforce the single-file cap + the
    /// content-type allowlist, then download/verify/cache via [`fetch_verified`]
    /// (the cap + cache + integrity check are shared; only the inbound-specific
    /// content-type allowlist and the cheap declared-size pre-check live here).
    ///
    /// [`fetch_verified`]: AttachmentManager::fetch_verified
    async fn fetch(&self, descriptor: &AttachmentDescriptor) -> Result<Vec<u8>, AttachmentError> {
        self.check_content_type(&descriptor.content_type)?;
        self.fetch_envelope(descriptor).await
    }

    /// Fetch one descriptor's verified bytes without the content-type gate:
    /// an encrypted task's blob is an opaque envelope, gated on its opened
    /// name instead.
    async fn fetch_envelope(
        &self,
        descriptor: &AttachmentDescriptor,
    ) -> Result<Vec<u8>, AttachmentError> {
        // Pre-empt an oversized download off the declared size (a config artifact
        // carries no declared size, so this gate is descriptor-only). A negative
        // declared size is rejected, never clamped to 0 (P1-10a).
        let declared =
            u64::try_from(descriptor.size).map_err(|_| AttachmentError::InvalidDeclaredSize {
                size: descriptor.size,
            })?;
        if declared > self.config.max_single_bytes {
            return Err(AttachmentError::SizeLimitExceeded {
                size: declared,
                limit: self.config.max_single_bytes,
            });
        }
        self.fetch_verified(
            &descriptor.reference,
            &descriptor.sha256,
            self.config.max_single_bytes,
        )
        .await
    }

    /// Read, hash, cache and upload one output file; build its descriptor.
    /// On an encrypted task the file envelope is what is hashed, cached and
    /// uploaded.
    async fn upload_one(
        &self,
        abs: &Path,
        rel: &str,
        encrypted: Option<(&E2ee, &str)>,
    ) -> Result<AttachmentDescriptor, AttachmentError> {
        // The content-type gate needs only the name — run it before touching the
        // bytes, so the blocking hop below is not wasted on a rejected file.
        let content_type = guess_content_type(rel);
        self.check_content_type(&content_type)?;
        if let Some((e2ee, task_id)) = encrypted {
            return self.upload_sealed(abs, rel, e2ee, task_id).await;
        }
        // Full read + full-buffer hash + cache write (incl. the LRU scan inside
        // cache_put) of a 100 MB-scale artifact → blocking pool.
        let (bytes, sha256) = {
            let abs = abs.to_path_buf();
            let max_single = self.config.max_single_bytes;
            let cache_dir = self.cache_dir.clone();
            let cache_cap = self.config.cache_max_bytes;
            run_blocking(move || -> Result<(Vec<u8>, String), AttachmentError> {
                let bytes = std::fs::read(&abs)?;
                let size = bytes.len() as u64;
                if size > max_single {
                    return Err(AttachmentError::SizeLimitExceeded {
                        size,
                        limit: max_single,
                    });
                }
                let sha256 = sha256_hex(&bytes);
                // Cache before the move so a later inbound fetch of the same
                // bytes hits.
                cache_put(&cache_dir, cache_cap, &sha256, &bytes);
                Ok((bytes, sha256))
            })
            .await??
        };
        let size = bytes.len();
        let uploaded = self
            .backend
            .upload(rel, &content_type, &sha256, bytes)
            .await?;
        Ok(AttachmentDescriptor {
            id: uploaded.id,
            name: rel.into(),
            content_type,
            size: i64::try_from(size).unwrap_or(i64::MAX),
            sha256,
            reference: uploaded.reference,
            direction: Some(DIRECTION_OUTBOUND.to_owned()),
        })
    }

    /// Seal one output file of an encrypted task and upload the envelope
    /// under `<sha256>.bin`.
    async fn upload_sealed(
        &self,
        abs: &Path,
        rel: &str,
        e2ee: &E2ee,
        task_id: &str,
    ) -> Result<AttachmentDescriptor, AttachmentError> {
        let bytes = {
            let abs = abs.to_path_buf();
            let max_single = self.config.max_single_bytes;
            run_blocking(move || -> Result<Vec<u8>, AttachmentError> {
                let bytes = std::fs::read(&abs)?;
                let size = bytes.len() as u64;
                if size > max_single {
                    return Err(AttachmentError::SizeLimitExceeded {
                        size,
                        limit: max_single,
                    });
                }
                Ok(bytes)
            })
            .await??
        };
        let (envelope, digest) = e2ee
            .seal_file(task_id, &bytes)
            .await
            .map_err(AttachmentError::Encryption)?;
        drop(bytes);
        let envelope = {
            let cache_dir = self.cache_dir.clone();
            let cache_cap = self.config.cache_max_bytes;
            let sha256 = digest.sha256.clone();
            run_blocking(move || {
                cache_put(&cache_dir, cache_cap, &sha256, &envelope);
                envelope
            })
            .await?
        };
        let uploaded = self
            .backend
            .upload(
                &format!("{}.bin", digest.sha256),
                SEALED_CONTENT_TYPE,
                &digest.sha256,
                envelope,
            )
            .await?;
        Ok(AttachmentDescriptor {
            id: uploaded.id,
            name: rel.into(),
            content_type: SEALED_CONTENT_TYPE.to_owned(),
            size: i64::try_from(digest.size).unwrap_or(i64::MAX),
            sha256: digest.sha256,
            reference: uploaded.reference,
            direction: Some(DIRECTION_OUTBOUND.to_owned()),
        })
    }

    fn check_content_type(&self, content_type: &str) -> Result<(), AttachmentError> {
        if self.config.content_type_allowlist.is_empty()
            || self
                .config
                .content_type_allowlist
                .iter()
                .any(|allowed| allowed == content_type)
        {
            Ok(())
        } else {
            Err(AttachmentError::ContentTypeNotAllowed {
                content_type: content_type.to_owned(),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Content-addressed cache (A4). Free functions (not methods) so the async call
// sites can move an owned `cache_dir` + cap into a `spawn_blocking` closure
// — every one of these touches the filesystem, and `cache_get`/
// `cache_put`/`cache_gc` do full-blob hashing or a whole-dir scan.
// ---------------------------------------------------------------------------

/// Read cached bytes for `sha256` (verifying they still hash correctly; a
/// corrupt entry is removed). `None` on miss or unsafe key.
fn cache_get(cache_dir: &Path, sha256: &str) -> Option<Vec<u8>> {
    let key = cache_key(sha256)?;
    let path = cache_dir.join(&key);
    let bytes = std::fs::read(&path).ok()?;
    if sha256_hex(&bytes) == key {
        touch(&path);
        Some(bytes)
    } else {
        let _ = std::fs::remove_file(&path);
        None
    }
}

/// Store `bytes` under their `sha256` (content-addressed), then GC the cache
/// back under the size cap. Best-effort: any failure leaves the cache intact
/// and the caller keeps the bytes it already has.
fn cache_put(cache_dir: &Path, cache_max_bytes: u64, sha256: &str, bytes: &[u8]) {
    let Some(key) = cache_key(sha256) else {
        return;
    };
    // A single blob larger than the whole cap can never fit; skip caching it.
    if bytes.len() as u64 > cache_max_bytes {
        return;
    }
    if std::fs::create_dir_all(cache_dir).is_err() {
        return;
    }
    let tmp = cache_dir.join(format!(".tmp.{key}"));
    if std::fs::write(&tmp, bytes).is_err() {
        return;
    }
    let final_path = cache_dir.join(&key);
    if std::fs::rename(&tmp, &final_path).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return;
    }
    cache_gc(cache_dir, cache_max_bytes);
}

/// Evict least-recently-used cache entries until total size ≤ the cap (A4).
/// Recency is the file `modified` time, bumped on each cache hit by [`touch`].
fn cache_gc(cache_dir: &Path, cap: u64) {
    let Ok(entries) = std::fs::read_dir(cache_dir) else {
        return;
    };
    let mut files: Vec<(PathBuf, u64, SystemTime)> = Vec::new();
    let mut total = 0_u64;
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        // Only real cache entries count; skip `.tmp.*` and anything stray.
        if cache_key(&name).is_none() {
            continue;
        }
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        total = total.saturating_add(meta.len());
        let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        files.push((entry.path(), meta.len(), modified));
    }
    if total <= cap {
        return;
    }
    files.sort_by_key(|(_, _, modified)| *modified);
    for (path, len, _) in files {
        if total <= cap {
            break;
        }
        if std::fs::remove_file(&path).is_ok() {
            total = total.saturating_sub(len);
        }
    }
}

// ---------------------------------------------------------------------------
// Free helpers
// ---------------------------------------------------------------------------

/// Lowercase hex SHA-256 of `bytes` — the integrity check + cache key (A4).
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_digest(hasher)
}

/// Finalize `hasher` into its lowercase hex digest.
fn hex_digest(hasher: Sha256) -> String {
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        // Writing to a String is infallible.
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// An [`std::io::Write`] adapter that feeds every written byte into a running
/// SHA-256 alongside the inner writer — the incremental-hash half of the
/// streaming download path (P1-10a): the hash is complete the moment the stream
/// ends, without ever holding the body in memory.
struct HashingSink<W: std::io::Write> {
    inner: W,
    hasher: Sha256,
}

impl<W: std::io::Write> std::io::Write for HashingSink<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.hasher.update(&buf[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// A 64-char lowercase hex string usable as a cache filename, or `None` if the
/// input is not a valid sha256 hex (so an untrusted descriptor hash can never
/// escape the cache dir as a path component).
fn cache_key(sha256: &str) -> Option<String> {
    let key = sha256.to_ascii_lowercase();
    if key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(key)
    } else {
        None
    }
}

/// Whether a descriptor is an agent-produced (outbound) artifact (skipped on
/// inbound materialization).
fn is_outbound(descriptor: &AttachmentDescriptor) -> bool {
    descriptor.direction.as_deref() == Some(DIRECTION_OUTBOUND)
}

/// Bump a cache file's modified time to now so it survives LRU GC longer
/// (best-effort; failure is ignored — GC still works off insertion time).
fn touch(path: &Path) {
    if let Ok(file) = std::fs::OpenOptions::new().write(true).open(path) {
        let _ = file.set_modified(SystemTime::now());
    }
}

/// Best-effort MIME guess from a file extension; unknown → octet-stream. The
/// attachment bytes are opaque (no redaction over binaries).
fn guess_content_type(name: &str) -> String {
    let ext = Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let content_type = match ext.as_str() {
        "txt" | "log" | "md" => "text/plain",
        "json" => "application/json",
        "csv" => "text/csv",
        "html" | "htm" => "text/html",
        "xml" => "application/xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" | "tgz" => "application/gzip",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    };
    content_type.to_owned()
}

/// List every **regular file** under `root` (recursively), returning
/// `(absolute path, relative-path name with `/` separators)`. Symlinks are
/// skipped (`file_type` does not follow them), so neither a symlink loop nor a
/// symlink pointing outside `root` can be uploaded. A missing `root` → empty.
fn list_files(root: &Path) -> std::io::Result<Vec<(PathBuf, String)>> {
    let mut out = Vec::new();
    if root.is_dir() {
        collect_files(root, root, &mut out)?;
    }
    Ok(out)
}

fn collect_files(root: &Path, dir: &Path, out: &mut Vec<(PathBuf, String)>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_dir() {
            collect_files(root, &path, out)?;
        } else if file_type.is_file()
            && let Ok(rel) = path.strip_prefix(root)
        {
            let name = rel.to_string_lossy().replace('\\', "/");
            out.push((path.clone(), name));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;

    use super::{AttachmentBackend, AttachmentError, AttachmentManager, sha256_hex};
    use crate::config::AttachmentsConfig;
    use crate::protocol::frames::AttachmentDescriptor;
    use crate::transport::http::UploadedAttachment;

    /// In-memory backend: serves downloads from `store` (keyed by `ref`), records
    /// uploads, and counts downloads (to prove cache hits avoid re-download). The
    /// trait is implemented on `Arc<MemBackend>` so the manager owns a `'static`
    /// box while the test keeps a handle to inspect it.
    #[derive(Default)]
    struct MemBackend {
        store: Mutex<std::collections::HashMap<String, Vec<u8>>>,
        uploads: Mutex<Vec<(String, String, Vec<u8>)>>, // (name, content_type, bytes)
        downloads: AtomicUsize,
    }

    impl MemBackend {
        fn with(reference: &str, bytes: &[u8]) -> Arc<Self> {
            let backend = Self::default();
            backend
                .store
                .lock()
                .unwrap()
                .insert(reference.to_owned(), bytes.to_vec());
            Arc::new(backend)
        }
        fn download_count(&self) -> usize {
            self.downloads.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl AttachmentBackend for Arc<MemBackend> {
        async fn download(
            &self,
            descriptor: &AttachmentDescriptor,
        ) -> Result<Vec<u8>, AttachmentError> {
            self.downloads.fetch_add(1, Ordering::SeqCst);
            self.store
                .lock()
                .unwrap()
                .get(&descriptor.reference)
                .cloned()
                .ok_or(AttachmentError::Unsupported)
        }

        async fn upload(
            &self,
            name: &str,
            content_type: &str,
            _sha256: &str,
            bytes: Vec<u8>,
        ) -> Result<UploadedAttachment, AttachmentError> {
            let mut uploads = self.uploads.lock().unwrap();
            let id = format!("att-{}", uploads.len());
            uploads.push((name.to_owned(), content_type.to_owned(), bytes));
            Ok(UploadedAttachment {
                id: id.clone(),
                reference: format!("/agent/attachments/{id}"),
            })
        }
    }

    fn descriptor(name: &str, bytes: &[u8], reference: &str) -> AttachmentDescriptor {
        AttachmentDescriptor {
            id: "host-id".to_owned(),
            name: name.into(),
            content_type: "text/plain".to_owned(),
            size: i64::try_from(bytes.len()).unwrap(),
            sha256: sha256_hex(bytes),
            reference: reference.to_owned(),
            direction: Some("inbound".to_owned()),
        }
    }

    fn manager(
        backend: &Arc<MemBackend>,
        ws: &std::path::Path,
        config: AttachmentsConfig,
    ) -> AttachmentManager {
        AttachmentManager::new(Box::new(Arc::clone(backend)), ws, config)
    }

    #[test]
    fn sha256_hex_is_lowercase_hex_of_the_known_vector() {
        // SHA-256("abc") — the canonical NIST test vector.
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[tokio::test]
    async fn materialize_verifies_sha256_and_writes_into_inputs() {
        let ws = tempfile::tempdir().unwrap();
        let backend = MemBackend::with("/agent/attachments/a-1", b"INPUT-DATA");
        let mgr = manager(&backend, ws.path(), AttachmentsConfig::default());
        let work_dir = ws.path().join("threads").join("th-1");

        let descriptors = vec![descriptor(
            "doc.txt",
            b"INPUT-DATA",
            "/agent/attachments/a-1",
        )];
        let written = mgr
            .materialize_inputs(&work_dir, &descriptors)
            .await
            .unwrap();

        assert_eq!(written.len(), 1);
        let dest = work_dir.join("inputs").join("doc.txt");
        assert_eq!(std::fs::read(&dest).unwrap(), b"INPUT-DATA");
    }

    #[tokio::test]
    async fn materialize_rejects_sha256_mismatch() {
        let ws = tempfile::tempdir().unwrap();
        let backend = MemBackend::with("/agent/attachments/bad", b"TAMPERED");
        let mgr = manager(&backend, ws.path(), AttachmentsConfig::default());
        let work_dir = ws.path().join("th");

        // Descriptor claims the hash of "ORIGINAL" but the backend serves "TAMPERED".
        let mut d = descriptor("doc.txt", b"ORIGINAL", "/agent/attachments/bad");
        d.size = i64::try_from("TAMPERED".len()).unwrap();
        let err = mgr.materialize_inputs(&work_dir, &[d]).await.unwrap_err();
        assert!(matches!(err, AttachmentError::IntegrityMismatch { .. }));
        // Nothing was written on rejection.
        assert!(!work_dir.join("inputs").join("doc.txt").exists());
    }

    #[tokio::test]
    async fn cache_dedups_second_fetch_without_redownload() {
        let ws = tempfile::tempdir().unwrap();
        let backend = MemBackend::with("/agent/attachments/a-1", b"CACHE-ME");
        let mgr = manager(&backend, ws.path(), AttachmentsConfig::default());

        let descriptors = vec![descriptor("a.txt", b"CACHE-ME", "/agent/attachments/a-1")];
        mgr.materialize_inputs(&ws.path().join("t1"), &descriptors)
            .await
            .unwrap();
        assert_eq!(backend.download_count(), 1, "first fetch downloads");

        // A second materialization (different thread, same workspace cache) is a
        // content-addressed cache hit — no second download.
        mgr.materialize_inputs(&ws.path().join("t2"), &descriptors)
            .await
            .unwrap();
        assert_eq!(backend.download_count(), 1, "second fetch is a cache hit");
        assert_eq!(
            std::fs::read(ws.path().join("t2").join("inputs").join("a.txt")).unwrap(),
            b"CACHE-ME"
        );
    }

    #[tokio::test]
    async fn enforces_single_file_size_limit_before_download() {
        let ws = tempfile::tempdir().unwrap();
        let backend = MemBackend::with("/agent/attachments/big", b"too-big-payload");
        let config = AttachmentsConfig {
            max_single_bytes: 4,
            ..AttachmentsConfig::default()
        };
        let mgr = manager(&backend, ws.path(), config);

        let d = descriptor("big.bin", b"too-big-payload", "/agent/attachments/big");
        let err = mgr
            .materialize_inputs(&ws.path().join("t"), &[d])
            .await
            .unwrap_err();
        assert!(matches!(err, AttachmentError::SizeLimitExceeded { .. }));
        // The size gate runs off the descriptor — no byte transfer was attempted.
        assert_eq!(backend.download_count(), 0);
    }

    #[tokio::test]
    async fn rejects_negative_declared_size_before_any_transfer() {
        // P1-10a: a negative declared size used to clamp to 0 via unwrap_or(0),
        // sailing past every declared-size gate. It must be rejected explicitly,
        // with zero byte transfer.
        let ws = tempfile::tempdir().unwrap();
        let backend = MemBackend::with("/agent/attachments/neg", b"whatever");
        let mgr = manager(&backend, ws.path(), AttachmentsConfig::default());

        let mut d = descriptor("neg.bin", b"whatever", "/agent/attachments/neg");
        d.size = -1;
        let err = mgr
            .materialize_inputs(&ws.path().join("t"), &[d])
            .await
            .unwrap_err();
        assert!(
            matches!(err, AttachmentError::InvalidDeclaredSize { size: -1 }),
            "expected InvalidDeclaredSize, got {err:?}"
        );
        assert_eq!(backend.download_count(), 0, "no byte transfer on rejection");
    }

    #[tokio::test]
    async fn enforces_per_execution_size_limit() {
        let ws = tempfile::tempdir().unwrap();
        let backend = Arc::new(MemBackend::default());
        backend
            .store
            .lock()
            .unwrap()
            .insert("/r/1".to_owned(), b"AAAA".to_vec());
        backend
            .store
            .lock()
            .unwrap()
            .insert("/r/2".to_owned(), b"BBBB".to_vec());
        let config = AttachmentsConfig {
            max_execution_bytes: 6, // two 4-byte files = 8 > 6
            ..AttachmentsConfig::default()
        };
        let mgr = manager(&backend, ws.path(), config);

        let descriptors = vec![
            descriptor("a.txt", b"AAAA", "/r/1"),
            descriptor("b.txt", b"BBBB", "/r/2"),
        ];
        let err = mgr
            .materialize_inputs(&ws.path().join("t"), &descriptors)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            AttachmentError::ExecutionLimitExceeded { .. }
        ));
    }

    #[tokio::test]
    async fn enforces_content_type_allowlist() {
        let ws = tempfile::tempdir().unwrap();
        let backend = MemBackend::with("/r/png", b"PNGDATA");
        let config = AttachmentsConfig {
            content_type_allowlist: vec!["image/png".to_owned()],
            ..AttachmentsConfig::default()
        };
        let mgr = manager(&backend, ws.path(), config);

        // descriptor() uses content_type "text/plain", which is not allowed.
        let d = descriptor("note.txt", b"PNGDATA", "/r/png");
        let err = mgr
            .materialize_inputs(&ws.path().join("t"), &[d])
            .await
            .unwrap_err();
        assert!(matches!(err, AttachmentError::ContentTypeNotAllowed { .. }));
    }

    #[tokio::test]
    async fn unsafe_inbound_name_is_rejected_before_writing() {
        let ws = tempfile::tempdir().unwrap();
        let backend = MemBackend::with("/r/x", b"DATA");
        let mgr = manager(&backend, ws.path(), AttachmentsConfig::default());
        let d = descriptor("../../escape.txt", b"DATA", "/r/x");
        let err = mgr
            .materialize_inputs(&ws.path().join("t"), &[d])
            .await
            .unwrap_err();
        assert!(matches!(err, AttachmentError::UnsafeName { .. }));
    }

    #[tokio::test]
    async fn collect_outputs_uploads_and_returns_descriptors() {
        let ws = tempfile::tempdir().unwrap();
        let backend = Arc::new(MemBackend::default());
        let mgr = manager(&backend, ws.path(), AttachmentsConfig::default());

        let work_dir = ws.path().join("threads").join("th-out");
        let output_dir = work_dir.join("output");
        std::fs::create_dir_all(output_dir.join("sub")).unwrap();
        std::fs::write(output_dir.join("report.txt"), b"OUTPUT-A").unwrap();
        std::fs::write(output_dir.join("sub").join("data.json"), b"{\"k\":1}").unwrap();

        let mut descriptors = mgr.collect_outputs(&work_dir).await;
        descriptors.sort_by(|a, b| a.name.as_plain().cmp(&b.name.as_plain()));

        assert_eq!(descriptors.len(), 2);
        assert_eq!(descriptors[0].name, "report.txt".into());
        assert_eq!(descriptors[0].content_type, "text/plain");
        assert_eq!(descriptors[0].sha256, sha256_hex(b"OUTPUT-A"));
        assert_eq!(descriptors[0].direction.as_deref(), Some("outbound"));
        assert_eq!(descriptors[1].name, "sub/data.json".into());
        assert_eq!(descriptors[1].content_type, "application/json");
        assert_eq!(descriptors[1].sha256, sha256_hex(b"{\"k\":1}"));
        // Every descriptor carries the host-proxy `ref` minted on upload (the
        // exact id depends on filesystem scan order, so just match the shape).
        for descriptor in &descriptors {
            assert!(
                descriptor.reference.starts_with("/agent/attachments/att-"),
                "unexpected ref {:?}",
                descriptor.reference
            );
        }
        // Both files were uploaded as bytes (out-of-band), not left behind.
        assert_eq!(backend.uploads.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn collect_outputs_on_missing_dir_is_empty() {
        let ws = tempfile::tempdir().unwrap();
        let backend = Arc::new(MemBackend::default());
        let mgr = manager(&backend, ws.path(), AttachmentsConfig::default());
        assert!(
            mgr.collect_outputs(&ws.path().join("nope"))
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn fetch_verified_caches_and_avoids_redownload() {
        // The config/skills provisioning seam: by `(ref, sha256)`, no descriptor.
        let ws = tempfile::tempdir().unwrap();
        let backend = MemBackend::with("/agent/attachments/claude-md", b"# CLAUDE.md\n");
        let mgr = manager(&backend, ws.path(), AttachmentsConfig::default());
        let sha = sha256_hex(b"# CLAUDE.md\n");

        let first = mgr
            .fetch_verified("/agent/attachments/claude-md", &sha, 1 << 20)
            .await
            .unwrap();
        assert_eq!(first, b"# CLAUDE.md\n");
        assert_eq!(backend.download_count(), 1, "first fetch downloads");

        // A second fetch of the same sha is a content-addressed cache hit — even a
        // different `ref` resolves from cache (the sha is the key).
        let second = mgr
            .fetch_verified("/agent/attachments/other", &sha, 1 << 20)
            .await
            .unwrap();
        assert_eq!(second, b"# CLAUDE.md\n");
        assert_eq!(backend.download_count(), 1, "second fetch is a cache hit");
    }

    /// Seam: the blocking-pool hops (cache probe, streamed read-back,
    /// cache promote + LRU GC) return correct results under concurrent load —
    /// distinct blobs fetched in parallel each verify and cache independently.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fetch_verified_is_correct_under_concurrent_load() {
        let ws = tempfile::tempdir().unwrap();
        let backend = Arc::new(MemBackend::default());
        let blobs: Vec<Vec<u8>> = (0..8).map(|i| format!("BLOB-{i}").into_bytes()).collect();
        for (i, bytes) in blobs.iter().enumerate() {
            backend
                .store
                .lock()
                .unwrap()
                .insert(format!("/r/{i}"), bytes.clone());
        }
        let mgr = Arc::new(manager(&backend, ws.path(), AttachmentsConfig::default()));

        let handles: Vec<_> = blobs
            .iter()
            .enumerate()
            .map(|(i, bytes)| {
                let mgr = Arc::clone(&mgr);
                let sha = sha256_hex(bytes);
                let want = bytes.clone();
                tokio::spawn(async move {
                    let got = mgr
                        .fetch_verified(&format!("/r/{i}"), &sha, 1 << 20)
                        .await
                        .unwrap();
                    assert_eq!(got, want);
                })
            })
            .collect();
        for handle in handles {
            handle.await.unwrap();
        }
        assert_eq!(backend.download_count(), 8, "each blob downloaded once");

        // A second pass resolves everything from the cache — the blocking-pool
        // cache probe still hits after the concurrent fills.
        for (i, bytes) in blobs.iter().enumerate() {
            let got = mgr
                .fetch_verified(&format!("/r/{i}"), &sha256_hex(bytes), 1 << 20)
                .await
                .unwrap();
            assert_eq!(&got, bytes);
        }
        assert_eq!(backend.download_count(), 8, "second pass is all cache hits");
    }

    #[tokio::test]
    async fn fetch_verified_rejects_sha256_mismatch() {
        let ws = tempfile::tempdir().unwrap();
        let backend = MemBackend::with("/agent/attachments/bad", b"TAMPERED");
        let mgr = manager(&backend, ws.path(), AttachmentsConfig::default());
        // Ask for the hash of "ORIGINAL"; the backend serves "TAMPERED".
        let wrong = sha256_hex(b"ORIGINAL");
        let err = mgr
            .fetch_verified("/agent/attachments/bad", &wrong, 1 << 20)
            .await
            .unwrap_err();
        assert!(matches!(err, AttachmentError::IntegrityMismatch { .. }));
    }

    #[tokio::test]
    async fn fetch_verified_enforces_max_bytes() {
        let ws = tempfile::tempdir().unwrap();
        let backend = MemBackend::with("/agent/attachments/big", b"way-too-large-config");
        let mgr = manager(&backend, ws.path(), AttachmentsConfig::default());
        let sha = sha256_hex(b"way-too-large-config");
        // The cap is the explicit `max_bytes` arg (not the manager's config).
        let err = mgr
            .fetch_verified("/agent/attachments/big", &sha, 4)
            .await
            .unwrap_err();
        assert!(matches!(err, AttachmentError::SizeLimitExceeded { .. }));
    }

    // -- Host-proxy streaming + same-origin token gating (P1-10a/c) ---------

    use secrecy::SecretString;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::HostProxyBackend;
    use crate::transport::http::HttpClient;

    /// A manager whose byte plane is the REAL host-proxy backend over `base`.
    fn host_proxy_manager(
        base: &str,
        ws: &std::path::Path,
        config: AttachmentsConfig,
    ) -> AttachmentManager {
        let backend = HostProxyBackend::new(
            HttpClient::new().unwrap(),
            base.to_owned(),
            SecretString::from("connect-tok"),
        );
        AttachmentManager::new(Box::new(backend), ws, config)
    }

    /// P1-10a regression: a body far larger than the cap (with a small LYING
    /// declared size, so the descriptor pre-check passes) aborts mid-stream with
    /// the size-limit failure — the body is never buffered whole, and no temp
    /// file survives the abort.
    #[tokio::test]
    async fn host_proxy_aborts_oversized_body_mid_stream() {
        let server = MockServer::start().await;
        let body = vec![0xCD_u8; 1 << 20]; // 1 MiB served
        Mock::given(method("GET"))
            .and(path("/agent/attachments/huge"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .mount(&server)
            .await;

        let ws = tempfile::tempdir().unwrap();
        let config = AttachmentsConfig {
            max_single_bytes: 1024,
            ..AttachmentsConfig::default()
        };
        let mgr = host_proxy_manager(&server.uri(), ws.path(), config);

        let mut d = descriptor("huge.bin", b"lie", "/agent/attachments/huge");
        d.size = 100; // declared small: the in-flight cap must trip, not the pre-check
        let err = mgr
            .materialize_inputs(&ws.path().join("t"), &[d])
            .await
            .unwrap_err();
        assert!(
            matches!(err, AttachmentError::SizeLimitExceeded { limit: 1024, .. }),
            "expected a mid-stream size abort, got {err:?}"
        );
        // The aborted temp file is cleaned up; nothing near body-size was kept.
        let cache = ws.path().join("attachments-cache");
        if cache.is_dir() {
            for entry in std::fs::read_dir(&cache).unwrap().flatten() {
                let meta = entry.metadata().unwrap();
                assert!(
                    meta.len() <= 1024,
                    "no file beyond the cap may survive the abort ({:?} is {} bytes)",
                    entry.path(),
                    meta.len()
                );
            }
        }
        // Nothing was materialized into the thread inputs.
        assert!(!ws.path().join("t").join("inputs").exists());
    }

    /// P1-10c regression, same-origin half: a host-proxy relative `ref` resolves
    /// under the configured base and carries the connect token (the mock matches
    /// the header, so a token-less request would 404 and fail the fetch).
    #[tokio::test]
    async fn host_proxy_attaches_token_to_same_origin_downloads() {
        let server = MockServer::start().await;
        let bytes = b"SAME-ORIGIN-DATA".to_vec();
        Mock::given(method("GET"))
            .and(path("/agent/attachments/s1"))
            .and(header("x-internal-token", "connect-tok"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes.clone()))
            .mount(&server)
            .await;

        let ws = tempfile::tempdir().unwrap();
        let mgr = host_proxy_manager(&server.uri(), ws.path(), AttachmentsConfig::default());
        let d = descriptor("s1.txt", &bytes, "/agent/attachments/s1");
        let written = mgr
            .materialize_inputs(&ws.path().join("t"), &[d])
            .await
            .unwrap();
        assert_eq!(written.len(), 1);
        assert_eq!(std::fs::read(&written[0]).unwrap(), bytes);
    }

    /// P1-10c regression, cross-origin half: an absolute `ref` pointing at a
    /// DIFFERENT origin is fetched WITHOUT the connect token (sha256 still gates
    /// the content) — the token never travels to an arbitrary origin.
    #[tokio::test]
    async fn host_proxy_withholds_token_from_cross_origin_downloads() {
        let host = MockServer::start().await;
        let other = MockServer::start().await; // different port → different origin
        let bytes = b"CDN-BYTES".to_vec();
        Mock::given(method("GET"))
            .and(path("/blob"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes.clone()))
            .mount(&other)
            .await;

        let ws = tempfile::tempdir().unwrap();
        let mgr = host_proxy_manager(&host.uri(), ws.path(), AttachmentsConfig::default());
        let d = descriptor("cdn.txt", &bytes, &format!("{}/blob", other.uri()));
        let written = mgr
            .materialize_inputs(&ws.path().join("t"), &[d])
            .await
            .unwrap();
        assert_eq!(std::fs::read(&written[0]).unwrap(), bytes);

        let requests = other.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert!(
            !requests[0].headers.contains_key("x-internal-token"),
            "the connect token must never travel to a cross-origin ref"
        );
        // And the host proxy itself was never contacted for this descriptor.
        assert!(host.received_requests().await.unwrap().is_empty());
    }
}
