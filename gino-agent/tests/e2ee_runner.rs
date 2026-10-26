//! E2ee runner foundation scenarios: the key files, the `e2ee` capability on
//! register and heartbeat, and the KeyPackage pool at the host, driven
//! black-box against the stub host.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

#[allow(dead_code)]
mod support;

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use gino_e2ee::{Identity, encode_b64url, fingerprint_display};
use serde_json::{Value, json};
use tempfile::TempDir;

use support::fake_claude::{self, Behavior};
use support::stub_host::StubHost;
use support::{RunnerProc, SETTLE, Workspace, wait_until};

const IDENTITY_KEY_FILE: &str = "e2ee-identity.key";
const STATE_KEY_FILE: &str = "e2ee-state.key";

/// The state dir: where the harness puts the agent DB, beside the workspace.
fn state_dir(workspace: &Workspace) -> PathBuf {
    workspace.dir().parent().unwrap().to_path_buf()
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// The fake engine, wrapped to record its env and argv into `dump/`.
fn recording_engine() -> TempDir {
    let fakes = fake_claude::install(&Behavior::echo_lines("sess-e2ee", 1));
    let dir = fakes.path();
    std::fs::rename(dir.join("claude"), dir.join("claude-real")).unwrap();
    let wrapper = format!(
        "#!/bin/sh\nenv > '{dump}/env'\nprintf '%s\\n' \"$@\" > '{dump}/args'\npwd > '{dump}/cwd'\nexec '{real}' \"$@\"\n",
        dump = dir.display(),
        real = dir.join("claude-real").display(),
    );
    std::fs::write(dir.join("claude"), wrapper).unwrap();
    std::fs::set_permissions(dir.join("claude"), std::fs::Permissions::from_mode(0o755)).unwrap();
    fakes
}

fn boot(host: &StubHost, workspace: &Workspace, fakes: TempDir, log: &Path) -> RunnerProc {
    let envs: [(&str, &OsStr); 2] = [
        ("RUST_LOG", OsStr::new("info")),
        ("NO_COLOR", OsStr::new("1")),
    ];
    RunnerProc::spawn_in_with_env(
        host,
        workspace,
        fakes,
        &envs,
        std::fs::File::create(log).unwrap().into(),
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// Every textual form of the key files that must never leave the daemon.
fn secrets(state_dir: &Path) -> Vec<String> {
    let mut out = vec![IDENTITY_KEY_FILE.to_owned(), STATE_KEY_FILE.to_owned()];
    for name in [IDENTITY_KEY_FILE, STATE_KEY_FILE] {
        let bytes = std::fs::read(state_dir.join(name)).unwrap();
        out.push(hex(&bytes));
        out.push(encode_b64url(&bytes));
        out.push(base64::engine::general_purpose::STANDARD.encode(&bytes));
    }
    out
}

fn assert_no_secret(what: &str, text: &str, secrets: &[String]) {
    for secret in secrets {
        assert!(!text.contains(secret.as_str()), "{what} exposes {secret}");
    }
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() && !path.is_symlink() {
            walk(&path, out);
        }
        out.push(path);
    }
}

/// Distinct upload payloads (an outbox replay repeats one).
async fn distinct_uploads(host: &StubHost) -> usize {
    let mut uploads: Vec<String> = host
        .key_package_uploads()
        .await
        .iter()
        .map(Value::to_string)
        .collect();
    uploads.sort();
    uploads.dedup();
    uploads.len()
}

fn one_time_len(upload: &Value) -> usize {
    upload["one_time"].as_array().map_or(0, Vec::len)
}

#[tokio::test]
async fn keys_capability_and_key_package_pool() {
    let host = StubHost::start(json!({"heartbeatIntervalMs": 500})).await;
    let workspace = Workspace::new().await;
    let state = state_dir(&workspace);
    let log_dir = tempfile::tempdir().unwrap();
    let log = log_dir.path().join("agent.log");
    let fakes = recording_engine();
    let dump = fakes.path().to_path_buf();
    let runner = boot(&host, &workspace, fakes, &log);
    assert!(host.wait_connected(SETTLE).await, "runner never connected");

    // Both key files, 0600, in the state dir.
    let identity_path = state.join(IDENTITY_KEY_FILE);
    let state_key_path = state.join(STATE_KEY_FILE);
    for path in [&identity_path, &state_key_path] {
        assert_eq!(mode(path), 0o600, "{}", path.display());
        assert_eq!(std::fs::read(path).unwrap().len(), 32);
    }
    let seed: [u8; 32] = std::fs::read(&identity_path).unwrap().try_into().unwrap();
    let public_key = Identity::from_seed(&seed).public_key();
    let capability = json!({
        "versions": [1],
        "mls_suites": [1],
        "credential": {"type": "basic", "public_key": encode_b64url(&public_key)},
    });

    // The capability on register and on every heartbeat.
    let registers = host.register_bodies().await;
    assert_eq!(registers.len(), 1);
    assert_eq!(registers[0]["e2ee"], capability);
    assert!(host.wait_heartbeats(2, SETTLE).await, "no heartbeats");
    for heartbeat in host.heartbeats().await {
        assert_eq!(heartbeat["e2ee"], capability, "heartbeat {heartbeat}");
    }

    // The initial publication: ten one-time plus one last-resort.
    assert!(host.wait_key_package_uploads(1, SETTLE).await, "no upload");
    let uploads = host.key_package_uploads().await;
    assert_eq!(one_time_len(&uploads[0]), 10);
    assert!(uploads[0]["last_resort"].is_string());
    assert_eq!(host.key_package_pool().await, (10, true));

    // A claim leaves four: topped up to ten, the last-resort kept.
    host.claim_key_packages(6).await;
    assert!(host.wait_key_package_uploads(2, SETTLE).await, "no top-up");
    let top_up = host.key_package_uploads().await.last().cloned().unwrap();
    assert_eq!(one_time_len(&top_up), 6);
    assert!(top_up.get("last_resort").is_none_or(Value::is_null));
    assert_eq!(host.key_package_pool().await, (10, true));

    // A message run: the engine sees no key file, path or key material.
    host.push_message("t-e2ee", Some("th-e2ee"), "hello", &[], 1)
        .await;
    let run = host
        .wait_thread_terminal("th-e2ee", SETTLE)
        .await
        .expect("no thread_result");
    assert_eq!(run.status, "succeeded", "run: {run:?}");
    let secrets = secrets(&state);
    for name in ["env", "args", "cwd"] {
        let text = std::fs::read_to_string(dump.join(name)).unwrap();
        assert_no_secret(&format!("the engine {name}"), &text, &secrets);
    }

    // Nothing under the workspace names or holds a key.
    let mut files = Vec::new();
    walk(workspace.dir(), &mut files);
    for path in &files {
        assert_no_secret("the workspace", &path.display().to_string(), &secrets);
        if path.is_file() && !path.is_symlink() {
            let bytes = std::fs::read(path).unwrap_or_default();
            assert!(
                !bytes.windows(32).any(|w| w == seed),
                "{} holds the identity seed",
                path.display()
            );
        }
    }

    // The fingerprint is logged; the seed never is.
    let fingerprint = fingerprint_display(&public_key);
    assert!(
        wait_until(SETTLE, || std::fs::read_to_string(&log)
            .is_ok_and(|text| text.contains(&fingerprint)))
        .await,
        "fingerprint not logged"
    );
    runner.shutdown().await;
    let text = std::fs::read_to_string(&log).unwrap();
    assert_eq!(text.matches(&fingerprint).count(), 1, "{text}");
    assert_no_secret("the log", &text, &secrets);

    // A restart reuses both keys and publishes nothing new.
    let identity_before = std::fs::read(&identity_path).unwrap();
    let state_key_before = std::fs::read(&state_key_path).unwrap();
    let uploads_before = distinct_uploads(&host).await;
    let runner = boot(
        &host,
        &workspace,
        fake_claude::install(&Behavior::echo_lines("s", 1)),
        &log,
    );
    assert!(
        host.wait_connects(2, SETTLE).await,
        "runner never reconnected"
    );
    assert!(
        wait_until(SETTLE, || std::fs::read_to_string(&log)
            .is_ok_and(|text| text.contains(&fingerprint)))
        .await
    );
    assert_eq!(std::fs::read(&identity_path).unwrap(), identity_before);
    assert_eq!(std::fs::read(&state_key_path).unwrap(), state_key_before);
    let registers = host.register_bodies().await;
    assert_eq!(registers.last().unwrap()["e2ee"], capability);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        distinct_uploads(&host).await,
        uploads_before,
        "no upload after a restart"
    );
    runner.shutdown().await;
}

async fn refused_start(prepare: impl FnOnce(&Path)) -> String {
    let host = StubHost::start(json!({})).await;
    let root = tempfile::tempdir().unwrap();
    let workspace = root.path().join("workspace");
    let identity = root.path().join(IDENTITY_KEY_FILE);
    std::fs::write(&identity, [7u8; 32]).unwrap();
    std::fs::set_permissions(&identity, std::fs::Permissions::from_mode(0o600)).unwrap();
    prepare(&identity);
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_gino-agent"))
        .arg("run")
        .env("GINO_HOST_URL", host.base_url())
        .env("GINO_REGISTER_TOKEN", "e2e-register-token")
        .env("GINO_AGENT_NAME", "e2e-runner")
        .env("GINO_WORKSPACE_DIR", &workspace)
        .env("GINO_DB_PATH", root.path().join("agent.db"))
        .env("RUST_LOG", "off")
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true)
        .output();
    let output = tokio::time::timeout(SETTLE, output)
        .await
        .expect("the daemon did not exit")
        .unwrap();
    assert!(!output.status.success());
    assert!(host.register_bodies().await.is_empty(), "registered anyway");
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[tokio::test]
async fn a_key_file_readable_by_others_refuses_to_start() {
    let stderr = refused_start(|path| {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
    })
    .await;
    assert!(stderr.contains("0600"), "{stderr}");
    assert!(stderr.contains(IDENTITY_KEY_FILE), "{stderr}");
}

#[tokio::test]
async fn a_key_file_of_the_wrong_length_refuses_to_start() {
    let stderr = refused_start(|path| std::fs::write(path, [7u8; 31]).unwrap()).await;
    assert!(stderr.contains("32"), "{stderr}");
    assert!(stderr.contains(IDENTITY_KEY_FILE), "{stderr}");
}
