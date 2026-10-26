use std::ffi::OsString;
use std::fmt::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chrono::TimeDelta;
use gino_e2ee::{Identity, decode_b64url, encode_b64url, fingerprint_display};
use serde_json::{Value, json};
use tokio::sync::Notify;

use super::{
    E2ee, E2eeError, E2eeKeys, IDENTITY_KEY_FILE, STATE_KEY_FILE, lock, record_task_e2ee, state_dir,
};
use crate::agent_api::client::Client;
use crate::agent_api::{AgentApiServer, ApiContext, socket_path};
use crate::db::{Db, OutboxRow, TaskRow};
use crate::protocol::frames::{
    E2eeKeyPackageStatusData, E2eeKeyPackagesData, E2eeLiveFrame, E2eeLogData, E2eeWelcomeData,
    InboundFrame, KeyPackageRejection, TaskE2ee,
};
use crate::sandbox::{
    DEFAULT_CONVERSATIONS_MAX_BYTES, IsolationSpec, Launch, LaunchContext, LlmBaseUrl, SandboxHost,
    launch, resolve, wrap,
};
use crate::scheduler::now;

struct Fixture {
    dir: tempfile::TempDir,
    db: Arc<Mutex<Db>>,
    flush: Arc<Notify>,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("agent.db")).unwrap();
        Self {
            dir,
            db: Arc::new(Mutex::new(db)),
            flush: Arc::new(Notify::new()),
        }
    }

    fn e2ee(&self) -> E2ee {
        let keys = E2eeKeys::load_or_create(self.dir.path()).unwrap();
        E2ee::new(
            keys,
            Arc::clone(&self.db),
            Arc::clone(&self.flush),
            Arc::default(),
        )
        .unwrap()
    }

    fn uploads(&self) -> Vec<OutboxRow> {
        lock(&self.db)
            .list_unacked_outbox()
            .unwrap()
            .into_iter()
            .filter(|row| row.msg_type == "e2ee_key_packages")
            .collect()
    }

    fn ack_all(&self) {
        let db = lock(&self.db);
        for row in db.list_unacked_outbox().unwrap() {
            db.mark_outbox_acked(&row.id).unwrap();
        }
    }

    fn seed(&self) -> [u8; 32] {
        std::fs::read(self.dir.path().join(IDENTITY_KEY_FILE))
            .unwrap()
            .try_into()
            .unwrap()
    }
}

fn payload(row: &OutboxRow) -> E2eeKeyPackagesData {
    serde_json::from_str(&row.payload).unwrap()
}

fn counts(row: &OutboxRow) -> (usize, bool) {
    let data = payload(row);
    (
        data.one_time.map_or(0, |kps| kps.len()),
        data.last_resort.is_some(),
    )
}

fn status(id: Option<&str>, one_time: u64, last_resort: bool) -> E2eeLiveFrame {
    E2eeLiveFrame::KeyPackageStatus {
        id: id.map(str::to_owned),
        data: E2eeKeyPackageStatusData {
            one_time,
            last_resort,
            rejected: Vec::new(),
        },
    }
}

#[test]
fn state_dir_is_the_db_directory() {
    assert_eq!(
        state_dir(Path::new("/var/lib/gino/agent.db")),
        Path::new("/var/lib/gino")
    );
    assert_eq!(state_dir(Path::new("agent.db")), Path::new("."));
}

#[test]
fn capability_and_fingerprint_come_from_the_identity_file() {
    let fx = Fixture::new();
    let keys = E2eeKeys::load_or_create(fx.dir.path()).unwrap();
    let public_key = Identity::from_seed(&fx.seed()).public_key();
    assert_eq!(keys.fingerprint(), fingerprint_display(&public_key));
    let capability = serde_json::to_value(keys.capability()).unwrap();
    assert_eq!(
        capability,
        json!({
            "versions": [1],
            "mls_suites": [1],
            "credential": {"type": "basic", "public_key": encode_b64url(&public_key)},
        })
    );
    // Debug shows the fingerprint, never key material.
    let debug = format!("{keys:?}");
    assert!(debug.contains(&keys.fingerprint()));
    assert!(!debug.contains(&encode_b64url(&fx.seed())));
}

#[test]
fn the_initial_publication_persists_the_store_and_enqueues_ten_plus_one() {
    let fx = Fixture::new();
    let e2ee = fx.e2ee();
    e2ee.publish_initial();

    let uploads = fx.uploads();
    assert_eq!(uploads.len(), 1);
    assert_eq!(counts(&uploads[0]), (10, true));
    assert!(uploads[0].task_id.is_none());
    let data = payload(&uploads[0]);
    for kp in data.one_time.unwrap().iter().chain(data.last_resort.iter()) {
        assert!(decode_b64url(kp).is_ok());
    }
    let row = lock(&fx.db).get_e2ee_key_packages().unwrap().unwrap();
    assert!(row.last_resort_created_at.is_some());
    assert_eq!(
        lock(&e2ee.pool).pending.as_deref(),
        Some(uploads[0].id.as_str())
    );

    // A stored state is never re-published from scratch.
    e2ee.publish_initial();
    assert_eq!(fx.uploads().len(), 1);
}

#[test]
fn the_store_is_sealed_at_rest() {
    let fx = Fixture::new();
    let e2ee = fx.e2ee();
    e2ee.publish_initial();
    let row = lock(&fx.db).get_e2ee_key_packages().unwrap().unwrap();
    let snapshot = lock(&e2ee.pool).store.snapshot().unwrap();
    assert_ne!(row.store, snapshot);
    assert_eq!(
        e2ee.open_at_rest("e2ee_key_packages", &row.store).unwrap(),
        snapshot
    );
}

#[test]
fn a_restart_restores_the_store_without_republishing() {
    let fx = Fixture::new();
    let first = fx.e2ee();
    first.publish_initial();
    let snapshot = lock(&first.pool).store.snapshot().unwrap();
    let created = lock(&first.pool).last_resort_created_at;
    drop(first);
    fx.ack_all();

    let second = fx.e2ee();
    second.publish_initial();
    assert!(fx.uploads().is_empty());
    let pool = lock(&second.pool);
    assert_eq!(pool.store.snapshot().unwrap(), snapshot);
    assert_eq!(
        pool.last_resort_created_at.map(|t| t.timestamp()),
        created.map(|t| t.timestamp())
    );
}

#[test]
fn a_state_sealed_under_another_key_refuses_to_load() {
    let fx = Fixture::new();
    fx.e2ee().publish_initial();
    std::fs::remove_file(fx.dir.path().join(STATE_KEY_FILE)).unwrap();
    let keys = E2eeKeys::load_or_create(fx.dir.path()).unwrap();
    let err = E2ee::new(
        keys,
        Arc::clone(&fx.db),
        Arc::clone(&fx.flush),
        Arc::default(),
    )
    .unwrap_err();
    assert!(matches!(err, E2eeError::AtRest(_)), "{err}");
}

#[test]
fn statuses_top_up_one_upload_at_a_time() {
    let fx = Fixture::new();
    let e2ee = fx.e2ee();
    e2ee.publish_initial();
    let first = fx.uploads()[0].id.clone();

    // The socket-open status precedes the upload's ack: wait for its answer.
    e2ee.on_live_frame(status(None, 0, false));
    assert_eq!(fx.uploads().len(), 1);

    // The answer settles it.
    fx.ack_all();
    e2ee.on_live_frame(status(Some(&first), 10, true));
    assert!(fx.uploads().is_empty());
    assert_eq!(lock(&e2ee.pool).pending, None);

    // A claim drops the host below five: top up to ten, no last-resort.
    e2ee.on_live_frame(status(None, 3, true));
    let uploads = fx.uploads();
    assert_eq!(uploads.len(), 1);
    assert_eq!(counts(&uploads[0]), (7, false));

    // No duplicate while that upload is unacked.
    e2ee.on_live_frame(status(None, 2, true));
    assert_eq!(fx.uploads().len(), 1);

    // Acked but unanswered: that upload is settled, the next status decides.
    fx.ack_all();
    e2ee.on_live_frame(status(None, 4, true));
    assert!(fx.uploads().is_empty());
    e2ee.on_live_frame(status(None, 4, true));
    let uploads = fx.uploads();
    assert_eq!(uploads.len(), 1);
    assert_eq!(counts(&uploads[0]), (6, false));
}

#[test]
fn a_rejected_upload_is_not_retried_until_the_next_status() {
    let fx = Fixture::new();
    let e2ee = fx.e2ee();
    e2ee.publish_initial();
    let first = fx.uploads()[0].id.clone();
    fx.ack_all();

    e2ee.on_live_frame(E2eeLiveFrame::KeyPackageStatus {
        id: Some(first),
        data: E2eeKeyPackageStatusData {
            one_time: 0,
            last_resort: false,
            rejected: vec![KeyPackageRejection {
                code: "key_changed".to_owned(),
                index: Some(0),
            }],
        },
    });
    assert!(fx.uploads().is_empty());

    e2ee.on_live_frame(status(None, 0, false));
    let uploads = fx.uploads();
    assert_eq!(uploads.len(), 1);
    assert_eq!(counts(&uploads[0]), (10, true));
}

#[test]
fn the_last_resort_is_replaced_when_stale_or_missing_at_the_host() {
    let fx = Fixture::new();
    let e2ee = fx.e2ee();
    e2ee.publish_initial();
    fx.ack_all();
    lock(&e2ee.pool).pending = None;

    e2ee.check_last_resort();
    assert!(fx.uploads().is_empty());

    lock(&e2ee.pool).last_resort_created_at = Some(now() - TimeDelta::days(57));
    e2ee.check_last_resort();
    let uploads = fx.uploads();
    assert_eq!(uploads.len(), 1);
    assert_eq!(counts(&uploads[0]), (0, true));
    let created = lock(&e2ee.pool).last_resort_created_at.unwrap();
    assert!(now() - created < TimeDelta::minutes(1));

    let replacement = uploads[0].id.clone();
    fx.ack_all();
    e2ee.on_live_frame(status(Some(&replacement), 10, false));
    let uploads = fx.uploads();
    assert_eq!(uploads.len(), 1);
    assert_eq!(counts(&uploads[0]), (0, true));
}

/// Every order in which the socket-open status, publish_initial and the
/// upload's ack and answer can be handled yields exactly one publication.
#[test]
fn the_initial_publication_happens_once_in_any_order() {
    // 'p': publish_initial; 'o': the socket-open status, sent before the host
    // read any upload; 'k': the upload's ack, applied by the transport as it
    // arrives (so possibly before an earlier status is handled); 'a': the
    // upload's answer, which follows its ack and the socket-open status.
    for order in ["poka", "pkoa", "opka", "okpa"] {
        let fx = Fixture::new();
        let e2ee = fx.e2ee();
        let mut ids: Vec<String> = Vec::new();
        for step in order.chars() {
            match step {
                'p' => e2ee.publish_initial(),
                'o' => e2ee.on_live_frame(status(None, 0, false)),
                'k' => fx.ack_all(),
                _ => e2ee.on_live_frame(status(ids.first().map(String::as_str), 10, true)),
            }
            for row in fx.uploads() {
                if !ids.contains(&row.id) {
                    ids.push(row.id);
                }
            }
        }
        assert_eq!(ids.len(), 1, "order {order}");
        fx.ack_all();
        assert_eq!(lock(&e2ee.pool).pending, None, "order {order}");
    }
}

#[test]
fn records_are_buffered_by_seq_and_kind() {
    let fx = Fixture::new();
    let e2ee = fx.e2ee();
    let log = InboundFrame::E2eeLog {
        task_id: "t-1".to_owned(),
        data: E2eeLogData {
            seq: 4,
            kind: "commit".to_owned(),
            epoch: 3,
            message: "bXNn".to_owned(),
            drop_public_key: Some("ZHBr".to_owned()),
        },
        msg_id: None,
    };
    let welcome = InboundFrame::E2eeWelcome {
        task_id: "t-1".to_owned(),
        data: E2eeWelcomeData {
            welcome: "d2Vs".to_owned(),
            seq: 4,
        },
        msg_id: None,
    };
    assert!(e2ee.on_record(&log));
    assert!(e2ee.on_record(&welcome));
    assert!(e2ee.on_record(&log));

    let rows = lock(&fx.db).list_e2ee_log_pending("t-1").unwrap();
    let kinds: Vec<_> = rows.iter().map(|r| (r.seq, r.msg_type.as_str())).collect();
    assert_eq!(kinds, [(4, "e2ee_welcome"), (4, "e2ee_log")]);
    let stored: Value = serde_json::from_str(&rows[1].payload).unwrap();
    assert_eq!(
        stored,
        json!({"seq": 4, "kind": "commit", "epoch": 3, "message": "bXNn", "drop_public_key": "ZHBr"})
    );
}

fn task_row(id: &str) -> TaskRow {
    TaskRow {
        id: id.to_owned(),
        name: None,
        kind: None,
        status: "active".to_owned(),
        engine: None,
        model: None,
        workdir: None,
        meta: None,
        created_at: "2026-01-01T00:00:00.000Z".to_owned(),
        updated_at: "2026-01-01T00:00:00.000Z".to_owned(),
    }
}

#[test]
fn task_e2ee_is_recorded_once_and_a_refused_marker_marks_the_group_lost() {
    let db = Db::open_in_memory().unwrap();
    let group_id =
        |profile: &str, task: &str| encode_b64url(&gino_e2ee::group_id(profile, task).unwrap());
    let status = |task: &str| db.get_e2ee_group(task).unwrap().unwrap().status;
    db.insert_task_row(&task_row("t-1")).unwrap();
    let e2ee = TaskE2ee {
        profile_id: "gino.task-content.v1".to_owned(),
        group_id: group_id("gino.task-content.v1", "t-1"),
    };
    assert!(record_task_e2ee(&db, "t-1", &e2ee));
    let row = db.get_task_e2ee("t-1").unwrap().unwrap();
    assert_eq!(
        (row.profile_id.as_str(), row.group_id.as_str()),
        (e2ee.profile_id.as_str(), e2ee.group_id.as_str())
    );
    assert_eq!(status("t-1"), "pending");
    // A later different marker is ignored.
    let other = TaskE2ee {
        profile_id: "gino.task-content.v1".to_owned(),
        group_id: "b3RoZXI".to_owned(),
    };
    assert!(record_task_e2ee(&db, "t-1", &other));
    assert_eq!(db.get_task_e2ee("t-1").unwrap().unwrap(), row);
    assert_eq!(status("t-1"), "pending");

    // A mismatching derivation is stored as sent, its group state unusable.
    db.insert_task_row(&task_row("t-2")).unwrap();
    assert!(record_task_e2ee(&db, "t-2", &other));
    assert_eq!(
        db.get_task_e2ee("t-2").unwrap().unwrap().group_id,
        "b3RoZXI"
    );
    assert_eq!(status("t-2"), "lost");

    // So is an unsupported profile.
    db.insert_task_row(&task_row("t-3")).unwrap();
    let chat = TaskE2ee {
        profile_id: "gino.chat.v1".to_owned(),
        group_id: group_id("gino.chat.v1", "t-3"),
    };
    assert!(record_task_e2ee(&db, "t-3", &chat));
    assert_eq!(status("t-3"), "lost");
}

#[test]
fn seal_and_open_at_rest_round_trip_under_their_label() {
    let fx = Fixture::new();
    let e2ee = fx.e2ee();
    let sealed = e2ee.seal_at_rest("group:t-1", b"snapshot").unwrap();
    assert_eq!(
        e2ee.open_at_rest("group:t-1", &sealed).unwrap(),
        b"snapshot"
    );
    assert!(e2ee.open_at_rest("group:t-2", &sealed).is_err());
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
        out.push(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &bytes,
        ));
    }
    out
}

fn assert_no_secret(what: &str, text: &str, secrets: &[String]) {
    for secret in secrets {
        assert!(!text.contains(secret.as_str()), "{what} exposes {secret}");
    }
}

fn assert_launch_hides_keys(launch: &Launch, state_dir: &Path, secrets: &[String]) {
    let keys = [
        state_dir.join(IDENTITY_KEY_FILE),
        state_dir.join(STATE_KEY_FILE),
    ];
    for window in launch.args.windows(2) {
        if ["--bind", "--ro-bind", "--dev-bind"].contains(&window[0].to_str().unwrap_or("")) {
            let source = Path::new(&window[1]);
            for key in &keys {
                assert!(
                    !key.starts_with(source),
                    "{} binds {}",
                    source.display(),
                    key.display()
                );
            }
        }
    }
    let mut text: Vec<String> = launch
        .args
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    for (key, value) in &launch.env {
        text.push(format!("{key}={}", value.to_string_lossy()));
    }
    text.push(launch.cwd.display().to_string());
    assert_no_secret("the engine launch", &text.join("\n"), secrets);
}

#[test]
fn key_files_are_never_exposed_to_an_engine_launch() {
    // The default layout: the agent DB, and so the key files, at the root
    // of the workspace.
    let tmp = tempfile::tempdir().unwrap();
    let workspace = std::fs::canonicalize(tmp.path()).unwrap();
    E2eeKeys::load_or_create(&workspace).unwrap();
    let secrets = secrets(&workspace);

    let bin_dir = workspace.join("bin");
    std::fs::create_dir(&bin_dir).unwrap();
    let engine = bin_dir.join("engine");
    std::fs::write(&engine, "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&engine, std::fs::Permissions::from_mode(0o755)).unwrap();
    let host = SandboxHost::fixture(Some(bin_dir.into_os_string()));

    let work_dir = workspace.join("threads/t1");
    let memory_dir = crate::memory::memory_dir(&workspace, "task-1");
    let agent_memory_dir = crate::memory::agent_memory_dir(&workspace);
    let direct = Launch::direct(
        "engine".into(),
        vec!["-p".to_owned()],
        vec![
            ("GINO_TASK_ID".to_owned(), "task-1".into()),
            (
                "GINO_AGENT_SOCK".to_owned(),
                socket_path(&workspace).into_os_string(),
            ),
            (
                "GINO_MEMORY_DIR".to_owned(),
                OsString::from(memory_dir.as_os_str()),
            ),
        ],
        work_dir.join("project"),
    );
    let off = IsolationSpec::default();
    let keys: [&str; 0] = [];
    let agent = PathBuf::from("/opt/gino/gino-agent");
    let ctx = LaunchContext {
        isolation: &off,
        task_override: None,
        workspace_dir: &workspace,
        task_id: Some("task-1"),
        thread_id: Some("th-1"),
        work_dir: Some(&work_dir),
        memory_dir: Some(&memory_dir),
        agent_memory_dir: Some(&agent_memory_dir),
        agent_memory_access: crate::memory::AgentMemoryAccess::Rw,
        task_archives: &[],
        conversations_max_bytes: DEFAULT_CONVERSATIONS_MAX_BYTES,
        self_exe: Some(&agent),
        global_config_dir: None,
        config_dir_keys: &keys,
        floored: false,
    };

    let unwrapped = launch(direct.clone(), &ctx).unwrap();
    assert_launch_hides_keys(&unwrapped, &workspace, &secrets);

    let sandbox = IsolationSpec {
        mode: Some("sandbox".to_owned()),
        ..IsolationSpec::default()
    };
    let isolation = resolve(&sandbox, None, &workspace, LlmBaseUrl::default()).unwrap();
    let wrapped = wrap(direct, &ctx, &isolation, &host).unwrap();
    assert!(wrapped.sandboxed);
    assert_launch_hides_keys(&wrapped, &workspace, &secrets);

    // Nothing the launch prepared in the workspace carries a key.
    for entry in walk(&work_dir) {
        let name = entry.file_name().unwrap().to_string_lossy().into_owned();
        assert_no_secret("the work dir", &name, &secrets);
    }
}

#[test]
fn an_operator_bind_of_the_state_dir_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = std::fs::canonicalize(tmp.path()).unwrap();
    for paths in [Some(vec![workspace.clone()]), None] {
        let spec = IsolationSpec {
            mode: Some("sandbox".to_owned()),
            read_paths: paths.clone(),
            write_paths: paths.is_none().then(|| vec![workspace.clone()]),
            ..IsolationSpec::default()
        };
        assert!(resolve(&spec, None, &workspace, LlmBaseUrl::default()).is_err());
    }
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path));
        }
        out.push(path);
    }
    out
}

#[tokio::test]
async fn key_files_are_never_exposed_by_the_agent_api() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = std::fs::canonicalize(tmp.path()).unwrap();
    let db_path = workspace.join("agent.db");
    let db = Db::open(&db_path).unwrap();
    db.insert_task_row(&task_row("task-a")).unwrap();
    let db = Arc::new(Mutex::new(db));
    let keys = E2eeKeys::load_or_create(&state_dir(&db_path)).unwrap();
    let e2ee = E2ee::new(
        keys,
        Arc::clone(&db),
        Arc::new(Notify::new()),
        Arc::default(),
    )
    .unwrap();
    e2ee.publish_initial();
    let secrets = secrets(&workspace);

    let ctx = ApiContext {
        db,
        nudge: Arc::new(Notify::new()),
        flush: Arc::new(Notify::new()),
        agent_name: Some("tester".to_owned()),
        host_url: Some("http://host.test".to_owned()),
        workspace_dir: workspace.clone(),
        db_path,
        e2ee: None,
    };
    let server = AgentApiServer::start(ctx, &workspace).unwrap();
    let socket = socket_path(&workspace);
    let responses = tokio::task::spawn_blocking(move || {
        let mut client = Client::connect(&socket).unwrap();
        [
            ("system.info", json!({})),
            ("task.list", json!({})),
            ("thread.list", json!({"task_id": "task-a"})),
            ("cron.list", json!({"task_id": "task-a"})),
        ]
        .map(|(method, params)| client.call(method, params).unwrap())
    })
    .await
    .unwrap();
    server.shutdown().await;

    assert_eq!(responses[0]["scope"], "operator");
    for response in &responses {
        assert_no_secret("the agent API", &response.to_string(), &secrets);
    }
}

#[test]
fn only_a_method_the_profile_declares_is_an_allowed_host_action() {
    use gino_e2ee::EnvelopeType;
    use gino_e2ee::field_map::{
        Direction, FieldMap, FieldRule, FrameRule, KeyedPlain, Kind, When, WhenOp,
    };

    use super::groups::host_action_declared;

    static DECLARING: FieldMap = FieldMap {
        profile: "test.declaring",
        frames: &[FrameRule {
            frame_type: "thread_message",
            direction: Direction::AgentToHost,
            scope: "taskId",
            fields: &[FieldRule {
                path: "data.input.params",
                kind: Kind::Json,
                envelopes: &[EnvelopeType::Content],
                aad: "field:input.params",
                when: Some(When {
                    path: "data.kind",
                    op: WhenOp::Eq,
                    value: "host_action",
                }),
                keyed_plain: Some(KeyedPlain {
                    key: "data.input.method",
                    table: &[("comment", &["kind"])],
                }),
            }],
        }],
    };
    assert!(host_action_declared(&DECLARING, "comment"));
    assert!(!host_action_declared(&DECLARING, "other"));
    assert!(!host_action_declared(&DECLARING, ""));

    let gino = FieldMap::for_profile(super::groups::PROFILE).unwrap();
    for method in ["comment", "noop", "data.input.method"] {
        assert!(!host_action_declared(gino, method), "{method}");
        assert!(!super::host_action_allowed(super::groups::PROFILE, method));
    }
    assert!(!super::host_action_allowed("unknown.profile", "comment"));
}
