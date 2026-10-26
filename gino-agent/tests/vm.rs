//! KVM scenarios of `vm` isolation.
//!
//! Each scenario boots the real `gino-agent` daemon against the stub host with
//! a local isolation file selecting `vm`, so every run goes through the
//! daemon's launch path into a `gino-vmm` microVM. The fake engines live in a
//! host dir shared read-only into the guest (`readPaths`) and named by
//! `GINO_IT_FAKES`; the test guest root's `/usr/local/sbin/{claude,codex}`
//! dispatch to them. Probe results come back as `assistant_text` messages
//! `KEY=VALUE`, as in `tests/sandbox.rs`.
//!
//! They need `/dev/kvm`, the VM artifacts and a non-root user, so every test is
//! `#[ignore]` and also returns early unless `GINO_VM_TESTS=1`;
//! `scripts/vm-it.sh` builds the artifacts and runs them. Environment:
//! `GINO_VM_KERNEL`, `GINO_VM_ROOTFS` (the root image with the dispatchers),
//! `GINO_VM_VMM`, `GINO_VM_PUBLIC_IP` (a public-style
//! address of the test host), optionally `GINO_VM_IT_LOGS` (a dir that keeps
//! every daemon log) and `GINO_VM_NO_KVM=1` for the run without `/dev/kvm`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

#[allow(dead_code)]
mod support;

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, TcpListener, UdpSocket};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{Value, json};
use tempfile::TempDir;

use support::stub_host::{StubHost, ThreadRun, build_tar, delivery_id, provisioning_entry};
use support::{RunnerProc, Workspace, wait_until};

/// Generous: a run boots a VM.
const RUN_TIMEOUT: Duration = Duration::from_mins(1);

/// How long gino-vmm may take to go away after a run or the daemon ends
/// (covers the daemon's TERM grace).
const VMM_GONE_TIMEOUT: Duration = Duration::from_secs(15);

/// The session id every fake `claude` announces.
const SESSION: &str = "sess-vm";

/// The guest path of the gino-agent binary.
const GUEST_AGENT: &str = "/gino-agent";

/// The VM artifacts, or `None` unless the KVM suite was asked for.
struct Artifacts {
    kernel: PathBuf,
    rootfs: PathBuf,
    vmm: PathBuf,
}

fn artifacts() -> Option<Artifacts> {
    if std::env::var("GINO_VM_TESTS").ok().as_deref() != Some("1") {
        return None;
    }
    let var = |key: &str| PathBuf::from(std::env::var(key).unwrap_or_else(|_| panic!("{key}")));
    Some(Artifacts {
        kernel: var("GINO_VM_KERNEL"),
        rootfs: var("GINO_VM_ROOTFS"),
        vmm: var("GINO_VM_VMM"),
    })
}

impl Artifacts {
    /// The isolation file's `vm` block.
    fn vm_block(&self) -> Value {
        json!({
            "kernel": self.kernel,
            "rootfs": self.rootfs,
            "vmm": self.vmm,
            "vcpus": 1,
            "memoryMib": 512,
        })
    }
}

/// Bash helpers the fake engines share (as in `tests/sandbox.rs`): `emit`
/// prints one assistant text line, `check KEY CMD` reports whether `CMD`
/// succeeded, `value KEY CMD` reports its output.
const PRELUDE: &str = r#"#!/usr/bin/env bash
set -u
emit() {
  local t
  t="$(printf '%s' "$1" | tr '\n' ' ' | tr -cd 'A-Za-z0-9 _.:/=,+()`-')"
  printf '{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"%s"}]}}\n' "$t"
}
check() { if ( eval "$2" ) >/dev/null 2>&1; then emit "$1=ok"; else emit "$1=denied"; fi; }
value() { emit "$1=$( ( eval "$2" ) 2>&1 | tr '\n' ' ' | sed 's/ *$//')"; }
wd="$(dirname "${ENGINE_CONFIG_DIR:-.}")"
touch "$wd/engine-ran" 2>/dev/null
"#;

/// A fake `claude` script: init, the probe `body`, then a successful result.
fn claude_script(body: &str) -> String {
    let init = json!({ "type": "system", "subtype": "init", "session_id": SESSION, "model": "stub", "tools": [] });
    let result = json!({ "type": "result", "subtype": "success", "is_error": false, "result": "done", "session_id": SESSION });
    format!("{PRELUDE}printf '%s\\n' '{init}'\n{body}\nprintf '%s\\n' '{result}'\n")
}

/// Write an executable script `name` into `dir`.
fn write_exe(dir: &Path, name: &str, script: &str) {
    let path = dir.join(name);
    std::fs::write(&path, script).expect("write fake engine");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .expect("chmod fake engine");
}

/// A fresh fakes dir holding a probing `claude` running `body`.
fn claude_fakes(body: &str) -> TempDir {
    let dir = tempfile::Builder::new()
        .prefix("fake-engines-")
        .tempdir()
        .expect("create fake engine dir");
    write_exe(dir.path(), "claude", &claude_script(body));
    dir
}

/// A thread's work dir on the host.
fn work_dir(workspace: &Workspace, thread_id: &str) -> PathBuf {
    workspace.dir().join("threads").join(thread_id)
}

/// The daemon's SQLite path (a sibling of the workspace dir in the harness).
fn db_path(workspace: &Workspace) -> PathBuf {
    workspace.dir().parent().unwrap().join("agent.db")
}

/// A daemon running `vm` isolation against a stub host.
struct VmDaemon {
    host: StubHost,
    runner: Option<RunnerProc>,
    fakes: PathBuf,
    log: PathBuf,
    _dir: TempDir,
    // Last: holds the serial lock until everything else is gone.
    workspace: Workspace,
}

/// How to boot a [`VmDaemon`].
struct Boot<'a> {
    /// Names the daemon log.
    name: &'a str,
    /// The isolation file's `network` block.
    network: Value,
    /// The isolation file's `vm` block.
    vm: Value,
    /// The isolation file's `vmDisk`.
    vm_disk: Option<&'a str>,
    /// The stub host's register config.
    config: Value,
    /// Extra daemon env.
    env: Vec<(&'a str, OsString)>,
    /// Provisioning blobs staged on the stub host before the daemon boots.
    blobs: Vec<(&'a str, Vec<u8>)>,
    /// A `claude` script installed in the workspace's engine home.
    managed_claude: Option<String>,
}

impl<'a> Boot<'a> {
    fn new(name: &'a str, artifacts: &Artifacts) -> Self {
        Self {
            name,
            network: json!({ "mode": "none" }),
            vm: artifacts.vm_block(),
            vm_disk: None,
            config: json!({}),
            env: Vec::new(),
            blobs: Vec::new(),
            managed_claude: None,
        }
    }

    fn managed_claude(mut self, script: String) -> Self {
        self.managed_claude = Some(script);
        self
    }

    fn network(mut self, network: Value) -> Self {
        self.network = network;
        self
    }

    fn vm(mut self, vm: Value) -> Self {
        self.vm = vm;
        self
    }

    fn vm_disk(mut self, scope: &'a str) -> Self {
        self.vm_disk = Some(scope);
        self
    }

    fn config(mut self, config: Value) -> Self {
        self.config = config;
        self
    }

    fn blob(mut self, id: &'a str, bytes: &[u8]) -> Self {
        self.blobs.push((id, bytes.to_vec()));
        self
    }

    fn env(mut self, key: &'a str, value: impl Into<OsString>) -> Self {
        self.env.push((key, value.into()));
        self
    }

    /// Boot the daemon with the engine fakes in `fakes` (on the daemon's
    /// `PATH` and shared into the guest) and wait for it to connect.
    async fn start(self, fakes: TempDir) -> VmDaemon {
        let host = StubHost::start(self.config).await;
        for (id, bytes) in &self.blobs {
            host.stage_blob(id, bytes).await;
        }
        let workspace = Workspace::new().await;
        if let Some(script) = &self.managed_claude {
            let bin = workspace.dir().join("engines/home/.local/bin");
            std::fs::create_dir_all(&bin).unwrap();
            write_exe(&bin, "claude", script);
        }
        let dir = tempfile::Builder::new().prefix("vm-it-").tempdir().unwrap();
        let fakes_path = fakes.path().to_path_buf();
        let mut isolation = json!({
            "mode": "vm",
            "network": self.network,
            "readPaths": [fakes_path],
            "vm": self.vm,
        });
        if let Some(scope) = self.vm_disk {
            isolation["vmDisk"] = json!(scope);
        }
        let file = dir.path().join("isolation.json");
        std::fs::write(&file, isolation.to_string()).unwrap();
        let log = match std::env::var_os("GINO_VM_IT_LOGS") {
            Some(logs) => PathBuf::from(logs).join(format!("{}.log", self.name)),
            None => dir.path().join("agent.log"),
        };
        let mut env: Vec<(&str, OsString)> = vec![
            ("GINO_ISOLATION_FILE", file.into_os_string()),
            ("GINO_IT_FAKES", fakes_path.clone().into_os_string()),
            ("RUST_LOG", "info".into()),
        ];
        env.extend(self.env);
        let env: Vec<(&str, &OsStr)> = env.iter().map(|(k, v)| (*k, v.as_os_str())).collect();
        let runner = RunnerProc::spawn_in_with_env(
            &host,
            &workspace,
            fakes,
            &env,
            std::fs::File::create(&log).unwrap().into(),
        );
        assert!(
            host.wait_connected(RUN_TIMEOUT).await,
            "runner never connected; log {}",
            log.display()
        );
        VmDaemon {
            host,
            runner: Some(runner),
            fakes: fakes_path,
            log,
            _dir: dir,
            workspace,
        }
    }
}

impl VmDaemon {
    /// Push a chat message for `task_id`/`thread_id` and wait for the run's
    /// terminal result.
    async fn run(&self, task_id: &str, thread_id: &str, msg_id: i64) -> ThreadRun {
        self.host
            .push_message(task_id, Some(thread_id), "probe", &[], msg_id)
            .await;
        self.terminal(thread_id).await
    }

    /// Wait for `thread_id`'s terminal result.
    async fn terminal(&self, thread_id: &str) -> ThreadRun {
        self.host
            .wait_thread_terminal(thread_id, RUN_TIMEOUT)
            .await
            .unwrap_or_else(|| {
                panic!(
                    "no terminal result for {thread_id}; log {}",
                    self.log.display()
                )
            })
    }

    /// The `KEY=VALUE` probe results a run reported.
    async fn probes(&self, task_id: &str, thread_id: &str) -> HashMap<String, String> {
        self.host
            .messages_for(task_id, thread_id)
            .await
            .into_iter()
            .filter(|m| m.kind == "assistant_text")
            .filter_map(|m| m.content)
            .filter_map(|c| {
                c.split_once('=')
                    .map(|(k, v)| (k.to_owned(), v.trim().to_owned()))
            })
            .collect()
    }

    /// The `error` transcript rows of a run.
    async fn errors(&self, task_id: &str, thread_id: &str) -> Vec<String> {
        self.host
            .messages_for(task_id, thread_id)
            .await
            .into_iter()
            .filter(|m| m.kind == "error")
            .filter_map(|m| m.content)
            .collect()
    }

    fn work_dir(&self, thread_id: &str) -> PathBuf {
        work_dir(&self.workspace, thread_id)
    }

    /// The daemon's pid.
    fn pid(&self) -> u32 {
        self.runner.as_ref().unwrap().pid()
    }

    /// Kill the daemon (SIGKILL) and wait for it.
    async fn kill(&mut self) {
        if let Some(runner) = self.runner.take() {
            runner.shutdown().await;
        }
    }
}

/// Substitute `@WS@` (workspace dir) and `@DB@` (agent db path) in a probe body.
fn render(body: &str, workspace: &Workspace) -> String {
    body.replace("@WS@", &workspace.dir().display().to_string())
        .replace("@DB@", &db_path(workspace).display().to_string())
}

/// Assert each `(key, expected)` probe value.
fn expect(results: &HashMap<String, String>, wanted: &[(&str, &str)]) {
    for (key, value) in wanted {
        assert_eq!(
            results.get(*key).map(String::as_str),
            Some(*value),
            "probe {key}: {results:#?}"
        );
    }
}

/// This test process's uid and gid, which the daemon and so the engine run as.
fn own_ids() -> (u32, u32) {
    let meta = std::fs::metadata("/proc/self").unwrap();
    (meta.uid(), meta.gid())
}

// ---------------------------------------------------------------------------
// Process helpers
// ---------------------------------------------------------------------------

/// The `stat` fields after the command name of process `pid`.
fn stat_fields(pid: u32) -> Option<Vec<String>> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_, rest) = stat.rsplit_once(") ")?;
    Some(rest.split(' ').map(str::to_owned).collect())
}

/// Whether `pid` runs (exists and is not a zombie).
fn alive(pid: u32) -> bool {
    stat_fields(pid).is_some_and(|fields| fields[0] != "Z")
}

/// Whether `pid` runs the `gino-vmm` binary, by its `argv[0]` (libkrun
/// renames the main thread, so `comm` does not tell).
fn is_vmm(pid: u32) -> bool {
    std::fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|cmdline| {
        let argv0 = cmdline.split(|b| *b == 0).next().unwrap_or_default();
        Path::new(OsStr::from_bytes(argv0)).file_name() == Some(OsStr::new("gino-vmm"))
    })
}

/// Every running `gino-vmm` process.
fn vmm_pids() -> Vec<u32> {
    std::fs::read_dir("/proc")
        .unwrap()
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse::<u32>().ok())
        .filter(|pid| is_vmm(*pid) && alive(*pid))
        .collect()
}

/// The parent of `pid`.
fn ppid(pid: u32) -> Option<u32> {
    stat_fields(pid)?.get(1)?.parse().ok()
}

/// The running `gino-vmm` children of `daemon`.
fn vmm_children(daemon: u32) -> Vec<u32> {
    vmm_pids()
        .into_iter()
        .filter(|pid| ppid(*pid) == Some(daemon))
        .collect()
}

/// Wait until `pids` and every other `gino-vmm` process are gone.
async fn assert_vmm_gone(pids: &[u32], when: &str) {
    let gone = wait_until(VMM_GONE_TIMEOUT, || {
        pids.iter().all(|pid| !alive(*pid)) && vmm_pids().is_empty()
    })
    .await;
    assert!(
        gone,
        "gino-vmm still running {when}: ours {pids:?}, all {:?}",
        vmm_pids()
    );
}

/// Wait for `marker` and return the daemon's gino-vmm child then.
async fn vmm_of_running_engine(daemon: &VmDaemon, marker: &Path) -> u32 {
    assert!(
        wait_until(RUN_TIMEOUT, || marker.is_file()).await,
        "the engine never started; log {}",
        daemon.log.display()
    );
    let pids = vmm_children(daemon.pid());
    assert_eq!(pids.len(), 1, "gino-vmm children: {pids:?}");
    pids[0]
}

// ---------------------------------------------------------------------------
// a, b, d: boot, stdio, work dir, identity and privileges
// ---------------------------------------------------------------------------

const BOOT_PROBE: &str = r#"
value STDIN_FIRST 'IFS= read -r line; printf "%s" "$line" | grep -o "\"subtype\":\"[a-z]*\""'
while IFS= read -r -t 10 line; do
  case "$line" in *'"type":"user"'*) break ;; esac
done
check STDIN_PROMPT 'printf "%s" "$line" | grep -q probe'
value VM 'echo "$GINO_VM"'
value UID 'id -u'
value GID 'id -g'
value CAPEFF 'grep "^CapEff:" /proc/self/status | cut -f2'
value CAPPRM 'grep "^CapPrm:" /proc/self/status | cut -f2'
value CAPBND 'grep "^CapBnd:" /proc/self/status | cut -f2'
value NNP 'grep "^NoNewPrivs:" /proc/self/status | cut -f2'
value PID1 'cat /proc/1/comm'
value KERNEL 'uname -r'
value CWD 'pwd'
value WD 'echo "$wd"'
check W_WORKDIR 'echo vm-wrote > "$wd/written.txt"'
check W_HOME 'touch "$ENGINE_CONFIG_DIR/state.json"'
check W_TMP 'echo x > /tmp/tmp.txt'
check W_ROOT 'touch /escape'
check W_USR 'touch /usr/escape'
check W_ETC 'touch /etc/escape'
check W_AGENT 'touch /gino-agent'
value WD_FS 'stat -f -c %T "$wd"'
value CLAUDE_VERSION '/usr/local/bin/claude --version'
"#;

const MANAGED_PROBE: &str = r#"
value ENGINE 'echo "$0"'
check W_ENGINE 'touch "$(dirname "$0")/x"'
"#;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs KVM and the VM artifacts; run scripts/vm-it.sh"]
async fn vm_runs_the_agent_installed_engine_from_a_read_only_share() {
    let Some(artifacts) = artifacts() else {
        return;
    };
    let daemon = Boot::new("engine-dir", &artifacts)
        .managed_claude(claude_script(MANAGED_PROBE))
        .start(claude_fakes("emit FAKE=path"))
        .await;

    let run = daemon.run("t-eng", "th-eng", 1).await;
    assert_eq!(run.status, "succeeded", "run: {run:?}");
    let managed = daemon
        .workspace
        .dir()
        .join("engines/home/.local/bin/claude");
    expect(
        &daemon.probes("t-eng", "th-eng").await,
        &[
            ("ENGINE", &managed.display().to_string()),
            ("W_ENGINE", "denied"),
        ],
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs KVM and the VM artifacts; run scripts/vm-it.sh"]
async fn vm_engine_boots_round_trips_stdio_and_writes_its_work_dir() {
    let Some(artifacts) = artifacts() else {
        return;
    };
    let daemon = Boot::new("boot", &artifacts)
        .start(claude_fakes(BOOT_PROBE))
        .await;

    let run = daemon.run("t-boot", "th-boot", 1).await;
    assert_eq!(run.status, "succeeded", "run: {run:?}");
    let results = daemon.probes("t-boot", "th-boot").await;
    let (uid, gid) = own_ids();
    assert_ne!(uid, 0, "the suite must run as a non-root user");
    let wd = daemon.work_dir("th-boot");
    let wd_str = wd.display().to_string();
    let project = wd.join("project").display().to_string();
    expect(
        &results,
        &[
            ("STDIN_FIRST", "subtype:initialize"),
            ("STDIN_PROMPT", "ok"),
            ("VM", "1"),
            ("UID", &uid.to_string()),
            ("GID", &gid.to_string()),
            ("CAPEFF", "0000000000000000"),
            ("CAPPRM", "0000000000000000"),
            ("CAPBND", "0000000000000000"),
            ("NNP", "1"),
            ("PID1", "init.krun"),
            ("CWD", &project),
            ("WD", &wd_str),
            ("W_WORKDIR", "ok"),
            ("W_HOME", "ok"),
            ("W_TMP", "ok"),
            ("W_ROOT", "denied"),
            ("W_USR", "denied"),
            ("W_ETC", "denied"),
            ("W_AGENT", "denied"),
            ("WD_FS", "fuseblk"),
        ],
    );
    assert!(
        results["KERNEL"].contains("gino"),
        "kernel: {}",
        results["KERNEL"]
    );
    assert!(
        results["CLAUDE_VERSION"].contains("(Claude Code)"),
        "claude --version: {}",
        results["CLAUDE_VERSION"]
    );
    // The guest's write landed on the host, owned by the daemon's uid: the
    // engine's uid in the guest is the daemon's, and virtiofs creates files as
    // the VMM process, which runs as the daemon.
    let written = wd.join("written.txt");
    assert_eq!(std::fs::read_to_string(&written).unwrap(), "vm-wrote\n");
    let meta = std::fs::metadata(&written).unwrap();
    assert_eq!((meta.uid(), meta.gid()), (uid, gid));
    assert!(wd.join(".engine-home/state.json").is_file());
}

// ---------------------------------------------------------------------------
// The root disk: an overlay per run or per task; the base image never changes
// ---------------------------------------------------------------------------

const DISK_PROBE: &str = r#"
value ROOT_FS 'stat -f -c %T /'
value ROOT_GIB 'df -BG --output=size / | tail -1 | tr -dc 0-9'
value MARKER 'cat /var/tmp/gino-marker 2>/dev/null || echo none'
check W_MARKER 'echo "$GINO_THREAD_ID" > /var/tmp/gino-marker'
check W_ETC 'touch /etc/escape'
"#;

/// The size and mtime of a file, which change if anything writes it.
fn file_stamp(path: &Path) -> (u64, std::time::SystemTime) {
    let meta = std::fs::metadata(path).unwrap();
    (meta.len(), meta.modified().unwrap())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs KVM and the VM artifacts; run scripts/vm-it.sh"]
async fn vm_root_disk_is_per_run_or_per_task_and_the_base_never_changes() {
    let Some(artifacts) = artifacts() else {
        return;
    };
    let base = file_stamp(&artifacts.rootfs);
    let mut vm = artifacts.vm_block();
    vm["diskGib"] = json!(4);

    // Run disks: every run starts from the base.
    let daemon = Boot::new("disk-run", &artifacts)
        .vm(vm.clone())
        .start(claude_fakes(DISK_PROBE))
        .await;
    for (thread, msg) in [("th-r1", 1), ("th-r2", 2)] {
        let run = daemon.run("t-disk", thread, msg).await;
        assert_eq!(run.status, "succeeded", "run: {run:?}");
        let results = daemon.probes("t-disk", thread).await;
        expect(
            &results,
            &[
                ("ROOT_FS", "ext2/ext3"),
                ("MARKER", "none"),
                ("W_MARKER", "ok"),
                ("W_ETC", "denied"),
            ],
        );
        let gib: u64 = results["ROOT_GIB"].parse().unwrap();
        assert!((3..=4).contains(&gib), "root size {gib} GiB");
    }
    drop(daemon);

    // Task disks: a task's later run sees its earlier writes, another task
    // does not.
    let daemon = Boot::new("disk-task", &artifacts)
        .vm(vm)
        .vm_disk("task")
        .start(claude_fakes(DISK_PROBE))
        .await;
    for (task, thread, msg, marker) in [
        ("t-disk", "th-t1", 1, "none"),
        ("t-disk", "th-t2", 2, "th-t1"),
        ("t-other", "th-t3", 3, "none"),
    ] {
        let run = daemon.run(task, thread, msg).await;
        assert_eq!(run.status, "succeeded", "run: {run:?}");
        expect(&daemon.probes(task, thread).await, &[("MARKER", marker)]);
    }
    drop(daemon);

    assert_eq!(file_stamp(&artifacts.rootfs), base);
}

// ---------------------------------------------------------------------------
// Docker in the guest
// ---------------------------------------------------------------------------

const DOCKER_PROBE: &str = r#"
value SOCKET_GROUP 'stat -c %g /run/docker.sock'
value HELLO 'docker run --rm hello-world 2>&1 | grep -o "Hello from Docker"'
"#;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs KVM and the VM artifacts; run scripts/vm-it.sh"]
async fn vm_docker_runs_containers_for_the_engine() {
    let Some(artifacts) = artifacts() else {
        return;
    };
    let mut vm = artifacts.vm_block();
    vm["docker"] = json!(true);
    vm["memoryMib"] = json!(1024);
    vm["diskGib"] = json!(8);
    let daemon = Boot::new("docker", &artifacts)
        .network(json!({ "mode": "full" }))
        .vm(vm)
        .start(claude_fakes(DOCKER_PROBE))
        .await;
    let run = daemon.run("t-docker", "th-docker", 1).await;
    assert_eq!(run.status, "succeeded", "run: {run:?}");
    let (_, gid) = own_ids();
    expect(
        &daemon.probes("t-docker", "th-docker").await,
        &[
            ("SOCKET_GROUP", &gid.to_string()),
            ("HELLO", "Hello from Docker"),
        ],
    );
}

// ---------------------------------------------------------------------------
// The PreCompact archive hook runs the guest gino-agent
// ---------------------------------------------------------------------------

const PRECOMPACT_PROBE: &str = r#"
settings=""
prev=""
for arg in "$@"; do
  [ "$prev" = "--settings" ] && settings="$arg"
  prev="$arg"
done
hook="$(printf '%s' "$settings" | grep -o '"command":"[^"]*"' | head -1 | sed 's/^"command":"//; s/"$//')"
value HOOK 'echo "$hook"'
transcript="$ENGINE_CONFIG_DIR/projects/vm/transcript.jsonl"
mkdir -p "$(dirname "$transcript")"
cat > "$transcript" <<'JSONL'
{"type":"user","message":{"role":"user","content":"vm archive question"}}
{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"vm archive answer"}]}}
JSONL
check HOOK_RUN "printf '{\"transcript_path\":\"%s\",\"session_id\":\"sess-vm\"}' \"$transcript\" | sh -c \"\$hook\""
"#;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs KVM and the VM artifacts; run scripts/vm-it.sh"]
async fn vm_precompact_hook_archives_into_the_thread_conversations_dir() {
    let Some(artifacts) = artifacts() else {
        return;
    };
    let daemon = Boot::new("precompact", &artifacts)
        .start(claude_fakes(PRECOMPACT_PROBE))
        .await;

    let run = daemon.run("t-pc", "th-pc", 1).await;
    assert_eq!(run.status, "succeeded", "run: {run:?}");
    let results = daemon.probes("t-pc", "th-pc").await;
    expect(
        &results,
        &[
            ("HOOK", &format!("{GUEST_AGENT} archive")),
            ("HOOK_RUN", "ok"),
        ],
    );

    let conversations = daemon.work_dir("th-pc").join("conversations");
    let archived: Vec<String> = std::fs::read_dir(&conversations)
        .unwrap_or_else(|e| panic!("{}: {e}", conversations.display()))
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension() == Some(OsStr::new("md")))
        .map(|path| std::fs::read_to_string(path).unwrap())
        .collect();
    assert_eq!(archived.len(), 1, "archives: {archived:?}");
    assert!(
        archived[0].contains("vm archive question") && archived[0].contains("vm archive answer"),
        "archive: {}",
        archived[0]
    );
    let index = std::fs::read_to_string(conversations.join("sessions-index.json")).unwrap();
    assert!(index.contains(SESSION), "index: {index}");
}

// ---------------------------------------------------------------------------
// c: other threads, agent state and host paths are invisible
// ---------------------------------------------------------------------------

const ISOLATION_PROBE: &str = r#"
o="@WS@/threads/th-a"
echo secret > "$wd/secret.txt"
check READ_OTHER_WD 'ls "$o"'
check READ_OTHER_SECRET 'cat "$o/secret.txt"'
check READ_DB 'cat "@DB@"'
value DB_DIR_LS 'ls "$(dirname "@DB@")"'
check READ_GLOBAL 'ls "@WS@/engine-config"'
value STORE_COUNT 'ls "@WS@/store" | wc -l'
check STORE_WRITE 'touch "@WS@/store/new"'
check READ_GLOBAL_STORE 'cat "@GLOBAL_STORE@"'
value WS_LS 'ls "@WS@"'
value THREADS_LS 'ls "@WS@/threads"'
check READ_HOST_SECRET 'cat "@SECRET@"'
check READ_SOURCE 'ls "@SOURCE@"'
check READ_VMM 'ls "@VMM@"'
value CLAUDE_MD 'cat "$ENGINE_CONFIG_DIR/CLAUDE.md"'
check CLAUDE_MD_WRITE 'echo x >> "$ENGINE_CONFIG_DIR/CLAUDE.md"'
value SKILL 'cat "$ENGINE_CONFIG_DIR/skills/demo/SKILL.md"'
check SKILLS_WRITE 'touch "$ENGINE_CONFIG_DIR/skills/new"'
value TASK_FILE 'cat "$wd/project/TASK.md"'
check TASK_FILE_WRITE 'echo x >> "$wd/project/TASK.md"'
value TASK_SKILL 'cat "$wd/project/skills/task-demo/SKILL.md"'
check TASK_SKILL_WRITE 'touch "$wd/project/skills/task-demo/new"'
"#;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs KVM and the VM artifacts; run scripts/vm-it.sh"]
async fn vm_hides_other_threads_agent_state_and_host_paths() {
    let Some(artifacts) = artifacts() else {
        return;
    };
    let secret_dir = tempfile::Builder::new()
        .prefix("host-secret-")
        .tempdir()
        .unwrap();
    let secret = secret_dir.path().join("secret.txt");
    std::fs::write(&secret, "host secret").unwrap();

    let claude_md = b"global instructions\n";
    let skill_tar = build_tar(&[("SKILL.md", b"demo skill\n")]);
    let entries = json!({ "entries": [
        provisioning_entry("clauderc", "CLAUDE.md", "file", claude_md),
        provisioning_entry("demo-skill", "skills/demo", "dir", &skill_tar),
    ] });
    // The probe needs the workspace path, which exists only once the daemon
    // booted: the fake reads it from a file written next to it.
    let fakes = claude_fakes(r#"source "$GINO_IT_FAKES/probe.sh""#);
    let daemon = Boot::new("isolation", &artifacts)
        .config(entries)
        .blob("clauderc", claude_md)
        .blob("demo-skill", &skill_tar)
        .start(fakes)
        .await;
    let global = daemon
        .workspace
        .dir()
        .join("engine-config/skills/demo/SKILL.md");
    assert!(
        wait_until(RUN_TIMEOUT, || global.is_file()).await,
        "global scope never materialized"
    );
    // The global entries are copied into the engine home, never shared at
    // their store paths.
    let global_store =
        std::fs::canonicalize(daemon.workspace.dir().join("engine-config/CLAUDE.md")).unwrap();
    let probe = render(ISOLATION_PROBE, &daemon.workspace)
        .replace("@SECRET@", &secret.display().to_string())
        .replace("@SOURCE@", env!("CARGO_MANIFEST_DIR"))
        .replace("@VMM@", &artifacts.vmm.display().to_string())
        .replace("@GLOBAL_STORE@", &global_store.display().to_string());
    std::fs::write(daemon.fakes.join("probe.sh"), probe).unwrap();

    let a = daemon.run("t-a", "th-a", 1).await;
    assert_eq!(a.status, "succeeded", "run A: {a:?}");
    assert!(daemon.work_dir("th-a").join("secret.txt").is_file());

    // B carries task-scope store entries.
    let task_md = b"task instructions\n";
    let task_skill = build_tar(&[("SKILL.md", b"task skill\n")]);
    let file = daemon
        .host
        .stage_provisioning_entry("task-md", "TASK.md", "file", task_md)
        .await;
    let dir = daemon
        .host
        .stage_provisioning_entry("task-skill", "skills/task-demo", "dir", &task_skill)
        .await;
    daemon
        .host
        .push_frame(&json!({
            "type": "task_upsert",
            "taskId": "t-b",
            "data": { "status": "active", "entries": [file, dir] },
            "msgId": delivery_id(2),
        }))
        .await;
    let b = daemon.run("t-b", "th-b", 3).await;
    assert_eq!(b.status, "succeeded", "run B: {b:?}");

    // B probes A, which has already run and left its files behind.
    let results = daemon.probes("t-b", "th-b").await;
    expect(
        &results,
        &[
            ("READ_OTHER_WD", "denied"),
            ("READ_OTHER_SECRET", "denied"),
            ("READ_DB", "denied"),
            // Only the ancestors of the shared work dir exist.
            ("DB_DIR_LS", "workspace"),
            ("READ_GLOBAL", "denied"),
            // The store holds only B's own task-scope entries, read-only.
            ("STORE_COUNT", "2"),
            ("STORE_WRITE", "denied"),
            ("READ_GLOBAL_STORE", "denied"),
            ("WS_LS", "store threads"),
            ("THREADS_LS", "th-b"),
            ("READ_HOST_SECRET", "denied"),
            ("READ_SOURCE", "denied"),
            ("READ_VMM", "denied"),
            ("CLAUDE_MD", "global instructions"),
            ("CLAUDE_MD_WRITE", "denied"),
            ("SKILL", "demo skill"),
            ("SKILLS_WRITE", "denied"),
            ("TASK_FILE", "task instructions"),
            ("TASK_FILE_WRITE", "denied"),
            ("TASK_SKILL", "task skill"),
            ("TASK_SKILL_WRITE", "denied"),
        ],
    );
}

// ---------------------------------------------------------------------------
// e: the agent API over vsock, scoped to the run's own task
// ---------------------------------------------------------------------------

const API_PROBE: &str = r#"
value SOCK 'echo "$GINO_AGENT_SOCK"'
value BIN 'echo "$GINO_RUNNER_BIN"'
value CRON_ID '"$GINO_RUNNER_BIN" cron create --type interval --value 3600000 --prompt p'
value CRON_LIST '"$GINO_RUNNER_BIN" cron list | cut -f1'
value TASK_LIST '"$GINO_RUNNER_BIN" task list | cut -f1'
value ACTION '"$GINO_RUNNER_BIN" action comment "{\"body\":\"$GINO_THREAD_ID\"}"'
other_cron="$(cat "$GINO_IT_FAKES/other-cron")"
check FOREIGN_CRON_LIST '"$GINO_RUNNER_BIN" cron list --task-id t-other'
check FOREIGN_CRON_PAUSE '"$GINO_RUNNER_BIN" cron pause "$other_cron"'
check FOREIGN_TASK '"$GINO_RUNNER_BIN" task show t-other'
check NO_TOKEN 'env -u GINO_AGENT_TOKEN "$GINO_RUNNER_BIN" task list'
check BAD_TOKEN 'GINO_AGENT_TOKEN=0000 "$GINO_RUNNER_BIN" task list'
value SOCK_MODE 'stat -c %a "$GINO_AGENT_SOCK"'
"#;

/// One operator-scope agent API call on the daemon socket; returns `result`.
fn operator_api(socket: &Path, method: &str, params: &Value) -> Value {
    let mut stream = BufReader::new(UnixStream::connect(socket).unwrap());
    let line = json!({ "v": 1, "id": "t", "method": method, "params": params });
    stream
        .get_mut()
        .write_all(format!("{line}\n").as_bytes())
        .unwrap();
    let mut response = String::new();
    stream.read_line(&mut response).unwrap();
    let response: Value = serde_json::from_str(&response).unwrap();
    response["result"].clone()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs KVM and the VM artifacts; run scripts/vm-it.sh"]
async fn vm_engine_uses_the_agent_api_over_vsock_within_its_own_task() {
    let Some(artifacts) = artifacts() else {
        return;
    };
    let daemon = Boot::new("agent-api", &artifacts)
        .start(claude_fakes(API_PROBE))
        .await;
    let socket = daemon.workspace.dir().join("run/agent.sock");
    assert!(
        wait_until(RUN_TIMEOUT, || socket.exists()).await,
        "agent socket never appeared"
    );
    daemon
        .host
        .push_task_upsert("t-other", Some("other"), Some("chat"), None, 1)
        .await;
    daemon
        .host
        .push_task_upsert("t-api", Some("mine"), Some("chat"), None, 2)
        .await;
    assert!(
        wait_until(RUN_TIMEOUT, || {
            operator_api(&socket, "task.show", &json!({ "id": "t-other" })).is_object()
        })
        .await,
        "t-other never reached the daemon"
    );
    let other = operator_api(
        &socket,
        "cron.create",
        &json!({ "type": "interval", "value": "3600000", "prompt": "o", "task_id": "t-other" }),
    )["cron"]
        .clone();
    let other_id = other["id"].as_str().unwrap().to_owned();
    std::fs::write(daemon.fakes.join("other-cron"), &other_id).unwrap();

    let run = daemon.run("t-api", "th-api", 3).await;
    assert_eq!(run.status, "succeeded", "run: {run:?}");
    let results = daemon.probes("t-api", "th-api").await;
    let cron_id = results["CRON_ID"].clone();
    let uuid = cron_id
        .strip_prefix("cron-")
        .unwrap_or_else(|| panic!("cron create: {results:#?}"));
    uuid::Uuid::parse_str(uuid).unwrap_or_else(|_| panic!("cron create: {results:#?}"));
    expect(
        &results,
        &[
            ("SOCK", "/run/gino/agent.sock"),
            ("BIN", GUEST_AGENT),
            ("CRON_LIST", &cron_id),
            ("TASK_LIST", "t-api"),
            ("FOREIGN_CRON_LIST", "denied"),
            ("FOREIGN_CRON_PAUSE", "denied"),
            ("FOREIGN_TASK", "denied"),
            ("NO_TOKEN", "denied"),
            ("BAD_TOKEN", "denied"),
        ],
    );

    // The cron landed on the run's task; the other task's is untouched.
    let mine = operator_api(&socket, "cron.list", &json!({ "task_id": "t-api" }));
    assert_eq!(mine["crons"][0]["id"], cron_id.as_str(), "{mine}");
    let theirs = operator_api(&socket, "cron.list", &json!({ "task_id": "t-other" }));
    assert_eq!(theirs["crons"], json!([other]), "t-other's crons changed");

    // `action` recorded one host_action on the run's own thread.
    let actions: Vec<_> = daemon
        .host
        .messages_for("t-api", "th-api")
        .await
        .into_iter()
        .filter(|m| m.kind == "host_action")
        .collect();
    assert_eq!(actions.len(), 1, "{actions:?}");
    assert_eq!(results["ACTION"], actions[0].seq.to_string());
    assert_eq!(
        actions[0].input,
        Some(json!({ "method": "comment", "params": { "body": "th-api" } }))
    );
}

// ---------------------------------------------------------------------------
// f: network modes
// ---------------------------------------------------------------------------

/// A non-loopback address of this machine (routing lookup only, no traffic).
fn non_loopback_ip() -> IpAddr {
    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    socket.connect("192.0.2.1:9").unwrap();
    socket.local_addr().unwrap().ip()
}

/// The test host's public-style address.
fn public_ip() -> IpAddr {
    std::env::var("GINO_VM_PUBLIC_IP")
        .expect("GINO_VM_PUBLIC_IP")
        .parse()
        .unwrap()
}

/// A TCP server on `ip` answering each `ping` line with `pong`; returns its port.
fn pong_server(ip: IpAddr) -> u16 {
    let listener = TcpListener::bind((ip, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut line = String::new();
            let mut reader = BufReader::new(&stream);
            if reader.read_line(&mut line).is_ok() && line == "ping\n" {
                let _ = (&stream).write_all(b"pong\n");
            }
        }
    });
    port
}

/// A UDP server on `ip` echoing every datagram; returns its port.
fn udp_echo(ip: IpAddr) -> u16 {
    let socket = UdpSocket::bind((ip, 0)).unwrap();
    let port = socket.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        while let Ok((n, from)) = socket.recv_from(&mut buf) {
            let _ = socket.send_to(&buf[..n], from);
        }
    });
    port
}

/// The `gino_agent::net` decision lines of `thread_id` in a daemon log, ANSI
/// styling removed.
fn decision_lines(log: &Path, thread_id: &str) -> Vec<String> {
    let raw = std::fs::read_to_string(log).unwrap_or_default();
    let mut plain = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            chars.by_ref().find(|c| *c == 'm');
        } else {
            plain.push(c);
        }
    }
    plain
        .lines()
        .filter(|l| {
            l.contains("network decision") && l.contains(&format!("thread_id=\"{thread_id}\""))
        })
        .map(str::to_owned)
        .collect()
}

/// Whether a decision line for `target_ip`:`port` over `proto` says `decision`.
fn logged(lines: &[String], proto: &str, ip: &str, port: u16, decision: &str) -> bool {
    lines.iter().any(|l| {
        l.contains(&format!("proto=\"{proto}\""))
            && l.contains(&format!("target_ip={ip} "))
            && l.contains(&format!("port={port} "))
            && l.contains(&format!("decision=\"{decision}\""))
    })
}

/// Probe helpers: `udp.pl HOST PORT` (echo round trip), `rcode.pl NAME` (the
/// DNS rcode of an A query to the gateway), `tcp HOST PORT` (a `ping`/`pong`
/// round trip) and the loopback and link checks.
const NET_HELPERS: &str = r#"
cat > /tmp/udp.pl <<'PL'
use strict;
use IO::Socket::INET;
use IO::Select;
my ($host, $port) = @ARGV;
my $s = IO::Socket::INET->new(PeerAddr => $host, PeerPort => $port, Proto => 'udp') or die "socket: $!";
$s->send("ping") or die "send: $!";
IO::Select->new($s)->can_read(3) or exit 1;
my $r;
defined $s->recv($r, 16) or exit 1;
exit($r eq "ping" ? 0 : 1);
PL
cat > /tmp/rcode.pl <<'PL'
use strict;
use IO::Socket::INET;
use IO::Select;
my $name = shift;
my $q = pack('n n n n n n', 0x1234, 0x0100, 1, 0, 0, 0);
$q .= pack('C', length $_) . $_ for split /\./, $name;
$q .= pack('C n n', 0, 1, 1);
my $s = IO::Socket::INET->new(PeerAddr => '10.0.2.2', PeerPort => 53, Proto => 'udp') or die "socket: $!";
$s->send($q) or die "send: $!";
IO::Select->new($s)->can_read(3) or die "no answer";
my $r;
$s->recv($r, 512);
my (undef, $flags) = unpack('n n', $r);
print $flags & 0xf;
PL
cat > /tmp/lo.pl <<'PL'
use strict;
use IO::Socket::INET;
my $l = IO::Socket::INET->new(Listen => 1, LocalAddr => '127.0.0.1', LocalPort => 0, Proto => 'tcp') or die "listen: $!";
my $c = IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => $l->sockport, Proto => 'tcp') or die "connect: $!";
my $s = $l->accept or die "accept: $!";
print $c "ping\n";
my $r = <$s>;
exit($r eq "ping\n" ? 0 : 1);
PL
tcp() { exec 3<>"/dev/tcp/$1/$2"; printf "ping\n" >&3; read -t 5 -r r <&3; test "$r" = pong; }
check LO_TCP 'timeout 5 perl /tmp/lo.pl'
value LINKS 'tail -n +3 /proc/net/dev | cut -d: -f1 | tr -d " " | sort | tr "\n" ","'
"#;

const NONE_PROBE: &str = r#"
check EXTERNAL 'timeout 5 bash -c "exec 3<>/dev/tcp/@EXT_IP@/@EXT_PORT@"'
check GATEWAY 'timeout 5 bash -c "exec 3<>/dev/tcp/10.0.2.2/@EXT_PORT@"'
check DNS 'timeout 5 getent hosts example.com'
"#;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs KVM and the VM artifacts; run scripts/vm-it.sh"]
async fn vm_network_none_has_only_loopback() {
    let Some(artifacts) = artifacts() else {
        return;
    };
    let ip = non_loopback_ip();
    let port = pong_server(ip);
    let body = format!("{NET_HELPERS}{NONE_PROBE}")
        .replace("@EXT_IP@", &ip.to_string())
        .replace("@EXT_PORT@", &port.to_string());
    let daemon = Boot::new("net-none", &artifacts)
        .start(claude_fakes(&body))
        .await;
    let run = daemon.run("t-none", "th-none", 1).await;
    assert_eq!(run.status, "succeeded", "run: {run:?}");
    let results = daemon.probes("t-none", "th-none").await;
    expect(
        &results,
        &[
            ("LO_TCP", "ok"),
            ("LINKS", "lo,"),
            ("EXTERNAL", "denied"),
            ("GATEWAY", "denied"),
            ("DNS", "denied"),
        ],
    );
}

/// Fixed port of the SSH-style banner server (a non-HTTP port).
const BANNER_PORT: u16 = 2222;

/// A TCP server on `ip:port` that greets with an SSH-style banner and answers
/// the client's banner line with `ok`.
fn banner_server(ip: IpAddr, port: u16) {
    let listener = TcpListener::bind((ip, port)).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let _ = (&stream).write_all(b"SSH-2.0-gino-it\r\n");
            let mut line = String::new();
            if BufReader::new(&stream).read_line(&mut line).is_ok() && line.starts_with("SSH-2.0-")
            {
                let _ = (&stream).write_all(b"ok\n");
            }
        }
    });
}

const ALLOWLIST_PROBE: &str = r#"
u="${ANTHROPIC_BASE_URL#*://}"
hp="${u%%/*}"
h="${hp%:*}"
p="${hp##*:}"
value LLM_HOST 'echo "$h"'
value LLM_PATH 'echo "/${u#*/}"'
check LLM 'tcp "$h" "$p"'
check GATEWAY_OTHER 'timeout 5 bash -c "exec 3<>/dev/tcp/10.0.2.2/@OTHER_TCP@"'
check ALLOWED_NAME 'getent hosts allowed.test'
check DISALLOWED_NAME 'getent hosts example.com'
check DISALLOWED_CONNECT 'timeout 5 bash -c "exec 3<>/dev/tcp/example.com/80"'
value BANNER 'exec 3<>/dev/tcp/@IP@/@BANNER_PORT@; read -t 5 -r b <&3; printf "SSH-2.0-probe\r\n" >&3; read -t 5 -r a <&3; echo "$b $a"'
check TCP_OTHER_PORT 'timeout 5 bash -c "exec 3<>/dev/tcp/@IP@/@OTHER_TCP@"'
check UDP_ALLOWED 'timeout 5 perl /tmp/udp.pl @IP@ @UDP_PORT@'
check UDP_DENIED 'timeout 5 perl /tmp/udp.pl @IP@ @OTHER_UDP@'
value NX_RCODE 'timeout 5 perl /tmp/rcode.pl denied.example'
check OUTSIDE_CIDR 'timeout 5 bash -c "exec 3<>/dev/tcp/192.0.2.10/@BANNER_PORT@"'
value RESOLV 'cat /etc/resolv.conf'
value MAC 'cat /sys/class/net/eth0/address'
"#;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs KVM and the VM artifacts; run scripts/vm-it.sh"]
async fn vm_allowlist_admits_only_matching_flows() {
    let Some(artifacts) = artifacts() else {
        return;
    };
    let llm_port = pong_server(IpAddr::from([127, 0, 0, 1]));
    // Upstreams live on the test host's own address; only a covering cidr
    // rule admits them.
    let ip = non_loopback_ip();
    banner_server(ip, BANNER_PORT);
    let other_tcp = TcpListener::bind((ip, 0)).unwrap();
    let other_tcp_port = other_tcp.local_addr().unwrap().port();
    let udp_port = udp_echo(ip);
    let other_udp_port = udp_echo(ip);
    let cidr = format!("{ip}/32");
    let network = json!({ "mode": "allowlist", "allow": [
        { "host": "allowed.test", "ports": [443] },
        { "cidr": cidr, "ports": [BANNER_PORT] },
        { "cidr": cidr, "ports": [udp_port], "proto": "udp" },
    ] });
    let body = format!("{NET_HELPERS}{ALLOWLIST_PROBE}")
        .replace("@IP@", &ip.to_string())
        .replace("@BANNER_PORT@", &BANNER_PORT.to_string())
        .replace("@OTHER_TCP@", &other_tcp_port.to_string())
        .replace("@UDP_PORT@", &udp_port.to_string())
        .replace("@OTHER_UDP@", &other_udp_port.to_string());
    let daemon = Boot::new("net-allowlist", &artifacts)
        .network(network)
        .env(
            "ANTHROPIC_BASE_URL",
            format!("http://127.0.0.1:{llm_port}/api/llm"),
        )
        .start(claude_fakes(&body))
        .await;

    let run = daemon.run("t-al", "th-al", 1).await;
    assert_eq!(run.status, "succeeded", "run: {run:?}");
    let results = daemon.probes("t-al", "th-al").await;
    expect(
        &results,
        &[
            ("LO_TCP", "ok"),
            ("LINKS", "eth0,lo,"),
            ("LLM_HOST", "10.0.2.2"),
            ("LLM_PATH", "/api/llm"),
            ("LLM", "ok"),
            ("GATEWAY_OTHER", "denied"),
            ("ALLOWED_NAME", "ok"),
            ("DISALLOWED_NAME", "denied"),
            ("DISALLOWED_CONNECT", "denied"),
            ("BANNER", "SSH-2.0-gino-it ok"),
            ("TCP_OTHER_PORT", "denied"),
            ("UDP_ALLOWED", "ok"),
            ("UDP_DENIED", "denied"),
            ("NX_RCODE", "3"),
            ("OUTSIDE_CIDR", "denied"),
            ("RESOLV", "nameserver 10.0.2.2"),
            ("MAC", "5a:94:ef:e4:0c:ee"),
        ],
    );

    let lines = decision_lines(&daemon.log, "th-al");
    let ip = ip.to_string();
    for (proto, port, decision) in [
        ("tcp", BANNER_PORT, "allow"),
        ("tcp", other_tcp_port, "deny"),
        ("udp", udp_port, "allow"),
        ("udp", other_udp_port, "deny"),
    ] {
        assert!(
            logged(&lines, proto, &ip, port, decision),
            "no {decision} line for {proto}/{port}: {lines:#?}"
        );
    }
}

const FULL_PROBE: &str = r#"
check PUBLIC_TCP 'tcp @PUBLIC@ @PUBLIC_PORT@'
check PUBLIC_UDP 'timeout 5 perl /tmp/udp.pl @PUBLIC@ @PUBLIC_UDP@'
check HOST_LOOPBACK 'timeout 5 bash -c "exec 3<>/dev/tcp/10.0.2.2/@LOOPBACK_PORT@"'
check PRIVATE 'timeout 5 bash -c "exec 3<>/dev/tcp/@PRIVATE@/@PRIVATE_PORT@"'
check PRIVATE_10 'timeout 5 bash -c "exec 3<>/dev/tcp/10.1.2.3/80"'
check LINK_LOCAL 'timeout 5 bash -c "exec 3<>/dev/tcp/169.254.169.254/80"'
"#;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs KVM and the VM artifacts; run scripts/vm-it.sh"]
async fn vm_full_reaches_public_destinations_but_not_local_or_private_ones() {
    let Some(artifacts) = artifacts() else {
        return;
    };
    let public = public_ip();
    let public_port = pong_server(public);
    let public_udp = udp_echo(public);
    let loopback_port = pong_server(IpAddr::from([127, 0, 0, 1]));
    // The exit refuses private destinations by address, after the public
    // rule matched (see the decision log), whether or not anything answers
    // there.
    let private = IpAddr::from([172, 17, 0, 1]);
    let private_port = 80;
    let body = format!("{NET_HELPERS}{FULL_PROBE}")
        .replace("@PUBLIC@", &public.to_string())
        .replace("@PUBLIC_PORT@", &public_port.to_string())
        .replace("@PUBLIC_UDP@", &public_udp.to_string())
        .replace("@LOOPBACK_PORT@", &loopback_port.to_string())
        .replace("@PRIVATE@", &private.to_string())
        .replace("@PRIVATE_PORT@", &private_port.to_string());
    let daemon = Boot::new("net-full", &artifacts)
        .network(json!({ "mode": "full" }))
        .start(claude_fakes(&body))
        .await;

    let run = daemon.run("t-full", "th-full", 1).await;
    assert_eq!(run.status, "succeeded", "run: {run:?}");
    let results = daemon.probes("t-full", "th-full").await;
    expect(
        &results,
        &[
            ("LO_TCP", "ok"),
            ("LINKS", "eth0,lo,"),
            ("PUBLIC_TCP", "ok"),
            ("PUBLIC_UDP", "ok"),
            ("HOST_LOOPBACK", "denied"),
            ("PRIVATE", "denied"),
            ("PRIVATE_10", "denied"),
            ("LINK_LOCAL", "denied"),
        ],
    );
    let lines = decision_lines(&daemon.log, "th-full");
    for (ip, port) in [
        (private.to_string(), private_port),
        ("10.1.2.3".to_owned(), 80),
    ] {
        assert!(
            logged(&lines, "tcp", &ip, port, "refused"),
            "no refused line for {ip}:{port}: {lines:#?}"
        );
    }
    assert!(
        logged(&lines, "tcp", &public.to_string(), public_port, "allow"),
        "no allow line for the public target: {lines:#?}"
    );
}

// ---------------------------------------------------------------------------
// g, i: SIGINT reaches a codex-style engine; nothing outlives the run
// ---------------------------------------------------------------------------

/// A fake `codex` that reads its prompt to EOF (codex closes stdin after the
/// prompt), announces its thread, signals readiness, then waits; SIGINT is
/// trapped and recorded in the work dir before exiting with status 130.
const HANGING_CODEX: &str = r#"#!/usr/bin/env bash
set -u
wd="$(dirname "$ENGINE_CONFIG_DIR")"
trap 'printf "sigint uid=%s vm=%s\n" "$(id -u)" "${GINO_VM:-}" > "$wd/sigint.marker"; exit 130' INT
prompt="$(cat)"
printf '%s' "$prompt" > "$wd/prompt.txt"
printf '%s\n' '{"type":"thread.started","thread_id":"codex-vm"}'
printf '%s\n' '{"type":"turn.started"}'
echo ready > "$wd/ready.marker"
for _ in $(seq 1 600); do sleep 0.1; done
printf '%s\n' '{"type":"turn.completed"}'
"#;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs KVM and the VM artifacts; run scripts/vm-it.sh"]
async fn vm_interrupt_reaches_codex_through_guest_init_and_cancels_the_run() {
    let Some(artifacts) = artifacts() else {
        return;
    };
    let fakes = claude_fakes("");
    write_exe(fakes.path(), "codex", HANGING_CODEX);
    let daemon = Boot::new("interrupt", &artifacts).start(fakes).await;

    daemon
        .host
        .push_task_upsert_with_engine("t-int", "codex", 1)
        .await;
    daemon
        .host
        .push_message("t-int", Some("th-int"), "hang please", &[], 2)
        .await;
    let wd = daemon.work_dir("th-int");
    // Readiness proves the engine saw stdin EOF after the prompt.
    let vmm = vmm_of_running_engine(&daemon, &wd.join("ready.marker")).await;
    assert!(
        std::fs::read_to_string(wd.join("prompt.txt"))
            .unwrap()
            .contains("hang please")
    );

    daemon
        .host
        .push_frame(&json!({ "type": "interrupt", "taskId": "t-int", "msgId": delivery_id(3) }))
        .await;
    let run = daemon.terminal("th-int").await;
    assert_eq!(run.status, "cancelled", "run: {run:?}");
    let marker =
        std::fs::read_to_string(wd.join("sigint.marker")).expect("the codex never saw SIGINT");
    let (uid, _) = own_ids();
    assert_eq!(marker.trim(), format!("sigint uid={uid} vm=1"));
    assert_vmm_gone(&[vmm], "after the cancelled run").await;
}

/// A fake `claude` that signals readiness, then runs for `secs` seconds.
fn slow_claude(secs: u32) -> String {
    claude_script(&format!(
        "echo ready > \"$wd/ready.marker\"\nfor _ in $(seq 1 {}); do sleep 0.1; done",
        secs * 10
    ))
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs KVM and the VM artifacts; run scripts/vm-it.sh"]
async fn vm_session_end_and_daemon_death_leave_no_vmm_behind() {
    let Some(artifacts) = artifacts() else {
        return;
    };
    let fakes = claude_fakes("");
    write_exe(fakes.path(), "claude", &slow_claude(2));
    let mut daemon = Boot::new("lifecycle", &artifacts).start(fakes).await;

    // A run that ends by itself.
    daemon
        .host
        .push_message("t-life", Some("th-end"), "probe", &[], 1)
        .await;
    let vmm = vmm_of_running_engine(&daemon, &daemon.work_dir("th-end").join("ready.marker")).await;
    let run = daemon.terminal("th-end").await;
    assert_eq!(run.status, "succeeded", "run: {run:?}");
    assert_vmm_gone(&[vmm], "after the session ended").await;

    // A run whose daemon is killed mid-run.
    write_exe(&daemon.fakes, "claude", &slow_claude(60));
    daemon
        .host
        .push_message("t-life", Some("th-kill"), "probe", &[], 2)
        .await;
    let vmm =
        vmm_of_running_engine(&daemon, &daemon.work_dir("th-kill").join("ready.marker")).await;
    daemon.kill().await;
    assert_vmm_gone(&[vmm], "after the daemon was killed").await;
}

// ---------------------------------------------------------------------------
// h: a crashed or misconfigured gino-vmm fails the run with a runner-side reason
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs KVM and the VM artifacts; run scripts/vm-it.sh"]
async fn vm_killed_vmm_fails_the_run_with_a_runner_side_reason() {
    let Some(artifacts) = artifacts() else {
        return;
    };
    // The engine prints one assistant line, then keeps running.
    let fakes = claude_fakes("emit started\nsleep 60");
    let daemon = Boot::new("vmm-killed", &artifacts).start(fakes).await;

    daemon
        .host
        .push_message("t-crash", Some("th-crash"), "probe", &[], 1)
        .await;
    let vmm = vmm_of_running_engine(&daemon, &daemon.work_dir("th-crash").join("engine-ran")).await;
    // The daemon reads the engine's stdout only once it saw the engine start,
    // so a kill from now on comes after the start.
    let deadline = tokio::time::Instant::now() + RUN_TIMEOUT;
    while !daemon
        .host
        .messages_for("t-crash", "th-crash")
        .await
        .iter()
        .any(|m| m.kind == "assistant_text" && m.content.as_deref() == Some("started"))
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the engine's output never reached the host; log {}",
            daemon.log.display()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(i32::try_from(vmm).unwrap()),
        nix::sys::signal::Signal::SIGKILL,
    )
    .unwrap();
    let run = daemon.terminal("th-crash").await;
    assert_eq!(run.status, "failed", "run: {run:?}");
    let errors = daemon.errors("t-crash", "th-crash").await;
    assert!(
        errors.iter().any(|e| e.contains("gino-vmm exited")
            && e.contains("SIGKILL")
            && e.contains("without an engine exit status")),
        "errors: {errors:#?}; run: {run:?}"
    );
    assert_vmm_gone(&[vmm], "after the crash").await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs KVM and the VM artifacts; run scripts/vm-it.sh"]
async fn vm_vmm_config_failure_fails_the_run_before_the_engine_starts() {
    let Some(artifacts) = artifacts() else {
        return;
    };
    // A kernel file that passes the probe (it exists) but is no kernel.
    let bad = tempfile::Builder::new()
        .prefix("bad-kernel-")
        .tempdir()
        .unwrap();
    let kernel = bad.path().join("vmlinux");
    std::fs::write(&kernel, b"not a kernel").unwrap();
    let mut vm = artifacts.vm_block();
    vm["kernel"] = json!(kernel);
    let daemon = Boot::new("vmm-config", &artifacts)
        .vm(vm)
        .start(claude_fakes(""))
        .await;

    let run = daemon.run("t-cfg", "th-cfg", 1).await;
    assert_eq!(run.status, "failed", "run: {run:?}");
    let error = run.error.clone().unwrap_or_default();
    assert!(
        error.contains("gino-vmm failed before the VM started"),
        "error: {error}; run: {run:?}"
    );
    assert!(
        !daemon.work_dir("th-cfg").join("engine-ran").exists(),
        "the engine must not run"
    );
    assert_vmm_gone(&[], "after the failed start").await;
}

// ---------------------------------------------------------------------------
// j: fail closed before any spawn
// ---------------------------------------------------------------------------

/// Boot a daemon with `vm`, run once and assert the run failed as
/// unavailable, mentioning `needle`, without starting the engine or gino-vmm.
async fn assert_unavailable(artifacts: &Artifacts, name: &str, vm: Value, needle: &str) {
    let daemon = Boot::new(name, artifacts)
        .vm(vm)
        .start(claude_fakes(""))
        .await;
    let run = daemon.run("t-closed", "th-closed", 1).await;
    assert_eq!(run.status, "failed", "{name}: {run:?}");
    let error = run.error.clone().unwrap_or_default();
    assert!(
        error.contains("engine sandbox is unavailable") && error.contains(needle),
        "{name} error: {error}"
    );
    assert_eq!(
        run.failure_reason.as_deref(),
        Some("runner.invalid_request"),
        "{name}"
    );
    assert!(
        !daemon.work_dir("th-closed").join("engine-ran").exists(),
        "{name}: the engine must not run"
    );
    assert!(
        vmm_children(daemon.pid()).is_empty(),
        "{name}: gino-vmm started"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs KVM and the VM artifacts; run scripts/vm-it.sh"]
async fn vm_missing_or_bad_artifacts_fail_closed() {
    let Some(artifacts) = artifacts() else {
        return;
    };
    let bad = tempfile::Builder::new()
        .prefix("bad-artifacts-")
        .tempdir()
        .unwrap();
    let plain = bad.path().join("plain");
    std::fs::write(&plain, b"#!/bin/sh\nexit 0\n").unwrap();
    let failing = bad.path().join("failing-vmm");
    write_exe(
        bad.path(),
        "failing-vmm",
        "#!/bin/sh\necho 'gino-vmm: libkrun is unusable' >&2\nexit 120\n",
    );

    let with = |key: &str, value: Value| {
        let mut vm = artifacts.vm_block();
        vm[key] = value;
        vm
    };
    let cases = [
        (
            "missing-kernel",
            with("kernel", json!(bad.path().join("vmlinux"))),
            "is not a file",
        ),
        (
            "missing-rootfs",
            with("rootfs", json!(bad.path().join("rootfs"))),
            "rootfs image",
        ),
        (
            "missing-vmm",
            with("vmm", json!(bad.path().join("gino-vmm"))),
            "is not an executable file",
        ),
        (
            "non-executable-vmm",
            with("vmm", json!(plain)),
            "is not an executable file",
        ),
        (
            "failing-vmm-probe",
            with("vmm", json!(failing)),
            "gino-vmm probe failed",
        ),
    ];
    for (name, vm, needle) in cases {
        assert_unavailable(&artifacts, name, vm, needle).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the VM artifacts without /dev/kvm; run scripts/vm-it.sh"]
async fn vm_without_kvm_access_fails_closed() {
    let Some(artifacts) = artifacts() else {
        return;
    };
    if std::env::var("GINO_VM_NO_KVM").ok().as_deref() != Some("1") {
        return;
    }
    assert!(
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .is_err(),
        "/dev/kvm must not be usable in this run"
    );
    let vm = artifacts.vm_block();
    assert_unavailable(&artifacts, "no-kvm", vm, "/dev/kvm").await;
}

// ---------------------------------------------------------------------------
// Agent and task memory
// ---------------------------------------------------------------------------

/// The task fact the memory scenarios store.
const TASK_FACT: &str = "task-fact-7f3a";
/// The agent fact the memory scenarios store.
const AGENT_FACT: &str = "agent-fact-91c2";
/// The claude auto memory fact the memory scenarios store.
const CLAUDE_FACT: &str = "claude-fact-5d1e";
/// The in-engine claude auto memory dir with task memory on.
const GUEST_AUTO_MEMORY: &str = "/run/gino/memory/task/claude";

/// Boot a daemon with the agent-local `envs` and a probing `claude` running
/// `body` (with `@WS@` rendered once the workspace exists).
async fn memory_daemon(
    name: &str,
    artifacts: &Artifacts,
    envs: &[(&'static str, &str)],
    body: &str,
) -> VmDaemon {
    let mut boot = Boot::new(name, artifacts);
    for (key, value) in envs {
        boot = boot.env(key, *value);
    }
    let daemon = boot
        .start(claude_fakes(r#"source "$GINO_IT_FAKES/probe.sh""#))
        .await;
    std::fs::write(
        daemon.fakes.join("probe.sh"),
        render(body, &daemon.workspace),
    )
    .unwrap();
    daemon
}

impl VmDaemon {
    /// Run each `(task, thread)` in order, all expected to succeed, starting
    /// at delivery id `msg_id`.
    async fn run_threads(&self, runs: &[(&str, &str)], msg_id: i64) {
        for (msg_id, (task, thread)) in (msg_id..).zip(runs) {
            let run = self.run(task, thread, msg_id).await;
            assert_eq!(run.status, "succeeded", "{thread}: {run:?}");
        }
    }

    /// Upsert `task_id` carrying `meta`.
    async fn push_task_meta(&self, task_id: &str, meta: &Value, msg_id: i64) {
        self.host
            .push_frame(&json!({
                "type": "task_upsert",
                "taskId": task_id,
                "data": { "status": "active", "meta": meta },
                "msgId": delivery_id(msg_id),
            }))
            .await;
    }

    /// A host task memory dir.
    fn task_memory(&self, task_id: &str) -> PathBuf {
        self.workspace.dir().join("memory/task").join(task_id)
    }

    /// The host agent memory dir.
    fn agent_memory(&self) -> PathBuf {
        self.workspace.dir().join("memory/agent")
    }

    /// The guest engine argv a probe saved in `thread_id`'s work dir.
    fn guest_argv(&self, thread_id: &str) -> Vec<String> {
        let raw = std::fs::read(self.work_dir(thread_id).join("engine-argv")).unwrap();
        raw.split(|b| *b == 0)
            .filter(|arg| !arg.is_empty())
            .map(|arg| String::from_utf8(arg.to_vec()).unwrap())
            .collect()
    }

    /// The guest `--settings` JSON of `thread_id`'s run, asserting no argv
    /// element names the host workspace.
    fn guest_settings(&self, thread_id: &str) -> Value {
        let argv = self.guest_argv(thread_id);
        let ws = self.workspace.dir().display().to_string();
        assert!(
            !argv.iter().any(|arg| arg.contains(&ws)),
            "{thread_id} argv names the host workspace: {argv:#?}"
        );
        let at = argv.iter().position(|arg| arg == "--settings").unwrap();
        serde_json::from_str(&argv[at + 1]).unwrap()
    }

    /// Assert `thread_id` ran with task memory on and claude auto memory at
    /// the task share.
    fn expect_auto_memory_on(&self, thread_id: &str, results: &HashMap<String, String>) {
        let settings = self.guest_settings(thread_id);
        assert_eq!(
            settings["autoMemoryDirectory"], GUEST_AUTO_MEMORY,
            "{settings}"
        );
        assert!(settings.get("autoMemoryEnabled").is_none(), "{settings}");
        expect(
            results,
            &[("AUTO_MEMORY", GUEST_AUTO_MEMORY), ("DISABLE_ENV", "unset")],
        );
    }

    /// Assert `thread_id` ran with claude auto memory off and nothing outside
    /// the task memory trees of `on_tasks` holds an auto memory dir or index.
    fn expect_auto_memory_off(
        &self,
        thread_id: &str,
        results: &HashMap<String, String>,
        on_tasks: &[&str],
    ) {
        let settings = self.guest_settings(thread_id);
        assert_eq!(settings["autoMemoryEnabled"], false, "{settings}");
        assert!(settings.get("autoMemoryDirectory").is_none(), "{settings}");
        expect(results, &[("DISABLE_ENV", "1")]);

        let ws = self.workspace.dir();
        let root = ws.join("memory");
        let on: Vec<PathBuf> = on_tasks.iter().map(|t| self.task_memory(t)).collect();
        let mut found = auto_memory_paths(&self.work_dir(thread_id).join(".engine-home"), &[]);
        found.extend(auto_memory_paths(&ws.join("engine-config"), &[]));
        found.extend(auto_memory_paths(ws, std::slice::from_ref(&root)));
        found.extend(auto_memory_paths(&root, &on));
        assert!(found.is_empty(), "auto memory left behind: {found:#?}");
    }
}

/// Every `memory` dir and `MEMORY.md` under `dir`, not descending into `skip`.
fn auto_memory_paths(dir: &Path, skip: &[PathBuf]) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if skip.contains(&path) {
                continue;
            }
            let is_dir = entry.file_type().is_ok_and(|t| t.is_dir());
            let name = entry.file_name();
            if name == "MEMORY.md" || (is_dir && name == "memory") {
                found.push(path.clone());
            }
            if is_dir {
                stack.push(path);
            }
        }
    }
    found
}

/// Probe lines saving the engine argv to the work dir and reading the auto
/// memory dir and its disable switch.
const AUTO_MEMORY_PROBE: &str = r#"
printf '%s\0' "$@" > "$wd/engine-argv"
settings=""; prev=""
for a in "$@"; do [ "$prev" = --settings ] && settings="$a"; prev="$a"; done
amd="$(printf '%s' "$settings" | sed -n 's/.*"autoMemoryDirectory":"\([^"]*\)".*/\1/p')"
value AUTO_MEMORY 'echo "$amd"'
value DISABLE_ENV 'echo "${CLAUDE_CODE_DISABLE_AUTO_MEMORY-unset}"'
"#;

const TASK_MEMORY_PROBE: &str = r#"
value MEM_DIR 'echo "${GINO_MEMORY_DIR-unset}"'
value AGENT_DIR 'echo "${GINO_AGENT_MEMORY_DIR-unset}"'
case "$GINO_THREAD_ID" in
th-a1)
  check TASK_WRITE 'echo "- task-fact-7f3a" >> "$GINO_MEMORY_DIR/index.md" && echo task-fact-7f3a > "$GINO_MEMORY_DIR/fact.md"'
  check CLAUDE_WRITE 'echo "- [Fact](fact.md) claude-fact-5d1e" > "$amd/MEMORY.md" && echo claude-fact-5d1e > "$amd/fact.md"'
  check AGENT_WRITE 'echo agent-fact-91c2 > "$GINO_AGENT_MEMORY_DIR/fact.md"'
  ;;
th-a2)
  value TASK_READ 'cat "$GINO_MEMORY_DIR/fact.md"'
  value CLAUDE_READ 'cat "$amd/fact.md"'
  check CLAUDE_INDEX 'grep -q "(fact.md) claude-fact-5d1e" "$amd/MEMORY.md"'
  check CTX_SECTION '/gino-agent memory-context | grep -q "^## Task memory"'
  check CTX_FACT '/gino-agent memory-context | grep -q task-fact-7f3a'
  ;;
th-b1)
  value TASK_LS 'ls "$GINO_MEMORY_DIR"'
  check TASK_FACT_SEEN 'grep -rq task-fact-7f3a "$GINO_MEMORY_DIR"'
  value CLAUDE_LS 'ls -A "$amd"'
  check CLAUDE_FACT_SEEN 'grep -rq claude-fact-5d1e "$GINO_MEMORY_DIR"'
  check OTHER_CLAUDE 'cat "@WS@/memory/task/t-a/claude/fact.md"'
  check CTX_SECTION '/gino-agent memory-context | grep -q "^## Task memory"'
  check CTX_FACT '/gino-agent memory-context | grep -q task-fact-7f3a'
  check WS_MEMORY 'test -e "@WS@/memory"'
  check OTHER_LIST 'ls "@WS@/memory/task/t-a"'
  check OTHER_READ 'cat "@WS@/memory/task/t-a/fact.md"'
  check OTHER_WRITE 'echo x > "@WS@/memory/task/t-a/fact.md"'
  check OTHER_CREATE 'echo x > "@WS@/memory/task/t-a/planted.md"'
  value AGENT_READ 'cat "$GINO_AGENT_MEMORY_DIR/fact.md"'
  ;;
esac
"#;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs KVM and the VM artifacts; run scripts/vm-it.sh"]
async fn vm_task_memory_persists_per_task_and_agent_memory_is_shared() {
    let Some(artifacts) = artifacts() else {
        return;
    };
    let probe = format!("{AUTO_MEMORY_PROBE}{TASK_MEMORY_PROBE}");
    let daemon = memory_daemon("memory-task", &artifacts, &[], &probe).await;
    // Every run boots its own VM.
    daemon
        .run_threads(&[("t-a", "th-a1"), ("t-a", "th-a2"), ("t-b", "th-b1")], 1)
        .await;

    let a1 = daemon.probes("t-a", "th-a1").await;
    expect(
        &a1,
        &[
            ("MEM_DIR", "/run/gino/memory/task"),
            ("AGENT_DIR", "/run/gino/memory/agent"),
            ("TASK_WRITE", "ok"),
            ("AGENT_WRITE", "ok"),
            ("CLAUDE_WRITE", "ok"),
        ],
    );
    daemon.expect_auto_memory_on("th-a1", &a1);
    let a2 = daemon.probes("t-a", "th-a2").await;
    daemon.expect_auto_memory_on("th-a2", &a2);
    expect(
        &a2,
        &[
            ("TASK_READ", TASK_FACT),
            ("CLAUDE_READ", CLAUDE_FACT),
            ("CLAUDE_INDEX", "ok"),
            ("CTX_SECTION", "ok"),
            ("CTX_FACT", "ok"),
        ],
    );
    // Task B gets its own fresh tree at the same path; A's is not in its view.
    let b1 = daemon.probes("t-b", "th-b1").await;
    daemon.expect_auto_memory_on("th-b1", &b1);
    expect(
        &b1,
        &[
            ("MEM_DIR", "/run/gino/memory/task"),
            ("TASK_LS", "claude index.md system"),
            ("TASK_FACT_SEEN", "denied"),
            ("CLAUDE_LS", ""),
            ("CLAUDE_FACT_SEEN", "denied"),
            ("OTHER_CLAUDE", "denied"),
            ("CTX_SECTION", "ok"),
            ("CTX_FACT", "denied"),
            ("WS_MEMORY", "denied"),
            ("OTHER_LIST", "denied"),
            ("OTHER_READ", "denied"),
            ("OTHER_WRITE", "denied"),
            ("OTHER_CREATE", "denied"),
            ("AGENT_READ", AGENT_FACT),
        ],
    );

    let a = daemon.task_memory("t-a");
    assert_eq!(
        std::fs::read_to_string(a.join("fact.md")).unwrap().trim(),
        TASK_FACT
    );
    assert!(
        std::fs::read_to_string(a.join("index.md"))
            .unwrap()
            .contains(&format!("- {TASK_FACT}"))
    );
    assert!(!a.join("planted.md").exists());
    assert_eq!(
        std::fs::read_to_string(a.join("claude/fact.md"))
            .unwrap()
            .trim(),
        CLAUDE_FACT
    );
    assert!(
        std::fs::read_to_string(a.join("claude/MEMORY.md"))
            .unwrap()
            .contains(CLAUDE_FACT)
    );
    let b = daemon.task_memory("t-b");
    assert!(b.join("index.md").is_file());
    assert!(!b.join("fact.md").exists());
    assert_eq!(std::fs::read_dir(b.join("claude")).unwrap().count(), 0);
    assert_eq!(
        std::fs::read_to_string(daemon.agent_memory().join("fact.md"))
            .unwrap()
            .trim(),
        AGENT_FACT
    );
}

/// Reports which memory shares, env vars and writes a run has.
const MEMORY_ACCESS_PROBE: &str = r#"
werr() { perl -e 'open(my $f, ">>", $ARGV[0]) and print("ok"), exit 0; print($!{EROFS} ? "EROFS" : $!{EACCES} ? "EACCES" : "other $!")' "$1"; }
value MEM_ENV 'echo "${GINO_MEMORY_DIR-unset}"'
value AGENT_ENV 'echo "${GINO_AGENT_MEMORY_DIR-unset}"'
value CONV_ENV 'echo "${GINO_CONVERSATIONS_DIR-unset}"'
check TASK_MOUNT 'test -e /run/gino/memory/task'
check AGENT_MOUNT 'test -e /run/gino/memory/agent'
check CONV_MOUNT 'test -e /run/gino/conversations'
check MEMORY_ROOT 'test -e /run/gino/memory'
value AGENT_READ 'head -n 1 /run/gino/memory/agent/index.md'
value AGENT_WRITE 'werr "/run/gino/memory/agent/fact-$GINO_TASK_ID.md"'
value TASK_WRITE 'werr /run/gino/memory/task/fact.md'
"#;

/// The probe of a run with task memory on (and its view mounted).
const TASK_ON: [(&str, &str); 5] = [
    ("MEM_ENV", "/run/gino/memory/task"),
    ("CONV_ENV", "/run/gino/conversations"),
    ("TASK_MOUNT", "ok"),
    ("CONV_MOUNT", "ok"),
    ("TASK_WRITE", "ok"),
];
/// The probe of a run with task memory off.
const TASK_OFF: [(&str, &str); 4] = [
    ("MEM_ENV", "unset"),
    ("CONV_ENV", "unset"),
    ("TASK_MOUNT", "denied"),
    ("CONV_MOUNT", "denied"),
];
/// The probe of a run with agent memory on.
const AGENT_ON: [(&str, &str); 2] = [
    ("AGENT_ENV", "/run/gino/memory/agent"),
    ("AGENT_MOUNT", "ok"),
];
/// The probe of a run with agent memory off.
const AGENT_OFF: [(&str, &str); 2] = [("AGENT_ENV", "unset"), ("AGENT_MOUNT", "denied")];

/// Assert an agent memory write was refused by a read-only share that still
/// reads.
fn expect_read_only_agent(results: &HashMap<String, String>) {
    let write = results.get("AGENT_WRITE").map(String::as_str);
    assert!(
        matches!(write, Some("EROFS" | "EACCES")),
        "agent write: {results:#?}"
    );
    assert!(
        results
            .get("AGENT_READ")
            .is_some_and(|line| !line.is_empty()),
        "agent read: {results:#?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs KVM and the VM artifacts; run scripts/vm-it.sh"]
async fn vm_agent_memory_read_only_and_task_memory_off() {
    let Some(artifacts) = artifacts() else {
        return;
    };
    let probe = format!("{AUTO_MEMORY_PROBE}{MEMORY_ACCESS_PROBE}");
    // Agent memory read-only and task memory off for the whole daemon.
    {
        let daemon = memory_daemon(
            "memory-ro-task-off",
            &artifacts,
            &[
                ("GINO_AGENT_MEMORY_ACCESS", "ro"),
                ("GINO_TASK_MEMORY", "off"),
            ],
            &probe,
        )
        .await;
        daemon.run_threads(&[("t-ro", "th-ro")], 1).await;
        let results = daemon.probes("t-ro", "th-ro").await;
        expect_read_only_agent(&results);
        expect(&results, &AGENT_ON);
        expect(&results, &TASK_OFF);
        daemon.expect_auto_memory_off("th-ro", &results, &[]);
        assert!(daemon.agent_memory().join("index.md").is_file());
        assert!(!daemon.agent_memory().join("fact-t-ro.md").exists());
        assert!(!daemon.workspace.dir().join("memory/task").exists());
    }

    // Per-task meta: agent memory read-only for one task, task memory off for
    // another, which still writes agent memory.
    let daemon = memory_daemon("memory-meta", &artifacts, &[], &probe).await;
    daemon
        .push_task_meta("t-meta-ro", &json!({ "memory": { "agent": "ro" } }), 1)
        .await;
    daemon
        .push_task_meta("t-meta-off", &json!({ "memory": { "task": "off" } }), 2)
        .await;
    daemon
        .run_threads(
            &[("t-meta-ro", "th-meta-ro"), ("t-meta-off", "th-meta-off")],
            3,
        )
        .await;
    let ro = daemon.probes("t-meta-ro", "th-meta-ro").await;
    expect_read_only_agent(&ro);
    expect(&ro, &AGENT_ON);
    expect(&ro, &TASK_ON);
    daemon.expect_auto_memory_on("th-meta-ro", &ro);
    let off = daemon.probes("t-meta-off", "th-meta-off").await;
    expect(&off, &TASK_OFF);
    daemon.expect_auto_memory_off("th-meta-off", &off, &["t-meta-ro"]);
    expect(&off, &AGENT_ON);
    expect(&off, &[("AGENT_WRITE", "ok")]);
    let agent = daemon.agent_memory();
    assert!(!agent.join("fact-t-meta-ro.md").exists());
    assert!(agent.join("fact-t-meta-off.md").is_file());
    assert!(daemon.task_memory("t-meta-ro").join("fact.md").is_file());
    assert!(!daemon.task_memory("t-meta-off").exists());
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs KVM and the VM artifacts; run scripts/vm-it.sh"]
async fn vm_agent_memory_off_drops_its_share_alone_or_with_task_memory() {
    let Some(artifacts) = artifacts() else {
        return;
    };
    let daemon = memory_daemon(
        "memory-agent-off",
        &artifacts,
        &[("GINO_AGENT_MEMORY_ACCESS", "off")],
        MEMORY_ACCESS_PROBE,
    )
    .await;
    daemon
        .push_task_meta("t-both-off", &json!({ "memory": { "task": "off" } }), 1)
        .await;
    daemon
        .run_threads(
            &[
                ("t-agent-off", "th-agent-off"),
                ("t-both-off", "th-both-off"),
            ],
            2,
        )
        .await;
    let agent_off = daemon.probes("t-agent-off", "th-agent-off").await;
    expect(&agent_off, &AGENT_OFF);
    expect(&agent_off, &TASK_ON);
    // Both off: no memory shares at all.
    let both_off = daemon.probes("t-both-off", "th-both-off").await;
    expect(&both_off, &TASK_OFF);
    expect(&both_off, &AGENT_OFF);
    expect(&both_off, &[("MEMORY_ROOT", "denied")]);
    assert!(daemon.task_memory("t-agent-off").join("fact.md").is_file());
    assert!(!daemon.task_memory("t-both-off").exists());
}

const CONVERSATIONS_PROBE: &str = r#"
c="${GINO_CONVERSATIONS_DIR:-/nonexistent}/th-c1"
case "$GINO_THREAD_ID" in
th-d1)
  check SECRET_WRITE 'echo task-d-secret > "$GINO_MEMORY_DIR/secret.md"'
  ;;
th-c1)
  check ARCHIVE_WRITE 'mkdir -p "$GINO_ARCHIVE_DIR" && echo conv-marker-5b1e > "$GINO_ARCHIVE_DIR/transcript-1.jsonl"'
  check PLANT 'ln -s "@WS@/memory/task/t-d/secret.md" "$GINO_ARCHIVE_DIR/leak-task.md" && ln -s "@WS@/memory/agent/index.md" "$GINO_ARCHIVE_DIR/leak-agent.md"'
  ;;
th-c2)
  value CONV_DIR 'echo "${GINO_CONVERSATIONS_DIR-unset}"'
  value CONV_READ 'cat "$c/transcript-1.jsonl"'
  check CONV_WRITE 'echo x > "$c/transcript-1.jsonl"'
  check CONV_CREATE 'echo x > "$c/new.jsonl"'
  check LEAK_TASK 'test -e "$c/leak-task.md" || test -L "$c/leak-task.md"'
  check LEAK_AGENT 'test -e "$c/leak-agent.md" || test -L "$c/leak-agent.md"'
  check LEAK_CONTENT 'grep -rq task-d-secret "$GINO_CONVERSATIONS_DIR"'
  ;;
th-d2)
  check SEES_C 'test -e "$c"'
  check SEES_C_FILE 'grep -rq conv-marker-5b1e "$GINO_CONVERSATIONS_DIR"'
  ;;
esac
"#;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs KVM and the VM artifacts; run scripts/vm-it.sh"]
async fn vm_conversations_view_is_a_read_only_snapshot_of_the_task_only() {
    let Some(artifacts) = artifacts() else {
        return;
    };
    let daemon = memory_daemon("memory-conversations", &artifacts, &[], CONVERSATIONS_PROBE).await;
    daemon
        .run_threads(
            &[
                ("t-d", "th-d1"),
                ("t-c", "th-c1"),
                ("t-c", "th-c2"),
                ("t-d", "th-d2"),
            ],
            1,
        )
        .await;

    expect(
        &daemon.probes("t-d", "th-d1").await,
        &[("SECRET_WRITE", "ok")],
    );
    expect(
        &daemon.probes("t-c", "th-c1").await,
        &[("ARCHIVE_WRITE", "ok"), ("PLANT", "ok")],
    );
    // The archive is readable but not writable; planted symlinks are not followed.
    expect(
        &daemon.probes("t-c", "th-c2").await,
        &[
            ("CONV_DIR", "/run/gino/conversations"),
            ("CONV_READ", "conv-marker-5b1e"),
            ("CONV_WRITE", "denied"),
            ("CONV_CREATE", "denied"),
            ("LEAK_TASK", "denied"),
            ("LEAK_AGENT", "denied"),
            ("LEAK_CONTENT", "denied"),
        ],
    );
    // Another task never sees the archive.
    expect(
        &daemon.probes("t-d", "th-d2").await,
        &[("SEES_C", "denied"), ("SEES_C_FILE", "denied")],
    );

    let archive = daemon.work_dir("th-c1").join("conversations");
    assert_eq!(
        std::fs::read_to_string(archive.join("transcript-1.jsonl"))
            .unwrap()
            .trim(),
        "conv-marker-5b1e"
    );
    assert!(!archive.join("new.jsonl").exists());
    assert!(archive.join("leak-task.md").is_symlink());
}
