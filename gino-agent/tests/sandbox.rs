//! Privileged engine-sandbox scenarios.
//!
//! Each scenario boots the real `gino-agent` daemon against the stub host with
//! `engine.isolation` (or a task's `meta.isolation`) turned on and a fake engine
//! that probes its own surroundings from inside the sandbox. Every probe result
//! comes back as an `assistant_text` message `KEY=VALUE`, which the scenario
//! asserts on.
//!
//! They need bubblewrap, unprivileged user namespaces and a non-root user, so
//! every test is `#[ignore]` and also returns early unless `GINO_SANDBOX_IT=1`;
//! `scripts/sandbox-it.sh` runs them in a suitably configured container.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

#[allow(dead_code)]
mod support;

use std::collections::HashMap;
use std::ffi::OsStr;
use std::net::{IpAddr, TcpListener, UdpSocket};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{Value, json};
use tempfile::TempDir;

use support::stub_host::{StubHost, ThreadRun, build_tar, delivery_id, provisioning_entry};
use support::{RunnerProc, Workspace, wait_until};

/// Generous: a sandboxed spawn adds a bwrap probe and namespace setup.
const RUN_TIMEOUT: Duration = Duration::from_secs(30);

/// The session id every fake `claude` announces.
const SESSION: &str = "sess-sandbox";

/// Whether the privileged suite was asked for.
fn enabled() -> bool {
    std::env::var("GINO_SANDBOX_IT").is_ok_and(|v| v == "1")
}

/// The register config turning the sandbox on with `network` mode, merged
/// over `extra` (e.g. global provisioning `entries`).
fn sandbox_config(network: &str, extra: Value) -> Value {
    let mut config = extra;
    config["engine"] =
        json!({ "isolation": { "mode": "sandbox", "network": { "mode": network } } });
    config
}

/// Bash helpers the fake engines share: `emit` prints one assistant text
/// line, `check KEY CMD` reports whether `CMD` succeeded, `value KEY CMD`
/// reports its output. Text is reduced to a JSON-safe character set.
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
touch "$PWD/../engine-ran" 2>/dev/null
"#;

/// A fake `claude` script: init, the probe `body`, then a successful result.
fn claude_script(body: &str) -> String {
    let init = json!({ "type": "system", "subtype": "init", "session_id": SESSION, "model": "stub", "tools": [] });
    let result = json!({ "type": "result", "subtype": "success", "is_error": false, "result": "done", "session_id": SESSION });
    format!("{PRELUDE}printf '%s\\n' '{init}'\n{body}\nprintf '%s\\n' '{result}'\n")
}

/// A fresh directory for the engine fakes.
fn fake_dir() -> TempDir {
    tempfile::Builder::new()
        .prefix("fake-engines-")
        .tempdir()
        .expect("create fake engine dir")
}

/// Write an executable script `name` into `dir`.
fn write_exe(dir: &Path, name: &str, script: &str) {
    let path = dir.join(name);
    std::fs::write(&path, script).expect("write fake engine");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .expect("chmod fake engine");
}

/// A fakes dir holding a probing `claude` running `body`.
fn claude_fakes(body: &str) -> TempDir {
    let dir = fake_dir();
    write_exe(dir.path(), "claude", &claude_script(body));
    dir
}

/// Substitute `@WS@` (workspace dir) and `@DB@` (agent db path) in a probe body.
fn render(body: &str, workspace: &Workspace) -> String {
    let ws = workspace.dir();
    body.replace("@WS@", &ws.display().to_string())
        .replace("@DB@", &db_path(workspace).display().to_string())
}

/// The daemon's SQLite path (a sibling of the workspace dir in the harness).
fn db_path(workspace: &Workspace) -> PathBuf {
    workspace.dir().parent().unwrap().join("agent.db")
}

/// A thread's work dir on the host.
fn work_dir(workspace: &Workspace, thread_id: &str) -> PathBuf {
    workspace.dir().join("threads").join(thread_id)
}

/// Push a chat message for `task_id`/`thread_id` and wait for the run's
/// terminal result.
async fn run_thread(host: &StubHost, task_id: &str, thread_id: &str, msg_id: i64) -> ThreadRun {
    host.push_message(task_id, Some(thread_id), "probe", &[], msg_id)
        .await;
    host.wait_thread_terminal(thread_id, RUN_TIMEOUT)
        .await
        .unwrap_or_else(|| panic!("no terminal result for {thread_id}"))
}

/// The `KEY=VALUE` probe results a run reported.
async fn probes(host: &StubHost, task_id: &str, thread_id: &str) -> HashMap<String, String> {
    host.messages_for(task_id, thread_id)
        .await
        .into_iter()
        .filter_map(|m| m.content)
        .filter_map(|c| {
            c.split_once('=')
                .map(|(k, v)| (k.to_owned(), v.trim().to_owned()))
        })
        .collect()
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

/// Push a `task_upsert` carrying `meta`.
async fn push_task_meta(host: &StubHost, task_id: &str, meta: &Value, msg_id: i64) {
    host.push_frame(&json!({
        "type": "task_upsert",
        "taskId": task_id,
        "data": { "status": "active", "meta": meta },
        "msgId": delivery_id(msg_id),
    }))
    .await;
}

/// A non-loopback address of this machine (routing lookup only, no traffic).
fn non_loopback_ip() -> IpAddr {
    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    socket.connect("192.0.2.1:9").unwrap();
    socket.local_addr().unwrap().ip()
}

// ---------------------------------------------------------------------------
// Filesystem isolation between two sandboxed threads
// ---------------------------------------------------------------------------

const ISOLATION_PROBE: &str = r#"
case "$GINO_THREAD_ID" in th-a) other=th-b ;; *) other=th-a ;; esac
o="@WS@/threads/$other"
echo secret > "$wd/secret.txt"
echo mine > "/tmp/marker-$GINO_THREAD_ID"
check READ_OTHER_WD 'ls "$o"'
check READ_OTHER_SECRET 'cat "$o/secret.txt"'
check READ_OTHER_HOME 'ls "$o/.engine-home"'
check READ_DB 'cat "@DB@"'
check READ_GLOBAL 'ls "@WS@/engine-config"'
check READ_STORE 'ls "@WS@/store"'
value WS_LS 'ls "@WS@"'
value THREADS_LS 'ls "@WS@/threads"'
check OTHER_TMP 'test -e "/tmp/marker-$other"'
value ENGINE_HOME 'echo "$ENGINE_CONFIG_DIR"'
value CLAUDE_HOME 'echo "$CLAUDE_CONFIG_DIR"'
value CLAUDE_MD 'cat "$ENGINE_CONFIG_DIR/CLAUDE.md"'
check CLAUDE_MD_WRITE 'echo x >> "$ENGINE_CONFIG_DIR/CLAUDE.md"'
value SKILL 'cat "$ENGINE_CONFIG_DIR/skills/demo/SKILL.md"'
value SKILLS_LS 'ls -l "$ENGINE_CONFIG_DIR/skills"'
value ROOT_FS 'grep " / " /proc/self/mounts'
check SKILLS_WRITE 'touch "$ENGINE_CONFIG_DIR/skills/new"'
check HOME_WRITE 'touch "$ENGINE_CONFIG_DIR/state.json"'
"#;

#[tokio::test]
#[ignore = "needs bubblewrap and user namespaces; run scripts/sandbox-it.sh"]
async fn sandboxed_threads_cannot_see_each_other_or_agent_state() {
    if !enabled() {
        return;
    }
    let claude_md = b"global instructions\n";
    let skill_tar = build_tar(&[("SKILL.md", b"demo skill\n")]);
    let entries = json!({ "entries": [
        provisioning_entry("clauderc", "CLAUDE.md", "file", claude_md),
        provisioning_entry("demo-skill", "skills/demo", "dir", &skill_tar),
    ] });
    let host = StubHost::start(sandbox_config("none", entries)).await;
    host.stage_blob("clauderc", claude_md).await;
    host.stage_blob("demo-skill", &skill_tar).await;

    let workspace = Workspace::new().await;
    let fakes = claude_fakes(&render(ISOLATION_PROBE, &workspace));
    let runner = RunnerProc::spawn_in_with_fakes(&host, &workspace, fakes, None);
    assert!(
        host.wait_connected(RUN_TIMEOUT).await,
        "runner never connected"
    );
    let global = workspace.dir().join("engine-config/skills/demo/SKILL.md");
    assert!(
        wait_until(RUN_TIMEOUT, || global.is_file()).await,
        "global scope never materialized"
    );

    let a = run_thread(&host, "t-a", "th-a", 1).await;
    assert_eq!(a.status, "succeeded", "run A: {a:?}");
    assert!(work_dir(&workspace, "th-a").join("secret.txt").is_file());
    let b = run_thread(&host, "t-b", "th-b", 2).await;
    assert_eq!(b.status, "succeeded", "run B: {b:?}");

    // B probes A, which has already run and left its files behind.
    let results = probes(&host, "t-b", "th-b").await;
    let home = work_dir(&workspace, "th-b").join(".engine-home");
    let home = home.display().to_string();
    expect(
        &results,
        &[
            ("READ_OTHER_WD", "denied"),
            ("READ_OTHER_SECRET", "denied"),
            ("READ_OTHER_HOME", "denied"),
            ("READ_DB", "denied"),
            ("READ_GLOBAL", "denied"),
            ("READ_STORE", "denied"),
            ("WS_LS", "threads"),
            ("THREADS_LS", "th-b"),
            ("OTHER_TMP", "denied"),
            ("ENGINE_HOME", &home),
            ("CLAUDE_HOME", &home),
            ("CLAUDE_MD", "global instructions"),
            ("CLAUDE_MD_WRITE", "denied"),
            ("SKILL", "demo skill"),
            ("SKILLS_WRITE", "denied"),
            ("HOME_WRITE", "ok"),
        ],
    );
    // A's view of the workspace is likewise only its own thread.
    let results = probes(&host, "t-a", "th-a").await;
    expect(&results, &[("THREADS_LS", "th-a"), ("READ_DB", "denied")]);

    runner.shutdown().await;
}

// ---------------------------------------------------------------------------
// Writes are confined to the work dir and a private /tmp
// ---------------------------------------------------------------------------

const WRITE_PROBE: &str = r#"
check W_WORKDIR 'echo x > "$wd/written.txt"'
check W_CWD 'echo x > "$PWD/cwd.txt"'
check W_TMP 'echo x > /tmp/tmp.txt'
check W_WS 'echo x > "@WS@/escape.txt"'
check W_THREADS 'echo x > "@WS@/threads/escape.txt"'
check W_USR 'touch /usr/escape'
check W_ETC 'touch /etc/escape'
check W_ROOT 'touch /escape'
value ROOT_FS 'grep " / " /proc/self/mounts'
check W_AGENT 'touch "$GINO_RUNNER_BIN"'
check W_ENGINE_BIN 'touch "$(command -v claude)"'
"#;

#[tokio::test]
#[ignore = "needs bubblewrap and user namespaces; run scripts/sandbox-it.sh"]
async fn sandboxed_writes_are_confined_to_the_work_dir_and_tmp() {
    if !enabled() {
        return;
    }
    let host = StubHost::start(sandbox_config("none", json!({}))).await;
    let workspace = Workspace::new().await;
    let fakes = claude_fakes(&render(WRITE_PROBE, &workspace));
    let runner = RunnerProc::spawn_in_with_fakes(&host, &workspace, fakes, None);
    assert!(
        host.wait_connected(RUN_TIMEOUT).await,
        "runner never connected"
    );

    let run = run_thread(&host, "t-w", "th-w", 1).await;
    assert_eq!(run.status, "succeeded", "run: {run:?}");
    // Nothing outside the work dir reached the host, whatever the sandbox saw.
    let wd = work_dir(&workspace, "th-w");
    assert!(
        wd.join("written.txt").is_file(),
        "work dir write must land on the host"
    );
    assert!(!workspace.dir().join("escape.txt").exists());
    assert!(!workspace.dir().join("threads/escape.txt").exists());
    let results = probes(&host, "t-w", "th-w").await;
    expect(
        &results,
        &[
            ("W_WORKDIR", "ok"),
            ("W_CWD", "ok"),
            ("W_TMP", "ok"),
            ("W_WS", "denied"),
            ("W_THREADS", "denied"),
            ("W_USR", "denied"),
            ("W_ETC", "denied"),
            ("W_ROOT", "denied"),
            ("W_AGENT", "denied"),
            ("W_ENGINE_BIN", "denied"),
        ],
    );

    runner.shutdown().await;
}

// ---------------------------------------------------------------------------
// Process isolation and privileges
// ---------------------------------------------------------------------------

const PROC_PROBE: &str = r#"
value UID 'id -u'
value GID 'id -g'
value CAPEFF 'grep "^CapEff:" /proc/self/status | cut -f2'
value CAPPRM 'grep "^CapPrm:" /proc/self/status | cut -f2'
value NNP 'grep "^NoNewPrivs:" /proc/self/status | cut -f2'
value PID1 'cat /proc/1/comm'
value PIDS 'ls /proc | grep -E "^[0-9]+$" | sort -n | tr "\n" ","'
value DAEMONS 'for p in /proc/[0-9]*; do tr "\0" " " < "$p/cmdline"; echo; done 2>/dev/null | grep -c " run *$"'
value SANDBOX 'echo "$GINO_SANDBOX"'
"#;

#[tokio::test]
#[ignore = "needs bubblewrap and user namespaces; run scripts/sandbox-it.sh"]
async fn sandboxed_engine_sees_only_its_own_processes_without_privileges() {
    if !enabled() {
        return;
    }
    let host = StubHost::start(sandbox_config("none", json!({}))).await;
    let workspace = Workspace::new().await;
    let fakes = claude_fakes(PROC_PROBE);
    let runner = RunnerProc::spawn_in_with_fakes(&host, &workspace, fakes, None);
    assert!(
        host.wait_connected(RUN_TIMEOUT).await,
        "runner never connected"
    );

    let run = run_thread(&host, "t-p", "th-p", 1).await;
    assert_eq!(run.status, "succeeded", "run: {run:?}");
    let results = probes(&host, "t-p", "th-p").await;
    expect(
        &results,
        &[
            ("UID", "1000"),
            ("GID", "1000"),
            ("CAPEFF", "0000000000000000"),
            ("CAPPRM", "0000000000000000"),
            ("NNP", "1"),
            ("PID1", "gino-agent"),
            ("DAEMONS", "0"),
            ("SANDBOX", "1"),
        ],
    );
    // A fresh pid namespace: only sandbox-init, the engine and its probes.
    let pids: Vec<u32> = results["PIDS"]
        .split(',')
        .filter(|p| !p.is_empty())
        .map(|p| p.parse().unwrap())
        .collect();
    assert!(
        pids.first() == Some(&1) && pids.len() < 16 && pids.iter().all(|p| *p < 200),
        "unexpected sandbox pids: {pids:?}"
    );

    runner.shutdown().await;
}

// ---------------------------------------------------------------------------
// Network modes
// ---------------------------------------------------------------------------

/// Loopback TCP and UDP round trips inside the sandbox.
const LOOPBACK_PROBE: &str = r#"
cat > /tmp/lo.pl <<'PL'
use strict;
use IO::Socket::INET;
my $proto = shift;
if ($proto eq 'tcp') {
  my $l = IO::Socket::INET->new(Listen => 1, LocalAddr => '127.0.0.1', LocalPort => 0, Proto => 'tcp') or die "listen: $!";
  my $c = IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => $l->sockport, Proto => 'tcp') or die "connect: $!";
  my $s = $l->accept or die "accept: $!";
  print $c "ping\n";
  my $r = <$s>;
  exit($r eq "ping\n" ? 0 : 1);
}
my $a = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0, Proto => 'udp') or die "bind: $!";
my $b = IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => $a->sockport, Proto => 'udp') or die "connect: $!";
$b->send("ping") or die "send: $!";
my $r;
$a->recv($r, 16);
exit($r eq "ping" ? 0 : 1);
PL
check LO_TCP 'timeout 5 perl /tmp/lo.pl tcp'
check LO_UDP 'timeout 5 perl /tmp/lo.pl udp'
"#;

const NET_PROBE: &str = r#"
check STUB_HOST 'timeout 5 bash -c "exec 3<>/dev/tcp/127.0.0.1/@STUB_PORT@"'
check EXTERNAL 'timeout 5 bash -c "exec 3<>/dev/tcp/@EXT_IP@/@EXT_PORT@"'
value LINKS 'tail -n +3 /proc/net/dev | cut -d: -f1 | tr -d " " | sort | tr "\n" ","'
"#;

/// Run the network probe under `network` mode and return its results.
async fn network_probe(network: &str) -> HashMap<String, String> {
    let host = StubHost::start(sandbox_config(network, json!({}))).await;
    let external = TcpListener::bind("0.0.0.0:0").unwrap();
    let body = format!("{LOOPBACK_PROBE}{NET_PROBE}")
        .replace("@STUB_PORT@", &host.addr.port().to_string())
        .replace("@EXT_IP@", &non_loopback_ip().to_string())
        .replace(
            "@EXT_PORT@",
            &external.local_addr().unwrap().port().to_string(),
        );
    let workspace = Workspace::new().await;
    let fakes = claude_fakes(&body);
    let runner = RunnerProc::spawn_in_with_fakes(&host, &workspace, fakes, None);
    assert!(
        host.wait_connected(RUN_TIMEOUT).await,
        "runner never connected"
    );

    let run = run_thread(&host, "t-n", "th-n", 1).await;
    assert_eq!(run.status, "succeeded", "run: {run:?}");
    let results = probes(&host, "t-n", "th-n").await;
    runner.shutdown().await;
    results
}

#[tokio::test]
#[ignore = "needs bubblewrap and user namespaces; run scripts/sandbox-it.sh"]
async fn network_none_keeps_loopback_and_blocks_everything_else() {
    if !enabled() {
        return;
    }
    let results = network_probe("none").await;
    expect(
        &results,
        &[
            ("LO_TCP", "ok"),
            ("LO_UDP", "ok"),
            ("STUB_HOST", "denied"),
            ("EXTERNAL", "denied"),
            ("LINKS", "lo,"),
        ],
    );
}

#[tokio::test]
#[ignore = "needs bubblewrap and user namespaces; run scripts/sandbox-it.sh"]
async fn network_full_reaches_the_host() {
    if !enabled() {
        return;
    }
    let results = network_probe("full").await;
    expect(
        &results,
        &[
            ("LO_TCP", "ok"),
            ("LO_UDP", "ok"),
            ("STUB_HOST", "ok"),
            ("EXTERNAL", "ok"),
        ],
    );
}

// ---------------------------------------------------------------------------
// Allowlist network: the loopback LLM endpoint through the gateway, nothing else
// ---------------------------------------------------------------------------

const ALLOWLIST_PROBE: &str = r#"
u="${ANTHROPIC_BASE_URL#*://}"
hp="${u%%/*}"
h="${hp%:*}"
p="${hp##*:}"
value LLM_HOST 'echo "$h"'
value LLM_PATH 'echo "/${u#*/}"'
check LLM 'exec 3<>"/dev/tcp/$h/$p"; printf "ping\n" >&3; read -t 5 -r r <&3; test "$r" = pong'
check LLM_DIRECT 'timeout 5 bash -c "exec 3<>/dev/tcp/127.0.0.1/$p"'
check GATEWAY_OTHER 'timeout 5 bash -c "exec 3<>/dev/tcp/10.0.2.2/@OTHER_PORT@"'
check ALLOWED_NAME 'getent hosts allowed.test'
check DISALLOWED_NAME 'getent hosts example.com'
check DISALLOWED_CONNECT 'timeout 5 bash -c "exec 3<>/dev/tcp/example.com/80"'
check EXTERNAL 'timeout 5 bash -c "exec 3<>/dev/tcp/@EXT_IP@/@EXT_PORT@"'
value RESOLV 'cat /etc/resolv.conf'
value LINKS 'tail -n +3 /proc/net/dev | cut -d: -f1 | tr -d " " | sort | tr "\n" ","'
value CAPEFF 'grep "^CapEff:" /proc/self/status | cut -f2'
"#;

/// A loopback TCP server answering each `ping` line with `pong`.
fn llm_stub() -> u16 {
    use std::io::{BufRead, BufReader, Write};
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
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

#[tokio::test]
#[ignore = "needs bubblewrap, user namespaces and /dev/net/tun; run scripts/sandbox-it.sh"]
async fn allowlist_reaches_the_loopback_llm_endpoint_and_nothing_else() {
    if !enabled() {
        return;
    }
    let llm_port = llm_stub();
    let mut config = sandbox_config("allowlist", json!({}));
    config["engine"]["anthropicBaseUrl"] = json!(format!("http://127.0.0.1:{llm_port}/api/llm"));
    config["engine"]["isolation"]["network"]["allow"] =
        json!([{ "host": "allowed.test", "ports": [443] }]);
    let host = StubHost::start(config).await;
    let external = TcpListener::bind("0.0.0.0:0").unwrap();
    let body = ALLOWLIST_PROBE
        .replace("@OTHER_PORT@", &host.addr.port().to_string())
        .replace("@EXT_IP@", &non_loopback_ip().to_string())
        .replace(
            "@EXT_PORT@",
            &external.local_addr().unwrap().port().to_string(),
        );
    let workspace = Workspace::new().await;
    let fakes = claude_fakes(&body);
    let runner = RunnerProc::spawn_in_with_fakes(&host, &workspace, fakes, None);
    assert!(
        host.wait_connected(RUN_TIMEOUT).await,
        "runner never connected"
    );

    let run = run_thread(&host, "t-al", "th-al", 1).await;
    assert_eq!(run.status, "succeeded", "run: {run:?}");
    let results = probes(&host, "t-al", "th-al").await;
    runner.shutdown().await;
    expect(
        &results,
        &[
            ("LLM_HOST", "10.0.2.2"),
            ("LLM_PATH", "/api/llm"),
            ("LLM", "ok"),
            ("LLM_DIRECT", "denied"),
            ("GATEWAY_OTHER", "denied"),
            ("ALLOWED_NAME", "ok"),
            ("DISALLOWED_NAME", "denied"),
            ("DISALLOWED_CONNECT", "denied"),
            ("EXTERNAL", "denied"),
            ("RESOLV", "nameserver 10.0.2.2"),
            ("CAPEFF", "0000000000000000"),
        ],
    );
    assert!(
        results["LINKS"].contains("gino0"),
        "links: {}",
        results["LINKS"]
    );
}

// ---------------------------------------------------------------------------
// Allowlist rules from the local isolation file
// ---------------------------------------------------------------------------

/// Fixed port of the SSH-style banner server (a non-HTTP port).
const BANNER_PORT: u16 = 2222;

const RULES_PROBE: &str = r#"
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
value BANNER 'exec 3<>/dev/tcp/@IP@/@BANNER_PORT@; read -t 5 -r b <&3; printf "SSH-2.0-probe\r\n" >&3; read -t 5 -r a <&3; echo "$b $a"'
check TCP_OTHER_PORT 'timeout 5 bash -c "exec 3<>/dev/tcp/@IP@/@OTHER_TCP@"'
check UDP_ALLOWED 'timeout 5 perl /tmp/udp.pl @IP@ @UDP_PORT@'
check UDP_DENIED 'timeout 5 perl /tmp/udp.pl @IP@ @OTHER_UDP@'
value NX_RCODE 'timeout 5 perl /tmp/rcode.pl denied.example'
check OUTSIDE_CIDR 'timeout 5 bash -c "exec 3<>/dev/tcp/192.0.2.10/@BANNER_PORT@"'
"#;

/// A TCP server on `ip:port` that greets with an SSH-style banner and answers
/// the client's banner line with `ok`.
fn banner_server(ip: IpAddr, port: u16) {
    use std::io::{BufRead, BufReader, Write};
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

/// The `gino_agent::net` decision lines in the daemon log, ANSI styling removed.
fn decision_lines(log: &Path) -> Vec<String> {
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
        .filter(|l| l.contains("gino_agent::net") && l.contains("network decision"))
        .map(str::to_owned)
        .collect()
}

#[tokio::test]
#[ignore = "needs bubblewrap, user namespaces and /dev/net/tun; run scripts/sandbox-it.sh"]
async fn allowlist_rules_from_the_isolation_file_admit_only_matching_flows() {
    if !enabled() {
        return;
    }
    // Upstreams live on the container's private address, so only a covering
    // cidr rule admits them.
    let ip = non_loopback_ip();
    banner_server(ip, BANNER_PORT);
    let other_tcp = TcpListener::bind((ip, 0)).unwrap();
    let other_tcp_port = other_tcp.local_addr().unwrap().port();
    let udp_port = udp_echo(ip);
    let other_udp_port = udp_echo(ip);

    let dir = tempfile::Builder::new()
        .prefix("allowlist-it-")
        .tempdir()
        .unwrap();
    let cidr = format!("{ip}/32");
    let isolation = json!({
        "mode": "sandbox",
        "network": { "mode": "allowlist", "allow": [
            { "cidr": cidr, "ports": [BANNER_PORT] },
            { "cidr": cidr, "ports": [udp_port], "proto": "udp" },
        ] },
    });
    let file = dir.path().join("isolation.json");
    std::fs::write(&file, isolation.to_string()).unwrap();
    let log = dir.path().join("agent.log");

    let host = StubHost::start(json!({})).await;
    let body = format!("{LOOPBACK_PROBE}{RULES_PROBE}")
        .replace("@IP@", &ip.to_string())
        .replace("@BANNER_PORT@", &BANNER_PORT.to_string())
        .replace("@OTHER_TCP@", &other_tcp_port.to_string())
        .replace("@UDP_PORT@", &udp_port.to_string())
        .replace("@OTHER_UDP@", &other_udp_port.to_string());
    let workspace = Workspace::new().await;
    let fakes = claude_fakes(&body);
    let runner = RunnerProc::spawn_in_with_env(
        &host,
        &workspace,
        fakes,
        &[
            ("GINO_ISOLATION_FILE", file.as_os_str()),
            ("RUST_LOG", OsStr::new("gino_agent::net=info")),
        ],
        std::fs::File::create(&log).unwrap().into(),
    );
    assert!(
        host.wait_connected(RUN_TIMEOUT).await,
        "runner never connected"
    );

    let run = run_thread(&host, "t-rules", "th-rules", 1).await;
    assert_eq!(run.status, "succeeded", "run: {run:?}");
    let results = probes(&host, "t-rules", "th-rules").await;
    runner.shutdown().await;
    expect(
        &results,
        &[
            ("LO_TCP", "ok"),
            ("LO_UDP", "ok"),
            ("BANNER", "SSH-2.0-gino-it ok"),
            ("TCP_OTHER_PORT", "denied"),
            ("UDP_ALLOWED", "ok"),
            ("UDP_DENIED", "denied"),
            ("NX_RCODE", "3"),
            ("OUTSIDE_CIDR", "denied"),
        ],
    );

    let lines = decision_lines(&log);
    let logged = |proto: &str, port: u16, decision: &str| {
        lines.iter().any(|l| {
            l.contains("thread_id=\"th-rules\"")
                && l.contains(&format!("proto=\"{proto}\""))
                && l.contains(&format!("port={port} "))
                && l.contains(&format!("decision=\"{decision}\""))
        })
    };
    for (proto, port, decision) in [
        ("tcp", BANNER_PORT, "allow"),
        ("tcp", other_tcp_port, "deny"),
        ("udp", udp_port, "allow"),
        ("udp", other_udp_port, "deny"),
    ] {
        assert!(
            logged(proto, port, decision),
            "no {decision} line for {proto}/{port}: {lines:#?}"
        );
    }
    assert!(
        lines
            .iter()
            .any(|l| l.contains("target_ip=192.0.2.10") && l.contains("decision=\"deny\"")),
        "no deny line for the address outside every cidr: {lines:#?}"
    );
}

// ---------------------------------------------------------------------------
// SIGINT reaches a sandboxed codex through sandbox-init
// ---------------------------------------------------------------------------

/// A fake `codex` that announces its thread, signals readiness, then waits;
/// SIGINT is trapped and recorded in the work dir before exiting.
const HANGING_CODEX: &str = r#"#!/usr/bin/env bash
set -u
wd="$(dirname "$ENGINE_CONFIG_DIR")"
trap 'printf "sigint uid=%s sandbox=%s\n" "$(id -u)" "${GINO_SANDBOX:-}" > "$wd/sigint.marker"; exit 130' INT
cat > /dev/null
printf '%s\n' '{"type":"thread.started","thread_id":"codex-sandboxed"}'
printf '%s\n' '{"type":"turn.started"}'
echo ready > "$wd/ready.marker"
for _ in $(seq 1 300); do sleep 0.1; done
printf '%s\n' '{"type":"turn.completed"}'
"#;

#[tokio::test]
#[ignore = "needs bubblewrap and user namespaces; run scripts/sandbox-it.sh"]
async fn interrupt_reaches_the_sandboxed_codex_through_sandbox_init() {
    if !enabled() {
        return;
    }
    let host = StubHost::start(sandbox_config("none", json!({}))).await;
    let workspace = Workspace::new().await;
    let fakes = claude_fakes("");
    write_exe(fakes.path(), "codex", HANGING_CODEX);
    let runner = RunnerProc::spawn_in_with_fakes(&host, &workspace, fakes, None);
    assert!(
        host.wait_connected(RUN_TIMEOUT).await,
        "runner never connected"
    );

    host.push_task_upsert_with_engine("t-int", "codex", 1).await;
    host.push_message("t-int", Some("th-int"), "hang", &[], 2)
        .await;
    let wd = work_dir(&workspace, "th-int");
    assert!(
        wait_until(RUN_TIMEOUT, || wd.join("ready.marker").is_file()).await,
        "the sandboxed codex never started"
    );

    host.push_frame(&json!({ "type": "interrupt", "taskId": "t-int", "msgId": delivery_id(3) }))
        .await;
    let run = host
        .wait_thread_terminal("th-int", RUN_TIMEOUT)
        .await
        .expect("no terminal result after the interrupt");
    assert_eq!(run.status, "cancelled", "run: {run:?}");
    let marker =
        std::fs::read_to_string(wd.join("sigint.marker")).expect("the codex never saw SIGINT");
    assert_eq!(marker.trim(), "sigint uid=1000 sandbox=1");

    runner.shutdown().await;
}

// ---------------------------------------------------------------------------
// A missing bwrap fails closed
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs bubblewrap and user namespaces; run scripts/sandbox-it.sh"]
async fn missing_bwrap_fails_closed_without_running_the_engine() {
    if !enabled() {
        return;
    }
    let host = StubHost::start(sandbox_config("none", json!({}))).await;
    let workspace = Workspace::new().await;
    let fakes = fake_dir();
    let ran = fakes.path().join("ran");
    write_exe(
        fakes.path(),
        "claude",
        &claude_script(&format!("touch '{}'", ran.display())),
    );
    // Only the fakes dir is on PATH, so bwrap cannot be found.
    let path = fakes.path().display().to_string();
    let runner = RunnerProc::spawn_in_with_fakes(&host, &workspace, fakes, Some(&path));
    assert!(
        host.wait_connected(RUN_TIMEOUT).await,
        "runner never connected"
    );

    let run = run_thread(&host, "t-nobwrap", "th-nobwrap", 1).await;
    assert_eq!(run.status, "failed", "run: {run:?}");
    let error = run.error.clone().unwrap_or_default();
    assert!(
        error.contains("engine sandbox is unavailable"),
        "error: {error}"
    );
    assert_eq!(
        run.failure_reason.as_deref(),
        Some("runner.invalid_request")
    );
    assert!(
        !ran.exists(),
        "the engine must never run without its sandbox"
    );
    assert!(
        !work_dir(&workspace, "th-nobwrap")
            .join("engine-ran")
            .exists()
    );

    runner.shutdown().await;
}

// ---------------------------------------------------------------------------
// The local agent API inside the sandbox
// ---------------------------------------------------------------------------

const API_PROBE: &str = r#"
value SOCK 'echo "$GINO_AGENT_SOCK"'
value CRON_ID '"$GINO_RUNNER_BIN" cron create --type interval --value 3600000 --prompt p'
check CRON_LIST_OK '"$GINO_RUNNER_BIN" cron list'
value CRON_LIST '"$GINO_RUNNER_BIN" cron list | cut -f1'
check TASK_LIST_OK '"$GINO_RUNNER_BIN" task list'
value TASK_LIST '"$GINO_RUNNER_BIN" task list | cut -f1'
check READ_DB 'cat "@DB@"'
"#;

#[tokio::test]
#[ignore = "needs bubblewrap and user namespaces; run scripts/sandbox-it.sh"]
async fn sandboxed_engine_manages_its_own_crons_through_the_agent_api() {
    if !enabled() {
        return;
    }
    let host = StubHost::start(sandbox_config("none", json!({}))).await;
    let workspace = Workspace::new().await;
    let fakes = claude_fakes(&render(API_PROBE, &workspace));
    let runner = RunnerProc::spawn_in_with_fakes(&host, &workspace, fakes, None);
    assert!(
        host.wait_connected(RUN_TIMEOUT).await,
        "runner never connected"
    );

    host.push_task_upsert("t-other", Some("other"), Some("chat"), None, 1)
        .await;
    host.push_task_upsert("t-api", Some("mine"), Some("chat"), None, 2)
        .await;
    let run = run_thread(&host, "t-api", "th-api", 3).await;
    assert_eq!(run.status, "succeeded", "run: {run:?}");
    let results = probes(&host, "t-api", "th-api").await;
    let cron_id = results["CRON_ID"].clone();
    let uuid = cron_id
        .strip_prefix("cron-")
        .unwrap_or_else(|| panic!("cron create: {results:#?}"));
    uuid::Uuid::parse_str(uuid).unwrap_or_else(|_| panic!("cron create: {results:#?}"));
    expect(
        &results,
        &[
            ("SOCK", "/run/gino/agent.sock"),
            ("CRON_LIST_OK", "ok"),
            ("CRON_LIST", &cron_id),
            ("TASK_LIST_OK", "ok"),
            ("TASK_LIST", "t-api"),
            ("READ_DB", "denied"),
        ],
    );

    runner.shutdown().await;
}

const ACTION_PROBE: &str = r#"
value SEQ '"$GINO_RUNNER_BIN" action comment "{\"body\":\"$GINO_THREAD_ID\"}"'
"#;

#[tokio::test]
#[ignore = "needs bubblewrap and user namespaces; run scripts/sandbox-it.sh"]
async fn sandboxed_engine_records_a_host_action_on_its_own_thread() {
    if !enabled() {
        return;
    }
    let host = StubHost::start(sandbox_config("none", json!({}))).await;
    let workspace = Workspace::new().await;
    let fakes = claude_fakes(ACTION_PROBE);
    let runner = RunnerProc::spawn_in_with_fakes(&host, &workspace, fakes, None);
    assert!(
        host.wait_connected(RUN_TIMEOUT).await,
        "runner never connected"
    );

    host.push_task_upsert("t-other", Some("other"), Some("chat"), None, 1)
        .await;
    host.push_task_upsert("t-act", Some("mine"), Some("chat"), None, 2)
        .await;
    for (task, thread, msg_id) in [("t-other", "th-other", 3), ("t-act", "th-act", 4)] {
        let run = run_thread(&host, task, thread, msg_id).await;
        assert_eq!(run.status, "succeeded", "{thread}: {run:?}");
    }
    for (task, thread) in [("t-other", "th-other"), ("t-act", "th-act")] {
        let results = probes(&host, task, thread).await;
        let actions: Vec<_> = host
            .messages_for(task, thread)
            .await
            .into_iter()
            .filter(|m| m.kind == "host_action")
            .collect();
        assert_eq!(actions.len(), 1, "{thread}: {actions:?} {results:#?}");
        assert_eq!(
            results.get("SEQ"),
            Some(&actions[0].seq.to_string()),
            "{thread}: {results:#?}"
        );
        assert_eq!(
            actions[0].input,
            Some(json!({ "method": "comment", "params": { "body": thread } })),
            "{thread}"
        );
    }

    runner.shutdown().await;
}

// ---------------------------------------------------------------------------
// Task meta.isolation overrides
// ---------------------------------------------------------------------------

const META_PROBE: &str = r#"
value SANDBOX 'echo "${GINO_SANDBOX:-unset}"'
value UID 'id -u'
check READ_DB 'cat "@DB@"'
value CLI '"$GINO_RUNNER_BIN" system'
printf '%s\n' '{"type":"user","message":{"role":"user","content":"archive me"}}' \
  '{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"archived"}]}}' \
  > "$wd/transcript.jsonl"
check ARCHIVE 'printf "{\"transcript_path\":\"%s\",\"session_id\":\"s-arch\"}" "$wd/transcript.jsonl" | "$GINO_RUNNER_BIN" archive'
"#;

#[tokio::test]
#[ignore = "needs bubblewrap and user namespaces; run scripts/sandbox-it.sh"]
async fn task_meta_isolation_overrides_the_default() {
    if !enabled() {
        return;
    }
    // Isolation is off in the agent config; only the task meta turns it on
    // (tightening is always allowed).
    let host = StubHost::start(json!({})).await;
    let workspace = Workspace::new().await;
    let fakes = claude_fakes(&render(META_PROBE, &workspace));
    let runner = RunnerProc::spawn_in_with_fakes(&host, &workspace, fakes, None);
    assert!(
        host.wait_connected(RUN_TIMEOUT).await,
        "runner never connected"
    );

    push_task_meta(
        &host,
        "t-sb",
        &json!({ "isolation": { "mode": "sandbox" } }),
        1,
    )
    .await;
    push_task_meta(&host, "t-vm", &json!({ "isolation": { "mode": "vm" } }), 2).await;
    push_task_meta(
        &host,
        "t-jail",
        &json!({ "isolation": { "mode": "jail" } }),
        3,
    )
    .await;
    push_task_meta(&host, "t-bogus", &json!({ "isolation": "bogus" }), 4).await;
    push_task_meta(&host, "t-off", &json!({ "team": "infra" }), 5).await;

    // Sandboxed by the override.
    let run = run_thread(&host, "t-sb", "th-sb", 6).await;
    assert_eq!(run.status, "succeeded", "run: {run:?}");
    let results = probes(&host, "t-sb", "th-sb").await;
    expect(
        &results,
        &[
            ("SANDBOX", "1"),
            ("UID", "1000"),
            ("READ_DB", "denied"),
            ("ARCHIVE", "ok"),
        ],
    );
    assert!(
        results["CLI"].contains("workspace_dir : (not available to this run)"),
        "in-sandbox CLI: {}",
        results["CLI"]
    );
    let conversations = work_dir(&workspace, "th-sb").join("conversations");
    assert!(
        conversations.join("sessions-index.json").is_file(),
        "the archive must land in the work dir's conversations/"
    );

    // Invalid or unsupported overrides fail before any engine spawn.
    for (task, thread, msg, needle) in [
        ("t-vm", "th-vm", 7, "vm mode needs engine.isolation.vm"),
        ("t-jail", "th-jail", 8, "unknown isolation mode `jail`"),
        ("t-bogus", "th-bogus", 9, "invalid isolation in task meta"),
    ] {
        let run = run_thread(&host, task, thread, msg).await;
        assert_eq!(run.status, "failed", "{task}: {run:?}");
        let error = run.error.clone().unwrap_or_default();
        assert!(error.contains(needle), "{task} error: {error}");
        assert!(
            !work_dir(&workspace, thread).join("engine-ran").exists(),
            "{task}: the engine must not run"
        );
    }

    // Without an isolation override the engine runs directly, as before.
    let run = run_thread(&host, "t-off", "th-off", 10).await;
    assert_eq!(run.status, "succeeded", "run: {run:?}");
    let results = probes(&host, "t-off", "th-off").await;
    expect(&results, &[("SANDBOX", "unset"), ("READ_DB", "ok")]);
    assert!(work_dir(&workspace, "th-off").join("engine-ran").is_file());

    runner.shutdown().await;
    // Release the workspace's serial lock before taking a new one.
    drop(workspace);
    drop(host);

    // With a sandboxed default, an override that turns isolation off fails.
    let host = StubHost::start(sandbox_config("none", json!({}))).await;
    let workspace = Workspace::new().await;
    let fakes = claude_fakes(&render(META_PROBE, &workspace));
    let runner = RunnerProc::spawn_in_with_fakes(&host, &workspace, fakes, None);
    assert!(
        host.wait_connected(RUN_TIMEOUT).await,
        "runner never connected"
    );
    push_task_meta(
        &host,
        "t-loose",
        &json!({ "isolation": { "mode": "off" } }),
        1,
    )
    .await;
    let run = run_thread(&host, "t-loose", "th-loose", 2).await;
    assert_eq!(run.status, "failed", "run: {run:?}");
    let error = run.error.clone().unwrap_or_default();
    assert!(
        error.contains("would loosen isolation.mode from `sandbox` to `off`")
            && error.contains("allowTaskOverride"),
        "error: {error}"
    );
    assert_eq!(
        run.failure_reason.as_deref(),
        Some("runner.invalid_request")
    );
    assert!(
        !work_dir(&workspace, "th-loose").join("engine-ran").exists(),
        "the engine must not run"
    );

    runner.shutdown().await;
}

// ---------------------------------------------------------------------------
// Task-scope provisioning entries
// ---------------------------------------------------------------------------

const TASK_ENTRY_PROBE: &str = r#"
value TASK_FILE 'cat "$wd/project/TASK.md"'
value TASK_SKILL 'cat "$wd/project/skills/task-demo/SKILL.md"'
check TASK_FILE_WRITE 'echo x >> "$wd/project/TASK.md"'
check TASK_SKILL_WRITE 'touch "$wd/project/skills/task-demo/new"'
"#;

#[tokio::test]
#[ignore = "needs bubblewrap and user namespaces; run scripts/sandbox-it.sh"]
async fn task_scope_entries_are_readable_in_the_sandbox() {
    if !enabled() {
        return;
    }
    let host = StubHost::start(json!({})).await;
    let workspace = Workspace::new().await;
    let fakes = claude_fakes(&render(TASK_ENTRY_PROBE, &workspace));
    let runner = RunnerProc::spawn_in_with_fakes(&host, &workspace, fakes, None);
    assert!(
        host.wait_connected(RUN_TIMEOUT).await,
        "runner never connected"
    );

    let task_md = b"task instructions\n";
    let skill_tar = build_tar(&[("SKILL.md", b"task skill\n")]);
    let file = host
        .stage_provisioning_entry("task-md", "TASK.md", "file", task_md)
        .await;
    let dir = host
        .stage_provisioning_entry("task-skill", "skills/task-demo", "dir", &skill_tar)
        .await;
    host.push_frame(&json!({
        "type": "task_upsert",
        "taskId": "t-entries",
        "data": {
            "status": "active",
            "meta": { "isolation": { "mode": "sandbox" } },
            "entries": [file, dir],
        },
        "msgId": delivery_id(1),
    }))
    .await;

    let run = run_thread(&host, "t-entries", "th-entries", 2).await;
    assert_eq!(run.status, "succeeded", "run: {run:?}");
    let project = work_dir(&workspace, "th-entries").join("project");
    assert!(
        project.join("TASK.md").is_symlink(),
        "the task entry must be materialized as a store symlink"
    );
    let results = probes(&host, "t-entries", "th-entries").await;
    expect(
        &results,
        &[
            ("TASK_FILE", "task instructions"),
            ("TASK_SKILL", "task skill"),
            ("TASK_FILE_WRITE", "denied"),
            ("TASK_SKILL_WRITE", "denied"),
        ],
    );

    runner.shutdown().await;
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
/// The claude auto memory dir inside the sandbox.
const ENGINE_AUTO_MEMORY: &str = "/run/gino/memory/task/claude";

/// Probe prelude of the memory scenarios: reads the engine's `--settings`
/// JSON into `AUTO_MEMORY_DIR` and reports its auto memory keys, the auto
/// memory env switch, and whether any argv element names the host workspace.
const SETTINGS_PROBE: &str = r#"
settings=; prev=; host_arg=none
for a in "$@"; do
  [ "$prev" = --settings ] && settings="$a"
  case "$a" in *"@WS@"*) host_arg=found ;; esac
  prev="$a"
done
AUTO_MEMORY_DIR="$(printf '%s' "$settings" | sed -n 's/.*"autoMemoryDirectory":"\([^"]*\)".*/\1/p')"
value AUTO_DIR 'echo "$AUTO_MEMORY_DIR"'
value AUTO_ENABLED 'printf %s "$settings" | sed -n "s/.*\"autoMemoryEnabled\":\([a-z]*\).*/\1/p"'
value AUTO_DISABLE_ENV 'echo "${CLAUDE_CODE_DISABLE_AUTO_MEMORY-unset}"'
value HOST_ARG 'echo "$host_arg"'
"#;

/// Boot a sandboxed runner with the agent-local `envs` and a probing `claude`
/// running [`SETTINGS_PROBE`] then `body` (with `@WS@` rendered).
async fn memory_runner(envs: &[(&str, &OsStr)], body: &str) -> (StubHost, Workspace, RunnerProc) {
    let host = StubHost::start(sandbox_config("none", json!({}))).await;
    let workspace = Workspace::new().await;
    let fakes = claude_fakes(&render(&format!("{SETTINGS_PROBE}{body}"), &workspace));
    let runner =
        RunnerProc::spawn_in_with_env(&host, &workspace, fakes, envs, std::process::Stdio::null());
    assert!(
        host.wait_connected(RUN_TIMEOUT).await,
        "runner never connected"
    );
    (host, workspace, runner)
}

/// Run each `(task, thread)` in order, all expected to succeed, starting at
/// delivery id `msg_id`.
async fn run_threads(host: &StubHost, runs: &[(&str, &str)], msg_id: i64) {
    for (msg_id, (task, thread)) in (msg_id..).zip(runs) {
        let run = run_thread(host, task, thread, msg_id).await;
        assert_eq!(run.status, "succeeded", "{thread}: {run:?}");
    }
}

/// A host task memory dir.
fn task_memory(workspace: &Workspace, task_id: &str) -> PathBuf {
    workspace.dir().join("memory/task").join(task_id)
}

/// Every `memory` dir and `MEMORY.md` below `dir`, symlinks not followed.
fn auto_memory_paths(dir: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let is_dir = entry.file_type().is_ok_and(|t| t.is_dir());
        let name = entry.file_name();
        if (is_dir && name == "memory") || name == "MEMORY.md" {
            found.push(path.clone());
        }
        if is_dir {
            auto_memory_paths(&path, found);
        }
    }
}

/// Assert the workspace holds no claude auto memory outside its memory trees
/// (engine homes and the engine config dir included).
fn expect_no_auto_memory(workspace: &Workspace) {
    let mut found = Vec::new();
    auto_memory_paths(workspace.dir(), &mut found);
    found.retain(|p| !p.starts_with(workspace.dir().join("memory")));
    assert!(
        found.is_empty(),
        "auto memory outside the memory trees: {found:#?}"
    );
}

const TASK_MEMORY_PROBE: &str = r#"
value MEM_DIR 'echo "${GINO_MEMORY_DIR-unset}"'
value AGENT_DIR 'echo "${GINO_AGENT_MEMORY_DIR-unset}"'
case "$GINO_THREAD_ID" in
th-a1)
  check CLAUDE_WRITE 'echo "- [claude fact](fact.md)" > "$AUTO_MEMORY_DIR/MEMORY.md" && echo claude-fact-5d1e > "$AUTO_MEMORY_DIR/fact.md"'
  check TASK_WRITE 'echo "- task-fact-7f3a" >> "$GINO_MEMORY_DIR/index.md" && echo task-fact-7f3a > "$GINO_MEMORY_DIR/fact.md"'
  check AGENT_WRITE 'echo agent-fact-91c2 > "$GINO_AGENT_MEMORY_DIR/fact.md"'
  ;;
th-a2)
  value TASK_READ 'cat "$GINO_MEMORY_DIR/fact.md"'
  value CLAUDE_INDEX 'cat "$AUTO_MEMORY_DIR/MEMORY.md"'
  value CLAUDE_READ 'cat "$AUTO_MEMORY_DIR/fact.md"'
  check CTX_SECTION '"$GINO_RUNNER_BIN" memory-context | grep -q "^## Task memory"'
  check CTX_FACT '"$GINO_RUNNER_BIN" memory-context | grep -q task-fact-7f3a'
  ;;
th-b1)
  value TASK_LS 'ls "$GINO_MEMORY_DIR"'
  check TASK_FACT_SEEN 'grep -rq task-fact-7f3a "$GINO_MEMORY_DIR"'
  value CLAUDE_LS 'ls -A "$AUTO_MEMORY_DIR"'
  check CLAUDE_FACT_SEEN 'grep -rq claude-fact-5d1e "$AUTO_MEMORY_DIR"'
  check OTHER_CLAUDE_LIST 'ls "@WS@/memory/task/t-a/claude"'
  check OTHER_CLAUDE_READ 'cat "@WS@/memory/task/t-a/claude/MEMORY.md"'
  check CTX_SECTION '"$GINO_RUNNER_BIN" memory-context | grep -q "^## Task memory"'
  check CTX_FACT '"$GINO_RUNNER_BIN" memory-context | grep -q task-fact-7f3a'
  check WS_MEMORY 'test -e "@WS@/memory"'
  check OTHER_LIST 'ls "@WS@/memory/task/t-a"'
  check OTHER_READ 'cat "@WS@/memory/task/t-a/fact.md"'
  check OTHER_WRITE 'echo x > "@WS@/memory/task/t-a/fact.md"'
  check OTHER_CREATE 'echo x > "@WS@/memory/task/t-a/planted.md"'
  value AGENT_READ 'cat "$GINO_AGENT_MEMORY_DIR/fact.md"'
  ;;
esac
"#;

#[tokio::test]
#[ignore = "needs bubblewrap and user namespaces; run scripts/sandbox-it.sh"]
async fn task_memory_persists_per_task_and_agent_memory_is_shared() {
    if !enabled() {
        return;
    }
    let (host, workspace, runner) = memory_runner(&[], TASK_MEMORY_PROBE).await;
    run_threads(
        &host,
        &[("t-a", "th-a1"), ("t-a", "th-a2"), ("t-b", "th-b1")],
        1,
    )
    .await;

    let a1 = probes(&host, "t-a", "th-a1").await;
    expect(
        &a1,
        &[
            ("MEM_DIR", "/run/gino/memory/task"),
            ("AGENT_DIR", "/run/gino/memory/agent"),
            ("AUTO_DIR", ENGINE_AUTO_MEMORY),
            ("AUTO_ENABLED", ""),
            ("AUTO_DISABLE_ENV", "unset"),
            ("HOST_ARG", "none"),
            ("CLAUDE_WRITE", "ok"),
            ("TASK_WRITE", "ok"),
            ("AGENT_WRITE", "ok"),
        ],
    );
    let a2 = probes(&host, "t-a", "th-a2").await;
    expect(
        &a2,
        &[
            ("TASK_READ", TASK_FACT),
            ("AUTO_DIR", ENGINE_AUTO_MEMORY),
            ("CLAUDE_INDEX", "- claude fact(fact.md)"),
            ("CLAUDE_READ", CLAUDE_FACT),
            ("CTX_SECTION", "ok"),
            ("CTX_FACT", "ok"),
        ],
    );
    // Task B gets its own fresh tree at the same path; A's is not in its view.
    let b1 = probes(&host, "t-b", "th-b1").await;
    expect(
        &b1,
        &[
            ("MEM_DIR", "/run/gino/memory/task"),
            ("TASK_LS", "claude index.md system"),
            ("TASK_FACT_SEEN", "denied"),
            ("AUTO_DIR", ENGINE_AUTO_MEMORY),
            ("HOST_ARG", "none"),
            ("CLAUDE_LS", ""),
            ("CLAUDE_FACT_SEEN", "denied"),
            ("OTHER_CLAUDE_LIST", "denied"),
            ("OTHER_CLAUDE_READ", "denied"),
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

    let a = task_memory(&workspace, "t-a");
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
    assert!(a.join("claude/MEMORY.md").is_file());
    let b = task_memory(&workspace, "t-b");
    assert!(b.join("index.md").is_file());
    assert!(!b.join("fact.md").exists());
    assert!(!b.join("claude/MEMORY.md").exists());
    expect_no_auto_memory(&workspace);
    assert_eq!(
        std::fs::read_to_string(workspace.dir().join("memory/agent/fact.md"))
            .unwrap()
            .trim(),
        AGENT_FACT
    );

    runner.shutdown().await;
}

const AGENT_RO_PROBE: &str = r#"
werr() { perl -e 'open(my $f, ">>", $ARGV[0]) and print("ok"), exit 0; print($!{EROFS} ? "EROFS" : $!{EACCES} ? "EACCES" : "other $!")' "$1"; }
value AGENT_READ 'head -n 1 "$GINO_AGENT_MEMORY_DIR/index.md"'
value AGENT_WRITE 'werr "$GINO_AGENT_MEMORY_DIR/fact-$GINO_TASK_ID.md"'
value TASK_WRITE 'werr "$GINO_MEMORY_DIR/fact.md"'
"#;

/// Assert an agent memory write was refused by a read-only mount.
fn expect_refused(results: &HashMap<String, String>) {
    let write = results.get("AGENT_WRITE").map(String::as_str);
    assert!(
        matches!(write, Some("EROFS" | "EACCES")),
        "agent write: {results:#?}"
    );
}

#[tokio::test]
#[ignore = "needs bubblewrap and user namespaces; run scripts/sandbox-it.sh"]
async fn agent_memory_read_only_refuses_writes_and_keeps_reads() {
    if !enabled() {
        return;
    }
    // Read-only for the whole runner.
    {
        let (host, workspace, runner) = memory_runner(
            &[("GINO_AGENT_MEMORY_ACCESS", OsStr::new("ro"))],
            AGENT_RO_PROBE,
        )
        .await;
        run_threads(&host, &[("t-ro", "th-ro")], 1).await;
        let results = probes(&host, "t-ro", "th-ro").await;
        expect_refused(&results);
        expect(&results, &[("TASK_WRITE", "ok")]);
        assert!(!results["AGENT_READ"].is_empty(), "{results:#?}");
        let agent = workspace.dir().join("memory/agent");
        assert!(agent.join("index.md").is_file());
        assert!(!agent.join("fact-t-ro.md").exists());
        runner.shutdown().await;
    }

    // Read-only for one task through its meta; another task still writes.
    let (host, workspace, runner) = memory_runner(&[], AGENT_RO_PROBE).await;
    push_task_meta(
        &host,
        "t-meta-ro",
        &json!({ "memory": { "agent": "ro" } }),
        1,
    )
    .await;
    run_threads(&host, &[("t-meta-ro", "th-meta-ro"), ("t-rw", "th-rw")], 2).await;
    let ro = probes(&host, "t-meta-ro", "th-meta-ro").await;
    expect_refused(&ro);
    expect(&ro, &[("TASK_WRITE", "ok")]);
    assert!(!ro["AGENT_READ"].is_empty(), "{ro:#?}");
    let rw = probes(&host, "t-rw", "th-rw").await;
    expect(&rw, &[("AGENT_WRITE", "ok"), ("TASK_WRITE", "ok")]);
    let agent = workspace.dir().join("memory/agent");
    assert!(!agent.join("fact-t-meta-ro.md").exists());
    assert!(agent.join("fact-t-rw.md").is_file());

    runner.shutdown().await;
}

const MEMORY_SWITCH_PROBE: &str = r#"
value MEM_ENV 'echo "${GINO_MEMORY_DIR-unset}"'
value AGENT_ENV 'echo "${GINO_AGENT_MEMORY_DIR-unset}"'
value CONV_ENV 'echo "${GINO_CONVERSATIONS_DIR-unset}"'
check TASK_MOUNT 'test -e /run/gino/memory/task'
check AGENT_MOUNT 'test -e /run/gino/memory/agent'
check CONV_MOUNT 'test -e /run/gino/conversations'
check MEMORY_ROOT 'test -e /run/gino/memory'
"#;

/// The switch probe of a run with task memory on (and its view mounted).
const TASK_ON: [(&str, &str); 8] = [
    ("MEM_ENV", "/run/gino/memory/task"),
    ("CONV_ENV", "/run/gino/conversations"),
    ("TASK_MOUNT", "ok"),
    ("CONV_MOUNT", "ok"),
    ("AUTO_DIR", ENGINE_AUTO_MEMORY),
    ("AUTO_ENABLED", ""),
    ("AUTO_DISABLE_ENV", "unset"),
    ("HOST_ARG", "none"),
];
/// The switch probe of a run with task memory off (claude auto memory off).
const TASK_OFF: [(&str, &str); 8] = [
    ("MEM_ENV", "unset"),
    ("CONV_ENV", "unset"),
    ("TASK_MOUNT", "denied"),
    ("CONV_MOUNT", "denied"),
    ("AUTO_DIR", ""),
    ("AUTO_ENABLED", "false"),
    ("AUTO_DISABLE_ENV", "1"),
    ("HOST_ARG", "none"),
];
/// The switch probe of a run with agent memory on.
const AGENT_ON: [(&str, &str); 2] = [
    ("AGENT_ENV", "/run/gino/memory/agent"),
    ("AGENT_MOUNT", "ok"),
];
/// The switch probe of a run with agent memory off.
const AGENT_OFF: [(&str, &str); 2] = [("AGENT_ENV", "unset"), ("AGENT_MOUNT", "denied")];

#[tokio::test]
#[ignore = "needs bubblewrap and user namespaces; run scripts/sandbox-it.sh"]
async fn memory_switches_drop_the_mounts_and_env() {
    if !enabled() {
        return;
    }
    // Agent memory off for the runner.
    {
        let (host, _workspace, runner) = memory_runner(
            &[("GINO_AGENT_MEMORY_ACCESS", OsStr::new("off"))],
            MEMORY_SWITCH_PROBE,
        )
        .await;
        run_threads(&host, &[("t-agent-off", "th-agent-off")], 1).await;
        let results = probes(&host, "t-agent-off", "th-agent-off").await;
        expect(&results, &AGENT_OFF);
        expect(&results, &TASK_ON);
        runner.shutdown().await;
    }

    // Task memory off for the runner.
    {
        let (host, workspace, runner) = memory_runner(
            &[("GINO_TASK_MEMORY", OsStr::new("off"))],
            MEMORY_SWITCH_PROBE,
        )
        .await;
        run_threads(&host, &[("t-task-off", "th-task-off")], 1).await;
        let results = probes(&host, "t-task-off", "th-task-off").await;
        expect(&results, &TASK_OFF);
        expect(&results, &AGENT_ON);
        assert!(!workspace.dir().join("memory/task").exists());
        expect_no_auto_memory(&workspace);
        runner.shutdown().await;
    }

    // Task memory off for one task through its meta; another task keeps it.
    {
        let (host, workspace, runner) = memory_runner(&[], MEMORY_SWITCH_PROBE).await;
        push_task_meta(
            &host,
            "t-meta-off",
            &json!({ "memory": { "task": "off" } }),
            1,
        )
        .await;
        run_threads(
            &host,
            &[("t-meta-off", "th-meta-off"), ("t-on", "th-on")],
            2,
        )
        .await;
        let off = probes(&host, "t-meta-off", "th-meta-off").await;
        expect(&off, &TASK_OFF);
        expect(&off, &AGENT_ON);
        let on = probes(&host, "t-on", "th-on").await;
        expect(&on, &TASK_ON);
        expect(&on, &AGENT_ON);
        assert!(!task_memory(&workspace, "t-meta-off").exists());
        assert!(task_memory(&workspace, "t-on").join("index.md").is_file());
        expect_no_auto_memory(&workspace);
        runner.shutdown().await;
    }

    // Both off: no memory mounts at all.
    let (host, workspace, runner) = memory_runner(
        &[
            ("GINO_TASK_MEMORY", OsStr::new("off")),
            ("GINO_AGENT_MEMORY_ACCESS", OsStr::new("off")),
        ],
        MEMORY_SWITCH_PROBE,
    )
    .await;
    run_threads(&host, &[("t-both-off", "th-both-off")], 1).await;
    let results = probes(&host, "t-both-off", "th-both-off").await;
    expect(&results, &TASK_OFF);
    expect(&results, &AGENT_OFF);
    expect(&results, &[("MEMORY_ROOT", "denied")]);
    assert!(!workspace.dir().join("memory/task").exists());
    expect_no_auto_memory(&workspace);

    runner.shutdown().await;
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

#[tokio::test]
#[ignore = "needs bubblewrap and user namespaces; run scripts/sandbox-it.sh"]
async fn conversations_view_is_a_read_only_snapshot_of_the_task_only() {
    if !enabled() {
        return;
    }
    let (host, workspace, runner) = memory_runner(&[], CONVERSATIONS_PROBE).await;
    run_threads(
        &host,
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
        &probes(&host, "t-d", "th-d1").await,
        &[("SECRET_WRITE", "ok")],
    );
    expect(
        &probes(&host, "t-c", "th-c1").await,
        &[("ARCHIVE_WRITE", "ok"), ("PLANT", "ok")],
    );
    // The archive is readable but not writable; planted symlinks are not followed.
    expect(
        &probes(&host, "t-c", "th-c2").await,
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
        &probes(&host, "t-d", "th-d2").await,
        &[("SEES_C", "denied"), ("SEES_C_FILE", "denied")],
    );

    let archive = work_dir(&workspace, "th-c1").join("conversations");
    assert_eq!(
        std::fs::read_to_string(archive.join("transcript-1.jsonl"))
            .unwrap()
            .trim(),
        "conv-marker-5b1e"
    );
    assert!(!archive.join("new.jsonl").exists());
    assert!(archive.join("leak-task.md").is_symlink());

    runner.shutdown().await;
}
