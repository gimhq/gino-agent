//! End-to-end encrypted tasks (protocol §5.3, [e2ee spec](../../docs/e2ee/spec.md)).
//!
//! The host plays two roles, kept apart in this module:
//!
//! * **Delivery Service** (spec §3), which never holds a key: the key directory (pinned identity
//!   keys, verified KeyPackages, claims), the scope record, the handshake log, epoch links,
//!   Welcome delivery and the `e2ee_request` operations a runner sends.
//! * **The operator's client device**, a group member like any user device would be: it creates
//!   a task's group, adds the runner from a claimed KeyPackage, seals what the operator sends
//!   (`message`, `cron_upsert`, attachments) and opens what the runner reports. Its identity seed,
//!   group snapshots and epoch secrets live in the `client_*` tables. A production host keeps
//!   this role on user devices; it sits here so one process can drive an encrypted task end to
//!   end.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use gino_e2ee::field_map::FieldMap;
use gino_e2ee::{
    CachedSecrets, EntryKind, EnvelopeType, Header, HistoryPolicy, Identity, KeyCache,
    KeyHistoryRecord, Location, LogEntry, MemoryKeyCache, ScopeGroup, decode_b64url, encode_b64url,
    fingerprint, fingerprint_display, inspect_key_package, inspect_message,
    seal_file as seal_file_envelope, welcome_recipients,
};
use openmls_rust_crypto::RustCrypto;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use tracing::warn;

use crate::config::unknown_agent;
use crate::host::{Host, HostError, Reply, Shared};
use crate::util::{fail, lock, now, reply, str_field, unix_secs};

/// The task-content profile (task-content §1).
pub(crate) const PROFILE: &str = "gino.task-content.v1";
/// The most log entries one `log` / `log_from_epoch` answer carries; `more` asks for the rest.
const LOG_PAGE: i64 = 100;
/// The size of an epoch-link record (spec §5.6).
const EPOCH_LINK_LEN: usize = 124;

// ─── key directory ──────────────────────────────────────────────────────────

/// Record the agent's `e2ee` capability (register and every heartbeat). The first identity key
/// is pinned; a different one is held as a key change until an operator re-pins it (spec §3.5).
pub(crate) fn observe_capability(
    host: &Host,
    agent_id: &str,
    capability: Option<&Value>,
) -> Result<(), HostError> {
    let Some(key) = capability
        .and_then(|c| c.pointer("/credential/public_key"))
        .and_then(Value::as_str)
        .filter(|key| decode_b64url(key).is_ok_and(|bytes| bytes.len() == 32))
    else {
        return Ok(());
    };
    let db = lock(&host.db);
    let pinned: Option<String> = db
        .query_row(
            "SELECT public_key FROM e2ee_identities WHERE agent_id = ?",
            [agent_id],
            |r| r.get(0),
        )
        .optional()?;
    match pinned {
        None => {
            db.execute(
                "INSERT INTO e2ee_identities (agent_id, public_key, pinned_at) VALUES (?, ?, ?)",
                params![agent_id, key, now()],
            )?;
        }
        Some(pinned) if pinned != key => {
            warn!(agent = %agent_id, "e2ee identity key changed; awaiting an operator re-pin");
            db.execute(
                "UPDATE e2ee_identities SET pending_key = ? WHERE agent_id = ?",
                params![key, agent_id],
            )?;
        }
        Some(_) => {}
    }
    Ok(())
}

fn key_fingerprint(key: &str) -> Option<(String, String)> {
    let bytes: [u8; 32] = decode_b64url(key).ok()?.try_into().ok()?;
    Some((fingerprint(&bytes), fingerprint_display(&bytes)))
}

/// The identity as the operator sees it: the pinned key, its fingerprint and any key change.
pub(crate) fn identity_view(host: &Host, agent_id: &str) -> Result<Value, HostError> {
    let row: Option<(String, Option<String>)> = lock(&host.db)
        .query_row(
            "SELECT public_key, pending_key FROM e2ee_identities WHERE agent_id = ?",
            [agent_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((key, pending)) = row else {
        return Ok(Value::Null);
    };
    let (pool_one_time, pool_last_resort) = pool(&lock(&host.db), agent_id)?;
    Ok(json!({
        "publicKey": key,
        "fingerprint": key_fingerprint(&key).map(|f| f.1),
        "keyChange": pending.map(|p| json!({ "publicKey": p, "fingerprint": key_fingerprint(&p).map(|f| f.1) })),
        "keyPackages": { "one_time": pool_one_time, "last_resort": pool_last_resort },
    }))
}

/// `POST /api/agents/{id}/e2ee/repin`: accept a pending key change. KeyPackages of the old key
/// are dropped.
pub(crate) async fn repin(State(host): Shared, Path(agent_id): Path<String>) -> Reply {
    if !host.agent_exists(&agent_id)? {
        return Ok(unknown_agent(&agent_id));
    }
    let changed = {
        let db = lock(&host.db);
        let changed = db.execute(
            "UPDATE e2ee_identities SET public_key = pending_key, pending_key = NULL, pinned_at = ?
             WHERE agent_id = ? AND pending_key IS NOT NULL",
            params![now(), agent_id],
        )?;
        if changed > 0 {
            db.execute(
                "DELETE FROM e2ee_key_packages WHERE agent_id = ?",
                [&agent_id],
            )?;
        }
        changed > 0
    };
    if !changed {
        return Ok(fail(StatusCode::CONFLICT, "no key change to accept"));
    }
    send_pool_status(&host, &agent_id, None, None)?;
    Ok(reply(StatusCode::OK, &identity_view(&host, &agent_id)?))
}

fn pinned_key(db: &Connection, agent_id: &str) -> Result<Option<(String, bool)>, HostError> {
    Ok(db
        .query_row(
            "SELECT public_key, pending_key IS NOT NULL FROM e2ee_identities WHERE agent_id = ?",
            [agent_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?)
}

/// `(unclaimed current one-time KeyPackages, a current last-resort one is held)`.
fn pool(db: &Connection, agent_id: &str) -> Result<(i64, bool), HostError> {
    let now = i64::try_from(unix_secs()).unwrap_or(i64::MAX);
    db.execute("DELETE FROM e2ee_key_packages WHERE not_after < ?", [now])?;
    let one_time: i64 = db.query_row(
        "SELECT COUNT(*) FROM e2ee_key_packages WHERE agent_id = ? AND last_resort = 0 AND claimed = 0",
        [agent_id],
        |r| r.get(0),
    )?;
    let last_resort: i64 = db.query_row(
        "SELECT COUNT(*) FROM e2ee_key_packages WHERE agent_id = ? AND last_resort = 1",
        [agent_id],
        |r| r.get(0),
    )?;
    Ok((one_time, last_resort > 0))
}

/// Send the live `e2ee_key_package_status`: on connect, after each claim, and (with the
/// upload's `outboxId` as `id` and the refusals) answering an upload. Only to an e2ee-capable
/// agent.
pub(crate) fn send_pool_status(
    host: &Host,
    agent_id: &str,
    id: Option<&str>,
    rejected: Option<Vec<Value>>,
) -> Result<(), HostError> {
    let (one_time, last_resort) = {
        let db = lock(&host.db);
        if pinned_key(&db, agent_id)?.is_none() {
            return Ok(());
        }
        pool(&db, agent_id)?
    };
    let mut data = json!({ "one_time": one_time, "last_resort": last_resort });
    if let Some(rejected) = rejected {
        data["rejected"] = Value::Array(rejected);
    }
    let mut frame = json!({ "type": "e2ee_key_package_status", "data": data });
    if let Some(id) = id {
        frame["id"] = json!(id);
    }
    host.send(agent_id, &frame);
    Ok(())
}

/// A durable `e2ee_key_packages {one_time?, last_resort?}`: verify each KeyPackage under the
/// pinned key (spec §3.5) and pool the valid ones; a new last-resort one replaces the previous.
pub(crate) fn key_packages(
    host: &Host,
    agent_id: &str,
    data: &Value,
    outbox_id: Option<&str>,
) -> Result<(), HostError> {
    let mut rejected = Vec::new();
    {
        let db = lock(&host.db);
        let pinned = pinned_key(&db, agent_id)?;
        let now = unix_secs();
        let mut admit = |encoded: &str,
                         index: Option<usize>,
                         last_resort: bool|
         -> Result<(), HostError> {
            let refuse = |code: &str| {
                let mut entry = json!({ "code": code });
                if let Some(index) = index {
                    entry["index"] = json!(index);
                }
                entry
            };
            let Ok(bytes) = decode_b64url(encoded) else {
                rejected.push(refuse("malformed"));
                return Ok(());
            };
            let info = match inspect_key_package(&bytes, now) {
                Ok(info) => info,
                Err(err) => {
                    rejected.push(refuse(&err.error.to_string()));
                    return Ok(());
                }
            };
            match &pinned {
                Some((key, false)) if *key == encode_b64url(&info.public_key) => {}
                // No pinned key, a key change awaiting re-pin, or a KeyPackage under another key.
                _ => {
                    rejected.push(refuse("key_changed"));
                    return Ok(());
                }
            }
            if info.last_resort != last_resort {
                rejected.push(refuse("malformed"));
                return Ok(());
            }
            if last_resort {
                db.execute(
                    "DELETE FROM e2ee_key_packages WHERE agent_id = ? AND last_resort = 1",
                    [agent_id],
                )?;
            }
            db.execute(
                "INSERT OR IGNORE INTO e2ee_key_packages (reference, agent_id, last_resort, data, not_after)
                 VALUES (?, ?, ?, ?, ?)",
                params![
                    encode_b64url(&info.reference),
                    agent_id,
                    last_resort,
                    bytes,
                    i64::try_from(info.not_after).unwrap_or(i64::MAX)
                ],
            )?;
            Ok(())
        };
        if let Some(list) = data.get("one_time").and_then(Value::as_array) {
            for (index, item) in list.iter().enumerate() {
                admit(item.as_str().unwrap_or_default(), Some(index), false)?;
            }
        }
        if let Some(item) = str_field(data, "last_resort") {
            admit(item, None, true)?;
        }
    }
    send_pool_status(host, agent_id, outbox_id, Some(rejected))
}

/// Claim one KeyPackage of `agent_id`: a one-time one is consumed atomically; with the pool
/// empty the last-resort one is handed out and kept (spec §3.5).
fn claim(db: &Connection, agent_id: &str) -> Result<Option<Vec<u8>>, HostError> {
    pool(db, agent_id)?;
    let one_time: Option<(String, Vec<u8>)> = db
        .query_row(
            "SELECT reference, data FROM e2ee_key_packages
             WHERE agent_id = ? AND last_resort = 0 AND claimed = 0 ORDER BY rowid LIMIT 1",
            [agent_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((reference, data)) = one_time {
        db.execute(
            "DELETE FROM e2ee_key_packages WHERE reference = ?",
            [reference],
        )?;
        return Ok(Some(data));
    }
    Ok(db
        .query_row(
            "SELECT data FROM e2ee_key_packages WHERE agent_id = ? AND last_resort = 1",
            [agent_id],
            |r| r.get(0),
        )
        .optional()?)
}

// ─── Delivery Service ───────────────────────────────────────────────────────

/// A log entry as it rides `e2ee_log` and `e2ee_response.entries`.
fn entry_json(
    seq: i64,
    kind: &str,
    epoch: i64,
    message: &[u8],
    drop_public_key: Option<&[u8]>,
) -> Value {
    let mut entry =
        json!({ "seq": seq, "kind": kind, "epoch": epoch, "message": encode_b64url(message) });
    if let Some(key) = drop_public_key {
        entry["drop_public_key"] = json!(encode_b64url(key));
    }
    entry
}

fn kind_of(name: &str) -> Option<EntryKind> {
    match name {
        "commit" => Some(EntryKind::Commit),
        "proposal" => Some(EntryKind::Proposal),
        "key_history" => Some(EntryKind::KeyHistory),
        "key_history_sealed" => Some(EntryKind::KeyHistorySealed),
        _ => None,
    }
}

/// Append one entry to a task's log; returns its `seq`.
fn append(
    db: &Connection,
    task_id: &str,
    kind: &str,
    epoch: u64,
    message: &[u8],
    drop_public_key: Option<&[u8]>,
    submitter: &str,
) -> Result<u64, HostError> {
    let last: i64 = db.query_row(
        "SELECT COALESCE(MAX(seq), 0) FROM e2ee_log WHERE task_id = ?",
        [task_id],
        |r| r.get(0),
    )?;
    let seq = last + 1;
    db.execute(
        "INSERT INTO e2ee_log (task_id, seq, kind, epoch, message, drop_public_key, submitter, accepted_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        params![task_id, seq, kind, i64::try_from(epoch)?, message, drop_public_key, submitter, now()],
    )?;
    Ok(u64::try_from(seq)?)
}

/// The framing checks of an epoch link (spec §3.4).
fn link_framed(link: &[u8], epoch: u64) -> bool {
    link.len() == EPOCH_LINK_LEN
        && Header::parse_as(link, EnvelopeType::EpochLink).is_ok_and(|header| header.epoch == epoch)
}

/// The scope's `(group id, current epoch)`.
fn scope(db: &Connection, task_id: &str) -> Result<Option<(Vec<u8>, u64)>, HostError> {
    let row: Option<(Vec<u8>, i64)> = db
        .query_row(
            "SELECT group_id, epoch FROM e2ee_scopes WHERE task_id = ?",
            [task_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    row.map(|(id, epoch)| Ok((id, u64::try_from(epoch)?)))
        .transpose()
}

/// One accepted commit unit (spec §3.2): the commit, its epoch link and key-history entries.
/// The framing checks run first; the inner `Err` is the DS rejection `(code, epoch)`.
struct Unit<'a> {
    commit: &'a [u8],
    drop_public_key: &'a [u8],
    epoch_link: Option<&'a [u8]>,
    key_history: Vec<(&'a str, Vec<u8>)>,
}

fn accept_commit(
    db: &Connection,
    task_id: &str,
    unit: &Unit<'_>,
    submitter: &str,
) -> Result<Result<Vec<u64>, (&'static str, u64)>, HostError> {
    let Some((group_id, epoch)) = scope(db, task_id)? else {
        return Ok(Err(("not_member", 0)));
    };
    let Ok(info) = inspect_message(unit.commit) else {
        return Ok(Err(("malformed", epoch)));
    };
    if info.group_id != group_id || info.content_type != gino_e2ee::MessageContent::Commit {
        return Ok(Err(("malformed", epoch)));
    }
    if info.epoch != epoch {
        return Ok(Err(("epoch_conflict", epoch)));
    }
    if unit.drop_public_key.len() != 32
        || unit
            .epoch_link
            .is_some_and(|link| !link_framed(link, epoch + 1))
        || unit
            .key_history
            .iter()
            .any(|(kind, _)| !matches!(*kind, "key_history" | "key_history_sealed"))
    {
        return Ok(Err(("malformed", epoch)));
    }
    let mut seqs = vec![append(
        db,
        task_id,
        "commit",
        epoch,
        unit.commit,
        Some(unit.drop_public_key),
        submitter,
    )?];
    db.execute(
        "UPDATE e2ee_scopes SET epoch = ?, drop_public_key = ? WHERE task_id = ?",
        params![i64::try_from(epoch + 1)?, unit.drop_public_key, task_id],
    )?;
    if let Some(link) = unit.epoch_link {
        db.execute(
            "INSERT OR IGNORE INTO e2ee_links (task_id, epoch, link) VALUES (?, ?, ?)",
            params![task_id, i64::try_from(epoch + 1)?, link],
        )?;
    }
    for (kind, message) in &unit.key_history {
        seqs.push(append(
            db,
            task_id,
            kind,
            epoch + 1,
            message,
            None,
            submitter,
        )?);
    }
    Ok(Ok(seqs))
}

fn log_entries(
    db: &Connection,
    task_id: &str,
    column: &str,
    from: i64,
) -> Result<(Vec<Value>, bool), HostError> {
    let mut stmt = db.prepare(&format!(
        "SELECT seq, kind, epoch, message, drop_public_key FROM e2ee_log
         WHERE task_id = ? AND {column} ORDER BY seq LIMIT ?"
    ))?;
    let mut entries: Vec<Value> = stmt
        .query_map(params![task_id, from, LOG_PAGE + 1], |r| {
            let message: Vec<u8> = r.get(3)?;
            let drop_key: Option<Vec<u8>> = r.get(4)?;
            Ok(entry_json(
                r.get(0)?,
                &r.get::<_, String>(1)?,
                r.get(2)?,
                &message,
                drop_key.as_deref(),
            ))
        })?
        .collect::<Result<_, _>>()?;
    let more = entries.len() > usize::try_from(LOG_PAGE).unwrap_or(usize::MAX);
    entries.truncate(usize::try_from(LOG_PAGE).unwrap_or(usize::MAX));
    Ok((entries, more))
}

/// Deliver log entries `seqs` to every agent member except `except` as durable `e2ee_log`.
fn deliver_entries(
    host: &Host,
    task_id: &str,
    seqs: &[u64],
    except: Option<&str>,
) -> Result<(), HostError> {
    let (members, entries) = {
        let db = lock(&host.db);
        let members: Vec<String> = db
            .prepare("SELECT agent_id FROM e2ee_members WHERE task_id = ?")?
            .query_map([task_id], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        let mut entries = Vec::new();
        for seq in seqs {
            let seq = i64::try_from(*seq)?;
            let (found, _) = log_entries(&db, task_id, "seq >= ?", seq)?;
            entries.extend(found.into_iter().take(1));
        }
        (members, entries)
    };
    for agent_id in members.iter().filter(|m| Some(m.as_str()) != except) {
        for entry in &entries {
            host.enqueue(
                agent_id,
                json!({ "type": "e2ee_log", "taskId": task_id, "data": entry }),
            )?;
        }
    }
    Ok(())
}

/// A live `e2ee_request {op, …}` from a runner: answer with the live `e2ee_response` under the
/// same `taskId` and `reqId`. Reads are served to current members only.
pub(crate) fn request(host: &Host, agent_id: &str, frame: &Value) -> Result<(), HostError> {
    let (Some(task_id), Some(req_id)) = (str_field(frame, "taskId"), str_field(frame, "reqId"))
    else {
        return Ok(());
    };
    let empty = json!({});
    let data = frame.get("data").unwrap_or(&empty);
    let (answer, delivered) = answer_request(host, agent_id, task_id, data)?;
    tracing::debug!(agent = %agent_id, task = %task_id, op = str_field(data, "op").unwrap_or("-"), ok = %answer["ok"], "e2ee_request");
    host.send(
        agent_id,
        &json!({ "type": "e2ee_response", "taskId": task_id, "reqId": req_id, "data": answer }),
    );
    if !delivered.is_empty() {
        sync_client(host, task_id)?;
        deliver_entries(host, task_id, &delivered, Some(agent_id))?;
    }
    Ok(())
}

fn rejection(code: &str, epoch: Option<u64>) -> Value {
    let mut answer = json!({ "ok": false, "error": { "code": code } });
    if let Some(epoch) = epoch {
        answer["epoch"] = json!(epoch);
    }
    answer
}

/// The `e2ee_response` data and the seqs of entries a commit appended.
fn answer_request(
    host: &Host,
    agent_id: &str,
    task_id: &str,
    data: &Value,
) -> Result<(Value, Vec<u64>), HostError> {
    let db = lock(&host.db);
    let member = db
        .query_row(
            "SELECT 1 FROM e2ee_members WHERE task_id = ? AND agent_id = ?",
            params![task_id, agent_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    let Some((_, epoch)) = scope(&db, task_id)?.filter(|_| member) else {
        return Ok((rejection("not_member", None), Vec::new()));
    };
    let number = |key: &str| data.get(key).and_then(Value::as_i64);
    let bytes = |key: &str| str_field(data, key).and_then(|v| decode_b64url(v).ok());
    let answer = match str_field(data, "op") {
        Some(op @ ("log" | "log_from_epoch")) => {
            let (column, from) = if op == "log" {
                ("seq > ?", number("after_seq").unwrap_or(0))
            } else {
                ("epoch >= ?", number("epoch").unwrap_or(0))
            };
            let (entries, more) = log_entries(&db, task_id, column, from)?;
            json!({ "ok": true, "entries": entries, "more": more, "epoch": epoch })
        }
        Some("link") => {
            let link: Option<Vec<u8>> = db
                .query_row(
                    "SELECT link FROM e2ee_links WHERE task_id = ? AND epoch = ?",
                    params![task_id, number("epoch").unwrap_or(-1)],
                    |r| r.get(0),
                )
                .optional()?;
            let mut answer = json!({ "ok": true, "epoch": epoch });
            if let Some(link) = link {
                answer["link"] = json!(encode_b64url(&link));
            }
            answer
        }
        Some("put_link") => {
            let link_epoch = number("epoch").and_then(|e| u64::try_from(e).ok());
            match (link_epoch, bytes("link")) {
                (Some(link_epoch), Some(link))
                    if link_epoch <= epoch && link_framed(&link, link_epoch) =>
                {
                    let stored: Option<Vec<u8>> = db
                        .query_row(
                            "SELECT link FROM e2ee_links WHERE task_id = ? AND epoch = ?",
                            params![task_id, i64::try_from(link_epoch)?],
                            |r| r.get(0),
                        )
                        .optional()?;
                    if let Some(stored) = stored {
                        let mut answer = rejection("link_exists", Some(epoch));
                        answer["link"] = json!(encode_b64url(&stored));
                        answer
                    } else {
                        db.execute(
                            "INSERT INTO e2ee_links (task_id, epoch, link) VALUES (?, ?, ?)",
                            params![task_id, i64::try_from(link_epoch)?, link],
                        )?;
                        json!({ "ok": true, "epoch": epoch })
                    }
                }
                _ => rejection("malformed", Some(epoch)),
            }
        }
        Some("commit") => return commit_op(&db, agent_id, task_id, epoch, data),
        _ => rejection("malformed", Some(epoch)),
    };
    Ok((answer, Vec::new()))
}

/// The `commit` operation: one commit unit from a runner (its own Update, spec §3.2).
fn commit_op(
    db: &Connection,
    agent_id: &str,
    task_id: &str,
    epoch: u64,
    data: &Value,
) -> Result<(Value, Vec<u64>), HostError> {
    let bytes = |key: &str| str_field(data, key).and_then(|v| decode_b64url(v).ok());
    let history: Option<Vec<(String, Vec<u8>)>> = data
        .get("key_history")
        .and_then(Value::as_array)
        .map_or(Some(Vec::new()), |items| {
            items
                .iter()
                .map(|item| {
                    Some((
                        str_field(item, "kind")?.to_owned(),
                        decode_b64url(str_field(item, "message")?).ok()?,
                    ))
                })
                .collect()
        });
    let (Some(commit), Some(drop_key), Some(history)) =
        (bytes("commit"), bytes("drop_public_key"), history)
    else {
        return Ok((rejection("malformed", Some(epoch)), Vec::new()));
    };
    let link = bytes("epoch_link");
    let unit = Unit {
        commit: &commit,
        drop_public_key: &drop_key,
        epoch_link: link.as_deref(),
        key_history: history
            .iter()
            .map(|(k, m)| (k.as_str(), m.clone()))
            .collect(),
    };
    Ok(match accept_commit(db, task_id, &unit, agent_id)? {
        Ok(seqs) => (
            json!({ "ok": true, "seq": seqs[0], "epoch": epoch + 1 }),
            seqs,
        ),
        Err((code, epoch)) => (rejection(code, Some(epoch)), Vec::new()),
    })
}

/// The DS view of a task's scope for the operator: current epoch, last log `seq` and members.
pub(crate) fn scope_view(host: &Host, task_id: &str) -> Result<Value, HostError> {
    let db = lock(&host.db);
    let Some((_, epoch)) = scope(&db, task_id)? else {
        return Ok(Value::Null);
    };
    let seq: i64 = db.query_row(
        "SELECT COALESCE(MAX(seq), 0) FROM e2ee_log WHERE task_id = ?",
        [task_id],
        |r| r.get(0),
    )?;
    let members: Vec<String> = db
        .prepare("SELECT agent_id FROM e2ee_members WHERE task_id = ? ORDER BY agent_id")?
        .query_map([task_id], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    Ok(json!({ "profile_id": PROFILE, "epoch": epoch, "seq": seq, "members": members }))
}

// ─── the operator's client device ───────────────────────────────────────────

fn client_identity(db: &Connection) -> Result<Identity, HostError> {
    let seed: Option<Vec<u8>> = db
        .query_row("SELECT seed FROM client_identity WHERE id = 1", [], |r| {
            r.get(0)
        })
        .optional()?;
    if let Some(seed) = seed.and_then(|s| <[u8; 32]>::try_from(s).ok()) {
        return Ok(Identity::from_seed(&seed));
    }
    let identity = Identity::generate(&RustCrypto::default())?;
    db.execute(
        "INSERT OR REPLACE INTO client_identity (id, seed) VALUES (1, ?)",
        [identity.seed().to_vec()],
    )?;
    Ok(identity)
}

fn load_group(db: &Connection, task_id: &str) -> Result<ScopeGroup<MemoryKeyCache>, HostError> {
    let snapshot: Vec<u8> = db
        .query_row(
            "SELECT snapshot FROM client_groups WHERE task_id = ?",
            [task_id],
            |r| r.get(0),
        )
        .optional()?
        .ok_or_else(|| HostError(format!("the client device holds no group for {task_id}")))?;
    let mut cache = MemoryKeyCache::default();
    let mut stmt = db.prepare("SELECT epoch, secrets FROM client_secrets WHERE task_id = ?")?;
    let rows = stmt.query_map([task_id], |r| {
        Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?))
    })?;
    for row in rows {
        let (epoch, secrets) = row?;
        cache.put(u64::try_from(epoch)?, CachedSecrets::from_bytes(&secrets)?);
    }
    Ok(ScopeGroup::restore(&snapshot, cache)?)
}

fn save_group(
    db: &Connection,
    task_id: &str,
    group: &ScopeGroup<MemoryKeyCache>,
) -> Result<(), HostError> {
    db.execute(
        "INSERT OR REPLACE INTO client_groups (task_id, snapshot) VALUES (?, ?)",
        params![task_id, group.snapshot()?],
    )?;
    db.execute("DELETE FROM client_secrets WHERE task_id = ?", [task_id])?;
    let cache = group.history().cache();
    for epoch in cache.epochs() {
        if let Some(secrets) = cache.get(epoch) {
            db.execute(
                "INSERT INTO client_secrets (task_id, epoch, secrets) VALUES (?, ?, ?)",
                params![task_id, i64::try_from(epoch)?, secrets.to_bytes().to_vec()],
            )?;
        }
    }
    Ok(())
}

fn link_fetcher(db: &Connection, task_id: &str) -> impl FnMut(u64) -> Option<Vec<u8>> {
    move |epoch| {
        db.query_row(
            "SELECT link FROM e2ee_links WHERE task_id = ? AND epoch = ?",
            params![task_id, i64::try_from(epoch).ok()?],
            |r| r.get(0),
        )
        .ok()
    }
}

/// A stored log entry: `(seq, kind, epoch, message, drop_public_key)`.
type LogRow = (i64, String, i64, Vec<u8>, Option<Vec<u8>>);

/// Apply every log entry the client device has not seen (runner commits, key history).
fn sync_client(host: &Host, task_id: &str) -> Result<(), HostError> {
    let db = lock(&host.db);
    let mut group = load_group(&db, task_id)?;
    let after = i64::try_from(group.seq())?;
    let entries: Vec<LogRow> = db
        .prepare("SELECT seq, kind, epoch, message, drop_public_key FROM e2ee_log WHERE task_id = ? AND seq > ? ORDER BY seq")?
        .query_map(params![task_id, after], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?
        .collect::<Result<_, _>>()?;
    for (seq, kind, epoch, bytes, drop_public_key) in entries {
        let kind =
            kind_of(&kind).ok_or_else(|| HostError(format!("unknown log entry kind {kind}")))?;
        group.apply(&LogEntry {
            seq: u64::try_from(seq)?,
            kind,
            epoch: u64::try_from(epoch)?,
            bytes,
            drop_public_key,
        })?;
    }
    save_group(&db, task_id, &group)
}

/// The `task_upsert.data.e2ee` of a new group and the Welcome that adds its runner.
#[derive(Debug)]
pub(crate) struct NewGroup {
    pub(crate) e2ee: Value,
    welcome: Vec<u8>,
    seq: u64,
}

/// Create `task_id`'s group on the client device and add `agent_id` from a claimed
/// KeyPackage. A runner that is not e2ee-capable or holds no KeyPackage is refused with 409
/// `runner_without_encryption`: an encrypted task is never downgraded (protocol §5.3).
pub(crate) fn create_group(
    host: &Host,
    agent_id: &str,
    task_id: &str,
) -> Result<Result<NewGroup, Response>, HostError> {
    let refuse = |why: &str| {
        Ok(Err(crate::util::reply(
            StatusCode::CONFLICT,
            &json!({ "error": "runner_without_encryption", "message": why }),
        )))
    };
    let created = {
        let db = lock(&host.db);
        match pinned_key(&db, agent_id)? {
            Some((_, false)) => {}
            Some((_, true)) => return refuse("the runner's identity key changed; re-pin it first"),
            None => return refuse("the runner is not e2ee-capable"),
        }
        if scope(&db, task_id)?.is_some() {
            return Ok(Err(fail(StatusCode::CONFLICT, "scope_exists")));
        }
        let Some(key_package) = claim(&db, agent_id)? else {
            return refuse("the runner has no KeyPackage at the host");
        };
        let identity = client_identity(&db)?;
        let mut group = ScopeGroup::create(
            &identity,
            PROFILE,
            task_id,
            HistoryPolicy::Full,
            MemoryKeyCache::default(),
        )?;
        db.execute(
            "INSERT INTO e2ee_scopes (task_id, profile_id, group_id, epoch, drop_public_key, created_at)
             VALUES (?, ?, ?, 0, ?, ?)",
            params![task_id, PROFILE, group.group_id(), group.drop_public_key()?.to_vec(), now()],
        )?;
        let unit = group.add_members(&identity, &[key_package], None)?;
        let history: Vec<(&str, Vec<u8>)> = unit
            .key_history
            .iter()
            .map(|record| match record {
                KeyHistoryRecord::Message(m) => ("key_history", m.clone()),
                KeyHistoryRecord::Sealed(m) => ("key_history_sealed", m.clone()),
            })
            .collect();
        let accepted = accept_commit(
            &db,
            task_id,
            &Unit {
                commit: &unit.commit,
                drop_public_key: &unit.drop_public_key,
                epoch_link: unit.epoch_link.as_deref(),
                key_history: history,
            },
            "client",
        )?;
        let seqs =
            accepted.map_err(|(code, _)| HostError(format!("own commit refused: {code}")))?;
        group.commit_accepted(seqs[0])?;
        // The DS learns the joiners from the Welcome's KeyPackageRefs (spec §3.3); here the one
        // joiner is the runner whose KeyPackage was just claimed.
        let welcome = unit
            .welcome
            .ok_or_else(|| HostError("an Add commit without a Welcome".into()))?;
        if welcome_recipients(&welcome).map_or(true, |r| r.is_empty()) {
            return Err(HostError("the Welcome names no recipient".into()));
        }
        db.execute(
            "INSERT OR IGNORE INTO e2ee_members (task_id, agent_id) VALUES (?, ?)",
            params![task_id, agent_id],
        )?;
        save_group(&db, task_id, &group)?;
        NewGroup {
            e2ee: json!({ "profile_id": PROFILE, "group_id": encode_b64url(group.group_id()) }),
            welcome,
            seq: seqs[0],
        }
    };
    send_pool_status(host, agent_id, None, None)?;
    Ok(Ok(created))
}

/// The durable `e2ee_welcome {welcome, seq}` that lets the runner join; it continues the log
/// after `seq`.
pub(crate) fn deliver_welcome(
    host: &Host,
    agent_id: &str,
    task_id: &str,
    group: &NewGroup,
) -> Result<(), HostError> {
    host.enqueue(
        agent_id,
        json!({ "type": "e2ee_welcome", "taskId": task_id,
                "data": { "welcome": encode_b64url(&group.welcome), "seq": group.seq } }),
    )?;
    Ok(())
}

/// `POST /api/tasks/{id}/e2ee/update`: the client device commits an Update of its own leaf (a
/// new epoch); the runner receives the commit as `e2ee_log`.
pub(crate) async fn client_update(State(host): Shared, Path(task_id): Path<String>) -> Reply {
    let seqs = {
        let db = lock(&host.db);
        if scope(&db, &task_id)?.is_none() {
            return Ok(fail(StatusCode::NOT_FOUND, "not an encrypted task"));
        }
        let identity = client_identity(&db)?;
        let mut group = load_group(&db, &task_id)?;
        let unit = group.self_update(&identity)?;
        let accepted = accept_commit(
            &db,
            &task_id,
            &Unit {
                commit: &unit.commit,
                drop_public_key: &unit.drop_public_key,
                epoch_link: unit.epoch_link.as_deref(),
                key_history: Vec::new(),
            },
            "client",
        )?;
        let seqs = match accepted {
            Ok(seqs) => seqs,
            Err((code, epoch)) => {
                group.commit_rejected()?;
                save_group(&db, &task_id, &group)?;
                return Ok(reply(
                    StatusCode::CONFLICT,
                    &json!({ "error": code, "epoch": epoch }),
                ));
            }
        };
        group.commit_accepted(seqs[0])?;
        save_group(&db, &task_id, &group)?;
        seqs
    };
    deliver_entries(&host, &task_id, &seqs, None)?;
    let epoch = scope(&lock(&host.db), &task_id)?.map_or(0, |s| s.1);
    Ok(reply(
        StatusCode::OK,
        &json!({ "seq": seqs[0], "epoch": epoch }),
    ))
}

/// Seal every mapped field of a host→agent frame under the current epoch (task-content §2).
pub(crate) fn seal_frame(
    host: &Host,
    task_id: &str,
    frame_type: &str,
    frame: &Value,
) -> Result<Value, HostError> {
    let db = lock(&host.db);
    let group = load_group(&db, task_id)?;
    let (epoch, secrets) = group.current()?;
    let map = FieldMap::for_profile(PROFILE).ok_or_else(|| HostError("no field map".into()))?;
    Ok(map.seal_frame(
        frame_type,
        frame,
        epoch,
        &secrets.content_key,
        &RustCrypto::default(),
    )?)
}

/// Open every mapped field of a stored agent→host frame (any epoch the client device held).
pub(crate) fn open_frame(
    host: &Host,
    task_id: &str,
    frame_type: &str,
    frame: &Value,
) -> Result<Value, HostError> {
    let db = lock(&host.db);
    let mut group = load_group(&db, task_id)?;
    let map = FieldMap::for_profile(PROFILE).ok_or_else(|| HostError("no field map".into()))?;
    let opened = map.open_frame(frame_type, frame, |envelope, location| {
        group
            .open(envelope, location, link_fetcher(&db, task_id))
            .map_err(|err| {
                err.encryption_error()
                    .unwrap_or(gino_e2ee::Error::Malformed)
            })
    })?;
    save_group(&db, task_id, &group)?;
    Ok(opened)
}

fn file_location(task_id: &str) -> Result<Location, HostError> {
    Ok(Location::new(task_id)?.part("field", "file")?)
}

/// Seal attachment bytes as a file envelope (task-content §2: `scope:{taskId}|field:file`).
pub(crate) fn seal_file(host: &Host, task_id: &str, bytes: &[u8]) -> Result<Vec<u8>, HostError> {
    let db = lock(&host.db);
    let group = load_group(&db, task_id)?;
    let (epoch, secrets) = group.current()?;
    let sealed = seal_file_envelope(
        &secrets.content_key,
        epoch,
        &file_location(task_id)?,
        bytes,
        &RustCrypto::default(),
    )?;
    Ok(sealed.envelope)
}

/// Open a file envelope of the task.
pub(crate) fn open_file(host: &Host, task_id: &str, envelope: &[u8]) -> Result<Vec<u8>, HostError> {
    let db = lock(&host.db);
    let mut group = load_group(&db, task_id)?;
    let opened = group.open(
        envelope,
        &file_location(task_id)?,
        link_fetcher(&db, task_id),
    )?;
    save_group(&db, task_id, &group)?;
    Ok(opened.plaintext)
}

/// Refuse a frame of an encrypted task whose mapped fields arrived in plaintext (spec §3.8:
/// `plaintext_rejected`; the frame is neither stored nor acked). Sealed values are stored as
/// received; whether they open is the client's concern.
pub(crate) fn check_sealed(
    host: &Host,
    task_id: &str,
    frame_type: &str,
    frame: &Value,
) -> Result<(), HostError> {
    let encrypted = lock(&host.db)
        .query_row("SELECT encrypted FROM tasks WHERE id = ?", [task_id], |r| {
            r.get::<_, bool>(0)
        })
        .optional()?
        .unwrap_or(false);
    if !encrypted {
        return Ok(());
    }
    let map = FieldMap::for_profile(PROFILE).ok_or_else(|| HostError("no field map".into()))?;
    // Walk every mapped value without a key: each sealed one "opens" to an empty JSON string,
    // so the walk visits them all and only a plaintext value fails, as `plaintext_rejected`.
    let placeholder = |envelope: &[u8], _: &Location| {
        let header = Header::parse(envelope)?;
        Ok(gino_e2ee::Opened {
            envelope_type: header.envelope_type,
            epoch: header.epoch,
            plaintext: b"\"\"".to_vec(),
        })
    };
    match map.open_frame(frame_type, frame, placeholder) {
        Err(gino_e2ee::Error::PlaintextRejected) => Err(HostError("plaintext_rejected".into())),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::{kind_of, link_framed};

    #[test]
    fn entry_kinds_parse() {
        for name in ["commit", "proposal", "key_history", "key_history_sealed"] {
            assert!(kind_of(name).is_some(), "{name}");
        }
        assert!(kind_of("welcome").is_none());
    }

    #[test]
    fn a_link_of_the_wrong_size_is_not_framed() {
        assert!(!link_framed(&[0; 10], 1));
    }
}
