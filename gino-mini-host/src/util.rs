//! Small helpers shared by every module: JSON replies, ids, timestamps and row mapping.

use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, Params};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};

pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

pub(crate) fn reply(status: StatusCode, body: &Value) -> Response {
    (status, Json(body)).into_response()
}

pub(crate) fn fail(status: StatusCode, message: &str) -> Response {
    reply(status, &json!({ "error": message }))
}

/// RFC 3339 UTC with milliseconds, e.g. `2026-11-10T11:30:00.000Z`.
pub(crate) fn now() -> String {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    let secs = i64::try_from(ms / 1000).unwrap_or(i64::MAX);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        ms % 1000
    )
}

/// Unix time in seconds.
pub(crate) fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub(crate) fn base36(mut n: u128) -> String {
    const DIGITS: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut out = Vec::new();
    loop {
        out.push(DIGITS[usize::try_from(n % 36).unwrap_or(0)]);
        n /= 36;
        if n == 0 {
            break;
        }
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_default()
}

/// `<prefix>-<base36 ms>-<8 hex>`.
pub(crate) fn new_id(prefix: &str) -> String {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    let random = uuid::Uuid::new_v4().simple().to_string();
    format!("{prefix}-{}-{}", base36(ms), &random[..8])
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

/// Standard base64 (with padding), the encoding of the operator API and terminal data.
pub(crate) fn b64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub(crate) fn b64_decode(text: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(text).ok()
}

pub(crate) fn str_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

pub(crate) fn non_empty<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    str_field(value, key).filter(|s| !s.is_empty())
}

/// The request body as a JSON object; anything else reads as `{}`.
pub(crate) fn body_object(body: &[u8]) -> Value {
    serde_json::from_slice::<Value>(body)
        .ok()
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}))
}

pub(crate) fn parse_json_text(text: Option<&str>) -> Value {
    text.and_then(|t| serde_json::from_str(t).ok())
        .unwrap_or(Value::Null)
}

/// Rows as JSON objects keyed by column name. Blob columns read as `null`.
pub(crate) fn rows<P: Params>(
    db: &Connection,
    sql: &str,
    params: P,
) -> rusqlite::Result<Vec<Map<String, Value>>> {
    let mut stmt = db.prepare(sql)?;
    let names: Vec<String> = stmt.column_names().map(ToString::to_string).collect();
    let mut out = Vec::new();
    let mut cursor = stmt.query(params)?;
    while let Some(row) = cursor.next()? {
        let mut object = Map::new();
        for (i, name) in names.iter().enumerate() {
            let value = match row.get_ref(i)? {
                ValueRef::Integer(n) => json!(n),
                ValueRef::Real(f) => json!(f),
                ValueRef::Text(t) => Value::String(String::from_utf8_lossy(t).into_owned()),
                ValueRef::Null | ValueRef::Blob(_) => Value::Null,
            };
            object.insert(name.clone(), value);
        }
        out.push(object);
    }
    Ok(out)
}

pub(crate) fn first_row<P: Params>(
    db: &Connection,
    sql: &str,
    params: P,
) -> rusqlite::Result<Option<Map<String, Value>>> {
    Ok(rows(db, sql, params)?.into_iter().next())
}

/// RFC 7386 JSON merge patch: an object merges key by key (`null` removes the key), any
/// other value replaces `target`.
pub(crate) fn merge_patch(target: &mut Value, patch: &Value) {
    let Value::Object(patch) = patch else {
        *target = patch.clone();
        return;
    };
    if !target.is_object() {
        *target = Value::Object(Map::new());
    }
    if let Value::Object(target) = target {
        for (key, value) in patch {
            if value.is_null() {
                target.remove(key);
            } else {
                merge_patch(target.entry(key.clone()).or_insert(Value::Null), value);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{base36, merge_patch, now, sha256_hex};

    #[test]
    fn timestamps_are_rfc3339_millis() {
        let ts = now();
        assert_eq!(ts.len(), 24, "{ts}");
        assert!(ts.ends_with('Z') && ts.as_bytes()[10] == b'T', "{ts}");
    }

    #[test]
    fn base36_matches_javascript() {
        assert_eq!(base36(0), "0");
        assert_eq!(base36(35), "z");
        assert_eq!(base36(1_761_480_000_000), "mh7npmo0");
    }

    #[test]
    fn merge_patch_follows_rfc_7386() {
        let mut target = json!({ "engine": { "model": "a", "env": { "A": "1" } }, "x": 1 });
        merge_patch(
            &mut target,
            &json!({ "engine": { "model": null, "env": { "B": "2" } }, "x": [1] }),
        );
        assert_eq!(
            target,
            json!({ "engine": { "env": { "A": "1", "B": "2" } }, "x": [1] })
        );
    }

    #[test]
    fn sha256_is_lowercase_hex() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
