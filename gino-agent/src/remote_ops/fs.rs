//! File operations for the `fs_request` / `fs_response` frame pair.
//!
//! A relative path resolves against the workspace directory; an absolute path is
//! used as given. File bytes never ride in a frame: `put` and `get` move them
//! over the attachment byte channel (see [`super::RemoteOps`]).

use std::fs::{self, Metadata};
use std::io;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use rustix::fs::{CWD, RenameFlags, renameat_with};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};

use crate::attachments::AttachmentError;

/// `fs_request.data`.
#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub(crate) enum FsRequest {
    List {
        path: PathBuf,
    },
    Stat {
        path: PathBuf,
    },
    /// Download the blob at `ref` from the byte channel into `path`.
    /// `exclusive` creates `path` only if nothing exists there; other ops
    /// ignore the field.
    Put {
        path: PathBuf,
        #[serde(rename = "ref")]
        reference: String,
        sha256: String,
        size: u64,
        #[serde(default)]
        exclusive: bool,
    },
    /// Upload the file at `path` to the byte channel under the name `upload`.
    Get {
        path: PathBuf,
        upload: String,
    },
    Mkdir {
        path: PathBuf,
        #[serde(default)]
        recursive: bool,
    },
    Remove {
        path: PathBuf,
        #[serde(default)]
        recursive: bool,
    },
    /// `exclusive` moves only if nothing exists at `to`.
    Rename {
        path: PathBuf,
        to: PathBuf,
        #[serde(default)]
        exclusive: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ErrorCode {
    Disabled,
    NotFound,
    Exists,
    TooLarge,
    Invalid,
    Denied,
    Io,
}

#[derive(Debug, Serialize)]
pub(crate) struct FsError {
    pub(crate) code: ErrorCode,
    pub(crate) message: String,
}

impl FsError {
    pub(crate) fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl From<io::Error> for FsError {
    fn from(err: io::Error) -> Self {
        let code = match err.kind() {
            io::ErrorKind::NotFound => ErrorCode::NotFound,
            io::ErrorKind::AlreadyExists => ErrorCode::Exists,
            io::ErrorKind::PermissionDenied => ErrorCode::Denied,
            _ => ErrorCode::Io,
        };
        Self::new(code, err.to_string())
    }
}

impl From<AttachmentError> for FsError {
    fn from(err: AttachmentError) -> Self {
        match err {
            AttachmentError::Io(err) => err.into(),
            AttachmentError::SizeLimitExceeded { .. } => {
                Self::new(ErrorCode::TooLarge, err.to_string())
            }
            other => Self::new(ErrorCode::Io, other.to_string()),
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct Stat {
    #[serde(rename = "type")]
    kind: &'static str,
    size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    mtime_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct Entry {
    name: String,
    #[serde(flatten)]
    stat: Stat,
}

/// The success half of `fs_response.data`.
#[derive(Debug, Default, Serialize)]
pub(crate) struct FsOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    entries: Option<Vec<Entry>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stat: Option<Stat>,
    /// `get`: digest and length of the uploaded bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
}

impl FsOutput {
    /// The answer to a `get`: what was uploaded.
    pub(crate) fn uploaded(sha256: String, size: u64) -> Self {
        Self {
            sha256: Some(sha256),
            size: Some(size),
            ..Self::default()
        }
    }
}

fn stat_of(meta: &Metadata) -> Stat {
    let file_type = meta.file_type();
    let kind = if file_type.is_symlink() {
        "symlink"
    } else if file_type.is_dir() {
        "dir"
    } else if file_type.is_file() {
        "file"
    } else {
        "other"
    };
    let mtime_ms = meta
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .and_then(|age| u64::try_from(age.as_millis()).ok());
    Stat {
        kind,
        size: meta.len(),
        mtime_ms,
    }
}

/// Run one metadata request. Blocking: call from the blocking pool. `put` and
/// `get` are transfers and are handled by [`super::RemoteOps`].
pub(crate) fn execute(workspace_dir: &Path, request: FsRequest) -> Result<FsOutput, FsError> {
    let at = |path: &Path| workspace_dir.join(path);
    match request {
        FsRequest::List { path } => list(&at(&path)),
        FsRequest::Stat { path } => Ok(FsOutput {
            stat: Some(stat_of(&fs::symlink_metadata(at(&path))?)),
            ..FsOutput::default()
        }),
        FsRequest::Put { .. } | FsRequest::Get { .. } => Err(FsError::new(
            ErrorCode::Invalid,
            "transfers need the byte channel",
        )),
        FsRequest::Mkdir { path, recursive } => {
            if recursive {
                fs::create_dir_all(at(&path))?;
            } else {
                fs::create_dir(at(&path))?;
            }
            Ok(FsOutput::default())
        }
        FsRequest::Remove { path, recursive } => remove(&at(&path), recursive),
        FsRequest::Rename {
            path,
            to,
            exclusive,
        } => {
            if exclusive {
                rename_exclusive(&at(&path), &at(&to))?;
            } else {
                fs::rename(at(&path), at(&to))?;
            }
            Ok(FsOutput::default())
        }
    }
}

/// Move `from` to `to` only if nothing, not even a dangling symlink, sits at
/// `to`: `renameat2(RENAME_NOREPLACE)`, so of concurrent exclusive renames to
/// one path exactly one wins. A filesystem without the flag answers `EINVAL`;
/// a regular file then moves by `link(2)` + `unlink`, which never replaces
/// either, and anything else is refused as `invalid`.
fn rename_exclusive(from: &Path, to: &Path) -> Result<(), FsError> {
    match renameat_with(CWD, from, CWD, to, RenameFlags::NOREPLACE) {
        Ok(()) => Ok(()),
        Err(Errno::INVAL) => link_rename(from, to),
        Err(errno) => Err(io::Error::from(errno).into()),
    }
}

/// The exclusive move of [`rename_exclusive`] where `RENAME_NOREPLACE` is
/// unsupported: regular files only.
fn link_rename(from: &Path, to: &Path) -> Result<(), FsError> {
    if !fs::symlink_metadata(from)?.is_file() {
        return Err(FsError::new(
            ErrorCode::Invalid,
            "exclusive rename of a non-regular file is unsupported on this filesystem",
        ));
    }
    fs::hard_link(from, to)?;
    fs::remove_file(from)?;
    Ok(())
}

fn list(path: &Path) -> Result<FsOutput, FsError> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        entries.push(Entry {
            name: entry.file_name().to_string_lossy().into_owned(),
            stat: stat_of(&entry.metadata()?),
        });
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(FsOutput {
        entries: Some(entries),
        ..FsOutput::default()
    })
}

fn remove(path: &Path, recursive: bool) -> Result<FsOutput, FsError> {
    // `symlink_metadata` so a symlink is removed itself, never its target.
    if !fs::symlink_metadata(path)?.is_dir() {
        fs::remove_file(path)?;
    } else if recursive {
        fs::remove_dir_all(path)?;
    } else {
        fs::remove_dir(path)?;
    }
    Ok(FsOutput::default())
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{ErrorCode, FsRequest, execute, link_rename};

    fn run(dir: &std::path::Path, request: Value) -> Result<Value, ErrorCode> {
        let request: FsRequest = serde_json::from_value(request).unwrap();
        execute(dir, request)
            .map(|output| serde_json::to_value(output).unwrap())
            .map_err(|err| err.code)
    }

    #[test]
    fn exclusive_rename_moves_onto_a_free_path_only() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("src"), "new").unwrap();
        std::fs::write(root.join("file"), "old").unwrap();
        std::fs::create_dir(root.join("dir")).unwrap();
        std::os::unix::fs::symlink("missing", root.join("dangling")).unwrap();

        for to in ["file", "dir", "dangling"] {
            assert_eq!(
                run(
                    root,
                    json!({"op": "rename", "path": "src", "to": to, "exclusive": true})
                )
                .unwrap_err(),
                ErrorCode::Exists,
                "{to}"
            );
        }
        assert_eq!(std::fs::read_to_string(root.join("file")).unwrap(), "old");
        assert!(root.join("dir").is_dir());
        assert!(!root.join("missing").exists(), "the link is not followed");
        assert_eq!(std::fs::read_to_string(root.join("src")).unwrap(), "new");

        run(
            root,
            json!({"op": "rename", "path": "src", "to": "free", "exclusive": true}),
        )
        .unwrap();
        assert_eq!(std::fs::read_to_string(root.join("free")).unwrap(), "new");
        assert!(!root.join("src").exists());
    }

    #[test]
    fn concurrent_exclusive_renames_have_exactly_one_winner() {
        const N: usize = 16;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        for i in 0..N {
            std::fs::write(root.join(format!("src-{i}")), format!("content-{i}")).unwrap();
        }
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(N));
        let threads: Vec<_> = (0..N)
            .map(|i| {
                let (root, barrier) = (root.clone(), std::sync::Arc::clone(&barrier));
                std::thread::spawn(move || {
                    barrier.wait();
                    let request = json!({"op": "rename", "path": format!("src-{i}"),
                                         "to": "dest", "exclusive": true});
                    (i, run(&root, request))
                })
            })
            .collect();
        let mut winners = Vec::new();
        for thread in threads {
            match thread.join().unwrap() {
                (i, Ok(_)) => winners.push(i),
                (_, Err(code)) => assert_eq!(code, ErrorCode::Exists),
            }
        }
        assert_eq!(winners.len(), 1, "{winners:?}");
        assert_eq!(
            std::fs::read_to_string(root.join("dest")).unwrap(),
            format!("content-{}", winners[0])
        );
        assert_eq!(
            std::fs::read_dir(&root).unwrap().count(),
            N,
            "losers keep their source"
        );
    }

    #[test]
    fn link_rename_moves_regular_files_and_refuses_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("a"), "a").unwrap();
        std::fs::write(root.join("taken"), "old").unwrap();
        std::fs::create_dir(root.join("d")).unwrap();
        std::os::unix::fs::symlink("missing", root.join("dangling")).unwrap();

        for to in ["taken", "d", "dangling"] {
            assert_eq!(
                link_rename(&root.join("a"), &root.join(to))
                    .unwrap_err()
                    .code,
                ErrorCode::Exists,
                "{to}"
            );
        }
        assert_eq!(std::fs::read_to_string(root.join("taken")).unwrap(), "old");
        link_rename(&root.join("a"), &root.join("b")).unwrap();
        assert_eq!(std::fs::read_to_string(root.join("b")).unwrap(), "a");
        assert!(!root.join("a").exists());
        assert_eq!(
            link_rename(&root.join("d"), &root.join("e"))
                .unwrap_err()
                .code,
            ErrorCode::Invalid
        );
        assert!(root.join("d").is_dir());
    }

    #[test]
    fn mkdir_list_stat_rename_remove() {
        let dir = tempfile::tempdir().unwrap();
        run(
            dir.path(),
            json!({"op": "mkdir", "path": "d/e", "recursive": true}),
        )
        .unwrap();
        assert_eq!(
            run(dir.path(), json!({"op": "mkdir", "path": "d"})).unwrap_err(),
            ErrorCode::Exists
        );
        std::fs::write(dir.path().join("d/f.txt"), "abc").unwrap();

        let listed = run(dir.path(), json!({"op": "list", "path": "d"})).unwrap();
        let entries = listed["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["name"], json!("e"));
        assert_eq!(entries[0]["type"], json!("dir"));
        assert_eq!(entries[1]["name"], json!("f.txt"));
        assert_eq!(entries[1]["type"], json!("file"));
        assert_eq!(entries[1]["size"], json!(3));

        let stat = run(dir.path(), json!({"op": "stat", "path": "d/f.txt"})).unwrap();
        assert_eq!(stat["stat"]["type"], json!("file"));
        assert_eq!(stat["stat"]["size"], json!(3));

        run(
            dir.path(),
            json!({"op": "rename", "path": "d/f.txt", "to": "d/g.txt"}),
        )
        .unwrap();
        assert!(dir.path().join("d/g.txt").exists());

        run(dir.path(), json!({"op": "remove", "path": "d/g.txt"})).unwrap();
        // A non-empty directory needs `recursive`.
        assert_eq!(
            run(dir.path(), json!({"op": "remove", "path": "d"})).unwrap_err(),
            ErrorCode::Io
        );
        run(
            dir.path(),
            json!({"op": "remove", "path": "d", "recursive": true}),
        )
        .unwrap();
        assert!(!dir.path().join("d").exists());
    }

    #[test]
    fn missing_path_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        for op in ["list", "stat", "remove"] {
            assert_eq!(
                run(dir.path(), json!({"op": op, "path": "nope"})).unwrap_err(),
                ErrorCode::NotFound,
                "{op}"
            );
        }
    }

    #[test]
    fn absolute_path_is_used_as_given() {
        let workspace = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let target = other.path().join("abs");
        run(workspace.path(), json!({"op": "mkdir", "path": target})).unwrap();
        assert!(target.is_dir());
    }
}
