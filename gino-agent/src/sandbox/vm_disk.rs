//! Root disks of `vm` runs: the configured ext4 image as a shared read-only
//! base plus a qcow2 overlay holding the run's writes.
//!
//! Layout under `<workspace>/vm/disks/`:
//!
//! - `base/<sha256>.ext4`: the configured image, hard-linked (or copied) under
//!   its content hash; `base/index.json` caches the hash by file identity.
//! - `tasks/<taskId>/disk.json` and `root.qcow2`: a task disk, kept across the
//!   task's runs and removed with the task. The manifest pins its base, so a
//!   new image never rebases it; a base stays while a manifest names it.
//!
//! A run without a task disk gets an overlay in its run dir, removed with it.
//! A task disk has one writer: a run holds an exclusive lock on it, and a
//! concurrent run of the task gets a run overlay instead.

use std::fs::{self, File, TryLockError};
use std::io::{self, Read as _};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::memory::valid_task_id;
use crate::provisioning::store::hex_digest;

const DISKS_DIR: &str = "vm/disks";
const BASE_DIR: &str = "base";
const TASKS_DIR: &str = "tasks";
const INDEX_FILE: &str = "index.json";
const MANIFEST_FILE: &str = "disk.json";
const LOCK_FILE: &str = "disk.lock";
const OVERLAY_FILE: &str = "root.qcow2";
/// A run needs this share of the disk size free on the disks' filesystem.
const FREE_SPACE_DIVISOR: u64 = 4;
/// How long a busy task disk lock is retried before the run takes a run disk.
const LOCK_WAIT: Duration = Duration::from_secs(1);
const LOCK_POLL: Duration = Duration::from_millis(50);

/// The base image a run boots: its content hash and its file under `base/`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Base {
    pub(crate) sha256: String,
    pub(crate) path: PathBuf,
}

/// The overlay a run boots from; a task disk's lock is held while it lives.
#[derive(Debug)]
pub(crate) struct RootDisk {
    pub(crate) path: PathBuf,
    _lock: Option<File>,
}

/// `base/index.json`: the hash of the image last adopted, by file identity.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BaseIndex {
    image: PathBuf,
    dev: u64,
    ino: u64,
    size: u64,
    mtime_ns: i64,
    sha256: String,
}

/// `tasks/<taskId>/disk.json`.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    /// sha256 of the base image.
    base: String,
    /// Overlay files in the task dir, bottom to top; the last one is written.
    layers: Vec<String>,
    size_bytes: u64,
    created_at: String,
}

/// The disks dir of a workspace.
#[derive(Clone, Debug)]
pub(crate) struct DiskStore {
    root: PathBuf,
}

impl DiskStore {
    pub(crate) fn new(workspace_dir: &Path) -> Self {
        Self {
            root: workspace_dir.join(DISKS_DIR),
        }
    }

    /// Adopt `image` as a base: hash it unless the index already knows this
    /// file, place it under `base/<sha256>.ext4` and drop bases nothing
    /// references any more.
    pub(crate) fn base(&self, image: &Path) -> io::Result<Base> {
        let dir = self.root.join(BASE_DIR);
        create_private_dir(&dir)?;
        let lock = File::create(dir.join(".lock"))?;
        lock.lock()?;

        let meta = fs::metadata(image)?;
        let identity = |sha256: String| BaseIndex {
            image: image.to_path_buf(),
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.size(),
            mtime_ns: meta.mtime() * 1_000_000_000 + meta.mtime_nsec(),
            sha256,
        };
        let index_path = dir.join(INDEX_FILE);
        let known = fs::read(&index_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<BaseIndex>(&bytes).ok())
            .filter(|index| *index == identity(index.sha256.clone()));
        let sha256 = if let Some(index) = known {
            index.sha256
        } else {
            let sha256 = sha256_file(image)?;
            write_atomic(&index_path, &serde_json::to_vec(&identity(sha256.clone()))?)?;
            sha256
        };
        let path = dir.join(format!("{sha256}.ext4"));
        if !path.exists() {
            let staging = dir.join(format!(".{sha256}.tmp"));
            let _ = fs::remove_file(&staging);
            if fs::hard_link(image, &staging).is_err() {
                fs::copy(image, &staging)?;
            }
            fs::rename(&staging, &path)?;
        }
        self.remove_unused_bases(&sha256)?;
        Ok(Base { sha256, path })
    }

    /// A run overlay on `base` in `run_dir`, of `size` bytes.
    pub(crate) fn run_disk(&self, run_dir: &Path, base: &Base, size: u64) -> io::Result<RootDisk> {
        let size = disk_size(base, size)?;
        self.check_space(size)?;
        let path = run_dir.join(OVERLAY_FILE);
        create_overlay(&path, &base.path, size)?;
        Ok(RootDisk { path, _lock: None })
    }

    /// The task's disk, created on `base` with `size` bytes when it does not
    /// exist yet; `None` while another run holds it.
    pub(crate) fn task_disk(
        &self,
        task_id: &str,
        base: &Base,
        size: u64,
    ) -> io::Result<Option<RootDisk>> {
        if !valid_task_id(task_id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("task id `{task_id}` cannot name a disk dir"),
            ));
        }
        let dir = self.root.join(TASKS_DIR).join(task_id);
        create_private_dir(&dir)?;
        let lock = File::create(dir.join(LOCK_FILE))?;
        // A child forked elsewhere in the process holds a copy of the lock
        // until it execs, so a busy lock is retried briefly.
        let deadline = Instant::now() + LOCK_WAIT;
        loop {
            match lock.try_lock() {
                Ok(()) => break,
                Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                    std::thread::sleep(LOCK_POLL);
                }
                Err(TryLockError::WouldBlock) => return Ok(None),
                Err(TryLockError::Error(err)) => return Err(err),
            }
        }
        self.check_space(size)?;

        let manifest_path = dir.join(MANIFEST_FILE);
        let manifest = match fs::read(&manifest_path) {
            Ok(bytes) => serde_json::from_slice::<Manifest>(&bytes).map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: {err}", manifest_path.display()),
                )
            })?,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                let size = disk_size(base, size)?;
                create_overlay(&dir.join(OVERLAY_FILE), &base.path, size)?;
                let manifest = Manifest {
                    base: base.sha256.clone(),
                    layers: vec![OVERLAY_FILE.to_owned()],
                    size_bytes: size,
                    created_at: crate::scheduler::to_iso(crate::scheduler::now()),
                };
                write_atomic(&manifest_path, &serde_json::to_vec_pretty(&manifest)?)?;
                manifest
            }
            Err(err) => return Err(err),
        };
        let top = manifest.layers.last().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} lists no layers", manifest_path.display()),
            )
        })?;
        let base_path = self
            .root
            .join(BASE_DIR)
            .join(format!("{}.ext4", manifest.base));
        if !base_path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "the base {} of task disk {task_id} is missing",
                    manifest.base
                ),
            ));
        }
        Ok(Some(RootDisk {
            path: dir.join(top),
            _lock: Some(lock),
        }))
    }

    /// Fail unless the disks' filesystem has a quarter of `size` free.
    fn check_space(&self, size: u64) -> io::Result<()> {
        let stat = nix::sys::statvfs::statvfs(&self.root).map_err(io::Error::from)?;
        let free = stat.blocks_available() * stat.fragment_size();
        let needed = size / FREE_SPACE_DIVISOR;
        if free < needed {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                format!(
                    "{} has {} MiB free; a VM disk of {} MiB needs {} MiB",
                    self.root.display(),
                    free >> 20,
                    size >> 20,
                    needed >> 20
                ),
            ));
        }
        Ok(())
    }

    /// Remove `base/*.ext4` files other than `current` that no task manifest
    /// names.
    fn remove_unused_bases(&self, current: &str) -> io::Result<()> {
        let mut keep = vec![current.to_owned()];
        if let Ok(tasks) = fs::read_dir(self.root.join(TASKS_DIR)) {
            for task in tasks.flatten() {
                let manifest = fs::read(task.path().join(MANIFEST_FILE))
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<Manifest>(&bytes).ok());
                keep.extend(manifest.map(|m| m.base));
            }
        }
        for entry in fs::read_dir(self.root.join(BASE_DIR))?.flatten() {
            let name = entry.file_name();
            let Some(sha) = name.to_str().and_then(|n| n.strip_suffix(".ext4")) else {
                continue;
            };
            if !keep.iter().any(|k| k == sha) {
                fs::remove_file(entry.path())?;
            }
        }
        Ok(())
    }
}

/// Remove a task's disk dir; a missing dir or an invalid id is a no-op.
pub(crate) fn remove_task(workspace_dir: &Path, task_id: &str) -> io::Result<()> {
    if !valid_task_id(task_id) {
        return Ok(());
    }
    match fs::remove_dir_all(workspace_dir.join(DISKS_DIR).join(TASKS_DIR).join(task_id)) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

/// Create a sparse qcow2 image of `size` bytes backed by the raw `base`.
/// imago is async; it runs on a private runtime in its own thread, so this
/// works from inside the daemon's runtime too.
/// `size`, raised to the base image's size: a smaller disk would cut off its
/// filesystem.
fn disk_size(base: &Base, size: u64) -> io::Result<u64> {
    Ok(size.max(fs::metadata(&base.path)?.len()))
}

fn create_overlay(path: &Path, base: &Path, size: u64) -> io::Result<()> {
    use imago::{FormatCreateBuilder as _, Storage as _, StorageCreateOptions};

    let path = path.to_path_buf();
    let base = base
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "base path is not UTF-8"))?
        .to_owned();
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .build()?
            .block_on(async {
                let file =
                    imago::file::File::create_open(StorageCreateOptions::new().filename(&path))
                        .await?;
                imago::qcow2::Qcow2::<imago::file::File>::create_builder(file)
                    .size(size)
                    .backing(base, "raw".to_owned())
                    .create()
                    .await
            })
    })
    .join()
    .map_err(|_| io::Error::other("the qcow2 creation thread panicked"))?
}

fn sha256_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex_digest(hasher))
}

fn create_private_dir(dir: &Path) -> io::Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let staging = path.with_extension("tmp");
    fs::write(&staging, bytes)?;
    fs::rename(staging, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1 << 20;

    fn store() -> (tempfile::TempDir, DiskStore, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("rootfs.ext4");
        fs::write(&image, b"base image bytes").unwrap();
        let store = DiskStore::new(&dir.path().join("ws"));
        (dir, store, image)
    }

    /// The virtual size and the first bytes of a qcow2 image through its
    /// backing chain, as libkrun's block device reads it.
    fn read_overlay(path: &Path, len: usize) -> (u64, Vec<u8>) {
        let path = path.to_path_buf();
        std::thread::spawn(move || {
            let mut qcow2 =
                imago::qcow2::Qcow2::<imago::file::File>::open_path_sync(&path, false).unwrap();
            qcow2.open_implicit_dependencies_sync().unwrap();
            let access = imago::SyncFormatAccess::new(qcow2).unwrap();
            let mut buf = vec![0u8; len];
            access.read(&mut buf[..], 0).unwrap();
            (access.size(), buf)
        })
        .join()
        .unwrap()
    }

    #[test]
    fn base_is_content_addressed_and_cached() {
        let (_dir, store, image) = store();
        let base = store.base(&image).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(b"base image bytes");
        assert_eq!(base.sha256, hex_digest(hasher));
        assert_eq!(fs::read(&base.path).unwrap(), b"base image bytes");
        assert_eq!(store.base(&image).unwrap(), base);
    }

    #[test]
    fn a_new_image_replaces_an_unreferenced_base_but_keeps_pinned_ones() {
        let (_dir, store, image) = store();
        let first = store.base(&image).unwrap();
        store.task_disk("t1", &first, 64 * MIB).unwrap().unwrap();
        fs::remove_file(&image).unwrap();
        fs::write(&image, b"second image").unwrap();
        let second = store.base(&image).unwrap();
        assert_ne!(first.sha256, second.sha256);
        assert!(first.path.exists(), "pinned by t1");

        remove_task(store.root.parent().unwrap().parent().unwrap(), "t1").unwrap();
        fs::remove_file(&image).unwrap();
        fs::write(&image, b"third image").unwrap();
        store.base(&image).unwrap();
        assert!(!first.path.exists() && !second.path.exists());
    }

    #[test]
    fn run_disk_is_a_sparse_overlay_reading_through_to_the_base() {
        let (dir, store, image) = store();
        let base = store.base(&image).unwrap();
        let disk = store.run_disk(dir.path(), &base, 64 * MIB).unwrap();
        assert!(fs::metadata(&disk.path).unwrap().len() < MIB);
        let (size, head) = read_overlay(&disk.path, 16);
        assert_eq!(size, 64 * MIB);
        assert_eq!(head, b"base image bytes");
    }

    #[test]
    fn a_disk_is_never_smaller_than_its_base() {
        let (dir, store, image) = store();
        fs::write(&image, vec![7u8; 4096]).unwrap();
        let base = store.base(&image).unwrap();
        let disk = store.run_disk(dir.path(), &base, 512).unwrap();
        assert_eq!(read_overlay(&disk.path, 0).0, 4096);
        let disk = store.task_disk("t1", &base, 512).unwrap().unwrap();
        assert_eq!(read_overlay(&disk.path, 0).0, 4096);
    }

    #[test]
    fn task_disk_persists_and_has_one_writer() {
        let (_dir, store, image) = store();
        let base = store.base(&image).unwrap();
        let disk = store.task_disk("t1", &base, 64 * MIB).unwrap().unwrap();
        let manifest: Manifest = serde_json::from_slice(
            &fs::read(disk.path.parent().unwrap().join(MANIFEST_FILE)).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest.base, base.sha256);
        assert_eq!(manifest.layers, [OVERLAY_FILE]);
        assert_eq!(manifest.size_bytes, 64 * MIB);

        assert!(store.task_disk("t1", &base, 64 * MIB).unwrap().is_none());
        let path = disk.path.clone();
        drop(disk);
        let again = store.task_disk("t1", &base, 128 * MIB).unwrap().unwrap();
        assert_eq!(again.path, path);
        assert_eq!(read_overlay(&again.path, 0).0, 64 * MIB, "the size is kept");
    }

    #[test]
    fn invalid_task_ids_are_refused() {
        let (_dir, store, image) = store();
        let base = store.base(&image).unwrap();
        for id in ["", "..", "a/b"] {
            assert!(store.task_disk(id, &base, MIB).is_err(), "{id:?}");
            remove_task(Path::new("/nonexistent"), id).unwrap();
        }
    }

    #[test]
    fn too_little_free_space_fails() {
        let (_dir, store, image) = store();
        let base = store.base(&image).unwrap();
        let err = store.task_disk("t1", &base, u64::MAX).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::StorageFull);
    }
}
