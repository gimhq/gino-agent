//! Provisioning reconcile / GC / repair orchestrator (agent-
//! architecture §9b).
//!
//! The [`Provisioner`] ties the merged provisioning pieces together: it diffs a
//! DESIRED [`ProvisioningEntry`] set against the installed `config_entries`
//! manifest, materializes the bytes/bundles into the content-addressed store
//! ([`store`]), (re)points the scope symlinks, and records the manifest rows —
//! plus refcount-GC of orphaned store entries and restart-repair of missing /
//! dangling links. It is **engine-agnostic**: it knows only `target`/`kind`; the
//! host chooses the meta-driven `target` per engine.
//!
//! Bytes arrive through the [`BlobFetcher`] seam (production: the
//! [`AttachmentManager`], reusing the content-addressed cache), so the
//! orchestrator does no host I/O itself and is unit-testable with a fake fetcher.
//! NO runner / executor / engine wiring lives here.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;
use tokio::sync::Mutex as AsyncMutex;
use tracing::{debug, warn};

use super::store::{self, EntryKind};
use super::{ProvisioningError, safe_link_path, short_id};
use crate::attachments::{AttachmentManager, run_blocking};
use crate::db::{ConfigEntryRow, Db};
use crate::protocol::frames::{EntryKind as WireKind, ProvisioningEntry};

/// Store sub-directory under the workspace dir. Mirrors the (private) canonical
/// `store::STORE_SUBDIR`: this is the one read-side that must enumerate the store
/// tree (the GC scan), and re-stating the name here avoids widening store.rs.
const STORE_SUBDIR: &str = "store";

// ===========================================================================
// Blob fetch seam
// ===========================================================================

/// Out-of-band byte/bundle fetch for one content-addressed artifact. Abstracted
/// as a trait so the [`Provisioner`] is unit-testable with a fake fetcher;
/// production wires the [`AttachmentManager`] impl (which serves from / fills the
/// Attachment cache and verifies integrity).
#[async_trait]
pub(crate) trait BlobFetcher: Send + Sync {
    /// Fetch + integrity-verify the bytes for `(reference, sha256)`. For a `dir`
    /// entry the bytes are an uncompressed tar; for a `file` entry the file bytes.
    async fn fetch(&self, reference: &str, sha256: &str) -> Result<Vec<u8>, ProvisioningError>;
}

#[async_trait]
impl BlobFetcher for AttachmentManager {
    async fn fetch(&self, reference: &str, sha256: &str) -> Result<Vec<u8>, ProvisioningError> {
        self.fetch_verified(reference, sha256, self.max_single_bytes())
            .await
            .map_err(|err| ProvisioningError::Fetch {
                reason: err.to_string(),
            })
    }
}

// ===========================================================================
// Provisioner
// ===========================================================================

/// The reconcile / GC / repair orchestrator over the content-addressed store +
/// `config_entries` manifest.
pub(crate) struct Provisioner {
    /// Workspace root that holds the `store/` tree (the store root passed to
    /// [`store`] primitives).
    workspace_dir: PathBuf,
    db: Arc<Mutex<Db>>,
    fetcher: Arc<dyn BlobFetcher>,
    /// Serializes GC against reconcile / repair so GC never removes a store entry
    /// a reconcile is mid-materializing, between materialize and link (the
    /// store-mutating critical sections).
    gc_lock: AsyncMutex<()>,
}

impl std::fmt::Debug for Provisioner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Provisioner")
            .field("workspace_dir", &self.workspace_dir)
            .finish_non_exhaustive()
    }
}

impl Provisioner {
    /// Build a provisioner over the workspace `store/` tree, the manifest `db`, and
    /// the byte `fetcher`.
    pub(crate) fn new(
        workspace_dir: PathBuf,
        db: Arc<Mutex<Db>>,
        fetcher: Arc<dyn BlobFetcher>,
    ) -> Self {
        Self {
            workspace_dir,
            db,
            fetcher,
            gc_lock: AsyncMutex::new(()),
        }
    }

    /// The host-proxy reference for a desired entry's bytes — content-addressed
    /// by full `sha256` on the host's blob route (`GET /agent/attachments?sha256=…`,
    /// authorized by desired-set membership). Content addressing, not the entry
    /// name: the name is a logical label, only the sha identifies the bytes the
    /// host actually serves (host configstore serve).
    fn reference_for(sha256: &str) -> String {
        format!("/agent/attachments?sha256={sha256}")
    }

    /// Reconcile `desired` against the installed `scope` manifest: ADD / REPOINT
    /// every desired entry (materialize the store entry if absent, (re)point the
    /// symlink under `scope_root`, upsert the row), then REMOVE the symlink + row
    /// for any installed `target` no longer desired. Idempotent — re-running with
    /// the same `desired` performs no fetch and leaves the rows unchanged.
    pub(crate) async fn reconcile(
        &self,
        scope: &str,
        scope_root: &Path,
        desired: &[ProvisioningEntry],
    ) -> Result<(), ProvisioningError> {
        // Serialize against GC (Risk 4): a store entry materialized below must not
        // be GC'd in the window before its symlink/row land.
        let _gc = self.gc_lock.lock().await;

        // Snapshot the installed rows for this scope (target -> row), used to keep
        // `installed_at` stable on an unchanged entry and to drive removals.
        let installed: HashMap<String, ConfigEntryRow> = {
            let db = lock_db(&self.db);
            db.list_config_entries(scope)?
                .into_iter()
                .map(|row| (row.target.clone(), row))
                .collect()
        };

        for entry in desired {
            self.materialize_and_link(scope, scope_root, entry, installed.get(&entry.target))
                .await?;
        }

        let desired_targets: HashSet<&str> =
            desired.iter().map(|entry| entry.target.as_str()).collect();
        for target in installed.keys() {
            if desired_targets.contains(target.as_str()) {
                continue;
            }
            store::remove_link(scope_root, target)?;
            lock_db(&self.db).delete_config_entry(scope, target)?;
            debug!(scope, target, "reconcile dropped entry no longer desired");
        }
        Ok(())
    }

    /// Materialize one entry into the store (fetch only when absent), (re)point its
    /// symlink, and upsert the manifest row. `existing` is the current row at this
    /// `(scope, target)` (for `installed_at` stability).
    async fn materialize_and_link(
        &self,
        scope: &str,
        scope_root: &Path,
        entry: &ProvisioningEntry,
        existing: Option<&ConfigEntryRow>,
    ) -> Result<(), ProvisioningError> {
        // Fail fast on a hostile `target` before any fetch / materialize (defense
        // in depth; `store::link` re-checks via the same guard).
        safe_link_path(scope_root, &entry.target)?;

        let kind = store_kind(entry.kind);
        let store_path = store::store_path(&self.workspace_dir, &entry.id, &entry.sha256)?;
        // Reuse requires full-hash re-verification: the short-id path
        // plus a shape check is not identity — a truncated post-crash file or a
        // tampered entry passes `is_file()` forever. A verified entry keeps the
        // re-reconcile fetch-free; anything else is evicted and re-fetched. The
        // sweep re-reads every byte of the entry → blocking pool.
        let verified = {
            let store_path = store_path.clone();
            let sha = entry.sha256.clone();
            run_blocking(move || store::verify_entry(&store_path, kind, &sha)).await?
        };
        if !verified {
            self.evict_and_materialize(&entry.id, &entry.sha256, kind)
                .await?;
        }
        // The (re)link itself is a handful of small syscalls (symlink + rename)
        // — cheap enough to stay inline on the async thread.
        let link_path = store::link(scope_root, &entry.target, &store_path, kind)?;

        // Keep `installed_at` stable when the row already points at this exact
        // sha256, so a no-op re-reconcile leaves the row byte-for-byte unchanged.
        let installed_at = match existing {
            Some(row) if row.sha256.eq_ignore_ascii_case(&entry.sha256) => row.installed_at.clone(),
            _ => now_iso(),
        };
        let row = ConfigEntryRow {
            id: 0, // assigned by SQLite on insert; ignored on the upsert path
            scope: scope.to_owned(),
            name: entry.id.clone(),
            sha256: entry.sha256.clone(),
            short: short_id(&entry.sha256).to_owned(),
            target: entry.target.clone(),
            kind: kind_label(kind).to_owned(),
            store_path: path_string(&store_path),
            link_path: path_string(&link_path),
            installed_at,
        };
        lock_db(&self.db).upsert_config_entry(&row)?;
        Ok(())
    }

    /// Evict the (missing/corrupt) store entry for `(name, sha256)`, fetch its
    /// bytes, and re-materialize it as `kind` — the shared heal path of
    /// reconcile and repair. Eviction stays ordered before the fetch (as
    /// before); the filesystem halves (tree removal, tar unpack / large-file
    /// write + seal) run on the blocking pool, only the fetch is async.
    async fn evict_and_materialize(
        &self,
        name: &str,
        sha256: &str,
        kind: EntryKind,
    ) -> Result<(), ProvisioningError> {
        {
            let ws = self.workspace_dir.clone();
            let name = name.to_owned();
            let sha = sha256.to_owned();
            run_blocking(move || store::remove_store_entry(&ws, &name, &sha)).await??;
        }
        let bytes = self
            .fetcher
            .fetch(&Self::reference_for(sha256), sha256)
            .await?;
        let ws = self.workspace_dir.clone();
        let name = name.to_owned();
        let sha = sha256.to_owned();
        run_blocking(move || match kind {
            EntryKind::File => store::materialize_file(&ws, &name, &sha, &bytes).map(|_| ()),
            EntryKind::Dir => store::materialize_dir(&ws, &name, &sha, &bytes).map(|_| ()),
        })
        .await??;
        Ok(())
    }

    /// Refcount-GC the store: remove every `store/<name>/<short>` entry that no
    /// `config_entries` row references (i.e. `count_store_refs(name, sha256) == 0`).
    /// Held under the GC lock so it never races a reconcile materialize (Risk 4).
    pub(crate) async fn gc(&self) -> Result<(), ProvisioningError> {
        let _gc = self.gc_lock.lock().await;

        // The referenced `(name, short)` set across all scopes — the store dir name
        // is `short` (= sha256[:12]), so refcount-by-(name,sha256) reduces to a
        // membership test on this set.
        let referenced: HashSet<(String, String)> = {
            let db = lock_db(&self.db);
            db.list_all_config_entries()?
                .into_iter()
                .map(|row| (row.name, row.short))
                .collect()
        };

        // The whole-store directory scan (plus tree deletions) is filesystem
        // work → blocking pool.
        let workspace_dir = self.workspace_dir.clone();
        run_blocking(move || gc_scan(&workspace_dir, &referenced)).await??;
        Ok(())
    }

    /// Release every manifest row for `scope` — the terminal-state cleanup.
    /// Dropping the rows removes the scope from the repair/GC root set: the
    /// store entries it referenced become refcount-orphans that the next
    /// [`Self::gc`] collects, and [`Self::repair`] no longer rebuilds the scope's
    /// symlink tree at startup. The on-disk symlinks are deliberately left in
    /// place: a task scope's root lives inside a terminal thread's `work_dir`,
    /// which is reclaimed as a whole by workspace lifecycle, not link by link.
    pub(crate) async fn release_scope(&self, scope: &str) -> Result<(), ProvisioningError> {
        // Serialize against GC / reconcile (Risk 4) so the row set GC refcounts
        // against is never observed mid-release.
        let _gc = self.gc_lock.lock().await;

        let db = lock_db(&self.db);
        let rows = db.list_config_entries(scope)?;
        for row in &rows {
            db.delete_config_entry(scope, &row.target)?;
        }
        if !rows.is_empty() {
            debug!(scope, released = rows.len(), "released provisioning scope");
        }
        Ok(())
    }

    /// Restart-repair (Risk 2): for each manifest row,
    /// full-hash verify the store entry — a missing/truncated/tampered entry is
    /// evicted, re-fetched and re-materialized; an intact one has its read-only
    /// sealing healed (a chmod'ed-back entry is re-sealed). A missing or dangling
    /// symlink is then recreated. Treats the FS as authoritative for bytes and
    /// the table as the index. Held under the GC lock.
    pub(crate) async fn repair(&self) -> Result<(), ProvisioningError> {
        let _gc = self.gc_lock.lock().await;

        let rows = {
            let db = lock_db(&self.db);
            db.list_all_config_entries()?
        };
        for row in rows {
            let Some(kind) = parse_kind(&row.kind) else {
                warn!(scope = %row.scope, target = %row.target, kind = %row.kind,
                    "repair: unknown entry kind, skipping");
                continue;
            };
            // Recompute the store path under the current workspace dir (robust to a
            // relocated workspace; the table stores an absolute snapshot only).
            let store_path = store::store_path(&self.workspace_dir, &row.name, &row.sha256)?;
            // Full-hash verification sweep + recursive re-seal both walk/read the
            // whole entry → one blocking-pool hop for the pair.
            let intact = {
                let store_path = store_path.clone();
                let sha = row.sha256.clone();
                run_blocking(move || -> Result<bool, ProvisioningError> {
                    if store::verify_entry(&store_path, kind, &sha) {
                        store::seal_entry(&store_path, kind)?;
                        Ok(true)
                    } else {
                        Ok(false)
                    }
                })
                .await??
            };
            if !intact {
                self.evict_and_materialize(&row.name, &row.sha256, kind)
                    .await?;
                warn!(scope = %row.scope, target = %row.target,
                    "repair re-fetched a missing or corrupt store entry");
            }
            let link_path = PathBuf::from(&row.link_path);
            if !link_broken(&link_path) {
                continue;
            }
            let Some(scope_root) = scope_root_of(&link_path, &row.target) else {
                warn!(target = %row.target, link = %row.link_path,
                    "repair: cannot derive scope root from link path, skipping");
                continue;
            };
            store::link(&scope_root, &row.target, &store_path, kind)?;
            debug!(scope = %row.scope, target = %row.target, "repair recreated symlink");
        }
        Ok(())
    }
}

// ===========================================================================
// Free helpers
// ===========================================================================

/// The filesystem half of [`Provisioner::gc`]: scan the store tree and remove
/// every `store/<name>/<short>` entry not in `referenced`. Extracted as a free
/// function so the whole scan-and-delete pass moves onto the blocking pool in
/// one hop.
fn gc_scan(
    workspace_dir: &Path,
    referenced: &HashSet<(String, String)>,
) -> Result<(), ProvisioningError> {
    let store_base = workspace_dir.join(STORE_SUBDIR);
    let names = match std::fs::read_dir(&store_base) {
        Ok(names) => names,
        // No store tree yet → nothing to collect.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err.into()),
    };
    for name_entry in names.flatten() {
        if !name_entry.file_type().is_ok_and(|ty| ty.is_dir()) {
            continue;
        }
        let Ok(name) = name_entry.file_name().into_string() else {
            continue;
        };
        let Ok(shorts) = std::fs::read_dir(name_entry.path()) else {
            continue;
        };
        for short_entry in shorts.flatten() {
            let Ok(short) = short_entry.file_name().into_string() else {
                continue;
            };
            // In-flight / stale temp siblings are not store entries; leave them
            // (a concurrent reconcile is serialized out by the GC lock anyway).
            if short.starts_with(".tmp.") {
                continue;
            }
            if referenced.contains(&(name.clone(), short.clone())) {
                continue;
            }
            // `short` is the on-disk dir name (= sha256[:12]); `store_path`
            // re-derives <short> via `short_id`, which is identity on a 12-char
            // input, so passing `short` as the sha key targets exactly this dir.
            store::remove_store_entry(workspace_dir, &name, &short)?;
            debug!(name, short, "gc removed unreferenced store entry");
        }
    }
    Ok(())
}

/// Poison-tolerant DB lock (mirrors `executor::lock_db`, Lock 6): recover the
/// guard rather than panic. Critical sections are short and never span an `.await`.
fn lock_db(db: &Mutex<Db>) -> MutexGuard<'_, Db> {
    db.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The current instant as the host-aligned ISO timestamp (millisecond `…Z`).
fn now_iso() -> String {
    crate::scheduler::to_iso(crate::scheduler::now())
}

/// Map the wire [`WireKind`] onto the store's [`EntryKind`] (same two shapes).
fn store_kind(kind: WireKind) -> EntryKind {
    match kind {
        WireKind::File => EntryKind::File,
        WireKind::Dir => EntryKind::Dir,
    }
}

/// The `config_entries.kind` column label for a store [`EntryKind`].
fn kind_label(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::File => "file",
        EntryKind::Dir => "dir",
    }
}

/// Parse a `config_entries.kind` column back to an [`EntryKind`] (`None` on a
/// corrupt/unknown value — reconcile only ever writes `file`/`dir`).
fn parse_kind(kind: &str) -> Option<EntryKind> {
    match kind {
        "file" => Some(EntryKind::File),
        "dir" => Some(EntryKind::Dir),
        _ => None,
    }
}

/// Whether the link at `link_path` is missing or dangling (so repair must
/// recreate it): absent entirely, or a symlink whose target does not resolve.
fn link_broken(link_path: &Path) -> bool {
    match std::fs::symlink_metadata(link_path) {
        // Missing (NotFound) or otherwise unreadable → treat as broken.
        Err(_) => true,
        // Present as a link/file: `metadata` follows the link, so an error means a
        // dangling symlink; success means it resolves and is fine.
        Ok(_) => std::fs::metadata(link_path).is_err(),
    }
}

/// Derive the scope root from a stored `link_path` and its `target`: strip the
/// `target`'s components off the tail (since `link_path == scope_root.join(target)`).
/// `None` if `link_path` is shorter than `target` (a corrupt row).
fn scope_root_of(link_path: &Path, target: &str) -> Option<PathBuf> {
    let depth = Path::new(target).components().count();
    let mut root = link_path.to_path_buf();
    for _ in 0..depth {
        if !root.pop() {
            return None;
        }
    }
    Some(root)
}

/// Render a path for storage in the manifest (`store_path` / `link_path` columns).
fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;

    use super::{BlobFetcher, Provisioner};
    use crate::attachments::sha256_hex;
    use crate::db::Db;
    use crate::protocol::frames::{EntryKind, ProvisioningEntry};
    use crate::provisioning::{ProvisioningError, store};

    /// In-memory fetcher keyed by `reference`, counting fetches to prove the store
    /// short-circuits re-fetch. It asserts the served bytes match the requested
    /// `sha256`, mirroring the real fetcher's integrity contract.
    #[derive(Default)]
    struct FakeFetcher {
        blobs: Mutex<HashMap<String, Vec<u8>>>,
        fetches: AtomicUsize,
    }

    impl FakeFetcher {
        fn insert(&self, reference: &str, bytes: &[u8]) {
            self.blobs
                .lock()
                .unwrap()
                .insert(reference.to_owned(), bytes.to_vec());
        }
        fn fetch_count(&self) -> usize {
            self.fetches.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl BlobFetcher for FakeFetcher {
        async fn fetch(&self, reference: &str, sha256: &str) -> Result<Vec<u8>, ProvisioningError> {
            self.fetches.fetch_add(1, Ordering::SeqCst);
            let bytes = self
                .blobs
                .lock()
                .unwrap()
                .get(reference)
                .cloned()
                .ok_or_else(|| ProvisioningError::Fetch {
                    reason: format!("no blob at {reference}"),
                })?;
            assert_eq!(
                sha256_hex(&bytes),
                sha256,
                "fake blob sha mismatch at {reference}"
            );
            Ok(bytes)
        }
    }

    /// An uncompressed tar built in-memory from `(path, bytes)` members.
    fn build_tar(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, data) in members {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            builder.append_data(&mut header, path, *data).unwrap();
        }
        builder.into_inner().unwrap()
    }

    fn entry(id: &str, target: &str, kind: EntryKind, bytes: &[u8]) -> ProvisioningEntry {
        ProvisioningEntry {
            id: id.to_owned(),
            sha256: sha256_hex(bytes),
            target: target.to_owned(),
            kind,
        }
    }

    /// A provisioner over a fresh in-memory DB + the `fake` fetcher. Returns the DB
    /// handle too so the test can inspect the manifest rows.
    fn provisioner(ws: &Path, fake: &Arc<FakeFetcher>) -> (Provisioner, Arc<Mutex<Db>>) {
        let db = Arc::new(Mutex::new(Db::open_in_memory().unwrap()));
        // Clone the concrete handle, then coerce to the trait object (unsizing
        // happens at the `let`, not inside `Arc::clone`).
        let concrete = Arc::clone(fake);
        let fetcher: Arc<dyn BlobFetcher> = concrete;
        (
            Provisioner::new(ws.to_path_buf(), Arc::clone(&db), fetcher),
            db,
        )
    }

    /// The content-addressed reference the provisioner fetches for `bytes`.
    fn blob_ref(bytes: &[u8]) -> String {
        format!("/agent/attachments?sha256={}", sha256_hex(bytes))
    }

    fn rows(db: &Arc<Mutex<Db>>, scope: &str) -> Vec<crate::db::ConfigEntryRow> {
        db.lock().unwrap().list_config_entries(scope).unwrap()
    }

    #[tokio::test]
    async fn reconcile_adds_file_and_dir_then_is_idempotent() {
        let ws = tempfile::tempdir().unwrap();
        let fake = Arc::new(FakeFetcher::default());
        let (prov, db) = provisioner(ws.path(), &fake);
        let scope_root = ws.path().join("global");

        let file_bytes = b"# CLAUDE.md\n";
        let tar = build_tar(&[("SKILL.md", b"# demo\n"), ("run.sh", b"#!/bin/sh\n")]);
        let file_entry = entry("claude-md", "CLAUDE.md", EntryKind::File, file_bytes);
        let dir_entry = entry("demo-skill", ".claude/skills/demo", EntryKind::Dir, &tar);
        fake.insert(&blob_ref(file_bytes), file_bytes);
        fake.insert(&blob_ref(&tar), &tar);
        let desired = vec![file_entry.clone(), dir_entry.clone()];

        prov.reconcile("global", &scope_root, &desired)
            .await
            .unwrap();

        // Symlinks resolve to the stored bytes.
        assert_eq!(
            std::fs::read(scope_root.join("CLAUDE.md")).unwrap(),
            file_bytes
        );
        assert_eq!(
            std::fs::read(scope_root.join(".claude/skills/demo/SKILL.md")).unwrap(),
            b"# demo\n"
        );
        // Store entries of the right shape exist.
        assert!(
            store::store_path(ws.path(), "claude-md", &file_entry.sha256)
                .unwrap()
                .is_file()
        );
        assert!(
            store::store_path(ws.path(), "demo-skill", &dir_entry.sha256)
                .unwrap()
                .is_dir()
        );
        // Manifest rows present (one per target).
        assert_eq!(rows(&db, "global").len(), 2);
        assert_eq!(fake.fetch_count(), 2);

        // Second reconcile (same desired) is a no-op: no extra fetch, and the rows
        // (incl. `installed_at` and the SQLite id) are byte-for-byte unchanged.
        let before = rows(&db, "global");
        prov.reconcile("global", &scope_root, &desired)
            .await
            .unwrap();
        assert_eq!(fake.fetch_count(), 2, "store hit avoids re-fetch");
        assert_eq!(before, rows(&db, "global"), "idempotent: rows unchanged");
    }

    #[tokio::test]
    async fn reconcile_repoints_on_new_sha() {
        let ws = tempfile::tempdir().unwrap();
        let fake = Arc::new(FakeFetcher::default());
        let (prov, db) = provisioner(ws.path(), &fake);
        let scope_root = ws.path().join("global");

        let v1 = b"VERSION-1\n";
        let e1 = entry("claude-md", "CLAUDE.md", EntryKind::File, v1);
        fake.insert(&blob_ref(v1), v1);
        prov.reconcile("global", &scope_root, std::slice::from_ref(&e1))
            .await
            .unwrap();
        assert_eq!(std::fs::read(scope_root.join("CLAUDE.md")).unwrap(), v1);

        // Same (scope, target), new bytes → new sha. The blob at the same reference
        // is replaced with the new version.
        let v2 = b"VERSION-2\n";
        let e2 = entry("claude-md", "CLAUDE.md", EntryKind::File, v2);
        fake.insert(&blob_ref(v2), v2);
        prov.reconcile("global", &scope_root, std::slice::from_ref(&e2))
            .await
            .unwrap();

        // The symlink repoints to v2 and exactly one row remains, sha/short updated.
        assert_eq!(std::fs::read(scope_root.join("CLAUDE.md")).unwrap(), v2);
        let manifest = rows(&db, "global");
        assert_eq!(manifest.len(), 1);
        assert_eq!(manifest[0].sha256, e2.sha256);
        assert_eq!(manifest[0].short, &e2.sha256[..12]);
        // Both store versions persist until GC.
        assert!(
            store::store_path(ws.path(), "claude-md", &e1.sha256)
                .unwrap()
                .is_file()
        );
        assert!(
            store::store_path(ws.path(), "claude-md", &e2.sha256)
                .unwrap()
                .is_file()
        );
    }

    #[tokio::test]
    async fn reconcile_removes_dropped_entry() {
        let ws = tempfile::tempdir().unwrap();
        let fake = Arc::new(FakeFetcher::default());
        let (prov, db) = provisioner(ws.path(), &fake);
        let scope_root = ws.path().join("global");

        let a = entry("claude-md", "CLAUDE.md", EntryKind::File, b"A\n");
        let b = entry("agents-md", "AGENTS.md", EntryKind::File, b"B\n");
        fake.insert(&blob_ref(b"A\n"), b"A\n");
        fake.insert(&blob_ref(b"B\n"), b"B\n");
        prov.reconcile("global", &scope_root, &[a.clone(), b.clone()])
            .await
            .unwrap();
        assert!(scope_root.join("AGENTS.md").exists());

        // Drop `b` from desired → its symlink + row go; `a` survives.
        prov.reconcile("global", &scope_root, std::slice::from_ref(&a))
            .await
            .unwrap();
        assert!(scope_root.join("CLAUDE.md").exists());
        assert!(!scope_root.join("AGENTS.md").exists());
        let manifest = rows(&db, "global");
        assert_eq!(manifest.len(), 1);
        assert_eq!(manifest[0].target, "CLAUDE.md");
    }

    #[tokio::test]
    async fn gc_removes_only_unreferenced_store_entries() {
        let ws = tempfile::tempdir().unwrap();
        let fake = Arc::new(FakeFetcher::default());
        let (prov, _db) = provisioner(ws.path(), &fake);
        let scope_root = ws.path().join("global");

        let keep = entry("keep", "KEEP.md", EntryKind::File, b"KEEP\n");
        fake.insert(&blob_ref(b"KEEP\n"), b"KEEP\n");
        let v1 = entry("cfg", "CFG.md", EntryKind::File, b"v1\n");
        fake.insert(&blob_ref(b"v1\n"), b"v1\n");
        prov.reconcile("global", &scope_root, &[keep.clone(), v1.clone()])
            .await
            .unwrap();

        // Repoint cfg → v2: leaves the v1 store entry unreferenced.
        let v2 = entry("cfg", "CFG.md", EntryKind::File, b"v2\n");
        fake.insert(&blob_ref(b"v2\n"), b"v2\n");
        prov.reconcile("global", &scope_root, &[keep.clone(), v2.clone()])
            .await
            .unwrap();
        assert!(
            store::store_path(ws.path(), "cfg", &v1.sha256)
                .unwrap()
                .is_file()
        );

        prov.gc().await.unwrap();

        // The orphaned v1 is gone; v2 (referenced) and keep (referenced) survive.
        assert!(
            !store::store_path(ws.path(), "cfg", &v1.sha256)
                .unwrap()
                .exists()
        );
        assert!(
            store::store_path(ws.path(), "cfg", &v2.sha256)
                .unwrap()
                .is_file()
        );
        assert!(
            store::store_path(ws.path(), "keep", &keep.sha256)
                .unwrap()
                .is_file()
        );
        // The live symlink still resolves to v2.
        assert_eq!(std::fs::read(scope_root.join("CFG.md")).unwrap(), b"v2\n");
    }

    #[tokio::test]
    async fn repair_recreates_symlink_from_present_store() {
        let ws = tempfile::tempdir().unwrap();
        let fake = Arc::new(FakeFetcher::default());
        let (prov, _db) = provisioner(ws.path(), &fake);
        let scope_root = ws.path().join("global");

        let bytes = b"# CLAUDE.md\n";
        let e = entry("claude-md", "CLAUDE.md", EntryKind::File, bytes);
        fake.insert(&blob_ref(bytes), bytes);
        prov.reconcile("global", &scope_root, std::slice::from_ref(&e))
            .await
            .unwrap();
        let link = scope_root.join("CLAUDE.md");

        // Delete only the symlink (store entry stays present).
        std::fs::remove_file(&link).unwrap();
        assert!(!link.exists());
        let before = fake.fetch_count();

        prov.repair().await.unwrap();

        assert_eq!(std::fs::read(&link).unwrap(), bytes);
        assert_eq!(fake.fetch_count(), before, "store present → no re-fetch");
    }

    #[tokio::test]
    async fn repair_refetches_when_store_entry_also_gone() {
        let ws = tempfile::tempdir().unwrap();
        let fake = Arc::new(FakeFetcher::default());
        let (prov, _db) = provisioner(ws.path(), &fake);
        let scope_root = ws.path().join("global");

        let tar = build_tar(&[("SKILL.md", b"# demo\n")]);
        let e = entry("demo-skill", ".claude/skills/demo", EntryKind::Dir, &tar);
        fake.insert(&blob_ref(&tar), &tar);
        prov.reconcile("global", &scope_root, std::slice::from_ref(&e))
            .await
            .unwrap();
        let link = scope_root.join(".claude/skills/demo");
        let store_path = store::store_path(ws.path(), "demo-skill", &e.sha256).unwrap();

        // Delete BOTH the symlink and the store entry.
        std::fs::remove_file(&link).unwrap();
        store::remove_store_entry(ws.path(), "demo-skill", &e.sha256).unwrap();
        assert!(!store_path.exists());
        let before = fake.fetch_count();

        prov.repair().await.unwrap();

        // The store entry is re-fetched + re-materialized and the link recreated.
        assert_eq!(fake.fetch_count(), before + 1, "store gone → re-fetch");
        assert!(store_path.is_dir());
        assert_eq!(std::fs::read(link.join("SKILL.md")).unwrap(), b"# demo\n");
    }

    /// Releasing a scope drops its manifest rows, which unroots the scope
    /// from repair (a lost link stays gone, nothing re-fetched) and lets GC
    /// collect the now-unreferenced store entry. The on-disk symlink itself is
    /// left in place — the dead scope root is reclaimed wholesale elsewhere.
    #[tokio::test]
    async fn release_scope_unroots_rows_from_repair_and_gc() {
        let ws = tempfile::tempdir().unwrap();
        let fake = Arc::new(FakeFetcher::default());
        let (prov, db) = provisioner(ws.path(), &fake);
        let scope_root = ws.path().join("t1-project");

        let e = entry("task-claude", "CLAUDE.md", EntryKind::File, b"X\n");
        fake.insert(&blob_ref(b"X\n"), b"X\n");
        prov.reconcile("t1", &scope_root, std::slice::from_ref(&e))
            .await
            .unwrap();
        assert_eq!(rows(&db, "t1").len(), 1);

        prov.release_scope("t1").await.unwrap();
        assert!(rows(&db, "t1").is_empty());
        let link = scope_root.join("CLAUDE.md");
        assert!(link.exists(), "release leaves the on-disk link in place");

        // Released rows no longer root repair: a removed link stays gone.
        std::fs::remove_file(&link).unwrap();
        let before = fake.fetch_count();
        prov.repair().await.unwrap();
        assert!(!link.exists(), "released scope must not be repaired");
        assert_eq!(fake.fetch_count(), before, "repair must not re-fetch");

        // ...and GC collects the now-unreferenced store entry.
        prov.gc().await.unwrap();
        assert!(
            !store::store_path(ws.path(), "task-claude", &e.sha256)
                .unwrap()
                .exists()
        );
    }

    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn chmod(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// Acceptance: a post-crash zero-length store file passes `is_file()`
    /// but fails full-hash re-verification — reconcile evicts and re-fetches it
    /// instead of silently reusing the corrupt entry.
    #[tokio::test]
    async fn reconcile_heals_truncated_store_file() {
        let ws = tempfile::tempdir().unwrap();
        let fake = Arc::new(FakeFetcher::default());
        let (prov, _db) = provisioner(ws.path(), &fake);
        let scope_root = ws.path().join("global");

        let bytes = b"# CLAUDE.md\n";
        let e = entry("claude-md", "CLAUDE.md", EntryKind::File, bytes);
        fake.insert(&blob_ref(bytes), bytes);
        let desired = vec![e.clone()];
        prov.reconcile("global", &scope_root, &desired)
            .await
            .unwrap();
        let store_file = store::store_path(ws.path(), "claude-md", &e.sha256).unwrap();

        // Simulate the crash artifact: replace the entry with a zero-length file.
        std::fs::remove_file(&store_file).unwrap();
        std::fs::write(&store_file, b"").unwrap();
        assert!(store_file.is_file(), "the corrupt entry passes is_file()");
        let before = fake.fetch_count();

        prov.reconcile("global", &scope_root, &desired)
            .await
            .unwrap();

        assert_eq!(fake.fetch_count(), before + 1, "hash mismatch → re-fetch");
        assert_eq!(std::fs::read(&store_file).unwrap(), bytes);
        assert_eq!(std::fs::read(scope_root.join("CLAUDE.md")).unwrap(), bytes);
        assert_eq!(mode_of(&store_file), 0o444, "healed entry is re-sealed");
    }

    /// Acceptance: an entry tampered through the store path (the symlink
    /// write-through poisoning scenario) is detected by repair's full-hash
    /// verification, evicted, and re-fetched.
    #[tokio::test]
    async fn repair_heals_tampered_entry() {
        let ws = tempfile::tempdir().unwrap();
        let fake = Arc::new(FakeFetcher::default());
        let (prov, _db) = provisioner(ws.path(), &fake);
        let scope_root = ws.path().join("global");

        let bytes = b"# CLAUDE.md\n";
        let e = entry("claude-md", "CLAUDE.md", EntryKind::File, bytes);
        fake.insert(&blob_ref(bytes), bytes);
        prov.reconcile("global", &scope_root, std::slice::from_ref(&e))
            .await
            .unwrap();
        let store_file = store::store_path(ws.path(), "claude-md", &e.sha256).unwrap();
        let link = scope_root.join("CLAUDE.md");

        // Tamper through the store path after a chmod-back (a same-uid process
        // can always do this — the read-only bits only stop casual writes).
        chmod(&store_file, 0o644);
        std::fs::write(&link, b"# CLAUDE.md\nEVIL APPENDED\n").unwrap();
        let before = fake.fetch_count();

        prov.repair().await.unwrap();

        assert_eq!(fake.fetch_count(), before + 1, "tampered → re-fetch");
        assert_eq!(std::fs::read(&store_file).unwrap(), bytes);
        assert_eq!(std::fs::read(&link).unwrap(), bytes);
        assert_eq!(mode_of(&store_file), 0o444, "healed entry is re-sealed");
    }

    /// Acceptance: an intact entry whose read-only sealing was chmod'ed
    /// back is re-sealed by repair without any re-fetch.
    #[tokio::test]
    async fn repair_reseals_chmod_back_entry_without_refetch() {
        let ws = tempfile::tempdir().unwrap();
        let fake = Arc::new(FakeFetcher::default());
        let (prov, _db) = provisioner(ws.path(), &fake);
        let scope_root = ws.path().join("global");

        let file_bytes = b"# CLAUDE.md\n";
        let tar = build_tar(&[("SKILL.md", b"# demo\n")]);
        let fe = entry("claude-md", "CLAUDE.md", EntryKind::File, file_bytes);
        let de = entry("demo-skill", ".claude/skills/demo", EntryKind::Dir, &tar);
        fake.insert(&blob_ref(file_bytes), file_bytes);
        fake.insert(&blob_ref(&tar), &tar);
        prov.reconcile("global", &scope_root, &[fe.clone(), de.clone()])
            .await
            .unwrap();
        let store_file = store::store_path(ws.path(), "claude-md", &fe.sha256).unwrap();
        let store_dir = store::store_path(ws.path(), "demo-skill", &de.sha256).unwrap();

        // Chmod back (content intact).
        chmod(&store_file, 0o644);
        chmod(&store_dir, 0o755);
        chmod(&store_dir.join("SKILL.md"), 0o644);
        let before = fake.fetch_count();

        prov.repair().await.unwrap();

        assert_eq!(fake.fetch_count(), before, "intact content → no re-fetch");
        assert_eq!(mode_of(&store_file), 0o444);
        assert_eq!(mode_of(&store_dir), 0o555);
        assert_eq!(mode_of(&store_dir.join("SKILL.md")), 0o444);
    }

    /// Seam: reconciles of distinct scopes driven concurrently — with the
    /// verify / unpack / materialize work hopping through the blocking pool —
    /// land every symlink and manifest row correctly, and the shared dir bundle
    /// is still fetched exactly once (the reconciles serialize on the GC lock,
    /// so later scopes verify-hit the store entry the first one materialized).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_reconciles_land_all_entries() {
        let ws = tempfile::tempdir().unwrap();
        let fake = Arc::new(FakeFetcher::default());
        let (prov, db) = provisioner(ws.path(), &fake);
        let prov = Arc::new(prov);

        let tar = build_tar(&[("SKILL.md", b"# demo\n")]);
        fake.insert(&blob_ref(&tar), &tar);
        let mut handles = Vec::new();
        for i in 0..4 {
            let file_bytes = format!("# scope {i}\n").into_bytes();
            fake.insert(&blob_ref(&file_bytes), &file_bytes);
            let desired = vec![
                entry(
                    &format!("cfg-{i}"),
                    "CLAUDE.md",
                    EntryKind::File,
                    &file_bytes,
                ),
                entry("demo-skill", ".claude/skills/demo", EntryKind::Dir, &tar),
            ];
            let scope_root = ws.path().join(format!("t{i}-project"));
            let prov = Arc::clone(&prov);
            handles.push(tokio::spawn(async move {
                prov.reconcile(&format!("t{i}"), &scope_root, &desired)
                    .await
                    .unwrap();
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }

        for i in 0..4 {
            let scope_root = ws.path().join(format!("t{i}-project"));
            assert_eq!(
                std::fs::read(scope_root.join("CLAUDE.md")).unwrap(),
                format!("# scope {i}\n").as_bytes()
            );
            assert_eq!(
                std::fs::read(scope_root.join(".claude/skills/demo/SKILL.md")).unwrap(),
                b"# demo\n"
            );
            assert_eq!(rows(&db, &format!("t{i}")).len(), 2);
        }
        assert_eq!(
            fake.fetch_count(),
            5,
            "4 per-scope files + the shared bundle exactly once"
        );
    }

    #[tokio::test]
    async fn reconcile_rejects_traversal_target() {
        let ws = tempfile::tempdir().unwrap();
        let fake = Arc::new(FakeFetcher::default());
        let (prov, db) = provisioner(ws.path(), &fake);
        let scope_root = ws.path().join("global");

        let evil = entry("evil", "../escape", EntryKind::File, b"PWNED\n");
        fake.insert(&blob_ref(b"PWNED\n"), b"PWNED\n");
        let err = prov
            .reconcile("global", &scope_root, &[evil])
            .await
            .unwrap_err();
        assert!(matches!(err, ProvisioningError::UnsafeTarget { .. }));
        // Fail-fast: rejected before any fetch, and no symlink escaped the scope.
        assert_eq!(fake.fetch_count(), 0);
        assert!(!ws.path().join("escape").exists());
        assert!(rows(&db, "global").is_empty());
    }
}
