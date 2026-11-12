# gino-agent - Task List

> Updated: 2026-11-10

## Usage

Each task is a single line linking to its detail file. All detailed information lives in `docs/task/<timestamp>-<feature-slug>.md`.

### Format

- [ ] [**20260907-1428-add-endpoint Add endpoint**](20260907-1428-add-endpoint.md) `P1`

### Status Markers

| Marker | Meaning |
|--------|---------|
| `[ ]`  | Pending |
| `[-]`  | In progress |
| `[x]`  | Completed |
| `[~]`  | Closed / Won't do |
| `[d]`  | Deleted detail file; index entry retained |

### Priority: P0 (blocking) > P1 (high) > P2 (medium) > P3 (low)

### Rules

- Only update the checkbox marker; never delete the line or change its other content. If the detail file is deleted, mark the entry `[d]`.
- Record change history and deletion reasons in `docs/changelog.md`; update affected dependency and plan references.
- New tasks append to the end.
- See each `<timestamp>-<feature-slug>.md` for full details, except `[d]` entries whose files have been deleted; consult `docs/changelog.md` for their history.

---

## Tasks

- [x] [**20261027-0613-vm-block-root-docker VM block root, task disks and Docker**](20261027-0613-vm-block-root-docker.md) `P1`
- [x] [**20261027-0613-engine-install-update Engine install and update**](20261027-0613-engine-install-update.md) `P1`
- [ ] [**20261027-0613-chunk-block-storage Chunk-based block storage engine**](20261027-0613-chunk-block-storage.md) `P2`
- [x] [**20261028-0050-vm-image-release Kernel, vmm and rootfs release channels with lode**](20261028-0050-vm-image-release.md) `P1`
- [x] [**20261101-1538-config-update-clear Host config updates can clear fields**](20261101-1538-config-update-clear.md) `P1`
- [-] [**20261105-0743-host-integration-readiness Single agent source and host integration readiness**](20261105-0743-host-integration-readiness.md) `P1`
- [x] [**20261110-1039-bks-runner-parity Runner settings, telemetry and exclusive file operations for bks**](20261110-1039-bks-runner-parity.md) `P1`
- [x] [**20261110-1130-mini-host-full-protocol Reference host covering the whole protocol**](20261110-1130-mini-host-full-protocol.md) `P1`
- [x] [**20261111-1000-engine-models-auth Engine model lists, auth status and per-engine defaults**](20261111-1000-engine-models-auth.md) `P1`
- [x] [**20261112-0220-engine-tree-symlinks No symlink following in engine-writable trees**](20261112-0220-engine-tree-symlinks.md) `P1`
