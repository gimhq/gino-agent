# gino-agent - Plan Index

> Updated: 2026-10-27

## Usage

Each plan is a single line linking to its detail file. All detailed information lives in `docs/plan/<timestamp>-<feature-slug>.md`.

### Format

- [ ] [**20260907-1440-add-endpoint Add endpoint**](20260907-1440-add-endpoint.md) `YYYY-MM-DD`

### Status Markers

| Marker | Meaning |
|--------|---------|
| `[ ]`  | Draft / Pending review |
| `[-]`  | Approved / Implementing |
| `[x]`  | Completed |
| `[~]`  | Rejected / Abandoned |
| `[d]`  | Deleted detail file; index entry retained |

### Rules

- Only update the checkbox marker; never delete the line or change its other content. If the detail file is deleted, mark the entry `[d]`.
- Record change history and deletion reasons in `docs/changelog.md`; update affected task and plan references.
- New plans append to the end.
- See each `<timestamp>-<feature-slug>.md` for full details, except `[d]` entries whose files have been deleted; consult `docs/changelog.md` for their history.

---

## Plans

- [x] [**20261027-0614-vm-block-root-docker VM block root, task disks and Docker**](20261027-0614-vm-block-root-docker.md) `2026-10-27`
- [x] [**20261027-0614-engine-install-update Engine install and update**](20261027-0614-engine-install-update.md) `2026-10-27`
- [ ] [**20261027-0614-chunk-block-storage Chunk-based block storage engine**](20261027-0614-chunk-block-storage.md) `2026-10-27`
- [x] [**20261028-0050-vm-image-release Kernel, vmm and rootfs release channels with lode**](20261028-0050-vm-image-release.md) `2026-10-28`
