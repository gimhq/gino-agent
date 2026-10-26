# 20261027-0614-chunk-block-storage Chunk-based block storage engine

- **status**: draft
- **createdAt**: 2026-10-27 06:14
- **approvedAt**: (pending)
- **relatedTask**: 20261027-0613-chunk-block-storage

## Context

- Design: `/srv/docs/chunk-block-storage-design.md` (immutable objects in an S3-compatible store,
  a writable local overlay per volume, flattened manifests; ublk/NBD/vhost-user-blk frontends,
  UFFD memory snapshots, fork, hibernate, migration).
- After 20261027-0614-vm-block-root-docker, VM disks are a read-only base image plus qcow2
  overlays described by a per-task `disk.json` manifest, opened by libkrun's imago backend.
- libkrun fit: no snapshot/restore or userfaultfd, so memory snapshots, live fork, hibernate and
  migration are out of reach without changing the VMM. Guest memory is anonymous mmap, so
  vhost-user-blk needs a libkrun fork. ublk and NBD need host privileges the agent does not have.
  libkrun's block device holds a `Box<dyn DynStorage>` from imago, which is the cheapest place to
  plug a custom backend in-process.

## Proposal

- **Backend**: a `gino-blockstore` crate implementing imago's `Storage` over the design's data
  model (overlay sparse file + dirty bitmap, frozen layers, flattened manifest of extents to
  `BaseChunk`/`Pack`/`Zero`, host chunk cache, `object_store` client). A small libkrun patch adds a
  disk entry point taking a caller-provided storage object (to upstream; pinned fork meanwhile).
- **Scope of disks**: same as phase 1 (base + per-run or per-task volume), durability L0 by
  default; L2 (flush waits for the pack upload) per volume as an option. L1 replication,
  memory snapshots and fork stay out unless the VMM changes.
- **Migration from phase 1**: chunk the base image into content-addressed chunks; seal a task's
  qcow2 overlay into a pack and write its manifest; `disk.json` gains the volume id.
- **Roadmap**: the design's P0 (single-host engine passing fio/fsx and dm-log-writes power-fail
  replay) then P1 (object storage, lazy fetch, attach on another host). P2+ requires a VMM
  decision first.

## Risks

- Silent corruption from flush ordering or GC; the design's checksums, replay tests and GC grace
  period are prerequisites, not extras.
- Maintaining a libkrun patch until upstream accepts it.
- Object store choice and operations (Garage, SeaweedFS, Ceph RGW).

## Scope

New crate, gino-vmm integration, a libkrun fork pin, agent disk manager changes, catalog (SQLite in
the agent workspace for a single host), docs and a storage test harness. Separate approval
required before any work.

## Alternatives

- ublk frontend with libkrun on `/dev/ublkbN`: no libkrun patch, but needs root and kernel 6.0+.
- Switch to Firecracker or Cloud Hypervisor to gain vhost-user-blk, snapshots and UFFD: unlocks
  the full design at the cost of the libkrun stack (virtiofs root share, init, vsock mapping).

## Annotations

(none)
