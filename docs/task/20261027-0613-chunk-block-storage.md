# 20261027-0613-chunk-block-storage Chunk-based block storage engine

- **status**: pending
- **priority**: P2
- **owner**: (unassigned)
- **createdAt**: 2026-10-27 06:13

## Description

Phase 2 of VM storage: replace the qcow2 layer chain with the flattened-manifest engine of
`/srv/docs/chunk-block-storage-design.md` (content-addressed base chunks, delta packs, object
store as source of truth), plugged into gino-vmm as an in-process imago storage backend.

## ActiveForm

Building the chunk-based block storage engine

## Dependencies

- **blocked by**: 20261027-0613-vm-block-root-docker
- **blocks**: (none)

## Notes

Plan: [20261027-0614-chunk-block-storage](../plan/20261027-0614-chunk-block-storage.md) (draft, not approved)
