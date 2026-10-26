# 20261027-0613-vm-block-root-docker VM block root, task disks and Docker

- **status**: completed
- **priority**: P1
- **owner**: l1-gino
- **createdAt**: 2026-10-27 06:13

## Description

Boot `vm` runs from a block-device root: a shared read-only ext4 base image plus a writable
qcow2 overlay per run, kept per task when the task asks for it. Trim the guest kernel of devices a
libkrun guest never has, add what Docker needs, and run dockerd in the guest.

Acceptance:

- The guest root is `/dev/vda` (ext4, read-write, writes land in the overlay); workspace, memory,
  control and engine dirs stay virtiofs shares.
- An ephemeral run deletes its overlay; a task-scoped disk survives runs of the same task and is
  removed with the task; a concurrent run of a task whose disk is in use gets an ephemeral overlay.
- `docker run hello-world` (pulled through the allowlist exit) succeeds inside a `vm` run.
- The kernel fragment explicitly disables the unused options listed in the plan; `build.sh`
  verifies them; the guest still boots and runs claude.
- Gates, the KVM suite (`scripts/vm-it.sh`) and the host's `SANDBOX_MODE=vm` real-engine e2e pass.

## ActiveForm

Moving the VM guest to a block root with task disks and Docker

## Dependencies

- **blocked by**: (none)
- **blocks**: 20261027-0613-chunk-block-storage

## Notes

Plan: [20261027-0614-vm-block-root-docker](../plan/20261027-0614-vm-block-root-docker.md)

- complete: Block root, task disks and Docker in the guest; KVM suite, smoke and host real-engine e2e pass
