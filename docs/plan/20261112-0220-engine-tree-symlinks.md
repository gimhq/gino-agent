# 20261112-0220-engine-tree-symlinks No symlink following in engine-writable trees

- **status**: completed
- **task**: [20261112-0220-engine-tree-symlinks](../task/20261112-0220-engine-tree-symlinks.md)

## Decisions

- Approved by the user 2026-11-12 (audit follow-up, items 1 and 2).
- `paths.rs` gains `open_dir_beneath`, `open_file_beneath`, `create_file_in`,
  `create_dir_beneath` and `touch_beneath`: a per-component walk with `O_NOFOLLOW` over
  `openat`, as the conversations view already does. `openat2(RESOLVE_NO_SYMLINKS)` was not used:
  container seccomp profiles still refuse it in places.
- The root's last component is not followed either: `project`, `.engine-home` and `inputs` are
  themselves engine-writable names.
- A file the daemon owns (`inputs/<name>`) replaces a planted link; a planted directory link is
  an error for that operation. A linked memory file renders as "not a regular file".

## Proposal

1. Helper and its tests in `paths.rs`.
2. Regression tests at the five sites (red), then the fixes: `memory::render_tree`,
   `attachments` (materialize, collect), `provisioning::store` (`link`, `remove_link`),
   `sandbox::bwrap::prepare_engine_home`, the VM placeholders, `executor::prepare_cwd`.
3. CI job `agent-sandbox`: bubblewrap, user namespaces and `/dev/net/tun` on the runner, then
   the ignored `tests/sandbox.rs` scenarios.
4. Gates, `scripts/sandbox-it.sh`, changelog.

## Risks

- `store::link` still removes a squatting non-symlink entry by path after its parent was opened
  without following links; an engine racing that window needs a live process in the same work
  dir, which a reconcile before the run does not have.
- The CI job is unverified until its first run: AppArmor on the runner image, the `tun` module
  and the tmpfs over `$HOME` (the checkout lives below it) are the open points.
- `tests/vm.rs` stays manual (`scripts/vm-it.sh`): it needs KVM plus the kernel, VMM and rootfs
  builds.
