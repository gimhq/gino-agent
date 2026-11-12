# 20261112-0220-engine-tree-symlinks No symlink following in engine-writable trees

- **status**: completed
- **priority**: P1
- **owner**: gino-main-session
- **createdAt**: 2026-11-12 02:20

## Description

Found by the 2026-11-12 repository audit. The daemon runs outside the engine's sandbox or VM,
yet several of its file operations inside trees the engine can write (a thread's work dir, a
task memory tree) followed symlinks, so a sandboxed engine could make the daemon read or write
host files:

- codex: the memory context read `index.md` / `system/definition.md` through a planted link
  into the next thread's first prompt;
- `output/` itself as a link: the linked directory's files were uploaded as artifacts;
- `inputs` or `inputs/<name>` as a link: the next turn's attachment was written through it;
- a linked directory under `project/`: provisioning created, replaced or removed entries
  outside the work dir;
- a link at `.engine-home` (or its `CLAUDE.md` / `skills`): mount targets were created through
  it.

The sandbox integration suite (`tests/sandbox.rs`) never ran in CI, so nothing guarded this
boundary.

Acceptance:

1. Each of the five operations refuses a planted symlink (or replaces the link, for a file the
   daemon owns) and touches nothing outside the tree; a regression test per operation fails
   before the fix.
2. One shared helper walks a path below a root with `O_NOFOLLOW`; the call sites use it.
3. CI runs `tests/sandbox.rs` on every push.
4. Agent gates and `scripts/sandbox-it.sh` pass.

- complete: agent gates pass (nextest 1009), sandbox-it 17/17; the agent-sandbox CI job awaits its first run
