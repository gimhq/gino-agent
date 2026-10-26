---
title: Agent memory definition
---

# How this memory works

This directory (`$GINO_AGENT_MEMORY_DIR`) is the persistent memory of this
agent. It is shared by every task on this agent (and every thread of those
tasks). `index.md` is loaded into every new thread, so keep it small.

## What belongs here

- Facts true for every task on this agent: the environment, installed tools,
  conventions, recurring lessons.
- Never task-private or owner-private data: tasks on one agent can belong to
  different owners, and every one of them reads this memory. Task facts go to
  the task memory (`$GINO_MEMORY_DIR`).
- Claude Code's native auto memory is task-scoped (it lives in each task's
  `claude/` subdir); agent-wide facts go to this tree.

## Access

This memory may be read-only. Then the injected context says so and writes to
this directory fail; record what you learned in the task memory instead.

## Store

- One topic per file; name files after their topic (e.g. `toolchain.md`).
- Add every new file to the Map in `index.md` with a one-line description.
- Put only the key facts every task must always remember in the Core memory
  section of `index.md`.
- Prefer editing an existing entry over appending a new one.
- Write dates as absolute dates (`2026-01-31`), never "today" or "last week".

## Prune

- Remove stale entries and merge duplicates.
- Stay under the size cap. When the directory exceeds it, the injected context
  reports the current size and the cap; prune until it is back under.

## Correct

- Fix wrong facts in place.
- Delete facts that turned out to be false.

## Concurrency

Every task on this agent shares this directory and the last writer wins.
Re-read a file right before editing it and keep edits small.
