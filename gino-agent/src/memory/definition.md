---
title: Memory definition
---

# How this memory works

This directory (`$GINO_MEMORY_DIR`) is the persistent memory of this task. It is
shared by every thread of this task (scheduled runs, new chats); other tasks
never see it. `index.md` is loaded into every new thread, so keep it small.

Facts true for every task on this agent go to the agent memory
(`$GINO_AGENT_MEMORY_DIR`) when it is available; task facts stay here.

## Claude native memory

`claude/` in this directory holds Claude Code's own auto memory (its
`MEMORY.md` and topic files). Claude writes and loads it itself, scoped to this
task. Do not put gino memory files there, and do not hand-edit Claude's files
unless correcting a wrong fact. This tree's `index.md` and topic files are the
cross-engine store every engine (Claude and Codex) reads: facts every engine
must know belong here, and anything meant for the whole agent belongs in the
agent memory. Engines other than Claude may read `$GINO_MEMORY_DIR/claude/` for
Claude's notes when useful.

## Store

- One topic per file; name files after their topic (e.g. `deploy-notes.md`).
- Add every new file to the Map in `index.md` with a one-line description.
- Put only the key facts the task must always remember in the Core memory
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

Parallel threads of this task share this directory and the last writer wins.
Re-read a file right before editing it and keep edits small.

## History

When `$GINO_CONVERSATIONS_DIR` is set, it holds read-only copies of the
archived transcripts of this task's earlier threads, one subdirectory per
thread. Read them for context and store only distilled facts in memory.
The view is a point-in-time copy taken when this thread started (archives
written by concurrently running threads appear on the next thread), and it may
be truncated to the newest archives.
