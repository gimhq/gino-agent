---
name: gino
description: Operate the gino agent from inside a task — show system info, schedule/cancel background work (crons), and inspect tasks and threads. Use when the user asks what this agent is or can do, wants a reminder / recurring check / periodic report, wants to stop a schedule, or asks about the status of tasks or runs.
---

# Gino agent operations

Use the runner's built-in CLI to inspect this agent and manage your own scheduled
work. No host access or tokens are needed — it talks to the local runner. The
binary is at **`$GINO_RUNNER_BIN`**; the current task is **`$GINO_TASK_ID`** (both
set in your environment). Every command is:

```bash
"$GINO_RUNNER_BIN" <area> <action> …
```

## 1. System info

```bash
"$GINO_RUNNER_BIN" system        # (alias: info)
```

Prints the agent id, version, host URL, workspace/db paths, capabilities, and live
counts (tasks, active crons, pending/running threads). Use it to answer "what is
this agent / what's running right now".

## 2. Crons (scheduled work)

A cron fires its **prompt** on a schedule; each fire runs that prompt as a turn of
the task.

```bash
# every day at 09:00 (5-field cron expression, UTC):
"$GINO_RUNNER_BIN" cron create --type cron --value "0 9 * * *" --prompt "Post the daily standup summary"
# every 30 minutes (interval is in MILLISECONDS):
"$GINO_RUNNER_BIN" cron create --type interval --value "1800000" --prompt "Check the build and report failures"
# once, at a local time:
"$GINO_RUNNER_BIN" cron create --type once --value "2026-02-01T15:30:00" --prompt "Remind me about the meeting"
```

- `--type`  : `cron` (5-field expr) | `interval` (ms) | `once` (ISO local time)
- `--value` : the expression / interval / timestamp
- `--prompt`: what to do on each fire (be specific)
- `--continuity` (optional): `isolated` (default, fresh session each fire) | `shared` (one ongoing thread)
- `--task-id` (optional): defaults to `$GINO_TASK_ID`

`create` prints the new cron id — **keep it** to manage the trigger:

```bash
CRON_ID=$("$GINO_RUNNER_BIN" cron create --type interval --value "3600000" --prompt "Hourly heartbeat")

"$GINO_RUNNER_BIN" cron list                 # this task's triggers
"$GINO_RUNNER_BIN" cron pause   "$CRON_ID"   # stop firing, keep it
"$GINO_RUNNER_BIN" cron resume  "$CRON_ID"   # start firing again
"$GINO_RUNNER_BIN" cron cancel  "$CRON_ID"   # cancel for good (alias of delete)
```

A new trigger starts firing within ~1 second (or at its first scheduled time), and
survives across your sessions until cancelled.

## 3. Tasks (read-only)

Tasks are assigned by the host; inspect them here.

```bash
"$GINO_RUNNER_BIN" task list            # id, status, kind, name
"$GINO_RUNNER_BIN" task show <task-id>  # the task + its threads + its crons
```

## 4. Threads (read-only)

A thread is one execution (a chat turn or a cron fire) under a task.

```bash
"$GINO_RUNNER_BIN" thread list                 # threads for $GINO_TASK_ID
"$GINO_RUNNER_BIN" thread list --task-id <id>  # threads for another task
"$GINO_RUNNER_BIN" thread show <thread-id>     # status, session id, result/error, prompt
```

## When to use

- **system** — "what can you do / what's running / which agent is this"
- **cron create** — reminders, recurring checks, daily/periodic reports, monitoring, "do X at/every …"
- **cron list / pause / resume / cancel** — manage existing schedules
- **task list / show** — check what work exists and its status
- **thread list / show** — inspect a specific run (succeeded/failed, session, output)

## Notes

- Cron expressions are 5-field (`min hour day month weekday`), evaluated in UTC; `interval` values are milliseconds.
- `task` and `thread` are read-only — tasks/threads are driven by the host and the runner; only crons are yours to create and cancel.
