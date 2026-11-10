# 20261110-1130-mini-host-full-protocol Reference host covering the whole protocol

- **status**: completed
- **priority**: P1
- **owner**: gino-main-session
- **createdAt**: 2026-11-10 11:30

## Description

`gino-mini-host` is the reference base other host applications build on. It speaks only part
of `docs/protocol.md`, so a joint run against it cannot stand in for production. Make it
implement the whole protocol and gate releases on a joint run with the real agent.

Acceptance:

1. mini-host implements every frame of the §8 catalog and the §2 byte channel: host config with
   `config_update` and version, global and task provisioning, attachments both ways, `fs_request`
   (all ops, exclusive put/rename), terminals, end-to-end encrypted tasks (key directory,
   KeyPackage pool, DS log, Welcome, DS requests, an operator-side client that seals and opens),
   `close`, and every field the agent reports (heartbeat `capabilities`, `engines`, `e2ee`,
   `configVersion`, `defaults`; `thread_result` `engine`, `model`, `usage`).
2. An operator API drives each feature, documented in the crate docs and `docs/host-quickstart.md`.
3. A joint suite runs the real agent binary against mini-host for each protocol surface and
   passes; it is part of the release checklist.
4. protocol.md stale parts (terminal section's protocol version and Host SDK/Hono notes, §7
   terminal line) are corrected.
5. v0.3.0 is released only after the joint suite passes.

- complete: joint suite 13/13 against agent 0.3.0
