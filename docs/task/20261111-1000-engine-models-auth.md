# 20261111-1000-engine-models-auth Engine model lists, auth status and per-engine defaults

- **status**: completed
- **priority**: P1
- **owner**: gino-main-session
- **createdAt**: 2026-11-11 10:00

## Description

A host cannot see which models an agent's engines offer, whether each engine is signed in, or
what a task without a model runs on for an engine other than claude; the default engine is
fixed to claude. Both CLIs can report their own model list and auth state, so the agent probes
them and reports the result.

Acceptance:

1. Heartbeat `engines[]` items carry `auth` (`authenticated` | `unauthenticated` | `unknown`),
   `models` (`[{id, name?, description?, isDefault?}]`, as the CLI reports them), `defaultModel`
   and `baseUrlHost`. The probe runs with the same binary, credentials and config dir as a real
   run; it reruns after a `config_update` that changes them, and hourly.
2. `config.engine.defaultEngine` selects the engine of a task that names none (`null` clears it
   back to `claude`); `defaults` reports that engine with its effective default model.
3. The agent never rewrites a requested model.
4. mini-host rejects a task whose engine the agent does not advertise, or whose model is not in
   the reported list for that engine, with 400.
5. The e2e fakes speak both probes; a joint scenario covers the probe, a re-probe after a
   credential change, the default engine and the mini-host checks.
6. protocol §3, §5 and §8, quickstart and changelog updated; released as 0.3.1.

- complete: joint 14/14 against agent 0.3.1
