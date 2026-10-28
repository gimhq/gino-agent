# 20261028-0050-vm-image-release Kernel, vmm and rootfs release channels with lode

- **status**: completed
- **createdAt**: 2026-10-28 00:50
- **approvedAt**: 2026-10-28 01:10
- **relatedTask**: 20261028-0050-vm-image-release

## Context

- `vm/kernel/build.sh` builds `vmlinux` (6.12.114, sha256-pinned tarball, tinyconfig + fragment);
  `vm/vmm/build.sh` builds `gino-vmm` as one static musl binary with libkrun compiled in;
  `vm/rootfs/build.sh` builds `rootfs.ext4` (+ `rootfs.versions`) from `vm/rootfs/Dockerfile`.
  They run only locally and in the KVM suite; nothing publishes them.
- The `vm` isolation block requires `kernel`, `rootfs` and `vmm` paths.
- `release.yml` runs on every published release, builds the agent asset and signs it for lode's
  github source (`channel = stable` reads `/releases/latest`); lode-cli is pinned to v0.2.1.
- lode v0.4.0 `[[resource]]`: native `lode/v1` manifest only (no github source), identity
  `<app>/<name>`, installed under `$LODE_DIR/resources/<name>/current`, path injected as
  `LODE_RESOURCE_<NAME>`, own channel and policy; `auto` applies only a semver upgrade.
- `vm_disk` imports the configured rootfs into `base/<sha256>.ext4` by hard link or copy, so lode
  pruning an old version never touches a base a run is using.
- Reference: `micaoss/mica-build` cuts each release by `workflow_dispatch` as
  `<name>.<YYYYMMDD-HHMM>` at the `main` commit the run started on, reuses a component whose
  inputs hash equals the latest release's, and creates the release as a draft, uploads every asset
  with `SHA256SUMS` and the lock last, then publishes it.

## Proposal

1. **Channels.** Three resources, each released on its own: `kernel` (`vmlinux`, `config`),
   `vmm` (`gino-vmm`) and `rootfs` (`rootfs.ext4` sparse-tarred, `rootfs.versions`). Assets
   `gino-<name>-linux-x64.tar.gz`; lode identities `gino-agent/<name>`.
2. **Release naming.** Tag `<name>.<YYYYMMDD-HHMM>` (UTC, the run start) at the `main` commit;
   the lode version is the same stamp as semver `YYYY.MMDD.HHMM` with leading zeros dropped
   (`rootfs.20261028-0049` -> `2026.1028.49`), so every later release is a provable upgrade.
3. **Workflow.** One `release-vm.yml`, `workflow_dispatch` with `channel` (`kernel` | `vmm` |
   `rootfs`), plus a weekly `schedule` for `rootfs`; `concurrency` per channel, never cancelled;
   `main` only.
   - **plan**: the inputs hash of the channel (kernel: `vm/kernel/`; vmm: `vm/vmm/`,
     `gino-vmm/`; rootfs: `vm/rootfs/`). Kernel and vmm stop with "unchanged" when it equals the
     hash recorded by the channel's latest release.
   - **build** (no secrets): the existing build script; rootfs is rolling: it always rebuilds, so
     upstream packages move, and stops with "unchanged" when `rootfs.versions` (pins and
     installed packages, without the per-build image lines) equals the latest release's.
   - **publish**: create the release as a draft with `--latest=false`, upload the asset, its
     `.sig` (with `LODE_SIGNING_KEY`), `SHA256SUMS` and `release.lock` last (channel, version,
     commit, inputs hash, content sha256, upstream versions), then publish it. Then update the
     channel manifest (below).
   - `release.yml` only runs for `v*` tags; lode-cli pinned to v0.4.0 in both workflows.
4. **Manifests.** One rolling release per channel (`<name>-manifest`, `--latest=false`) holds
   `manifest.json` at
   `https://github.com/gimhq/gino-agent/releases/download/<name>-manifest/manifest.json`. The
   publish step downloads it, adds the version (`lode-cli manifest --app gino-agent/<name>`), sets
   `channels.stable.latest`, keeps the newest 10 versions, runs `manifest-sign` and uploads it
   back. The workflow fails if any non-agent release is marked latest.
5. **Agent.** `vm.kernel`, `vm.vmm` and `vm.rootfs` become optional: an explicit path wins, else
   `$LODE_RESOURCE_KERNEL/vmlinux`, `$LODE_RESOURCE_VMM/gino-vmm`,
   `$LODE_RESOURCE_ROOTFS/rootfs.ext4`, else a config error naming the field and the variable.
   Paths resolve per run, so a lode update applies to the next run (`notify = "none"`).
6. **Docs.** Operator `lode.toml` snippet (three `[[resource]]`, `required = true` on vm hosts),
   release runbook (`gh workflow run release-vm.yml -f channel=<name>`, naming, reuse, rolling
   rootfs), agent-architecture §9e config, changelog.

## Risks

- A non-agent release marked latest would break lode's agent update on the github source;
  guarded by `--latest=false` and the workflow check.
- The rootfs asset is large (~1.4 GiB ext4, a few hundred MiB compressed); within GitHub's 2 GiB
  asset limit, but every rootfs version is a full download. Weekly rolling bounds the churn.
- A rolling rootfs takes whatever upstream ships that week (Debian packages, unpinned tools); the
  pinned engine and the smoke boot in the build job are the gate.
- lode-cli v0.2.1 -> v0.4.0 for signing; the agent artifact message (`lode.artifact.v2`) is
  unchanged.

## Scope

- In: `release-vm.yml`, the `release.yml` filter, the agent path fallback with tests, docs.
- Out: heartbeat reporting of kernel/vmm/rootfs versions, arm64 artifacts, non-stable channels,
  a resource service like mica-res.

## Alternatives

- One manifest on GitHub Pages or a lode-server registry: cleaner URLs, but new hosting to run.
- Tag-push or release-published triggers per channel: the dispatch run owns the tag and the
  commit, which avoids a tag/release mismatch and makes reuse a plan step.
- Bundling the three into the agent asset: couples the channels this task separates.

## Implementation Notes

- `VmConfig.kernel` / `rootfs` / `vmm` default to empty; `load_isolation_file` fills them with
  `fill_from_lode` (`LODE_RESOURCE_<NAME>` + file) and `validate` rejects an unset one naming the
  field and the variable.
- `vm/release.sh` (stamp, inputs, latest, package, manifest) carries the workflow logic.
  `lode-cli manifest` takes only `--key <file>`, so the publish job writes the secret to a 0600
  temp file; without a key the manifest is written by `jq` unsigned.
- Every run builds all three channels and runs `vm/smoke.sh`, so a channel is never published
  without booting against the current other two.
- Verified locally: `release.sh` subcommands; signed and unsigned manifests merged and pruned;
  `lode-cli pull` (lode v0.4.0, loopback http, `require_signature = "enforce"`) of the three real
  assets, byte-identical to the build outputs, the rootfs extracted sparse (1.4 GiB, 821 MiB on
  disk; the gzip asset is 305 MiB); actionlint and shellcheck; agent fmt, clippy, deny, shear,
  nextest (954 passed). The workflow itself runs only on GitHub.
