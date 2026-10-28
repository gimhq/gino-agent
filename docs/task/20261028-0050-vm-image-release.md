# 20261028-0050-vm-image-release Kernel, vmm and rootfs release channels with lode

- **status**: completed
- **priority**: P1
- **owner**: l1-gino
- **createdAt**: 2026-10-28 00:50

## Description

Publish the guest kernel, `gino-vmm` and the default rootfs as release artifacts, each on its own
release channel independent of the agent (the rootfs rolling), distributed through lode
`[[resource]]` entries, and let the agent find them from lode without explicit `vm` paths.

Acceptance:

- `release-vm.yml` cuts `<name>.<YYYYMMDD-HHMM>` releases for `kernel`, `vmm` and `rootfs`, skips
  an unchanged channel, signs and uploads the asset and updates a signed native `lode/v1`
  manifest per channel; the agent release workflow ignores them and they never become the
  repository latest release. The rootfs also rolls on a weekly schedule.
- lode installs the three resources (`gino-agent/<name>`) from those manifests.
- With `vm.kernel` / `vm.vmm` / `vm.rootfs` omitted, the agent uses `LODE_RESOURCE_<NAME>`;
  explicit paths still win; neither present is a config error.
- A resource update takes effect on the next run; running VMs are unaffected.

## ActiveForm

Releasing the guest kernel and rootfs through lode

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

Plan: [20261028-0050-vm-image-release](../plan/20261028-0050-vm-image-release.md)

- complete: kernel, vmm and rootfs release channels (release-vm.yml) with lode resources; agent falls back to LODE_RESOURCE_<NAME>
