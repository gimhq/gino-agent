#!/usr/bin/env bash
# Release helpers for the VM channels (kernel, vmm, rootfs), used by .github/workflows/release-vm.yml.
# Each channel is a lode resource `gino-agent/<channel>` with its own releases
# (`<channel>.<YYYYMMDD-HHMM>`) and a native lode/v1 manifest on the rolling release
# `<channel>-manifest`.
#
#   release.sh stamp                     print `<YYYYMMDD-HHMM> <semver>` for now (UTC)
#   release.sh inputs <channel>          print the sha256 of the channel's tracked inputs
#   release.sh latest <channel>          print the newest published `<channel>.*` tag (empty if none)
#   release.sh package <channel> <dir>   pack the built channel into <dir>/gino-<channel>-linux-x64.tar.gz
#   release.sh manifest <channel> <asset> <version> <url> <manifest.json>
#                                        add <asset> as <version> to the manifest (created when
#                                        missing), point `stable` at it and keep the newest
#                                        $KEEP versions; signed with $LODE_KEY_FILE when set
#
# Environment:
#   VM_OUT        build outputs of vm/*/build.sh (default: <worktree>/.tmp/vm)
#   LODE_CLI      lode-cli binary (default: lode-cli)
#   LODE_KEY_FILE lode signing key file; unset writes an unsigned manifest
#   KEEP          versions kept in a manifest (default: 10)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WT="$(git -C "$HERE" rev-parse --show-toplevel)"
VM_OUT="${VM_OUT:-$WT/.tmp/vm}"
LODE_CLI="${LODE_CLI:-lode-cli}"
KEEP="${KEEP:-10}"
APP=gino-agent

die() { echo "release: $*" >&2; exit 1; }

channel() {
  case "${1:-}" in
    kernel | vmm | rootfs) ;;
    *) die "unknown channel '${1:-}' (kernel, vmm or rootfs)" ;;
  esac
}

# The paths whose content makes up a channel's inputs.
input_paths() {
  case "$1" in
    kernel) echo vm/kernel ;;
    vmm) echo vm/vmm gino-vmm ;;
    rootfs) echo vm/rootfs ;;
  esac
}

cmd_stamp() {
  local now
  now="$(date -u +%Y%m%d%H%M)"
  # semver YYYY.MMDD.HHMM: base-10 numbers, so leading zeros drop.
  printf '%s-%s %d.%d.%d\n' "${now:0:8}" "${now:8:4}" "${now:0:4}" "$((10#${now:4:4}))" "$((10#${now:8:4}))"
}

cmd_inputs() {
  channel "$1"
  # shellcheck disable=SC2046
  git -C "$WT" ls-files -s -- $(input_paths "$1") | sha256sum | cut -d' ' -f1
}

cmd_latest() {
  channel "$1"
  gh release list --exclude-drafts --limit 200 --json tagName,createdAt \
    | jq -r --arg p "$1." '[.[] | select(.tagName | startswith($p))] | sort_by(.createdAt) | last | .tagName // empty'
}

cmd_package() {
  channel "$1"
  local dir="$2" pkg asset="gino-$1-linux-x64.tar.gz"
  pkg="$(mktemp -d)"
  trap 'rm -rf "$pkg"' RETURN
  chmod 0755 "$pkg"
  case "$1" in
    kernel)
      install -m 0644 "$VM_OUT/kernel/vmlinux" "$pkg/vmlinux"
      install -m 0644 "$VM_OUT/kernel/config" "$pkg/config"
      ;;
    vmm) install -m 0755 "$VM_OUT/bin/gino-vmm" "$pkg/gino-vmm" ;;
    rootfs)
      cp --sparse=always "$VM_OUT/rootfs/rootfs.ext4" "$pkg/rootfs.ext4"
      install -m 0644 "$VM_OUT/rootfs/rootfs.versions" "$pkg/rootfs.versions"
      ;;
  esac
  mkdir -p "$dir"
  tar -C "$pkg" --sparse --owner=0 --group=0 --numeric-owner --mtime='@0' -cf - . | gzip -n -9 > "$dir/$asset"
  echo "$dir/$asset"
}

cmd_manifest() {
  channel "$1"
  local name="$APP/$1" asset="$2" version="$3" url="$4" manifest="$5"
  [[ -f "$asset" ]] || die "asset $asset is missing"
  if [[ -n "${LODE_KEY_FILE:-}" ]]; then
    "$LODE_CLI" manifest "$asset" --app "$name" --version "$version" --url "$url" \
      --key "$LODE_KEY_FILE" --into "$manifest" >&2
  else
    [[ -f "$manifest" ]] || jq -n --arg name "$name" '{schema: "lode/v1", name: $name, channels: {}, versions: {}}' > "$manifest"
    local sha size
    sha="$(sha256sum "$asset" | cut -d' ' -f1)"
    size="$(stat -c %s "$asset")"
    jq --arg v "$version" --arg n "$(basename "$asset")" --arg u "$url" --arg s "$sha" --argjson z "$size" \
      '.versions[$v] = {assets: [{name: $n, url: $u, sha256: $s, size: $z}]} | .channels.stable.latest = $v' \
      "$manifest" > "$manifest.tmp"
    mv "$manifest.tmp" "$manifest"
  fi
  [[ "$(jq -r .name "$manifest")" == "$name" ]] || die "$manifest is not the manifest of $name"
  # Keep the newest $KEEP versions by semver precedence (all are YYYY.MMDD.HHMM).
  jq --argjson keep "$KEEP" '
    (.versions | keys | sort_by(split(".") | map(tonumber)) | .[-$keep:]) as $kept
    | .versions |= with_entries(select(.key as $k | $kept | index($k)))' "$manifest" > "$manifest.tmp"
  mv "$manifest.tmp" "$manifest"
  if [[ -n "${LODE_KEY_FILE:-}" ]]; then
    "$LODE_CLI" manifest-sign --into "$manifest" --key "$LODE_KEY_FILE" >&2
  fi
}

sub="${1:-}"
shift || true
case "$sub" in
  stamp) cmd_stamp ;;
  inputs) cmd_inputs "$@" ;;
  latest) cmd_latest "$@" ;;
  package) cmd_package "$@" ;;
  manifest) cmd_manifest "$@" ;;
  *) die "usage: release.sh stamp | inputs <channel> | latest <channel> | package <channel> <dir> | manifest <channel> <asset> <version> <url> <manifest.json>" ;;
esac
