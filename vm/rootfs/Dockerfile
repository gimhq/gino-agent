# Guest root for VM-isolated engine runs, written by build.sh as the ext4 base image every run
# boots from (a per-run or per-task qcow2 overlay holds its writes).
#
# guest-init binds the gino-agent binary at /gino-agent and starts dockerd when the run enables
# Docker. The usual workspace roots of the agent images (/workspace, /data, /srv) exist as mount
# points. busybox-static lets vm/smoke.sh mount the image from an otherwise empty boot root.
FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8

# Native claude CLI release; checksum from downloads.claude.ai/claude-code-releases/<version>/manifest.json.
ARG CLAUDE_VERSION=2.1.308
ARG CLAUDE_SHA256=356733f185fa988e6bf3aa9a555269fdd167982a2e2a80d3c8a78037bb92ad58

# Docker Engine from download.docker.com; the key's sha256 pins the repository signer.
ARG DOCKER_GPG_SHA256=1500c1f56fa9e26b9b8f42452a553675796ade0807cdce11975eb98170b3a570
ARG DOCKER_VERSION=5:29.9.2-1~debian.12~bookworm
ARG CONTAINERD_VERSION=2.4.2-3~debian.12~bookworm
ARG BUILDX_VERSION=0.38.1-1~debian.12~bookworm
ARG COMPOSE_VERSION=5.6.1-1~debian.12~bookworm

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# hadolint ignore=DL3008
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash busybox-static ca-certificates coreutils curl findutils git grep gzip iptables less \
      openssh-client procps ripgrep sed tar xz-utils \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb

RUN install -d -m 0755 /etc/apt/keyrings \
 && curl -fsSL -o /etc/apt/keyrings/docker.asc https://download.docker.com/linux/debian/gpg \
 && echo "${DOCKER_GPG_SHA256}  /etc/apt/keyrings/docker.asc" | sha256sum -c - \
 && echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable" \
      > /etc/apt/sources.list.d/docker.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      "docker-ce=${DOCKER_VERSION}" "docker-ce-cli=${DOCKER_VERSION}" \
      "containerd.io=${CONTAINERD_VERSION}" "docker-buildx-plugin=${BUILDX_VERSION}" \
      "docker-compose-plugin=${COMPOSE_VERSION}" \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb

RUN curl -fsSL -o /usr/local/bin/claude \
      "https://downloads.claude.ai/claude-code-releases/${CLAUDE_VERSION}/linux-x64/claude" \
 && echo "${CLAUDE_SHA256}  /usr/local/bin/claude" | sha256sum -c - \
 && chmod 0755 /usr/local/bin/claude

RUN useradd -m -u 1000 -U -s /bin/bash engine \
 && rm -rf /tmp/* /run/* \
 && mkdir -p /opt/gino /run/gino /workspace /data /srv \
 && chmod 1777 /tmp
