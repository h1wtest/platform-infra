#!/usr/bin/env bash
set -euo pipefail
# Explicit local user installation; no root, no global CA installation, no cluster changes.
if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  echo 'This pinned installer supports Linux x86_64 (WSL2). Install tools explicitly on other platforms.' >&2
  exit 1
fi
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$HOME/.local/bin"
curl --fail --silent --show-error --location --max-time 120 https://github.com/astral-sh/uv/releases/download/0.13.5/uv-x86_64-unknown-linux-gnu.tar.gz --output "$work/uv.tar.gz"
printf '%s  %s\n' f68d291c75783122dad58ab77def0e13f3233f358731db5d6d7e8715603b928f "$work/uv.tar.gz" | sha256sum --check
tar -xzf "$work/uv.tar.gz" -C "$work"
install -m 0755 "$work/uv-x86_64-unknown-linux-gnu/uv" "$HOME/.local/bin/uv"
curl --fail --silent --show-error --location --max-time 120 https://dl.k8s.io/release/v1.36.1/bin/linux/amd64/kubectl --output "$work/kubectl"
curl --fail --silent --show-error --location --max-time 30 https://dl.k8s.io/release/v1.36.1/bin/linux/amd64/kubectl.sha256 --output "$work/kubectl.sha256"
printf '%s  %s\n' "$(cat "$work/kubectl.sha256")" "$work/kubectl" | sha256sum --check
install -m 0755 "$work/kubectl" "$HOME/.local/bin/kubectl"
curl --fail --silent --show-error --location --max-time 120 https://github.com/k3d-io/k3d/releases/download/v5.9.0/k3d-linux-amd64 --output "$work/k3d"
curl --fail --silent --show-error --location --max-time 30 https://github.com/k3d-io/k3d/releases/download/v5.9.0/checksums.txt --output "$work/k3d-checksums.txt"
# Verify the exact release asset, not a loose substring or an unchecked downloaded executable.
while read -r checksum filename; do
  if [[ "$filename" == k3d-linux-amd64 || "$filename" == '*k3d-linux-amd64' ]]; then
    printf '%s  %s\n' "$checksum" "$work/k3d" | sha256sum --check
    install -m 0755 "$work/k3d" "$HOME/.local/bin/k3d"
    break
  fi
done < "$work/k3d-checksums.txt"
if [[ ! -x "$HOME/.local/bin/k3d" ]]; then
  echo 'Pinned k3d checksum entry unavailable; installation failed closed.' >&2
  exit 1
fi
printf 'Installed pinned user tools. Set PATH="$HOME/.local/bin:$PATH". Docker Desktop, curl, openssl and make must already be installed.\n'
