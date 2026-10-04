#!/usr/bin/env bash
# Run this on the VPS. It fetches main, rebuilds the panel, and restarts services.
# It does not change the admin password, Reality keys, or device locks.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "run as root: bash deploy/update.sh" >&2
  exit 1
fi

if [[ ! -d "$ROOT/.git" ]]; then
  echo "not a git checkout: $ROOT" >&2
  echo "clone first: git clone https://github.com/m-iller/PrivateVPN.git /opt/privatevpn" >&2
  exit 1
fi

if [[ ! -f /etc/privatevpn/config.json ]]; then
  echo "panel is not installed yet" >&2
  echo "bash deploy/install-ubuntu.sh --address PUBLIC_IP --domain vpn.example.com" >&2
  exit 1
fi

if [[ "${PRIVATEVPN_UPDATE_PHASE:-}" != "restart" ]]; then
  if [[ $# -gt 0 ]]; then
    echo "usage: bash deploy/update.sh" >&2
    exit 2
  fi
  if [[ -n "$(git status --porcelain)" ]]; then
    echo "local changes in $ROOT. Refusing to pull." >&2
    git status --porcelain >&2
    exit 1
  fi

  echo "Fetching origin/main"
  git fetch origin main
  if git show-ref --verify --quiet refs/heads/main; then
    git checkout main
    git merge --ff-only origin/main
  else
    git checkout -b main origin/main
  fi
  PRIVATEVPN_UPDATE_PHASE=restart exec bash "$ROOT/deploy/update.sh"
fi

export PATH="/usr/local/go/bin:${PATH}"
export GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}"

if [[ ! -x /usr/local/go/bin/go ]]; then
  echo "Go is missing. Run deploy/install-ubuntu.sh --address PUBLIC_IP" >&2
  exit 1
fi
if [[ ! -x /usr/local/bin/xray ]]; then
  echo "Xray is missing. Run deploy/install-ubuntu.sh --address PUBLIC_IP" >&2
  exit 1
fi

tmpbin="$(mktemp)"
trap 'rm -f "$tmpbin"' EXIT
go build -trimpath -ldflags "-s -w" -o "$tmpbin" ./cmd/panel
install -m 0755 "$tmpbin" /usr/local/bin/privatevpn
rm -f "$tmpbin"
trap - EXIT

sudoers_tmp="$(mktemp)"
trap 'rm -f "$sudoers_tmp"' EXIT
install -m 0440 "$ROOT/deploy/sudoers-privatevpn" "$sudoers_tmp"
visudo -cf "$sudoers_tmp" >/dev/null
install -m 0440 "$sudoers_tmp" /etc/sudoers.d/privatevpn
rm -f "$sudoers_tmp"
trap - EXIT
install -m 0644 "$ROOT/deploy/xray.service" /etc/systemd/system/xray.service
install -m 0644 "$ROOT/deploy/privatevpn.service" /etc/systemd/system/privatevpn.service

systemctl daemon-reload
systemctl restart xray
systemctl restart privatevpn
systemctl --no-pager --full status xray privatevpn

echo
echo "Fetched, rebuilt, and restarted. Password, Reality keys, and device locks were kept."
echo "Panel password file: /etc/privatevpn/admin.password"
