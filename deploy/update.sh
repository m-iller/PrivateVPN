#!/usr/bin/env bash
# First run installs. Later runs rebuild the panel and restart services.
# An update keeps the admin password, Reality keys, and device locks.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi

if [[ ! -f /etc/privatevpn/config.json ]]; then
  exec bash "$ROOT/deploy/install-ubuntu.sh" "$@"
fi

if [[ $# -gt 0 ]]; then
  echo "config already exists; extra arguments ignored" >&2
  echo "password, Reality keys, and device locks stay as they are" >&2
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
(
  cd "$ROOT"
  go build -trimpath -ldflags "-s -w" -o "$tmpbin" ./cmd/panel
)
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
echo "Updated. Password, Reality keys, and device locks were kept."
echo "Panel password file: /etc/privatevpn/admin.password"
