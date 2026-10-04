#!/usr/bin/env bash
# Install the private VPN panel and Xray on Ubuntu 24.04.
# Order a clean Ubuntu image on VDSina. Not the 3X-UI, WireGuard, or OpenVPN images.
set -euo pipefail

XRAY_VERSION="v26.3.27"
XRAY_SHA256="23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae"
GO_VERSION="1.26.7"
GO_SHA256="ffb5f8de10c62550dfddab66b36b57030721e0a44a3218e9e1181d7b59f121ca"

ADDRESS=""
DOMAIN=""
PUBLIC_URL=""

usage() {
  echo "usage: sudo bash deploy/install-ubuntu.sh --address PUBLIC_IP [--domain vpn.example.com] [--public-url https://vpn.example.com:8443]" >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --address) ADDRESS="${2:-}"; shift 2 ;;
    --domain) DOMAIN="${2:-}"; shift 2 ;;
    --public-url) PUBLIC_URL="${2:-}"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi
if [[ -z "$ADDRESS" ]]; then
  echo "--address is required" >&2
  usage
fi
if [[ -z "$DOMAIN" && -z "$PUBLIC_URL" ]]; then
  PUBLIC_URL="https://${ADDRESS}:8443"
  echo "warning: no domain set; panel certificate will be self-signed and Happ may refuse it" >&2
fi
if [[ -f /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  if [[ "${ID:-}" != "ubuntu" ]]; then
    echo "this script targets Ubuntu" >&2
    exit 1
  fi
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y curl ca-certificates openssl tar unzip sudo git

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

	if [[ ! -x /usr/local/bin/xray ]] || ! /usr/local/bin/xray version | grep -q "26.3.27"; then
  curl -fsSL -o "$tmpdir/xray.zip" "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-64.zip"
  echo "${XRAY_SHA256}  $tmpdir/xray.zip" | sha256sum -c -
  unzip -q -o "$tmpdir/xray.zip" -d "$tmpdir/xray"
  install -m 0755 "$tmpdir/xray/xray" /usr/local/bin/xray
fi

if [[ ! -x /usr/local/go/bin/go ]]; then
  curl -fsSL -o "$tmpdir/go.tgz" "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
  echo "${GO_SHA256}  $tmpdir/go.tgz" | sha256sum -c -
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "$tmpdir/go.tgz"
fi
export PATH="/usr/local/go/bin:${PATH}"
export GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}"

(
  cd "$ROOT"
  go build -trimpath -ldflags "-s -w" -o /usr/local/bin/privatevpn ./cmd/panel
)
chmod 0755 /usr/local/bin/privatevpn

id -u xray >/dev/null 2>&1 || useradd --system --home /nonexistent --shell /usr/sbin/nologin xray
id -u privatevpn >/dev/null 2>&1 || useradd --system --home /var/lib/privatevpn --shell /usr/sbin/nologin privatevpn

install -d -m 0700 -o privatevpn -g privatevpn /etc/privatevpn /var/lib/privatevpn
install -d -m 0750 -o privatevpn -g xray /usr/local/etc/xray

if [[ ! -f /etc/privatevpn/config.json ]]; then
  pass="$(openssl rand -hex 16)"
  umask 077
  printf '%s\n' "$pass" > /etc/privatevpn/admin.password
  chown privatevpn:privatevpn /etc/privatevpn/admin.password
  chmod 0600 /etc/privatevpn/admin.password
  ADMIN_PASSWORD="$pass" /usr/local/bin/privatevpn -init \
    -config /etc/privatevpn/config.json \
    -address "$ADDRESS" \
    -domain "$DOMAIN" \
    -public-url "$PUBLIC_URL" \
    -data-dir /var/lib/privatevpn \
    -xray-config /usr/local/etc/xray/config.json \
    -listen :8443
  unset pass
  unset ADMIN_PASSWORD
fi

chown privatevpn:privatevpn /etc/privatevpn/config.json
chmod 0600 /etc/privatevpn/config.json
chown privatevpn:xray /usr/local/etc/xray/config.json
chmod 0640 /usr/local/etc/xray/config.json

	install -m 0440 "$ROOT/deploy/sudoers-privatevpn" /etc/sudoers.d/privatevpn
	install -m 0644 "$ROOT/deploy/xray.service" /etc/systemd/system/xray.service
	install -m 0644 "$ROOT/deploy/privatevpn.service" /etc/systemd/system/privatevpn.service

if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  ufw allow 80/tcp
  ufw allow 443/tcp
  ufw allow 8443/tcp
fi

systemctl daemon-reload
systemctl enable --now xray
systemctl enable --now privatevpn

echo
echo "Panel password is in /etc/privatevpn/admin.password"
if [[ -n "$DOMAIN" ]]; then
  echo "Open https://${DOMAIN}:8443 after DNS points at ${ADDRESS}."
  echo "Port 80 must reach this VPS so Let's Encrypt can issue the certificate."
else
  echo "No domain was set. The panel is https://${ADDRESS}:8443 with a self-signed certificate."
  echo "Accept that warning in a browser. Happ may refuse the subscription URL."
  echo "The VPN on port 443 does not need a domain."
fi
echo "VDSina does not filter 80, 443, or 8443. If ufw is active, allow 22, 80, 443, and 8443."
echo "In the panel, add a device and import that link in Happ on that device only."
