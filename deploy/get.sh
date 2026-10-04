#!/usr/bin/env bash
# Short install for a VPS console where pasting does not work:
#   curl -sL <link to this file> | bash -s vpn.example.com
# The argument is the Cloudflare proxied hostname. It clones the repo into
# /opt/privatevpn and runs install-ubuntu.sh in Cloudflare mode.
set -euo pipefail

CDN="${1:-}"
if [[ -z "$CDN" ]]; then
  echo "usage: curl -sL <link> | bash -s vpn.example.com" >&2
  exit 2
fi
if [[ "$(id -u)" -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq git ca-certificates curl iproute2 >/dev/null

if [[ ! -d /opt/privatevpn/.git ]]; then
  git clone -q https://github.com/m-iller/PrivateVPN.git /opt/privatevpn
fi
cd /opt/privatevpn
git fetch -q origin main
git checkout -q main
git merge -q --ff-only origin/main

ADDRESS="$(ip -4 route get 1.1.1.1 | awk '{for (i = 1; i < NF; i++) if ($i == "src") print $(i + 1)}')"
if [[ -z "$ADDRESS" ]]; then
  echo "could not find this server's IPv4 address" >&2
  exit 1
fi

bash deploy/install-ubuntu.sh --address "$ADDRESS" --cdn "$CDN"

echo
echo "Panel:    https://${CDN}:8443"
echo "Password: $(cat /etc/privatevpn/admin.password)"
