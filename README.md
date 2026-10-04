# Private VPN

Panel and Xray for two people, about six devices, on one Netherlands VPS. Happ imports a subscription URL. That URL stays valid so the app can refresh. The first Happ device id (`x-hwid`) locks the link. Any other device id is refused.

This is one Netherlands endpoint (VLESS + Reality on port 443). A Netherlands address is outside the Russian IP whitelist, so this VPS is not a whitelist-bypass hop.

## Server

On VDSina, order clean Ubuntu 24.04. Do not use the 3X-UI, Outline, WireGuard, IPsec, OpenVPN, or 3proxy images. 1 core, 1 GB RAM, and 10 GB disk are enough.

Open TCP 80, 443, and 8443. Point a domain at the VPS before install if you want a certificate Happ will trust.

## Install

Copy this repo to the VPS, then:

```bash
sudo bash deploy/install-ubuntu.sh --address PUBLIC_IP --domain vpn.example.com
```

The admin password is written to `/etc/privatevpn/admin.password` (mode 0600). The panel is `https://vpn.example.com:8443`.

Without a domain the script still installs, with a self-signed certificate. Happ often rejects that. Use a domain.

## Add a device

1. Sign in to the panel.
2. Add a device. The cap is 6.
3. On that one device, open Happ and add the subscription URL.
4. Happ must send a device id. It does by default. If import fails with a device-id error, turn HWID on in Happ and open the link again.

A browser open does not lock the link, because a browser does not send `x-hwid`. The profile is not returned until Happ does.

The same device can refresh the subscription later. A second device gets a refusal.

## Replace a device

Remove the profile from the old Happ first. In the panel, choose **Unbind and rotate key**. That clears the lock and changes the VLESS id, so the old copy stops connecting. The next Happ that opens the same URL becomes the only device.

Revoke frees the slot and removes the key.

## Layout

| Path | What |
| --- | --- |
| `/etc/privatevpn/config.json` | Panel secrets, mode 0600 |
| `/var/lib/privatevpn/devices.json` | Device tokens and locks |
| `/usr/local/etc/xray/config.json` | Reality inbound |

Xray is pinned to v26.3.27. The panel runs as `privatevpn` and may restart Xray through a single sudoers rule.

## Tests

```bash
go test ./...
```
