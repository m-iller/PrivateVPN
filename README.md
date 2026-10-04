# Private VPN

Panel and Xray for two people, about six devices, on one Netherlands VPS. Happ imports a subscription URL. That URL stays valid so the app can refresh. The first Happ device id (`x-hwid`) locks the link. Any other device id is refused.

This is one Netherlands endpoint (VLESS + Reality on port 443). A Netherlands address is outside the Russian IP whitelist, so this VPS is not a whitelist-bypass hop.

## Server

On VDSina, order clean Ubuntu 24.04. Do not use the 3X-UI, Outline, WireGuard, IPsec, OpenVPN, or 3proxy images. 1 core, 1 GB RAM, and 10 GB disk are enough.

## Open the ports

VDSina does not filter 80, 443, or 8443. SSH in as root and check the firewall on the VPS:

```bash
ufw status
```

If it says `Status: inactive`, those ports are already reachable. Leave UFW off.

If it says `Status: active`, allow SSH first, then the other ports:

```bash
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 8443/tcp
```

Port 22 is SSH. Port 443 is the VPN. Port 8443 is the panel. Port 80 is unused unless you later add a domain for a Let's Encrypt certificate.

## No domain

The VPN does not need a domain. The tunnel is VLESS on port 443 and uses `www.microsoft.com` as its disguise. Install with the public IP only. The panel certificate is self-signed for that IP.

Open `https://203.0.113.10:8443` in a browser and accept the certificate warning. Happ often refuses that same certificate when it downloads the subscription. If Happ rejects the link, a domain is the fix for the panel certificate. The VPN itself still works without one.

## Point a domain

Skip this section when you have no domain. Use it when you want a certificate Happ will trust. Do it before install.

1. In the VDSina account, open this server and copy its public IPv4 address.
2. Where you bought the domain, add one DNS record:

| Type | Name | Value |
| --- | --- | --- |
| A | `vpn` | that IPv4 address |

The name `vpn` makes `vpn.example.com`. Use your real domain. If the host field wants the full name, enter `vpn.example.com`.

Leave any proxy off. On Cloudflare the cloud stays grey (DNS only). An orange cloud sends people to Cloudflare, and Cloudflare does not forward port 8443, so Happ and the panel never reach the VPS.

3. Wait until the name resolves to that IP. On your PC:

```bash
nslookup vpn.example.com
```

The answer must be the VPS address.

## Install Go

On the VPS, as root. The panel is built with Go 1.26.7 from `/usr/local/go`.

```bash
apt-get update
apt-get install -y curl ca-certificates
curl -fsSL -o /tmp/go.tgz https://go.dev/dl/go1.26.7.linux-amd64.tar.gz
echo "ffb5f8de10c62550dfddab66b36b57030721e0a44a3218e9e1181d7b59f121ca  /tmp/go.tgz" | sha256sum -c -
rm -rf /usr/local/go
tar -C /usr/local -xzf /tmp/go.tgz
rm -f /tmp/go.tgz
printf 'export PATH=/usr/local/go/bin:$PATH\n' > /etc/profile.d/go.sh
export PATH=/usr/local/go/bin:$PATH
go version
```

`go version` must print `go version go1.26.7 linux/amd64`. `install-ubuntu.sh` installs this same copy when `/usr/local/go/bin/go` is missing. Later updates call `/usr/local/go/bin/go` directly.

## First install on the VPS

SSH in as root. Ubuntu does not run a Windows `.bat` file. The update command is a shell script you start on the VPS.

Clone the repo and install. GitHub no longer accepts an account password for `git clone`. Use a personal access token when Git asks for a password, or use a deploy key (below).

```bash
apt-get update
apt-get install -y git
git clone https://github.com/m-iller/PrivateVPN.git /opt/privatevpn
bash /opt/privatevpn/deploy/install-ubuntu.sh --address 203.0.113.10
```

Use the VPS public IP. The panel is `https://203.0.113.10:8443`. Accept the certificate warning in the browser.

With a domain that already points at the VPS, add it so Let's Encrypt can issue a certificate:

```bash
bash /opt/privatevpn/deploy/install-ubuntu.sh --address 203.0.113.10 --domain vpn.example.com
```

The panel is then `https://vpn.example.com:8443`.

The admin password is written to `/etc/privatevpn/admin.password` (mode 0600) only on this first install.

```bash
cat /etc/privatevpn/admin.password
```

### So later updates can pull

The repo is private. Add a read-only deploy key once, then the update script can fetch without asking.

```bash
ssh-keygen -t ed25519 -f /root/.ssh/privatevpn_deploy -N ""
cat /root/.ssh/privatevpn_deploy.pub
```

In GitHub, open the repo, Settings, Deploy keys, and add that public key. Leave write access off. Then point this clone at SSH:

```bash
mkdir -p /root/.ssh
printf 'Host github.com\n  IdentityFile /root/.ssh/privatevpn_deploy\n  IdentitiesOnly yes\n' >> /root/.ssh/config
chmod 600 /root/.ssh/config
git -C /opt/privatevpn remote set-url origin git@github.com:m-iller/PrivateVPN.git
```

## Update

On the VPS, as root:

```bash
bash /opt/privatevpn/deploy/update.sh
```

That fetches `main`, fast-forwards the checkout, rebuilds `/usr/local/bin/privatevpn`, and restarts Xray and the panel. A pull only updates source files. The running program is the compiled binary, so the script builds it before the restart. The admin password, Reality keys, and device locks stay as they are.

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

Xray is pinned to v26.7.28, the same core Happ 4.3 ships. An older server core rejects that client's Reality handshake, the tunnel still looks connected, and the ping stays empty. Xray 26.7 also refuses a Reality client below v26.3.27 unless the config sets a lower `minClientVer`. The generated config sets `1.0.0` so Happ is not diverted to the decoy site. The panel runs as `privatevpn` and may restart Xray through a single sudoers rule.

## Tests

```bash
go test ./...
```
