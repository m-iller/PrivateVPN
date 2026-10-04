# Private VPN

Panel and Xray for two people, about six devices, on one Netherlands VPS. Happ imports a subscription URL. That URL stays valid so the app can refresh. The first Happ device id (`x-hwid`) locks the link. Any other device id is refused.

This is one Netherlands endpoint (VLESS + Reality on port 443). A Netherlands address is outside the Russian IP whitelist, so this VPS is not a whitelist-bypass hop.

## Server

On VDSina, order clean Ubuntu 24.04. Do not use the 3X-UI, Outline, WireGuard, IPsec, OpenVPN, or 3proxy images. 1 core, 1 GB RAM, and 10 GB disk are enough.

Open TCP 80, 443, and 8443. Point a domain at the VPS before install if you want a certificate Happ will trust.

## Upload from Windows

`deploy.bat` runs on your PC. It uploads this folder to the VPS and runs the server script. The VPS stays Ubuntu. The bat file does not store the SSH password.

### Before upload

1. Order clean Ubuntu 24.04. Note the public IP and the root SSH password (or use an SSH key).
2. In the VDSina firewall, allow TCP 22, 80, 443, and 8443.
3. If you have a domain, point it at that IP before the first install. Port 80 must reach the VPS so Let's Encrypt can issue a certificate Happ will trust.

Install OpenSSH Client if `ssh` is missing: Windows Settings, Optional features, OpenSSH Client.

### First install

Open Command Prompt or PowerShell in this folder so you can type the SSH password. Do not double-click the bat file.

```bat
deploy.bat root@203.0.113.10 --address 203.0.113.10 --domain vpn.example.com
```

Use your IP and domain. The script copies the project to `/opt/privatevpn` and installs. SSH as root. That is the VDSina default.

No domain:

```bat
deploy.bat root@203.0.113.10 --address 203.0.113.10
```

The panel certificate is then self-signed. Happ often rejects that.

When the script finishes, read the password and open the panel:

```bash
ssh root@203.0.113.10
cat /etc/privatevpn/admin.password
```

The panel is `https://vpn.example.com:8443`. The password file is mode 0600. It is created only on the first install.

### Update

After you change the files in this folder:

```bat
deploy.bat root@203.0.113.10
```

An update rebuilds `/usr/local/bin/privatevpn` and restarts Xray and the panel. It does not change the admin password, Reality keys, or device locks.

The upload skips `.git`, `bin`, executables, `config.json`, `admin.password`, `data`, and database files. Do not put those secrets in this folder before you run the bat.

### Manual upload

Use this if you copy the folder yourself with WinSCP, FileZilla, or `scp`.

1. Upload this folder to `/opt/privatevpn`. Do not upload `config.json` or `admin.password` from your PC.
2. SSH in as root. If the copy changed script line endings, fix them, then install:

```bash
sed -i 's/\r$//' /opt/privatevpn/deploy/*.sh
bash /opt/privatevpn/deploy/update.sh --address 203.0.113.10 --domain vpn.example.com
```

3. Later, upload the new files to the same folder and run:

```bash
sed -i 's/\r$//' /opt/privatevpn/deploy/*.sh
bash /opt/privatevpn/deploy/update.sh
```

4. Read the password once with `cat /etc/privatevpn/admin.password`.

`deploy.bat` already strips those carriage returns before it runs the script. A second run of `deploy/install-ubuntu.sh` with the same `--address` is safe too: if `/etc/privatevpn/config.json` already exists, it does not generate a new password or new Reality keys.

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
