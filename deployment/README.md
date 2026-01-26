# Endpoint Deployment Scripts

Automated Tailscale deployment scripts for ManageEngine Endpoint Central (or similar MDM solutions).

## Overview

These scripts automate the deployment of Tailscale clients to connect with your IceLaborVPN Headscale server. They:

1. **Install Tailscale** if not already present
2. **Retrieve a dynamic authkey** via Headscale API (no hardcoded keys)
3. **Connect to Headscale** with the device hostname
4. **Configure auto-start** on system boot

## Scripts

| Script | Platform | Description |
|--------|----------|-------------|
| `deploy-tailscale-windows.ps1` | Windows | PowerShell script for Windows 10/11/Server |
| `deploy-tailscale-linux.sh` | Linux | Bash script for Debian/Ubuntu/RHEL/Fedora/Arch/Alpine |
| `deploy-tailscale-macos.sh` | macOS | Bash script for macOS (uses Homebrew) |

## Prerequisites

### On the Headscale Server

Generate an API key with long expiration:

```bash
sudo headscale apikeys create --expiration 365d
```

Save the key securely - you'll need it for the deployment scripts.

### In the Scripts

Edit the configuration section at the top of each script:

```bash
HEADSCALE_URL="https://headscale.example.com"      # Your Headscale URL
HEADSCALE_API_KEY="YOUR_API_KEY_HERE"              # API key from above
HEADSCALE_USER="default"                            # Your Headscale user/namespace
```

## Deployment via ManageEngine Endpoint Central

### Windows Clients

1. Go to **Software Deployment** → **Script Repository** → **Add Script**
2. **Name:** `Tailscale Headscale Deployment`
3. **Script Type:** PowerShell
4. **Execution Mode:** System Context (Run as SYSTEM)
5. Paste the content of `deploy-tailscale-windows.ps1`
6. **Deploy** to target computers or groups

### Linux Clients

1. Go to **Script Repository** → **Add Script**
2. **Script Type:** Shell Script
3. **Run as:** root
4. Paste the content of `deploy-tailscale-linux.sh`
5. **Deploy** to target computers

### macOS Clients

1. Go to **Script Repository** → **Add Script**
2. **Script Type:** Shell Script
3. **Run as:** root
4. Paste the content of `deploy-tailscale-macos.sh`
5. **Deploy** to target computers

## Logs

| Platform | Log Location |
|----------|--------------|
| Windows | `%TEMP%\tailscale-deploy.log` |
| Linux | `/var/log/tailscale-deploy.log` |
| macOS | `/var/log/tailscale-deploy.log` |

## Security Considerations

- **API Key Protection:** The Headscale API key grants the ability to create auth keys. Store it securely and rotate annually.
- **Dynamic Auth Keys:** Each deployment generates a single-use auth key valid for 1 hour, minimizing exposure.
- **TLS:** All communication with Headscale uses HTTPS/TLS 1.2+.

## Troubleshooting

### Windows: "Access Denied"
Ensure the script runs as SYSTEM or Administrator.

### Linux: "Unknown distribution"
The script supports Debian, Ubuntu, RHEL, CentOS, Fedora, Arch, and Alpine. For other distributions, install Tailscale manually first.

### macOS: "Homebrew not found"
The script will attempt to install Homebrew. For managed environments, pre-install Homebrew or use the PKG installer from tailscale.com.

### API Error: "Unauthorized"
Verify the API key is correct and not expired. Generate a new one if needed.

## Related

- [Guacamole Auto-Sync](headscale-guacamole-sync.py) - Automatically create Guacamole connections for Headscale nodes
- [Headscale Onboarding](../scripts/headscale-onboard.sh) - Manual node onboarding script

## License

MIT License - Part of [IceLaborVPN](https://github.com/icepaule/IceLaborVPN)
