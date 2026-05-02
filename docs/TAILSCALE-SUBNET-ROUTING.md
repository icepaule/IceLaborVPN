# Tailscale Subnet Routing for Portal

Stand: 2026-05-02

## Architektur

```
┌─────────────────┐       ┌──────────────────┐       ┌──────────────┐
│ Tailscale-Client│       │ Headscale-VM     │       │ Heim-LAN     │
│ (iPhone/AWS/PC) │ ─────▶│ headscale.thesoc.│ ─────▶│ via Subnet-  │
│  100.64.0.x     │  TS   │ de (46.4.142.238)│  TS   │ Router       │
└─────────────────┘       └──────────────────┘       │ (synnas+nuc) │
                                  │                  └──────────────┘
                          ┌───────┴────────┐
                          │ nginx          │
                          │ portal.thesoc. │
                          │ de (auth_req)  │
                          └────────────────┘
```

## Hetzner-VM (`headscale-gw`, 46.4.142.238)

- Tailscale 1.96+, akzeptiert Routes (`tailscale set --accept-routes`).
- Empfängt LAN-Subnets via Tailscale-Subnet-Router (synnas / nuc-ha).
- nginx `/etc/nginx/sites-enabled/portal` + `include /etc/nginx/portal-extras.conf;`.
- HTTP/2 erforderlich (`listen 443 ssl http2;`) — Tailscale-Noise-Protokoll braucht extended-CONNECT (RFC 8441).

## Subnet-Router

Zwei aktive Router auf dem Tailnet (Failover-Setup):

| Node | Routes | Primary für |
|---|---|---|
| nuc-ha (NUC-HA, 100.64.0.8) | 10.10.0.0/24, 10.10.10/24, 10.10.12/24, 10.10.13/24, 192.168.1/24, 192.168.178/24 | alle 6 Heim-LANs |
| synnas (Synology, 100.64.0.3) | + 10.10.33.0/24 (NFS-Storage) | nur 10.10.33/24 (exklusiv); Failover für andere |

### Setup auf neuem Router

```bash
# Linux/Synology mit Tailscale
tailscale set --advertise-routes=10.10.0.0/24,10.10.10.0/24,10.10.12.0/24,10.10.13.0/24,10.10.33.0/24,192.168.1.0/24,192.168.178.0/24 --accept-routes

# Auf Headscale-Server (VM)
headscale routes list
headscale routes enable -r <id>   # für jeden enabled-fähigen Eintrag
```

### Voraussetzungen

- IPv4 Forwarding: `sysctl net.ipv4.ip_forward=1`
- Linux iptables: keine Drop-Regel auf gewünschten Ports
- Auf Sophos (im DMZ-Subnet): NoNAT-Regel und FW-Allow für die Subnetze

## Portal-Server (Sophos NAT-Setup)

Hetzner-Sophos hat:
- `NoNAT Hetzner DMZ1 to Any`: Source `46.4.142.232/29` → Translated Source = Original (kein MASQ auf Reply!)
- `NoNAT VPN Hetzner` und `NoNAT Hetzner to VPN` für 10.10.0/24 ↔ DMZ1
- `Allow Headscale Direct Inbound`: WAN→DMZ, HTTP+HTTPS Allow für 46.4.142.238
- WSP-Regel `WAF_Headscale` deaktiviert/gelöscht (DNS umgeht WSP direkt)

## DNS-Split

| Hostname | Resolves zu | Zweck |
|---|---|---|
| headscale.thesoc.de | 46.4.142.238 (direkt zur VM) | Tailscale-Login (Noise/HTTP2) |
| portal.thesoc.de | 94.130.248.179 (Sophos Public) | Web-Portal mit WAF + auth_request |

## Bekannte Limitationen

- **Sophos WSP unterstützt kein HTTP/2 und kein `upgrade=any`** — Tailscale-Login braucht direkten Pfad zur VM (DNS umgangen).
- **Lokales Netz**: FritzBox/UniFi haben statische Routen für `46.4.142.232/29 → lokale Sophos`. Externe Tailscale-Clients sind davon nicht betroffen.

## Cert-Renewal

Headscale-VM nutzt Letsencrypt mit `--nginx`-Authenticator (nicht standalone, da nginx auf 80 lauscht):
```
authenticator = nginx
```
in `/etc/letsencrypt/renewal/headscale.thesoc.de.conf`.
