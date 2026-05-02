# Portal Services

Stand: 2026-05-02

Das `portal.thesoc.de` Web-Portal aggregiert alle internen Services hinter einer **auth-protected Single-Page-Application** (`/var/www/html/portal/index.html`). Klick auf einen Tile öffnet den jeweiligen Service als Sub-Path-Reverse-Proxy oder als Direct-Link über Tailscale.

## Use Cases & Zugriff

Zwei orthogonale Wege, einen Service zu erreichen:

| Use Case | Pfad | Vorteile |
|---|---|---|
| **Tailscale-Client** (iPhone, AWS, Synology) | direkt `http://<lan-ip>:<port>/` über Subnet-Router | App läuft am Port-Root → keine Konfig-Änderung am Backend |
| **Office-Browser** (kein Tailscale) | `https://portal.thesoc.de/<service>/` mit auth + 2FA | überall erreichbar, kein Client-Install |

Beide funktionieren parallel — die App selbst muss nicht modifiziert werden, solange wir bei „Subdomain pro App" für die Office-Variante bleiben (siehe unten).

## Auth-Architektur

```
Browser → portal.thesoc.de → Sophos-WAF → nginx (auth_request /auth/verify)
                                            │
                                            ├── /auth/* → icelabor-auth.service (FastAPI, :8089)
                                            │             └── Guacamole-Auth-Gateway
                                            └── /<service>/ → Tailscale-Backend (100.64/10 oder LAN-IP)
```

Login-Flow: Guacamole-Postgres-User mit optionalem TOTP. Auth-Gate erstellt Session-Cookie, alle anderen `/<service>/` requesten `auth_request /auth/verify` und folgen dem Redirect zu `/auth/login` falls Session abgelaufen.

## Service-Sektionen

Siehe `website/index.html` und `nginx/portal-extras.conf` für vollständige Liste.

| Sektion | Services |
|---|---|
| Smart Home | Home Assistant, Node-RED, Beszel Hub |
| Network & Mgmt | AdGuard, Sophos, UniFi, FritzBox, Mikrotik, ESXi, USG |
| Storage | Synology DSM, Homarr, Heimdall, Portainer Syno, Docker Registry, Plex |
| Container/K8s | Portainer (NUC + K3s), ArgoCD, Grafana, Gateway-Cockpit |
| Knowledge | XWiki, XWiki-Bridge, XWiki-AutoDoc, AnythingLLM, Paperless-NGX, Paperless-AI, Open Archiver |
| AI/Search | SearXNG, OpenWebUI, Tax-AI, Analytics, Stock-Analyzer, Kibana, Qdrant, MinIO |
| Malware Analysis | CAPE Sandbox, Sandbox UI, CAPE Cockpit, MWDB |
| OSINT | SpiderFoot, Maigret, Blackbird, IceSpider, IceSeller, Leak-Monitor, NSDAP-UI/API |
| IoT | Tasmota Matrix1-4, Luft1, WiFi Buttons, Gasmeter, BSB-LAN |
| Remote | Guacamole Console, Cribbl |

## Tile-Markierungen

- 🔒 `class="tunnel-only"` — Service nur über Tailscale-VPN/-Subnet erreichbar (kein Reverse-Proxy, da App nicht subpath-fähig: FritzBox, UniFi, ESXi, Mikrotik, Sophos-Schwalbe). Klick öffnet direkte LAN-IP — funktioniert nur mit aktivem Tailscale.
- TBD `class="tbd"` — Service-Tile als Platzhalter, Backend noch nicht angebunden.

## Sub-Path-Limitationen — Empfehlung „Subdomain pro App"

Folgende Apps **brechen unter Sub-Path** (404 nach Login wegen hardcoded `/login`, `/static`, `/api` usw.) und brauchen weiterhin Port-Root:

- Solidtime, Nextcloud, Homarr, OpenWebUI, ArgoCD (manche Versionen)

Lösung: **eigene Subdomain pro App**, App bleibt auf Port-Root. Dies erhält LAN-Direkt-Zugriff UND ermöglicht Office-Browser-Zugriff:

```nginx
server {
    listen 443 ssl http2;
    server_name solidtime.thesoc.de;
    ssl_certificate     /etc/letsencrypt/live/wildcard.thesoc.de/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/wildcard.thesoc.de/privkey.pem;

    location / {
        auth_request /auth/verify;
        error_page 401 = @auth_redirect;
        proxy_pass http://100.64.0.3:8000;
        proxy_set_header Host $host;
        proxy_http_version 1.1;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
    }
}
```

Voraussetzungen:
1. **Wildcard-Letsencrypt-Cert** (`*.thesoc.de`) via DNS-01 challenge.
2. **Wildcard-A-Record** für `*.thesoc.de` → `94.130.248.179` (Sophos public).
3. **Sophos WSP-Regel** mit Domain-Liste oder Wildcard.

Nach Subdomain-Migration: Tile in `index.html` anpassen — `<a href="https://solidtime.thesoc.de/" target="_blank">`.

## Erweitern um neuen Service

1. **Tailscale-Reachability** prüfen: `curl -sk -I http://<lan-ip>:<port>/` muss antworten.
2. **Block in `nginx/portal-extras.conf`** anhängen — bzw. bei sub-path-feindlicher App Subdomain-Block (siehe oben).
3. **Tile in `website/index.html`** einfügen.
4. **Test**: `nginx -t && systemctl reload nginx`.
5. **Commit**: `git add nginx/portal-extras.conf website/index.html docs/PORTAL-SERVICES.md && git commit -m "Add <service>"`.

## Deployment

```bash
sudo cp nginx/portal-extras.conf /etc/nginx/portal-extras.conf
sudo cp website/index.html /var/www/html/portal/index.html
sudo nginx -t && sudo systemctl reload nginx
```

Plus einmalig in `/etc/nginx/sites-enabled/portal` vor der letzten `}` einfügen:

```
    include /etc/nginx/portal-extras.conf;
```

## Bekannter Status (2026-05-02)

| Status | Services |
|---|---|
| ✅ Funktional via /sub-path/ | ha, beszel, adguard, heimdall, dockerreg, portainer, portainer-k3s, portainer-syno, grafana, wiki, paperless, archiver, searxng, xwiki-llm, xwiki-autodoc, stock, kibana, minio, mwdb, iceseller, spiderfoot, maigret, blackbird, nsdap, matrix2/3/4, luft1, buttons, gasmeter, bsb |
| ⚠️ Sub-Path-broken (TODO Subdomain) | solidtime, homarr, nextcloud, openwebui, xwiki-bridge |
| ❌ Backend offline | taxai, analytics, cribbl (capev2-Server), argocd, paperless-ai, qdrant, icespider |
| 🔒 Tunnel-only (Tailscale required) | sophos, unifi, fritzbox, mikrotik, esxi, usg, plex |
