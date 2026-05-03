# Subdomain-SSO mit shared Auth-Cookie

Stand: 2026-05-03

Apps die unter Sub-Path nicht funktionieren (Solidtime, Homarr, Nextcloud, OpenWebUI, xwiki-bridge) bekommen eine **eigene Subdomain** unter `*.thesoc.de`. Apps bleiben dabei intern auf Port-Root (LAN-Direktzugriff bleibt erhalten), und der Auth-Cookie wird shared über `Domain=.thesoc.de`.

## Architektur

```
Tailscale-Client (LAN/Remote): http://<lan-ip>:<port>/        ← App auf Port-Root, unverändert
Office-Browser:                https://<app>.thesoc.de/       ← nginx auf Headscale-VM
                                       │
                                       ├── auth_request → 127.0.0.1:8089 (icelabor-auth)
                                       └── proxy_pass → http://100.64.0.X:<port> (Tailscale-Subnet-Router)
```

## DNS

Subdomains zeigen **direkt auf die Headscale-VM** (`46.4.142.238`), nicht auf die Sophos. Damit umgeht Tailscale-Traffic die Sophos-WSP-Limitation (kein HTTP/2 möglich) und der Sophos-Reverse-Proxy bleibt nur für `portal.thesoc.de` aktiv.

```dns
solidtime.thesoc.de.       3600  IN  A  46.4.142.238
homarr.thesoc.de.          3600  IN  A  46.4.142.238
nextcloud.thesoc.de.       3600  IN  A  46.4.142.238
openwebui.thesoc.de.       3600  IN  A  46.4.142.238
xwiki-bridge.thesoc.de.    3600  IN  A  46.4.142.238
```

**Warum kein Wildcard?** Damit AWS-Subdomains (`admin`, `auth`, `mwdb`, `cape`, ...) und alle anderen externen Services unangetastet bleiben. Wildcard `*.thesoc.de → 46.4.142.238` würde JEDEN nicht explizit gesetzten Hostname auf die VM ziehen.

## Auth-Cookie-Patch

Der icelabor-auth.service setzt nach Login einen Session-Cookie. Damit der Cookie über alle `*.thesoc.de` Subdomains gültig ist, wurde `/opt/icelabor/auth-gate.py` gepatcht:

| vorher | nachher |
|---|---|
| `Path=/; HttpOnly; Secure; SameSite=Strict` | `Path=/; Domain=.thesoc.de; HttpOnly; Secure; SameSite=Lax` |

`SameSite=Strict` muss auf `Lax`, weil der initiale Login-Redirect (`portal.thesoc.de/auth/login → solidtime.thesoc.de/`) sonst den Cookie nicht setzt.

Patch-Script: `auth/cookie-domain-patch.py` (idempotent, Backup automatisch nach `.bak.preSubdomain`).

## Privacy-Hinweis

Mit `Domain=.thesoc.de` wird der Cookie auch an alle anderen `*.thesoc.de` Hosts gesendet — inklusive AWS-gehostete Services (`auth.thesoc.de`, `mwdb.thesoc.de`, etc.). Diese kennen den Cookie-Namen `icelabor_session` nicht und ignorieren ihn — kein konkreter Schaden, aber zusätzliche Header-Bytes pro Request. Strengere Variante: alle Apps unter `*.app.thesoc.de` mit `Domain=.app.thesoc.de`.

## nginx-Block-Template (pro Subdomain)

Siehe `nginx/portal-subdomains.conf`. Pro Subdomain:

```nginx
server {
    listen 443 ssl http2;
    server_name <app>.thesoc.de;

    ssl_certificate     /etc/letsencrypt/live/<app>.thesoc.de/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/<app>.thesoc.de/privkey.pem;

    location = /auth/verify {
        internal;
        proxy_pass http://127.0.0.1:8089/auth/verify;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header Host $host;
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header Cookie $http_cookie;
    }
    location @auth_redirect {
        return 302 https://portal.thesoc.de/auth/login?redirect=https://$host$request_uri;
    }
    location / {
        auth_request /auth/verify;
        error_page 401 = @auth_redirect;
        proxy_pass http://<backend-tailscale-ip>:<port>;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_buffering off;
    }
}
```

## Cert-Erstellung pro Subdomain

```bash
# Auf Headscale-VM, nach DNS-Propagation
sudo certbot --nginx -d solidtime.thesoc.de
sudo certbot --nginx -d homarr.thesoc.de
sudo certbot --nginx -d nextcloud.thesoc.de
sudo certbot --nginx -d openwebui.thesoc.de
sudo certbot --nginx -d xwiki-bridge.thesoc.de

# Subdomain-Config aktivieren
sudo ln -s /etc/nginx/sites-available/portal-subdomains.conf /etc/nginx/sites-enabled/portal-subdomains.conf
sudo nginx -t && sudo systemctl reload nginx
```

## Sophos

**Keine Sophos-Änderungen nötig.** Die FW-Rule `Allow Headscale Direct Inbound` (WAN → DMZ, HTTP+HTTPS, Destination `Headscale_Backend = 46.4.142.238`) gilt automatisch für jede Subdomain die DNS-mäßig auf `.238` zeigt — Sophos macht reines L3-Forwarding ohne Hostname-Filtering.

## Erweitern um neue App

1. DNS-A-Record `<new>.thesoc.de → 46.4.142.238` (Hetzner DNS-Konsole)
2. Server-Block in `nginx/portal-subdomains.conf` ergänzen (Vorlage oben)
3. `certbot --nginx -d <new>.thesoc.de`
4. `nginx -t && systemctl reload nginx`
5. Tile in `website/index.html` aktualisieren — `<a href="https://<new>.thesoc.de/">`
6. Commit + Push
