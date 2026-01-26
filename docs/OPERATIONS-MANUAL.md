# IceLaborVPN - Betriebs- und Administrationshandbuch

**Secure Remote Access Gateway für Malware-Analyse-Infrastruktur**

---

## Dokumenteninformationen

| Attribut | Wert |
|----------|------|
| Dokumentenversion | 1.0 |
| Klassifizierung | INTERN / VERTRAULICH |
| Zielgruppe | IT Security Officer (ITSO), DevSecOps, SOC |
| Compliance | DORA, ISO 27001, MITRE ATT&CK |
| Erstellungsdatum | 2026-01-26 |
| Nächste Review | 2026-07-26 |

---

## Inhaltsverzeichnis

1. [Einleitung und Zweck](#1-einleitung-und-zweck)
2. [Architektur und Komponenten](#2-architektur-und-komponenten)
3. [Sicherheitsarchitektur](#3-sicherheitsarchitektur)
4. [DORA-Compliance](#4-dora-compliance)
5. [MITRE ATT&CK Mapping](#5-mitre-attck-mapping)
6. [Installation und Erstkonfiguration](#6-installation-und-erstkonfiguration)
7. [Benutzerverwaltung](#7-benutzerverwaltung)
8. [Betriebsverfahren](#8-betriebsverfahren)
9. [Monitoring und Logging](#9-monitoring-und-logging)
10. [Incident Response](#10-incident-response)
11. [Backup und Recovery](#11-backup-und-recovery)
12. [Wartung und Updates](#12-wartung-und-updates)
13. [Notfallverfahren](#13-notfallverfahren)
14. [Anhänge](#14-anhänge)

---

## 1. Einleitung und Zweck

### 1.1 Dokumentenzweck

Dieses Handbuch beschreibt den sicheren Betrieb des IceLaborVPN-Systems, einer Zero-Trust Remote Access Lösung für den Zugriff auf die Malware-Analyse-Infrastruktur. Es richtet sich an IT Security Officers (ITSO) und erfüllt die Anforderungen des Digital Operational Resilience Act (DORA) für regulierte Finanzinstitute.

### 1.2 Systemzweck

IceLaborVPN ermöglicht:
- Sicheren Remote-Zugriff auf isolierte Malware-Analyse-Systeme
- Browser-basierten Zugang ohne Client-Installation (HTML5)
- Multi-Faktor-Authentifizierung (TOTP/2FA)
- Vollständige Session-Aufzeichnung für Audit-Zwecke
- Zero-Trust Netzwerkarchitektur über WireGuard VPN

### 1.3 Scope und Grenzen

| In Scope | Out of Scope |
|----------|--------------|
| VPN-Gateway (Headscale) | Malware-Analyse-Systeme selbst |
| Remote Access Gateway (Guacamole) | Endpoint-Security der Clients |
| Reverse Proxy (Nginx) | Netzwerk-Infrastruktur |
| Authentifizierung & Autorisierung | Physische Sicherheit |

---

## 2. Architektur und Komponenten

### 2.1 Architekturübersicht

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        INTERNET (Untrusted Zone)                             │
└─────────────────────────────────────┬───────────────────────────────────────┘
                                      │ HTTPS (443)
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                     DMZ - IceLaborVPN Gateway                                │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  Nginx Reverse Proxy                                                 │   │
│  │  • TLS 1.3 Termination      • Rate Limiting                         │   │
│  │  • Security Headers          • Fail2ban Integration                  │   │
│  └──────────────────────────────────┬──────────────────────────────────┘   │
│                                     │                                        │
│  ┌──────────────┐    ┌──────────────┴──────────────┐    ┌──────────────┐   │
│  │  Headscale   │    │    Apache Guacamole         │    │  Fail2ban    │   │
│  │  (VPN Ctrl)  │    │  • TOTP/2FA                 │    │  (IPS)       │   │
│  │              │    │  • Session Recording        │    │              │   │
│  └──────┬───────┘    │  • PostgreSQL Backend       │    └──────────────┘   │
│         │            └──────────────┬──────────────┘                        │
└─────────┼───────────────────────────┼───────────────────────────────────────┘
          │ WireGuard (UDP 41641)     │
          ▼                           ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                     Internal Network (Trusted Zone)                          │
│                                                                              │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐          │
│  │  CAPE Sandbox    │  │  MWDB            │  │  Analysis VMs    │          │
│  │  <TAILSCALE_IP>      │  │  <TAILSCALE_IP>:8443 │  │  <TAILSCALE_IP>      │          │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘          │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Komponentenbeschreibung

| Komponente | Version | Zweck | Port |
|------------|---------|-------|------|
| Nginx | 1.24.x | Reverse Proxy, TLS, Rate Limiting | 80, 443 |
| Headscale | 0.23.x | WireGuard VPN Control Plane | 8080 |
| Guacamole | 1.5.x | HTML5 Remote Access | 8085 |
| PostgreSQL | 15.x | Guacamole Database | 5432 |
| Fail2ban | 1.0.x | Intrusion Prevention | - |
| Tailscale | Latest | VPN Client | 41641/UDP |

### 2.3 Datenfluss

1. **Authentifizierung:** User → Nginx → Guacamole → PostgreSQL → TOTP Validation
2. **Session:** User → Nginx → Guacamole → guacd → Target System (via Tailscale)
3. **Recording:** guacd → Session Recording Storage → Audit Archive

---

## 3. Sicherheitsarchitektur

### 3.1 Defense in Depth

```
Layer 1: Network Security
├── Firewall (UFW)
├── Rate Limiting (nginx)
└── Fail2ban (IP Blocking)

Layer 2: Transport Security
├── TLS 1.3 only
├── HSTS enabled
└── Certificate Transparency

Layer 3: Authentication
├── Username/Password
├── TOTP/2FA (mandatory)
└── Session Tokens

Layer 4: Authorization
├── Role-Based Access Control
├── Connection-Level Permissions
└── Time-Based Restrictions

Layer 5: Audit & Monitoring
├── Access Logging
├── Session Recording
└── Security Event Alerting
```

### 3.2 Authentifizierungsmechanismen

| Mechanismus | Beschreibung | DORA-Relevanz |
|-------------|--------------|---------------|
| Password | SHA-256 gehashed, min. 12 Zeichen | Art. 9 (2) |
| TOTP | 6-stellig, 30s Intervall, SHA-1 | Art. 9 (2) |
| Brute-Force Protection | 5 Versuche → 5 Min. Sperre | Art. 9 (3) |
| Rate Limiting | 5 Login/Min., 30 Req/Sek. allgemein | Art. 9 (3) |
| Session Timeout | 60 Min. Inaktivität | Art. 9 (4) |

### 3.3 Verschlüsselung

| Bereich | Algorithmus | Schlüssellänge |
|---------|-------------|----------------|
| TLS | TLS 1.3 | 256-bit (AES-GCM) |
| VPN | WireGuard | Curve25519, ChaCha20-Poly1305 |
| Database | At-rest encryption | AES-256 |
| Password Storage | SHA-256 | 256-bit |

### 3.4 Netzwerksegmentierung

```
Zone 1: Internet (Untrusted)
    │
    ▼ [Firewall: allow 80, 443]
Zone 2: DMZ (Semi-Trusted)
    │ - Gateway Server
    │ - Guacamole
    │
    ▼ [WireGuard VPN only]
Zone 3: Lab Network (Trusted)
    │ - CAPE Sandbox
    │ - MWDB
    │ - Analysis VMs
```

---

## 4. DORA-Compliance

### 4.1 DORA-Anforderungen Mapping

Der Digital Operational Resilience Act (EU 2022/2554) stellt Anforderungen an IKT-Risikomanagement für Finanzunternehmen.

| DORA Artikel | Anforderung | Umsetzung in IceLaborVPN |
|--------------|-------------|--------------------------|
| **Art. 5** | IKT-Risikomanagement | Dokumentierte Risikobewertung, regelmäßige Reviews |
| **Art. 6** | IKT-Systeme & Tools | Gehärtete Konfiguration, Patch-Management |
| **Art. 9** | Schutz und Prävention | MFA, Encryption, Access Control |
| **Art. 10** | Erkennung | Logging, Monitoring, Alerting |
| **Art. 11** | Reaktion und Wiederherstellung | Incident Response, Backup/Recovery |
| **Art. 12** | Backup-Richtlinien | Tägliche Backups, getestete Wiederherstellung |
| **Art. 13** | Lernen und Weiterentwicklung | Post-Incident Reviews, Verbesserungsprozess |
| **Art. 14** | Kommunikation | Eskalationspfade, Meldepflichten |

### 4.2 IKT-Risikomanagement (Art. 5-6)

**Risikoidentifikation:**

| Risiko-ID | Risiko | Wahrscheinlichkeit | Auswirkung | Maßnahme |
|-----------|--------|-------------------|------------|----------|
| R-001 | Brute-Force Angriff | Hoch | Mittel | MFA, Rate Limiting, Fail2ban |
| R-002 | Session Hijacking | Mittel | Hoch | TLS 1.3, Secure Cookies |
| R-003 | Credential Theft | Mittel | Hoch | TOTP, Password Policy |
| R-004 | System Compromise | Niedrig | Kritisch | Hardening, Updates, Monitoring |
| R-005 | Denial of Service | Mittel | Mittel | Rate Limiting, CDN-ready |

### 4.3 Schutz und Prävention (Art. 9)

**Technische Maßnahmen:**

```yaml
access_control:
  authentication:
    - type: password
      min_length: 12
      complexity: true
      rotation: 90_days
    - type: totp
      mandatory: true
      issuer: IceLaborVPN

  authorization:
    model: RBAC
    roles:
      - admin: full_access
      - analyst: read_execute
      - auditor: read_only

  session:
    timeout: 60_minutes
    concurrent_limit: 3
    recording: mandatory

encryption:
  transport: TLS_1.3
  at_rest: AES_256
  key_management: HSM_recommended
```

### 4.4 Erkennung (Art. 10)

**Monitoring-Anforderungen:**

| Metrik | Schwellwert | Aktion |
|--------|-------------|--------|
| Fehlgeschlagene Logins | >5/5min | Alert + IP-Block |
| Concurrent Sessions | >3/User | Alert |
| Ungewöhnliche Zugriffszeiten | Außerhalb 06:00-22:00 | Alert |
| Ressourcenauslastung | >80% | Warning |
| Zertifikatsablauf | <30 Tage | Critical Alert |

### 4.5 Dokumentationspflichten

Gemäß DORA müssen folgende Dokumente vorgehalten werden:

- [ ] IKT-Risikomanagement-Rahmenwerk
- [ ] Business Continuity Plan
- [ ] Incident Response Plan
- [ ] Backup und Recovery Prozeduren
- [ ] Change Management Policy
- [ ] Audit Trails (min. 5 Jahre)
- [ ] Penetration Test Reports
- [ ] Vulnerability Assessments

---

## 5. MITRE ATT&CK Mapping

### 5.1 Abgedeckte Taktiken und Techniken

IceLaborVPN adressiert folgende MITRE ATT&CK Techniken:

| Tactic | Technique | ID | Mitigierung |
|--------|-----------|----|-----------  |
| **Initial Access** | Valid Accounts | T1078 | MFA, Password Policy, Account Lockout |
| | External Remote Services | T1133 | VPN-only Access, Network Segmentation |
| **Credential Access** | Brute Force | T1110 | Rate Limiting, Fail2ban, Account Lockout |
| | Credentials from Password Stores | T1555 | Encrypted Storage, No plaintext |
| **Persistence** | Account Manipulation | T1098 | Audit Logging, RBAC |
| **Lateral Movement** | Remote Services | T1021 | Network Segmentation, Session Recording |
| **Collection** | Screen Capture | T1113 | Session Recording (authorized) |
| **Exfiltration** | Exfiltration Over Web Service | T1567 | Egress Filtering, DLP |

### 5.2 Detection Rules

```yaml
# Beispiel: Sigma Rule für Brute-Force Detection
title: IceLaborVPN Brute Force Attempt
status: production
logsource:
  product: nginx
  service: access
detection:
  selection:
    cs-uri-stem: '/guacamole/api/tokens'
    sc-status: 401
  condition: selection | count() by c-ip > 5
  timeframe: 5m
level: high
tags:
  - attack.credential_access
  - attack.t1110
```

### 5.3 Incident Indikatoren (IOCs)

| Indikator | Typ | Schweregrad |
|-----------|-----|-------------|
| >5 fehlgeschlagene Logins/5min | Behavioral | Medium |
| Login außerhalb Geschäftszeiten | Behavioral | Low |
| Neuer User-Agent | Behavioral | Low |
| Geoblocking-Verletzung | Network | High |
| Session von mehreren IPs | Behavioral | High |

---

## 6. Installation und Erstkonfiguration

### 6.1 Voraussetzungen

**Hardware:**
- CPU: 2 Cores minimum
- RAM: 4 GB minimum
- Storage: 50 GB SSD
- Network: Public IPv4, optional IPv6

**Software:**
- Ubuntu 22.04 LTS oder Debian 12
- Root-Zugriff
- DNS-Eintrag für Domain

### 6.2 Installationsschritte

```bash
# 1. Repository klonen
git clone https://github.com/icepaule/IceLaborVPN.git
cd IceLaborVPN

# 2. Konfiguration anpassen
cp .env.example .env
nano .env  # Alle Werte ausfüllen!

# 3. Installation starten
chmod +x scripts/install.sh
sudo ./scripts/install.sh

# 4. TOTP einrichten (beim ersten Login)
# Browser: https://your-domain.com/guacamole/
```

### 6.3 Post-Installation Checkliste

- [ ] SSL-Zertifikat validieren
- [ ] TOTP für Admin-Account einrichten
- [ ] Backup-Job konfigurieren
- [ ] Monitoring-Alerts einrichten
- [ ] Fail2ban-Regeln testen
- [ ] Penetration Test durchführen
- [ ] Dokumentation vervollständigen

---

## 7. Benutzerverwaltung

### 7.1 Benutzerrollen

| Rolle | Berechtigungen | Verwendung |
|-------|---------------|------------|
| **Administrator** | Vollzugriff, Benutzerverwaltung | IT-Administration |
| **Analyst** | SSH/RDP Zugriff, keine Admin-Rechte | Malware-Analysten |
| **Auditor** | Nur Lesen, Session-Recordings | Compliance, ITSO |
| **Guest** | Zeitlich begrenzt, einzelne Connection | Externe Partner |

### 7.2 Benutzer anlegen

```bash
# Via Guacamole Web-UI (empfohlen)
# Settings → Users → New User

# Via PostgreSQL (nur Notfall)
sudo docker exec -it guacamole-db psql -U guacamole -d guacamole
INSERT INTO guacamole_entity (name, type) VALUES ('newuser', 'USER');
-- ... weitere SQL-Befehle
```

### 7.3 TOTP-Einrichtung

1. Benutzer loggt sich erstmalig ein
2. QR-Code wird angezeigt
3. Scan mit Authenticator-App (Google, Microsoft, Authy)
4. 6-stelligen Code eingeben zur Bestätigung
5. Backup-Codes sicher aufbewahren

### 7.4 Benutzer deaktivieren

```bash
# Sofortige Deaktivierung bei Sicherheitsvorfall
sudo docker exec -it guacamole-db psql -U guacamole -d guacamole \
  -c "UPDATE guacamole_user SET disabled = true WHERE entity_id = (SELECT entity_id FROM guacamole_entity WHERE name = 'username');"
```

---

## 8. Betriebsverfahren

### 8.1 Tägliche Aufgaben

| Aufgabe | Frequenz | Verantwortlich |
|---------|----------|----------------|
| Log-Review | Täglich | SOC / ITSO |
| Backup-Verifizierung | Täglich | IT-Operations |
| Systemstatus prüfen | Täglich | IT-Operations |
| Fehlgeschlagene Logins prüfen | Täglich | SOC |

### 8.2 Wöchentliche Aufgaben

| Aufgabe | Frequenz | Verantwortlich |
|---------|----------|----------------|
| Fail2ban-Statistiken | Wöchentlich | SOC |
| Benutzeraktivität Review | Wöchentlich | ITSO |
| Disk Space Check | Wöchentlich | IT-Operations |
| Container Updates prüfen | Wöchentlich | DevOps |

### 8.3 Monatliche Aufgaben

| Aufgabe | Frequenz | Verantwortlich |
|---------|----------|----------------|
| Security Updates einspielen | Monatlich | DevSecOps |
| Benutzerberechtigungen Review | Monatlich | ITSO |
| Backup-Restore Test | Monatlich | IT-Operations |
| SSL-Zertifikat Check | Monatlich | IT-Operations |

### 8.4 Status-Kommandos

```bash
# Systemstatus
/opt/IceLaborVPN/scripts/status.sh

# Container Status
docker compose -f /opt/guacamole/docker-compose.yml ps

# Tailscale Nodes
sudo headscale nodes list

# Fail2ban Status
sudo fail2ban-client status guacamole

# Aktive Sessions
curl -s http://localhost:8085/guacamole/api/session/data/postgresql/activeConnections \
  -H "Guacamole-Token: $TOKEN" | jq
```

---

## 9. Monitoring und Logging

### 9.1 Log-Quellen

| Log | Pfad | Retention | Inhalt |
|-----|------|-----------|--------|
| Nginx Access | /var/log/nginx/access.log | 90 Tage | HTTP-Requests |
| Nginx Error | /var/log/nginx/error.log | 90 Tage | Fehler, Rate Limits |
| Guacamole | docker logs guacamole | 30 Tage | Auth, Sessions |
| Fail2ban | /var/log/fail2ban.log | 90 Tage | Bans, Unbans |
| Session Recordings | /opt/guacamole/record/ | 1 Jahr | Video-Aufzeichnungen |
| Audit | /var/log/icelaborvpn/audit.log | 5 Jahre | Compliance Events |

### 9.2 Log-Aggregation

Empfohlene SIEM-Integration:
- **Elasticsearch/OpenSearch** für Log-Speicherung
- **Filebeat** für Log-Shipping
- **Grafana/Kibana** für Visualisierung

### 9.3 Alerting-Regeln

```yaml
alerts:
  - name: brute_force_attack
    condition: failed_logins > 10 in 5m
    severity: high
    action: notify_soc, block_ip

  - name: certificate_expiry
    condition: ssl_expiry < 30d
    severity: critical
    action: notify_ops

  - name: service_down
    condition: guacamole_health != ok
    severity: critical
    action: notify_ops, auto_restart

  - name: disk_space_low
    condition: disk_usage > 80%
    severity: warning
    action: notify_ops
```

---

## 10. Incident Response

### 10.1 Incident Klassifizierung

| Severity | Beschreibung | Reaktionszeit | Beispiele |
|----------|--------------|---------------|-----------|
| **Critical** | Systemkompromittierung, Datenverlust | 15 Min. | Unauthorized access, Malware |
| **High** | Service-Ausfall, aktiver Angriff | 1 Stunde | DDoS, Brute-Force erfolgreich |
| **Medium** | Verdächtige Aktivität | 4 Stunden | Ungewöhnliche Logins |
| **Low** | Policy-Verletzung | 24 Stunden | Password-Sharing |

### 10.2 Incident Response Prozess

```
1. DETECTION
   └─→ Automatisch (SIEM, Fail2ban) oder manuell (User Report)

2. ANALYSIS
   └─→ Scope bestimmen, IOCs sammeln, Timeline erstellen

3. CONTAINMENT
   └─→ Betroffene Accounts sperren
   └─→ Verdächtige IPs blocken
   └─→ Sessions beenden

4. ERADICATION
   └─→ Kompromittierte Credentials rotieren
   └─→ Malware entfernen
   └─→ Vulnerability patchen

5. RECOVERY
   └─→ Services wiederherstellen
   └─→ Monitoring verstärken
   └─→ Benutzer informieren

6. LESSONS LEARNED
   └─→ Post-Incident Review (innerhalb 5 Tage)
   └─→ Dokumentation aktualisieren
   └─→ Präventivmaßnahmen implementieren
```

### 10.3 Sofortmaßnahmen

```bash
# ALLE aktiven Sessions beenden
sudo docker exec guacamole-db psql -U guacamole -d guacamole \
  -c "DELETE FROM guacamole_user_session;"

# Spezifischen User sperren
sudo docker exec guacamole-db psql -U guacamole -d guacamole \
  -c "UPDATE guacamole_user SET disabled = true WHERE entity_id = (SELECT entity_id FROM guacamole_entity WHERE name = 'username');"

# IP sofort blocken
sudo fail2ban-client set guacamole banip 192.0.2.1

# Guacamole neu starten (Kill all sessions)
sudo docker compose -f /opt/guacamole/docker-compose.yml restart guacamole
```

### 10.4 Eskalationsmatrix

| Severity | L1 SOC | L2 Security | ITSO | CISO | Extern (BaFin) |
|----------|--------|-------------|------|------|----------------|
| Critical | ✓ | ✓ | ✓ | ✓ | Bei Datenverlust |
| High | ✓ | ✓ | ✓ | - | - |
| Medium | ✓ | ✓ | - | - | - |
| Low | ✓ | - | - | - | - |

---

## 11. Backup und Recovery

### 11.1 Backup-Strategie

| Komponente | Frequenz | Retention | Methode |
|------------|----------|-----------|---------|
| PostgreSQL | Täglich | 30 Tage | pg_dump |
| Konfiguration | Bei Änderung | 90 Tage | Git |
| Session Recordings | Kontinuierlich | 1 Jahr | Filesystem |
| SSL-Zertifikate | Bei Erneuerung | 2 Jahre | Encrypted Archive |

### 11.2 Backup-Script

```bash
#!/bin/bash
# /opt/IceLaborVPN/scripts/backup.sh

BACKUP_DIR="/backup/icelaborvpn/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# PostgreSQL Backup
docker exec guacamole-db pg_dump -U guacamole guacamole | \
  gzip > "$BACKUP_DIR/guacamole-db.sql.gz"

# Konfiguration
tar -czf "$BACKUP_DIR/config.tar.gz" \
  /opt/guacamole/config \
  /etc/nginx/sites-available \
  /etc/fail2ban/jail.d \
  /opt/IceLaborVPN/.env

# Encryption
gpg --symmetric --cipher-algo AES256 "$BACKUP_DIR/guacamole-db.sql.gz"
rm "$BACKUP_DIR/guacamole-db.sql.gz"

# Cleanup old backups
find /backup/icelaborvpn -type d -mtime +30 -exec rm -rf {} \;
```

### 11.3 Recovery-Prozedur

```bash
# 1. Container stoppen
cd /opt/guacamole && docker compose down

# 2. Datenbank wiederherstellen
gpg -d backup/guacamole-db.sql.gz.gpg | gunzip | \
  docker exec -i guacamole-db psql -U guacamole -d guacamole

# 3. Konfiguration wiederherstellen
tar -xzf backup/config.tar.gz -C /

# 4. Container starten
docker compose up -d

# 5. Funktionstest
curl -k https://localhost/guacamole/
```

### 11.4 RTO/RPO

| Metrik | Zielwert | Aktueller Wert |
|--------|----------|----------------|
| **RTO** (Recovery Time Objective) | 4 Stunden | 2 Stunden |
| **RPO** (Recovery Point Objective) | 24 Stunden | 24 Stunden |

---

## 12. Wartung und Updates

### 12.1 Update-Prozess

```
1. ANKÜNDIGUNG
   └─→ Wartungsfenster kommunizieren (min. 48h vorher)

2. VORBEREITUNG
   └─→ Backup erstellen
   └─→ Rollback-Plan dokumentieren
   └─→ Testumgebung aktualisieren

3. DURCHFÜHRUNG (im Wartungsfenster)
   └─→ Benutzer informieren
   └─→ Updates einspielen
   └─→ Funktionstests

4. VALIDIERUNG
   └─→ Security Scan
   └─→ Performance Check
   └─→ Log Review

5. DOKUMENTATION
   └─→ Change Record erstellen
   └─→ Konfiguration committen
```

### 12.2 Update-Kommandos

```bash
# System-Updates
sudo apt update && sudo apt upgrade -y

# Docker Images aktualisieren
cd /opt/guacamole
docker compose pull
docker compose up -d

# Headscale aktualisieren
sudo apt install --only-upgrade headscale

# Nach Updates
sudo systemctl restart nginx
sudo fail2ban-client reload
```

### 12.3 Vulnerability Management

| Severity | Patch-Zeitraum |
|----------|----------------|
| Critical | 24 Stunden |
| High | 7 Tage |
| Medium | 30 Tage |
| Low | 90 Tage |

---

## 13. Notfallverfahren

### 13.1 Service-Ausfall

```bash
# Quick Diagnostic
systemctl status nginx headscale docker
docker compose -f /opt/guacamole/docker-compose.yml ps
tail -100 /var/log/nginx/error.log

# Restart-Reihenfolge
sudo systemctl restart docker
cd /opt/guacamole && docker compose up -d
sudo systemctl restart nginx
sudo systemctl restart fail2ban
```

### 13.2 Kompromittierung vermutet

1. **Sofort:** Alle externen Zugriffe sperren
   ```bash
   sudo ufw deny from any to any port 443
   ```

2. **Analyse:** Logs sichern
   ```bash
   cp -r /var/log /forensics/$(date +%Y%m%d_%H%M%S)/
   docker logs guacamole > /forensics/guacamole.log
   ```

3. **Containment:** Siehe Abschnitt 10.3

4. **Kommunikation:** ITSO und CISO informieren

### 13.3 Notfall-Kontakte

| Rolle | Kontakt | Verfügbarkeit |
|-------|---------|---------------|
| IT-Operations | ops@example.com | 24/7 |
| ITSO | itso@example.com | Geschäftszeiten |
| CISO | ciso@example.com | Bei Critical |
| External SOC | +49 xxx | 24/7 |

---

## 14. Anhänge

### Anhang A: Konfigurationsdateien

Siehe `/opt/IceLaborVPN/config/` für alle Konfigurationsvorlagen.

### Anhang B: Compliance Checkliste

- [ ] DORA Art. 5-6: IKT-Risikomanagement dokumentiert
- [ ] DORA Art. 9: MFA implementiert
- [ ] DORA Art. 10: Monitoring aktiv
- [ ] DORA Art. 11: Incident Response Plan vorhanden
- [ ] DORA Art. 12: Backup-Policy implementiert
- [ ] ISO 27001 A.9: Access Control implementiert
- [ ] ISO 27001 A.12: Operations Security dokumentiert

### Anhang C: Glossar

| Begriff | Definition |
|---------|------------|
| DORA | Digital Operational Resilience Act (EU 2022/2554) |
| TOTP | Time-based One-Time Password |
| RBAC | Role-Based Access Control |
| RTO | Recovery Time Objective |
| RPO | Recovery Point Objective |
| IOC | Indicator of Compromise |
| MITRE ATT&CK | Adversarial Tactics, Techniques, and Common Knowledge |

### Anhang D: Änderungshistorie

| Version | Datum | Autor | Änderungen |
|---------|-------|-------|------------|
| 1.0 | 2026-01-26 | IcePorge | Initiale Version |

---

**Ende des Dokuments**

*Dieses Dokument unterliegt der regelmäßigen Überprüfung. Nächste geplante Review: 2026-07-26*
## 15. Endpoint Deployment

### 15.1 Übersicht

Für den automatisierten Rollout von Tailscale-Clients auf Unternehmensgeräten stehen Deployment-Scripts für verschiedene Plattformen zur Verfügung.

| Plattform | Script | MDM-Kompatibilität |
|-----------|--------|-------------------|
| Windows | `deploy-tailscale-windows.ps1` | Endpoint Central, Intune, SCCM |
| Linux | `deploy-tailscale-linux.sh` | Endpoint Central, Ansible, Puppet |
| macOS | `deploy-tailscale-macos.sh` | Endpoint Central, Jamf, Munki |

### 15.2 Sicherheitskonzept

Die Deployment-Scripts verwenden **dynamische Authkeys** statt statischer Keys:

```
┌──────────────┐     API-Request      ┌──────────────┐
│   Endpoint   │ ──────────────────▶  │  Headscale   │
│   Central    │                      │    Server    │
└──────────────┘                      └──────────────┘
       │                                     │
       │  Deploy Script                      │ Generate
       │  mit API-Key                        │ Single-Use Key
       ▼                                     ▼
┌──────────────┐     Einmal-Key       ┌──────────────┐
│   Client     │ ◀────────────────    │  Preauthkey  │
│   Device     │     (1h gültig)      │   (unique)   │
└──────────────┘                      └──────────────┘
```

**Vorteile:**
- Keine langlebigen Keys in Scripts
- Jedes Gerät erhält einzigartigen Key
- Kompromittierte Keys nach 1h ungültig
- Audit-Trail der Key-Erstellung

### 15.3 Deployment mit ManageEngine Endpoint Central

#### 15.3.1 Vorbereitung

1. **API-Key auf Headscale-Server erstellen:**
   ```bash
   sudo headscale apikeys create --expiration 365d
   ```
   Output sicher speichern.

2. **Scripts anpassen:**
   - `HEADSCALE_URL` auf Ihre Domain setzen
   - `HEADSCALE_API_KEY` eintragen
   - `HEADSCALE_USER` auf Ihren Namespace setzen

#### 15.3.2 Windows-Deployment

1. **Endpoint Central** → **Software Deployment** → **Script Repository**
2. **Add Script** mit folgenden Einstellungen:
   - **Name:** Tailscale Headscale Deployment
   - **Script Type:** PowerShell
   - **Execution Mode:** System Context
3. Inhalt von `deploy-tailscale-windows.ps1` einfügen
4. **Configuration** → **Deploy** auf Zielgruppen

#### 15.3.3 Linux-Deployment

1. **Script Repository** → **Add Script**
   - **Script Type:** Shell Script
   - **Run as:** root
2. Inhalt von `deploy-tailscale-linux.sh` einfügen
3. Deploy auf Linux-Zielgruppen

#### 15.3.4 macOS-Deployment

1. **Script Repository** → **Add Script**
   - **Script Type:** Shell Script
   - **Run as:** root
2. Inhalt von `deploy-tailscale-macos.sh` einfügen
3. Deploy auf Mac-Zielgruppen

### 15.4 Deployment-Logs

| Plattform | Log-Pfad |
|-----------|----------|
| Windows | `%TEMP%\tailscale-deploy.log` |
| Linux | `/var/log/tailscale-deploy.log` |
| macOS | `/var/log/tailscale-deploy.log` |

### 15.5 Troubleshooting

| Problem | Ursache | Lösung |
|---------|---------|--------|
| "Unauthorized" API-Fehler | API-Key abgelaufen/falsch | Neuen Key generieren |
| Installation schlägt fehl | Keine Internet-Verbindung | Proxy-Einstellungen prüfen |
| Verbindung timeout | Firewall blockiert UDP 41641 | Firewall-Regel hinzufügen |

---

## 16. Guacamole Auto-Sync

### 16.1 Funktionsbeschreibung

Das Guacamole Auto-Sync Feature synchronisiert automatisch Headscale-Nodes mit Apache Guacamole-Verbindungen. Es:

- Scannt alle Online-Nodes auf offene Ports (SSH/22, RDP/3389, VNC/5900)
- Erstellt automatisch Guacamole-Verbindungen für erkannte Services
- Entfernt Verbindungen wenn Nodes offline gehen
- Läuft als Cronjob alle 5 Minuten

### 16.2 Architektur

```
┌─────────────┐     JSON      ┌──────────────────┐
│  Headscale  │ ────────────▶ │                  │
│   CLI       │               │   Sync-Script    │
└─────────────┘               │   (Python 3)     │
                              │                  │
┌─────────────┐   Port-Scan   │                  │
│   Nodes     │ ◀──────────── │                  │
│ 22/3389/5900│               └────────┬─────────┘
└─────────────┘                        │
                                       │ SQL
                              ┌────────▼─────────┐
                              │    Guacamole     │
                              │    PostgreSQL    │
                              └──────────────────┘
```

### 16.3 Konfiguration

Das Script `/opt/guacamole/headscale-guacamole-sync.py` enthält folgende Konfigurationsoptionen:

```python
CONFIG = {
    "default_username": "admin",       # Standard-Benutzername für Verbindungen
    "ssh_color_scheme": "green-black", # SSH-Terminal Farbschema
    "scan_timeout": 1,                 # Port-Scan Timeout in Sekunden
    "skip_nodes": ["headscale-gw"],    # Nodes die übersprungen werden
}
```

### 16.4 Installation

```bash
# Script installieren
sudo cp deployment/headscale-guacamole-sync.py /opt/guacamole/
sudo chmod +x /opt/guacamole/headscale-guacamole-sync.py

# Cronjob einrichten
echo '*/5 * * * * root /usr/bin/python3 /opt/guacamole/headscale-guacamole-sync.py >> /var/log/headscale-sync.log 2>&1' | \
  sudo tee /etc/cron.d/headscale-sync
```

### 16.5 Manuelle Ausführung

```bash
sudo python3 /opt/guacamole/headscale-guacamole-sync.py
```

### 16.6 Namenskonvention

Automatisch erstellte Verbindungen folgen dem Schema:

| Protokoll | Verbindungsname |
|-----------|----------------|
| SSH | `{hostname} (SSH)` |
| RDP | `{hostname} (RDP)` |
| VNC | `{hostname} (VNC)` |

### 16.7 Log-Analyse

```bash
# Live-Log verfolgen
tail -f /var/log/headscale-sync.log

# Letzte Sync-Ausgabe
tail -50 /var/log/headscale-sync.log
```

**Beispiel-Output:**
```
[2026-01-26T18:04:16] === Starte Headscale-Guacamole Sync ===
[2026-01-26T18:04:16] Gefunden: 4 Headscale-Nodes, 3 Guacamole-Verbindungen
[2026-01-26T18:04:16] Prüfe Node: sandbox-01 (100.64.0.x)
[2026-01-26T18:04:16]   Port 22 (ssh) offen
[2026-01-26T18:04:17]   Port 3389 (rdp) geschlossen
[2026-01-26T18:04:17] Prüfe Node: workstation-01 (100.64.0.y)
[2026-01-26T18:04:18]   Port 3389 (rdp) offen
[2026-01-26T18:04:18] Erstelle Verbindung: workstation-01 (RDP)
[2026-01-26T18:04:19] === Sync abgeschlossen ===
```

---

## 17. API-Referenz

### 17.1 Headscale API

Die Headscale REST-API ermöglicht programmatische Verwaltung:

**Basis-URL:** `https://<headscale-domain>/api/v1/`

**Authentifizierung:** Bearer Token
```bash
curl -H "Authorization: Bearer <API_KEY>" \
  https://headscale.example.com/api/v1/node
```

### 17.2 Wichtige Endpoints

| Endpoint | Methode | Beschreibung |
|----------|---------|--------------|
| `/node` | GET | Liste aller Nodes |
| `/preauthkey` | POST | Neuen Authkey erstellen |
| `/preauthkey` | GET | Authkeys auflisten |
| `/user` | GET | Benutzer/Namespaces auflisten |

### 17.3 Authkey erstellen (API)

```bash
curl -X POST "https://headscale.example.com/api/v1/preauthkey" \
  -H "Authorization: Bearer <API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "user": "lab",
    "reusable": false,
    "ephemeral": false,
    "expiration": "2026-01-27T00:00:00Z"
  }'
```

---

*Ergänzung zum Operations Manual v1.0 - Stand: 2026-01-26*
