#!/bin/bash
# =============================================================================
# Headscale Onboarding Script
# Fügt neue Systeme zum Headscale VPN hinzu
#
# Author: IcePorge Project
# Usage: ./headscale-onboard.sh [OPTIONS]
#
# Modes:
#   --generate-key    Erstellt einen neuen AuthKey auf dem Headscale-Server
#   --install         Installiert Tailscale und verbindet mit Headscale
#   --status          Zeigt aktuellen Verbindungsstatus
#   --list-nodes      Listet alle verbundenen Nodes (erfordert Server-Zugriff)
# =============================================================================

set -euo pipefail

# Konfiguration
HEADSCALE_SERVER="https://headscale.thesoc.de"
HEADSCALE_SSH_HOST="${HEADSCALE_SSH_USER}@${HEADSCALE_SSH_HOST}"
HEADSCALE_USER="lab"
KEY_EXPIRATION="365d"

# Farben
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

show_help() {
    cat << 'EOF'
Headscale Onboarding Script
============================

USAGE:
  ./headscale-onboard.sh [OPTION]

OPTIONS:
  --generate-key       Generiert einen neuen AuthKey auf dem Headscale-Server
                       (erfordert SSH-Zugriff auf den Server)

  --install [KEY]      Installiert Tailscale und verbindet mit Headscale
                       KEY kann als Argument oder interaktiv eingegeben werden

  --status             Zeigt den aktuellen Tailscale/Headscale Status

  --list-nodes         Listet alle verbundenen Nodes
                       (erfordert SSH-Zugriff auf den Server)

  --disconnect         Trennt die Verbindung zu Headscale

  --help               Zeigt diese Hilfe

BEISPIELE:
  # Neuen Key generieren (auf einem System mit Server-Zugriff)
  ./headscale-onboard.sh --generate-key

  # Tailscale installieren und verbinden
  ./headscale-onboard.sh --install abc123def456...

  # Status prüfen
  ./headscale-onboard.sh --status

OFFICE-ZUGRIFF:
  1. Tailscale Client installieren: https://tailscale.com/download
  2. Key generieren: ./headscale-onboard.sh --generate-key
  3. Im Tailscale Client: "Use custom server" -> https://headscale.thesoc.de
  4. AuthKey eingeben
  5. Zugriff auf CAPEv2: https://<TAILSCALE_IP>:8443
  6. Zugriff auf Cockpit: https://<TAILSCALE_IP>:9090

EOF
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Dieses Script muss als root ausgeführt werden"
        exit 1
    fi
}

generate_key() {
    log_info "Generiere neuen AuthKey auf ${HEADSCALE_SERVER}..."

    # SSH-Verbindung prüfen
    if ! ssh -o ConnectTimeout=5 -o BatchMode=yes ${HEADSCALE_SSH_HOST} "echo ok" &>/dev/null; then
        log_error "Keine SSH-Verbindung zu ${HEADSCALE_SSH_HOST} möglich"
        log_info "Stelle sicher, dass dein SSH-Key autorisiert ist"
        exit 1
    fi

    # Key generieren
    KEY=$(ssh ${HEADSCALE_SSH_HOST} "sudo headscale preauthkeys create --user ${HEADSCALE_USER} --reusable --expiration ${KEY_EXPIRATION}" 2>/dev/null | head -1)

    if [[ -z "$KEY" ]]; then
        log_error "Konnte keinen Key generieren"
        exit 1
    fi

    echo ""
    log_success "Neuer AuthKey erstellt (gültig für ${KEY_EXPIRATION}):"
    echo ""
    echo -e "  ${GREEN}${KEY}${NC}"
    echo ""
    log_info "Verwende diesen Key mit:"
    echo "  ./headscale-onboard.sh --install ${KEY}"
    echo ""
    log_info "Oder für manuelle Installation auf anderen Systemen:"
    echo "  tailscale up --login-server ${HEADSCALE_SERVER} --authkey ${KEY}"
    echo ""
}

install_tailscale() {
    local AUTH_KEY="$1"

    check_root

    # Prüfen ob Tailscale bereits installiert ist
    if command -v tailscale &>/dev/null; then
        log_info "Tailscale ist bereits installiert"
        INSTALLED=true
    else
        log_info "Installiere Tailscale..."
        INSTALLED=false

        # Betriebssystem erkennen
        if [[ -f /etc/debian_version ]]; then
            # Debian/Ubuntu
            curl -fsSL https://tailscale.com/install.sh | sh
        elif [[ -f /etc/redhat-release ]]; then
            # RHEL/CentOS/Fedora
            curl -fsSL https://tailscale.com/install.sh | sh
        else
            log_error "Unbekanntes Betriebssystem. Bitte Tailscale manuell installieren:"
            log_info "https://tailscale.com/download/linux"
            exit 1
        fi

        log_success "Tailscale installiert"
    fi

    # Tailscale-Daemon starten
    if ! systemctl is-active --quiet tailscaled; then
        log_info "Starte Tailscale-Daemon..."
        systemctl enable --now tailscaled
    fi

    # Aktuellen Status prüfen
    CURRENT_STATUS=$(tailscale status 2>&1 || true)

    if echo "$CURRENT_STATUS" | grep -q "100.64"; then
        log_warn "Tailscale ist bereits verbunden:"
        tailscale status
        echo ""
        read -p "Neu verbinden? (j/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Jj]$ ]]; then
            exit 0
        fi
    fi

    # Mit Headscale verbinden
    log_info "Verbinde mit ${HEADSCALE_SERVER}..."

    if tailscale up --login-server "${HEADSCALE_SERVER}" --authkey "${AUTH_KEY}" --reset 2>&1; then
        log_success "Erfolgreich verbunden!"
        echo ""
        tailscale status
        echo ""

        # IP-Adresse anzeigen
        IP=$(tailscale ip -4 2>/dev/null || echo "unbekannt")
        log_success "Tailscale IP: ${IP}"
        echo ""
        log_info "Dieses System ist jetzt über ${IP} im Headscale-Netzwerk erreichbar"
    else
        log_error "Verbindung fehlgeschlagen"
        exit 1
    fi
}

show_status() {
    echo ""
    log_info "Tailscale Status:"
    echo "================="

    if command -v tailscale &>/dev/null; then
        tailscale status 2>&1 || echo "Nicht verbunden"
        echo ""

        if tailscale status &>/dev/null; then
            IP=$(tailscale ip -4 2>/dev/null || echo "N/A")
            echo "Tailscale IP: ${IP}"
            echo "Login Server: $(tailscale debug prefs 2>/dev/null | grep -o 'ControlURL:[^,]*' | cut -d: -f2- || echo 'N/A')"
        fi
    else
        log_warn "Tailscale ist nicht installiert"
    fi
    echo ""
}

list_nodes() {
    log_info "Verbundene Nodes auf ${HEADSCALE_SERVER}:"
    echo ""

    if ! ssh -o ConnectTimeout=5 -o BatchMode=yes ${HEADSCALE_SSH_HOST} "echo ok" &>/dev/null; then
        log_error "Keine SSH-Verbindung zu ${HEADSCALE_SSH_HOST} möglich"
        exit 1
    fi

    ssh ${HEADSCALE_SSH_HOST} "sudo headscale nodes list" 2>/dev/null | grep -v "WRN.*updated version"
    echo ""
}

disconnect() {
    check_root
    log_info "Trenne Verbindung zu Headscale..."
    tailscale logout 2>&1 || true
    log_success "Verbindung getrennt"
}

# Hauptprogramm
case "${1:-}" in
    --generate-key)
        generate_key
        ;;
    --install)
        if [[ -n "${2:-}" ]]; then
            install_tailscale "$2"
        else
            echo -n "AuthKey eingeben: "
            read -r AUTH_KEY
            if [[ -z "$AUTH_KEY" ]]; then
                log_error "Kein AuthKey angegeben"
                exit 1
            fi
            install_tailscale "$AUTH_KEY"
        fi
        ;;
    --status)
        show_status
        ;;
    --list-nodes)
        list_nodes
        ;;
    --disconnect)
        disconnect
        ;;
    --help|-h|"")
        show_help
        ;;
    *)
        log_error "Unbekannte Option: $1"
        show_help
        exit 1
        ;;
esac
