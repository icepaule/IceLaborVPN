#!/bin/bash
# =============================================================================
# IceLaborVPN Installation Script
# Secure Remote Access Gateway for Malware Analysis Labs
#
# Components:
#   - Headscale (Self-hosted Tailscale control server)
#   - Apache Guacamole (HTML5 Remote Desktop Gateway)
#   - Nginx (Reverse Proxy with SSL)
#   - Fail2ban (Intrusion Prevention)
#
# DORA/MITRE Compliance Features:
#   - TOTP/2FA Authentication
#   - Rate Limiting
#   - Session Recording
#   - Audit Logging
#
# Usage: sudo ./install.sh
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LOG_FILE="/var/log/icelaborvpn-install.log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1" | tee -a "$LOG_FILE"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"; }

# =============================================================================
# Pre-flight Checks
# =============================================================================
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_env() {
    if [[ ! -f "$PROJECT_DIR/.env" ]]; then
        log_error ".env file not found. Copy .env.example to .env and configure it."
        exit 1
    fi
    source "$PROJECT_DIR/.env"

    # Validate required variables
    local required_vars=(
        "HEADSCALE_DOMAIN"
        "HEADSCALE_SERVER_IP"
        "GUAC_ADMIN_PASSWORD"
        "GUAC_DB_PASSWORD"
        "SSL_EMAIL"
    )

    for var in "${required_vars[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            log_error "Required variable $var is not set in .env"
            exit 1
        fi
    done

    log_success "Environment configuration validated"
}

check_system() {
    log "Checking system requirements..."

    # Check OS
    if [[ ! -f /etc/debian_version ]]; then
        log_error "This script requires Debian/Ubuntu"
        exit 1
    fi

    # Check memory
    local mem_gb=$(free -g | awk '/^Mem:/{print $2}')
    if [[ $mem_gb -lt 2 ]]; then
        log_warn "Less than 2GB RAM detected. Performance may be impacted."
    fi

    log_success "System requirements met"
}

# =============================================================================
# Installation Functions
# =============================================================================
install_dependencies() {
    log "Installing system dependencies..."

    apt-get update
    apt-get install -y \
        curl \
        wget \
        gnupg \
        lsb-release \
        ca-certificates \
        apt-transport-https \
        software-properties-common \
        nginx \
        certbot \
        python3-certbot-nginx \
        fail2ban \
        apache2-utils \
        jq \
        ufw

    log_success "Dependencies installed"
}

install_docker() {
    log "Installing Docker..."

    if command -v docker &>/dev/null; then
        log_warn "Docker already installed"
        return
    fi

    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker

    log_success "Docker installed"
}

install_headscale() {
    log "Installing Headscale..."

    local HEADSCALE_VERSION="0.23.0"
    local ARCH=$(dpkg --print-architecture)

    wget -q "https://github.com/juanfont/headscale/releases/download/v${HEADSCALE_VERSION}/headscale_${HEADSCALE_VERSION}_linux_${ARCH}.deb" \
        -O /tmp/headscale.deb

    dpkg -i /tmp/headscale.deb || apt-get install -f -y
    rm /tmp/headscale.deb

    # Configure Headscale
    mkdir -p /etc/headscale
    envsubst < "$PROJECT_DIR/config/headscale.yaml.template" > /etc/headscale/config.yaml

    systemctl enable --now headscale

    # Create initial user
    headscale users create "${HEADSCALE_USER:-lab}" || true

    log_success "Headscale installed"
}

install_tailscale() {
    log "Installing Tailscale client..."

    curl -fsSL https://tailscale.com/install.sh | sh
    systemctl enable --now tailscaled

    log_success "Tailscale installed"
}

setup_guacamole() {
    log "Setting up Apache Guacamole..."

    mkdir -p /opt/guacamole/{config,extensions,db-init,db-data,drive,record}

    # Copy configuration
    cp "$PROJECT_DIR/guacamole/docker-compose.yml" /opt/guacamole/
    envsubst < "$PROJECT_DIR/guacamole/guacamole.properties.template" > /opt/guacamole/config/guacamole.properties

    # Generate database schema
    docker run --rm guacamole/guacamole /opt/guacamole/bin/initdb.sh --postgresql > /opt/guacamole/db-init/01-schema.sql

    # Create admin user SQL
    local ADMIN_HASH=$(echo -n "$GUAC_ADMIN_PASSWORD" | sha256sum | cut -d' ' -f1 | tr 'a-f' 'A-F')
    envsubst < "$PROJECT_DIR/guacamole/02-admin-user.sql.template" > /opt/guacamole/db-init/02-admin-user.sql
    sed -i "s/{{ADMIN_HASH}}/$ADMIN_HASH/g" /opt/guacamole/db-init/02-admin-user.sql

    # Start containers
    cd /opt/guacamole
    docker compose up -d

    log_success "Guacamole configured"
}

setup_nginx() {
    log "Configuring Nginx reverse proxy..."

    # Generate htpasswd for basic auth fallback
    htpasswd -bc /etc/nginx/.htpasswd "${GUAC_ADMIN_USER:-admin}" "$GUAC_ADMIN_PASSWORD"

    # Copy nginx configuration
    envsubst '${HEADSCALE_DOMAIN} ${CAPE_HOST} ${CAPE_WEB_PORT} ${COCKPIT_PORT}' \
        < "$PROJECT_DIR/nginx/headscale.conf.template" \
        > /etc/nginx/sites-available/headscale

    ln -sf /etc/nginx/sites-available/headscale /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default

    nginx -t
    systemctl reload nginx

    log_success "Nginx configured"
}

setup_ssl() {
    log "Setting up SSL certificates..."

    certbot --nginx -d "$HEADSCALE_DOMAIN" --email "$SSL_EMAIL" --agree-tos --non-interactive

    log_success "SSL certificates installed"
}

setup_fail2ban() {
    log "Configuring Fail2ban..."

    envsubst < "$PROJECT_DIR/config/fail2ban-jail.conf.template" > /etc/fail2ban/jail.d/icelaborvpn.conf
    cp "$PROJECT_DIR/config/fail2ban-filter-guacamole.conf" /etc/fail2ban/filter.d/guacamole.conf

    systemctl restart fail2ban

    log_success "Fail2ban configured"
}

setup_firewall() {
    log "Configuring firewall..."

    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw allow http
    ufw allow https
    ufw --force enable

    log_success "Firewall configured"
}

setup_audit_logging() {
    log "Setting up audit logging..."

    # Create log directories
    mkdir -p /var/log/icelaborvpn/{access,auth,sessions}
    chmod 750 /var/log/icelaborvpn

    # Configure logrotate
    cat > /etc/logrotate.d/icelaborvpn << 'EOF'
/var/log/icelaborvpn/*/*.log {
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
}
EOF

    log_success "Audit logging configured"
}

create_systemd_services() {
    log "Creating systemd services..."

    cp "$PROJECT_DIR/systemd/icelaborvpn-guacamole.service" /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable icelaborvpn-guacamole

    log_success "Systemd services created"
}

# =============================================================================
# Post-Installation
# =============================================================================
generate_authkey() {
    log "Generating Headscale auth key..."

    local KEY=$(headscale preauthkeys create --user "${HEADSCALE_USER:-lab}" --reusable --expiration 365d 2>/dev/null | head -1)

    echo ""
    log_success "Initial AuthKey (valid for 365 days):"
    echo ""
    echo -e "  ${GREEN}${KEY}${NC}"
    echo ""
    echo "$KEY" > /opt/guacamole/initial-authkey.txt
    chmod 600 /opt/guacamole/initial-authkey.txt
}

connect_local_tailscale() {
    log "Connecting local Tailscale to Headscale..."

    local KEY=$(cat /opt/guacamole/initial-authkey.txt 2>/dev/null || headscale preauthkeys create --user "${HEADSCALE_USER:-lab}" --reusable --expiration 365d 2>/dev/null | head -1)

    tailscale up --login-server "https://${HEADSCALE_DOMAIN}" --authkey "$KEY" --hostname "$(hostname)-gw"

    log_success "Local Tailscale connected"
}

print_summary() {
    echo ""
    echo "=============================================="
    echo "  IceLaborVPN Installation Complete"
    echo "=============================================="
    echo ""
    echo "Access URLs:"
    echo "  Portal:    https://${HEADSCALE_DOMAIN}/"
    echo "  Guacamole: https://${HEADSCALE_DOMAIN}/guacamole/"
    echo ""
    echo "Credentials:"
    echo "  Username: ${GUAC_ADMIN_USER:-admin}"
    echo "  Password: [as configured in .env]"
    echo ""
    echo "IMPORTANT: On first login, set up TOTP/2FA!"
    echo ""
    echo "Tailscale IP: $(tailscale ip -4 2>/dev/null || echo 'Not connected')"
    echo ""
    echo "Logs: /var/log/icelaborvpn-install.log"
    echo ""
}

# =============================================================================
# Main
# =============================================================================
main() {
    echo ""
    echo "=============================================="
    echo "  IceLaborVPN Installation"
    echo "  Secure Remote Access for Malware Labs"
    echo "=============================================="
    echo ""

    check_root
    check_env
    check_system

    install_dependencies
    install_docker
    install_headscale
    install_tailscale
    setup_guacamole
    setup_nginx
    setup_ssl
    setup_fail2ban
    setup_firewall
    setup_audit_logging
    create_systemd_services

    generate_authkey
    connect_local_tailscale

    print_summary
}

main "$@"
