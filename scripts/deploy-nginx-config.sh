#!/bin/bash
# =============================================================================
# Deploy Nginx Configuration to Headscale Server
# Processes the template and applies it to the server
#
# Usage: ./deploy-nginx-config.sh
#
# Required Environment Variables (or set below):
#   HEADSCALE_DOMAIN  - Your headscale domain (e.g., headscale.example.com)
#   CAPE_HOST         - Tailscale IP of CAPE server (e.g., 100.64.0.1)
#   CAPE_WEB_PORT     - CAPE web port (default: 8443)
#   COCKPIT_PORT      - Cockpit port (default: 9090)
# =============================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE_FILE="${SCRIPT_DIR}/../nginx/headscale.conf.template"

# Configuration - set these or use environment variables
HEADSCALE_DOMAIN="${HEADSCALE_DOMAIN:-}"
CAPE_HOST="${CAPE_HOST:-}"
CAPE_WEB_PORT="${CAPE_WEB_PORT:-8443}"
COCKPIT_PORT="${COCKPIT_PORT:-9090}"
NGINX_LOGIN_RATE="${NGINX_LOGIN_RATE:-5r/m}"
NGINX_GENERAL_RATE="${NGINX_GENERAL_RATE:-30r/s}"

# Prompt for missing values
if [[ -z "$HEADSCALE_DOMAIN" ]]; then
    read -p "Headscale Domain: " HEADSCALE_DOMAIN
fi

if [[ -z "$CAPE_HOST" ]]; then
    read -p "CAPE Tailscale IP: " CAPE_HOST
fi

log_info "Configuration:"
echo "  HEADSCALE_DOMAIN: ${HEADSCALE_DOMAIN}"
echo "  CAPE_HOST: ${CAPE_HOST}"
echo "  CAPE_WEB_PORT: ${CAPE_WEB_PORT}"
echo "  COCKPIT_PORT: ${COCKPIT_PORT}"
echo ""

# Check if template exists
if [[ ! -f "$TEMPLATE_FILE" ]]; then
    log_error "Template not found: $TEMPLATE_FILE"
    exit 1
fi

# Create processed config
OUTPUT_FILE="/tmp/headscale-nginx.conf"

log_info "Processing template..."

# Use envsubst to replace variables
export HEADSCALE_DOMAIN CAPE_HOST CAPE_WEB_PORT COCKPIT_PORT NGINX_LOGIN_RATE NGINX_GENERAL_RATE

# envsubst needs the variable names to replace
envsubst '${HEADSCALE_DOMAIN} ${CAPE_HOST} ${CAPE_WEB_PORT} ${COCKPIT_PORT} ${NGINX_LOGIN_RATE} ${NGINX_GENERAL_RATE}' \
    < "$TEMPLATE_FILE" > "$OUTPUT_FILE"

log_success "Config generated: $OUTPUT_FILE"

# Show what to do
echo ""
log_info "To deploy, run these commands on the headscale server:"
echo ""
echo "  # Copy config to server (from this machine):"
echo "  scp $OUTPUT_FILE root@${HEADSCALE_DOMAIN}:/etc/nginx/sites-available/headscale"
echo ""
echo "  # Or manually copy content and on the server run:"
echo "  nginx -t && systemctl reload nginx"
echo ""

# Ask if we should try to deploy
read -p "Try to deploy now via SSH? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    log_info "Deploying to ${HEADSCALE_DOMAIN}..."

    if scp "$OUTPUT_FILE" "root@${HEADSCALE_DOMAIN}:/etc/nginx/sites-available/headscale"; then
        log_success "Config copied"

        log_info "Testing nginx config..."
        if ssh "root@${HEADSCALE_DOMAIN}" "nginx -t"; then
            log_info "Reloading nginx..."
            ssh "root@${HEADSCALE_DOMAIN}" "systemctl reload nginx"
            log_success "Deployment complete!"
        else
            log_error "Nginx config test failed. Please fix errors and reload manually."
            exit 1
        fi
    else
        log_error "Could not copy config. Please deploy manually."
        exit 1
    fi
else
    log_info "Manual deployment required. Config file: $OUTPUT_FILE"
fi

# Show the generated config for review
echo ""
log_info "Generated configuration preview:"
echo "=================================="
head -100 "$OUTPUT_FILE"
echo "..."
echo "(truncated - full config in $OUTPUT_FILE)"
