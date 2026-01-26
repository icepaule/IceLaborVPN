#!/bin/bash
#
# Tailscale Deployment Script for Headscale (Linux)
# For ManageEngine Endpoint Central
#
# Part of IceLaborVPN - https://github.com/icepaule/IceLaborVPN
#

set -e

# === CONFIGURATION - MODIFY THESE VALUES ===
HEADSCALE_URL="https://headscale.example.com"              # Your Headscale URL
HEADSCALE_API_KEY="YOUR_HEADSCALE_API_KEY_HERE"            # Generate with: headscale apikeys create --expiration 365d
HEADSCALE_USER="default"                                    # Headscale user/namespace
# ============================================

LOG_FILE="/var/log/tailscale-deploy.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

get_authkey() {
    log "Retrieving authkey from Headscale API..."
    
    EXPIRATION=$(date -u -d "+1 hour" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -v+1H '+%Y-%m-%dT%H:%M:%SZ')
    
    RESPONSE=$(curl -s -X POST "$HEADSCALE_URL/api/v1/preauthkey" \
        -H "Authorization: Bearer $HEADSCALE_API_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"user\": \"$HEADSCALE_USER\", \"reusable\": false, \"ephemeral\": false, \"expiration\": \"$EXPIRATION\"}")
    
    AUTHKEY=$(echo "$RESPONSE" | grep -o '"key":"[^"]*"' | cut -d'"' -f4)
    
    if [ -z "$AUTHKEY" ]; then
        log "ERROR: Could not retrieve authkey: $RESPONSE"
        exit 1
    fi
    
    log "Authkey received: ${AUTHKEY:0:8}..."
    echo "$AUTHKEY"
}

install_tailscale() {
    if command -v tailscale &> /dev/null; then
        log "Tailscale already installed: $(tailscale version)"
        return 0
    fi
    
    log "Installing Tailscale..."
    
    # Detect OS
    if [ -f /etc/debian_version ]; then
        log "Detected: Debian/Ubuntu"
        curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/jammy.noarmor.gpg | tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null
        curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/jammy.tailscale-keyring.list | tee /etc/apt/sources.list.d/tailscale.list
        apt-get update
        apt-get install -y tailscale
        
    elif [ -f /etc/redhat-release ]; then
        log "Detected: RHEL/CentOS/Fedora"
        dnf config-manager --add-repo https://pkgs.tailscale.com/stable/fedora/tailscale.repo 2>/dev/null || \
        yum-config-manager --add-repo https://pkgs.tailscale.com/stable/centos/8/tailscale.repo
        dnf install -y tailscale 2>/dev/null || yum install -y tailscale
        
    elif [ -f /etc/arch-release ]; then
        log "Detected: Arch Linux"
        pacman -Sy --noconfirm tailscale
        
    elif [ -f /etc/alpine-release ]; then
        log "Detected: Alpine"
        apk add tailscale
        
    else
        log "ERROR: Unknown Linux distribution"
        exit 1
    fi
    
    systemctl enable --now tailscaled
    log "Tailscale installed successfully"
}

connect_tailscale() {
    local AUTHKEY="$1"
    local HOSTNAME=$(hostname | tr '[:upper:]' '[:lower:]')
    
    log "Connecting to Headscale as '$HOSTNAME'..."
    
    tailscale up \
        --login-server="$HEADSCALE_URL" \
        --authkey="$AUTHKEY" \
        --hostname="$HOSTNAME" \
        --force-reauth
    
    sleep 3
    log "Tailscale Status:"
    tailscale status | tee -a "$LOG_FILE"
}

# === MAIN ===
log "=== Tailscale Deployment Start ==="
log "Computer: $(hostname)"

if [ "$EUID" -ne 0 ]; then
    log "ERROR: Script must be run as root"
    exit 1
fi

install_tailscale
AUTHKEY=$(get_authkey)
connect_tailscale "$AUTHKEY"

log "=== Deployment completed successfully ==="
exit 0
