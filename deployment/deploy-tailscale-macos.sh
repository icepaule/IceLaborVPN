#!/bin/bash
#
# Tailscale Deployment Script for Headscale (macOS)
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
    
    EXPIRATION=$(date -u -v+1H '+%Y-%m-%dT%H:%M:%SZ')
    
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
    if [ -d "/Applications/Tailscale.app" ] || command -v tailscale &> /dev/null; then
        log "Tailscale already installed"
        return 0
    fi
    
    log "Installing Tailscale..."
    
    # Check for Homebrew
    if ! command -v brew &> /dev/null; then
        log "Homebrew not found - installing..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    
    brew install --cask tailscale
    open -a Tailscale
    sleep 5
    
    log "Tailscale installed successfully"
}

connect_tailscale() {
    local AUTHKEY="$1"
    local HOSTNAME=$(hostname -s | tr '[:upper:]' '[:lower:]')
    
    log "Connecting to Headscale as '$HOSTNAME'..."
    
    TAILSCALE="/Applications/Tailscale.app/Contents/MacOS/Tailscale"
    if [ ! -f "$TAILSCALE" ]; then
        TAILSCALE=$(which tailscale 2>/dev/null || echo "/usr/local/bin/tailscale")
    fi
    
    if [ ! -f "$TAILSCALE" ]; then
        log "ERROR: Tailscale CLI not found"
        exit 1
    fi
    
    "$TAILSCALE" up \
        --login-server="$HEADSCALE_URL" \
        --authkey="$AUTHKEY" \
        --hostname="$HOSTNAME" \
        --force-reauth
    
    sleep 3
    log "Tailscale Status:"
    "$TAILSCALE" status | tee -a "$LOG_FILE"
}

# === MAIN ===
log "=== Tailscale Deployment Start ==="
log "Computer: $(hostname)"

if [ "$EUID" -ne 0 ]; then
    log "ERROR: Script must be run as root (sudo)"
    exit 1
fi

install_tailscale
AUTHKEY=$(get_authkey)
connect_tailscale "$AUTHKEY"

log "=== Deployment completed successfully ==="
exit 0
