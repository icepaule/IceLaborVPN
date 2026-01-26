#!/bin/bash
# =============================================================================
# Guacamole Session Monitor
# Monitors Guacamole logs for successful logins and sessions
# Sends Pushover notifications for security events
#
# Run as systemd service or via cron
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NOTIFY_SCRIPT="$SCRIPT_DIR/pushover-notify.sh"
STATE_FILE="/var/run/guacamole-monitor.state"
LOG_FILE="/var/log/icelaborvpn/session-monitor.log"

# Create log directory
mkdir -p "$(dirname "$LOG_FILE")"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Get last processed position
get_state() {
    if [[ -f "$STATE_FILE" ]]; then
        cat "$STATE_FILE"
    else
        echo "0"
    fi
}

save_state() {
    echo "$1" > "$STATE_FILE"
}

# Monitor Docker logs
monitor_guacamole() {
    local last_pos=$(get_state)
    local current_pos=0

    # Get new log entries
    docker logs guacamole 2>&1 | tail -n +$((last_pos + 1)) | while read -r line; do
        current_pos=$((current_pos + 1))

        # Successful authentication
        if echo "$line" | grep -q "User.*successfully authenticated"; then
            local user=$(echo "$line" | grep -oP 'User "\K[^"]+')
            local ip=$(echo "$line" | grep -oP 'from \K[0-9.]+' || echo "unknown")

            log "LOGIN: User '$user' from $ip"
            "$NOTIFY_SCRIPT" --type login --user "$user" --ip "$ip" --method "guacamole"
        fi

        # Session started (connection established)
        if echo "$line" | grep -q "Connection.*successfully established"; then
            local connection=$(echo "$line" | grep -oP 'Connection "\K[^"]+' || echo "unknown")
            local user=$(echo "$line" | grep -oP 'for user "\K[^"]+' || echo "unknown")

            log "SESSION: User '$user' connected to '$connection'"
            "$NOTIFY_SCRIPT" --type session --user "$user" --connection "$connection"
        fi

        # Failed authentication (for additional alerting)
        if echo "$line" | grep -q "Authentication attempt rejected"; then
            local user=$(echo "$line" | grep -oP 'User "\K[^"]+' || echo "unknown")
            local ip=$(echo "$line" | grep -oP 'from \K[0-9.]+' || echo "unknown")

            log "FAILED LOGIN: User '$user' from $ip"
            # Don't notify on every failure (Fail2ban handles aggregation)
        fi

        # Permission denied (potential privilege escalation)
        if echo "$line" | grep -qi "permission denied\|unauthorized\|forbidden"; then
            log "SECURITY: Permission denied event detected"
            "$NOTIFY_SCRIPT" --type attack --reason "Permission Denied" \
                --details "$line" --ip "internal"
        fi

    done

    # Update state
    local total_lines=$(docker logs guacamole 2>&1 | wc -l)
    save_state "$total_lines"
}

# Monitor nginx access logs for suspicious patterns
monitor_nginx() {
    local nginx_log="/var/log/nginx/access.log"

    if [[ ! -f "$nginx_log" ]]; then
        return
    fi

    # Check for suspicious patterns in last 100 lines
    tail -100 "$nginx_log" | while read -r line; do
        local ip=$(echo "$line" | awk '{print $1}')

        # SQL Injection attempts
        if echo "$line" | grep -qiE "(union.*select|or.*1.*=.*1|drop.*table|insert.*into)"; then
            log "ATTACK: SQL Injection attempt from $ip"
            "$NOTIFY_SCRIPT" --type attack --reason "SQL Injection Attempt" \
                --ip "$ip" --details "$(echo "$line" | cut -c1-200)"
        fi

        # Path traversal
        if echo "$line" | grep -qE "(\.\./|\.\.\\\\|%2e%2e)"; then
            log "ATTACK: Path traversal attempt from $ip"
            "$NOTIFY_SCRIPT" --type attack --reason "Path Traversal Attempt" \
                --ip "$ip" --details "$(echo "$line" | cut -c1-200)"
        fi

        # XSS attempts
        if echo "$line" | grep -qiE "(<script|javascript:|onerror=|onload=)"; then
            log "ATTACK: XSS attempt from $ip"
            "$NOTIFY_SCRIPT" --type attack --reason "XSS Attempt" \
                --ip "$ip" --details "$(echo "$line" | cut -c1-200)"
        fi

        # Scanner/Bot detection
        if echo "$line" | grep -qiE "(nikto|sqlmap|nmap|masscan|acunetix)"; then
            log "ATTACK: Security scanner detected from $ip"
            "$NOTIFY_SCRIPT" --type attack --reason "Security Scanner Detected" \
                --ip "$ip" --details "Automated scanning tool"
        fi
    done
}

# Service health check
check_services() {
    local services=("guacamole" "guacd" "guacamole-db")

    for service in "${services[@]}"; do
        if ! docker ps --format '{{.Names}}' | grep -q "^${service}$"; then
            log "SERVICE DOWN: $service"
            "$NOTIFY_SCRIPT" --type service --service "$service" --status "down"
        fi
    done

    # Check nginx
    if ! systemctl is-active --quiet nginx; then
        log "SERVICE DOWN: nginx"
        "$NOTIFY_SCRIPT" --type service --service "nginx" --status "down"
    fi

    # Check headscale
    if ! systemctl is-active --quiet headscale; then
        log "SERVICE DOWN: headscale"
        "$NOTIFY_SCRIPT" --type service --service "headscale" --status "down"
    fi
}

# Main loop
main() {
    log "Starting Guacamole Monitor"

    while true; do
        monitor_guacamole
        monitor_nginx
        check_services

        # Run every 30 seconds
        sleep 30
    done
}

# Run once or as daemon
case "${1:-daemon}" in
    once)
        monitor_guacamole
        monitor_nginx
        check_services
        ;;
    daemon)
        main
        ;;
    *)
        echo "Usage: $0 [once|daemon]"
        exit 1
        ;;
esac
