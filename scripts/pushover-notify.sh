#!/bin/bash
# =============================================================================
# IceLaborVPN Pushover Notification Script
# Sends alerts for security events
#
# Usage:
#   ./pushover-notify.sh --type login --user "admin" --ip "192.0.2.1"
#   ./pushover-notify.sh --type ban --ip "192.0.2.1" --reason "brute-force"
#   ./pushover-notify.sh --type alert --message "Custom alert message"
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Load environment
if [[ -f "$PROJECT_DIR/.env" ]]; then
    source "$PROJECT_DIR/.env"
elif [[ -f "/opt/IceLaborVPN/.env" ]]; then
    source "/opt/IceLaborVPN/.env"
fi

# Pushover Configuration
PUSHOVER_TOKEN="${PUSHOVER_APP_TOKEN:-}"
PUSHOVER_USER="${PUSHOVER_USER_KEY:-}"
PUSHOVER_API="https://api.pushover.net/1/messages.json"

# Hostname for identification
HOSTNAME="${HOSTNAME:-$(hostname)}"

# =============================================================================
# Functions
# =============================================================================

send_pushover() {
    local title="$1"
    local message="$2"
    local priority="${3:-0}"
    local sound="${4:-pushover}"

    if [[ -z "$PUSHOVER_TOKEN" ]] || [[ -z "$PUSHOVER_USER" ]]; then
        echo "ERROR: Pushover credentials not configured"
        return 1
    fi

    # Add timestamp
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S %Z')
    message="$message

Time: $timestamp
Host: $HOSTNAME"

    curl -s \
        --form-string "token=$PUSHOVER_TOKEN" \
        --form-string "user=$PUSHOVER_USER" \
        --form-string "title=$title" \
        --form-string "message=$message" \
        --form-string "priority=$priority" \
        --form-string "sound=$sound" \
        --form-string "html=1" \
        "$PUSHOVER_API" > /dev/null

    echo "Notification sent: $title"
}

notify_login() {
    local user="${1:-unknown}"
    local ip="${2:-unknown}"
    local method="${3:-web}"
    local connection="${4:-}"

    local title="🔐 IceLaborVPN Login"
    local message="<b>Successful Login</b>

User: <b>$user</b>
IP: <code>$ip</code>
Method: $method"

    if [[ -n "$connection" ]]; then
        message="$message
Connection: $connection"
    fi

    # GeoIP lookup (optional)
    local geo=$(curl -s "http://ip-api.com/line/$ip?fields=country,city" 2>/dev/null | tr '\n' ', ' | sed 's/,$//')
    if [[ -n "$geo" ]]; then
        message="$message
Location: $geo"
    fi

    send_pushover "$title" "$message" "0" "pushover"
}

notify_session_start() {
    local user="${1:-unknown}"
    local ip="${2:-unknown}"
    local connection="${3:-unknown}"
    local protocol="${4:-ssh}"

    local title="🖥️ Session Started"
    local message="<b>Remote Session Established</b>

User: <b>$user</b>
Connection: <b>$connection</b>
Protocol: $protocol
Client IP: <code>$ip</code>"

    send_pushover "$title" "$message" "0" "pushover"
}

notify_ban() {
    local ip="${1:-unknown}"
    local reason="${2:-multiple failed attempts}"
    local jail="${3:-guacamole}"
    local duration="${4:-3600}"

    local title="🚫 IP Banned"
    local message="<b>Fail2ban Triggered</b>

IP: <code>$ip</code>
Reason: $reason
Jail: $jail
Duration: ${duration}s"

    # GeoIP lookup
    local geo=$(curl -s "http://ip-api.com/line/$ip?fields=country,city,isp" 2>/dev/null | tr '\n' ', ' | sed 's/,$//')
    if [[ -n "$geo" ]]; then
        message="$message
Location/ISP: $geo"
    fi

    send_pushover "$title" "$message" "1" "siren"
}

notify_unban() {
    local ip="${1:-unknown}"
    local jail="${2:-guacamole}"

    local title="✅ IP Unbanned"
    local message="IP <code>$ip</code> has been unbanned from jail <b>$jail</b>"

    send_pushover "$title" "$message" "-1" "none"
}

notify_attack() {
    local attack_type="${1:-unknown}"
    local details="${2:-}"
    local ip="${3:-unknown}"

    local title="⚠️ SECURITY ALERT"
    local message="<b>Potential Attack Detected</b>

Type: <b>$attack_type</b>
Source IP: <code>$ip</code>"

    if [[ -n "$details" ]]; then
        message="$message

Details:
$details"
    fi

    # High priority with retry
    send_pushover "$title" "$message" "1" "alien"
}

notify_service_status() {
    local service="${1:-unknown}"
    local status="${2:-unknown}"
    local details="${3:-}"

    local title
    local priority
    local sound

    case "$status" in
        down|failed|error)
            title="🔴 Service Down: $service"
            priority="1"
            sound="falling"
            ;;
        up|started|recovered)
            title="🟢 Service Recovered: $service"
            priority="0"
            sound="magic"
            ;;
        *)
            title="🟡 Service Status: $service"
            priority="0"
            sound="pushover"
            ;;
    esac

    local message="Service: <b>$service</b>
Status: <b>$status</b>"

    if [[ -n "$details" ]]; then
        message="$message

$details"
    fi

    send_pushover "$title" "$message" "$priority" "$sound"
}

notify_custom() {
    local message="${1:-No message}"
    local priority="${2:-0}"

    send_pushover "📢 IceLaborVPN Alert" "$message" "$priority" "pushover"
}

show_help() {
    cat << 'EOF'
IceLaborVPN Pushover Notification Script

USAGE:
    pushover-notify.sh --type TYPE [OPTIONS]

TYPES:
    login       Successful login notification
    session     Remote session started
    ban         IP banned by Fail2ban
    unban       IP unbanned
    attack      Security attack detected
    service     Service status change
    custom      Custom message

OPTIONS:
    --user      Username (for login/session)
    --ip        IP address
    --method    Login method (web, ssh, rdp)
    --connection Connection name
    --protocol  Protocol (ssh, vnc, rdp)
    --reason    Reason for ban/alert
    --jail      Fail2ban jail name
    --duration  Ban duration in seconds
    --service   Service name
    --status    Service status (up, down)
    --message   Custom message text
    --priority  Message priority (-2 to 2)
    --details   Additional details

EXAMPLES:
    # Login notification
    pushover-notify.sh --type login --user admin --ip 192.0.2.1

    # Session started
    pushover-notify.sh --type session --user admin --ip 192.0.2.1 \
        --connection "CAPE Sandbox" --protocol ssh

    # IP banned
    pushover-notify.sh --type ban --ip 192.0.2.1 --reason "brute-force" \
        --jail guacamole --duration 3600

    # Attack detected
    pushover-notify.sh --type attack --ip 192.0.2.1 \
        --reason "SQL Injection attempt" --details "GET /api?id=1'OR'1'='1"

    # Custom alert
    pushover-notify.sh --type custom --message "Disk space low" --priority 1

ENVIRONMENT:
    PUSHOVER_APP_TOKEN  Pushover Application Token
    PUSHOVER_USER_KEY   Pushover User Key

EOF
}

# =============================================================================
# Main
# =============================================================================

# Parse arguments
TYPE=""
USER=""
IP=""
METHOD="web"
CONNECTION=""
PROTOCOL="ssh"
REASON=""
JAIL="guacamole"
DURATION="3600"
SERVICE=""
STATUS=""
MESSAGE=""
PRIORITY="0"
DETAILS=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --type) TYPE="$2"; shift 2 ;;
        --user) USER="$2"; shift 2 ;;
        --ip) IP="$2"; shift 2 ;;
        --method) METHOD="$2"; shift 2 ;;
        --connection) CONNECTION="$2"; shift 2 ;;
        --protocol) PROTOCOL="$2"; shift 2 ;;
        --reason) REASON="$2"; shift 2 ;;
        --jail) JAIL="$2"; shift 2 ;;
        --duration) DURATION="$2"; shift 2 ;;
        --service) SERVICE="$2"; shift 2 ;;
        --status) STATUS="$2"; shift 2 ;;
        --message) MESSAGE="$2"; shift 2 ;;
        --priority) PRIORITY="$2"; shift 2 ;;
        --details) DETAILS="$2"; shift 2 ;;
        --help|-h) show_help; exit 0 ;;
        *) echo "Unknown option: $1"; show_help; exit 1 ;;
    esac
done

# Execute based on type
case "$TYPE" in
    login)
        notify_login "$USER" "$IP" "$METHOD" "$CONNECTION"
        ;;
    session)
        notify_session_start "$USER" "$IP" "$CONNECTION" "$PROTOCOL"
        ;;
    ban)
        notify_ban "$IP" "$REASON" "$JAIL" "$DURATION"
        ;;
    unban)
        notify_unban "$IP" "$JAIL"
        ;;
    attack)
        notify_attack "$REASON" "$DETAILS" "$IP"
        ;;
    service)
        notify_service_status "$SERVICE" "$STATUS" "$DETAILS"
        ;;
    custom)
        notify_custom "$MESSAGE" "$PRIORITY"
        ;;
    "")
        echo "ERROR: --type is required"
        show_help
        exit 1
        ;;
    *)
        echo "ERROR: Unknown type: $TYPE"
        show_help
        exit 1
        ;;
esac
