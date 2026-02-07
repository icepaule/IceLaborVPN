#!/bin/bash
# =============================================================================
# IceLaborVPN Threat Intelligence Blocklist Manager
#
# Manages nftables-based IP blocklists from multiple OSINT feeds.
# Uses a dedicated nftables table (inet blocklist-table) with named sets
# for each feed source. Runs at priority -10 (before fail2ban).
#
# Usage:
#   update-blocklists.sh --init              Create table/sets, load cached feeds
#   update-blocklists.sh --feed <name|all>   Update specific feed or all feeds
#   update-blocklists.sh --status            Show current set sizes and last update
#   update-blocklists.sh --flush <name>      Flush a specific set
#
# Feed names: spamhaus, tor, et, blocklist_de, abuseipdb
# =============================================================================

set -euo pipefail

# =============================================================================
# Configuration
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CACHE_DIR="/var/lib/icelabor-blocklists/parsed"
CONFIG_DIR="/etc/icelabor-blocklists"
WHITELIST_FILE="$CONFIG_DIR/whitelist.conf"
ABUSEIPDB_KEY_FILE="$CONFIG_DIR/abuseipdb-key.conf"
LOGFILE="/var/log/icelaborvpn/blocklist-updates.log"
LOCKFILE="/var/run/icelabor-blocklist.lock"
PUSHOVER_SCRIPT="$SCRIPT_DIR/pushover-notify.sh"

TABLE_NAME="blocklist-table"
TABLE_FAMILY="inet"
CHAIN_NAME="blocklist-input"
CHAIN_PRIORITY="-10"

BATCH_SIZE=1000
CURL_TIMEOUT=30
CURL_RETRIES=2

# Feed definitions
declare -A FEED_URLS=(
    [spamhaus_v4]="https://www.spamhaus.org/drop/drop.txt"
    [spamhaus_v6]="https://www.spamhaus.org/drop/dropv6.txt"
    [tor]="https://www.dan.me.uk/torlist/?exit"
    [et]="https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
    [blocklist_de]="https://lists.blocklist.de/lists/all.txt"
    [abuseipdb]="API"
)

declare -A SET_NAMES=(
    [spamhaus_v4]="bl_spamhaus_v4"
    [spamhaus_v6]="bl_spamhaus_v6"
    [tor]="bl_tor_exit"
    [et]="bl_threats"
    [blocklist_de]="bl_active_attacks"
    [abuseipdb]="bl_abuseipdb"
)

declare -A SET_TYPES=(
    [spamhaus_v4]="ipv4_addr; flags interval"
    [spamhaus_v6]="ipv6_addr; flags interval"
    [tor]="ipv4_addr"
    [et]="ipv4_addr"
    [blocklist_de]="ipv4_addr"
    [abuseipdb]="ipv4_addr"
)

# =============================================================================
# Logging
# =============================================================================

mkdir -p "$(dirname "$LOGFILE")" 2>/dev/null

log() {
    local level="$1"
    shift
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*"
    echo "$msg" >> "$LOGFILE"
    if [[ "$level" == "ERROR" ]]; then
        echo "$msg" >&2
    else
        echo "$msg"
    fi
}

alert() {
    local message="$1"
    log "ALERT" "$message"
    if [[ -x "$PUSHOVER_SCRIPT" ]]; then
        "$PUSHOVER_SCRIPT" --type custom --message "Blocklist: $message" --priority 0 2>/dev/null || true
    fi
}

# =============================================================================
# Locking
# =============================================================================

acquire_lock() {
    exec 200>"$LOCKFILE"
    if ! flock -n 200; then
        log "ERROR" "Another instance is running (lockfile: $LOCKFILE)"
        exit 1
    fi
}

release_lock() {
    flock -u 200 2>/dev/null || true
    rm -f "$LOCKFILE" 2>/dev/null || true
}

trap release_lock EXIT

# =============================================================================
# Whitelist handling
# =============================================================================

load_whitelist() {
    WHITELIST_V4=()
    WHITELIST_V6=()

    if [[ ! -f "$WHITELIST_FILE" ]]; then
        log "WARN" "No whitelist file found at $WHITELIST_FILE"
        return
    fi

    while IFS= read -r line; do
        # Strip comments and whitespace
        line="${line%%#*}"
        line="${line// /}"
        [[ -z "$line" ]] && continue

        if [[ "$line" == *:* ]]; then
            WHITELIST_V6+=("$line")
        else
            WHITELIST_V4+=("$line")
        fi
    done < "$WHITELIST_FILE"

    log "INFO" "Loaded whitelist: ${#WHITELIST_V4[@]} IPv4, ${#WHITELIST_V6[@]} IPv6 entries"
}

# Check if an IP/CIDR is whitelisted
is_whitelisted() {
    local ip="$1"
    local -n wl_ref

    if [[ "$ip" == *:* ]]; then
        wl_ref=WHITELIST_V6
    else
        wl_ref=WHITELIST_V4
    fi

    # Extract just the IP part (strip CIDR if present)
    local ip_only="${ip%%/*}"

    for wl_entry in "${wl_ref[@]}"; do
        local wl_ip="${wl_entry%%/*}"
        local wl_cidr="${wl_entry#*/}"

        # Exact match check (simple but effective for most cases)
        if [[ "$ip_only" == "$wl_ip" ]]; then
            return 0
        fi

        # For CIDR ranges, use a network containment check
        if [[ "$wl_entry" == */* && "$ip" != */* ]]; then
            # Check if single IP falls within whitelisted CIDR
            if ip_in_cidr "$ip_only" "$wl_entry"; then
                return 0
            fi
        fi
    done

    return 1
}

# Simple IP-in-CIDR check using bash arithmetic (IPv4 only)
ip_in_cidr() {
    local ip="$1"
    local cidr="$2"
    local net="${cidr%%/*}"
    local mask="${cidr#*/}"

    # Convert IPs to integers
    local ip_int net_int
    IFS='.' read -r a b c d <<< "$ip"
    ip_int=$(( (a << 24) + (b << 16) + (c << 8) + d ))
    IFS='.' read -r a b c d <<< "$net"
    net_int=$(( (a << 24) + (b << 16) + (c << 8) + d ))

    local mask_int=$(( 0xFFFFFFFF << (32 - mask) ))
    [[ $(( ip_int & mask_int )) -eq $(( net_int & mask_int )) ]]
}

# Filter out whitelisted IPs from a file, write result to stdout
filter_whitelist() {
    local input_file="$1"
    local is_v6="$2"

    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue
        if ! is_whitelisted "$ip"; then
            echo "$ip"
        fi
    done < "$input_file"
}

# =============================================================================
# nftables operations
# =============================================================================

nft_table_exists() {
    nft list table "$TABLE_FAMILY" "$TABLE_NAME" &>/dev/null
}

nft_create_table() {
    log "INFO" "Creating nftables table $TABLE_FAMILY $TABLE_NAME"

    nft add table "$TABLE_FAMILY" "$TABLE_NAME"

    # Create all sets
    for feed in "${!SET_NAMES[@]}"; do
        local set_name="${SET_NAMES[$feed]}"
        local set_type="${SET_TYPES[$feed]}"
        log "INFO" "Creating set: $set_name (type: $set_type)"
        nft add set "$TABLE_FAMILY" "$TABLE_NAME" "$set_name" "{ type $set_type; }"
    done

    # Create input chain with priority before fail2ban
    nft add chain "$TABLE_FAMILY" "$TABLE_NAME" "$CHAIN_NAME" \
        "{ type filter hook input priority $CHAIN_PRIORITY; policy accept; }"

    # Add drop rules for each set
    for feed in "${!SET_NAMES[@]}"; do
        local set_name="${SET_NAMES[$feed]}"
        local set_type="${SET_TYPES[$feed]}"

        if [[ "$set_type" == *ipv6* ]]; then
            nft add rule "$TABLE_FAMILY" "$TABLE_NAME" "$CHAIN_NAME" \
                ip6 saddr "@${set_name}" counter drop
        else
            nft add rule "$TABLE_FAMILY" "$TABLE_NAME" "$CHAIN_NAME" \
                ip saddr "@${set_name}" counter drop
        fi
    done

    log "INFO" "nftables table $TABLE_NAME created with ${#SET_NAMES[@]} sets"
}

nft_flush_set() {
    local set_name="$1"
    nft flush set "$TABLE_FAMILY" "$TABLE_NAME" "$set_name"
}

# Batch-insert IPs into an nftables set
nft_batch_add() {
    local set_name="$1"
    local ip_file="$2"
    local total_count=0
    local batch=""
    local batch_count=0

    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue
        if [[ -n "$batch" ]]; then
            batch="$batch, $ip"
        else
            batch="$ip"
        fi
        batch_count=$((batch_count + 1))
        total_count=$((total_count + 1))

        if [[ $batch_count -ge $BATCH_SIZE ]]; then
            nft add element "$TABLE_FAMILY" "$TABLE_NAME" "$set_name" "{ $batch }" 2>/dev/null || true
            batch=""
            batch_count=0
        fi
    done < "$ip_file"

    # Flush remaining batch
    if [[ -n "$batch" ]]; then
        nft add element "$TABLE_FAMILY" "$TABLE_NAME" "$set_name" "{ $batch }" 2>/dev/null || true
    fi

    echo "$total_count"
}

# =============================================================================
# Feed parsers
# =============================================================================

# Download a feed with retries
download_feed() {
    local url="$1"
    local output="$2"

    curl -sSf --max-time "$CURL_TIMEOUT" --retry "$CURL_RETRIES" \
        -o "$output" "$url" 2>/dev/null
}

# Spamhaus DROP (IPv4 CIDRs)
parse_spamhaus_v4() {
    local raw_file="$1"
    local output="$2"

    # Lines like: 1.10.16.0/20 ; SBL123456
    grep -E '^[0-9]' "$raw_file" | sed 's/ *;.*//' | sort -u > "$output"
}

# Spamhaus DROP (IPv6 CIDRs)
parse_spamhaus_v6() {
    local raw_file="$1"
    local output="$2"

    grep -E '^[0-9a-fA-F]*:' "$raw_file" | sed 's/ *;.*//' | sort -u > "$output"
}

# Tor exit nodes (plain IPs, one per line)
parse_tor() {
    local raw_file="$1"
    local output="$2"

    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' "$raw_file" | sort -u > "$output"
}

# Emerging Threats (IPs and CIDRs, comments start with #)
parse_et() {
    local raw_file="$1"
    local output="$2"

    grep -E '^[0-9]' "$raw_file" | sort -u > "$output"
}

# Blocklist.de (plain IPs)
parse_blocklist_de() {
    local raw_file="$1"
    local output="$2"

    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' "$raw_file" | sort -u > "$output"
}

# AbuseIPDB API (top reported IPs)
parse_abuseipdb() {
    local output="$1"

    local api_key=""
    # Try fail2ban action config first
    if [[ -f "/etc/fail2ban/action.d/abuseipdb.local" ]]; then
        api_key=$(grep -oP 'abuseipdb_apikey\s*=\s*\K\S+' /etc/fail2ban/action.d/abuseipdb.local 2>/dev/null || true)
    fi
    # Then try dedicated key file
    if [[ -z "$api_key" && -f "$ABUSEIPDB_KEY_FILE" ]]; then
        api_key=$(grep -oP 'ABUSEIPDB_API_KEY\s*=\s*\K\S+' "$ABUSEIPDB_KEY_FILE" 2>/dev/null || true)
    fi

    if [[ -z "$api_key" ]]; then
        log "WARN" "No AbuseIPDB API key found, skipping feed"
        return 1
    fi

    local response
    response=$(curl -sSf --max-time "$CURL_TIMEOUT" \
        -H "Key: $api_key" \
        -H "Accept: application/json" \
        -G "https://api.abuseipdb.com/api/v2/blacklist" \
        -d "confidenceMinimum=90" \
        -d "limit=10000" 2>/dev/null)

    if [[ -z "$response" ]]; then
        log "ERROR" "AbuseIPDB API returned empty response"
        return 1
    fi

    # Extract IPs from JSON response using jq if available, fallback to grep
    if command -v jq &>/dev/null; then
        echo "$response" | jq -r '.data[].ipAddress' 2>/dev/null | \
            grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u > "$output"
    else
        echo "$response" | grep -oP '"ipAddress"\s*:\s*"\K[0-9.]+' | sort -u > "$output"
    fi
}

# =============================================================================
# Feed update logic
# =============================================================================

update_feed() {
    local feed="$1"
    local set_name="${SET_NAMES[$feed]}"
    local url="${FEED_URLS[$feed]}"
    local cache_file="$CACHE_DIR/${feed}.txt"
    local tmp_raw tmp_parsed tmp_filtered
    tmp_raw=$(mktemp)
    tmp_parsed=$(mktemp)
    tmp_filtered=$(mktemp)

    trap "rm -f '$tmp_raw' '$tmp_parsed' '$tmp_filtered'" RETURN

    log "INFO" "Updating feed: $feed (set: $set_name)"

    # Download / fetch
    local download_ok=true
    if [[ "$url" == "API" ]]; then
        # AbuseIPDB uses API, not direct download
        if ! parse_abuseipdb "$tmp_parsed"; then
            download_ok=false
        fi
    else
        if ! download_feed "$url" "$tmp_raw"; then
            download_ok=false
        fi
    fi

    if [[ "$download_ok" == "false" ]]; then
        log "ERROR" "Failed to download feed: $feed"
        if [[ -f "$cache_file" ]]; then
            log "INFO" "Using cached version for $feed ($(wc -l < "$cache_file") entries)"
            cp "$cache_file" "$tmp_filtered"
        else
            alert "Feed $feed download failed and no cache available"
            return 1
        fi
    else
        # Parse feed (skip for abuseipdb which is already parsed)
        if [[ "$url" != "API" ]]; then
            case "$feed" in
                spamhaus_v4) parse_spamhaus_v4 "$tmp_raw" "$tmp_parsed" ;;
                spamhaus_v6) parse_spamhaus_v6 "$tmp_raw" "$tmp_parsed" ;;
                tor)         parse_tor "$tmp_raw" "$tmp_parsed" ;;
                et)          parse_et "$tmp_raw" "$tmp_parsed" ;;
                blocklist_de) parse_blocklist_de "$tmp_raw" "$tmp_parsed" ;;
                *)
                    log "ERROR" "Unknown feed: $feed"
                    return 1
                    ;;
            esac
        fi

        local parsed_count
        parsed_count=$(wc -l < "$tmp_parsed")

        if [[ "$parsed_count" -eq 0 ]]; then
            log "WARN" "Feed $feed returned 0 entries after parsing"
            if [[ -f "$cache_file" ]]; then
                log "INFO" "Keeping cached version for $feed"
                cp "$cache_file" "$tmp_filtered"
            else
                return 0
            fi
        else
            # Apply whitelist filter
            local is_v6="false"
            [[ "$feed" == "spamhaus_v6" ]] && is_v6="true"
            filter_whitelist "$tmp_parsed" "$is_v6" > "$tmp_filtered"

            local filtered_count
            filtered_count=$(wc -l < "$tmp_filtered")
            local removed=$(( parsed_count - filtered_count ))

            if [[ $removed -gt 0 ]]; then
                log "INFO" "Whitelist removed $removed entries from $feed"
            fi

            # Update cache
            cp "$tmp_filtered" "$cache_file"
        fi
    fi

    # Apply to nftables
    local final_count
    final_count=$(wc -l < "$tmp_filtered")

    if [[ "$final_count" -gt 0 ]]; then
        nft_flush_set "$set_name"
        local loaded
        loaded=$(nft_batch_add "$set_name" "$tmp_filtered")
        log "INFO" "Feed $feed: loaded $loaded IPs into set $set_name"
    else
        log "WARN" "Feed $feed: no entries to load"
    fi
}

# =============================================================================
# Commands
# =============================================================================

cmd_init() {
    log "INFO" "=== Blocklist init starting ==="

    load_whitelist

    # Create table if it doesn't exist
    if nft_table_exists; then
        log "INFO" "Table $TABLE_NAME already exists, recreating..."
        nft delete table "$TABLE_FAMILY" "$TABLE_NAME"
    fi

    nft_create_table

    # Load cached feeds
    local loaded_feeds=0
    for feed in "${!SET_NAMES[@]}"; do
        local set_name="${SET_NAMES[$feed]}"
        local cache_file="$CACHE_DIR/${feed}.txt"

        if [[ -f "$cache_file" && -s "$cache_file" ]]; then
            local count
            count=$(nft_batch_add "$set_name" "$cache_file")
            log "INFO" "Loaded $count cached entries for $feed"
            loaded_feeds=$((loaded_feeds + 1))
        else
            log "INFO" "No cache for feed $feed"
        fi
    done

    log "INFO" "=== Blocklist init complete: $loaded_feeds feeds loaded from cache ==="
}

cmd_feed() {
    local target="$1"

    acquire_lock
    load_whitelist

    if ! nft_table_exists; then
        log "ERROR" "Table $TABLE_NAME does not exist. Run --init first."
        exit 1
    fi

    if [[ "$target" == "all" ]]; then
        local success=0 fail=0
        for feed in spamhaus_v4 spamhaus_v6 tor et blocklist_de abuseipdb; do
            if update_feed "$feed"; then
                success=$((success + 1))
            else
                fail=$((fail + 1))
            fi
        done
        log "INFO" "All feeds updated: $success succeeded, $fail failed"
    else
        # Map shorthand names to internal feed names
        case "$target" in
            spamhaus)
                update_feed "spamhaus_v4"
                update_feed "spamhaus_v6"
                ;;
            tor|et|blocklist_de|abuseipdb)
                update_feed "$target"
                ;;
            *)
                log "ERROR" "Unknown feed: $target"
                echo "Valid feeds: spamhaus, tor, et, blocklist_de, abuseipdb, all"
                exit 1
                ;;
        esac
    fi
}

cmd_status() {
    if ! nft_table_exists; then
        echo "Blocklist table does not exist. Run --init first."
        exit 1
    fi

    echo "=== IceLaborVPN Blocklist Status ==="
    echo ""
    printf "%-22s  %8s  %s\n" "SET" "ENTRIES" "LAST UPDATED"
    printf "%-22s  %8s  %s\n" "---" "-------" "------------"

    for feed in spamhaus_v4 spamhaus_v6 tor et blocklist_de abuseipdb; do
        local set_name="${SET_NAMES[$feed]}"
        local cache_file="$CACHE_DIR/${feed}.txt"

        # Count elements in set
        local count
        count=$(nft list set "$TABLE_FAMILY" "$TABLE_NAME" "$set_name" 2>/dev/null | \
            grep -c "," 2>/dev/null || echo "0")
        # Better count: number of elements line
        count=$(nft list set "$TABLE_FAMILY" "$TABLE_NAME" "$set_name" 2>/dev/null | \
            sed -n '/elements/,/}/p' | grep -oP '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|[0-9a-f:]+/' | wc -l 2>/dev/null || echo "0")

        local last_update="never"
        if [[ -f "$cache_file" ]]; then
            last_update=$(stat -c '%y' "$cache_file" 2>/dev/null | cut -d. -f1)
        fi

        printf "%-22s  %8s  %s\n" "$set_name" "$count" "$last_update"
    done

    echo ""
    echo "=== nftables counters ==="
    nft list chain "$TABLE_FAMILY" "$TABLE_NAME" "$CHAIN_NAME" 2>/dev/null | grep "counter" || echo "No counters found"
}

cmd_flush() {
    local target="$1"
    local set_name=""

    # Resolve target to set name
    for feed in "${!SET_NAMES[@]}"; do
        if [[ "$feed" == "$target" || "${SET_NAMES[$feed]}" == "$target" ]]; then
            set_name="${SET_NAMES[$feed]}"
            break
        fi
    done

    # Also check shorthand
    case "$target" in
        spamhaus)
            nft_flush_set "bl_spamhaus_v4"
            nft_flush_set "bl_spamhaus_v6"
            log "INFO" "Flushed sets: bl_spamhaus_v4, bl_spamhaus_v6"
            return 0
            ;;
    esac

    if [[ -z "$set_name" ]]; then
        echo "Unknown set: $target"
        echo "Valid sets: spamhaus_v4, spamhaus_v6, tor, et, blocklist_de, abuseipdb"
        exit 1
    fi

    nft_flush_set "$set_name"
    log "INFO" "Flushed set: $set_name"
}

# =============================================================================
# Main
# =============================================================================

show_help() {
    cat << 'EOF'
IceLaborVPN Blocklist Manager

USAGE:
    update-blocklists.sh --init              Initialize table and load cached feeds
    update-blocklists.sh --feed <name|all>   Update feed(s)
    update-blocklists.sh --status            Show blocklist status
    update-blocklists.sh --flush <name>      Flush a specific set

FEEDS:
    spamhaus      Spamhaus DROP (IPv4 + IPv6)
    tor           Tor exit nodes
    et            Emerging Threats
    blocklist_de  Blocklist.de active attacks
    abuseipdb     AbuseIPDB top reported IPs
    all           Update all feeds

EOF
}

if [[ $# -eq 0 ]]; then
    show_help
    exit 0
fi

case "$1" in
    --init)
        cmd_init
        ;;
    --feed)
        if [[ -z "${2:-}" ]]; then
            echo "ERROR: --feed requires a feed name or 'all'"
            exit 1
        fi
        cmd_feed "$2"
        ;;
    --status)
        cmd_status
        ;;
    --flush)
        if [[ -z "${2:-}" ]]; then
            echo "ERROR: --flush requires a set name"
            exit 1
        fi
        cmd_flush "$2"
        ;;
    --help|-h)
        show_help
        ;;
    *)
        echo "Unknown option: $1"
        show_help
        exit 1
        ;;
esac
