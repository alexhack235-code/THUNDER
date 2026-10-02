#!/usr/bin/env bash
# ==============================================================================
# THUNDER - Dynamic Firewall & IP Quarantine Manager (Linux & Termux)
# Built by: NEXO-TECH
# ==============================================================================

ACTION="${1:-status}"
TARGET_IP="$2"
REASON="${3:-Threat detected by THUNDER Defender}"
LOG_DIR="$(dirname "$0")/../logs"
LOG_PATH="$LOG_DIR/defender_events.log"

mkdir -p "$LOG_DIR"

log_msg() {
    local level="$1"
    local msg="$2"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] [$level] [FIREWALL] $msg" >> "$LOG_PATH"

    case "$level" in
        ALERT) echo -e "\e[31m[$timestamp] [$level] [FIREWALL] $msg\e[0m" ;;
        WARN)  echo -e "\e[33m[$timestamp] [$level] [FIREWALL] $msg\e[0m" ;;
        INFO)  echo -e "\e[36m[$timestamp] [$level] [FIREWALL] $msg\e[0m" ;;
        OK)    echo -e "\e[32m[$timestamp] [$level] [FIREWALL] $msg\e[0m" ;;
    esac
}

block_ip() {
    local ip="$1"
    local reason="$2"
    if [ -z "$ip" ]; then
        log_msg "WARN" "No IP specified for blocking."
        return
    fi

    # Loopback protection
    if [[ "$ip" =~ ^(127\.0\.0\.1|0\.0\.0\.0|::1)$ ]]; then
        log_msg "WARN" "Refusing to block loopback IP: $ip"
        return
    fi

    # Check for iptables or nftables
    if command -v iptables >/dev/null 2>&1; then
        iptables -C INPUT -s "$ip" -j DROP >/dev/null 2>&1 || iptables -I INPUT -s "$ip" -m comment --comment "THUNDER_BLOCK" -j DROP
        iptables -C OUTPUT -d "$ip" -j DROP >/dev/null 2>&1 || iptables -I OUTPUT -d "$ip" -m comment --comment "THUNDER_BLOCK" -j DROP
        log_msg "ALERT" "QUARANTINED IP: $ip via iptables | Reason: $reason"
    elif command -v ufw >/dev/null 2>&1; then
        ufw deny from "$ip" >/dev/null 2>&1
        log_msg "ALERT" "QUARANTINED IP: $ip via UFW | Reason: $reason"
    else
        log_msg "WARN" "No iptables/ufw detected (May require root / proot on Termux). Block logged for: $ip"
    fi
}

unblock_ip() {
    local ip="$1"
    if [ -z "$ip" ]; then return; fi
    if command -v iptables >/dev/null 2>&1; then
        iptables -D INPUT -s "$ip" -j DROP >/dev/null 2>&1
        iptables -D OUTPUT -d "$ip" -j DROP >/dev/null 2>&1
        log_msg "OK" "Unblocked IP: $ip"
    fi
}

list_blocked() {
    echo -e "\n\e[31m=== THUNDER ACTIVE FIREWALL BLOCKS (Linux/Termux) ===\e[0m"
    if command -v iptables >/dev/null 2>&1; then
        iptables -L -n -v | grep "THUNDER_BLOCK" || echo "No active THUNDER iptables rules found."
    else
        echo "iptables not available. Check defender_events.log for quarantined IPs."
    fi
}

flush_all() {
    if command -v iptables >/dev/null 2>&1; then
        iptables -D INPUT -m comment --comment "THUNDER_BLOCK" -j DROP 2>/dev/null
        iptables -D OUTPUT -m comment --comment "THUNDER_BLOCK" -j DROP 2>/dev/null
        log_msg "OK" "Flushed THUNDER firewall rules."
    fi
}

case "$ACTION" in
    block)   block_ip "$TARGET_IP" "$REASON" ;;
    unblock) unblock_ip "$TARGET_IP" ;;
    list)    list_blocked ;;
    flush)   flush_all ;;
    status)  list_blocked ;;
    *)       list_blocked ;;
esac
