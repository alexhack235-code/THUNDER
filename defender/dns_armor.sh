#!/usr/bin/env bash
# ==============================================================================
# THUNDER - DNS Armor & Encrypted Resolver Shield (Linux & Termux)
# Built by: NEXO-TECH
# ==============================================================================

PROVIDER="${1:-status}"
LOG_DIR="$(dirname "$0")/../logs"
LOG_PATH="$LOG_DIR/defender_events.log"

mkdir -p "$LOG_DIR"

log_msg() {
    local level="$1"
    local msg="$2"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] [$level] [DNS-ARMOR] $msg" >> "$LOG_PATH"

    case "$level" in
        ALERT) echo -e "\e[31m[$timestamp] [$level] [DNS-ARMOR] $msg\e[0m" ;;
        WARN)  echo -e "\e[33m[$timestamp] [$level] [DNS-ARMOR] $msg\e[0m" ;;
        INFO)  echo -e "\e[36m[$timestamp] [$level] [DNS-ARMOR] $msg\e[0m" ;;
        OK)    echo -e "\e[32m[$timestamp] [$level] [DNS-ARMOR] $msg\e[0m" ;;
    esac
}

set_dns() {
    local p1="$1"
    local p2="$2"
    local name="$3"

    log_msg "INFO" "Applying $name DNS ($p1, $p2)..."
    if [ -w "/etc/resolv.conf" ]; then
        echo "nameserver $p1" > /etc/resolv.conf
        echo "nameserver $p2" >> /etc/resolv.conf
        log_msg "OK" "Updated /etc/resolv.conf with $name."
    else
        log_msg "WARN" "/etc/resolv.conf is read-only (Requires root on Linux)."
    fi
}

show_status() {
    echo -e "\n\e[36m=======================================================\e[0m"
    echo -e "\e[33m         THUNDER DNS ARMOR & ENCRYPTED RESOLVER        \e[0m"
    echo -e "\e[32m         Built by NEXO-TECH (Linux & Termux)           \e[0m"
    echo -e "\e[36m=======================================================\e[0m"
    if [ -f "/etc/resolv.conf" ]; then
        echo -e "[+] Current Nameservers:\n$(grep '^nameserver' /etc/resolv.conf)"
    else
        echo -e "[+] Android / Termux DNS Active."
    fi
}

case "$PROVIDER" in
    quad9)      set_dns "9.9.9.9" "149.112.112.112" "Quad9 Threat-Blocking" ;;
    cloudflare) set_dns "1.1.1.1" "1.0.0.1" "Cloudflare Privacy" ;;
    adguard)    set_dns "94.140.14.14" "94.140.15.15" "AdGuard Ad-Shield" ;;
    status)     show_status ;;
    *)          show_status ;;
esac
