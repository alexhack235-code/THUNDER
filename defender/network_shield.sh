#!/usr/bin/env bash
# ==============================================================================
# THUNDER - Network Attack Defender (Linux & Termux)
# Built by: NEXO-TECH
# ==============================================================================

MODE="${1:-audit}"
INTERVAL=3
LOG_DIR="$(dirname "$0")/../logs"
LOG_PATH="$LOG_DIR/defender_events.log"

mkdir -p "$LOG_DIR"

log_msg() {
    local level="$1"
    local msg="$2"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] [$level] [NETWORK-SHIELD] $msg" >> "$LOG_PATH"

    case "$level" in
        ALERT) echo -e "\e[31m[$timestamp] [$level] [NETWORK-SHIELD] $msg\e[0m" ;;
        WARN)  echo -e "\e[33m[$timestamp] [$level] [NETWORK-SHIELD] $msg\e[0m" ;;
        INFO)  echo -e "\e[36m[$timestamp] [$level] [NETWORK-SHIELD] $msg\e[0m" ;;
        OK)    echo -e "\e[32m[$timestamp] [$level] [NETWORK-SHIELD] $msg\e[0m" ;;
    esac
}

get_gateway_ip() {
    if command -v ip >/dev/null 2>&1; then
        ip route show default 2>/dev/null | awk '{print $3}' | head -n 1
    elif command -v route >/dev/null 2>&1; then
        route -n | grep 'UG' | awk '{print $2}' | head -n 1
    fi
}

audit_network() {
    echo -e "\n\e[36m=======================================================\e[0m"
    echo -e "\e[33m         THUNDER NETWORK ATTACK DEFENDER AUDIT         \e[0m"
    echo -e "\e[32m         Built by NEXO-TECH (Linux & Termux)           \e[0m"
    echo -e "\e[36m=======================================================\e[0m"

    local gw
    gw=$(get_gateway_ip)
    echo -e "[+] Default Gateway IP : \e[37m${gw:-N/A}\e[0m"

    # Check ARP entries for duplicates
    local arp_file="/proc/net/arp"
    if [ -f "$arp_file" ]; then
        local dup_macs
        dup_macs=$(awk 'NR>1 && $4 != "00:00:00:00:00:00" {print $4}' "$arp_file" | sort | uniq -d)
        if [ -n "$dup_macs" ]; then
            echo -e "\e[31m[!] POTENTIAL ARP SPOOFING / POISONING DETECTED!\e[0m"
            echo -e "    Duplicate Hardware MAC(s) detected: $dup_macs"
            log_msg "ALERT" "Duplicate MAC in ARP table: $dup_macs"
        else
            echo -e "[+] ARP Table Status   : \e[32mCLEAN (No duplicate hardware MACs)\e[0m"
        fi
    elif command -v ip >/dev/null 2>&1; then
        local neigh_dup
        neigh_dup=$(ip neigh show | awk '{print $5}' | sort | uniq -d | grep -v 'FAILED\|INCOMPLETE')
        if [ -n "$neigh_dup" ]; then
            echo -e "\e[31m[!] POTENTIAL ARP SPOOFING DETECTED: $neigh_dup\e[0m"
        else
            echo -e "[+] ARP Table Status   : \e[32mCLEAN\e[0m"
        fi
    fi
}

start_monitor() {
    log_msg "OK" "Starting THUNDER Network Defender Monitor (Linux & Termux)..."
    local last_gw_mac=""
    local gw
    gw=$(get_gateway_ip)

    while true; do
        if [ -n "$gw" ] && [ -f "/proc/net/arp" ]; then
            local cur_mac
            cur_mac=$(grep -w "$gw" /proc/net/arp | awk '{print $4}')
            if [ -n "$last_gw_mac" ] && [ -n "$cur_mac" ] && [ "$cur_mac" != "$last_gw_mac" ]; then
                log_msg "ALERT" "GATEWAY ARP POISONING DETECTED! Gateway $gw MAC changed from $last_gw_mac to $cur_mac!"
            fi
            last_gw_mac="$cur_mac"
        fi
        sleep "$INTERVAL"
    done
}

if [ "$MODE" = "monitor" ]; then
    start_monitor
else
    audit_network
fi
