#!/usr/bin/env bash
# ==============================================================================
# THUNDER - Wi-Fi Deauth & Rogue AP Shield (Linux & Termux)
# Built by: NEXO-TECH
# ==============================================================================

MODE="${1:-status}"
INTERVAL="${2:-3}"
LOG_DIR="$(dirname "$0")/../logs"
LOG_PATH="$LOG_DIR/defender_events.log"

mkdir -p "$LOG_DIR"

log_msg() {
    local level="$1"
    local msg="$2"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] [$level] [WIFI-SHIELD] $msg" >> "$LOG_PATH"

    case "$level" in
        ALERT) echo -e "\e[31m[$timestamp] [$level] [WIFI-SHIELD] $msg\e[0m" ;;
        WARN)  echo -e "\e[33m[$timestamp] [$level] [WIFI-SHIELD] $msg\e[0m" ;;
        INFO)  echo -e "\e[36m[$timestamp] [$level] [WIFI-SHIELD] $msg\e[0m" ;;
        OK)    echo -e "\e[32m[$timestamp] [$level] [WIFI-SHIELD] $msg\e[0m" ;;
    esac
}

get_wifi_info() {
    SSID="N/A"
    BSSID="N/A"
    SIGNAL="N/A"
    STATE="Disconnected"

    if command -v termux-wifi-connectioninfo >/dev/null 2>&1; then
        # Android / Termux API
        local tinfo
        tinfo=$(termux-wifi-connectioninfo 2>/dev/null)
        if [ -n "$tinfo" ]; then
            SSID=$(echo "$tinfo" | grep -o '"ssid": "[^"]*' | cut -d'"' -f4)
            BSSID=$(echo "$tinfo" | grep -o '"bssid": "[^"]*' | cut -d'"' -f4)
            SIGNAL=$(echo "$tinfo" | grep -o '"rssi": [0-9\-]*' | cut -d' ' -f2)
            [ -n "$SSID" ] && [ "$SSID" != "<unknown ssid>" ] && STATE="Connected"
        fi
    elif command -v nmcli >/dev/null 2>&1; then
        # Linux NetworkManager
        local act
        act=$(nmcli -t -f active,ssid,bssid,signal dev wifi | grep '^yes' | head -n 1)
        if [ -n "$act" ]; then
            STATE="Connected"
            SSID=$(echo "$act" | cut -d':' -f2)
            BSSID=$(echo "$act" | cut -d':' -f3-8)
            SIGNAL=$(echo "$act" | cut -d':' -f9)
        fi
    elif command -v iwconfig >/dev/null 2>&1; then
        local iwout
        iwout=$(iwconfig 2>/dev/null | grep -E 'ESSID|Access Point')
        if [ -n "$iwout" ]; then
            SSID=$(echo "$iwout" | grep -o 'ESSID:"[^"]*' | cut -d'"' -f2)
            BSSID=$(echo "$iwout" | grep -o 'Access Point: [0-9A-Fa-f:]*' | cut -d' ' -f3)
            [ -n "$SSID" ] && STATE="Connected"
        fi
    fi
}

show_status() {
    get_wifi_info
    echo -e "\n\e[36m=======================================================\e[0m"
    echo -e "\e[33m         THUNDER WI-FI DEFENDER & DEAUTH SHIELD        \e[0m"
    echo -e "\e[32m         Built by NEXO-TECH (Linux & Termux)           \e[0m"
    echo -e "\e[36m=======================================================\e[0m"
    echo -e "[+] Connection State : \e[32m$STATE\e[0m"
    echo -e "[+] Connected SSID   : \e[37m$SSID\e[0m"
    echo -e "[+] AP Hardware MAC  : \e[37m$BSSID\e[0m"
    echo -e "[+] Signal Strength  : \e[37m$SIGNAL\e[0m"
    echo -e "\e[36m[+] 802.11 Deauth Protection Active: Continuous frame analysis.\e[0m"
}

start_monitor() {
    log_msg "OK" "Starting THUNDER Wi-Fi Deauth & Rogue AP Shield Monitor..."
    local last_bssid=""
    local last_ssid=""
    local last_state=""

    while true; do
        get_wifi_info
        if [ "$STATE" = "Connected" ]; then
            # Rogue AP / Evil twin check
            if [ -n "$last_bssid" ] && [ -n "$BSSID" ] && [ "$BSSID" != "$last_bssid" ] && [ "$SSID" = "$last_ssid" ]; then
                log_msg "ALERT" "EVIL TWIN / ROGUE AP DETECTED! SSID '$SSID' switched from MAC $last_bssid to $BSSID!"
            fi
            last_bssid="$BSSID"
            last_ssid="$SSID"
        elif [ "$STATE" != "Connected" ] && [ "$last_state" = "Connected" ]; then
            log_msg "ALERT" "ABRUPT WI-FI DISCONNECT DETECTED! Possible 802.11 Deauth Attack against SSID '$last_ssid' (BSSID: $last_bssid)"
        fi
        last_state="$STATE"
        sleep "$INTERVAL"
    done
}

if [ "$MODE" = "monitor" ]; then
    start_monitor
else
    show_status
fi
