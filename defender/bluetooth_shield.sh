#!/usr/bin/env bash
# ==============================================================================
# THUNDER - Bluetooth Intrusion & Stealth Shield (Linux & Termux)
# Built by: NEXO-TECH
# ==============================================================================

MODE="${1:-status}"
LOG_DIR="$(dirname "$0")/../logs"
LOG_PATH="$LOG_DIR/defender_events.log"

mkdir -p "$LOG_DIR"

log_msg() {
    local level="$1"
    local msg="$2"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] [$level] [BLUETOOTH-SHIELD] $msg" >> "$LOG_PATH"

    case "$level" in
        ALERT) echo -e "\e[31m[$timestamp] [$level] [BLUETOOTH-SHIELD] $msg\e[0m" ;;
        WARN)  echo -e "\e[33m[$timestamp] [$level] [BLUETOOTH-SHIELD] $msg\e[0m" ;;
        INFO)  echo -e "\e[36m[$timestamp] [$level] [BLUETOOTH-SHIELD] $msg\e[0m" ;;
        OK)    echo -e "\e[32m[$timestamp] [$level] [BLUETOOTH-SHIELD] $msg\e[0m" ;;
    esac
}

enable_stealth() {
    log_msg "INFO" "Enforcing Bluetooth Stealth Shield..."
    if command -v bluetoothctl >/dev/null 2>&1; then
        echo -e "discoverable off\npairable off\nexit" | bluetoothctl >/dev/null 2>&1
        log_msg "OK" "Bluetooth Stealth Active: Adapter hidden from BLE discovery scans."
    elif command -v hciconfig >/dev/null 2>&1; then
        hciconfig hci0 noscan >/dev/null 2>&1
        log_msg "OK" "Bluetooth Stealth Active: hci0 scan mode disabled."
    else
        log_msg "WARN" "No standard Bluetooth CLI tools detected. Ensure Bluetooth visibility is disabled in Android settings."
    fi
}

show_status() {
    echo -e "\n\e[36m=======================================================\e[0m"
    echo -e "\e[33m         THUNDER BLUETOOTH INTRUSION SHIELD            \e[0m"
    echo -e "\e[32m         Built by NEXO-TECH (Linux & Termux)           \e[0m"
    echo -e "\e[36m=======================================================\e[0m"

    if command -v bluetoothctl >/dev/null 2>&1; then
        local devices
        devices=$(bluetoothctl devices 2>/dev/null)
        echo -e "[+] Known Paired Devices:\n${devices:-None registered}"
    elif [ -d "/sys/class/bluetooth" ]; then
        local bt_count
        bt_count=$(ls -1 /sys/class/bluetooth 2>/dev/null | wc -l)
        echo -e "[+] Bluetooth Adapters Detected: $bt_count"
    else
        echo -e "[+] Bluetooth Status: Inactive or No Radio Adapter Present."
    fi
    echo -e "\n[+] Security Note: Run with 'stealth' to hide adapter from BLE sniffers."
}

case "$MODE" in
    stealth) enable_stealth ;;
    status)  show_status ;;
    *)       show_status ;;
esac
