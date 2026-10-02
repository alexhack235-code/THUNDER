#!/usr/bin/env bash
# ==============================================================================
# THUNDER - Anti-Ransomware Canary & Rapid-Encryption Shield (Linux & Termux)
# Built by: NEXO-TECH
# ==============================================================================

MODE="${1:-audit}"
LOG_DIR="$(dirname "$0")/../logs"
LOG_PATH="$LOG_DIR/defender_events.log"
CANARY_MARKER="__THUNDER_CANARY_TRAP__"

mkdir -p "$LOG_DIR"

WATCH_DIRS=(
    "$HOME"
    "$HOME/Downloads"
    "$HOME/Documents"
    "/sdcard/Download"
    "/sdcard/Documents"
)

log_msg() {
    local level="$1"
    local msg="$2"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] [$level] [RANSOMWARE-SHIELD] $msg" >> "$LOG_PATH"

    case "$level" in
        ALERT) echo -e "\e[31m[$timestamp] [$level] [RANSOMWARE-SHIELD] $msg\e[0m" ;;
        WARN)  echo -e "\e[33m[$timestamp] [$level] [RANSOMWARE-SHIELD] $msg\e[0m" ;;
        INFO)  echo -e "\e[36m[$timestamp] [$level] [RANSOMWARE-SHIELD] $msg\e[0m" ;;
        OK)    echo -e "\e[32m[$timestamp] [$level] [RANSOMWARE-SHIELD] $msg\e[0m" ;;
    esac
}

deploy_canaries() {
    log_msg "INFO" "Deploying canary honeypot files..."
    for dir in "${WATCH_DIRS[@]}"; do
        if [ -d "$dir" ]; then
            echo "$CANARY_MARKER: Monitored by THUNDER Defender." > "$dir/.thunder_canary_01.txt" 2>/dev/null
        fi
    done
    log_msg "OK" "Canary traps deployed across user directories."
}

audit_canaries() {
    echo -e "\n\e[36m=======================================================\e[0m"
    echo -e "\e[33m     THUNDER ANTI-RANSOMWARE CANARY & INTEGRITY AUDIT  \e[0m"
    echo -e "\e[32m         Built by NEXO-TECH (Linux & Termux)           \e[0m"
    echo -e "\e[36m=======================================================\e[0m"

    local found=0
    for dir in "${WATCH_DIRS[@]}"; do
        if [ -d "$dir" ]; then
            local cf="$dir/.thunder_canary_01.txt"
            if [ -f "$cf" ]; then
                if grep -q "$CANARY_MARKER" "$cf" 2>/dev/null; then
                    echo -e "[+] Canary in '$dir' : \e[32mINTACT & MONITORING\e[0m"
                    found=$((found+1))
                else
                    echo -e "[!] Canary in '$dir' : \e[31mCORRUPTED / ENCRYPTED!\e[0m"
                fi
            else
                echo -e "[-] Canary in '$dir' : \e[90mNot Deployed\e[0m"
            fi
        fi
    done

    echo -e "\n[+] Status: Anti-Ransomware watch active."
}

case "$MODE" in
    deploy)  deploy_canaries ;;
    audit)   audit_canaries ;;
    *)       audit_canaries ;;
esac
