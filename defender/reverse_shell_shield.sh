#!/usr/bin/env bash
# ==============================================================================
# THUNDER - Anti-Reverse Shell & Process Defense Shield (Linux & Termux)
# Built by: NEXO-TECH
# ==============================================================================

MODE="${1:-audit}"
AUTO_KILL="${2:-false}"
AUTO_BLOCK="${3:-false}"
INTERVAL=2
LOG_DIR="$(dirname "$0")/../logs"
LOG_PATH="$LOG_DIR/defender_events.log"
FW_SCRIPT="$(dirname "$0")/firewall_manager.sh"

mkdir -p "$LOG_DIR"

SUSPICIOUS_PROCS="sh|bash|zsh|dash|ash|nc|ncat|netcat|socat|python|python3|perl|ruby|php"

log_msg() {
    local level="$1"
    local msg="$2"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] [$level] [REVERSE-SHELL] $msg" >> "$LOG_PATH"

    case "$level" in
        ALERT) echo -e "\e[31m[$timestamp] [$level] [REVERSE-SHELL] $msg\e[0m" ;;
        WARN)  echo -e "\e[33m[$timestamp] [$level] [REVERSE-SHELL] $msg\e[0m" ;;
        INFO)  echo -e "\e[36m[$timestamp] [$level] [REVERSE-SHELL] $msg\e[0m" ;;
        OK)    echo -e "\e[32m[$timestamp] [$level] [REVERSE-SHELL] $msg\e[0m" ;;
    esac
}

audit_sockets() {
    echo -e "\n\e[36m=======================================================\e[0m"
    echo -e "\e[33m    THUNDER REVERSE SHELL & PROCESS DEFENDER AUDIT     \e[0m"
    echo -e "\e[32m         Built by NEXO-TECH (Linux & Termux)           \e[0m"
    echo -e "\e[36m=======================================================\e[0m"

    local found_threats=0

    # Inspect sockets using ss or netstat
    if command -v ss >/dev/null 2>&1; then
        while read -r line; do
            local remote_ip
            local pid
            local pname
            remote_ip=$(echo "$line" | awk '{print $5}' | cut -d':' -f1)
            pid=$(echo "$line" | grep -o 'pid=[0-9]*' | cut -d'=' -f2)
            pname=$(echo "$line" | grep -o 'users:(("[^"]*' | cut -d'"' -f2)

            if [ -n "$pname" ] && [[ "$pname" =~ ^($SUSPICIOUS_PROCS)$ ]]; then
                # Exclude loopback
                if [[ ! "$remote_ip" =~ ^(127\.0\.0\.1|::1|0\.0\.0\.0)$ ]]; then
                    found_threats=$((found_threats+1))
                    echo -e "\e[31m[!] ACTIVE REVERSE SHELL THREAT DETECTED:\e[0m"
                    echo -e "    Process : \e[1m$pname\e[0m (PID: $pid)"
                    echo -e "    Target  : \e[33m$remote_ip\e[0m"

                    if [ "$AUTO_KILL" = "true" ] && [ -n "$pid" ]; then
                        kill -9 "$pid" 2>/dev/null
                        log_msg "ALERT" "AUTO-KILL: Terminated reverse shell process $pname (PID: $pid)"
                    fi

                    if [ "$AUTO_BLOCK" = "true" ] && [ -n "$remote_ip" ]; then
                        bash "$FW_SCRIPT" block "$remote_ip" "Reverse Shell C2"
                    fi
                fi
            fi
        done < <(ss -tupn 2>/dev/null | grep -E 'ESTAB|SYN-SENT')
    elif command -v netstat >/dev/null 2>&1; then
        while read -r line; do
            local remote_ip
            local pid_prog
            remote_ip=$(echo "$line" | awk '{print $5}' | cut -d':' -f1)
            pid_prog=$(echo "$line" | awk '{print $7}')
            local pid
            local pname
            pid=$(echo "$pid_prog" | cut -d'/' -f1)
            pname=$(echo "$pid_prog" | cut -d'/' -f2)

            if [ -n "$pname" ] && [[ "$pname" =~ ^($SUSPICIOUS_PROCS)$ ]]; then
                if [[ ! "$remote_ip" =~ ^(127\.0\.0\.1|::1|0\.0\.0\.0)$ ]]; then
                    found_threats=$((found_threats+1))
                    echo -e "\e[31m[!] ACTIVE REVERSE SHELL THREAT DETECTED: $pname (PID: $pid) -> $remote_ip\e[0m"
                fi
            fi
        done < <(netstat -tupn 2>/dev/null | grep ESTABLISHED)
    fi

    if [ "$found_threats" -eq 0 ]; then
        echo -e "\e[32m[+] No active reverse shell sockets detected on this device.\e[0m"
    fi
}

start_monitor() {
    log_msg "OK" "Starting THUNDER Anti-Reverse Shell Monitor (AutoKill: $AUTO_KILL, AutoBlock: $AUTO_BLOCK)..."
    while true; do
        audit_sockets >/dev/null 2>&1
        sleep "$INTERVAL"
    done
}

if [ "$MODE" = "monitor" ]; then
    start_monitor
else
    audit_sockets
fi
