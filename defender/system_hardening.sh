#!/usr/bin/env bash
# ==============================================================================
# THUNDER - System Hardening & Kernel Security (Linux & Termux)
# Built by: NEXO-TECH
# ==============================================================================

ACTION="${1:-audit}"
LOG_DIR="$(dirname "$0")/../logs"
LOG_PATH="$LOG_DIR/defender_events.log"

mkdir -p "$LOG_DIR"

log_msg() {
    local level="$1"
    local msg="$2"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] [$level] [SYSTEM-HARDENING] $msg" >> "$LOG_PATH"

    case "$level" in
        ALERT) echo -e "\e[31m[$timestamp] [$level] [SYSTEM-HARDENING] $msg\e[0m" ;;
        WARN)  echo -e "\e[33m[$timestamp] [$level] [SYSTEM-HARDENING] $msg\e[0m" ;;
        INFO)  echo -e "\e[36m[$timestamp] [$level] [SYSTEM-HARDENING] $msg\e[0m" ;;
        OK)    echo -e "\e[32m[$timestamp] [$level] [SYSTEM-HARDENING] $msg\e[0m" ;;
    esac
}

audit_linux() {
    echo -e "\n\e[36m=======================================================\e[0m"
    echo -e "\e[33m    THUNDER SYSTEM HARDENING & KERNEL SECURITY AUDIT   \e[0m"
    echo -e "\e[32m         Built by NEXO-TECH (Linux & Termux)           \e[0m"
    echo -e "\e[36m=======================================================\e[0m"

    # Check IP Forwarding
    if [ -f "/proc/sys/net/ipv4/ip_forward" ]; then
        local ipf
        ipf=$(cat /proc/sys/net/ipv4/ip_forward)
        if [ "$ipf" = "0" ]; then
            echo -e "[+] IPv4 Forwarding            : \e[32mDISABLED (Safe)\e[0m"
        else
            echo -e "[!] IPv4 Forwarding            : \e[31mENABLED (Device acting as router/MITM node)\e[0m"
        fi
    fi

    # Check SYN Cookies
    if [ -f "/proc/sys/net/ipv4/tcp_syncookies" ]; then
        local syn
        syn=$(cat /proc/sys/net/ipv4/tcp_syncookies)
        if [ "$syn" = "1" ]; then
            echo -e "[+] TCP SYN Cookies            : \e[32mENABLED (Protected against SYN flood DoS)\e[0m"
        else
            echo -e "[!] TCP SYN Cookies            : \e[33mDISABLED\e[0m"
        fi
    fi

    # Check ICMP redirects
    if [ -f "/proc/sys/net/ipv4/conf/all/accept_redirects" ]; then
        local rdr
        rdr=$(cat /proc/sys/net/ipv4/conf/all/accept_redirects)
        if [ "$rdr" = "0" ]; then
            echo -e "[+] ICMP Redirects Acceptance  : \e[32mDISABLED (Protected against route spoofing)\e[0m"
        else
            echo -e "[!] ICMP Redirects Acceptance  : \e[33mENABLED\e[0m"
        fi
    fi
}

apply_hardening() {
    log_msg "INFO" "Applying Linux kernel hardening parameters..."
    if [ -w "/proc/sys/net/ipv4/ip_forward" ]; then
        echo 0 > /proc/sys/net/ipv4/ip_forward 2>/dev/null
        echo 1 > /proc/sys/net/ipv4/tcp_syncookies 2>/dev/null
        echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects 2>/dev/null
        log_msg "OK" "Kernel network parameters hardened."
    else
        log_msg "WARN" "Root access required to adjust /proc/sys values."
    fi
}

case "$ACTION" in
    apply) apply_hardening; audit_linux ;;
    audit) audit_linux ;;
    *)     audit_linux ;;
esac
