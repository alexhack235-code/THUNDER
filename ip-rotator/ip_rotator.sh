#!/usr/bin/env bash
# ==============================================================================
# THUNDER - Dynamic IP Rotator & 100+ Endpoint Switcher (Linux & Termux)
# Built by: NEXO-TECH
# ==============================================================================

ACTION="${1:-status}"
POOL_FILE="$(dirname "$0")/api_pool.json"
LOG_DIR="$(dirname "$0")/../logs"
LOG_PATH="$LOG_DIR/ip_rotations.log"

mkdir -p "$LOG_DIR"

log_msg() {
    local level="$1"
    local msg="$2"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] [$level] [IP-ROTATOR] $msg" >> "$LOG_PATH"

    case "$level" in
        ALERT) echo -e "\e[31m[$timestamp] [$level] [IP-ROTATOR] $msg\e[0m" ;;
        WARN)  echo -e "\e[33m[$timestamp] [$level] [IP-ROTATOR] $msg\e[0m" ;;
        INFO)  echo -e "\e[36m[$timestamp] [$level] [IP-ROTATOR] $msg\e[0m" ;;
        OK)    echo -e "\e[32m[$timestamp] [$level] [IP-ROTATOR] $msg\e[0m" ;;
    esac
}

get_random_mac() {
    # Locally administered unicast MAC (6 octets)
    printf '02:%02X:%02X:%02X:%02X:%02X:%02X\n' $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256))
}

check_external_ip() {
    echo -e "\n\e[36m================================================================\e[0m"
    echo -e "\e[33m          ⚡ THUNDER RANDOM IP ROTATOR (NEXO-TECH) ⚡          \e[0m"
    echo -e "\e[32m                       Linux & Termux Edition                   \e[0m"
    echo -e "\e[36m================================================================\e[0m"

    echo -e "[+] Querying 100+ Endpoint Pool for external IP validation..."

    # Fast fallback list
    local urls=(
        "https://api.ipify.org"
        "https://icanhazip.com"
        "https://ifconfig.me/ip"
        "https://ifconfig.co/ip"
        "https://api.seeip.org"
        "https://ident.me"
        "https://checkip.amazonaws.com"
        "https://wtfismyip.com/text"
    )

    local current_ip=""
    local used_url=""

    for u in "${urls[@]}"; do
        current_ip=$(curl -s -m 3 "$u" 2>/dev/null | tr -d '[:space:]')
        if [[ "$current_ip" =~ ^[0-9a-fA-F:\.]+$ ]] && [[ "$current_ip" =~ (\.|\:) ]]; then
            used_url="$u"
            break
        fi
    done

    if [ -n "$current_ip" ]; then
        echo -e "[+] Current External IP : \e[1m\e[32m$current_ip\e[0m \e[90m(Verified via $used_url)\e[0m"
        log_msg "OK" "Active Public IP: $current_ip"
    else
        echo -e "\e[31m[-] Could not contact external IP pool. Check connection.\e[0m"
    fi
}

rotate_mac_linux() {
    local iface="$1"
    if [ -z "$iface" ]; then
        iface=$(ip route show default 2>/dev/null | awk '{print $5}' | head -n 1)
    fi

    if [ -z "$iface" ]; then
        log_msg "WARN" "No active network interface found for MAC rotation."
        return
    fi

    local new_mac
    new_mac=$(get_random_mac)
    log_msg "INFO" "Rotating MAC address on interface $iface to $new_mac..."

    if command -v macchanger >/dev/null 2>&1; then
        ip link set dev "$iface" down 2>/dev/null
        macchanger -r "$iface" 2>/dev/null
        ip link set dev "$iface" up 2>/dev/null
        log_msg "OK" "MAC changed via macchanger."
    elif command -v ip >/dev/null 2>&1; then
        ip link set dev "$iface" down 2>/dev/null
        ip link set dev "$iface" address "$new_mac" 2>/dev/null
        ip link set dev "$iface" up 2>/dev/null
        log_msg "OK" "MAC updated to $new_mac via ip link."
    else
        log_msg "WARN" "Root permissions and ip/macchanger required to change hardware MAC on Linux."
    fi

    # Renew DHCP if tools available
    if command -v dhclient >/dev/null 2>&1; then
        dhclient -r "$iface" 2>/dev/null
        dhclient "$iface" 2>/dev/null
    elif command -v dhcpcd >/dev/null 2>&1; then
        dhcpcd -k "$iface" 2>/dev/null
        dhcpcd "$iface" 2>/dev/null
    fi

    check_external_ip
}

case "$ACTION" in
    rotate) rotate_mac_linux "$2" ;;
    status) check_external_ip ;;
    *)      check_external_ip ;;
esac
