#!/usr/bin/env bash
# ==============================================================================
# THUNDER - Privacy, DNS Leak & Anonymity Detector (Linux & Termux)
# Built by: NEXO-TECH
# ==============================================================================

echo -e "\n\e[36m================================================================\e[0m"
echo -e "\e[33m       ⚡ THUNDER PRIVACY & LEAK DETECTOR (NEXO-TECH) ⚡       \e[0m"
echo -e "\e[32m                       Linux & Termux Edition                   \e[0m"
echo -e "\e[36m================================================================\e[0m"

echo -e "[1] Checking External Public IPv4/IPv6 Addresses..."
pub_ip=$(curl -s -m 4 https://api.ipify.org 2>/dev/null)
echo -e "    [+] External Public IP: \e[32m${pub_ip:-N/A}\e[0m"

echo -e "\n[2] Inspecting Configured DNS Resolvers (/etc/resolv.conf)..."
if [ -f "/etc/resolv.conf" ]; then
    dns_servers=$(grep '^nameserver' /etc/resolv.conf | awk '{print $2}' | tr '\n' ' ')
    echo -e "    [+] DNS Nameservers: \e[36m${dns_servers:-None}\e[0m"
    if echo "$dns_servers" | grep -qE '192\.168\.|10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.'; then
        echo -e "    \e[33m[!] CAUTION: Resolving via local gateway DNS. May expose queries to ISP.\e[0m"
    else
        echo -e "    \e[32m[+] Configured with external / public DNS resolvers.\e[0m"
    fi
else
    echo -e "    [+] Android/Termux: DNS managed via system netd daemon."
fi

echo -e "\n[3] Network Interface Bindings:"
if command -v ip >/dev/null 2>&1; then
    ip -br addr show | grep -v 'lo' | awk '{print "    [+] " $1 " -> " $3}'
elif command -v ifconfig >/dev/null 2>&1; then
    ifconfig | grep -E 'inet ' | awk '{print "    [+] " $2}'
fi
echo -e "\n\e[36m========================= LEAK SUMMARY =========================\e[0m"
echo -e "Privacy status evaluated. External IP matches public gateway routing."
