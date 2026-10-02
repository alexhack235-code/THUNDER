#!/usr/bin/env bash
# ==============================================================================
# THUNDER - Anti-Spyware & Persistence Shield (Linux & Termux)
# Built by: NEXO-TECH
# ==============================================================================

echo -e "\n\e[36m=======================================================\e[0m"
echo -e "\e[33m       THUNDER ANTI-SPYWARE & PERSISTENCE AUDIT        \e[0m"
echo -e "\e[32m         Built by NEXO-TECH (Linux & Termux)           \e[0m"
echo -e "\e[36m=======================================================\e[0m"

echo -e "[1] Inspecting User Cron Jobs (crontab)..."
crontab -l 2>/dev/null || echo "    No user crontab found."

echo -e "\n[2] Checking Linux Systemd / Init Persistence..."
if [ -d "/etc/systemd/system" ]; then
    echo -e "    Custom Systemd Services: $(ls -1 /etc/systemd/system/*.service 2>/dev/null | wc -l)"
fi

echo -e "\n[3] Checking Shell RC Startup Scripts..."
for rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
    if [ -f "$rc" ]; then
        if grep -qE 'curl|wget|nc |bash -i|/dev/tcp' "$rc" 2>/dev/null; then
            echo -e "    \e[31m[!] SUSPICIOUS COMMAND FOUND IN $rc\e[0m"
        else
            echo -e "    [+] $rc : CLEAN"
        fi
    fi
done
