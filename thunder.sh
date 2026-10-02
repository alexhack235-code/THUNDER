#!/usr/bin/env bash
# ==============================================================================
# ⚡ THUNDER: Comprehensive Network & Device Defender Suite
# Built by: NEXO-TECH (Linux & Termux Edition)
# ==============================================================================

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEFENDER_DIR="$ROOT_DIR/defender"
SCANNER_DIR="$ROOT_DIR/thunder-scanner"
ROTATOR_DIR="$ROOT_DIR/ip-rotator"
LOG_PATH="$ROOT_DIR/logs/defender_events.log"

print_banner() {
    clear
    echo -e "\e[33m"
    echo " ████████╗██╗  ██╗██╗   ██╗███╗   ██╗██████╗ ███████╗██████╗ "
    echo " ╚══██╔══╝██║  ██║██║   ██║████╗  ██║██╔══██╗██╔════╝██╔══██╗"
    echo "    ██║   ███████║██║   ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝"
    echo "    ██║   ██╔══██║██║   ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗"
    echo "    ██║   ██║  ██║╚██████╔╝██║ ╚████║██████╔╝███████╗██║  ██║"
    echo "    ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝"
    echo -e "\e[0m"
    echo -e "\e[36m ======================================================================\e[0m"
    echo -e "\e[1m\e[37m        ⚡ THUNDER COMPREHENSIVE NETWORK & DEVICE DEFENDER ⚡        \e[0m"
    echo -e "\e[32m                  Built by NEXO-TECH (Linux & Termux)                   \e[0m"
    echo -e "\e[36m ======================================================================\e[0m"
}

run_shield_all() {
    print_banner
    echo -e "\n\e[33m[*] ENGAGING ALL THUNDER DEFENSIVE SHIELDS...\e[0m"
    
    echo -e "\e[36m[1/6] Activating Bluetooth Stealth Shield...\e[0m"
    bash "$DEFENDER_DIR/bluetooth_shield.sh" stealth

    echo -e "\e[36m[2/6] Deploying Anti-Ransomware Canary Traps...\e[0m"
    bash "$DEFENDER_DIR/anti_ransomware_shield.sh" deploy

    echo -e "\e[36m[3/6] Auditing USB Devices & Removable Media...\e[0m"
    bash "$DEFENDER_DIR/usb_shield.sh"

    echo -e "\e[36m[4/6] Initializing Wi-Fi Deauth Defense & Telemetry...\e[0m"
    bash "$DEFENDER_DIR/wifi_shield.sh" status

    echo -e "\e[36m[5/6] Inspecting Network ARP Integrity & Gateways...\e[0m"
    bash "$DEFENDER_DIR/network_shield.sh" audit

    echo -e "\e[36m[6/6] Auditing Process Sockets & Anti-Reverse Shell Monitor...\e[0m"
    bash "$DEFENDER_DIR/reverse_shell_shield.sh" audit

    echo -e "\n\e[32m[+] ALL SHIELDS ARE ARMED AND OPERATIONAL.\e[0m"
    echo -e "\e[90m[!] Event logs written to: $LOG_PATH\e[0m"
}

show_system_status() {
    print_banner
    echo -e "\n\e[33m[*] AUDITING THUNDER SYSTEM & DEFENSE TELEMETRY...\e[0m\n"
    bash "$DEFENDER_DIR/wifi_shield.sh" status
    echo ""
    bash "$DEFENDER_DIR/network_shield.sh" audit
    echo ""
    bash "$DEFENDER_DIR/reverse_shell_shield.sh" audit
    echo ""
    bash "$DEFENDER_DIR/bluetooth_shield.sh" status
}

interactive_menu() {
    while true; do
        print_banner
        echo -e " \e[33m[1]\e[0m  Arm All Defensive Shields (Wi-Fi, RevShell, Network, BT, Ransomware, USB)"
        echo -e " \e[33m[2]\e[0m  Wi-Fi Deauth & Rogue AP Defender"
        echo -e " \e[33m[3]\e[0m  Anti-Reverse Shell & Process Defense"
        echo -e " \e[33m[4]\e[0m  Network Defender (ARP Spoofing & Port Scans)"
        echo -e " \e[33m[5]\e[0m  Bluetooth Intrusion & Stealth Shield"
        echo -e " \e[33m[6]\e[0m  Anti-Ransomware Canary Traps & Integrity Check"
        echo -e " \e[33m[7]\e[0m  USB & Removable Media Shield"
        echo -e " \e[33m[8]\e[0m  Anti-Spyware & Persistence Audit (Cron, Startup, RC)"
        echo -e " \e[33m[9]\e[0m  DNS Armor & Encrypted Resolver (Quad9 / Cloudflare / AdGuard)"
        echo -e " \e[33m[10]\e[0m System Hardening & Kernel Security Audit"
        echo -e " \e[33m[11]\e[0m THUNDER Malware & Virus Scanner (Scan / Quarantine / Shred)"
        echo -e " \e[33m[12]\e[0m Random IP Changer & 100+ Endpoint Pool"
        echo -e " \e[33m[13]\e[0m Benchmark 100+ Public IP Endpoints"
        echo -e " \e[33m[14]\e[0m Privacy & DNS Leak Detector"
        echo -e " \e[33m[15]\e[0m View Dynamic Firewall Quarantined IPs"
        echo -e " \e[33m[16]\e[0m View Live Defender Event Logs"
        echo -e " \e[33m[17]\e[0m Comprehensive Defense Status Audit"
        echo -e " \e[31m[0]\e[0m  Exit THUNDER"
        echo -e "\e[36m ======================================================================\e[0m"
        
        read -r -p " Enter choice [0-17]: " choice

        case "$choice" in
            1)
                run_shield_all
                read -r -p "Press Enter to continue..."
                ;;
            2)
                print_banner
                bash "$DEFENDER_DIR/wifi_shield.sh" status
                read -r -p "Press Enter to continue..."
                ;;
            3)
                print_banner
                bash "$DEFENDER_DIR/reverse_shell_shield.sh" audit
                read -r -p "Press Enter to continue..."
                ;;
            4)
                print_banner
                bash "$DEFENDER_DIR/network_shield.sh" audit
                read -r -p "Press Enter to continue..."
                ;;
            5)
                print_banner
                echo "1. Show Bluetooth Status"
                echo "2. Enable Stealth Mode"
                read -r -p "Option: " bto
                if [ "$bto" = "2" ]; then
                    bash "$DEFENDER_DIR/bluetooth_shield.sh" stealth
                else
                    bash "$DEFENDER_DIR/bluetooth_shield.sh" status
                fi
                read -r -p "Press Enter to continue..."
                ;;
            6)
                print_banner
                echo "1. Audit Canary Honeypots"
                echo "2. Deploy Canary Honeypots"
                read -r -p "Option: " rso
                if [ "$rso" = "2" ]; then
                    bash "$DEFENDER_DIR/anti_ransomware_shield.sh" deploy
                else
                    bash "$DEFENDER_DIR/anti_ransomware_shield.sh" audit
                fi
                read -r -p "Press Enter to continue..."
                ;;
            7)
                print_banner
                bash "$DEFENDER_DIR/usb_shield.sh"
                read -r -p "Press Enter to continue..."
                ;;
            8)
                print_banner
                bash "$DEFENDER_DIR/anti_spyware_shield.sh"
                read -r -p "Press Enter to continue..."
                ;;
            9)
                print_banner
                echo "1. Status"
                echo "2. Quad9 Threat-Blocking DNS"
                echo "3. Cloudflare Privacy DNS"
                echo "4. AdGuard Ad-Shield DNS"
                read -r -p "Option: " dnso
                case "$dnso" in
                    2) bash "$DEFENDER_DIR/dns_armor.sh" quad9 ;;
                    3) bash "$DEFENDER_DIR/dns_armor.sh" cloudflare ;;
                    4) bash "$DEFENDER_DIR/dns_armor.sh" adguard ;;
                    *) bash "$DEFENDER_DIR/dns_armor.sh" status ;;
                esac
                read -r -p "Press Enter to continue..."
                ;;
            10)
                print_banner
                echo "1. Audit Kernel & System Hardening"
                echo "2. Apply Hardening Parameters"
                read -r -p "Option: " hardo
                if [ "$hardo" = "2" ]; then
                    bash "$DEFENDER_DIR/system_hardening.sh" apply
                else
                    bash "$DEFENDER_DIR/system_hardening.sh" audit
                fi
                read -r -p "Press Enter to continue..."
                ;;
            11)
                print_banner
                read -r -p "Enter path to scan (Default: current directory): " scan_target
                scan_target="${scan_target:-.}"
                echo "1. Audit Only"
                echo "2. Encrypted Quarantine"
                echo "3. Secure Shred & Eradicate"
                read -r -p "Remediation Mode [1-3]: " rmode
                case "$rmode" in
                    2) bash "$SCANNER_DIR/run_scanner.sh" "$scan_target" quarantine ;;
                    3) bash "$SCANNER_DIR/run_scanner.sh" "$scan_target" shred ;;
                    *) bash "$SCANNER_DIR/run_scanner.sh" "$scan_target" audit ;;
                esac
                read -r -p "Press Enter to continue..."
                ;;
            12)
                print_banner
                echo "1. Check Current External IP (via 100+ Endpoint Pool)"
                echo "2. Randomize Hardware MAC Address & Renew DHCP"
                read -r -p "Option [1-2]: " ipo
                if [ "$ipo" = "2" ]; then
                    bash "$ROTATOR_DIR/ip_rotator.sh" rotate
                else
                    bash "$ROTATOR_DIR/ip_rotator.sh" status
                fi
                read -r -p "Press Enter to continue..."
                ;;
            13)
                print_banner
                if command -v node >/dev/null 2>&1; then
                    node "$ROTATOR_DIR/proxy_rotator.js" 20
                else
                    bash "$ROTATOR_DIR/ip_rotator.sh" status
                fi
                read -r -p "Press Enter to continue..."
                ;;
            14)
                print_banner
                bash "$ROTATOR_DIR/leak_detector.sh"
                read -r -p "Press Enter to continue..."
                ;;
            15)
                print_banner
                bash "$DEFENDER_DIR/firewall_manager.sh" status
                read -r -p "Press Enter to continue..."
                ;;
            16)
                print_banner
                if [ -f "$LOG_PATH" ]; then
                    tail -n 25 "$LOG_PATH"
                else
                    echo "No events logged yet."
                fi
                read -r -p "Press Enter to continue..."
                ;;
            17)
                show_system_status
                read -r -p "Press Enter to continue..."
                ;;
            0)
                echo -e "\n\e[32m[+] Exiting THUNDER. Stay safe!\e[0m"
                exit 0
                ;;
            *)
                echo "Invalid choice."
                sleep 1
                ;;
        esac
    done
}

case "$1" in
    --shield-all) run_shield_all ;;
    --scan)       bash "$SCANNER_DIR/run_scanner.sh" "$2" "$3" ;;
    --rotate-ip)  bash "$ROTATOR_DIR/ip_rotator.sh" rotate ;;
    --status)     show_system_status ;;
    *)            interactive_menu ;;
esac
