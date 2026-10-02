#!/usr/bin/env bash
# ==============================================================================
# THUNDER - USB & Removable Media Shield (Linux & Termux)
# Built by: NEXO-TECH
# ==============================================================================

echo -e "\n\e[36m=======================================================\e[0m"
echo -e "\e[33m         THUNDER USB & BADUSB DEFENDER AUDIT           \e[0m"
echo -e "\e[32m         Built by NEXO-TECH (Linux & Termux)           \e[0m"
echo -e "\e[36m=======================================================\e[0m"

if command -v lsusb >/dev/null 2>&1; then
    echo -e "[+] Connected USB Devices:\n$(lsusb)"
elif [ -d "/sys/bus/usb/devices" ]; then
    usb_cnt=$(ls -1 /sys/bus/usb/devices 2>/dev/null | wc -l)
    echo -e "[+] USB Ports / Controllers Detected: $usb_cnt"
else
    echo -e "[+] Android / Termux: Direct USB interface restricted (OTG devices monitored by OS)."
fi

echo -e "\n[+] Recommendation: Disable USB debugging (ADB) when not in use."
