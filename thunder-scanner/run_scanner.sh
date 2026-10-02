#!/usr/bin/env bash
# ==============================================================================
# THUNDER - Virus & Malware Scanner & Cleaner (Linux & Termux)
# Built by: NEXO-TECH
# ==============================================================================

SCAN_PATH="${1:-.}"
MODE="${2:-audit}" # audit, quarantine, shred
SCANNER_DIR="$(cd "$(dirname "$0")" && pwd)"
VAULT_DIR="$SCANNER_DIR/../quarantine"
MANIFEST_FILE="$VAULT_DIR/manifest.json"

mkdir -p "$VAULT_DIR"

KNOWN_MD5_HASHES=(
    "44d88612fea8a8f36de82e1278abb02f:EICAR-Standard-AV-Test-File [TEST]"
    "84c82835a5d21bbcf75a61706d8ab549:Ransom:Win32/WannaCry.MD5 [CRITICAL]"
)

KNOWN_SHA256_HASHES=(
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f:EICAR-Standard-AV-Test-File-SHA256 [TEST]"
    "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa:Ransom:Win32/WannaCry.A [CRITICAL]"
)

MALICIOUS_PATTERNS=(
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*:EICAR-Standard-AV-Test-Signature [TEST]"
    "New-Object System.Net.Sockets.TCPClient:Trojan:PowerShell/ReverseShell.TCPClient [CRITICAL]"
    "AmsiUtils.amsiInitFailed:HackTool:PowerShell/AMSI.Bypass.Patch [HIGH]"
    "sekurlsa::logonpasswords:HackTool:Win32/Invoke-Mimikatz [CRITICAL]"
    "IEX(New-Object Net.WebClient).DownloadString:Trojan:Script/DownloadCradle [HIGH]"
    "c99shell:WebShell:PHP/c99.Generic [CRITICAL]"
    "b374k:WebShell:PHP/b374k.Generic [CRITICAL]"
    "eval(base64_decode(:WebShell:PHP/EvalBase64 [HIGH]"
    "stratum+tcp://:CoinMiner:Generic/StratumMining [HIGH]"
    "/bin/sh -i >& /dev/tcp/:Trojan:Linux/ReverseShell.BashTCP [CRITICAL]"
    "bash -i >& /dev/tcp/:Trojan:Linux/ReverseShell.BashTCP [CRITICAL]"
    "nc -e /bin/sh:Trojan:Linux/NetcatReverseShell [CRITICAL]"
    "nc -e /bin/bash:Trojan:Linux/NetcatReverseShell [CRITICAL]"
)

# Check if Rust binary is built
if [ -f "$SCANNER_DIR/target/release/thunder-scanner" ]; then
    echo -e "\e[32m[+] Using compiled high-performance Rust scanner binary...\e[0m"
    if [ "$MODE" = "quarantine" ]; then
        "$SCANNER_DIR/target/release/thunder-scanner" scan --path "$SCAN_PATH" --quarantine
    elif [ "$MODE" = "shred" ]; then
        "$SCANNER_DIR/target/release/thunder-scanner" scan --path "$SCAN_PATH" --shred
    else
        "$SCANNER_DIR/target/release/thunder-scanner" scan --path "$SCAN_PATH"
    fi
    exit 0
fi

# Native POSIX / Termux Scanner Engine
echo -e "\n\e[36m================================================================\e[0m"
echo -e "\e[33m          ⚡ THUNDER VIRUS & MALWARE SCANNER ⚡          \e[0m"
echo -e "\e[32m           Built by NEXO-TECH (Linux & Termux)                  \e[0m"
echo -e "\e[36m================================================================\e[0m"

echo -e "[+] Target Path      : \e[1m\e[37m$SCAN_PATH\e[0m"
echo -e "[+] Remediation Mode : \e[33m$MODE\e[0m"

files_scanned=0
threats_found=0

shred_file() {
    local target="$1"
    if command -v shred >/dev/null 2>&1; then
        shred -u -z -n 3 "$target" 2>/dev/null
    else
        # Fallback multi-pass overwrite
        local size
        size=$(wc -c < "$target" 2>/dev/null || echo 1024)
        dd if=/dev/zero of="$target" bs=1 count="$size" conv=notrunc 2>/dev/null
        rm -f "$target"
    fi
}

quarantine_file() {
    local target="$1"
    local tname="$2"
    local sha="$3"
    local rec_id="$(date +%s)_${sha:0:8}"
    local vault_path="$VAULT_DIR/$rec_id.vault"
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    # Move to vault
    mv "$target" "$vault_path" 2>/dev/null
    
    local new_entry="{\"id\":\"$rec_id\",\"original_path\":\"$target\",\"quarantined_path\":\"$vault_path\",\"detection_name\":\"$tname\",\"sha256\":\"$sha\",\"timestamp\":\"$timestamp\"}"
    
    if [ ! -f "$MANIFEST_FILE" ] || [ ! -s "$MANIFEST_FILE" ]; then
        echo "[$new_entry]" > "$MANIFEST_FILE"
    else
        # Append to existing JSON array
        if grep -q '\]' "$MANIFEST_FILE" 2>/dev/null; then
            sed -i '$ s/\]$//' "$MANIFEST_FILE" 2>/dev/null || true
            echo ",$new_entry]" >> "$MANIFEST_FILE"
        else
            echo "[$new_entry]" > "$MANIFEST_FILE"
        fi
    fi
}

while IFS= read -r -d '' file; do
    # Skip quarantine directory
    [[ "$file" =~ quarantine ]] && continue

    files_scanned=$((files_scanned+1))

    # Calculate hashes
    md5_hash=$(md5sum "$file" 2>/dev/null | awk '{print $1}')
    sha256_hash=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')

    is_threat=0
    threat_name=""

    # 1. Hash check
    for h in "${KNOWN_MD5_HASHES[@]}"; do
        hash_val="${h%%:*}"
        if [ "$md5_hash" = "$hash_val" ]; then
            is_threat=1
            threat_name="${h##*:}"
            break
        fi
    done

    if [ "$is_threat" -eq 0 ]; then
        for h in "${KNOWN_SHA256_HASHES[@]}"; do
            hash_val="${h%%:*}"
            if [ "$sha256_hash" = "$hash_val" ]; then
                is_threat=1
                threat_name="${h##*:}"
                break
            fi
        done
    fi

    # 2. Pattern check
    if [ "$is_threat" -eq 0 ]; then
        for p in "${MALICIOUS_PATTERNS[@]}"; do
            pat_str="${p%%:*}"
            if grep -F -q "$pat_str" "$file" 2>/dev/null; then
                is_threat=1
                threat_name="${p##*:}"
                break
            fi
        done
    fi

    if [ "$is_threat" -eq 1 ]; then
        threats_found=$((threats_found+1))
        echo -e "\e[31m[!] THREAT FOUND: \e[1m$threat_name\e[0m"
        echo -e "    File : $file"
        echo -e "    SHA  : ${sha256_hash:-N/A}"

        if [ "$MODE" = "quarantine" ]; then
            quarantine_file "$file" "$threat_name" "$sha256_hash"
            echo -e "    \e[32mAction: Quarantined safely to $VAULT_DIR\e[0m"
        elif [ "$MODE" = "shred" ]; then
            shred_file "$file"
            echo -e "    \e[31mAction: Permanently shredded & destroyed\e[0m"
        fi
        echo ""
    fi
done < <(find "$SCAN_PATH" -type f -size -100M -print0 2>/dev/null)

echo -e "\e[36m====================== SCAN RESULTS ======================\e[0m"
echo -e "Files Inspected : $files_scanned"
if [ "$threats_found" -eq 0 ]; then
    echo -e "Threats Found   : \e[32m0 (SYSTEM CLEAN)\e[0m"
else
    echo -e "Threats Found   : \e[31m$threats_found THREAT(S) DETECTED\e[0m"
fi
