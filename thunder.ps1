# ==============================================================================
# ⚡ THUNDER: Comprehensive Network & Device Defender Suite (10-Star Edition)
# Built by: NEXO-TECH
# ==============================================================================

param (
    [Parameter(Mandatory=$false)]
    [switch]$ShieldAll,

    [Parameter(Mandatory=$false)]
    [switch]$Scan,

    [Parameter(Mandatory=$false)]
    [string]$ScanPath = ".",

    [Parameter(Mandatory=$false)]
    [switch]$Quarantine,

    [Parameter(Mandatory=$false)]
    [switch]$Shred,

    [Parameter(Mandatory=$false)]
    [switch]$RotateIP,

    [Parameter(Mandatory=$false)]
    [switch]$Status,

    [Parameter(Mandatory=$false)]
    [switch]$BenchmarkAPIs,

    [Parameter(Mandatory=$false)]
    [switch]$BluetoothStealth,

    [Parameter(Mandatory=$false)]
    [switch]$HardenSystem,

    [Parameter(Mandatory=$false)]
    [switch]$DeployCanaries,

    [Parameter(Mandatory=$false)]
    [switch]$KeyloggerAudit,

    [Parameter(Mandatory=$false)]
    [switch]$NoElevate
)

# Self-Elevation Check
if (-not $NoElevate) {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "[*] Requesting Administrator Elevation for THUNDER Core Defenses..." -ForegroundColor Yellow
        $boundArgs = @()
        foreach ($key in $PSBoundParameters.Keys) {
            $val = $PSBoundParameters[$key]
            if ($val -is [System.Management.Automation.SwitchParameter]) {
                if ($val.IsPresent) { $boundArgs += "-$key" }
            } else {
                $boundArgs += "-$key `"$val`""
            }
        }
        $rawArgs = ($boundArgs + $args) -join " "
        $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $rawArgs"
        try {
            Start-Process powershell -ArgumentList $argList -Verb RunAs
            exit
        } catch {
            Write-Host "[-] Elevation cancelled by user. Continuing in unprivileged mode..." -ForegroundColor Yellow
            Start-Sleep -Seconds 1
        }
    }
}

$RootDir = $PSScriptRoot
$DefenderDir = "$RootDir\defender"
$ScannerDir = "$RootDir\thunder-scanner"
$RotatorDir = "$RootDir\ip-rotator"
$LogPath = "$RootDir\logs\defender_events.log"
$ReportPath = "$RootDir\report.html"

function Print-Banner {
    Clear-Host
    Write-Host @"
 ████████╗██╗  ██╗██╗   ██╗███╗   ██╗██████╗ ███████╗██████╗ 
 ╚══██╔══╝██║  ██║██║   ██║████╗  ██║██╔══██╗██╔════╝██╔══██╗
    ██║   ███████║██║   ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
    ██║   ██╔══██║██║   ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
    ██║   ██║  ██║╚██████╔╝██║ ╚████║██████╔╝███████╗██║  ██║
    ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝
"@ -ForegroundColor Yellow

    Write-Host " ======================================================================" -ForegroundColor Cyan
    Write-Host "        THUNDER COMPREHENSIVE NETWORK & DEVICE DEFENDER                " -ForegroundColor White
    Write-Host "                          Built by NEXO-TECH                           " -ForegroundColor Green
    Write-Host " ======================================================================" -ForegroundColor Cyan
}

function Run-ShieldAll {
    Print-Banner
    Write-Host "`n[*] ENGAGING ALL 8 THUNDER DEFENSIVE SHIELD LAYERS..." -ForegroundColor Yellow
    
    # 1. Enable Bluetooth Stealth
    Write-Host "[1/8] Activating Bluetooth Stealth Mode..." -ForegroundColor Cyan
    & "$DefenderDir\bluetooth_shield.ps1" -EnableStealth

    # 2. Deploy Anti-Ransomware Canaries
    Write-Host "[2/8] Deploying Alphabetical Anti-Ransomware Honeypot Sensors..." -ForegroundColor Cyan
    & "$DefenderDir\anti_ransomware_shield.ps1" -DeployCanaries

    # 3. Immunize USB & Disable AutoRun
    Write-Host "[3/8] Enforcing USB AutoRun Immunity & Storage Security..." -ForegroundColor Cyan
    & "$DefenderDir\usb_shield.ps1" -DisableAutoRun

    # 4. Enforce Windows Firewall Default-Deny Profiles
    Write-Host "[4/8] Enforcing Dynamic Firewall Profiles & Threat Quarantine..." -ForegroundColor Cyan
    & "$DefenderDir\firewall_manager.ps1" -Action EnforceProfiles

    # 5. Check Wi-Fi & PMF Status
    Write-Host "[5/8] Initializing Wi-Fi Deauth Defense & Telemetry..." -ForegroundColor Cyan
    & "$DefenderDir\wifi_shield.ps1"

    # 6. Check Network & Gateway ARP integrity
    Write-Host "[6/8] Pinning Gateway & Inspecting ARP / Port-Scan Telemetry..." -ForegroundColor Cyan
    & "$DefenderDir\network_shield.ps1" -PinGatewayARP

    # 7. Audit Keyloggers & Screen Hooks
    Write-Host "[7/8] Auditing Keylogger Hooks & Hidden Surveillance..." -ForegroundColor Cyan
    & "$DefenderDir\keylogger_shield.ps1"

    # 8. Audit Reverse Shell & Sockets
    Write-Host "[8/8] Auditing Process Sockets & Anti-Reverse Shell Monitor..." -ForegroundColor Cyan
    & "$DefenderDir\reverse_shell_shield.ps1"

    Write-Host "`n[+] ALL 8 DEFENSIVE SHIELD LAYERS ARE ARMED AND OPERATIONAL." -ForegroundColor Green
    Write-Host "[!] Background event logs written to: $LogPath" -ForegroundColor DarkGray
}

function Show-SystemStatus {
    Print-Banner
    Write-Host "`n========================= SYSTEM SECURITY AUDIT =========================" -ForegroundColor Cyan

    
    Write-Host "`n--- [1] Wi-Fi & 802.11 Deauth Telemetry ---" -ForegroundColor Yellow
    & "$DefenderDir\wifi_shield.ps1"

    Write-Host "`n--- [2] Reverse Shell & Outbound Socket Status ---" -ForegroundColor Yellow
    & "$DefenderDir\reverse_shell_shield.ps1"

    Write-Host "`n--- [3] Network & ARP Integrity ---" -ForegroundColor Yellow
    & "$DefenderDir\network_shield.ps1"

    Write-Host "`n--- [4] Bluetooth Radio & Stealth Status ---" -ForegroundColor Yellow
    & "$DefenderDir\bluetooth_shield.ps1"

    Write-Host "`n--- [5] Anti-Ransomware Canary Integrity ---" -ForegroundColor Yellow
    & "$DefenderDir\anti_ransomware_shield.ps1" -Audit

    Write-Host "`n--- [6] Keylogger & Screen Capture Surveillance Audit ---" -ForegroundColor Yellow
    & "$DefenderDir\keylogger_shield.ps1"

    Write-Host "`n--- [7] System Hardening & ASR Status ---" -ForegroundColor Yellow
    & "$DefenderDir\system_hardening.ps1" -Audit

    Write-Host "`n--- [8] Public IP & Endpoint Status ---" -ForegroundColor Yellow
    & "$RotatorDir\ip_rotator.ps1"
}

function Interactive-Menu {
    while ($true) {
        Print-Banner
        Write-Host " [1]  " -NoNewline -ForegroundColor Yellow; Write-Host "Arm All Defensive Shields (Wi-Fi, RevShell, Network, BT, Ransomware, USB, Keylogger)" -ForegroundColor White
        Write-Host " [2]  " -NoNewline -ForegroundColor Yellow; Write-Host "Wi-Fi Deauth & Rogue AP Defender (Status / Monitor)" -ForegroundColor White
        Write-Host " [3]  " -NoNewline -ForegroundColor Yellow; Write-Host "Anti-Reverse Shell & Process Defense (Auto-Kill & IP Quarantine)" -ForegroundColor White
        Write-Host " [4]  " -NoNewline -ForegroundColor Yellow; Write-Host "Network Defender (ARP Spoofing, Port Scans, Static ARP Pinning)" -ForegroundColor White
        Write-Host " [5]  " -NoNewline -ForegroundColor Yellow; Write-Host "Bluetooth Intrusion & Stealth Shield (Hardware Radio Control)" -ForegroundColor White
        Write-Host " [6]  " -NoNewline -ForegroundColor Yellow; Write-Host "Anti-Ransomware Canary Trap & VSS Protection Watchdog" -ForegroundColor White
        Write-Host " [7]  " -NoNewline -ForegroundColor Yellow; Write-Host "USB & BadUSB Removable Media Shield (AutoRun Immunizer / Storage Lockdown)" -ForegroundColor White
        Write-Host " [8]  " -NoNewline -ForegroundColor Yellow; Write-Host "Anti-Keylogger & Screen Capture Surveillance Defender" -ForegroundColor White
        Write-Host " [9]  " -NoNewline -ForegroundColor Yellow; Write-Host "Anti-Spyware & Advanced Persistence Audit (AutoRuns Scope)" -ForegroundColor White
        Write-Host " [10] " -NoNewline -ForegroundColor Yellow; Write-Host "DNS Armor & Dual-Stack Encrypted DoH Resolver (Quad9 / Cloudflare / AdGuard)" -ForegroundColor White
        Write-Host " [11] " -NoNewline -ForegroundColor Yellow; Write-Host "System Hardening & Attack Surface Reduction (ASR / LSA RunAsPPL Engine)" -ForegroundColor White
        Write-Host " [12] " -NoNewline -ForegroundColor Yellow; Write-Host "THUNDER Malware Scanner & Unreal Animated HTML Visualizer" -ForegroundColor White
        Write-Host " [13] " -NoNewline -ForegroundColor Yellow; Write-Host "Open Latest Cyberpunk HTML Security Dashboard" -ForegroundColor White
        Write-Host " [14] " -NoNewline -ForegroundColor Yellow; Write-Host "Random IP Changer & 100+ Endpoint Pool (Rotate MAC/DHCP)" -ForegroundColor White
        Write-Host " [15] " -NoNewline -ForegroundColor Yellow; Write-Host "Benchmark 100+ Public IP Endpoints & Latencies" -ForegroundColor White
        Write-Host " [16] " -NoNewline -ForegroundColor Yellow; Write-Host "Privacy, Dual-Stack & DNS Leak Detector" -ForegroundColor White
        Write-Host " [17] " -NoNewline -ForegroundColor Yellow; Write-Host "View Dynamic Firewall Quarantined Threat IPs" -ForegroundColor White
        Write-Host " [18] " -NoNewline -ForegroundColor Yellow; Write-Host "View Live Defender Event Logs" -ForegroundColor White
        Write-Host " [19] " -NoNewline -ForegroundColor Yellow; Write-Host "Comprehensive System Security Audit & Health Check" -ForegroundColor White
        Write-Host " [0]  " -NoNewline -ForegroundColor Red;    Write-Host "Exit THUNDER" -ForegroundColor Gray
        Write-Host " ======================================================================" -ForegroundColor Cyan
        
        $choice = Read-Host " Enter choice [0-19]"
        
        switch ($choice) {
            "1" {
                Run-ShieldAll
                Read-Host "`nPress Enter to return to menu..."
            }
            "2" {
                Print-Banner
                Write-Host "1. Single Status Check"
                Write-Host "2. Continuous Real-Time Deauth Monitor"
                $sub = Read-Host "Option [1-2]"
                if ($sub -eq "2") {
                    & "$DefenderDir\wifi_shield.ps1" -Monitor -AutoReconnect
                } else {
                    & "$DefenderDir\wifi_shield.ps1"
                }
                Read-Host "`nPress Enter to return to menu..."
            }
            "3" {
                Print-Banner
                Write-Host "1. Single Socket Audit"
                Write-Host "2. Continuous Anti-Reverse Shell Monitor with Auto-Kill & Auto-Block"
                $sub = Read-Host "Option [1-2]"
                if ($sub -eq "2") {
                    & "$DefenderDir\reverse_shell_shield.ps1" -Monitor -AutoKill -AutoBlockIP
                } else {
                    & "$DefenderDir\reverse_shell_shield.ps1"
                }
                Read-Host "`nPress Enter to return to menu..."
            }
            "4" {
                Print-Banner
                Write-Host "1. Single Network Audit"
                Write-Host "2. Pin Default Gateway Static ARP (Immune to ARP Spoofing)"
                Write-Host "3. Continuous ARP & Port-Scan Defense Monitor"
                $sub = Read-Host "Option [1-3]"
                if ($sub -eq "2") {
                    & "$DefenderDir\network_shield.ps1" -PinGatewayARP
                } elseif ($sub -eq "3") {
                    & "$DefenderDir\network_shield.ps1" -Monitor -AutoBlockAttacker
                } else {
                    & "$DefenderDir\network_shield.ps1"
                }
                Read-Host "`nPress Enter to return to menu..."
            }
            "5" {
                Print-Banner
                Write-Host "1. Bluetooth Status & Peripheral Audit"
                Write-Host "2. Enable Bluetooth Stealth Mode (Hide from BLE Sniffers)"
                Write-Host "3. Power Down Bluetooth Radio Hardware"
                Write-Host "4. Continuous Rogue Pairing Monitor"
                $sub = Read-Host "Option [1-4]"
                if ($sub -eq "2") {
                    & "$DefenderDir\bluetooth_shield.ps1" -EnableStealth
                } elseif ($sub -eq "3") {
                    & "$DefenderDir\bluetooth_shield.ps1" -DisableBluetooth
                } elseif ($sub -eq "4") {
                    & "$DefenderDir\bluetooth_shield.ps1" -Monitor
                } else {
                    & "$DefenderDir\bluetooth_shield.ps1"
                }
                Read-Host "`nPress Enter to return to menu..."
            }
            "6" {
                Print-Banner
                Write-Host "1. Audit Canary Honeypots & CFA Status"
                Write-Host "2. Deploy / Replant Alphabetical Canary Sensors"
                Write-Host "3. Enable Windows Defender Controlled Folder Access (CFA)"
                Write-Host "4. Start Real-Time Anti-Ransomware Watchdog with Auto-Kill"
                $sub = Read-Host "Option [1-4]"
                if ($sub -eq "2") {
                    & "$DefenderDir\anti_ransomware_shield.ps1" -DeployCanaries
                } elseif ($sub -eq "3") {
                    & "$DefenderDir\anti_ransomware_shield.ps1" -EnableCFA
                } elseif ($sub -eq "4") {
                    & "$DefenderDir\anti_ransomware_shield.ps1" -Monitor -AutoKill
                } else {
                    & "$DefenderDir\anti_ransomware_shield.ps1" -Audit
                }
                Read-Host "`nPress Enter to return to menu..."
            }
            "7" {
                Print-Banner
                Write-Host "1. Audit Connected USB Interfaces & BadUSB Devices"
                Write-Host "2. Disable Windows AutoRun / AutoPlay"
                Write-Host "3. Immunize Attached Removable USB Drives"
                Write-Host "4. Lock USB Storage in Read-Only Mode"
                $sub = Read-Host "Option [1-4]"
                if ($sub -eq "2") {
                    & "$DefenderDir\usb_shield.ps1" -DisableAutoRun
                } elseif ($sub -eq "3") {
                    & "$DefenderDir\usb_shield.ps1" -ImmunizeDrives
                } elseif ($sub -eq "4") {
                    & "$DefenderDir\usb_shield.ps1" -LockStorageReadOnly
                } else {
                    & "$DefenderDir\usb_shield.ps1" -Audit
                }
                Read-Host "`nPress Enter to return to menu..."
            }
            "8" {
                Print-Banner
                & "$DefenderDir\keylogger_shield.ps1" -Audit
                Read-Host "`nPress Enter to return to menu..."
            }
            "9" {
                Print-Banner
                & "$DefenderDir\anti_spyware_shield.ps1" -Audit
                Read-Host "`nPress Enter to return to menu..."
            }
            "10" {
                Print-Banner
                Write-Host "1. Current DNS Status"
                Write-Host "2. Set Quad9 Dual-Stack DNS (Threat & Malware Blocking)"
                Write-Host "3. Set Cloudflare Dual-Stack DNS (Zero-Logging & Speed)"
                Write-Host "4. Set AdGuard Dual-Stack DNS (Ad & Tracker Blocking)"
                Write-Host "5. Lock and Protect Windows Hosts File"
                Write-Host "6. Reset DNS to Automatic Network DHCP"
                $sub = Read-Host "Option [1-6]"
                switch ($sub) {
                    "2" { & "$DefenderDir\dns_armor.ps1" -Provider Quad9 }
                    "3" { & "$DefenderDir\dns_armor.ps1" -Provider Cloudflare }
                    "4" { & "$DefenderDir\dns_armor.ps1" -Provider AdGuard }
                    "5" { & "$DefenderDir\dns_armor.ps1" -Provider LockHosts }
                    "6" { & "$DefenderDir\dns_armor.ps1" -Provider DHCP }
                    default { & "$DefenderDir\dns_armor.ps1" -Provider Status }
                }
                Read-Host "`nPress Enter to return to menu..."
            }
            "11" {
                Print-Banner
                Write-Host "1. Audit Current System Hardening & Vulnerabilities"
                Write-Host "2. Apply Complete System Hardening (ASR Rules, LSA RunAsPPL, NetBIOS Disable, LLMNR Disable)"
                Write-Host "3. Revert Hardening to Default Baseline"
                $sub = Read-Host "Option [1-3]"
                if ($sub -eq "2") {
                    & "$DefenderDir\system_hardening.ps1" -ApplyHardening
                } elseif ($sub -eq "3") {
                    & "$DefenderDir\system_hardening.ps1" -RevertHardening
                } else {
                    & "$DefenderDir\system_hardening.ps1" -Audit
                }
                Read-Host "`nPress Enter to return to menu..."
            }
            "12" {
                Print-Banner
                Write-Host "THUNDER MALWARE & VIRUS SCANNER (RUST & NATIVE ENGINES)" -ForegroundColor Yellow
                $target = Read-Host "Enter directory or file to scan (Default: current directory)"

                if ([string]::IsNullOrWhiteSpace($target)) { $target = "." }
                $target = $target.Trim('"', "'")
                
                Write-Host "`nSelect Remediation Mode:"
                Write-Host "1. Audit Only + Generate Animated HTML Report"
                Write-Host "2. Encrypted Quarantine + Generate HTML Report"
                Write-Host "3. Secure Shred (DoD 3-Pass Overwrite & Destroy)"
                Write-Host "4. View Quarantined Files Vault"
                $mode = Read-Host "Option [1-4]"

                if ($mode -eq "2") {
                    & "$ScannerDir\run_scanner.ps1" -Path $target -Quarantine -OpenHtmlReport
                } elseif ($mode -eq "3") {
                    & "$ScannerDir\run_scanner.ps1" -Path $target -Shred -OpenHtmlReport
                } elseif ($mode -eq "4") {
                    & "$ScannerDir\run_scanner.ps1" -ListQuarantine
                } else {
                    & "$ScannerDir\run_scanner.ps1" -Path $target -OpenHtmlReport
                }
                Read-Host "`nPress Enter to return to menu..."
            }
            "13" {
                if (Test-Path $ReportPath) {
                    Write-Host "[+] Opening HTML Security Dashboard in default browser..." -ForegroundColor Green
                    Start-Process $ReportPath
                    Start-Sleep -Milliseconds 800
                } else {
                    Write-Host "No report generated yet. Run a scan (Option 12) first!" -ForegroundColor Yellow
                    Start-Sleep -Seconds 2
                }
            }
            "14" {
                Print-Banner
                Write-Host "1. Check Current External IP (via 100+ Endpoint Pool)"
                Write-Host "2. Randomize Network Adapter MAC & Force DHCP Renewal"
                Write-Host "3. Start Periodic Auto-IP Rotator Loop"
                $sub = Read-Host "Option [1-3]"

                if ($sub -eq "2") {
                    & "$RotatorDir\ip_rotator.ps1" -RotateMAC
                } elseif ($sub -eq "3") {
                    $minsInput = Read-Host "Enter rotation interval in minutes (Default: 5)"
                    $parsedMins = 5
                    if (-not [int]::TryParse($minsInput, [ref]$parsedMins) -or $parsedMins -le 0) {
                        $parsedMins = 5
                    }
                    & "$RotatorDir\ip_rotator.ps1" -AutoRotate -IntervalMinutes $parsedMins
                } else {
                    & "$RotatorDir\ip_rotator.ps1"
                }
                Read-Host "`nPress Enter to return to menu..."
            }
            "15" {
                Print-Banner
                & "$RotatorDir\ip_rotator.ps1" -BenchmarkPool
                Read-Host "`nPress Enter to return to menu..."
            }
            "16" {
                Print-Banner
                & "$RotatorDir\leak_detector.ps1"
                Read-Host "`nPress Enter to return to menu..."
            }
            "17" {
                Print-Banner
                & "$DefenderDir\firewall_manager.ps1" -Action Status
                Write-Host "`nOptions: [1] Flush all blocks, [2] Keep blocks"
                $opt = Read-Host "Choice"
                if ($opt -eq "1") {
                    & "$DefenderDir\firewall_manager.ps1" -Action FlushAll
                }
                Read-Host "`nPress Enter to return to menu..."
            }
            "18" {
                Print-Banner
                if (Test-Path $LogPath) {
                    Write-Host "=== RECENT THUNDER EVENTS (Last 25) ===" -ForegroundColor Cyan
                    Get-Content $LogPath -Tail 25
                } else {
                    Write-Host "No log entries recorded yet." -ForegroundColor Gray
                }
                Read-Host "`nPress Enter to return to menu..."
            }
            "19" {
                Print-Banner
                Show-SystemStatus
                Read-Host "`nPress Enter to return to menu..."
            }
            "0" {
                Write-Host "`n[+] Exiting THUNDER. Stay safe!" -ForegroundColor Green
                break
            }
            default {
                Write-Host "Invalid option. Try again." -ForegroundColor Yellow
                Start-Sleep -Seconds 1
            }
        }
    }
}

# CLI Flags Dispatcher
if ($ShieldAll) {
    Run-ShieldAll
}
elseif ($Status) {
    Show-SystemStatus
}
elseif ($Scan) {
    & "$ScannerDir\run_scanner.ps1" -Path $ScanPath -Quarantine:$Quarantine -Shred:$Shred -OpenHtmlReport
}
elseif ($RotateIP) {
    & "$RotatorDir\ip_rotator.ps1" -RotateMAC
}
elseif ($BenchmarkAPIs) {
    & "$RotatorDir\ip_rotator.ps1" -BenchmarkPool
}
elseif ($BluetoothStealth) {
    & "$DefenderDir\bluetooth_shield.ps1" -EnableStealth
}
elseif ($HardenSystem) {
    & "$DefenderDir\system_hardening.ps1" -ApplyHardening
}
elseif ($DeployCanaries) {
    & "$DefenderDir\anti_ransomware_shield.ps1" -DeployCanaries
}
elseif ($KeyloggerAudit) {
    & "$DefenderDir\keylogger_shield.ps1" -Audit
}
else {
    Interactive-Menu
}
