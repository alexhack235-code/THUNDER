# THUNDER: Enterprise Network & Device Defender
### Built by NEXO-TECH

THUNDER is an all-in-one defensive security framework engineered to protect workstations, laptops, servers, and mobile devices against modern cyber threats. It integrates real-time Wi-Fi deauthentication defense, anti-reverse shell monitoring, network ARP spoofing defense, ransomware honeypot traps, BadUSB mitigation, keylogger detection, encrypted DNS armor, attack surface reduction, a high-performance malware scanner, and a dynamic IP rotator with 105 active endpoints.

---

## Operating System Guides

THUNDER is designed to run seamlessly on **Windows**, **Linux**, and **Android (Termux)**. Follow the instructions below for your operating system.

---

### Windows Guide

#### Prerequisites
- Windows 10 or Windows 11 (64-bit recommended).
- PowerShell 5.1 or PowerShell 7+ (Built into Windows).
- Administrator privileges (required for firewall rules, network adapter configuration, and system hardening).

#### Step 1: Open PowerShell as Administrator
1. Press `Win + X` and select **Windows PowerShell (Admin)** or **Terminal (Admin)**.
2. Navigate to the THUNDER directory:
   ```powershell
   cd .\THUNDER
   ```

#### Step 2: Launch the Interactive Master Menu
Run the master controller:
```powershell
powershell -ExecutionPolicy Bypass -File .\thunder.ps1
```
*Note: If run without admin privileges, THUNDER will automatically prompt for elevation to ensure all defense modules function properly.*

#### Step 3: Available Interactive Menu Options
When launched, choose from the interactive menu:
- **[1] Arm All Defensive Shields**: Activates Bluetooth stealth, plants ransomware canaries, immunizes USB ports, enforces firewall profiles, checks Wi-Fi PMF, pins gateway ARP, and audits reverse shell sockets simultaneously.
- **[2] Wi-Fi Deauth Defender**: Inspects 802.11 reason codes, monitors for rogue APs, and enables auto-reconnection.
- **[3] Anti-Reverse Shell Shield**: Monitors active sockets, inspects process command-lines for encoded payloads, and auto-kills C2 connections.
- **[4] Network Defender**: Pins the default gateway ARP binding and detects port scans and SYN floods.
- **[5] Bluetooth Stealth Shield**: Disables discovery or powers down Bluetooth radio hardware.
- **[6] Anti-Ransomware Watchdog**: Plants alphabetical canary traps, protects Volume Shadow Copies (VSS), and enables Controlled Folder Access.
- **[7] USB & BadUSB Shield**: Disables AutoRun, immunizes flash drives, and locks storage in Read-Only mode.
- **[8] Anti-Keylogger Shield**: Audits global keyboard hooks and hidden screen recorders.
- **[9] Anti-Spyware & Persistence Audit**: Audits Run keys, Startup folders, Windows Services, WMI subscriptions, and Winlogon.
- **[10] DNS Armor**: Enforces dual-stack encrypted DoH via Quad9 (malware blocking), Cloudflare, or AdGuard, and protects the hosts file.
- **[11] System Hardening (ASR)**: Applies Microsoft Defender Attack Surface Reduction rules, enables LSA RunAsPPL, and disables NetBIOS over TCP/IP.
- **[12] Malware Scanner**: Scans any directory with MD5/SHA256 hashes, YARA signatures, and Shannon entropy heuristics, then generates the interactive HTML report.
- **[13] View Cyberpunk HTML Visualizer**: Opens `report.html` in your default web browser.
- **[14] Random IP Changer**: Randomizes the network adapter MAC address and renews the DHCP lease.
- **[15] Benchmark 105 Endpoint Pool**: Benchmarks all IP check endpoints in parallel.
- **[16] Privacy & Leak Detector**: Tests for upstream recursive DNS leaks and IPv6 exposure.
- **[17] Dynamic Firewall Quarantines**: Views and manages blocked threat IPs.
- **[18] Live Defender Event Logs**: Views real-time threat audit logs.
- **[19] Comprehensive System Security Audit**: Runs a unified audit across all security subsystems.

#### Direct CLI Automation Commands (Non-Interactive)
```powershell
# Arm all defensive shields in one command:
powershell -ExecutionPolicy Bypass -File .\thunder.ps1 -ShieldAll

# Run a malware scan with automatic quarantine and launch the HTML visualizer:
powershell -ExecutionPolicy Bypass -File .\thunder.ps1 -Scan -ScanPath "C:\TargetFolder" -Quarantine

# Enforce full system hardening and ASR rules:
powershell -ExecutionPolicy Bypass -File .\thunder.ps1 -HardenSystem

# Plant anti-ransomware honeypot canaries:
powershell -ExecutionPolicy Bypass -File .\thunder.ps1 -DeployCanaries

# Audit active keyloggers and surveillance tools:
powershell -ExecutionPolicy Bypass -File .\thunder.ps1 -KeyloggerAudit

# Randomize MAC address and rotate local IP:
powershell -ExecutionPolicy Bypass -File .\thunder.ps1 -RotateIP
```

---

### Linux Guide

#### Prerequisites
- Any modern Linux distribution (Ubuntu, Debian, Kali, Fedora, Arch, CentOS).
- Standard utilities: `bash`, `curl`, `iproute2`, `iptables` (or `ufw`).
- Root permissions (`sudo`) for firewall and network adapter modifications.

#### Step 1: Set Permissions
Open a terminal in the THUNDER directory and grant execution permissions:
```bash
chmod +x thunder.sh defender/*.sh thunder-scanner/*.sh ip-rotator/*.sh
```

#### Step 2: Launch the Master Menu
Run the master script:
```bash
sudo ./thunder.sh
```

#### Step 3: Direct CLI Commands on Linux
```bash
# Arm all defense shields:
sudo ./thunder.sh --shield-all

# Scan a directory with automatic quarantine:
sudo ./thunder.sh --scan /path/to/directory quarantine

# Scan a directory with permanent multi-pass shredding:
sudo ./thunder.sh --scan /path/to/directory shred

# Rotate MAC address and cycle network interface:
sudo ./thunder.sh --rotate-ip

# View active network defense status:
sudo ./thunder.sh --status
```

---

### Android (Termux) Guide

#### Prerequisites
- Android device with the **Termux** app installed (F-Droid version recommended).
- Internet connection for initial package installation.

#### Step 1: Install Required Packages in Termux
Open Termux and run:
```bash
pkg update -y
pkg install -y bash curl git nodejs rust
# Optional: Install Termux API for Wi-Fi and Bluetooth hardware access:
pkg install -y termux-api
```

#### Step 2: Grant Storage Permissions
```bash
termux-setup-storage
```

#### Step 3: Set Permissions & Run THUNDER
Navigate to the project folder and make scripts executable:
```bash
chmod +x thunder.sh defender/*.sh thunder-scanner/*.sh ip-rotator/*.sh
./thunder.sh
```

#### Termux Use Cases:
- **Scan Downloads & SD Card**: Select Option [11] or run `./thunder.sh --scan /sdcard/Download quarantine` to inspect downloaded files and APKs for malicious scripts, webshells, and high-entropy payloads.
- **Check Privacy & Public IP**: Select Option [12] to query the 105-endpoint pool and verify external IP routing.
- **Test for DNS Leaks**: Select Option [14] to ensure mobile traffic is resolving securely.

---

## Cyberpunk Interactive HTML Visualizer (`report.html`)

When a malware scan finishes, THUNDER generates a high-tech security operations visualizer (`report.html`).

### Visualizer Features:
- **Neural Particle Matrix**: Interactive canvas that responds to cursor movement.
- **Real-Time Threat Radar**: Rotating circular radar showing active sweep coordinates.
- **Metric Gauges**: Animated percentage displays for System Health Score, Total Files Inspected, Threats Quarantined, and Execution Latency.
- **Searchable Threat Inventory**: Filterable table with severity badges (Critical, High, Medium, Test, Quarantined) and metadata drawers.

To view the latest report at any time:
- On Windows: Double-click `report.html` or choose **Option 13** in `thunder.ps1`.
- On Linux: `xdg-open report.html`
- On Android (Termux): `termux-open report.html`

---

## Repository Structure

```
THUNDER/
├── thunder.ps1                      # Windows Master Interactive Controller & Daemon Manager
├── thunder.sh                       # Linux & Android (Termux) Master Interactive Controller
├── report.html                      # Cyberpunk Security Operations Dashboard
├── README.md                        # Master Operating Guide & Architecture Manual
├── defender/                        # Defense & Mitigation Modules
│   ├── wifi_shield.ps1              # Wi-Fi Deauth, 802.11 Reason Codes & Rogue AP Shield
│   ├── wifi_shield.sh               # Wi-Fi Deauth & Rogue AP Shield (Linux/Termux)
│   ├── reverse_shell_shield.ps1     # Anti-Reverse Shell, LOLBins & Socket Monitor
│   ├── reverse_shell_shield.sh      # Anti-Reverse Shell Monitor (Linux/Termux)
│   ├── network_shield.ps1           # ARP Poisoning, Port Scans & Static ARP Pinning
│   ├── network_shield.sh            # ARP Poisoning & Network Defender (Linux/Termux)
│   ├── bluetooth_shield.ps1         # Bluetooth Stealth & Hardware Radio Kill-Switch
│   ├── bluetooth_shield.sh          # Bluetooth Stealth Shield (Linux/Termux)
│   ├── anti_ransomware_shield.ps1   # Canary Honeypots, VSS Protection & Auto-Kill
│   ├── anti_ransomware_shield.sh    # Canary Honeypot Shield (Linux/Termux)
│   ├── usb_shield.ps1               # BadUSB Keyboard Spoofing & USB Storage Lockdown
│   ├── usb_shield.sh                # USB Media Interface Shield (Linux/Termux)
│   ├── keylogger_shield.ps1         # Anti-Keylogger & Hidden Screen Capture Defender
│   ├── anti_spyware_shield.ps1      # AutoRuns-Scope Persistence & Spyware Auditor
│   ├── anti_spyware_shield.sh       # Persistence & Cron Auditor (Linux/Termux)
│   ├── dns_armor.ps1                # Dual-Stack Encrypted DoH & Hosts File Guard
│   ├── dns_armor.sh                 # DNS Armor & Encrypted Resolver (Linux/Termux)
│   ├── system_hardening.ps1         # Microsoft Defender ASR Rules & LSA RunAsPPL
│   ├── system_hardening.sh          # Kernel Network Hardening (Linux/Termux)
│   ├── firewall_manager.ps1         # Dynamic Firewall Quarantine with TTL & Self-Defense
│   └── firewall_manager.sh          # Dynamic iptables/UFW Quarantine (Linux/Termux)
├── thunder-scanner/                 # Rust Malware & Threat Remediation Subdirectory
│   ├── Cargo.toml                   # Rust Project Manifest
│   ├── run_scanner.ps1              # High-Speed Scanner Runner & Auto-HTML Reporter
│   ├── run_scanner.sh               # Linux/Termux Scanner Runner & Native Engine
│   ├── generate_html_report.ps1     # Cyberpunk Animated Report Generator
│   └── src/
│       ├── main.rs                  # Rust CLI Dispatcher & Centralized Vault Anchor
│       ├── engine.rs                # Multi-Threaded Scanning Engine & File Traversal
│       ├── signatures.rs            # Signature DB (Hashes, YARA patterns, Webshells)
│       ├── heuristics.rs            # Shannon Entropy & PE Header Structure Analyzer
│       ├── quarantine.rs            # Isolated XOR-Masked Quarantine Vault
│       └── cleaner.rs               # Active Process Killer & DoD 3-Pass Secure Shredder
├── ip-rotator/                      # Dynamic IP Changer & 100+ Endpoint Pool
│   ├── api_pool.json                # 105 Verified Active Public IP & Routing Endpoints
│   ├── proxy_rotator.js             # High-Speed Async Multi-Endpoint Benchmark (Node.js)
│   ├── ip_rotator.ps1               # Hardware MAC Randomizer & DHCP Lease Cycler
│   ├── ip_rotator.sh                # Network Hardware & MAC Cycler (Linux/Termux)
│   ├── leak_detector.ps1            # Upstream Recursive DNS & IPv6 Privacy Leak Tester
│   └── leak_detector.sh             # Privacy & DNS Leak Tester (Linux/Termux)
├── quarantine/                      # XOR-Encrypted Sandbox Vault Storage
└── logs/                            # Real-Time Event & Threat Audit Logs
```

---

## Security Principles & Architecture

1. **Self-Preservation Guard**: The dynamic firewall manager prevents blocking local loopback, the active default gateway, or primary configured DNS servers, avoiding accidental network lockouts.
2. **Cryptographic Sandbox Isolation**: Quarantined threats are masked with byte-level XOR encoding and assigned unique IDs in `manifest.json`. Files inside the vault cannot be executed accidentally.
3. **DoD 5220.22-M Secure Shredding**: When `-Shred` is invoked, malicious files undergo multi-pass binary overwriting before deletion, preventing forensic file recovery.

---

### Built by NEXO-TECH
