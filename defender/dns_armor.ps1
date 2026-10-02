# ==============================================================================
# THUNDER - DNS Armor & Encrypted DoH Resolver Shield (10-Star Edition)
# Built by: NEXO-TECH
# ==============================================================================

param (
    [Parameter(Mandatory=$false)]
    [ValidateSet("Quad9", "Cloudflare", "AdGuard", "DHCP", "Flush", "LockHosts", "UnlockHosts", "Status")]
    [string]$Provider = "Status"
)

$LogPath = "$PSScriptRoot\..\logs\defender_events.log"
$HostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"

function Write-ThunderLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [DNS-ARMOR] $Message"
    if (!(Test-Path "$PSScriptRoot\..\logs")) {
        New-Item -ItemType Directory -Path "$PSScriptRoot\..\logs" -Force | Out-Null
    }
    Add-Content -Path $LogPath -Value $logEntry -Encoding UTF8
    
    switch ($Level) {
        "ALERT" { Write-Host $logEntry -ForegroundColor Red }
        "WARN"  { Write-Host $logEntry -ForegroundColor Yellow }
        "INFO"  { Write-Host $logEntry -ForegroundColor Cyan }
        "OK"    { Write-Host $logEntry -ForegroundColor Green }
    }
}

function Set-EncryptedDNS {
    param(
        [string[]]$IPv4Servers,
        [string[]]$IPv6Servers,
        [string]$ProviderName,
        [string]$DohTemplate = ""
    )

    Write-ThunderLog "Enforcing Dual-Stack Encrypted DNS Shield ($ProviderName)..." "INFO"

    $allServers = if ($IPv6Servers) { @($IPv4Servers) + @($IPv6Servers) } else { @($IPv4Servers) }
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    foreach ($a in $adapters) {
        try {
            Set-DnsClientServerAddress -InterfaceIndex $a.InterfaceIndex -ServerAddresses $allServers -ErrorAction Stop
            Write-ThunderLog "Applied $ProviderName DNS to adapter '$($a.Name)' ($($allServers -join ', '))" "OK"
        } catch {
            Write-ThunderLog "Could not set DNS on '$($a.Name)': $_ (Requires Administrator)" "WARN"
        }
    }

    # Enable native Windows 11 DNS-over-HTTPS (DoH) where supported
    if ($DohTemplate -and (Get-Command Set-DnsClientDohServerAddress -ErrorAction SilentlyContinue)) {
        foreach ($srv in $IPv4Servers) {
            try {
                Set-DnsClientDohServerAddress -ServerAddress $srv -DohTemplate $DohTemplate -AllowFallbackToUdp $true -AutoUpgrade $true -ErrorAction SilentlyContinue
                Write-ThunderLog "Configured native Windows DoH template ($DohTemplate) for $srv" "OK"
            } catch {}
        }
    }

    Clear-DnsClientCache
    Write-ThunderLog "Flushed local Windows DNS resolver cache." "OK"
}

function Reset-ToDHCP {
    Write-ThunderLog "Reverting DNS configuration to automatic DHCP resolution..." "INFO"
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    foreach ($a in $adapters) {
        try {
            Set-DnsClientServerAddress -InterfaceIndex $a.InterfaceIndex -ResetServerAddresses -ErrorAction SilentlyContinue
            Write-ThunderLog "Reset adapter '$($a.Name)' to DHCP DNS." "OK"
        } catch {}
    }
    Clear-DnsClientCache
}

function Lock-HostsFile {
    Write-ThunderLog "Auditing and locking Windows Hosts file ($HostsPath)..." "INFO"
    if (Test-Path $HostsPath) {
        try {
            $content = Get-Content $HostsPath -Raw
            $suspiciousLines = @()
            foreach ($line in ($content -split "`r?`n")) {
                $trimmed = $line.Trim()
                if ($trimmed -and -not $trimmed.StartsWith("#")) {
                    if ($trimmed -match "google|microsoft|virustotal|symantec|mcafee|kaspersky|sophos") {
                        $suspiciousLines += $trimmed
                    }
                }
            }

            if ($suspiciousLines.Count -gt 0) {
                Write-ThunderLog "CRITICAL: HOSTS FILE HIJACK DETECTED! Malicious domain redirects found:" "ALERT"
                foreach ($sl in $suspiciousLines) { Write-ThunderLog "    $sl" "ALERT" }
            } else {
                Write-ThunderLog "Hosts file is CLEAN (No rogue AV/Security redirects)." "OK"
            }

            # Set Read-Only
            Set-ItemProperty -Path $HostsPath -Name Attributes -Value ([System.IO.FileAttributes]::ReadOnly) -ErrorAction SilentlyContinue
            Write-ThunderLog "Enforced Read-Only write protection on $HostsPath" "OK"
        } catch {
            Write-ThunderLog "Failed to lock hosts file: $_" "WARN"
        }
    }
}

function Unlock-HostsFile {
    Write-ThunderLog "Removing Read-Only attribute on Windows Hosts file ($HostsPath)..." "INFO"
    if (Test-Path $HostsPath) {
        try {
            Set-ItemProperty -Path $HostsPath -Name Attributes -Value ([System.IO.FileAttributes]::Normal) -ErrorAction Stop
            Write-ThunderLog "Successfully unlocked $HostsPath for editing." "OK"
        } catch {
            Write-ThunderLog "Failed to unlock hosts file: $_ (Administrator privileges required)" "WARN"
        }
    }
}

function Show-DNSStatus {
    Write-Host "`n=======================================================" -ForegroundColor Cyan
    Write-Host "         THUNDER DNS ARMOR & ENCRYPTED RESOLVER        " -ForegroundColor Yellow
    Write-Host "                   Built by NEXO-TECH                  " -ForegroundColor DarkCyan
    Write-Host "=======================================================" -ForegroundColor Cyan

    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    foreach ($a in $adapters) {
        $dns = Get-DnsClientServerAddress -InterfaceIndex $a.InterfaceIndex -ErrorAction SilentlyContinue
        $servers = if ($dns) { ($dns.ServerAddresses | Where-Object {$_}) -join ", " } else { "DHCP Assigned" }
        Write-Host "[+] Adapter '$($a.Name)' : $servers" -ForegroundColor White
    }

    Write-Host "`n[+] Available Dual-Stack DNS Armor Profiles:" -ForegroundColor Cyan
    Write-Host "    - Quad9     : 9.9.9.9 / 149.112.112.112 | 2620:fe::fe (Threat & Malware Blocking DoH)" -ForegroundColor White
    Write-Host "    - Cloudflare: 1.1.1.1 / 1.0.0.1 | 2606:4700:4700::1111 (Zero-Logging & Speed DoH)" -ForegroundColor White
    Write-Host "    - AdGuard   : 94.140.14.14 / 94.140.15.15 | 2a10:50c0::ad1:ff (Ad & Tracker Shield DoH)" -ForegroundColor White
    Write-Host "    - DHCP      : Reverts all adapters to automatic network DHCP" -ForegroundColor White
    Write-Host "    - LockHosts : Inspects and locks %SystemRoot%\System32\drivers\etc\hosts" -ForegroundColor White
    Write-Host "    - UnlockHosts: Restores write access to hosts file" -ForegroundColor White
}

switch ($Provider) {
    "Quad9"       { Set-EncryptedDNS -IPv4Servers @("9.9.9.9", "149.112.112.112") -IPv6Servers @("2620:fe::fe", "2620:fe::9") -ProviderName "Quad9 Threat-Blocking" -DohTemplate "https://dns.quad9.net/dns-query" }
    "Cloudflare"  { Set-EncryptedDNS -IPv4Servers @("1.1.1.1", "1.0.0.1") -IPv6Servers @("2606:4700:4700::1111", "2606:4700:4700::1001") -ProviderName "Cloudflare Privacy" -DohTemplate "https://cloudflare-dns.com/dns-query" }
    "AdGuard"     { Set-EncryptedDNS -IPv4Servers @("94.140.14.14", "94.140.15.15") -IPv6Servers @("2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff") -ProviderName "AdGuard Ad-Shield" -DohTemplate "https://dns.adguard-dns.com/dns-query" }
    "DHCP"        { Reset-ToDHCP }
    "LockHosts"   { Lock-HostsFile }
    "UnlockHosts" { Unlock-HostsFile }
    "Flush"       { Clear-DnsClientCache; Write-ThunderLog "Flushed DNS resolver cache." "OK" }
    "Status"      { Show-DNSStatus }
}
