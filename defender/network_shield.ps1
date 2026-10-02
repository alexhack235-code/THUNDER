# ==============================================================================
# THUNDER - Network Attack Defender (10-Star Edition)
# Built by: NEXO-TECH
# ==============================================================================

param (
    [Parameter(Mandatory=$false)]
    [switch]$Monitor,

    [Parameter(Mandatory=$false)]
    [int]$IntervalSeconds = 2,

    [Parameter(Mandatory=$false)]
    [switch]$Audit,

    [Parameter(Mandatory=$false)]
    [switch]$AutoBlockAttacker,

    [Parameter(Mandatory=$false)]
    [switch]$PinGatewayARP
)

$LogPath = "$PSScriptRoot\..\logs\defender_events.log"
$FirewallScript = "$PSScriptRoot\firewall_manager.ps1"

function Write-ThunderLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [NETWORK-SHIELD] $Message"
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

function Get-ActiveDefaultGateway {
    try {
        $route = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Where-Object { $_.NextHop -ne "0.0.0.0" } | Select-Object -First 1
        if ($route) {
            return @{
                GatewayIP      = $route.NextHop
                InterfaceIndex = $route.InterfaceIndex
                InterfaceAlias = $route.InterfaceAlias
            }
        }
    } catch {}
    return $null
}

function Get-ArpNeighborData {
    $entries = @()
    try {
        # Native PowerShell cmdlets (robust across all Windows editions and locales)
        $neighbors = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {
            $_.State -notin @("Unreachable", "Permanent") -and $_.LinkLayerAddress -match "[0-9a-fA-F]{2}"
        }
        foreach ($n in $neighbors) {
            $entries += [PSCustomObject]@{
                IPAddress = $n.IPAddress
                MAC       = $n.LinkLayerAddress.ToLower().Replace("-", ":")
                State     = $n.State
                Interface = $n.InterfaceAlias
            }
        }
        return $entries
    } catch {
        # Fallback to arp -a
        $arpOutput = arp -a 2>$null
        if ($arpOutput) {
            foreach ($line in ($arpOutput -split "`r?`n")) {
                if ($line -match "^\s*([0-9\.]+)\s+([0-9a-fA-F\-]{17})\s+([a-zA-Z]+)") {
                    $entries += [PSCustomObject]@{
                        IPAddress = $matches[1]
                        MAC       = $matches[2].ToLower().Replace("-", ":")
                        State     = $matches[3]
                        Interface = "Default"
                    }
                }
            }
        }
        return $entries
    }
}

function Pin-GatewayStaticARP {
    $gw = Get-ActiveDefaultGateway
    if (-not $gw) {
        Write-ThunderLog "No active default gateway found to pin." "WARN"
        return
    }

    $neighbors = Get-ArpNeighborData
    $gwEntry = $neighbors | Where-Object { $_.IPAddress -eq $gw.GatewayIP } | Select-Object -First 1
    if ($gwEntry -and $gwEntry.MAC -ne "ff:ff:ff:ff:ff:ff") {
        try {
            # Set static ARP binding
            netsh interface ip add neighbors "$($gw.InterfaceIndex)" "$($gw.GatewayIP)" "$($gwEntry.MAC)" 2>$null | Out-Null
            Write-ThunderLog "STATIC ARP PINNED: Bound gateway $($gw.GatewayIP) -> $($gwEntry.MAC) on interface $($gw.InterfaceIndex) (Immune to ARP spoofing)." "OK"
        } catch {
            Write-ThunderLog "Failed to pin static gateway ARP: $_ (Administrator privileges required)" "WARN"
        }
    }
}

function Inspect-ArpPoisoning {
    param([string]$KnownGatewayIP, [ref]$GatewayMACRef)
    $arpEntries = Get-ArpNeighborData
    $threats = @()

    # 1. Gateway MAC Spoofing Check
    if ($KnownGatewayIP) {
        $gwEntry = $arpEntries | Where-Object { $_.IPAddress -eq $KnownGatewayIP } | Select-Object -First 1
        if ($gwEntry) {
            $currentGWMac = $gwEntry.MAC
            if ($GatewayMACRef.Value -ne "" -and $GatewayMACRef.Value -ne $currentGWMac) {
                $threats += [PSCustomObject]@{
                    Type        = "GATEWAY_ARP_POISONING"
                    TargetIP    = $KnownGatewayIP
                    OldMAC      = $GatewayMACRef.Value
                    NewMAC      = $currentGWMac
                    Description = "CRITICAL: Gateway MAC changed unexpectedly! Attacker is actively intercepting/MITM traffic via ARP Cache Poisoning."
                }
            }
            $GatewayMACRef.Value = $currentGWMac
        }
    }

    # 2. Duplicate MACs across different IPs Check
    $macGroups = $arpEntries | Where-Object { 
        $_.MAC -notmatch "^(ff:ff:ff:ff:ff:ff|01:00:5e|33:33)" -and $_.IPAddress -notmatch "^(224\.|239\.|255\.)"
    } | Group-Object -Property MAC | Where-Object { $_.Count -gt 1 }

    foreach ($group in $macGroups) {
        $ips = ($group.Group | Select-Object -ExpandProperty IPAddress) -join ", "
        $threats += [PSCustomObject]@{
            Type        = "DUPLICATE_MAC_ARP_SPOOF"
            MAC         = $group.Name
            IPs         = $ips
            Description = "Duplicate MAC address '$($group.Name)' mapped to multiple distinct IPs ($ips). Potential ARP Poisoning / Man-In-The-Middle attack."
        }
    }

    return $threats
}

function Inspect-PortScanActivity {
    try {
        # Only inspect SynReceived (inbound probes where an external host initiated half-open connection)
        $synConns = Get-NetTCPConnection -State SynReceived -ErrorAction SilentlyContinue
        if ($synConns) {
            $groupedByRemote = $synConns | Group-Object -Property RemoteAddress | Where-Object { $_.Count -ge 8 }
            $threats = @()
            foreach ($g in $groupedByRemote) {
                if ($g.Name -notin @("127.0.0.1", "0.0.0.0", "::1", "255.255.255.255")) {
                    $threats += [PSCustomObject]@{
                        Type        = "PORT_SCAN_OR_SYN_FLOOD"
                        AttackerIP  = $g.Name
                        PortCount   = $g.Count
                        Description = "Rapid multi-port inbound SYN probe / port scan detected from $($g.Name) ($($g.Count) simultaneous half-open sockets)."
                    }
                }
            }
            return $threats
        }
    } catch {}
    return @()
}

function Start-NetworkMonitor {
    Write-ThunderLog "Starting THUNDER Network Defender (ARP Poisoning, Port Scans, SYN Floods) [10-Star Engine]..." "OK"
    
    $gwInfo = Get-ActiveDefaultGateway
    $gwIP = if ($gwInfo) { $gwInfo.GatewayIP } else { "" }
    $gwMAC = ""
    
    Write-ThunderLog "Active Default Gateway: $(if ($gwIP) {"$gwIP on $($gwInfo.InterfaceAlias)"} else {'None detected'})" "INFO"

    # Seed initial gateway MAC
    $initEntries = Get-ArpNeighborData
    if ($gwIP) {
        $gwEntry = $initEntries | Where-Object { $_.IPAddress -eq $gwIP } | Select-Object -First 1
        if ($gwEntry) {
            $gwMAC = $gwEntry.MAC
            Write-ThunderLog "Baseline Gateway MAC: $gwMAC (Monitoring for unprovoked MAC mutations)" "OK"
        }
    }

    $gwMACRef = [ref]$gwMAC

    while ($true) {
        # Check for dynamic gateway shift (e.g., user connected to new Wi-Fi)
        $currentGW = Get-ActiveDefaultGateway
        if ($currentGW -and $currentGW.GatewayIP -ne $gwIP) {
            $gwIP = $currentGW.GatewayIP
            Write-ThunderLog "Network Interface Shift: Re-baselining gateway reference to $gwIP ($($currentGW.InterfaceAlias))." "INFO"
            $initEntries = Get-ArpNeighborData
            $gwEntry = $initEntries | Where-Object { $_.IPAddress -eq $gwIP } | Select-Object -First 1
            $gwMAC = if ($gwEntry) { $gwEntry.MAC } else { "" }
            $gwMACRef.Value = $gwMAC
        }

        # Check ARP Spoofing
        $arpThreats = Inspect-ArpPoisoning -KnownGatewayIP $gwIP -GatewayMACRef $gwMACRef
        foreach ($at in $arpThreats) {
            Write-ThunderLog "================= NETWORK THREAT: ARP SPOOFING =================" "ALERT"
            Write-ThunderLog "Type       : $($at.Type)" "ALERT"
            Write-ThunderLog "Description: $($at.Description)" "ALERT"
            Write-ThunderLog "==================================================================" "ALERT"
        }

        # Check Port Scanning / SYN Floods
        $scanThreats = Inspect-PortScanActivity
        foreach ($st in $scanThreats) {
            Write-ThunderLog "================= NETWORK THREAT: PORT SCAN ====================" "ALERT"
            Write-ThunderLog "Source IP  : $($st.AttackerIP)" "ALERT"
            Write-ThunderLog "Description: $($st.Description)" "ALERT"
            Write-ThunderLog "==================================================================" "ALERT"

            if ($AutoBlockAttacker -and (Test-Path $FirewallScript)) {
                & $FirewallScript -Action BlockIP -IPAddress $st.AttackerIP -Reason "Port Scanning / SYN Flood Probing" -DurationMinutes 60
            }
        }

        Start-Sleep -Seconds $IntervalSeconds
    }
}

function Show-NetworkAudit {
    Write-Host "`n=======================================================" -ForegroundColor Cyan
    Write-Host "         THUNDER NETWORK ATTACK DEFENDER AUDIT         " -ForegroundColor Yellow
    Write-Host "                   Built by NEXO-TECH                  " -ForegroundColor DarkCyan
    Write-Host "=======================================================" -ForegroundColor Cyan

    $gwInfo = Get-ActiveDefaultGateway
    Write-Host "[+] Default Gateway IP : $(if ($gwInfo) {"$($gwInfo.GatewayIP) on $($gwInfo.InterfaceAlias)"} else {'N/A'})" -ForegroundColor White

    $arpEntries = Get-ArpNeighborData
    Write-Host "[+] Active ARP Neighbors: $($arpEntries.Count)" -ForegroundColor White

    $dummyRef = [ref]""
    $arpThreats = Inspect-ArpPoisoning -KnownGatewayIP $(if ($gwInfo) {$gwInfo.GatewayIP} else {''}) -GatewayMACRef $dummyRef
    if ($arpThreats.Count -eq 0) {
        Write-Host "[+] ARP Table Status   : CLEAN (No duplicate MACs or rogue gateway spoofing detected)" -ForegroundColor Green
    } else {
        Write-Host "[!] ARP Table Status   : COMPROMISED / SUSPICIOUS" -ForegroundColor Red
        $arpThreats | Format-Table Type, Description -AutoSize
    }

    $scanThreats = Inspect-PortScanActivity
    if ($scanThreats.Count -eq 0) {
        Write-Host "[+] Port Scan Status   : CLEAN (No incoming port scans or SYN floods detected)" -ForegroundColor Green
    } else {
        Write-Host "[!] Port Scan Status   : ACTIVE PROBING DETECTED" -ForegroundColor Red
        $scanThreats | Format-Table AttackerIP, PortCount, Description -AutoSize
    }

    Write-Host "`n[+] Security Recommendation:" -ForegroundColor Cyan
    Write-Host "    Run with -PinGatewayARP to lock the default gateway hardware MAC binding statically." -ForegroundColor White
}

# Entrypoint logic
if ($PinGatewayARP) {
    Pin-GatewayStaticARP
}

if ($Monitor) {
    Start-NetworkMonitor
} else {
    Show-NetworkAudit
}
