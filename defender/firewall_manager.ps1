# ==============================================================================
# THUNDER - Dynamic Firewall & Threat Quarantine Manager (10-Star Edition)
# Built by: NEXO-TECH
# ==============================================================================

param (
    [Parameter(Mandatory=$false)]
    [ValidateSet("BlockIP", "UnblockIP", "ListBlocked", "FlushAll", "Status", "EnforceProfiles")]
    [string]$Action = "Status",

    [Parameter(Mandatory=$false)]
    [string]$IPAddress = "",

    [Parameter(Mandatory=$false)]
    [string]$Reason = "Threat quarantined by THUNDER Defender",

    [Parameter(Mandatory=$false)]
    [int]$DurationMinutes = 0 # 0 = Permanent until flushed, >0 = Auto-expiring TTL
)

$RulePrefix = "THUNDER_BLOCK_"
$LogPath = "$PSScriptRoot\..\logs\defender_events.log"

function Write-ThunderLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [FIREWALL] $Message"
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

function Get-ProtectedInfrastructureIPs {
    $protected = [System.Collections.Generic.HashSet[string]]::new()
    $protected.Add("127.0.0.1") | Out-Null
    $protected.Add("0.0.0.0") | Out-Null
    $protected.Add("::1") | Out-Null
    $protected.Add("255.255.255.255") | Out-Null

    # Protect Default Gateway
    try {
        $routes = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue
        foreach ($r in $routes) {
            if ($r.NextHop -and $r.NextHop -ne "0.0.0.0") { $protected.Add($r.NextHop) | Out-Null }
        }
    } catch {}

    # Protect Configured DNS Servers
    try {
        $dns = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue
        foreach ($d in $dns) {
            foreach ($addr in $d.ServerAddresses) { $protected.Add($addr) | Out-Null }
        }
    } catch {}

    return $protected
}

function Block-ThreatIP {
    param([string]$TargetIP, [string]$BlockReason, [int]$TTL)
    if ([string]::IsNullOrWhiteSpace($TargetIP)) {
        Write-ThunderLog "No IP or CIDR specified for blocking." "WARN"
        return
    }

    # Self-Preservation Guard: Never block gateway, loopback, or primary DNS
    $protected = Get-ProtectedInfrastructureIPs
    if ($protected.Contains($TargetIP)) {
        Write-ThunderLog "SELF-PRESERVATION GUARD: Refused to block critical infrastructure IP ($TargetIP)" "WARN"
        return
    }

    $sanitized = $TargetIP -replace "[^0-9a-zA-Z]", "_"
    $inboundRule = "${RulePrefix}IN_${sanitized}"
    $outboundRule = "${RulePrefix}OUT_${sanitized}"

    try {
        $existing = Get-NetFirewallRule -Name $inboundRule -ErrorAction SilentlyContinue
        if ($existing) {
            Write-ThunderLog "Target $TargetIP is already blocked." "INFO"
            return
        }

        $desc = "Auto-quarantined by THUNDER (NEXO-TECH). Reason: $BlockReason. Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        if ($TTL -gt 0) {
            $expiry = (Get-Date).AddMinutes($TTL).ToString("yyyy-MM-dd HH:mm:ss")
            $desc += " [TTL Expire: $expiry]"
        }

        # Inbound Block Rule
        New-NetFirewallRule -Name $inboundRule `
            -DisplayName "THUNDER Block Inbound: $TargetIP" `
            -Description $desc `
            -Direction Inbound `
            -Action Block `
            -RemoteAddress $TargetIP `
            -Enabled True -ErrorAction Stop | Out-Null

        # Outbound Block Rule
        New-NetFirewallRule -Name $outboundRule `
            -DisplayName "THUNDER Block Outbound: $TargetIP" `
            -Description $desc `
            -Direction Outbound `
            -Action Block `
            -RemoteAddress $TargetIP `
            -Enabled True -ErrorAction Stop | Out-Null

        Write-ThunderLog "QUARANTINED IP/SUBNET: $TargetIP | Reason: $BlockReason $(if ($TTL -gt 0) {"[TTL: ${TTL}m]"} else {''})" "ALERT"
    }
    catch {
        Write-ThunderLog "Failed to apply firewall rule for ${TargetIP}: $_ (Administrator privileges required)" "WARN"
    }
}

function Unblock-ThreatIP {
    param([string]$TargetIP)
    if ([string]::IsNullOrWhiteSpace($TargetIP)) { return }
    $sanitized = $TargetIP -replace "[^0-9a-zA-Z]", "_"
    $inboundRule = "${RulePrefix}IN_${sanitized}"
    $outboundRule = "${RulePrefix}OUT_${sanitized}"

    try {
        Remove-NetFirewallRule -Name $inboundRule -ErrorAction SilentlyContinue
        Remove-NetFirewallRule -Name $outboundRule -ErrorAction SilentlyContinue
        Write-ThunderLog "Unblocked IP/Subnet: $TargetIP" "OK"
    } catch {
        Write-ThunderLog "Error unblocking IP: $_" "WARN"
    }
}

function Enforce-FirewallProfiles {
    Write-ThunderLog "Enforcing Windows Defender Firewall Shield Profiles (Domain, Private, Public)..." "INFO"
    try {
        Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -ErrorAction Stop
        Write-ThunderLog "All Windows Firewall profiles armed with Default-Deny Inbound." "OK"
    } catch {
        Write-ThunderLog "Failed to configure firewall profiles: $_" "WARN"
    }
}

function List-BlockedIPs {
    try {
        # Check and cleanup expired TTL rules
        $rules = Get-NetFirewallRule -Name "${RulePrefix}*" -ErrorAction SilentlyContinue
        if ($rules) {
            $now = Get-Date
            $activeList = @()
            foreach ($r in $rules) {
                    $expireParsed = [DateTime]::MinValue
                    if ([DateTime]::TryParseExact($matches[1], "yyyy-MM-dd HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$expireParsed) -or [DateTime]::TryParse($matches[1], [ref]$expireParsed)) {
                        if ($now -gt $expireParsed) {
                            Remove-NetFirewallRule -Name $r.Name -ErrorAction SilentlyContinue
                            Write-ThunderLog "TTL Expired: Removed temporary quarantine rule $($r.DisplayName)" "INFO"
                            continue
                        }
                    }
                $activeList += $r
            }

            Write-Host "`n=== THUNDER ACTIVE FIREWALL THREAT QUARANTINES ===" -ForegroundColor Red
            if ($activeList.Count -gt 0) {
                $activeList | Select-Object DisplayName, Direction, Action, Enabled, Description | Format-Table -AutoSize
            } else {
                Write-Host "No active IP blocks currently enforced by THUNDER." -ForegroundColor Green
            }
        } else {
            Write-Host "No active IP blocks currently enforced by THUNDER." -ForegroundColor Green
        }
    } catch {
        Write-Host "Unable to read firewall rules (Requires Administrator permissions)." -ForegroundColor Yellow
    }
}

function Flush-AllRules {
    try {
        $rules = Get-NetFirewallRule -Name "${RulePrefix}*" -ErrorAction SilentlyContinue
        if ($rules) {
            $rules | Remove-NetFirewallRule -ErrorAction SilentlyContinue
            Write-ThunderLog "Flushed all active THUNDER firewall quarantine rules." "OK"
        } else {
            Write-ThunderLog "No rules to flush." "INFO"
        }
    } catch {
        Write-ThunderLog "Failed to flush rules: $_" "WARN"
    }
}

# Execution Dispatcher
switch ($Action) {
    "BlockIP"         { Block-ThreatIP -TargetIP $IPAddress -BlockReason $Reason -TTL $DurationMinutes }
    "UnblockIP"       { Unblock-ThreatIP -TargetIP $IPAddress }
    "ListBlocked"     { List-BlockedIPs }
    "FlushAll"        { Flush-AllRules }
    "EnforceProfiles" { Enforce-FirewallProfiles; List-BlockedIPs }
    "Status"          { List-BlockedIPs }
}
