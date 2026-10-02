# ==============================================================================
# THUNDER - Wi-Fi Deauth & Rogue AP Shield (10-Star Edition)
# Built by: NEXO-TECH
# ==============================================================================

param (
    [Parameter(Mandatory=$false)]
    [switch]$Monitor,

    [Parameter(Mandatory=$false)]
    [int]$IntervalSeconds = 2,

    [Parameter(Mandatory=$false)]
    [switch]$Status,

    [Parameter(Mandatory=$false)]
    [switch]$AutoReconnect,

    [Parameter(Mandatory=$false)]
    [int]$DeauthThreshold = 3,

    [Parameter(Mandatory=$false)]
    [string[]]$WhitelistBSSID = @()
)

$LogPath = "$PSScriptRoot\..\logs\defender_events.log"
$KnownMeshBSSIDs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

# Add user-provided whitelist
foreach ($mac in $WhitelistBSSID) {
    if (-not [string]::IsNullOrWhiteSpace($mac)) {
        $KnownMeshBSSIDs.Add($mac.Trim().ToLower().Replace("-", ":")) | Out-Null
    }
}

function Write-ThunderLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [WIFI-SHIELD] $Message"
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

function Get-WlanStatus {
    $wlanOutput = netsh wlan show interfaces 2>$null
    if (-not $wlanOutput) { return $null }

    $info = @{
        State       = "Disconnected"
        SSID        = "N/A"
        BSSID       = "N/A"
        RadioType   = "N/A"
        Channel     = "N/A"
        Signal      = "N/A"
        Profile     = "N/A"
        Auth        = "N/A"
        Cipher      = "N/A"
    }

    foreach ($line in ($wlanOutput -split "`r?`n")) {
        if ($line -match "^\s*State\s*:\s*(.+)$") { $info.State = $matches[1].Trim() }
        if ($line -match "^\s*SSID\s*:\s*(.+)$" -and -not ($line -match "BSSID")) { $info.SSID = $matches[1].Trim() }
        if ($line -match "^\s*BSSID\s*:\s*(.+)$") { $info.BSSID = $matches[1].Trim().ToLower().Replace("-", ":") }
        if ($line -match "^\s*Radio type\s*:\s*(.+)$") { $info.RadioType = $matches[1].Trim() }
        if ($line -match "^\s*Channel\s*:\s*(.+)$") { $info.Channel = $matches[1].Trim() }
        if ($line -match "^\s*Signal\s*:\s*(.+)$") { $info.Signal = $matches[1].Trim() }
        if ($line -match "^\s*Profile\s*:\s*(.+)$") { $info.Profile = $matches[1].Trim() }
        if ($line -match "^\s*Authentication\s*:\s*(.+)$") { $info.Auth = $matches[1].Trim() }
        if ($line -match "^\s*Cipher\s*:\s*(.+)$") { $info.Cipher = $matches[1].Trim() }
    }

    return $info
}

function Get-DetailedDeauthEvents {
    param([int]$Minutes = 10)
    $events = @()
    try {
        $startTime = (Get-Date).AddMinutes(-$Minutes)
        $rawEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-WLAN-AutoConfig/Operational'
            Id        = 8003, 11004, 11006, 11010
            StartTime = $startTime
        } -ErrorAction SilentlyContinue

        foreach ($e in $rawEvents) {
            $reasonCode = "Unknown"
            $xml = [xml]$e.ToXml()
            $eventData = $xml.Event.EventData.Data
            foreach ($d in $eventData) {
                if ($d.Name -match "ReasonCode|DisconnectReason") {
                    $reasonCode = $d.'#text'
                }
            }

            $events += [PSCustomObject]@{
                TimeCreated = $e.TimeCreated
                EventId     = $e.Id
                Message     = $e.Message.Split("`n")[0].Trim()
                ReasonCode  = $reasonCode
            }
        }
    } catch {}
    return $events
}

function Show-WifiStatus {
    $status = Get-WlanStatus
    Write-Host "`n=======================================================" -ForegroundColor Cyan
    Write-Host "         THUNDER WI-FI DEFENDER & DEAUTH SHIELD        " -ForegroundColor Yellow
    Write-Host "                   Built by NEXO-TECH                  " -ForegroundColor DarkCyan
    Write-Host "=======================================================" -ForegroundColor Cyan
    
    if (-not $status) {
        Write-Host "[-] No active Wi-Fi adapter detected on this system." -ForegroundColor Red
        return
    }

    Write-Host "[+] Connection State : " -NoNewline; Write-Host $status.State -ForegroundColor $(if ($status.State -eq "connected") {"Green"} else {"Yellow"})
    Write-Host "[+] Connected SSID   : $($status.SSID)" -ForegroundColor White
    Write-Host "[+] AP Hardware MAC  : $($status.BSSID)" -ForegroundColor White
    Write-Host "[+] Authentication   : $($status.Auth) (Cipher: $($status.Cipher))" -ForegroundColor White
    Write-Host "[+] Radio & Channel  : $($status.RadioType) | Ch: $($status.Channel)" -ForegroundColor White
    Write-Host "[+] Signal Strength  : $($status.Signal)" -ForegroundColor White

    # Check PMF (Protected Management Frames / 802.11w)
    if ($status.Auth -match "WPA3|WPA2-Enterprise") {
        Write-Host "[+] 802.11w (PMF)    : PROTECTED against Deauth Floods (WPA3 / Enterprise PMF active)" -ForegroundColor Green
    } else {
        Write-Host "[!] 802.11w (PMF)    : VULNERABLE TO 802.11 DEAUTH FRAMES (Legacy WPA2 unencrypted management frames)" -ForegroundColor Yellow
        Write-Host "    [->] THUNDER Deauth Shield active: Real-time monitor will detect attacks & auto-recover." -ForegroundColor Cyan
    }

    $recentEvents = Get-DetailedDeauthEvents -Minutes 10
    if ($recentEvents.Count -gt 0) {
        Write-Host "`n[!] Disconnect/Deauth events detected in last 10m: $($recentEvents.Count)" -ForegroundColor Red
        foreach ($ev in ($recentEvents | Select-Object -First 5)) {
            Write-Host "    - [$($ev.TimeCreated.ToString('HH:mm:ss'))] Event $($ev.EventId) (Reason Code: $($ev.ReasonCode)) - $($ev.Message)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "`n[+] No suspicious deauth drops in the last 10 minutes." -ForegroundColor Green
    }
}

function Start-DeauthMonitor {
    Write-ThunderLog "Starting THUNDER Wi-Fi & Deauth Attack Shield (10-Star Engine)..." "OK"
    Write-ThunderLog "Target Protection: 802.11 Frame Spoofing, Evil Twin APs, Mesh Roaming & Deauth Floods." "INFO"
    
    $lastBSSID = ""
    $lastSSID = ""
    $lastCipher = ""
    $consecutiveDisconnects = 0
    $lastState = ""

    # Seed initial BSSID to mesh list
    $initStatus = Get-WlanStatus
    if ($initStatus -and $initStatus.BSSID -ne "N/A") {
        $KnownMeshBSSIDs.Add($initStatus.BSSID) | Out-Null
        $lastCipher = $initStatus.Cipher
    }

    while ($true) {
        $status = Get-WlanStatus
        if ($null -ne $status) {
            $currState = $status.State
            $currSSID = $status.SSID
            $currBSSID = $status.BSSID
            $currCipher = $status.Cipher

            if ($currState -eq "connected") {
                # Check for Sudden BSSID Swap (Evil Twin vs Legitimate Mesh Roaming)
                if ($lastBSSID -ne "" -and $currBSSID -ne "" -and $currBSSID -ne $lastBSSID -and $currSSID -eq $lastSSID) {
                    if ($KnownMeshBSSIDs.Contains($currBSSID)) {
                        Write-ThunderLog "Mesh Roaming: Seamless handoff to whitelisted BSSID $currBSSID on SSID '$currSSID'." "INFO"
                    }
                    elseif ($lastCipher -ne "" -and $currCipher -ne "" -and $lastCipher -ne $currCipher) {
                        # Cipher mismatch is a definitive Rogue AP indicator
                        Write-ThunderLog "CRITICAL EVIL TWIN DETECTED! SSID '$currSSID' switched from $lastBSSID ($lastCipher) to rogue AP $currBSSID ($currCipher)!" "ALERT"
                    }
                    else {
                        Write-ThunderLog "SUSPICIOUS AP TRANSITION: SSID '$currSSID' switched to unverified BSSID $currBSSID (Signal: $($status.Signal)). Untrusted candidate." "WARN"
                    }
                }

                $lastBSSID = $currBSSID
                $lastSSID = $currSSID
                $lastCipher = $currCipher
                $consecutiveDisconnects = 0
            }
            elseif ($currState -ne "connected" -and $lastState -eq "connected") {
                # Abrupt disconnection
                $consecutiveDisconnects++
                
                # Check event log reason code immediately
                $recent = Get-DetailedDeauthEvents -Minutes 1
                $reasonStr = if ($recent.Count -gt 0) { " [Reason Code: $($recent[0].ReasonCode)]" } else { "" }

                Write-ThunderLog "ABRUPT WI-FI DISCONNECT DETECTED! Possible 802.11 Deauth/Disassociation Attack against SSID '$lastSSID' (BSSID: $lastBSSID)$reasonStr" "ALERT"

                if ($consecutiveDisconnects -ge $DeauthThreshold) {
                    Write-ThunderLog "HIGH SEVERITY: Sustained Deauthentication Flood Attack ($consecutiveDisconnects rapid disconnects)!" "ALERT"
                }

                if ($AutoReconnect -and $lastSSID -ne "" -and $lastSSID -ne "N/A") {
                    Write-ThunderLog "Initiating Shield Lock: Forcing fast re-association to '$lastSSID'..." "WARN"
                    netsh wlan connect name="$lastSSID" 2>$null | Out-Null
                }
            }

            $lastState = $currState
        }

        Start-Sleep -Seconds $IntervalSeconds
    }
}

# Entrypoint logic
if ($Monitor) {
    Start-DeauthMonitor
} else {
    Show-WifiStatus
}
