# ==============================================================================
# THUNDER - Dynamic IP Rotator & 100+ Endpoint Pool Switcher
# Built by: NEXO-TECH
# ==============================================================================

param (
    [Parameter(Mandatory=$false)]
    [switch]$CheckIP,

    [Parameter(Mandatory=$false)]
    [switch]$RotateMAC,

    [Parameter(Mandatory=$false)]
    [switch]$RenewDHCP,

    [Parameter(Mandatory=$false)]
    [switch]$AutoRotate,

    [Parameter(Mandatory=$false)]
    [int]$IntervalMinutes = 5,

    [Parameter(Mandatory=$false)]
    [string]$AdapterName = "",

    [Parameter(Mandatory=$false)]
    [switch]$BenchmarkPool
)

$ScriptDir = $PSScriptRoot
$PoolFile = "$ScriptDir\api_pool.json"
$LogPath = "$ScriptDir\..\logs\ip_rotations.log"

function Write-ThunderLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [IP-ROTATOR] $Message"
    if (!(Test-Path "$ScriptDir\..\logs")) {
        New-Item -ItemType Directory -Path "$ScriptDir\..\logs" -Force | Out-Null
    }
    Add-Content -Path $LogPath -Value $logEntry -Encoding UTF8
    
    switch ($Level) {
        "ALERT" { Write-Host $logEntry -ForegroundColor Red }
        "WARN"  { Write-Host $logEntry -ForegroundColor Yellow }
        "INFO"  { Write-Host $logEntry -ForegroundColor Cyan }
        "OK"    { Write-Host $logEntry -ForegroundColor Green }
    }
}

function Get-RandomMAC {
    # Generate valid locally administered unicast MAC (2nd char must be 2, 6, A, or E)
    $secondHex = @('2', '6', 'A', 'E')[(Get-Random -Maximum 4)]
    $firstByte = "0$secondHex"
    $rest = (1..5 | ForEach-Object { "{0:X2}" -f (Get-Random -Maximum 256) }) -join ""
    return "$firstByte$rest"
}

function Get-CurrentExternalIP {
    if (-not (Test-Path $PoolFile)) {
        Write-Host "[-] API pool file not found at $PoolFile" -ForegroundColor Red
        return $null
    }

    $endpoints = Get-Content $PoolFile | ConvertFrom-Json
    # Shuffle endpoints for high entropy randomization
    $shuffled = $endpoints | Sort-Object { Get-Random }

    foreach ($ep in $shuffled) {
        try {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $wc = New-Object System.Net.WebClient
            $wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 THUNDER-Rotator/1.0")
            $resp = $wc.DownloadString($ep.url)
            $sw.Stop()

            $ip = $null
            if ($ep.type -eq "text") {
                if ($resp -match "([0-9a-fA-F:\.]+)") { $ip = $matches[1].Trim() }
            } elseif ($ep.type -eq "json" -and $ep.key) {
                $j = $resp | ConvertFrom-Json
                $ip = $j.($ep.key)
            } elseif ($ep.type -eq "trace") {
                if ($resp -match "ip=([0-9a-fA-F:\.]+)") { $ip = $matches[1] }
            } elseif ($ep.type -eq "regex" -and $ep.regex) {
                if ($resp -match $ep.regex) { $ip = $matches[1] }
            }

            $ipParsed = $null
            if ($ip -and [System.Net.IPAddress]::TryParse($ip.Trim(), [ref]$ipParsed)) {
                return [PSCustomObject]@{
                    IP = $ipParsed.ToString()
                    EndpointName = $ep.name
                    Url = $ep.url
                    LatencyMs = $sw.ElapsedMilliseconds
                }
            }
        } catch {
            # Silent fallback to next endpoint in the 100+ pool
            continue
        }
    }

    return $null
}

function Rotate-AdapterMAC {
    param([string]$TargetAdapter)

    # Find active adapter
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    if (-not $adapters) {
        Write-ThunderLog "No active network adapter found to rotate MAC." "WARN"
        return
    }

    $adapter = if ($TargetAdapter) { $adapters | Where-Object { $_.Name -like "*$TargetAdapter*" } | Select-Object -First 1 } else { $adapters[0] }
    if (-not $adapter) {
        Write-ThunderLog "Could not locate adapter '$TargetAdapter'." "WARN"
        return
    }

    $newMAC = Get-RandomMAC
    $formattedMAC = ($newMAC -split '(?<=\G.{2})(?!$)' ) -join "-"
    Write-ThunderLog "Selected Adapter: $($adapter.Name) ($($adapter.InterfaceDescription))" "INFO"
    Write-ThunderLog "Generating new randomized MAC: $formattedMAC" "OK"

    try {
        # Modify NetworkAddress property
        Set-NetAdapter -Name $adapter.Name -MacAddress $newMAC -Confirm:$false -ErrorAction Stop
        Write-ThunderLog "Successfully updated hardware MAC address on $($adapter.Name) to $formattedMAC" "OK"

        # Restart adapter to apply
        Write-ThunderLog "Cycling adapter state to apply new hardware profile..." "INFO"
        Restart-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
    }
    catch {
        Write-ThunderLog "Direct MAC change failed or requires Administrator privileges: $_" "WARN"
    }

    # Release and Renew DHCP
    Renew-DhcpLease -AdapterName $adapter.Name
}

function Renew-DhcpLease {
    param([string]$AdapterName = "")
    Write-ThunderLog "Renewing DHCP Lease & clearing DNS resolver cache..." "INFO"
    try {
        Clear-DnsClientCache
        if ($AdapterName) {
            ipconfig /release "$AdapterName" 2>$null | Out-Null
            Start-Sleep -Seconds 2
            ipconfig /renew "$AdapterName" 2>$null | Out-Null
        } else {
            ipconfig /release 2>$null | Out-Null
            Start-Sleep -Seconds 2
            ipconfig /renew 2>$null | Out-Null
        }
        Write-ThunderLog "DHCP lease renewed successfully." "OK"
    } catch {
        Write-ThunderLog "Failed to renew DHCP: $_" "WARN"
    }
}

function Show-IPStatus {
    Write-Host "`n================================================================" -ForegroundColor Cyan
    Write-Host "          ⚡ THUNDER RANDOM IP ROTATOR (NEXO-TECH) ⚡          " -ForegroundColor Yellow
    Write-Host "================================================================" -ForegroundColor Cyan

    Write-Host "[+] Querying 100+ Endpoint Pool for external IP validation..." -ForegroundColor White
    $info = Get-CurrentExternalIP
    if ($info) {
        Write-Host "[+] Current External IP : " -NoNewline
        Write-Host $info.IP -ForegroundColor Green -NoNewline
        Write-Host " (Verified via $($info.EndpointName) in $($info.LatencyMs)ms)" -ForegroundColor DarkGray
        Write-Host "[+] Endpoint URL        : $($info.Url)" -ForegroundColor DarkCyan
    } else {
        Write-Host "[-] Unable to contact external IP pool. Check internet connectivity." -ForegroundColor Red
    }

    # Local Adapters
    Write-Host "`n[+] Local Network Interfaces:" -ForegroundColor White
    Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Format-Table Name, InterfaceDescription, MacAddress, Status -AutoSize
}

function Start-AutoRotationLoop {
    Write-ThunderLog "Starting THUNDER Auto-IP Rotation Loop (Interval: $IntervalMinutes minutes)..." "OK"
    while ($true) {
        Write-ThunderLog "Triggering scheduled IP & Hardware Rotation Cycle..." "INFO"
        Rotate-AdapterMAC -TargetAdapter $AdapterName
        
        $newIP = Get-CurrentExternalIP
        if ($newIP) {
            Write-ThunderLog "New Active Public IP: $($newIP.IP) (via $($newIP.EndpointName))" "OK"
        }

        Start-Sleep -Seconds ($IntervalMinutes * 60)
    }
}

# Entrypoint logic
if ($BenchmarkPool) {
    $nodeCmd = Get-Command node -ErrorAction SilentlyContinue
    if ($nodeCmd) {
        node "$ScriptDir\proxy_rotator.js" 35
    } else {
        Write-Host "Node.js not detected. Running PowerShell pool check..." -ForegroundColor Yellow
        $info = Get-CurrentExternalIP
        Write-Host "[+] Fast healthy endpoint found: $($info.EndpointName) -> $($info.IP)" -ForegroundColor Green
    }
}
elseif ($AutoRotate) {
    Start-AutoRotationLoop
}
elseif ($RotateMAC) {
    Rotate-AdapterMAC -TargetAdapter $AdapterName
    Show-IPStatus
}
elseif ($RenewDHCP) {
    Renew-DhcpLease -AdapterName $AdapterName
    Show-IPStatus
}
else {
    Show-IPStatus
}
