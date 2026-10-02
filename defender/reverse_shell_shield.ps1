# ==============================================================================
# THUNDER - Anti-Reverse Shell & Host Process Shield (10-Star Edition)
# Built by: NEXO-TECH
# ==============================================================================

param (
    [Parameter(Mandatory=$false)]
    [switch]$Monitor,

    [Parameter(Mandatory=$false)]
    [switch]$AutoKill,

    [Parameter(Mandatory=$false)]
    [switch]$AutoBlockIP,

    [Parameter(Mandatory=$false)]
    [int]$IntervalSeconds = 2,

    [Parameter(Mandatory=$false)]
    [switch]$Audit
)

$LogPath = "$PSScriptRoot\..\logs\defender_events.log"
$FirewallScript = "$PSScriptRoot\firewall_manager.ps1"

# Comprehensive LOLBins & Interpreter Catalog
$MonitoredShellNames = @(
    "cmd.exe", "powershell.exe", "pwsh.exe", "bash.exe", "wsl.exe", "sh.exe", "zsh.exe",
    "nc.exe", "ncat.exe", "netcat.exe", "socat.exe", "mshta.exe", "cscript.exe",
    "wscript.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
    "msbuild.exe", "installutil.exe", "msiexec.exe", "regasm.exe", "csc.exe",
    "python.exe", "pythonw.exe", "node.exe", "curl.exe", "wget.exe"
)

# Suspicious Parent Processes that should NEVER spawn interactive shells
$SuspiciousParents = @(
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe",
    "acrobt32.exe", "acrobat.exe", "acrord32.exe", "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
    "w3wp.exe", "httpd.exe", "nginx.exe", "sqlservr.exe", "mysqld.exe", "postgres.exe",
    "tomcat.exe", "java.exe", "wmiprvse.exe", "spoolsv.exe"
)

# High-Risk Command-Line Indicators
$SuspiciousCmdPatterns = @(
    "-enc", "-encodedcommand", "downloadstring", "downloadfile", "iex", "invoke-expression",
    "system.net.sockets.tcpclient", "system.net.webclient", "new-object", "frombase64string",
    "amsiutils", "bypass", "-w hidden", "-windowstyle hidden", "-nop", "-noprofile",
    "http://", "https://", "certutil -urlcache", "bitsadmin /transfer"
)

function Write-ThunderLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [REVERSE-SHELL] $Message"
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

function Get-ProcessMetadata {
    param([int]$ProcessId)
    try {
        $proc = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction SilentlyContinue
        if ($proc) {
            $parentName = "Unknown"
            if ($proc.ParentProcessId) {
                $parent = Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.ParentProcessId)" -ErrorAction SilentlyContinue
                if ($parent) { $parentName = $parent.Name }
            }

            return @{
                CommandLine = if ($proc.CommandLine) { $proc.CommandLine } else { "" }
                ExecutablePath = if ($proc.ExecutablePath) { $proc.ExecutablePath } else { "" }
                ParentPID   = $proc.ParentProcessId
                ParentName  = $parentName
            }
        }
    } catch {}
    return $null
}

function Is-PrivateOrLoopbackIP {
    param([string]$IPStr)
    if ($IPStr -in @("127.0.0.1", "0.0.0.0", "::1", "localhost", "255.255.255.255")) { return $true }
    if ($IPStr -like "10.*" -or $IPStr -like "192.168.*") { return $true }
    if ($IPStr -match "^172\.(1[6-9]|2[0-9]|3[0-1])\.") { return $true }
    return $false
}

function Inspect-OutboundConnections {
    $connections = Get-NetTCPConnection -State Established, SynSent -ErrorAction SilentlyContinue
    $threats = @()

    foreach ($conn in $connections) {
        $remoteIP = $conn.RemoteAddress
        $remotePort = $conn.RemotePort
        $owningPid = $conn.OwningProcess

        if ($owningPid -le 4) { continue } # System Idle / System

        $proc = Get-Process -Id $owningPid -ErrorAction SilentlyContinue
        if (-not $proc) { continue }
        $procName = $proc.ProcessName.ToLower() + ".exe"

        # Check if process matches monitored shell / LOLBin
        $isShell = $false
        foreach ($target in $MonitoredShellNames) {
            if ($procName -eq $target.ToLower()) {
                $isShell = $true
                break
            }
        }

        # Query full process metadata (Parent & Full CommandLine)
        $meta = Get-ProcessMetadata -ProcessId $owningPid
        $parentName = if ($meta) { $meta.ParentName.ToLower() } else { "unknown" }
        $cmdLine = if ($meta) { $meta.CommandLine } else { "" }
        $exePath = if ($meta) { $meta.ExecutablePath } else { try { $proc.Path } catch { "" } }

        $isSuspiciousParent = $false
        foreach ($susp in $SuspiciousParents) {
            if ($parentName -eq $susp.ToLower()) {
                $isSuspiciousParent = $true
                break
            }
        }

        # Check CommandLine for high-risk flags
        $hasSuspiciousCmd = $false
        $matchedCmdFlag = ""
        if (-not [string]::IsNullOrWhiteSpace($cmdLine)) {
            $cmdLower = $cmdLine.ToLower()
            foreach ($pat in $SuspiciousCmdPatterns) {
                if ($cmdLower.Contains($pat)) {
                    $hasSuspiciousCmd = $true
                    $matchedCmdFlag = $pat
                    break
                }
            }
        }

        # Dedicated raw netcat / reverse tunneling tools are inherently suspicious when connecting externally
        $isDedicatedTunnelTool = $procName -in @("nc.exe", "ncat.exe", "netcat.exe", "socat.exe")

        # Threat evaluation
        if ($isShell -or $isSuspiciousParent -or $hasSuspiciousCmd) {
            $isPrivate = Is-PrivateOrLoopbackIP -IPStr $remoteIP
            $threatLevel = "LOW"

            if ($isSuspiciousParent -and $isShell) {
                $threatLevel = "CRITICAL"
            } elseif ($hasSuspiciousCmd -and -not $isPrivate) {
                $threatLevel = "CRITICAL"
            } elseif ($isDedicatedTunnelTool -and -not $isPrivate) {
                $threatLevel = "HIGH"
            } elseif ($hasSuspiciousCmd) {
                $threatLevel = "MEDIUM"
            } else {
                # Benign developer or user connection without suspicious parent/flags
                $threatLevel = "LOW"
            }

            if ($threatLevel -in @("CRITICAL", "HIGH", "MEDIUM")) {
                $threats += [PSCustomObject]@{
                    PID              = $owningPid
                    ProcessName      = $proc.ProcessName
                    Path             = $exePath
                    CommandLine      = $cmdLine
                    ParentName       = $parentName
                    RemoteIP         = $remoteIP
                    RemotePort       = $remotePort
                    ThreatLevel      = $threatLevel
                    FlaggedIndicator = if ($hasSuspiciousCmd) { "Payload flag '$matchedCmdFlag'" } elseif ($isSuspiciousParent) { "Rogue child of $parentName" } elseif ($isDedicatedTunnelTool) { "Dedicated raw socket tunneling tool" } else { "External socket on shell" }
                }
            }
        }
    }

    return $threats
}

function Kill-ThreatProcess {
    param([int]$ProcessId, [string]$ProcessName)
    try {
        # Terminate entire process tree cleanly
        & taskkill.exe /PID $ProcessId /T /F 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Stop-Process -Id $ProcessId -Force -ErrorAction SilentlyContinue
        }
        Write-ThunderLog "SHIELD AUTO-KILL: Terminated malicious process tree $ProcessName (PID: $ProcessId)" "ALERT"
    } catch {
        Write-ThunderLog "Failed to kill process $ProcessName (PID: $ProcessId): $_" "WARN"
    }
}

function Quarantine-C2IP {
    param([string]$C2IP, [string]$Reason)
    if (Test-Path $FirewallScript) {
        & $FirewallScript -Action BlockIP -IPAddress $C2IP -Reason $Reason
    }
}

function Start-ReverseShellDefender {
    Write-ThunderLog "Starting THUNDER Anti-Reverse Shell Real-Time Defender (10-Star Engine)..." "OK"
    Write-ThunderLog "Deep Telemetry: Sockets + Process Tree + Full CommandLine + LOLBins Inspection." "INFO"
    Write-ThunderLog "Auto-Kill: $(if ($AutoKill) {'ENABLED'} else {'DISABLED'}) | Auto-Block IP: $(if ($AutoBlockIP) {'ENABLED'} else {'DISABLED'})" "INFO"

    $handledThreats = @{}
    $lastCleanup = Get-Date

    while ($true) {
        # Periodic TTL cleanup of handled threats every 10 minutes to prevent memory leaks
        if ((Get-Date) - $lastCleanup -gt (New-TimeSpan -Minutes 10)) {
            $handledThreats.Clear()
            $lastCleanup = Get-Date
        }

        $threats = Inspect-OutboundConnections
        foreach ($threat in $threats) {
            $key = "$($threat.PID)_$($threat.RemoteIP)_$($threat.RemotePort)"
            if (-not $handledThreats.ContainsKey($key)) {
                $handledThreats[$key] = Get-Date

                Write-ThunderLog "================= REVERSE SHELL THREAT DETECTED =================" "ALERT"
                Write-ThunderLog "Process       : $($threat.ProcessName) (PID: $($threat.PID))" "ALERT"
                Write-ThunderLog "Executable    : $($threat.Path)" "ALERT"
                Write-ThunderLog "Parent Process: $($threat.ParentName)" "ALERT"
                Write-ThunderLog "Command Line  : $($threat.CommandLine)" "ALERT"
                Write-ThunderLog "Destination C2: $($threat.RemoteIP):$($threat.RemotePort)" "ALERT"
                Write-ThunderLog "Trigger Reason: $($threat.FlaggedIndicator) | Severity: $($threat.ThreatLevel)" "ALERT"
                Write-ThunderLog "==================================================================" "ALERT"

                if ($AutoKill) {
                    Kill-ThreatProcess -ProcessId $threat.PID -ProcessName $threat.ProcessName
                }

                if ($AutoBlockIP -and -not (Is-PrivateOrLoopbackIP -IPStr $threat.RemoteIP)) {
                    Quarantine-C2IP -C2IP $threat.RemoteIP -Reason "Active Reverse Shell Target: $($threat.ProcessName)"
                }
            }
        }

        Start-Sleep -Seconds $IntervalSeconds
    }
}

function Show-AuditSummary {
    Write-Host "`n=======================================================" -ForegroundColor Cyan
    Write-Host "     THUNDER REVERSE SHELL & PROCESS DEFENDER AUDIT   " -ForegroundColor Yellow
    Write-Host "                   Built by NEXO-TECH                  " -ForegroundColor DarkCyan
    Write-Host "=======================================================" -ForegroundColor Cyan

    $threats = Inspect-OutboundConnections
    if ($threats.Count -eq 0) {
        Write-Host "[+] SYSTEM CLEAN: No active reverse shells, LOLBin sockets, or rogue parent-child chains." -ForegroundColor Green
    } else {
        Write-Host "[!] Found $($threats.Count) suspicious active connections!" -ForegroundColor Red
        $threats | Format-Table PID, ProcessName, ParentName, RemoteIP, RemotePort, ThreatLevel, FlaggedIndicator -AutoSize
    }
}

# Entrypoint logic
if ($Monitor) {
    Start-ReverseShellDefender
} else {
    Show-AuditSummary
}
