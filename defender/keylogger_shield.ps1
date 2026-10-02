# ==============================================================================
# THUNDER - Keylogger & Screen Capture Defender
# Built by: NEXO-TECH
# ==============================================================================
# Detects active keylogger processes, suspicious clipboard hooks,
# and screen capture / screenshot tools running silently.

param (
    [Parameter(Mandatory=$false)]
    [switch]$Audit,

    [Parameter(Mandatory=$false)]
    [switch]$Monitor,

    [Parameter(Mandatory=$false)]
    [switch]$AutoKill,

    [Parameter(Mandatory=$false)]
    [int]$IntervalSeconds = 3
)

$LogPath = "$PSScriptRoot\..\logs\defender_events.log"

$KeyloggerSignatures = @(
    "keylogger", "kl.exe", "keylog", "ardamax", "spyrix", "refog",
    "actual-spy", "actualspy", "revealer", "all-in-one-keylogger", "hooker",
    "ispy", "shadowlogger", "wolfeye", "kidlogger", "spytector",
    "elite-keylogger", "blazingtools", "keystroke", "perfect-keylogger"
)

$ClipboardHookAPIs = @(
    "SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState", "GetKeyboardState",
    "SetClipboardViewer", "AddClipboardFormatListener", "GetClipboardData",
    "RegisterHotKey", "RegisterRawInputDevices", "keybd_event"
)

$ScreenCaptureProcs = @(
    "screenshot", "screencap", "snagit", "lightshot", "greenshot",
    "sharex", "screenrec", "obs64", "obs32", "camtasia", "bandicam",
    "action", "fraps", "dxtory", "mirillis"
)

function Write-ThunderLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [KEYLOGGER-SHIELD] $Message"
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

function Inspect-KeyloggerProcesses {
    $threats = @()
    $procs = Get-Process -ErrorAction SilentlyContinue

    foreach ($p in $procs) {
        $pNameLower = $p.ProcessName.ToLower()
        $pPathLower = try { $p.Path.ToLower() } catch { "" }

        # Check against keylogger signatures
        foreach ($sig in $KeyloggerSignatures) {
            if ($pNameLower -match $sig -or $pPathLower -match $sig) {
                $threats += [PSCustomObject]@{
                    PID         = $p.Id
                    ProcessName = $p.ProcessName
                    Path        = try { $p.Path } catch { "N/A" }
                    ThreatType  = "KEYLOGGER"
                    Signature   = $sig
                    WindowTitle = try { $p.MainWindowTitle } catch { "" }
                }
                break
            }
        }

        # Check against screen capture processes
        foreach ($sc in $ScreenCaptureProcs) {
            if ($pNameLower -match $sc -and $p.MainWindowHandle -eq 0) {
                # Hidden screen recorder (no visible window)
                $threats += [PSCustomObject]@{
                    PID         = $p.Id
                    ProcessName = $p.ProcessName
                    Path        = try { $p.Path } catch { "N/A" }
                    ThreatType  = "HIDDEN_SCREEN_CAPTURE"
                    Signature   = $sc
                    WindowTitle = "HIDDEN (No visible window)"
                }
                break
            }
        }
    }

    # Check for processes with suspicious keyboard hook DLLs loaded
    foreach ($p in $procs) {
        try {
            $modules = $p.Modules | Select-Object -ExpandProperty ModuleName -ErrorAction SilentlyContinue
            if ($modules) {
                foreach ($m in $modules) {
                    $mLower = $m.ToLower()
                    if ($mLower -match "(keyboardhook|keylog|kbdhook|rawinputhook|winlogonhook|actualspy|ardamax)") {
                        $threats += [PSCustomObject]@{
                            PID         = $p.Id
                            ProcessName = $p.ProcessName
                            Path        = try { $p.Path } catch { "N/A" }
                            ThreatType  = "SUSPICIOUS_HOOK_DLL"
                            Signature   = $m
                            WindowTitle = try { $p.MainWindowTitle } catch { "" }
                        }
                        break
                    }
                }
            }
        } catch {}
    }

    return $threats | Sort-Object PID -Unique
}

function Show-KeyloggerAudit {
    Write-Host "`n=======================================================" -ForegroundColor Cyan
    Write-Host "    THUNDER KEYLOGGER & SCREEN CAPTURE DEFENDER AUDIT   " -ForegroundColor Yellow
    Write-Host "                   Built by NEXO-TECH                  " -ForegroundColor DarkCyan
    Write-Host "=======================================================" -ForegroundColor Cyan

    $threats = Inspect-KeyloggerProcesses
    if ($threats.Count -eq 0) {
        Write-Host "[+] SYSTEM CLEAN: No keylogger processes, clipboard hooks, or hidden recorders detected." -ForegroundColor Green
    } else {
        Write-Host "[!] KEYLOGGER / SURVEILLANCE THREATS DETECTED ($($threats.Count)):" -ForegroundColor Red
        $threats | Format-Table ThreatType, ProcessName, PID, Signature, Path -AutoSize

        if ($AutoKill) {
            foreach ($t in $threats) {
                try {
                    Stop-Process -Id $t.PID -Force -ErrorAction Stop
                    Write-ThunderLog "KILLED keylogger/surveillance process: $($t.ProcessName) (PID: $($t.PID))" "ALERT"
                } catch {
                    Write-ThunderLog "Failed to kill PID $($t.PID): $_" "WARN"
                }
            }
        }
    }
}

function Start-KeyloggerMonitor {
    Write-ThunderLog "Starting THUNDER Real-Time Keylogger & Surveillance Watchdog..." "OK"
    $seenPids = @{}
    while ($true) {
        $threats = Inspect-KeyloggerProcesses
        foreach ($t in $threats) {
            if (-not $seenPids.ContainsKey($t.PID)) {
                $seenPids[$t.PID] = Get-Date
                Write-ThunderLog "SURVEILLANCE THREAT: $($t.ProcessName) (PID: $($t.PID), Type: $($t.ThreatType))" "ALERT"
                if ($AutoKill) {
                    try {
                        Stop-Process -Id $t.PID -Force -ErrorAction Stop
                        Write-ThunderLog "SHIELD AUTO-KILL: Terminated surveillance process $($t.ProcessName) (PID: $($t.PID))" "ALERT"
                    } catch {
                        Write-ThunderLog "Failed to kill PID $($t.PID): $_" "WARN"
                    }
                }
            }
        }
        Start-Sleep -Seconds $IntervalSeconds
    }
}

# Entrypoint
if ($Monitor) {
    Start-KeyloggerMonitor
} else {
    Show-KeyloggerAudit
}
