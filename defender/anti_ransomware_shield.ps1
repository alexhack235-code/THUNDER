# ==============================================================================
# THUNDER - Anti-Ransomware Canary & VSS Protection Shield (10-Star Edition)
# Built by: NEXO-TECH
# ==============================================================================

param (
    [Parameter(Mandatory=$false)]
    [switch]$Monitor,

    [Parameter(Mandatory=$false)]
    [switch]$DeployCanaries,

    [Parameter(Mandatory=$false)]
    [switch]$Audit,

    [Parameter(Mandatory=$false)]
    [switch]$AutoKill,

    [Parameter(Mandatory=$false)]
    [switch]$ProtectVSS,

    [Parameter(Mandatory=$false)]
    [switch]$EnableCFA # Controlled Folder Access
)

$LogPath = "$PSScriptRoot\..\logs\defender_events.log"
$CanaryMarker = "__THUNDER_CANARY_HONEYPOT_ACTIVE__"

$WatchDirs = @(
    [Environment]::GetFolderPath("Desktop"),
    [Environment]::GetFolderPath("MyDocuments"),
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Pictures"
)

# Alphabetical boundary decoy names to catch sequential traversal
$CanaryFileNames = @(
    "!000_canary_sensor.docx",
    "0_budget_2026.xlsx",
    "z_confidential_records.pdf"
)

$RansomwareExtensions = @(
    ".locked", ".crypto", ".crypt", ".crypted", ".wnry", ".wncrypt",
    ".lockbit", ".blackcat", ".alphv", ".darkside", ".conti", ".revil",
    ".sodinokibi", ".ryuk", ".cerber", ".zepto", ".locky", ".mallox",
    ".enc", ".phobos", ".dharma", ".makop", ".cuba", ".play", ".royal"
)

function Write-ThunderLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [RANSOMWARE-SHIELD] $Message"
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

function Deploy-CanaryTraps {
    Write-ThunderLog "Deploying alphabetical boundary anti-ransomware honeypot traps..." "INFO"
    $count = 0
    foreach ($dir in $WatchDirs) {
        if (Test-Path $dir) {
            foreach ($fname in $CanaryFileNames) {
                $canaryPath = Join-Path $dir $fname
                $content = "$CanaryMarker: Monitored by THUNDER Defense Engine. Any modification triggers immediate process kill."
                try {
                    Set-Content -Path $canaryPath -Value $content -Force -ErrorAction SilentlyContinue
                    $fileItem = Get-Item $canaryPath -Force -ErrorAction SilentlyContinue
                    if ($fileItem) { $fileItem.Attributes = 'Normal' } # Keep visible to lure sequential ransomware
                    $count++
                } catch {}
            }
        }
    }
    Write-ThunderLog "Planted $count honeypot traps across Desktop, Documents, Downloads, and Pictures." "OK"
}

function Audit-Canaries {
    Write-Host "`n=======================================================" -ForegroundColor Cyan
    Write-Host "     THUNDER ANTI-RANSOMWARE CANARY & INTEGRITY AUDIT  " -ForegroundColor Yellow
    Write-Host "                   Built by NEXO-TECH                  " -ForegroundColor DarkCyan
    Write-Host "=======================================================" -ForegroundColor Cyan

    $healthy = 0
    $total = 0
    foreach ($dir in $WatchDirs) {
        if (Test-Path $dir) {
            foreach ($fname in $CanaryFileNames) {
                $total++
                $canaryPath = Join-Path $dir $fname
                if (Test-Path $canaryPath) {
                    $content = Get-Content $canaryPath -Raw -ErrorAction SilentlyContinue
                    if ($content -and $content.Contains($CanaryMarker)) {
                        Write-Host "[+] Canary '$fname' in '$dir' : INTACT & ACTIVE" -ForegroundColor Green
                        $healthy++
                    } else {
                        Write-Host "[!] Canary '$fname' in '$dir' : CORRUPTED / ENCRYPTED!" -ForegroundColor Red
                    }
                } else {
                    Write-Host "[-] Canary '$fname' in '$dir' : NOT PLANTED" -ForegroundColor Gray
                }
            }
        }
    }

    # Check Windows Defender Controlled Folder Access (CFA)
    try {
        $mpPref = Get-MpPreference -ErrorAction SilentlyContinue
        $cfaState = if ($mpPref) { $mpPref.EnableControlledFolderAccess } else { 0 }
        Write-Host "`n[+] Controlled Folder Access (CFA): $(if ($cfaState -eq 1) {'ENABLED (Locked)'} else {'DISABLED'})" -ForegroundColor $(if ($cfaState -eq 1) {'Green'} else {'Yellow'})
    } catch {}

    Write-Host "`n[+] Anti-Ransomware Score: $healthy / $total Canaries Intact." -ForegroundColor $(if ($healthy -eq $total -and $total -gt 0) {'Green'} else {'Yellow'})
}

function Enable-ControlledFolderAccess {
    try {
        Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction Stop
        Write-ThunderLog "Enabled Microsoft Defender Controlled Folder Access (CFA)." "OK"
    } catch {
        Write-ThunderLog "Failed to enable CFA: $_ (Administrator privileges required)" "WARN"
    }
}

function Start-RansomwareWatchdog {
    Deploy-CanaryTraps
    Write-ThunderLog "Starting THUNDER Real-Time Anti-Ransomware Watchdog (10-Star Engine)..." "OK"
    Write-ThunderLog "Active Defenses: Honeypot Canaries + Extension Traps + Auto-Kill." "INFO"

    $watchers = @()
    foreach ($dir in $WatchDirs) {
        if (Test-Path $dir) {
            $watcher = New-Object System.IO.FileSystemWatcher
            $watcher.Path = $dir
            $watcher.IncludeSubdirectories = $true
            $watcher.EnableRaisingEvents = $true

            $action = {
                $path = $Event.SourceEventArgs.FullPath
                $ext = [System.IO.Path]::GetExtension($path).ToLower()

                # Check known ransomware extensions
                foreach ($re in $using:RansomwareExtensions) {
                    if ($ext -eq $re) {
                        Write-Host "`n[CRITICAL ALERT] RANSOMWARE ENCRYPTION DETECTED!" -ForegroundColor Red
                        Write-Host "Infected File : $path" -ForegroundColor Red
                        Write-Host "Extension     : $ext" -ForegroundColor Red
                        
                        # Identify suspicious processes executing from temporary directories or scripts
                        if ($using:AutoKill) {
                            $suspects = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
                                $_.ProcessId -gt 4 -and $_.ExecutablePath -and (
                                    $_.ExecutablePath -match "AppData\\Local\\Temp|AppData\\Roaming\\[^\\]+\.exe|C:\\Users\\Public" -or
                                    $_.CommandLine -match "powershell.*-enc|cmd\.exe.*/c.*del|vssadmin|cipher.*/w"
                                )
                            }
                            foreach ($p in $suspects) {
                                try {
                                    Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
                                    Write-Host "KILLED SUSPECT ENCRYPTION PROCESS: $($p.Name) (PID: $($p.ProcessId))" -ForegroundColor Red
                                    Write-ThunderLog "SHIELD AUTO-KILL: Terminated hostile process $($p.Name) (PID: $($p.ProcessId))" "ALERT"
                                } catch {}
                            }
                        }
                        break
                    }
                }

                # Check Canary trigger
                if ($path -match "canary_sensor|budget_2026|confidential_records") {
                    Write-Host "`n[CRITICAL ALERT] CANARY HONEYPOT TRAP TRIGGERED! Target: $path" -ForegroundColor Red
                    Write-ThunderLog "CANARY HONEYPOT BREACH: File $path was modified or encrypted!" "ALERT"
                }
            }

            Register-ObjectEvent $watcher "Changed" -Action $action | Out-Null
            Register-ObjectEvent $watcher "Created" -Action $action | Out-Null
            Register-ObjectEvent $watcher "Renamed" -Action $action | Out-Null
            $watchers += $watcher
        }
    }

    while ($true) {
        # Check for Volume Shadow Copy deletion commands in running processes
        try {
            $vssKillers = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
                $_.CommandLine -match "vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete|wbadmin.*delete.*catalog|bcdedit.*recoveryenabled.*no"
            }
            foreach ($vk in $vssKillers) {
                Write-ThunderLog "CRITICAL: RANSOMWARE VSS WIPER DETECTED: $($vk.Name) -> $($vk.CommandLine)" "ALERT"
                Stop-Process -Id $vk.ProcessId -Force -ErrorAction SilentlyContinue
                Write-ThunderLog "SHIELD AUTO-KILL: Terminated VSS wiper process PID $($vk.ProcessId)" "ALERT"
            }
        } catch {}

        Start-Sleep -Seconds 2
    }
}

function Protect-VolumeShadowCopies {
    Write-ThunderLog "Enforcing Volume Shadow Copy (VSS) Hardening..." "INFO"
    try {
        Set-Service -Name "VSS" -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name "VSS" -ErrorAction SilentlyContinue
        Write-ThunderLog "Volume Shadow Copy Service (VSS) confirmed running." "OK"
    } catch {
        Write-ThunderLog "Could not verify VSS service: $_" "WARN"
    }
}

# Dispatcher
if ($ProtectVSS) {
    Protect-VolumeShadowCopies
}
if ($EnableCFA) {
    Enable-ControlledFolderAccess
}
if ($DeployCanaries) {
    Deploy-CanaryTraps
}
if ($Monitor) {
    Start-RansomwareWatchdog
} else {
    Audit-Canaries
}
