# ==============================================================================
# THUNDER - Anti-Spyware & Advanced Persistence Defender (10-Star Edition)
# Built by: NEXO-TECH
# ==============================================================================

param (
    [Parameter(Mandatory=$false)]
    [switch]$Audit,

    [Parameter(Mandatory=$false)]
    [switch]$CleanPersistence,

    [Parameter(Mandatory=$false)]
    [string]$RemoveTarget = ""
)

$LogPath = "$PSScriptRoot\..\logs\defender_events.log"

function Write-ThunderLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [SPYWARE-SHIELD] $Message"
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

function Audit-FullPersistence {
    Write-Host "`n=======================================================" -ForegroundColor Cyan
    Write-Host "   THUNDER ADVANCED PERSISTENCE & SPYWARE AUDIT        " -ForegroundColor Yellow
    Write-Host "                   Built by NEXO-TECH                  " -ForegroundColor DarkCyan
    Write-Host "=======================================================" -ForegroundColor Cyan

    $allEntries = @()

    # 1. Standard Run & RunOnce Registry Keys
    $runKeys = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    )

    foreach ($rk in $runKeys) {
        if (Test-Path $rk) {
            $props = Get-ItemProperty -Path $rk
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")) {
                    $val = "$($p.Value)"
                    $isSuspicious = $val -match "powershell.*-enc|wscript|cscript|mshta|\\temp\\|\\appdata\\local\\temp"
                    $allEntries += [PSCustomObject]@{
                        Category = "Registry Run"
                        Name     = $p.Name
                        Path     = $val
                        Location = $rk
                        Risk     = if ($isSuspicious) { "CRITICAL" } else { "NORMAL" }
                    }
                }
            }
        }
    }

    # 2. Startup Folders
    $startupPaths = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )

    foreach ($sp in $startupPaths) {
        if (Test-Path $sp) {
            $files = Get-ChildItem -Path $sp -File -Force -ErrorAction SilentlyContinue
            foreach ($f in $files) {
                $allEntries += [PSCustomObject]@{
                    Category = "Startup Folder"
                    Name     = $f.Name
                    Path     = $f.FullName
                    Location = $sp
                    Risk     = if ($f.Extension -in @(".bat", ".ps1", ".vbs", ".js", ".hta")) { "HIGH" } else { "NORMAL" }
                }
            }
        }
    }

    # 3. Winlogon Userinit & Shell Keys
    $winlogon = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    if (Test-Path $winlogon) {
        $userinit = (Get-ItemProperty -Path $winlogon -Name "Userinit" -ErrorAction SilentlyContinue).Userinit
        $shell = (Get-ItemProperty -Path $winlogon -Name "Shell" -ErrorAction SilentlyContinue).Shell

        if ($userinit -and $userinit.ToLower() -notmatch "userinit\.exe") {
            $allEntries += [PSCustomObject]@{
                Category = "Winlogon Hijack"
                Name     = "Userinit"
                Path     = $userinit
                Location = $winlogon
                Risk     = "CRITICAL"
            }
        }
        if ($shell -and $shell.ToLower() -ne "explorer.exe") {
            $allEntries += [PSCustomObject]@{
                Category = "Winlogon Hijack"
                Name     = "Shell"
                Path     = $shell
                Location = $winlogon
                Risk     = "CRITICAL"
            }
        }
    }

    # 4. WMI Event Subscriptions
    try {
        $wmiFilters = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue
        if ($wmiFilters) {
            foreach ($wf in $wmiFilters) {
                $allEntries += [PSCustomObject]@{
                    Category = "WMI Subscription"
                    Name     = $wf.Name
                    Path     = $wf.Query
                    Location = "root\subscription"
                    Risk     = "HIGH"
                }
            }
        }
    } catch {}

    # 5. PowerShell Profiles
    $profiles = @($PROFILE.AllUsersAllHosts, $PROFILE.AllUsersCurrentHost, $PROFILE.CurrentUserAllHosts, $PROFILE.CurrentUserCurrentHost)
    foreach ($pr in $profiles) {
        if ($pr -and (Test-Path $pr)) {
            $content = Get-Content $pr -Raw -ErrorAction SilentlyContinue
            $isRogue = $content -match "downloadstring|iex|invoke-expression|bypass"
            $allEntries += [PSCustomObject]@{
                Category = "PowerShell Profile"
                Name     = [System.IO.Path]::GetFileName($pr)
                Path     = $pr
                Location = "PSPROFILE"
                Risk     = if ($isRogue) { "CRITICAL" } else { "NORMAL" }
            }
        }
    }

    # Display Results
    Write-Host "[+] Total Persistence Artifacts Inspected: $($allEntries.Count)" -ForegroundColor White
    $highRisk = $allEntries | Where-Object { $_.Risk -in @("CRITICAL", "HIGH") }
    if ($highRisk) {
        Write-Host "`n[!] HIGH RISK PERSISTENCE THREATS FOUND ($($highRisk.Count)):" -ForegroundColor Red
        $highRisk | Format-Table Risk, Category, Name, Path, Location -AutoSize
    } else {
        Write-Host "[+] All persistence locations are CLEAN." -ForegroundColor Green
    }

    Write-Host "`n--- Summary Breakdown ---" -ForegroundColor Cyan
    $allEntries | Format-Table Risk, Category, Name, Path -AutoSize
    return $allEntries
}

function Clean-PersistenceItem {
    param([string]$TargetName)
    if ([string]::IsNullOrWhiteSpace($TargetName)) {
        Write-ThunderLog "No persistence target specified for removal." "WARN"
        return
    }

    $runKeys = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    )

    foreach ($rk in $runKeys) {
        if (Test-Path $rk) {
            try {
                Remove-ItemProperty -Path $rk -Name $TargetName -Force -ErrorAction SilentlyContinue
                Write-ThunderLog "Removed registry persistence value '$TargetName' from $rk" "OK"
            } catch {}
        }
    }
}

if ($CleanPersistence -and $RemoveTarget -ne "") {
    Clean-PersistenceItem -TargetName $RemoveTarget
} else {
    Audit-FullPersistence
}
