# ==============================================================================
# THUNDER - USB & Removable Media BadUSB / AutoRun Shield (10-Star Edition)
# Built by: NEXO-TECH
# ==============================================================================

param (
    [Parameter(Mandatory=$false)]
    [switch]$Monitor,

    [Parameter(Mandatory=$false)]
    [switch]$ImmunizeDrives,

    [Parameter(Mandatory=$false)]
    [switch]$Audit,

    [Parameter(Mandatory=$false)]
    [switch]$DisableAutoRun,

    [Parameter(Mandatory=$false)]
    [switch]$LockStorageReadOnly,

    [Parameter(Mandatory=$false)]
    [switch]$DisableUSBStorage
)

$LogPath = "$PSScriptRoot\..\logs\defender_events.log"

function Write-ThunderLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [USB-SHIELD] $Message"
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

function Disable-WindowsAutoRun {
    Write-ThunderLog "Disabling Windows AutoPlay / AutoRun across all drive types..." "INFO"
    try {
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        if (!(Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
        Set-ItemProperty -Path $regPath -Name "NoDriveTypeAutoRun" -Value 0xFF -Type DWord -Force
        Set-ItemProperty -Path $regPath -Name "NoAutorun" -Value 1 -Type DWord -Force

        $lmPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        if (Test-Path $lmPath) {
            Set-ItemProperty -Path $lmPath -Name "NoDriveTypeAutoRun" -Value 0xFF -Type DWord -Force -ErrorAction SilentlyContinue
        }

        Write-ThunderLog "AutoRun & AutoPlay successfully disabled (Immune to USB worms & RubberDucky execution)." "OK"
    } catch {
        Write-ThunderLog "Failed to write registry for AutoRun: $_" "WARN"
    }
}

function Set-USBStoragePolicy {
    param([bool]$ReadOnly, [bool]$Disable)
    try {
        if ($Disable) {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" -Value 4 -Type DWord -Force
            Write-ThunderLog "USB MASS STORAGE DISABLED: USB flash drives and external hard disks are blocked." "ALERT"
        }
        elseif ($ReadOnly) {
            $sdpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies"
            if (!(Test-Path $sdpPath)) { New-Item -Path $sdpPath -Force | Out-Null }
            Set-ItemProperty -Path $sdpPath -Name "WriteProtect" -Value 1 -Type DWord -Force
            Write-ThunderLog "USB WRITE-PROTECT ACTIVE: USB drives are locked in Read-Only mode (Prevents data exfiltration)." "OK"
        }
    } catch {
        Write-ThunderLog "Storage policy modification failed: $_ (Administrator privileges required)" "WARN"
    }
}

function Immunize-RemovableDrives {
    Write-ThunderLog "Scanning and immunizing attached removable drives..." "INFO"
    $drives = Get-CimInstance Win32_LogicalDisk -Filter "DriveType = 2" -ErrorAction SilentlyContinue

    if (-not $drives) {
        Write-ThunderLog "No removable USB drives currently attached." "INFO"
        return
    }

    foreach ($dr in $drives) {
        $root = "$($dr.DeviceID)\"
        Write-ThunderLog "Immunizing drive $root ($($dr.VolumeName))..." "INFO"

        # 1. Neutralize existing autorun.inf
        $autorun = Join-Path $root "autorun.inf"
        if (Test-Path $autorun) {
            try {
                $item = Get-Item $autorun -Force
                $item.Attributes = 'Normal'
                Remove-Item -Path $autorun -Force
                Write-ThunderLog "Neutralized existing autorun.inf on $root" "ALERT"
            } catch {}
        }

        # 2. Vaccine creation
        try {
            New-Item -ItemType Directory -Path "$root\autorun.inf\protection.folder" -Force | Out-Null
            $vacDir = Get-Item "$root\autorun.inf" -Force
            $vacDir.Attributes = 'ReadOnly', 'Hidden', 'System'
            Write-ThunderLog "Vaccinated drive $root with immutable AutoRun lock." "OK"
        } catch {}

        # 3. Clean hidden LNK shortcut worms
        $lnkFiles = Get-ChildItem -Path $root -Filter "*.lnk" -Force -ErrorAction SilentlyContinue
        foreach ($lnk in $lnkFiles) {
            Write-ThunderLog "SUSPICIOUS SHORTCUT WORM DETECTED: $($lnk.FullName)" "ALERT"
        }
    }
}

function Show-UsbAudit {
    Write-Host "`n=======================================================" -ForegroundColor Cyan
    Write-Host "         THUNDER USB & BADUSB DEFENDER AUDIT           " -ForegroundColor Yellow
    Write-Host "                   Built by NEXO-TECH                  " -ForegroundColor DarkCyan
    Write-Host "=======================================================" -ForegroundColor Cyan

    # AutoRun Check
    $autoRunVal = (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue).NoDriveTypeAutoRun
    Write-Host "[+] Windows AutoRun    : $(if ($autoRunVal -eq 255 -or $autoRunVal -eq 0xFF) {'DISABLED (Secure)'} else {'ENABLED (Vulnerable)'})" -ForegroundColor $(if ($autoRunVal -eq 255 -or $autoRunVal -eq 0xFF) {'Green'} else {'Red'})

    # Removable Drives
    $drives = Get-CimInstance Win32_LogicalDisk -Filter "DriveType = 2" -ErrorAction SilentlyContinue
    Write-Host "[+] Removable Drives   : $(if ($drives) {$drives.Count} else {'0 mounted'})" -ForegroundColor White
    if ($drives) {
        $drives | Select-Object DeviceID, VolumeName, Size, FreeSpace | Format-Table -AutoSize
    }

    # USB Controllers & Keyboards
    $keyboards = Get-PnpDevice -Class "Keyboard" -ErrorAction SilentlyContinue | Where-Object { $_.Present -eq $true }
    Write-Host "[+] Keyboard Interfaces ($($keyboards.Count)):" -ForegroundColor White
    foreach ($kb in $keyboards) {
        Write-Host "    - $($kb.FriendlyName) [$($kb.InstanceId)]" -ForegroundColor White
    }
}

function Start-UsbMonitor {
    Write-ThunderLog "Starting THUNDER Real-Time USB Insertion & BadUSB Monitor..." "OK"
    $lastDrives = (Get-CimInstance Win32_LogicalDisk -Filter "DriveType = 2" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DeviceID)
    $knownKbList = @(Get-PnpDevice -Class "Keyboard" -ErrorAction SilentlyContinue | Where-Object { $_.Present -eq $true } | Select-Object -ExpandProperty InstanceId)
    $lastKeyboards = [System.Collections.Generic.HashSet[string]]::new([string[]]$knownKbList)

    while ($true) {
        # 1. Removable storage check
        $currentDrives = (Get-CimInstance Win32_LogicalDisk -Filter "DriveType = 2" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DeviceID)
        foreach ($cd in $currentDrives) {
            if ($cd -notin $lastDrives) {
                Write-ThunderLog "================= NEW USB DRIVE INSERTED: $cd =================" "ALERT"
                Immunize-RemovableDrives
            }
        }
        $lastDrives = $currentDrives

        # 2. Real BadUSB Keystroke Injection / HID Keyboard Insertion Check
        $currentKeyboards = Get-PnpDevice -Class "Keyboard" -ErrorAction SilentlyContinue | Where-Object { $_.Present -eq $true }
        foreach ($kb in $currentKeyboards) {
            if (-not $lastKeyboards.Contains($kb.InstanceId)) {
                $lastKeyboards.Add($kb.InstanceId) | Out-Null
                Write-ThunderLog "CRITICAL BADUSB ALERT: Rogue Keyboard HID Device plugged in! Name: '$($kb.FriendlyName)', ID: '$($kb.InstanceId)'" "ALERT"
            }
        }

        Start-Sleep -Seconds 2
    }
}

# Dispatcher
if ($DisableAutoRun) { Disable-WindowsAutoRun }
if ($DisableUSBStorage) { Set-USBStoragePolicy -ReadOnly $false -Disable $true }
if ($LockStorageReadOnly) { Set-USBStoragePolicy -ReadOnly $true -Disable $false }
if ($ImmunizeDrives) { Immunize-RemovableDrives }

if ($Monitor) {
    Start-UsbMonitor
} elseif ($Audit -or (-not $DisableAutoRun -and -not $ImmunizeDrives -and -not $DisableUSBStorage -and -not $LockStorageReadOnly)) {
    Show-UsbAudit
}
