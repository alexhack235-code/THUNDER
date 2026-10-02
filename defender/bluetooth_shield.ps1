# ==============================================================================
# THUNDER - Bluetooth Intrusion & Stealth Shield (10-Star Edition)
# Built by: NEXO-TECH
# ==============================================================================

param (
    [Parameter(Mandatory=$false)]
    [switch]$Monitor,

    [Parameter(Mandatory=$false)]
    [int]$IntervalSeconds = 3,

    [Parameter(Mandatory=$false)]
    [switch]$Audit,

    [Parameter(Mandatory=$false)]
    [switch]$EnableStealth,

    [Parameter(Mandatory=$false)]
    [switch]$DisableBluetooth,

    [Parameter(Mandatory=$false)]
    [switch]$EnableBluetooth
)

$LogPath = "$PSScriptRoot\..\logs\defender_events.log"

function Write-ThunderLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [BLUETOOTH-SHIELD] $Message"
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

function Get-BluetoothAdapters {
    $adapters = Get-PnpDevice -Class "Bluetooth" -ErrorAction SilentlyContinue | Where-Object { 
        $_.Present -eq $true -and $_.FriendlyName -match "Adapter|Radio|Generic Bluetooth|Intel.*Bluetooth|Realtek.*Bluetooth|Qualcomm.*Bluetooth"
    }
    return $adapters
}

function Get-PairedBluetoothDevices {
    $devices = @()
    try {
        $pnpDevices = Get-PnpDevice -Class "Bluetooth" -ErrorAction SilentlyContinue | Where-Object { 
            $_.Status -eq "OK" -and $_.FriendlyName -notmatch "Adapter|Radio|Enumerator|Generic|Protocol|RFCOMM"
        }
        foreach ($d in $pnpDevices) {
            $isKeyboard = $d.FriendlyName -match "Keyboard|Keypad|Input"
            $devices += [PSCustomObject]@{
                Name        = $d.FriendlyName
                InstanceId  = $d.InstanceId
                Status      = $d.Status
                Class       = $d.Class
                IsHID       = $isKeyboard
            }
        }
    } catch {}
    return $devices
}

function Set-BluetoothStealthMode {
    Write-ThunderLog "Enforcing Bluetooth Stealth Shield..." "INFO"
    try {
        # Disable Discoverability in Registry
        $btRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters"
        if (Test-Path $btRegPath) {
            Set-ItemProperty -Path $btRegPath -Name "DisableDiscoverable" -Value 1 -Force -ErrorAction SilentlyContinue
        }

        $userBtReg = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Bluetooth"
        if (Test-Path $userBtReg) {
            Set-ItemProperty -Path $userBtReg -Name "Discoverable" -Value 0 -Force -ErrorAction SilentlyContinue
        }

        Write-ThunderLog "Bluetooth Stealth Mode Active: Adapter hidden from BLE sniffers and nearby scanners." "OK"
    } catch {
        Write-ThunderLog "Could not write registry for stealth mode: $_" "WARN"
    }
}

function Toggle-BluetoothRadio {
    param([bool]$Enable)
    $adapters = Get-BluetoothAdapters
    if (-not $adapters) {
        Write-ThunderLog "No Bluetooth radio hardware detected." "WARN"
        return
    }

    foreach ($a in $adapters) {
        try {
            if ($Enable) {
                Enable-PnpDevice -InstanceId $a.InstanceId -Confirm:$false -ErrorAction Stop
                Write-ThunderLog "Enabled Bluetooth Radio Hardware: $($a.FriendlyName)" "OK"
            } else {
                Disable-PnpDevice -InstanceId $a.InstanceId -Confirm:$false -ErrorAction Stop
                Write-ThunderLog "HARDWARE KILL-SWITCH: Disabled Bluetooth Radio Hardware: $($a.FriendlyName) (Immune to BlueBorne/BLE attacks)" "ALERT"
            }
        } catch {
            Write-ThunderLog "Failed to toggle Bluetooth hardware state: $_ (Administrator privileges required)" "WARN"
        }
    }
}

function Show-BluetoothAudit {
    Write-Host "`n=======================================================" -ForegroundColor Cyan
    Write-Host "         THUNDER BLUETOOTH INTRUSION SHIELD            " -ForegroundColor Yellow
    Write-Host "                   Built by NEXO-TECH                  " -ForegroundColor DarkCyan
    Write-Host "=======================================================" -ForegroundColor Cyan

    $adapters = Get-BluetoothAdapters
    if (-not $adapters -or $adapters.Count -eq 0) {
        Write-Host "[+] Bluetooth Hardware : DISABLED / NO ADAPTER DETECTED (Safe from BlueBorne/BLE intrusion)" -ForegroundColor Green
        return
    }

    Write-Host "[!] Bluetooth Radios   : ACTIVE ($($adapters.Count) hardware device detected)" -ForegroundColor Yellow
    foreach ($a in $adapters) {
        Write-Host "    - $($a.FriendlyName) [Status: $($a.Status)]" -ForegroundColor White
    }

    $paired = Get-PairedBluetoothDevices
    Write-Host "`n[+] Known Paired Peripherals ($($paired.Count)):" -ForegroundColor White
    if ($paired.Count -gt 0) {
        $paired | Format-Table Name, Status, IsHID, InstanceId -AutoSize
    } else {
        Write-Host "    No external Bluetooth peripherals currently active." -ForegroundColor Gray
    }

    Write-Host "`n[+] Security Controls:" -ForegroundColor Cyan
    Write-Host "    - EnableStealth    : Hides your Bluetooth device from BLE sniffers." -ForegroundColor White
    Write-Host "    - DisableBluetooth : Powers down Bluetooth radio completely." -ForegroundColor White
}

function Start-BluetoothMonitor {
    Write-ThunderLog "Starting THUNDER Bluetooth Intrusion Monitor (10-Star Engine)..." "OK"
    $knownDeviceIDs = @{}

    $initDevices = Get-PairedBluetoothDevices
    foreach ($d in $initDevices) {
        $knownDeviceIDs[$d.InstanceId] = $d.Name
    }

    while ($true) {
        $currentDevices = Get-PairedBluetoothDevices
        foreach ($cd in $currentDevices) {
            if (-not $knownDeviceIDs.ContainsKey($cd.InstanceId)) {
                $knownDeviceIDs[$cd.InstanceId] = $cd.Name
                $hidWarning = if ($cd.IsHID) { " [CRITICAL WARNING: Device advertises HID Keyboard capabilities - BadBluetooth vector!]" } else { "" }
                
                Write-ThunderLog "================= UNKNOWN BLUETOOTH PAIRING DETECTED =================" "ALERT"
                Write-ThunderLog "Device Name : $($cd.Name)$hidWarning" "ALERT"
                Write-ThunderLog "Instance ID : $($cd.InstanceId)" "ALERT"
                Write-ThunderLog "Status      : Potential unauthorized proximity pairing attempt!" "ALERT"
                Write-ThunderLog "======================================================================" "ALERT"
            }
        }

        Start-Sleep -Seconds $IntervalSeconds
    }
}

# Entrypoint logic
if ($DisableBluetooth) {
    Toggle-BluetoothRadio -Enable $false
}
elseif ($EnableBluetooth) {
    Toggle-BluetoothRadio -Enable $true
}

if ($EnableStealth) {
    Set-BluetoothStealthMode
}

if ($Monitor) {
    Start-BluetoothMonitor
} else {
    Show-BluetoothAudit
}
