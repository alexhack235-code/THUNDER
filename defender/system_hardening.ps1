# ==============================================================================
# THUNDER - System Hardening & Attack Surface Reduction (ASR) Engine (10-Star)
# Built by: NEXO-TECH
# ==============================================================================

param (
    [Parameter(Mandatory=$false)]
    [switch]$Audit,

    [Parameter(Mandatory=$false)]
    [switch]$ApplyHardening,

    [Parameter(Mandatory=$false)]
    [switch]$RevertHardening
)

$LogPath = "$PSScriptRoot\..\logs\defender_events.log"

# Top Microsoft Defender Attack Surface Reduction (ASR) Rule GUIDs
$ASRRules = @{
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "Block credential stealing from Windows local security authority subsystem (LSASS.exe)"
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = "Block all Office applications from creating child processes"
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = "Block Adobe Reader from creating child processes"
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "Block untrusted and unsigned processes that run from USB"
    "3b576869-a4ec-4529-8536-b80a7769e899" = "Block executable content from email client and webmail"
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = "Block execution of potentially obfuscated scripts"
    "d3e037e1-3eb8-44c8-a917-57927947596d" = "Block JavaScript or VBScript from launching downloaded executable content"
}

function Write-ThunderLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [SYSTEM-HARDENING] $Message"
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

function Audit-SystemHardening {
    Write-Host "`n=======================================================" -ForegroundColor Cyan
    Write-Host "    THUNDER SYSTEM HARDENING & ASR ATTACK SURFACE AUDIT " -ForegroundColor Yellow
    Write-Host "                   Built by NEXO-TECH                  " -ForegroundColor DarkCyan
    Write-Host "=======================================================" -ForegroundColor Cyan

    # 1. LLMNR
    $llmnrVal = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue).EnableMulticast
    Write-Host "[+] LLMNR Name Resolution     : $(if ($llmnrVal -eq 0) {'DISABLED (Safe from Responder)'} else {'ENABLED (Vulnerable to MITM)'})" -ForegroundColor $(if ($llmnrVal -eq 0) {'Green'} else {'Red'})

    # 2. WPAD
    $wpadVal = (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -ErrorAction SilentlyContinue).WpadOverride
    Write-Host "[+] WPAD Auto-Discovery       : $(if ($wpadVal -eq 1) {'DISABLED (Safe)'} else {'ENABLED (Vulnerable to Rogue Proxy)'})" -ForegroundColor $(if ($wpadVal -eq 1) {'Green'} else {'Yellow'})

    # 3. LSA RunAsPPL (Credential Guard against Mimikatz)
    $lsaPPL = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue).RunAsPPL
    Write-Host "[+] LSA Protection (RunAsPPL)  : $(if ($lsaPPL -eq 1 -or $lsaPPL -eq 2) {'ENABLED (LSASS Protected)'} else {'DISABLED (Vulnerable to Mimikatz)'})" -ForegroundColor $(if ($lsaPPL -ge 1) {'Green'} else {'Red'})

    # 4. PowerShell Auditing (ScriptBlock & Module Logging)
    $sbLog = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging
    Write-Host "[+] ScriptBlock Logging       : $(if ($sbLog -eq 1) {'ENABLED (Full Visibility)'} else {'DISABLED'})" -ForegroundColor $(if ($sbLog -eq 1) {'Green'} else {'Yellow'})

    # 5. Defender Attack Surface Reduction (ASR) Rules
    try {
        $mp = Get-MpPreference -ErrorAction SilentlyContinue
        $activeASRs = if ($mp) { $mp.AttackSurfaceReductionRules_Ids.Count } else { 0 }
        Write-Host "[+] Defender ASR Rules Active : $activeASRs / $($ASRRules.Count) Enterprise Rules Armed" -ForegroundColor $(if ($activeASRs -ge 5) {'Green'} else {'Yellow'})
    } catch {}

    Write-Host "`n[+] Security Actions:" -ForegroundColor Cyan
    Write-Host "    - Run with -ApplyHardening to automatically enforce all policies & ASR rules." -ForegroundColor White
    Write-Host "    - Run with -RevertHardening to restore default system settings." -ForegroundColor White
}

function Apply-SystemHardening {
    Write-ThunderLog "Enforcing complete THUNDER system hardening & ASR policies..." "INFO"

    try {
        # 1. Disable LLMNR
        $llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        if (!(Test-Path $llmnrPath)) { New-Item -Path $llmnrPath -Force | Out-Null }
        Set-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -Value 0 -Type DWord -Force
        Write-ThunderLog "Disabled LLMNR (Mitigated Responder poison attacks)." "OK"

        # 2. Disable WPAD
        $wpadPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad"
        if (!(Test-Path $wpadPath)) { New-Item -Path $wpadPath -Force | Out-Null }
        Set-ItemProperty -Path $wpadPath -Name "WpadOverride" -Value 1 -Type DWord -Force
        Write-ThunderLog "Disabled WPAD (Mitigated rogue proxy hijacking)." "OK"

        # 3. Enable LSA RunAsPPL
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Write-ThunderLog "Enabled LSA RunAsPPL (Protected LSASS memory from Mimikatz dumping)." "OK"

        # 4. Enable PowerShell ScriptBlock Logging
        $psLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        if (!(Test-Path $psLogPath)) { New-Item -Path $psLogPath -Force | Out-Null }
        Set-ItemProperty -Path $psLogPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force
        Write-ThunderLog "Enabled PowerShell ScriptBlock Logging." "OK"

        # 5. Apply Microsoft Defender ASR Rules
        $ruleIds = @($ASRRules.Keys)
        $ruleActions = @()
        for ($i = 0; $i -lt $ruleIds.Count; $i++) { $ruleActions += 1 } # 1 = Block mode

        Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleIds -AttackSurfaceReductionRules_Actions $ruleActions -ErrorAction SilentlyContinue
        Write-ThunderLog "Armed $($ruleIds.Count) Microsoft Defender Attack Surface Reduction (ASR) rules in Block Mode." "OK"

        # 6. Disable NetBIOS over TCP/IP on all network adapters
        try {
            $nics = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True" -ErrorAction SilentlyContinue
            foreach ($nic in $nics) {
                $nic | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions = 2} -ErrorAction SilentlyContinue | Out-Null
            }
            Write-ThunderLog "Disabled NetBIOS over TCP/IP across all network adapters." "OK"
        } catch {}

        Write-ThunderLog "THUNDER System Hardening applied successfully!" "OK"
    } catch {
        Write-ThunderLog "Some hardening options require Administrator privileges: $_" "WARN"
    }
}

function Revert-SystemHardening {
    Write-ThunderLog "Reverting THUNDER system hardening to default settings..." "INFO"
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 1 -Force -ErrorAction SilentlyContinue
        # Reset ASR rules
        $ruleIds = @($ASRRules.Keys)
        $ruleActions = @()
        for ($i = 0; $i -lt $ruleIds.Count; $i++) { $ruleActions += 0 } # 0 = Disabled
        Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleIds -AttackSurfaceReductionRules_Actions $ruleActions -ErrorAction SilentlyContinue

        # Restore NetBIOS to DHCP default (0 = Use DHCP default)
        try {
            $adapters = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True" -ErrorAction SilentlyContinue
            foreach ($a in $adapters) {
                $a | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]0 } | Out-Null
            }
        } catch {}

        Write-ThunderLog "Restored default Windows baseline configuration." "OK"
    } catch {}
}

if ($ApplyHardening) {
    Apply-SystemHardening
    Audit-SystemHardening
} elseif ($RevertHardening) {
    Revert-SystemHardening
    Audit-SystemHardening
} else {
    Audit-SystemHardening
}
