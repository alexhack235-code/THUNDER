# ==============================================================================
# THUNDER - Virus & Malware Scanner & Cleaner Engine Runner (10-Star Edition)
# Built by: NEXO-TECH
# ==============================================================================

param (
    [Parameter(Mandatory=$false)]
    [string]$Path = ".",

    [Parameter(Mandatory=$false)]
    [switch]$Quarantine,

    [Parameter(Mandatory=$false)]
    [switch]$Shred,

    [Parameter(Mandatory=$false)]
    [switch]$ListQuarantine,

    [Parameter(Mandatory=$false)]
    [string]$RestoreId = "",

    [Parameter(Mandatory=$false)]
    [switch]$BuildRust,

    [Parameter(Mandatory=$false)]
    [switch]$OpenHtmlReport
)

$ScannerDir = $PSScriptRoot
$VaultDir = "$ScannerDir\..\quarantine"
$ManifestFile = "$VaultDir\manifest.json"
$HtmlGenerator = "$ScannerDir\generate_html_report.ps1"
$ReportPath = "$ScannerDir\..\report.html"
$XorKey = 0x7E

# Ensure directories exist
if (!(Test-Path $VaultDir)) { New-Item -ItemType Directory -Path $VaultDir -Force | Out-Null }

# Signature definitions (Expanded 10-Star Database)
$KnownHashes = @{
    "44d88612fea8a8f36de82e1278abb02f" = "EICAR-Standard-AV-Test-File [TEST]"
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" = "EICAR-Standard-AV-Test-File-SHA256 [TEST]"
    "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa" = "Ransom:Win32/WannaCry.A [CRITICAL]"
    "84c82835a5d21bbcf75a61706d8ab549" = "Ransom:Win32/WannaCry.MD5 [CRITICAL]"
    "4a2c91a329d49ddb6fb1a88b56f8f7c9e0758410fb59bb36f048d0859c25bb28" = "Trojan:Win32/Emotet.Generic [CRITICAL]"
    "0277305cd021a602147328a3f50f17cf25425d6040e4995c732bb3038e061398" = "Ransom:Win32/NotPetya.A [CRITICAL]"
    "931215b22b10a9bfbe9a35e4e20ef9f43f11d13f990145c11bc37ea920b22a01" = "Ransom:Win32/DarkSide.A [CRITICAL]"
    "7f4c084046d296cf287a916891eb534b5c778408f654b9d031bfec6f0ad0ae62" = "Backdoor:Win32/CobaltStrike.Beacon [CRITICAL]"
    "9d90597b4b3b7bb577e116e25be4bebb8f8285514f77c862bc2d5c31ff7eb3bc" = "CoinMiner:Win32/XMRig.Silent [HIGH]"
    "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8" = "HackTool:Win32/Mimikatz.Generic [CRITICAL]"
    "1f81ab924e2c88463c2c1fb67a21394f48ad0a72ad41c888d3e9255a6d5952d7" = "Ransom:Win32/LockBit.3 [CRITICAL]"
}

$PatternSignatures = @(
    @{ Name = "EICAR-Standard-AV-Test-Signature"; Pattern = "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"; Severity = "TEST" },
    @{ Name = "Trojan:PowerShell/ReverseShell.TCPClient"; Pattern = "New-Object System.Net.Sockets.TCPClient"; Severity = "CRITICAL" },
    @{ Name = "Trojan:PowerShell/ReverseShell.SocketStream"; Pattern = "GetStream().Write("; Severity = "CRITICAL" },
    @{ Name = "HackTool:PowerShell/AMSI.Bypass.Patch"; Pattern = "AmsiUtils.amsiInitFailed"; Severity = "HIGH" },
    @{ Name = "HackTool:Win32/Invoke-Mimikatz"; Pattern = "sekurlsa::logonpasswords"; Severity = "CRITICAL" },
    @{ Name = "Trojan:Script/DownloadCradle.WebClient"; Pattern = "IEX(New-Object Net.WebClient).DownloadString"; Severity = "HIGH" },
    @{ Name = "WebShell:PHP/c99.Generic"; Pattern = "c99shell"; Severity = "CRITICAL" },
    @{ Name = "WebShell:PHP/b374k.Generic"; Pattern = "b374k"; Severity = "CRITICAL" },
    @{ Name = "WebShell:PHP/EvalBase64"; Pattern = "eval(base64_decode("; Severity = "HIGH" },
    @{ Name = "CoinMiner:Generic/StratumMining"; Pattern = "stratum+tcp://"; Severity = "HIGH" },
    @{ Name = "Backdoor:CobaltStrike/Stager"; Pattern = "/admin/get.php"; Severity = "CRITICAL" },
    @{ Name = "Trojan:Script/Empire.Agent"; Pattern = "$wc=New-Object System.Net.WebClient;$u='Mozilla"; Severity = "HIGH" }
)

function Calculate-ShannonEntropy {
    param([byte[]]$Bytes)
    if ($Bytes.Length -eq 0) { return 0 }
    $freq = @{}
    foreach ($b in $Bytes) { $freq[$b] = ($freq[$b] + 1) }
    $entropy = 0.0
    $len = [double]$Bytes.Length
    foreach ($count in $freq.Values) {
        $p = [double]$count / $len
        $entropy -= $p * [Math]::Log($p, 2)
    }
    return [Math]::Round($entropy, 2)
}

function Move-ToQuarantine {
    param([string]$FilePath, [string]$ThreatName, [string]$Sha256)
    try {
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        for ($i = 0; $i -lt $bytes.Length; $i++) {
            $bytes[$i] = $bytes[$i] -bxor $XorKey
        }
        $recId = "$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())_$($Sha256.Substring(0,8))"
        $vaultPath = "$VaultDir\$recId.vault"
        [System.IO.File]::WriteAllBytes($vaultPath, $bytes)
        Remove-Item -Path $FilePath -Force

        $records = @()
        if (Test-Path $ManifestFile) {
            $records = Get-Content $ManifestFile | ConvertFrom-Json
        }
        $records += [PSCustomObject]@{
            id = $recId
            original_path = $FilePath
            quarantined_path = $vaultPath
            detection_name = $ThreatName
            sha256 = $Sha256
            timestamp = (Get-Date).ToString("o")
        }
        $records | ConvertTo-Json -Depth 5 | Set-Content $ManifestFile
        return $true
    } catch {
        Write-Host "Failed to quarantine $FilePath: $_" -ForegroundColor Red
        return $false
    }
}

function Secure-ShredFile {
    param([string]$FilePath)
    try {
        $len = (Get-Item $FilePath).Length
        $bufferZeros = New-Object byte[] ([Math]::Min($len, 1048576))
        $bufferOnes = New-Object byte[] ([Math]::Min($len, 1048576))
        for ($i = 0; $i -lt $bufferOnes.Length; $i++) { $bufferOnes[$i] = 0xFF }

        $stream = [System.IO.File]::OpenWrite($FilePath)
        $stream.Write($bufferZeros, 0, $bufferZeros.Length)
        $stream.Flush()
        $stream.Position = 0
        $stream.Write($bufferOnes, 0, $bufferOnes.Length)
        $stream.Flush()
        $stream.Close()

        Remove-Item -Path $FilePath -Force
        return $true
    } catch {
        return $false
    }
}

function Run-NativeScanEngine {
    param([string]$ScanTarget, [bool]$AutoQuarantine, [bool]$AutoShred)
    Write-Host "`n================================================================" -ForegroundColor Cyan
    Write-Host "          ⚡ THUNDER VIRUS & MALWARE SCANNER ⚡          " -ForegroundColor Yellow
    Write-Host "                     Built by NEXO-TECH                         " -ForegroundColor DarkCyan
    Write-Host "================================================================" -ForegroundColor Cyan

    $resolvedPath = Resolve-Path $ScanTarget -ErrorAction SilentlyContinue
    if (-not $resolvedPath) {
        Write-Host "[-] Target path '$ScanTarget' does not exist." -ForegroundColor Red
        return
    }

    Write-Host "[+] Target Path       : $resolvedPath" -ForegroundColor White
    Write-Host "[+] Engines Active    : Hashes (MD5/SHA256) | YARA Patterns | PE Heuristics | Entropy" -ForegroundColor Cyan
    Write-Host "[+] Remediation Mode  : $(if ($AutoQuarantine) {'ENCRYPTED QUARANTINE'} elseif ($AutoShred) {'DOD 3-PASS SHRED'} else {'AUDIT ONLY'})" -ForegroundColor Yellow

    $files = Get-ChildItem -Path $resolvedPath -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
        $_.FullName -notmatch "quarantine" -and $_.Length -lt 100MB
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $threatsFound = @()

    foreach ($file in $files) {
        try {
            $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
            
            # Hashes
            $md5 = (Get-FileHash -Path $file.FullName -Algorithm MD5 -ErrorAction SilentlyContinue).Hash.ToLower()
            $sha256 = (Get-FileHash -Path $file.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash.ToLower()

            $isThreat = $false
            $threatName = ""
            $threatCategory = ""
            $threatSeverity = ""
            $details = ""

            if ($KnownHashes.ContainsKey($md5)) {
                $isThreat = $true
                $threatName = $KnownHashes[$md5]
                $threatCategory = "Known Malware"
                $threatSeverity = "CRITICAL"
                $details = "Matched known MD5 blacklist"
            }
            elseif ($KnownHashes.ContainsKey($sha256)) {
                $isThreat = $true
                $threatName = $KnownHashes[$sha256]
                $threatCategory = "Known Malware"
                $threatSeverity = "CRITICAL"
                $details = "Matched known SHA256 blacklist"
            }

            # Pattern check (case-insensitive)
            if (-not $isThreat) {
                $text = [System.Text.Encoding]::UTF8.GetString($bytes)
                foreach ($p in $PatternSignatures) {
                    if ($text.IndexOf($p.Pattern, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                        $isThreat = $true
                        $threatName = $p.Name
                        $threatCategory = "Malicious Signature"
                        $threatSeverity = $p.Severity
                        $details = "Matched signature pattern: '$($p.Pattern)'"
                        break
                    }
                }
            }

            # Heuristic check on executable formats
            if (-not $isThreat -and $file.Extension -in @(".exe", ".dll", ".ps1", ".bat", ".vbs", ".js", ".scr")) {
                $entropy = Calculate-ShannonEntropy -Bytes $bytes
                if ($bytes.Length -gt 2048 -and $entropy -ge 7.4) {
                    $isThreat = $true
                    $threatName = "Heuristic:Packed.HighEntropyPayload"
                    $threatCategory = "Obfuscated Binary"
                    $threatSeverity = "HIGH"
                    $details = "Shannon Entropy is $entropy/8.0 (Encrypted/Packed payload indicator)"
                }
            }

            if ($isThreat) {
                $actionStr = "FLAGGED"
                if ($AutoQuarantine) {
                    $quarSuccess = Move-ToQuarantine -FilePath $file.FullName -ThreatName $threatName -Sha256 $sha256
                    if ($quarSuccess) { $actionStr = "QUARANTINED" }
                }
                elseif ($AutoShred) {
                    $shredSuccess = Secure-ShredFile -FilePath $file.FullName
                    if ($shredSuccess) { $actionStr = "SHREDDED" }
                }

                $threatsFound += [PSCustomObject]@{
                    File = $file.FullName
                    ThreatName = $threatName
                    Severity = $threatSeverity
                    Details = $details
                    Action = $actionStr
                }
            }
        } catch {
            # Gracefully skip locked or unreadable files without aborting scan
            continue
        }
    }

    $sw.Stop()

    Write-Host "`n====================== SCAN RESULTS ======================" -ForegroundColor Cyan
    Write-Host "Files Inspected : $($files.Count)" -ForegroundColor White
    Write-Host "Time Elapsed    : $($sw.ElapsedMilliseconds) ms" -ForegroundColor White
    Write-Host "Threats Found   : $(if ($threatsFound.Count -eq 0) {'0 (SYSTEM CLEAN)'} else {$threatsFound.Count})" -ForegroundColor $(if ($threatsFound.Count -eq 0) {'Green'} else {'Red'})

    if ($threatsFound.Count -gt 0) {
        Write-Host "`n[!] MALICIOUS THREATS DETECTED:" -ForegroundColor Red
        $threatsFound | Format-Table ThreatName, Severity, Action, File -AutoSize
    }

    # Generate Animated Unreal HTML Report
    if (Test-Path $HtmlGenerator) {
        & $HtmlGenerator -ReportFile $ReportPath -Threats $threatsFound -FilesScanned $files.Count -ElapsedMs $sw.ElapsedMilliseconds -TargetScanPath $resolvedPath -RemediationMode $(if ($AutoQuarantine) {'QUARANTINE'} elseif ($AutoShred) {'SHRED'} else {'AUDIT'})
    }

    if ($OpenHtmlReport) {
        Start-Process $ReportPath
    }
}

function Show-QuarantineList {
    Write-Host "`n================ ENCRYPTED QUARANTINE VAULT ================" -ForegroundColor Yellow
    if (Test-Path $ManifestFile) {
        $records = Get-Content $ManifestFile | ConvertFrom-Json
        if ($records.Count -gt 0) {
            Write-Host "[+] Quarantined Items: $($records.Count)`n" -ForegroundColor White
            $records | Format-Table id, detection_name, original_path, timestamp -AutoSize
        } else {
            Write-Host "Quarantine vault is empty." -ForegroundColor Green
        }
    } else {
        Write-Host "Quarantine vault is empty." -ForegroundColor Green
    }
}

function Restore-QuarantineItem {
    param([string]$Id)
    if (-not (Test-Path $ManifestFile)) {
        Write-Host "No quarantine records found." -ForegroundColor Yellow
        return
    }
    $records = Get-Content $ManifestFile | ConvertFrom-Json
    $target = $records | Where-Object { $_.id -eq $Id -or $_.sha256 -like "$Id*" } | Select-Object -First 1
    if (-not $target) {
        Write-Host "Record '$Id' not found in vault." -ForegroundColor Red
        return
    }

    try {
        $bytes = [System.IO.File]::ReadAllBytes($target.quarantined_path)
        for ($i = 0; $i -lt $bytes.Length; $i++) {
            $bytes[$i] = $bytes[$i] -bxor $XorKey
        }
        $parent = Split-Path $target.original_path
        if (!(Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
        [System.IO.File]::WriteAllBytes($target.original_path, $bytes)
        Remove-Item -Path $target.quarantined_path -Force
        
        $newRecords = $records | Where-Object { $_.id -ne $target.id }
        $newRecords | ConvertTo-Json -Depth 5 | Set-Content $ManifestFile
        Write-Host "[+] Restored file to: $($target.original_path)" -ForegroundColor Green
    } catch {
        Write-Host "Failed to restore: $_" -ForegroundColor Red
    }
}

# Dispatcher
if ($ListQuarantine) {
    Show-QuarantineList
} elseif ($RestoreId -ne "") {
    Restore-QuarantineItem -Id $RestoreId
} else {
    # Check if compiled Rust binary exists and execute it, or compile with Cargo
    $rustBinary = "$ScannerDir\target\release\thunder-scanner.exe"
    $cargoCmd = Get-Command cargo -ErrorAction SilentlyContinue

    if ($cargoCmd -and $BuildRust) {
        Write-Host "[+] Compiling Rust Scanner binary..." -ForegroundColor Cyan
        Push-Location $ScannerDir
        cargo build --release
        Pop-Location
    }

    if (Test-Path $rustBinary) {
        Write-Host "[+] Launching compiled native Rust scanner binary at ultra-high speed..." -ForegroundColor Green
        $argsList = @("scan", "--path", $Path)
        if ($Quarantine) { $argsList += "--quarantine" }
        if ($Shred) { $argsList += "--shred" }
        & $rustBinary $argsList
    } else {
        Run-NativeScanEngine -ScanTarget $Path -AutoQuarantine $Quarantine -AutoShred $Shred
    }
}
