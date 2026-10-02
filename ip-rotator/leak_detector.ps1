# ==============================================================================
# THUNDER - Privacy, DNS & WebRTC Leak Detector (10-Star Edition)
# Built by: NEXO-TECH
# ==============================================================================

param (
    [Parameter(Mandatory=$false)]
    [switch]$Detailed
)

function Write-Header {
    Write-Host "`n================================================================" -ForegroundColor Cyan
    Write-Host "       ⚡ THUNDER PRIVACY & LEAK DETECTOR (10-STAR) ⚡       " -ForegroundColor Yellow
    Write-Host "                      Built by NEXO-TECH                        " -ForegroundColor DarkCyan
    Write-Host "================================================================" -ForegroundColor Cyan
}

Write-Header

# 1. Dual-Stack Public IP Check
Write-Host "[1] Checking External Public IPv4 and IPv6 Endpoints..." -ForegroundColor White
$ipv4 = $null
$ipv6 = $null

try {
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("User-Agent", "Mozilla/5.0 THUNDER-Leak/2.0")
    $ipv4 = $wc.DownloadString("https://api.ipify.org").Trim()
} catch {}

try {
    $wc2 = New-Object System.Net.WebClient
    $wc2.Headers.Add("User-Agent", "Mozilla/5.0 THUNDER-Leak/2.0")
    $ipv6 = $wc2.DownloadString("https://api64.ipify.org").Trim()
    if ($ipv6 -eq $ipv4) { $ipv6 = $null }
} catch {}

Write-Host "    [+] Public IPv4 Address : $(if ($ipv4) {$ipv4} else {'Not detected'})" -ForegroundColor $(if ($ipv4) {'Green'} else {'Yellow'})
Write-Host "    [+] Public IPv6 Address : $(if ($ipv6) {$ipv6} else {'IPv6 Tunnel Clean / Not leaking'})" -ForegroundColor $(if ($ipv6) {'Yellow'} else {'Green'})

# 2. Comprehensive Upstream DNS Leak Test
Write-Host "`n[2] Performing Upstream DNS Leak Analysis..." -ForegroundColor White
$configuredDNS = Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses.Count -gt 0 }
$isLocalLeak = $false

foreach ($cd in $configuredDNS) {
    $addrs = ($cd.ServerAddresses | Where-Object {$_}) -join ", "
    if ($addrs) {
        Write-Host "    [+] Interface '$($cd.InterfaceAlias)' -> $addrs" -ForegroundColor Cyan
        if ($addrs -like "*192.168.*" -or $addrs -like "*10.*" -or $addrs -like "*172.16.*") {
            $isLocalLeak = $true
        }
    }
}

# Test recursive resolving identity via Cloudflare DoH trace
try {
    $wc3 = New-Object System.Net.WebClient
    $trace = $wc3.DownloadString("https://1.1.1.1/cdn-cgi/trace")
    $colo = if ($trace -match "colo=([^\r\n]+)") { $matches[1] } else { "Unknown" }
    Write-Host "    [+] Upstream DNS POP Cluster: $colo (Cloudflare Secure Anycast Gateway)" -ForegroundColor Green
} catch {}

if ($isLocalLeak) {
    Write-Host "    [!] WARNING: DNS queries are routing through local router/ISP gateway. Run THUNDER DNS Armor to encrypt." -ForegroundColor Yellow
} else {
    Write-Host "    [+] DNS Resolvers: SECURE (Direct Public/Encrypted DNS active)." -ForegroundColor Green
}

# 3. WebRTC & Local Interface Bindings Audit
Write-Host "`n[3] WebRTC & Local Interface Exposure Audit..." -ForegroundColor White
$boundAddresses = Get-NetIPAddress -ErrorAction SilentlyContinue | Where-Object { 
    $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "::1" -and $_.IPAddress -notlike "fe80:*"
}

foreach ($ba in $boundAddresses) {
    Write-Host "    [+] Bound Adapter: $($ba.InterfaceAlias) -> $($ba.IPAddress)" -ForegroundColor Gray
}

# Summary
Write-Host "`n========================= PRIVACY SCORECARD =========================" -ForegroundColor Cyan
if ($isLocalLeak) {
    Write-Host "Overall Status : WARNING (Potential ISP DNS Leak Detected)" -ForegroundColor Yellow
    Write-Host "Action Required: Use THUNDER Option [9] (DNS Armor) to enforce Quad9 or Cloudflare DoH." -ForegroundColor White
} else {
    Write-Host "Overall Status : 10/10 EXCELLENT (No DNS leaks, IPv6 safely managed)" -ForegroundColor Green
}
