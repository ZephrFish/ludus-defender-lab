# deploy-sysmon-config.ps1 - Install Sysmon with bundled ZSEC lab config
# Bundled config (sysmonconfig.xml) is deployed by Ansible before this script runs.
# Internet download is only attempted if the bundled config is somehow missing.
param([switch]$Force)

$ErrorActionPreference = "Continue"
$SysmonDir = "C:\Tools\Sysmon"
$ConfigUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
$ConfigPath = "$SysmonDir\sysmonconfig.xml"

Write-Host "[*] Deploying Sysmon configuration..." -ForegroundColor Cyan

# Use bundled config if present (deployed by Ansible); fall back to download if missing
if (Test-Path $ConfigPath) {
    Write-Host "[+] Using bundled Sysmon config: $ConfigPath" -ForegroundColor Green
} else {
    Write-Host "[!] Bundled config not found — attempting download..." -ForegroundColor Yellow
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $ConfigUrl -OutFile $ConfigPath -UseBasicParsing
        Write-Host "[+] Downloaded Sysmon config to $ConfigPath" -ForegroundColor Green
    } catch {
        Write-Host "[!] Download failed: $_" -ForegroundColor Red
        Write-Host "[!] No config available — aborting Sysmon install" -ForegroundColor Red
        exit 1
    }
}

# Check if Sysmon is already installed
$sysmonService = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
if ($sysmonService -and -not $Force) {
    Write-Host "[*] Sysmon already installed, updating config..." -ForegroundColor Yellow
    & "$SysmonDir\Sysmon64.exe" -c $ConfigPath 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Sysmon config update failed (exit code: $LASTEXITCODE)"
    }
} else {
    Write-Host "[*] Installing Sysmon64..." -ForegroundColor Yellow
    & "$SysmonDir\Sysmon64.exe" -accepteula -i $ConfigPath 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Sysmon install failed (exit code: $LASTEXITCODE)"
    }
}

# Verify
$svc = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
    Write-Host "[+] Sysmon64 is running" -ForegroundColor Green
} else {
    throw "Sysmon64 service not running — install may have failed silently"
}
