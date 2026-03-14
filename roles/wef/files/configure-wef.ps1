# configure-wef.ps1 - Windows Event Forwarding configuration
param(
    [ValidateSet('Collector','Forwarder')]
    [string]$Mode = 'Forwarder',
    [string]$CollectorServer = '',
    [string]$SubscriptionXmlPath = '',
    [switch]$Force
)

$ErrorActionPreference = "Continue"
Write-Host "[*] Configuring WEF as $Mode..." -ForegroundColor Cyan

if ($Mode -eq 'Collector') {
    # Enable WinRM and WEC service
    winrm quickconfig -q 2>&1 | Out-Null
    wecutil qc /q 2>&1 | Out-Null
    Set-Service -Name Wecsvc -StartupType Automatic
    Start-Service -Name Wecsvc -ErrorAction SilentlyContinue

    # Resize ForwardedEvents log to hold meaningful data
    wevtutil sl ForwardedEvents /ms:524288000 2>&1 | Out-Null  # 500 MB

    # Create subscription from provided XML if supplied
    if ($SubscriptionXmlPath -and (Test-Path $SubscriptionXmlPath)) {
        $subId = "ZSec-MDI-Events"
        $existing = wecutil gs $subId 2>&1
        if ($LASTEXITCODE -eq 0 -and -not $Force) {
            Write-Host "[=] WEF subscription '$subId' already exists — skipping (use -Force to recreate)" -ForegroundColor DarkGray
        } else {
            if ($LASTEXITCODE -eq 0) {
                wecutil ds $subId 2>&1 | Out-Null
                Write-Host "[*] Deleted existing subscription '$subId' for recreation" -ForegroundColor Yellow
            }
            wecutil cs $SubscriptionXmlPath 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "[+] WEF subscription '$subId' created from $SubscriptionXmlPath" -ForegroundColor Green
            } else {
                throw "Failed to create WEF subscription (exit code: $LASTEXITCODE) — check $SubscriptionXmlPath"
            }
        }
    } else {
        Write-Host "[!] No subscription XML supplied — collector started without subscriptions." -ForegroundColor Yellow
        Write-Host "    Copy zsec-wef-subscription.xml to C:\Tools\WEF\ and re-run with -SubscriptionXmlPath" -ForegroundColor Yellow
    }

    Write-Host "[+] WEF Collector configured" -ForegroundColor Green

} else {
    # Configure as forwarder
    winrm quickconfig -q 2>&1 | Out-Null
    if ($CollectorServer) {
        # Add collector to WinRM trusted hosts so HTTPS isn't required in the lab
        $currentTrusted = (Get-Item WSMan:\localhost\Client\TrustedHosts).Value
        if ($currentTrusted -notlike "*$CollectorServer*") {
            winrm set winrm/config/client "@{TrustedHosts=`"$CollectorServer`"}" 2>&1 | Out-Null
        }
        Write-Host "[+] WEF Forwarder configured (collector: $CollectorServer)" -ForegroundColor Green
    } else {
        Write-Host "[+] WEF Forwarder configured (no collector specified)" -ForegroundColor Green
    }
}

# Enable audit policies for security events relevant to MDI/MDE detection
Write-Host "[*] Configuring audit policies..." -ForegroundColor Cyan
auditpol /set /subcategory:"Logon"                        /success:enable /failure:enable 2>&1 | Out-Null
auditpol /set /subcategory:"Logoff"                       /success:enable                 2>&1 | Out-Null
auditpol /set /subcategory:"Account Lockout"              /success:enable /failure:enable 2>&1 | Out-Null
auditpol /set /subcategory:"Process Creation"             /success:enable                 2>&1 | Out-Null
auditpol /set /subcategory:"Certification Services"       /success:enable /failure:enable 2>&1 | Out-Null
auditpol /set /subcategory:"Directory Service Changes"    /success:enable                 2>&1 | Out-Null
auditpol /set /subcategory:"Security Group Management"    /success:enable /failure:enable 2>&1 | Out-Null
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable 2>&1 | Out-Null
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable 2>&1 | Out-Null
Write-Host "[+] Audit policies configured" -ForegroundColor Green
