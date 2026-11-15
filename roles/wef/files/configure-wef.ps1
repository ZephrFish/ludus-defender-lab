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
            Write-Host "[=] WEF subscription '$subId' already exists -- skipping (use -Force to recreate)" -ForegroundColor DarkGray
        } else {
            if ($LASTEXITCODE -eq 0) {
                wecutil ds $subId 2>&1 | Out-Null
                Write-Host "[*] Deleted existing subscription '$subId' for recreation" -ForegroundColor Yellow
            }
            wecutil cs $SubscriptionXmlPath 2>&1
            $csExit = $LASTEXITCODE
            # Verify subscription was saved (wecutil cs may return non-zero
            # e.g. 15080 when saved but can't activate -- no forwarders yet)
            $verify = wecutil gs $subId 2>&1
            if ($LASTEXITCODE -eq 0) {
                if ($csExit -ne 0) {
                    Write-Host "[+] WEF subscription '$subId' saved (activation pending -- forwarders not yet connected)" -ForegroundColor Yellow
                } else {
                    Write-Host "[+] WEF subscription '$subId' created from $SubscriptionXmlPath" -ForegroundColor Green
                }
            } else {
                throw "Failed to create WEF subscription (exit code: $csExit) -- check $SubscriptionXmlPath"
            }
        }
    } else {
        Write-Host "[!] No subscription XML supplied -- collector started without subscriptions." -ForegroundColor Yellow
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

        # Point the forwarder at the collector. The subscription is source-initiated,
        # so without this policy value the forwarder never contacts the collector.
        $smPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager'
        $smValue = "Server=http://${CollectorServer}:5985/wsman/SubscriptionManager/WEC,Refresh=60"
        if (-not (Test-Path $smPath)) { New-Item -Path $smPath -Force | Out-Null }
        Set-ItemProperty -Path $smPath -Name '1' -Value $smValue -Type String
        Write-Host "[+] SubscriptionManager set: $smValue" -ForegroundColor Green

        # The forwarding service runs as NETWORK SERVICE, which cannot read the
        # Security log unless it is a member of Event Log Readers (S-1-5-32-573).
        $elr = Get-LocalGroup -SID 'S-1-5-32-573'
        $ns  = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-20')
        $isMember = Get-LocalGroupMember -Group $elr -ErrorAction SilentlyContinue |
                    Where-Object { $_.SID -eq $ns }
        if (-not $isMember) {
            Add-LocalGroupMember -Group $elr -Member $ns
            Write-Host "[+] Added NETWORK SERVICE to $($elr.Name)" -ForegroundColor Green
        }

        # WinRM only reads the SubscriptionManager policy when it starts. Restarting it
        # inline would drop the Ansible connection mid-task, so hand the restart to a
        # one-off SYSTEM scheduled task that runs after this script has returned.
        $taskName = 'ZSec-WEF-RestartWinRM'
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -Command `"Start-Sleep -Seconds 10; Restart-Service WinRM -Force; Unregister-ScheduledTask -TaskName $taskName -Confirm:`$false`""
        Register-ScheduledTask -TaskName $taskName -Action $action -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
        Start-ScheduledTask -TaskName $taskName
        Write-Host "[*] WinRM restart scheduled to apply forwarding policy" -ForegroundColor Cyan

        Write-Host "[+] WEF Forwarder configured (collector: $CollectorServer)" -ForegroundColor Green
    } else {
        throw "Forwarder mode requires -CollectorServer"
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
