# configure-smb-shares.ps1 - Create SMB shares with planted lure content for AD/ADCS lab
param([switch]$Force)

$ErrorActionPreference = "Continue"

function Write-Status {
    param([string]$Msg, [string]$Color = "White")
    Write-Host $Msg -ForegroundColor $Color
}

Write-Status "[*] Configuring SMB shares..." "Cyan"

# ---------------------------------------------------------------------------
# Share definitions
# Groups used: Administrators, Domain Users, Everyone, IT-Admins,
#              Backup-Operators (all created by ad_population)
# ---------------------------------------------------------------------------
$shares = @(
    @{
        Name         = "IT"
        Path         = "C:\Shares\IT"
        Description  = "IT Department - Scripts and Configs"
        FullAccess   = @("Administrators", "IT-Admins")
        ReadAccess   = @()
        ChangeAccess = @()
    },
    @{
        Name         = "HR"
        Path         = "C:\Shares\HR"
        Description  = "HR Department - Personnel Records"
        FullAccess   = @("Administrators")
        ReadAccess   = @("Domain Users")
        ChangeAccess = @()
    },
    @{
        Name         = "Finance"
        Path         = "C:\Shares\Finance"
        Description  = "Finance Department"
        FullAccess   = @("Administrators")
        ReadAccess   = @("Domain Users")
        ChangeAccess = @()
    },
    @{
        Name         = "Security"
        Path         = "C:\Shares\Security"
        Description  = "Security Team"
        FullAccess   = @("Administrators", "IT-Admins")
        ReadAccess   = @()
        ChangeAccess = @()
    },
    @{
        Name         = "Backups"
        Path         = "C:\Shares\Backups"
        Description  = "Backup Files - Restricted"
        FullAccess   = @("Administrators")
        ReadAccess   = @()
        ChangeAccess = @("Backup-Operators")
    },
    @{
        Name         = "Deploy"
        Path         = "C:\Shares\Deploy"
        Description  = "Deployment Scripts"
        FullAccess   = @("Administrators")
        ReadAccess   = @()
        ChangeAccess = @()
    },
    @{
        Name         = "Honeypot"
        Path         = "C:\Shares\Honeypot"
        Description  = "Common Resources"
        FullAccess   = @("Administrators")
        ReadAccess   = @("Everyone")
        ChangeAccess = @()
    }
)

# ---------------------------------------------------------------------------
# Create directories and shares
# ---------------------------------------------------------------------------
foreach ($share in $shares) {
    New-Item -ItemType Directory -Path $share.Path -Force | Out-Null

    if ($Force) {
        Remove-SmbShare -Name $share.Name -Force -ErrorAction SilentlyContinue
    }

    $existing = Get-SmbShare -Name $share.Name -ErrorAction SilentlyContinue
    if ($existing -and -not $Force) {
        Write-Status "[=] Share already exists: $($share.Name)" "Yellow"
        continue
    }

    $params = @{
        Name        = $share.Name
        Path        = $share.Path
        Description = $share.Description
        ErrorAction = "Stop"
    }
    if ($share.FullAccess.Count -gt 0)   { $params['FullAccess']   = $share.FullAccess }
    if ($share.ReadAccess.Count -gt 0)   { $params['ReadAccess']   = $share.ReadAccess }
    if ($share.ChangeAccess.Count -gt 0) { $params['ChangeAccess'] = $share.ChangeAccess }

    try {
        New-SmbShare @params
        Write-Status "[+] Created share: $($share.Name)" "Green"
    } catch {
        Write-Status "[!] Failed to create share $($share.Name): $_" "Red"
    }
}

# ---------------------------------------------------------------------------
# Enable filesystem auditing on Honeypot share (detect recon)
# ---------------------------------------------------------------------------
try {
    $acl = Get-Acl "C:\Shares\Honeypot"
    $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
        "Everyone", "ReadData,ListDirectory",
        "ContainerInherit,ObjectInherit", "None", "Success,Failure"
    )
    $acl.AddAuditRule($auditRule)
    Set-Acl "C:\Shares\Honeypot" $acl
    Write-Status "[+] Auditing enabled on Honeypot share" "Green"
} catch {
    Write-Status "[=] Could not set Honeypot auditing (non-fatal): $_" "Yellow"
}

# ---------------------------------------------------------------------------
# IT share: admin notes, deploy script, server config, PKI docs
# ---------------------------------------------------------------------------
$itScripts = "C:\Shares\IT\scripts"
$itConfigs = "C:\Shares\IT\configs"
$itPkiDocs = "C:\Shares\IT\pki-docs"
New-Item -ItemType Directory -Path $itScripts -Force | Out-Null
New-Item -ItemType Directory -Path $itConfigs -Force | Out-Null
New-Item -ItemType Directory -Path $itPkiDocs -Force | Out-Null

@"
IT Admin Notes - CONFIDENTIAL
==============================
Last updated: Jan 2026 - jsmith

Domain Admin account:
  User: Administrator
  Note: Check the keepass db on \\DC01\IT\configs\ for current password
  Fallback: D0main@dmin2026  (old password -- update after next audit!)

Deployment service account:
  svc_deploy - used by CI/CD pipeline automation
  See scripts\deploy.ps1 in this directory for the connection string

ADCS/PKI:
  CA: DC01 (DC01.zsec.local)
  Web enrolment: https://DC01.zsec.local/certsrv
  Admin contact: cert-admin@zsec.local

TODO:
  - Rotate svc_backup password (overdue since Q3)
  - Review template ACLs after last ESC4 finding
"@ | Out-File -FilePath "C:\Shares\IT\admin-notes.txt" -Encoding UTF8

@"
# deploy.ps1 - Deployment automation script
# DO NOT MODIFY - managed by IT Operations
# Last updated: Jan 2026

param(
    [string]`$Environment = "prod",
    [string]`$AppName     = "zsecapp"
)

# Service account credentials (automation - DO NOT SHARE)
`$deployUser = "ZSEC\svc_deploy"
`$deployPass = "D3pl0y@utomation!"
`$securePwd  = ConvertTo-SecureString `$deployPass -AsPlainText -Force
`$deployCred = New-Object System.Management.Automation.PSCredential(`$deployUser, `$securePwd)

# Target application server
`$appServer  = "DC01.zsec.local"
`$deployPath = "C:\inetpub\wwwroot\`$AppName"

Write-Host "[*] Deploying `$AppName to `$Environment on `$appServer..."
Invoke-Command -ComputerName `$appServer -Credential `$deployCred -ScriptBlock {
    param(`$src, `$dst)
    robocopy `$src `$dst /MIR /R:2 /W:5 | Out-Null
} -ArgumentList "\\DC01\Deploy\`$AppName", `$deployPath
Write-Host "[+] Deployment complete"
"@ | Out-File -FilePath "$itScripts\deploy.ps1" -Encoding UTF8

@"
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <connectionStrings>
    <add name="AppDB"
         connectionString="Server=DC01\SQLEXPRESS;Database=ZSECApp;User Id=svc_sql;Password=SqlService2026!;Integrated Security=false;"
         providerName="System.Data.SqlClient" />
  </connectionStrings>
  <appSettings>
    <add key="SmtpHost"    value="DC01.zsec.local" />
    <add key="SmtpPort"    value="25" />
    <add key="BackupShare" value="\\DC01\Backups" />
    <add key="BackupUser"  value="ZSEC\svc_backup" />
    <add key="BackupPass"  value="SvcBackup2026!" />
  </appSettings>
</configuration>
"@ | Out-File -FilePath "$itConfigs\server-config.xml" -Encoding UTF8

@"
ZSEC Certificate Templates - CONFIDENTIAL
==========================================
VulnerableTemplate      - Web server certs  (ESC1  - allows SAN override!)
AnyPurposeTemplate      - Multi-use certs   (ESC2  - any-purpose EKU)
EnrollmentAgentTemplate - Request agent     (ESC3  - enrol on behalf of another)
ACLVulnerableTemplate   - Domain Users can modify! (ESC4 - GenericWrite on template)
NoSecExtTemplate        - No security ext   (ESC9  - StrongCertificateBindingEnforcement=0)
SecureAdminsAuth        - Admin auth certs  (ESC13 - OID group link)
WebServerV1             - Legacy web server (ESC15 - application policy bypass)

CA Server:      DC01 (DC01.zsec.local)
Web Enrolment:  https://DC01.zsec.local/certsrv
Admin:          cert-admin@zsec.local
"@ | Out-File -FilePath "$itPkiDocs\certificate-templates.txt" -Encoding UTF8

Write-Status "[+] Planted IT share files (admin-notes.txt, deploy.ps1, server-config.xml, pki-docs)" "Green"

# ---------------------------------------------------------------------------
# HR share: employee listing (CSV content, .xlsx extension for realism)
# ---------------------------------------------------------------------------
@"
Employee Directory - HR CONFIDENTIAL
=====================================
Name,Username,Department,Extension,Manager
John Smith,jsmith,IT,x1001,cdavis
Alice Brown,abrown,IT,x1002,cdavis
Bob Wilson,bwilson,IT,x1003,cdavis
Carol Davis,cdavis,IT,x1010,Administrator
Dave Miller,dmiller,IT,x1004,cdavis
Sarah Connor,sconnor,Finance,x2001,jobrien
Mike Chen,mchen,HR,x3001,mgarcia
Tanya Lee,tlee,IT,x1005,cdavis
Maria Garcia,mgarcia,HR,x3010,Administrator
James OBrien,jobrien,Finance,x2010,Administrator
Lisa Nakamura,lnakamura,IT,x1006,cdavis

Service Accounts (managed by IT):
svc_backup,svc_backup,IT Infrastructure,N/A,cdavis
svc_deploy,svc_deploy,IT Infrastructure,N/A,cdavis
svc_sql,svc_sql,IT Infrastructure,N/A,cdavis
"@ | Out-File -FilePath "C:\Shares\HR\employees.xlsx" -Encoding UTF8
Write-Status "[+] Planted HR share files (employees.xlsx)" "Green"

# ---------------------------------------------------------------------------
# Finance share: budget stub (CSV content, .xlsx extension for realism)
# ---------------------------------------------------------------------------
@"
ZSEC Budget 2026 - CONFIDENTIAL
=================================
Department,Q1,Q2,Q3,Q4,Total
IT Infrastructure,45000,42000,48000,51000,186000
HR Operations,22000,22000,22000,22000,88000
Security,35000,38000,35000,42000,150000
Finance,18000,18000,18000,18000,72000
Management,55000,55000,55000,55000,220000

Notes:
- IT budget includes DC01 replacement hardware in Q4
- Security: SOC tooling renewal (Elastic Stack) in Q3
- Budget queries: jobrien@zsec.local
- CFO approval required for spend over GBP 5000
"@ | Out-File -FilePath "C:\Shares\Finance\budget-2026.xlsx" -Encoding UTF8
Write-Status "[+] Planted Finance share files (budget-2026.xlsx)" "Green"

# ---------------------------------------------------------------------------
# Backups share: backup job script with embedded service account credentials
# ---------------------------------------------------------------------------
New-Item -ItemType Directory -Path "C:\Shares\Backups\weekly" -Force | Out-Null

@"
# backup-job.ps1 - Weekly backup automation
# Runs: Sunday 02:00 via Windows Task Scheduler
# Account: svc_backup (ZSEC\svc_backup)

`$backupUser  = "ZSEC\svc_backup"
`$backupPass  = "SvcBackup2026!"
`$sourcePaths = @("C:\inetpub\wwwroot", "C:\Shares\IT\configs", "C:\Windows\SYSVOL")
`$destShare   = "\\DC01\Backups\weekly"
`$date        = Get-Date -Format "yyyy-MM-dd"

`$securePwd = ConvertTo-SecureString `$backupPass -AsPlainText -Force
`$cred      = New-Object System.Management.Automation.PSCredential(`$backupUser, `$securePwd)

foreach (`$src in `$sourcePaths) {
    `$dest = Join-Path `$destShare "`$date-$(Split-Path `$src -Leaf).bak"
    Write-Host "Backing up `$src -> `$dest"
    Copy-Item `$src `$dest -Recurse -Force -ErrorAction Continue
}
Write-Host "Backup complete: `$date"
"@ | Out-File -FilePath "C:\Shares\Backups\backup-job.ps1" -Encoding UTF8

"ZSEC AppDB Backup - 2026-01-07 - restore via: sqlcmd -S DC01\SQLEXPRESS -Q `"RESTORE DATABASE ZSECApp FROM DISK='`'" |
    Out-File -FilePath "C:\Shares\Backups\weekly\zsecapp-2026-01-07.bak" -Encoding UTF8

Write-Status "[+] Planted Backups share files (backup-job.ps1, weekly/*.bak)" "Green"

# ---------------------------------------------------------------------------
# Deploy share: deploy config with plaintext credentials
# ---------------------------------------------------------------------------
@"
<?xml version="1.0" encoding="utf-8"?>
<deployConfig>
  <environment name="production">
    <server>DC01.zsec.local</server>
    <deployUser>ZSEC\svc_deploy</deployUser>
    <deployPass>D3pl0y@utomation!</deployPass>
    <targetPath>C:\inetpub\wwwroot\zsecapp</targetPath>
    <artifactServer>DC01.zsec.local</artifactServer>
    <artifactPath>/var/lib/gitea/repos/zsec-webapp</artifactPath>
  </environment>
  <notifications>
    <smtp>DC01.zsec.local:25</smtp>
    <recipients>it-ops@zsec.local</recipients>
  </notifications>
</deployConfig>
"@ | Out-File -FilePath "C:\Shares\Deploy\deploy-config.xml" -Encoding UTF8

Write-Status "[+] Planted Deploy share files (deploy-config.xml)" "Green"

# ---------------------------------------------------------------------------
# Honeypot share: lure file to attract enumeration activity
# ---------------------------------------------------------------------------
@"
Common Resources
================
Shared files accessible to all staff.
Last updated: Jan 2026

For departmental resources:
  IT files   -> \\DC01\IT
  HR records -> \\DC01\HR
  Finance    -> \\DC01\Finance

Helpdesk: it-helpdesk@zsec.local  ext x9000
"@ | Out-File -FilePath "C:\Shares\Honeypot\README.txt" -Encoding UTF8

Write-Status "[+] Planted Honeypot lure file" "Green"
Write-Status "[+] SMB share configuration complete" "Green"
