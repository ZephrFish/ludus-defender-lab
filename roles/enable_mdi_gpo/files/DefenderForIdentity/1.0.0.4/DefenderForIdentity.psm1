<#
Copyright (c) Microsoft Corporation.
MIT License
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#>

#requires -Version 4.0
#requires -Modules ActiveDirectory, GroupPolicy

#region General settings

$script:settings = @{

    gpoNamePrefix                  = 'Microsoft Defender for Identity'

    gpoExtensions                  = @{
        'Core GPO Engine'                                = '00000000-0000-0000-0000-000000000000'
        'Tool Extension GUID (Computer Policy Settings)' = '0F6B957D-509E-11D1-A7CC-0000F87571E3'
        'Security'                                       = '827D319E-6EAC-11D2-A4EA-00C04F79F83A'
        'Computer Restricted Groups'                     = '803E14A0-B4FB-11D0-A0D0-00A0C90F574B'
        'Preference Tool CSE GUID Registry'              = 'BEE07A6A-EC9F-4659-B8C9-0B1937907C83'
        'Preference CSE GUID Registry'                   = 'B087BE9D-ED37-454F-AF9C-04291E351182'
        'Audit Configuration Extension'                  = '0F3F3735-573D-9804-99E4-AB2A69BA5FD4'
        'Audit Policy Configuration'                     = 'F3CCC681-B74C-4060-9F26-CD84525DCA2A'
    }

    ProcessorPerformance           = @{
        GpoName    = '{0} - Processor Performance'
        SchemeGuid = '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
        Key        = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings'
        ValueName  = 'ActivePowerScheme'
    }

    RemoteSAM                      = @{
        GpoName           = '{0} - Remote SAM Access'
        GpoRegSet         = @{
            'System\CurrentControlSet\Control\Lsa\RestrictRemoteSAM=1' = 'O:BAG:BAD:(A;;RC;;;BA)(A;;RC;;;{0})'
        }
        RegistrySet       = @{
            'System\CurrentControlSet\Control\Lsa\RestrictRemoteSAM' = 'O:BAG:BAD:(A;;RC;;;BA)(A;;RC;;;{0})'
        }
        DenyGPPermissions = [ordered]@{
            '{0}-516' = 'GpoApply'
        }
    }

    NTLMAuditing                   = @{
        GpoName     = '{0} - NTLM Auditing for DCs'
        RegistrySet = @{
            'System\CurrentControlSet\Control\Lsa\MSV1_0\AuditReceivingNTLMTraffic'   = '2'
            'System\CurrentControlSet\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic'  = '1|2'
            'System\CurrentControlSet\Services\Netlogon\Parameters\AuditNTLMInDomain' = '7'
        }
    }

    EntraConnectAuditing           = @{
        GpoName  = '{0} - Advanced Audit and URA Policy for Entra Connect'
        GptSet   = @{
            'SeServiceLogonRight' = '*{0},*S-1-5-80-0'
        }
        AuditSet = @'
Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value
,System,Audit Logon,{0cce9215-69ae-11d9-bed3-505054503030},Success and Failure,,3
'@
    }

    CAAuditing                     = @{
        GpoName       = '{0} - Auditing for CAs'
        GpoVal        = @{ 'AuditFilter' = 127 }
        GpoReg        = 'System\CurrentControlSet\Services\CertSvc\Configuration\%DomainName%-%ComputerName%-CA'
        RegPathActive = 'System\CurrentControlSet\Services\CertSvc\Configuration\Active'
        RegistrySet   = @{
            'System\CurrentControlSet\Services\CertSvc\Configuration\{0}\AuditFilter' = 127
        }
        GPPermissions = [ordered]@{
            '{0}-517'  = 'GpoApply'
            '{0}-516'  = 'GpoRead'
            'S-1-5-11' = 'GpoRead'
        }
    }

    AdvancedAuditPolicyDCs         = @{
        GpoName        = '{0} - Advanced Audit Policy for DCs'
        PolicySettings = @'
Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value
,System,Security System Extension,{0CCE9211-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Distribution Group Management,{0CCE9238-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Security Group Management,{0CCE9237-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Computer Account Management,{0CCE9236-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,User Account Management,{0CCE9235-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Directory Service Access,{0CCE923B-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Directory Service Changes,{0CCE923C-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Credential Validation,{0CCE923F-69AE-11D9-BED3-505054503030},Success and Failure,,3
'@
    }

    AdvancedAuditPolicyCAs         = @{
        GpoName        = '{0} - Advanced Audit Policy for CAs'
        PolicySettings = @'
Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value
,System,Audit Certification Services,{0cce9221-69ae-11d9-bed3-505054503030},Success and Failure,,3
'@
        GPPermissions  = [ordered]@{
            '{0}-517'  = 'GpoApply'
            '{0}-516'  = 'GpoRead'
            'S-1-5-11' = 'GpoRead'
        }
    }

    ObjectAuditing                 = @{
        Path     = '{0}'
        Auditing = @'
SecurityIdentifier,AccessMask,AuditFlagsValue,InheritedObjectAceType,Description,InheritanceType,PropagationFlags
S-1-1-0,852331,1,bf967aba-0de6-11d0-a285-00aa003049e2,Descendant User Objects,2,2
S-1-1-0,852331,1,bf967a9c-0de6-11d0-a285-00aa003049e2,Descendant Group Objects,2,2
S-1-1-0,852331,1,bf967a86-0de6-11d0-a285-00aa003049e2,Descendant Computer Objects,2,2
S-1-1-0,852331,1,ce206244-5827-4a86-ba1c-1c0c386c1b64,Descendant msDS-ManagedServiceAccount Objects,2,2
S-1-1-0,852075,1,7b8b558a-93a5-4af7-adca-c017e67f1057,Descendant msDS-GroupManagedServiceAccount Objects,2,2
S-1-1-0,852075,1,0feb936f-47b3-49f2-9386-1dedc2c23765,Descendant msDS-DelegatedManagedServiceAccount Objects,2,2
'@ | ConvertFrom-Csv
    }

    ConfigurationContainerAuditing = @{
        Validate = 'LDAP://CN=Microsoft Exchange,CN=Services,CN=Configuration,{0}'
        Path     = 'CN=Configuration,{0}'
        Auditing = @'
SecurityIdentifier,AccessMask,AuditFlagsValue,AceFlagsValue,InheritedObjectAceType,InheritanceType,PropagationFlags
S-1-1-0,32,3,194,00000000-0000-0000-0000-000000000000,1,0
'@ | ConvertFrom-Csv
    }

    AdfsAuditing                   = @{
        Validate = 'LDAP://CN=ADFS,CN=Microsoft,CN=Program Data,{0}'
        Path     = 'CN=ADFS,CN=Microsoft,CN=Program Data,{0}'
        Auditing = @'
SecurityIdentifier,AccessMask,AuditFlagsValue,AceFlagsValue,InheritedObjectAceType,InheritanceType,PropagationFlags
S-1-1-0,48,3,194,00000000-0000-0000-0000-000000000000,1,0
'@ | ConvertFrom-Csv
    }

    SensitiveGroups                = @{
        'Administrators'              = 'S-1-5-32-544'
        'Account Operators'           = 'S-1-5-32-548'
        'Backup Operators'            = 'S-1-5-32-551'
        'Domain Admins'               = '{0}-512'
        'Domain Controllers'          = '{0}-516'
        'Enterprise Admins'           = '{0}-519'
        'Group Policy Creator Owners' = '{0}-520'
        'Print Operators'             = 'S-1-5-32-550'
        'Replicators'                 = 'S-1-5-32-552'
        'Schema Admins'               = '{0}-518'
        'Server Operators'            = 'S-1-5-32-549'
        'Cert Publishers'             = '{0}-517'
    }
}

if (Test-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath ($PSUICulture))) {
    Import-LocalizedData -BindingVariable strings
} else {
    Import-LocalizedData -BindingVariable strings -UICulture en-US
}

#endregion

#region General helper functions

function Get-MDIValidationMessage {
    param($Result)
    if ($Result) {
        $strings['Validation_Passed']
    } else {
        $strings['Validation_Failed']
    }
}

function Resolve-MDIPath {
    param(
        [parameter(Mandatory)] $Path
    )
    $return = Resolve-Path -Path $Path -ErrorAction SilentlyContinue -ErrorVariable resolveError
    if ($return.Path) { $return.Path }
    else { $resolveError[0].TargetObject }
}

function Format-Json {
    param(
        [Parameter(Mandatory, ValueFromPipeline)] [String] $json
    )
    $indent = 0;
    ($json -Split '\n' | ForEach-Object {
        if ($_ -match '[\}\]]') {
            $indent--
        }
        $line = (' ' * $indent * 2) + $_.TrimStart().Replace(':  ', ': ')
        if ($_ -match '[\{\[]') {
            $indent++
        }
        $line
    }) -join "`n"
}

function Test-MDICAServer {
    [CmdletBinding()]
    param()
    [bool](Get-Service CertSvc -ErrorAction SilentlyContinue)
}

function New-MDIPassword {
    $guid = (New-Guid).guid.split('-')
    $guid[0] += [char](Get-Random -min 65 -max 90)
    $guid[1] += [char](Get-Random -min 65 -max 90)
    ConvertTo-SecureString ($guid -join '-') -AsPlainText -Force
}

#endregion

#region Sensor service helper functions

function Get-MDISensorBinPath {
    [CmdletBinding()]
    param()
    $wmiParams = @{
        Namespace   = 'root\cimv2'
        ClassName   = 'Win32_Service'
        Property    = 'PathName'
        Filter      = 'Name="AATPSensor"'
        ErrorAction = 'Stop'
    }
    Write-Verbose -Message $strings['Sensor_LocateConfigurationFile']
    try {
        $return = (Get-CimInstance @wmiParams | Select-Object -ExpandProperty PathName) -replace '"|Microsoft\.Tri\.Sensor\.exe', ''
    } catch {
        $return = $null
    }
    if ([string]::IsNullOrEmpty($return)) {
        Write-Warning $strings['Sensor_ServiceNotFound']
    }
    $return
}

function Get-MDISenseIdentityBinPath {
    [CmdletBinding()]
    param()
    $processParams = @{
        Name            = "SenseIdentity"
        FileVersionInfo = $true
    }
    $senseIdentityProcess = Get-Process @processParams
    ($senseIdentityProcess).FileName | Split-Path
}

function Stop-MDISensor {
    [CmdletBinding()]
    param()
    Stop-Service -Name AATPSensorUpdater -Force
}

function Start-MDISensor {
    [CmdletBinding()]
    param()
    Start-Service -Name AATPSensorUpdater
}

function Get-MDISensorProcessInformation {
    [CmdletBinding()]
    param()
    [PSCustomObject]@{
        AATPSensor        = $(try { (Get-Service AATPSensor -ErrorAction SilentlyContinue).Status } catch { $null })
        AATPSensorUpdater = $(try { (Get-Service AATPSensorUpdater -ErrorAction SilentlyContinue).Status } catch { $null })
        SenseIdentity     = $(try { if ((Get-Process -Name SenseIdentity -ErrorAction SilentlyContinue).Count -gt 0) { 'Running' } else { $null } } catch { $null })
    }
}
#endregion

#region Service account configuration functions
function Test-MDIKDSRootKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)] [string] $Server,
        [Parameter(Mandatory = $false)]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        [PSCustomObject] $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $adRootDseParams = @{

    }; if (-not [string]::IsNullOrEmpty($Server)) { $adRootDseParams.Add("Server", $Server) }
    $configurationNamingContext = (Get-ADRootDSE @adRootDseParams).configurationNamingContext
    $null = New-PSDrive -Name $($myDomain.netbiosname) -PSProvider ActiveDirectory -Server $myDomain.ChosenDC -Root "//RootDSE/"
    $kdsPath = '{0}:\CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,{1}' -f $($myDomain.netbiosname), $configurationNamingContext
    try {
        $kdsGci = Get-ChildItem -Path $kdsPath
        $kdsGet = (Get-KdsRootKey)
    } catch {
        return $false
    }
    Remove-PSDrive -Name $($myDomain.netbiosname)
    return ($kdsGci.distinguishedName.length -gt 0) -or $kdsGet
}

function Get-MDIDSA {
    [CmdletBinding()]
    param(
        [string] $Identity,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $returnVal = $null
    $adAccountParams = @{
        LDAPFilter = '(&(|(samaccountname={0})(samaccountname={0}$))(|(objectClass=user)(objectClass=msDS-GroupManagedServiceAccount)))' -f $Identity
        Properties = "msDS-PrincipalName", "DistinguishedName", "ObjectSid", "ObjectClass", "samaccountname"
    }; if (-not [string]::IsNullOrEmpty($Server)) { $adAccountParams.Add("Server", $Server) }
    try {
        $returnVal = Get-AdObject @adAccountParams -ErrorAction SilentlyContinue
        if ($returnVal -eq $null) {
            throw
        }
    } catch {
        $returnVal = $null
        Write-Warning ($strings['DSA_CannotFindIdentity'] -f $Identity)
    }
    return $returnVal
}

function New-MDIDSA {
    [CmdletBinding(DefaultParameterSetName = "gmsaAccount")]
    Param(
        [parameter(Mandatory = $true, ParameterSetName = "gmsaAccount", Position = 1)]
        [parameter(Mandatory = $true, ParameterSetName = "standardAccount", Position = 1)]
        [ValidateLength(1, 16)]
        [string]$Identity,
        [parameter(Mandatory = $true, ParameterSetName = "gmsaAccount")]
        [ValidateLength(1, 28)]
        [string]$GmsaGroupName,
        [parameter(Mandatory = $false, ParameterSetName = "gmsaAccount")]
        [parameter(Mandatory = $false, ParameterSetName = "standardAccount")]
        [string]$BaseDn,
        [parameter(Mandatory = $false, ParameterSetName = "standardAccount")]
        [switch]$ForceStandardAccount,
        [parameter(Mandatory = $false, ParameterSetName = "gmsaAccount")]
        [parameter(Mandatory = $false, ParameterSetName = "standardAccount")]
        [string]$Server,
        [parameter(Mandatory = $false, ParameterSetName = "gmsaAccount")]
        [parameter(Mandatory = $false, ParameterSetName = "standardAccount")]
        [string]$Domain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $returnVal = $false
    if ($Identity -match '.*\$') {
        $Identity = $Identity.replace('$', '')
    }
    try {
        $adObjectParams = @{
            LDAPFilter = "(objectSid=$(($myDomain).DomainSid)-519)"
        }; if (-not [string]::IsNullOrEmpty($Server)) { $adObjectParams.Add("Server", $Server) }
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $groups = $id.Groups | ForEach-Object { $_.Translate([Security.Principal.NTAccount]) }
        if ([bool]$(($myDomain).ParentDomain)) {
            $eaGroupName = '{0}\{1}' -f (Get-ADDomain -Server $($myDomain.ParentDomain)).netbiosname,
                (Get-ADObject -LDAPFilter "(objectSid=$($myDomain.forestSid)-519)" -Server $($myDomain.ParentDomain)).name
        } else {
            $eaGroupName = '{0}\{1}' -f ($myDomain.NetBIOSName), (Get-ADObject @adObjectParams).name
        }
    } catch {
        Write-Warning -Message $strings['DSA_EnterpriseAdminGroupNotFound']
    }

    if ([string]::IsNullOrEmpty($baseDn)) {
        $baseDn = $myDomain.UsersContainer
        $adObjectParams.LDAPFilter = "(distinguishedName=$baseDn)"
        try {
            $bdnCheck = Get-ADObject @adObjectParams
        } catch {
            $baseDn = $myDomain.DistinguishedName
        }
    }
    if ($forceStandardAccount) {
        $adUserParams = @{
            Identity = $Identity
        }; if (-not [string]::IsNullOrEmpty($Server)) { $adUserParams.Add("Server", $Server) }
        try {
            Get-Aduser @adUserParams -ErrorAction silentlycontinue
        } catch {
            try {
                $securePassword = New-MDIPassword
                $adUserParams.Add("Name", $Identity)
                $adUserParams.Add("AccountPassword", $securePassword)
                $adUserParams.Add("SamAccountName", $Identity)
                $adUserParams.Add("Path", $baseDn)
                $adUserParams.Add("Description", "This account runs the MDI service")
                $adUserParams.Add("Enabled", $true)
                $adUserParams.Remove("Identity")
                $serviceAccount = New-ADUser @adUserParams -PassThru
                $returnVal = $true
            } catch {
                Write-Error $strings['DSA_CannotCreateAccount']
            }
        }
    } else {
        if (-not (Test-MDIKDSRootKey -myDomain $myDomain -Domain $Domain -Server $Server)) {
            if ($eaGroupName -in $groups) {
                try {
                    $null = Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))
                    $strings['DSA_CreatedKDSRootKey']
                } catch {
                    throw $strings['DSA_CannotCreateKDSRootKey']
                }
            }
        } else {
            Write-Verbose $strings['DSA_FoundKDSRootKey']
        }
        if (Test-MDIKDSRootKey -myDomain $myDomain -Domain $Domain -Server $Server) {
            $domainDCs = "$($myDomain.DomainSid)-516"
            try {
                $adObjectParams.LDAPFilter = "(objectSid=$domainDCs)"
                $domainDCsGroupName = (Get-ADGroup @adObjectParams).Name
            } catch {
                Write-Warning $strings['DSA_CannotFindDomainControllersGroup']
            }
            $gmsaGroupParams = @{
                Name           = $GmsaGroupName
                SamAccountName = $GmsaGroupName
                Path           = $baseDn
                GroupScope     = "Universal"
                Description    = $strings['DSA_GroupDescription'] -f $Identity
            }; if (-not [string]::IsNullOrEmpty($Server)) { $gmsaGroupParams.Add("Server", $Server) }
            $getGmsaGroupParams = @{
                Identity = $GmsaGroupName
            }; if (-not [string]::IsNullOrEmpty($Server)) { $getGmsaGroupParams.Add("Server", $Server) }
            try {
                $groupExists = [bool](Get-ADGroup @getGmsaGroupParams -ErrorAction SilentlyContinue)
            } catch {
                $groupExists = $false
            }
            if (-not $groupExists) {
                try {
                    $null = New-ADGroup @gmsaGroupParams
                    Write-Verbose $strings['DSA_CreatedGMSAGroup']
                } catch {
                    Write-Error $strings['DSA_CannotCreateGMSAGroup']
                }
            }
            $newAdServiceAccountParams = @{
                Name                                       = $Identity
                DNSHostName                                = $($myDomain.DNSRoot)
                PrincipalsAllowedToRetrieveManagedPassword = [string[]]$GmsaGroupName
                SamAccountName                             = $gmsaAccountName
            }; if (-not [string]::IsNullOrEmpty($Server)) { $newAdServiceAccountParams.Add("Server", $Server) }
            if (-not [string]::IsNullOrEmpty($domainDCsGroupName)) {
                $newAdServiceAccountParams.PrincipalsAllowedToRetrieveManagedPassword += $domainDCsGroupName
            }
            try {
                $serviceAccount = New-ADServiceAccount @newAdServiceAccountParams -PassThru
                $returnVal = $true
            } catch {
                try {
                    $newAdServiceAccountParams.Add("Path", $baseDn)
                    $serviceAccount = New-ADServiceAccount @newAdServiceAccountParams -PassThru
                    $returnVal = $true
                } catch {
                    throw
                }
                Write-Error $strings['DSA_CannotCreateGMSAAccount']
            }
        } else {
            Write-Error $strings['DSA_CannotCreateGMSAAccount']
        }
    }
    if ($null -ne $serviceAccount) {
        Set-MDIDeletedObjectsContainerPermission -Identity ("{0}\{1}" -f $myDomain.NetBIOSName, $serviceAccount.SamAccountName) -Server $Server -myDomain $myDomain | Out-Null
    } else {
        Write-Warning $strings['DeletedObjectsPermissions_StatusFail']
    }
    return $returnVal
}

#endregion

#region Sensor configuration helper functions

function Get-MDISensorConfiguration {
    [CmdletBinding()]
    param()
    $sensorProcesses = Get-MDISensorProcessInformation
    if ($sensorProcesses.SenseIdentity -eq 'Running') {
        try {
            $sensorConfiguration = ((Get-ItemProperty 'hklm:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection' OnboardingInfo -ErrorAction SilentlyContinue).OnboardingInfo | ConvertFrom-Json).body | ConvertFrom-Json | Select-Object orgId, geoLocationUrl, datacenter
            if ($null -ne $sensorConfiguration) {
                $proxyUrl = $(try { (Get-ItemProperty -Path "hklm:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name ProxyServer -ErrorAction SilentlyContinue).ProxyServer } catch { $null })
                $SensorProxyConfiguration = [PSCustomObject]@{
                    IsProxyEnabled       = $(if ($null -ne $proxyUrl) { $true } else { $false })
                    Url                  = $proxyUrl
                    TelemetryProxyServer = $(try { (Get-ItemProperty -Path "hklm:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name TelemetryProxyServer -ErrorAction SilentlyContinue).TelemetryProxyServer } catch { $null })
                }
            }
            $sensorConfiguration | Add-Member -MemberType NoteProperty -Name SensorProxyConfiguration -Value $SensorProxyConfiguration -Force
        } catch {
            $sensorConfiguration = $null
            Write-Warning -Message $strings['Sensor_ErrorReadingSensorConfiguration']
        }
    } else {
        $sensorBinPath = Get-MDISensorBinPath
        if ($null -eq $sensorBinPath) {
            $sensorConfiguration = $null
            Write-Warning -Message $strings['Sensor_ErrorReadingSensorConfiguration']
        } else {
            Write-Verbose -Message $strings['Sensor_ReadConfigurationFile']
            $sensorConfigurationPath = Join-Path -Path $sensorBinPath -ChildPath 'SensorConfiguration.json'
            $sensorConfiguration = Get-Content -Path $sensorConfigurationPath -Raw | ConvertFrom-Json
        }

        if ($null -ne $sensorConfiguration.SensorProxyConfiguration) {
            $SensorProxyConfiguration = [PSCustomObject]@{
                IsProxyEnabled               = -not [string]::IsNullOrEmpty($sensorConfiguration.SensorProxyConfiguration.Url)
                IsAuthenticationProxyEnabled = -not [string]::IsNullOrEmpty($sensorConfiguration.SensorProxyConfiguration.UserName)
                Url                          = $sensorConfiguration.SensorProxyConfiguration.Url
                UserName                     = $sensorConfiguration.SensorProxyConfiguration.UserName
                EncryptedUserPasswordData    = $sensorConfiguration.SensorProxyConfiguration.EncryptedUserPasswordData.EncryptedBytes
                CertificateThumbprint        = $sensorConfiguration.SensorProxyConfiguration.EncryptedUserPasswordData.CertificateThumbprint

            }
            $sensorConfiguration.SensorProxyConfiguration = $SensorProxyConfiguration
        }
    }
    $sensorConfiguration
}

function Get-MDIEncryptedPassword {
    param(
        [Parameter(Mandatory = $true)] [string] $CertificateThumbprint,
        [Parameter(Mandatory = $true)] [PSCredential] $Credential
    )
    $store = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Store -ArgumentList @(
        [System.Security.Cryptography.X509Certificates.StoreName]::My,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
    )
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)

    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2] $store.Certificates.Find(
        [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $CertificateThumbprint, $false)[0]

    $rsaPublicKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    $bytes = [System.Text.Encoding]::Unicode.GetBytes(
        $Credential.GetNetworkCredential().Password
    )
    $encrypted = $rsaPublicKey.Encrypt($bytes, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
    $encryptedPassword = [System.Convert]::ToBase64String($encrypted)

    $store.Close()
    $encryptedPassword
}

function Get-MDIDecryptedPassword {
    param(
        [Parameter(Mandatory = $true)] [string] $CertificateThumbprint,
        [Parameter(Mandatory = $true)] [string] $EncryptedString
    )
    $store = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Store -ArgumentList @(
        [System.Security.Cryptography.X509Certificates.StoreName]::My,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
    )
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)

    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2] $store.Certificates.Find(
        [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $CertificateThumbprint, $false)[0]

    $rsaPublicKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)

    $encrypted = [System.Convert]::FromBase64String($EncryptedString)
    $bytes = $rsaPublicKey.Decrypt($encrypted, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
    $decryptedPassword = [System.Text.Encoding]::Unicode.GetString($bytes)

    $store.Close()
    $decryptedPassword
}

function Get-MDISensorProxyConfiguration {
    [CmdletBinding()]
    param()
    $sensorConfiguration = Get-MDISensorConfiguration
    if ($null -eq $sensorConfiguration) {
        $proxyConfiguration = $null
    } else {
        $proxyConfiguration = $sensorConfiguration.SensorProxyConfiguration
    }
    $proxyConfiguration
}

function Set-MDISensorProxyConfiguration {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $false)] [string] $ProxyUrl,
        [Parameter(Mandatory = $false)] [PSCredential] $ProxyCredential
    )
    $operation = if ([string]::IsNullOrEmpty($ProxyUrl)) { 'Clear' } else { 'Set' }
    if ($PSCmdlet.ShouldProcess($strings['Sensor_ProxyConfigurationAction'], $operation)) {
        if ('Set' -eq $operation) {
            [System.Uri] $resultUri = $null
            if (-not [System.Uri]::TryCreate($ProxyUrl, [System.UriKind]::Absolute, [ref] $resultUri)) {
                if (-not $ProxyUrl.StartsWith('http://')) {
                    $ProxyUrl = 'http://' + $ProxyUrl
                }
            }
        }
        $sensorProcesses = Get-MDISensorProcessInformation
        $sensorConfiguration = Get-MDISensorConfiguration
        if ($null -eq $sensorConfiguration) {
            Write-Error $strings['Sensor_ErrorReadingSensorConfiguration'] -ErrorAction Stop
        }
        if ($sensorProcesses.SenseIdentity -eq 'Running') {
            if ([string]::IsNullOrEmpty($ProxyUrl)) {
                try {
                    $null = Remove-ItemProperty -Path "hklm:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name TelemetryProxyServer -ErrorAction Stop
                    $null = Remove-ItemProperty -Path "hklm:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name ProxyServer -ErrorAction Stop
                } catch {
                    Write-Warning -Message $strings['Sensor_ProxyConfigurationActionFail']
                }
            } else {
                try {
                    $null = New-ItemProperty -Path "hklm:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name TelemetryProxyServer -PropertyType String -Value $ProxyUrl.Replace('http://', '') -Force -ErrorAction Stop
                    $null = New-ItemProperty -Path "hklm:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name ProxyServer -PropertyType String -Value $ProxyUrl -Force -ErrorAction Stop
                } catch {
                    Write-Warning -Message $strings['Sensor_ProxyConfigurationActionFail']
                }
            }
        } else {
            if ([string]::IsNullOrEmpty($ProxyUrl)) {
                $sensorConfiguration.SensorProxyConfiguration = $null
            } else {
                if ($ProxyCredential) {
                    $thumbprint = $sensorConfiguration.SecretManagerConfigurationCertificateThumbprint
                    $sensorConfiguration.SensorProxyConfiguration = [PSCustomObject]@{
                        '$type'                   = 'SensorProxyConfiguration'
                        Url                       = $ProxyUrl
                        UserName                  = $ProxyCredential.UserName
                        EncryptedUserPasswordData = [PSCustomObject]@{
                            '$type'               = 'EncryptedData'
                            EncryptedBytes        = Get-MDIEncryptedPassword -CertificateThumbprint $thumbprint -Credential $ProxyCredential
                            SecretVersion         = $null
                            CertificateThumbprint = $sensorConfiguration.SecretManagerConfigurationCertificateThumbprint
                        }
                    }
                } else {
                    $sensorConfiguration.SensorProxyConfiguration = [PSCustomObject]@{
                        '$type' = 'SensorProxyConfiguration'
                        Url     = $ProxyUrl
                    }
                }
            }
            Stop-MDISensor
            Write-Verbose -Message $strings['Sensor_WriteSensorConfigurationFile']
            $sensorConfiguration | ConvertTo-Json | Format-Json |
                Set-Content -Path (Join-Path -Path (Get-MDISensorBinPath) -ChildPath 'SensorConfiguration.json')
            Start-MDISensor
        }
    }
}

function Clear-MDISensorProxyConfiguration {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    if ($PSCmdlet.ShouldProcess($strings['Sensor_ProxyConfigurationAction'], 'Clear')) {
        Set-MDISensorProxyConfiguration -ProxyUrl $null
    }
}

#endregion

#region GPO helper functions

function Get-MDIGPOName {
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory = $false)] [string] $GpoNamePrefix
    )
    if ([string]::IsNullOrEmpty($GpoNamePrefix)) {
        $Name -f $script:settings['gpoNamePrefix']
    } else {
        $Name -f $GpoNamePrefix
    }
}

function New-MDIGPO {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory = $false)] [switch] $CreateGpoDisabled,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        [PSCustomObject] $myDomain
    )
    $returnVal = $null
    Write-Verbose -Message ($strings['GPO_Create'] -f $Name)
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $maxWaitTime = (Get-Date).AddSeconds(3)
    $successGpo = $false
    $gpoParams = @{
        Name = $Name
    }
    if (-not [string]::IsNullOrEmpty($Server)) { $gpoParams.Add("Server", $Server) }
    if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $gpoParams.Add("Domain", $myDomain.DNSRoot) }
    try {
        $gpoCreate = New-GPO @gpoParams -ErrorAction silentlycontinue
        $successGpo = $true
    } catch {
        $successGpo = $false
    }

    if ($successGpo) {
        do {
            Start-Sleep -Milliseconds 500
            $gpo = Get-MDIGPO @gpoParams -myDomain $myDomain
        } while (-not (($gpo) -or ($maxWaitTime -lt (Get-Date))))

        if ($gpo) {
            $gPCFileSysPath = $gpo.gPCFileSysPath
            do {
                Start-Sleep -Milliseconds 500
            } while (-not ((Test-Path -Path $gPCFileSysPath) -or ($maxWaitTime -lt (Get-Date))))
            if ($CreateGpoDisabled) {
                $gpo.GpoStatus = [Microsoft.GroupPolicy.GpoStatus]::AllSettingsDisabled
            } else {
                $gpo.GpoStatus = [Microsoft.GroupPolicy.GpoStatus]::UserSettingsDisabled
            }
            $returnVal = $gpo | Add-Member -MemberType NoteProperty -Name gPCFileSysPath -Value $gPCFileSysPath -PassThru -Force
        } else {
            $returnVal = $null
        }
    } else {
        $returnVal = $null
    }
    return $returnVal
}

function Get-MDIGPO {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $maxWaitTime = (Get-Date).AddSeconds(3)
    $gpoParams = @{
        Name = $Name
    }; if (-not [string]::IsNullOrEmpty($Server)) { $gpoParams.Add("Server", $Server) }
    if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $gpoParams.Add("Domain", $myDomain.DNSRoot) }
    try {
        $gpo = Get-Gpo @gpoParams -ErrorAction SilentlyContinue
    } catch {
        if ($null -eq $gpo) {
            Start-Sleep -Milliseconds 500
            try {
                if (-not [string]::IsNullOrEmpty($myDomain.PDCEmulator)) {
                    if (-not ("Server" -in $gpoParams.Keys)) {
                        $gpoParams.Add("Server", $myDomain.PDCEmulator)
                    } else {
                        $gpoParams.Server = $myDomain.PDCEmulator
                    }
                }
                $gpo = Get-Gpo @gpoParams -ErrorAction SilentlyContinue
            } catch {
                $gpo = $null
            }
        }
    }
    if ($null -eq $gpo) {
        Write-Verbose -Message ("'{0}' - {1}" -f $Name, $strings['GPO_NotFound'])
    } else {
        Start-Sleep -Milliseconds 500
        $getAdObjectParams = @{
            Identity   = $gpo.Path
            Properties = "gPCFileSysPath"
        }; if (-not [string]::IsNullOrEmpty($Server)) { $getAdObjectParams.Add("Server", $Server) }
        try {
            $gPCFileSysPath = (Get-ADObject @getAdObjectParams).gPCFileSysPath
        } catch {
            do {
                try {
                    Start-Sleep -Milliseconds 500
                    $gPCFileSysPath = (Get-ADObject @getAdObjectParams).gPCFileSysPath
                } catch {
                }
            } while (!(($gPCFileSysPath) -or ($maxWaitTime -lt (Get-Date))))
        }
        $gPCArray = $gPCFileSysPath.split('\')
        $gPCArray[2] = $Server
        $gPCFileSysPath = $gPCArray -join '\'
        do {
            Start-Sleep -Milliseconds 500
        } while (-not ((Test-Path -Path $gPCFileSysPath) -or ($maxWaitTime -lt (Get-Date))))
        $gpo | Add-Member -MemberType NoteProperty -Name gPCFileSysPath -Value $gPCFileSysPath -Force
    }
    return $gpo
}

function Get-MDIGPOLink {
    param(
        [guid] $Guid,
        [Parameter(Mandatory = $false)] [string] $Server,
        [Parameter(Mandatory = $false)]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        [PSCustomObject] $myDomain
    )
    Write-Verbose -Message $strings['GPO_GetLinks']
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $gpoReportParams = @{
        Guid       = $Guid
        ReportType = "Xml"
    }; if (-not [string]::IsNullOrEmpty($Server)) { $gpoReportParams.Add("Server", $Server) }
    if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $gpoReportParams.Add("Domain", $myDomain.DNSRoot) }
    $xml = [xml](Get-GPOReport @gpoReportParams)
    @($xml.GPO.LinksTo)
}

function Test-MDIGPOLink {
    [CmdletBinding()]
    param(
        [guid] $Guid,
        [Parameter(Mandatory = $false)] [string] $Server,
        [Parameter(Mandatory = $false)]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        [PSCustomObject] $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $return = $false
    $gpoParams = @{
        Guid = $Guid
    }
    if ($null -ne $myDomain) {
        $gpoParams.Add("myDomain", $myDomain)
    } else {
        if (-not [string]::IsNullOrEmpty($Server)) { $gpoParams.Add("Server", $Server) }
        if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $gpoParams.Add("Domain", $myDomain.DNSRoot) }
    }

    $enabledLinks = @(Get-MDIGPOLink @gpoParams | Where-Object { $_.Enabled -eq 'true' })
    if ($enabledLinks.Count -lt 1) {
        Write-Verbose -Message ($strings['GPO_NotLinkedOrEnabled'])
    } else {
        $return = $true
        $enabledLinks | ForEach-Object {
            Write-Verbose -Message ($strings['GPO_LinkedAndEnabled'] -f $_.SOMPath)
        }
    }
    $return
}

function Set-MDIGPOLink {
    param(
        [Parameter(Mandatory)] [guid] $Guid,
        [Parameter(Mandatory)] [string] $Target,
        [Microsoft.GroupPolicy.EnableLink] $LinkEnabled = [Microsoft.GroupPolicy.EnableLink]::Yes,
        [Microsoft.GroupPolicy.EnforceLink] $Enforced = [Microsoft.GroupPolicy.EnforceLink]::Yes,
        [Parameter(Mandatory = $false)] [string] $Server,
        [Parameter(Mandatory = $false)]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        [PSCustomObject] $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    Write-Verbose -Message $strings['GPO_SetLink']
    $gpLink = @{
        Guid        = $Guid
        LinkEnabled = $LinkEnabled
        Enforced    = $Enforced
        Target      = $Target
    }; if (-not [string]::IsNullOrEmpty($Server)) { $gpLink.Add("Server", $Server) }
    if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $gpLink.Add("Domain", $myDomain.DNSRoot) }
    $link = New-GPLink @gpLink -ErrorAction SilentlyContinue
    if ($null -eq $link) {
        $link = Set-GPLink @gpLink -ErrorAction SilentlyContinue
    }

    if ($null -eq $link) {
        throw $strings['GPO_UnableToUpdateLink']
    }
}

function Set-MDIGpoApplyPermission {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [guid] $Guid,
        [parameter(Mandatory)] [string]$Identity,
        [parameter(Mandatory)] [ValidateSet("Allow", "Deny")] [string]$PermissionType,
        [Parameter(Mandatory = $false)] [string] $Server,
        [Parameter(Mandatory = $false)]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        [PSCustomObject] $myDomain
    )
    $returnVal = $false
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $domainDn = $myDomain.DistinguishedName
    if ([string]::IsNullOrEmpty($Server)) {
        $gpo = [ADSI]"LDAP://CN=`{$($Guid)`},CN=Policies,CN=System,$domainDn"
    } else {
        $gpo = [ADSI]"LDAP://$Server/CN=`{$($Guid)`},CN=Policies,CN=System,$domainDn"
    }
    if ($null -ne $gpo) {
        $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            [System.Security.Principal.NTAccount]"$($myDomain.NetBIOSName)\$Identity",
            "ExtendedRight",
            $PermissionType,
            [Guid]"edacfd8f-ffb3-11d1-b41d-00a0c968f939"
        )
        $acl = $gpo.ObjectSecurity
        $acl.AddAccessRule($rule) | Out-Null
        try {
            $gpo.CommitChanges() | Out-Null
            $returnVal = $true
        } catch {
            Write-Warning -Message $strings['GPO_UnableToSetPermissions']
            $returnVal = $false
        }
    }
    return $returnVal
}

function Get-MDIGPOMachineVersion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [guid] $Guid,
        [Parameter(Mandatory = $false)] [string] $Server,
        [Parameter(Mandatory = $false)]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        [PSCustomObject] $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $gpoParams = @{
        Guid = $Guid
    }
    if (-not [string]::IsNullOrEmpty($Server)) { $gpoParams.Add("Server", $Server) }
    if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $gpoParams.Add("Domain", $myDomain.DNSRoot) }
    (Get-GPO @gpoParams).Computer | Select-Object -Property *Version
}

function Set-MDIGPOMachineVersion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [guid] $Guid,
        [Parameter(Mandatory)] [int] $Version,
        [Parameter(Mandatory = $false)] [ValidateSet('Sysvol', 'DS', 'All')] [string] $Mode = 'Sysvol',
        [Parameter(Mandatory = $false)] [string] $Server,
        [Parameter(Mandatory = $false)]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        [PSCustomObject] $myDomain
    )
    Write-Verbose -Message $strings['GPO_UpdateVersion']
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    if ($Mode -match 'ALL|DS') {
        $Replace = @{versionNumber = $Version }
        $gpoAdObjectPath = 'CN={0},{1}' -f "{$Guid}", (Get-MDIAdPath -myDomain $myDomain -Path 'CN=Policies,CN=System,{0}')
        $adObjectParams = @{
            Identity = $gpoAdObjectPath
            Replace  = $Replace
        }; if (-not [string]::IsNullOrEmpty($Server)) { $adObjectParams.Add("Server", $Server) }
        Set-ADObject @adObjectParams | Out-Null
    }
    if ($Mode -match 'ALL|Sysvol') {
        if ($Server) {
            $filePath = '\\{0}\SYSVOL\{1}\Policies\{2}\GPT.INI' -f $Server, $myDomain.DNSRoot, "{$guid}"
        } else {
            $filePath = '\\{0}\SYSVOL\{0}\Policies\{1}\GPT.INI' -f $myDomain.DNSRoot, "{$guid}"
        }
        $newContent = (([system.io.file]::ReadAllLines($filePath)) -join [environment]::NewLine) -replace 'Version=\d+', ('Version={0}' -f $version)
        [System.io.file]::WriteAllLines($filePath, $newContent, (New-Object System.Text.ASCIIEncoding))
    }
}

function Get-MDIGPOMachineExtension {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [guid] $Guid,
        [Parameter(Mandatory = $false)] [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        [PSCustomObject] $myDomain
    )
    Write-Verbose -Message $strings['GPO_GetExtension']
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $gpoAdObjectPath = 'CN={0},{1}' -f "{$Guid}", (Get-MDIAdPath -Path 'CN=Policies,CN=System,{0}' -myDomain $myDomain)
    $adObjectParams = @{
        Identity   = $gpoAdObjectPath
        Properties = @("gPCMachineExtensionNames", "VersionNumber")
    }; if (-not [string]::IsNullOrEmpty($Server)) { $adObjectParams.Add("Server", $Server) }
    Get-ADObject @adObjectParams
}

function Set-MDIGPOMachineExtension {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [guid] $Guid,
        [Parameter(Mandatory = $false)] [string[]] $Extension,
        [Parameter(Mandatory = $false)] [string] $RawExtension = $null,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        [PSCustomObject] $myDomain
    )
    Write-Verbose -Message $strings['GPO_SetExtension']
    $return = $null
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    if ([string]::IsNullOrEmpty($RawExtension)) {
        $extensions = $Extension | ForEach-Object { "{$_}" }
        $extensionGuids = '[{0}]' -f [string]::Join('', $extensions)
        $Replace = @{gPCMachineExtensionNames = $extensionGuids }
    } else {
        $Replace = @{gPCMachineExtensionNames = $RawExtension }
    }
    $gpoAdObjectPath = 'CN={0},{1}' -f "{$Guid}", (Get-MDIAdPath -Path 'CN=Policies,CN=System,{0}' -myDomain $myDomain)
    $adObjectParams = @{
        Identity = $gpoAdObjectPath
        Replace  = $Replace
    }; if (-not [string]::IsNullOrEmpty($Server)) { $adObjectParams.Add("Server", $Server) }
    try {
        $gpoUpdated = Set-ADObject @adObjectParams -PassThru
    } catch {
        Write-Verbose -Message $strings['GPO_UnableToSetExtension']
    }
    if ($gpoUpdated) {
        try {
            $gpoVersionParams = @{
                Guid = $Guid
            }; if (-not [string]::IsNullOrEmpty($Server)) { $gpoVersionParams.Add("Server", $Server) }
            $gpoComputerDSVersion = (Get-MDIGPOMachineVersion @gpoVersionParams -myDomain $myDomain).DSVersion
            if ($gpoComputerDSVersion -lt 2) { $gpoComputerDSVersion = 3 } else { $gpoComputerDSVersion++ }
            $setGpoMachineVersionParams = @{
                Guid    = $Guid
                Version = $gpoComputerDSVersion
                Mode    = "All"
            }; if (-not [string]::IsNullOrEmpty($Server)) { $setGpoMachineVersionParams.Add("Server", $Server) }
            Set-MDIGPOMachineVersion @setGpoMachineVersionParams -myDomain $myDomain
            $return = $gpoComputerDSVersion
        } catch {
            Write-Verbose -Message $strings['GPO_UnableToSetExtension']
        }
    }
    $return
}

function Test-MDIGPOEnabledAndLink {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $GPO,
        [Parameter(Mandatory = $false)] [switch] $ManualLinkRequired,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        [PSCustomObject] $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $state = $false
    $testMdiGpoLinkParams = @{
        Guid = $GPO.Id.Guid
    }; if (-not [string]::IsNullOrEmpty($Server)) { $testMdiGpoLinkParams.Add("Server", $Server) }
    if (-not ($GPO.GpoStatus -ne [Microsoft.GroupPolicy.GpoStatus]::AllSettingsDisabled)) {
        Write-Verbose -Message $strings['GPO_SettingsDisabled']
    } else {
        if (-not (Test-MDIGPOLink @testMdiGpoLinkParams -myDomain $myDomain)) {
            if ($ManualLinkRequired) {
                Write-Warning -Message ($strings['GPO_ManualLinkRequired'] -f $GPO.DisplayName)
            }
            Write-Verbose -Message $strings['GPO_LinkNotFound']
        } else {
            $state = $true
        }
    }
    $state
}

#endregion

#region Processor Performance helper functions

function Get-MDIProcessorPerformance {
    & "$($env:SystemRoot)\system32\powercfg.exe" @('/GETACTIVESCHEME')
}

function Test-MDIProcessorPerformance {
    [CmdletBinding()]
    param(
        [switch] $Detailed
    )
    Write-Verbose -Message $strings['ProcessorPerformance_Validate']
    $result = $false
    $activeScheme = Get-MDIProcessorPerformance
    if ($activeScheme -match ':\s+(?<guid>[a-fA-F0-9]{8}[-]?([a-fA-F0-9]{4}[-]?){3}[a-fA-F0-9]{12})\s+\((?<name>.*)\)') {
        $result = $Matches.guid -eq '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
    }
    Write-Verbose -Message (Get-MDIValidationMessage $result)
    if ($Detailed) {
        [PSCustomObject]([ordered]@{
                Status  = $result
                Details = $activeScheme
            })
    } else {
        $result
    }
}

function Set-MDIProcessorPerformance {
    & "$($env:SystemRoot)\system32\powercfg.exe" @('/SETACTIVE', '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c')
}

function Get-MDIProcessorPerformanceGPO {
    [CmdletBinding()]
    param(
        [string] $GpoNamePrefix,
        [Parameter(Mandatory = $false)] [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        [PSCustomObject] $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $gpoName = Get-MDIGPOName -Name $settings.ProcessorPerformance.GpoName -GpoNamePrefix $GpoNamePrefix
    $mdiGpoParams = @{
        Name = $gpoName
    }
    if (-not [string]::IsNullOrEmpty($Server)) { $mdiGpoParams.Add("Server", $Server) }
    if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $mdiGpoParams.Add("Domain", $myDomain.DNSRoot) }
    $gpo = Get-MDIGPO @mdiGpoParams -myDomain $myDomain
    $gpRegValParams = @{
        Guid = $gpo.Id.Guid
        Key  = $settings.ProcessorPerformance.Key
    }
    if (-not [string]::IsNullOrEmpty($Server)) { $gpRegValParams.Add("Server", $Server) }
    if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $gpRegValParams.Add("Domain", $myDomain.DNSRoot) }
    if ($gpo) {
        $gpo | Select-Object -Property *,
        @{N = 'GPRegistryValue'; E = { Get-GPRegistryValue @gpRegValParams } }
    }
}

function Test-MDIProcessorPerformanceGPO {
    [CmdletBinding()]
    param(
        [switch] $Detailed,
        [string] $GpoNamePrefix,
        [Parameter(Mandatory = $false)] [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        [PSCustomObject] $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $gpoName = Get-MDIGPOName -Name $settings.ProcessorPerformance.GpoName -GpoNamePrefix $GpoNamePrefix
    Write-Verbose -Message ($strings['GPO_Validate'] -f $gpoName)
    $processorPerfGpoParams = @{
        GpoNamePrefix = $GpoNamePrefix
    }
    if (-not [string]::IsNullOrEmpty($Server)) { $processorPerfGpoParams.Add("Server", $Server) }
    if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $processorPerfGpoParams.Add("Domain", $myDomain.DNSRoot) }
    $state = $false
    $gpo = Get-MDIProcessorPerformanceGPO @processorPerfGpoParams -myDomain $myDomain
    if ($gpo) {
        $gpSetOk = $gpo.GPRegistryValue.ValueName -eq $settings.ProcessorPerformance.ValueName -and
        $gpo.GPRegistryValue.Value -eq $settings.ProcessorPerformance.SchemeGuid -and
        $gpo.GPRegistryValue.PolicyState -eq [Microsoft.GroupPolicy.PolicyState]::Set
        $mdiGpoTestLinkParams = @{
            GPO = $gpo
        }
        if (-not [string]::IsNullOrEmpty($Server)) { $mdiGpoTestLinkParams.Add("Server", $Server) }
        if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $mdiGpoTestLinkParams.Add("Domain", $myDomain.DNSRoot) }
        if ($gpSetOk) {
            $state = Test-MDIGPOEnabledAndLink @mdiGpoTestLinkParams -myDomain $myDomain
        } else {
            Write-Verbose -Message $strings['GPO_SettingsMismatch']
        }
    }
    Write-Verbose -Message (Get-MDIValidationMessage $state)
    if ($Detailed) {
        [PSCustomObject]([ordered]@{
                Status  = $state
                Details = if ($gpo) { $gpo | Select-Object DisplayName, Id, GpoStatus, GPRegistryValue }
                else { "'{0}' - {1}" -f $gpoName, $strings['GPO_NotFound'] }
            })
    } else {
        $state
    }
}

function Set-MDIProcessorPerformanceGPO {
    [CmdletBinding()]
    param(
        [switch] $SkipGpoLink,
        [switch] $CreateGpoDisabled,
        [string] $GpoNamePrefix,
        [Parameter(Mandatory = $false)] [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        [PSCustomObject] $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $gpoName = Get-MDIGPOName -Name $settings.ProcessorPerformance.GpoName -GpoNamePrefix $GpoNamePrefix
    $gpoParams = @{
        GpoNamePrefix = $GpoNamePrefix
    }; if (-not [string]::IsNullOrEmpty($Server)) { $gpoParams.Add("Server", $Server) }
    if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $gpoParams.Add("Domain", $myDomain.DNSRoot) }
    $gpo = Get-MDIProcessorPerformanceGPO @gpoParams -myDomain $myDomain
    if ($null -eq $gpo) {
        $gpoParams.Add("CreateGpoDisabled", $CreateGpoDisabled)
        $gpoParams.Add("Name", $gpoName)
        $gpoParams.Remove("GpoNamePrefix")
        $gpo = New-MDIGPO -Name $gpoName -myDomain $myDomain -Server $Server -Domain $Domain -CreateGpoDisabled:$CreateGpoDisabled
    }
    if ($gpo) {
        $gppParams = @{
            Guid      = $gpo.Id.Guid
            Type      = 'String'
            Key       = $settings.ProcessorPerformance.Key
            ValueName = $settings.ProcessorPerformance.ValueName
            Value     = $settings.ProcessorPerformance.SchemeGuid
        }; if (-not [string]::IsNullOrEmpty($Server)) { $gppParams.Add("Server", $Server) }
        if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $gppParams.Add("Domain", $myDomain.DNSRoot) }
        try {
            $gpoUpdated = Set-GPRegistryValue @gppParams -ErrorAction SilentlyContinue
            if ($null -eq $gpoUpdated) {
                throw
            }
        } catch {
            if (-not ("Server" -in $gppParams.Keys)) {
                $gppParams.Add("Server", $myDomain.PDCEmulator)
            } else {
                $gppParams.Server = $myDomain.PDCEmulator
            }
            Start-Sleep -Milliseconds 750
            $gpoUpdated = Set-GPRegistryValue @gppParams
        }
        Start-Sleep -Milliseconds 750
        if (-not ($CreateGpoDisabled)) { $gpoUpdated.GpoStatus = [Microsoft.GroupPolicy.GpoStatus]::UserSettingsDisabled }
        $gpoUpdated.MakeAclConsistent()

        if (-not $SkipGpoLink) {
            $gpLinkParams = @{
                Guid        = $gpo.Id.Guid
                LinkEnabled = [Microsoft.GroupPolicy.EnableLink]::Yes
                Enforced    = [Microsoft.GroupPolicy.EnforceLink]::Yes
                Target      = 'OU=Domain Controllers,{0}' -f $myDomain.DistinguishedName
            }; if (-not [string]::IsNullOrEmpty($Server)) { $gpLinkParams.Add("Server", $Server) }
            if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $gpLinkParams.Add("Domain", $myDomain.DNSRoot) }
            Set-MDIGPOLink @gpLinkParams -myDomain $myDomain
        }
    } else {
        throw $strings['GPO_UnableToUpdate']
    }
}

#endregion

#region Directory Services Auditing helper functions

function Get-MDIAdPath {
    param(
        [Parameter(Mandatory)] $Path,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        [PSCustomObject] $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $DefaultNamingContext = (Get-ADRootDSE -Server $Server).defaultNamingContext
    $Path -f $DefaultNamingContext
}

function Get-MDISAcl {
    param(
        [Parameter(Mandatory)] $Path,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    $null = New-PSDrive -Name $($myDomain.netbiosname) -PSProvider ActiveDirectory -Server $myDomain.ChosenDC -Root "//RootDSE/"
    $Path = "$($myDomain.netbiosname):\" + $Path
    $acls = Get-Acl -Path $Path -Audit -ErrorAction Stop
    Remove-PSDrive -Name $($myDomain.netbiosname)
    if ($acls) {
        foreach ($acl in $acls.Audit) {
            [PSCustomObject]@{
                Account                = $acl.IdentityReference.Value
                SecurityIdentifier     = $acl.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                AccessMask             = [int]$acl.ActiveDirectoryRights
                AccessMaskDetails      = $acl.ActiveDirectoryRights
                AuditFlags             = $acl.AuditFlags
                AuditFlagsValue        = [int]$acl.AuditFlags
                InheritedObjectAceType = $acl.InheritedObjectType
                InheritanceType        = [int]$acl.InheritanceType
                PropagationFlags       = [int]$acl.PropagationFlags
            }
        }
    }
}

function Set-MDISAcl {
    param(
        [Parameter(Mandatory)] $Auditing,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    $null = New-PSDrive -Name $($myDomain.netbiosname) -PSProvider ActiveDirectory -Server $myDomain.ChosenDC -Root "//RootDSE/"
    $Path = "$($myDomain.netbiosname):\" + $(Get-MDIAdPath -Path $Auditing.Path -myDomain $myDomain)
    $acls = Get-Acl -Path $Path -Audit -ErrorAction SilentlyContinue
    if ($acls) {
        Write-Verbose -Message $strings['ACL_Set']
        foreach ($audit in $Auditing.Auditing) {
            $account = (New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList @(
                    $audit.SecurityIdentifier)).Translate([System.Security.Principal.NTAccount]).Value
            $argumentList = @(
                [Security.Principal.NTAccount] $account,
                [System.DirectoryServices.ActiveDirectoryRights] $audit.AccessMask,
                [System.Security.AccessControl.AuditFlags] $audit.AuditFlagsValue,
                [guid]::Empty.Guid.ToString(),
                [System.DirectoryServices.ActiveDirectorySecurityInheritance] $audit.InheritanceType,
                [guid] $audit.InheritedObjectAceType
            )
            $rule = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $argumentList
            $acls.AddAuditRule($rule)
        }
        Set-Acl -Path $Path -AclObject $acls
    }
    Remove-PSDrive -Name $($myDomain.netbiosname)
}

function Get-MDIDomainObjectAuditing {
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    try {
        Get-MDISAcl -Path (Get-MDIAdPath -Path $settings.ObjectAuditing.Path -myDomain $myDomain)
    } catch [System.Management.Automation.ActionPreferenceStopException] {
        if ('ObjectNotFound' -eq $_.Exception.ErrorRecord.CategoryInfo.Category) {
            Write-Warning $_.Exception.Message
        } else {
            throw $_
        }
    }
}

function Get-MDIAdfsAuditing {
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    try {
        Get-MDISAcl -Path (Get-MDIAdPath -Path $settings.AdfsAuditing.Path -myDomain $myDomain)
    } catch [System.Management.Automation.ActionPreferenceStopException] {
        if ('ObjectNotFound' -eq $_.Exception.ErrorRecord.CategoryInfo.Category) {
            Write-Warning $_.Exception.Message
        } else {
            throw $_
        }
    }
}

function Get-MDIConfigurationContainerAuditing {
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    try {
        Get-MDISAcl -Path (Get-MDIAdPath -Path $settings.ConfigurationContainerAuditing.Path -myDomain $myDomain)
    } catch [System.Management.Automation.ActionPreferenceStopException] {
        if ('ObjectNotFound' -eq $_.Exception.ErrorRecord.CategoryInfo.Category) {
            Write-Warning $_.Exception.Message
        } else {
            throw $_
        }
    }
}

function Test-MDIAuditing {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [object[]] $ExpectedAuditing,
        [switch] $Detailed,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    try {
        $AppliedAuditing = Get-MDISAcl -Path (Get-MDIAdPath -Path $Path -myDomain $myDomain) -myDomain $myDomain
        $isAuditingOk = @(foreach ($applied in $AppliedAuditing) {
                $ExpectedAuditing | Where-Object { ($_.SecurityIdentifier -eq $applied.SecurityIdentifier) -and
                ($_.AuditFlagsValue -eq $applied.AuditFlagsValue) -and
                ($_.InheritedObjectAceType -eq $applied.InheritedObjectAceType) -and
                ($_.InheritanceType -eq $applied.InheritanceType) -and
                ($_.PropagationFlags -eq $applied.PropagationFlags) -and
                (([System.DirectoryServices.ActiveDirectoryRights]$applied.AccessMask).HasFlag(([System.DirectoryServices.ActiveDirectoryRights]($_.AccessMask)))) }
            }).Count -ge $ExpectedAuditing.Count

    } catch [System.Management.Automation.ActionPreferenceStopException] {
        if ('ObjectNotFound' -eq $_.Exception.ErrorRecord.CategoryInfo.Category) {
            $isAuditingOk = $true
        } else {
            $isAuditingOk = $false
        }
    }
    if ($Detailed) {
        [PSCustomObject]([ordered]@{
                Status  = $isAuditingOk
                Details = $AppliedAuditing
            })
    } else {
        $isAuditingOk
    }
}

function Test-MDIDomainObjectAuditing {
    [CmdletBinding()]
    param(
        [switch] $Detailed,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        $myDomain
    )
    Write-Verbose -Message $strings['DomainObject_ValidateAuditing']
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    $result = Test-MDIAuditing -Path $settings.ObjectAuditing.Path -ExpectedAuditing $settings.ObjectAuditing.Auditing -Detailed:$Detailed -myDomain $myDomain
    if ($Detailed) {
        Write-Verbose -Message (Get-MDIValidationMessage $result.Status)
    } else {
        Write-Verbose -Message (Get-MDIValidationMessage $result)
    }
    $result
}

function Test-MDIAdfsAuditing {
    [CmdletBinding()]
    param(
        [switch] $Detailed,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        $myDomain
    )
    $result = [PSCustomObject]@{
        Status  = $true
        Details = $strings['ADFS_ContainerNotFound']
    }
    Write-Verbose -Message $strings['ADFS_ValidateAuditing']
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ([System.DirectoryServices.DirectoryEntry]::Exists((Get-MDIAdPath -Path $settings.AdfsAuditing.Validate -myDomain $myDomain))) {
        $result = Test-MDIAuditing -Path $settings.AdfsAuditing.Path -ExpectedAuditing $settings.AdfsAuditing.Auditing -Detailed:$Detailed -myDomain $myDomain
    } elseif (-not $Detailed) {
        $result = $true
    }
    if ($Detailed) {
        Write-Verbose -Message (Get-MDIValidationMessage $result.Status)
    } else {
        Write-Verbose -Message (Get-MDIValidationMessage $result)
    }
    $result
}

function Test-MDIConfigurationContainerAuditing {
    [CmdletBinding()]
    param(
        [switch] $Detailed,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        $myDomain
    )
    $result = [PSCustomObject]@{
        Status  = $true
        Details = $strings['Exchange_ContainerNotFound']
    }
    Write-Verbose -Message $strings['Exchange_ValidateAuditing']
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ([System.DirectoryServices.DirectoryEntry]::Exists((Get-MDIAdPath -Path $settings.ConfigurationContainerAuditing.Validate -myDomain $myDomain))) {
        $result = Test-MDIAuditing -Path $settings.ConfigurationContainerAuditing.Path -ExpectedAuditing $settings.ConfigurationContainerAuditing.Auditing -Detailed:$Detailed -myDomain $myDomain
    } elseif (-not $Detailed) {
        $result = $true
    }
    if ($Detailed) {
        Write-Verbose -Message (Get-MDIValidationMessage $result.Status)
    } else {
        Write-Verbose -Message (Get-MDIValidationMessage $result)
    }
    $result
}

function Set-MDIDomainObjectAuditing {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    Set-MDISAcl -Auditing $settings.ObjectAuditing -myDomain $myDomain
}

function Set-MDIAdfsAuditing {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ([System.DirectoryServices.DirectoryEntry]::Exists((Get-MDIAdPath -Path $settings.AdfsAuditing.Validate -myDomain $myDomain))) {
        Set-MDISAcl -Auditing $settings.AdfsAuditing -myDomain $myDomain
    } else {
        Write-Warning $strings['ADFS_ContainerNotFound']
    }
}

function Set-MDIConfigurationContainerAuditing {
    [CmdletBinding()]
    param(
        [switch] $Force,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($Force -or [System.DirectoryServices.DirectoryEntry]::Exists((Get-MDIAdPath -Path $settings.ConfigurationContainerAuditing.Validate -myDomain $myDomain))) {
        Set-MDISAcl -Auditing $settings.ConfigurationContainerAuditing -myDomain $myDomain
    } else {
        Write-Warning $strings['Exchange_ContainerNotFound']
    }
}

#endregion

#region Active Directory Recycle Bin functions

function Get-MDIAdRecycleBin {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $recycleBinParams = @{
        Filter = 'name -like "Recycle Bin Feature"'
    }; if (-not [string]::IsNullOrEmpty($Server)) { $recycleBinParams.Add("Server", $Server) }
    $value = if ((Get-ADOptionalFeature @recycleBinParams).EnabledScopes) { $true } else { $false }
    if ($value) {
        $recycleBinSetting = $strings['DomainRecycleBin_Enabled']
    } else {
        $recycleBinSetting = $strings['DomainRecycleBin_Disabled']
    }
    [PSCustomObject]@{
        Name          = $strings['DomainRecycleBin_Descriptor']
        ActualValue   = $value
        ExpectedValue = $true
    }
}

function Set-MDIAdRecycleBin {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $adGroupParams = @{
        Identity = ($settings.SensitiveGroups["Domain Admins"] -f $($myDomain.DomainSid) )
    }; if (-not [string]::IsNullOrEmpty($Server)) { $adGroupParams.Add("Server", $Server) }
    if (($myDomain.DomainFunctionality) -gt 3 -and ($myDomain.ForestFunctionality) -gt 3) {
        try {
            if ($env:username -in @( (Get-AdGroupMember @adGroupParams  | ForEach-Object { $_.SamAccountName } ) )) {
                $enableAdRecycleBinParams = @{
                    Identity = "CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$($myDomain.DistinguishedName)"
                    Scope    = "ForestOrConfigurationSet"
                    Target   = $env:USERDNSDOMAIN
                }; if (-not [string]::IsNullOrEmpty($Server)) { $enableAdRecycleBinParams.Add("Server", $Server) }
                $null = Enable-ADOptionalFeature @enableAdRecycleBinParams
                Write-Verbose -Message $strings["DomainRecycleBin_EnableSuccess"]
            } else {
                throw
            }
        } catch {
            Write-Warning -Message $strings['DomainRecycleBin_EnableFailed']
        }
    } else {
        Write-Warning -Message $strings['DomainRecycleBin_ForestDomainFail']
    }
}

function Test-MDIAdRecycleBin {
    [CmdletBinding()]
    param(
        [switch] $Detailed,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    Write-Verbose -Message $strings['DomainRecycleBin_Validation']
    $recycleBinParams = @{
        myDomain = $myDomain
    }
    if (-not [string]::IsNullOrEmpty($Server)) { $recycleBinParams.Add("Server", $Server) }
    if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $recycleBinParams.Add("Domain", $myDomain.DNSRoot) }
    $status = [bool](Get-MDIAdRecycleBin @recycleBinParams | Where-Object { $_.ActualValue -eq $_.ExpectedValue })
    if ($status) {
        $recycleBinSetting = $strings['DomainRecycleBin_Enabled']
    } else {
        $recycleBinSetting = $strings['DomainRecycleBin_Disabled']
    }
    Write-Verbose (Get-MDIValidationMessage $status)
    if ($Detailed) {
        [PSCustomObject]([ordered]@{
                Status  = $status
                Details = $recycleBinSetting
            })
    } else {
        $status
    }
}

#endregion

#region RemoteSAM helper functions
function Get-MDIRemoteSAM {
    [CmdletBinding()]
    param(
        [string] $Identity,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $mdiDsaParams = @{
        Identity = $Identity
    }; if (-not [string]::IsNullOrEmpty($Server)) { $mdiDsaParams.Add("Server", $Server) }
    $identitySid = (Get-MDIDSA @mdiDsaParams -myDomain $myDomain).objectSid.value
    $settings.RemoteSAM.RegistrySet.GetEnumerator() | ForEach-Object {
        $name = ($_.Name -split '\\')[-1]
        $path = 'HKLM:\{0}' -f ($_.Name -replace $name)
        $value = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $name
        $expected = $_.Value -f $identitySid
        [PSCustomObject]@{
            Path          = $path
            Name          = $name
            ActualValue   = $value
            ExpectedValue = $expected
        }
    }
}

function Set-MDIRemoteSAM {
    [CmdletBinding()]
    param(
        [string] $Identity,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $mdiDsaParams = @{
        Identity = $Identity
    }; if (-not [string]::IsNullOrEmpty($Server)) { $mdiDsaParams.Add("Server", $Server) }
    $identitySid = (Get-MDIDSA @mdiDsaParams -myDomain $myDomain).objectSid.value
    $settings.RemoteSAM.RegistrySet.GetEnumerator() | ForEach-Object {
        $name = ($_.Name -split '\\')[-1]
        $path = 'HKLM:\{0}' -f ($_.Name -replace $name)
        $value = $_.Value -f $identitySid
        Set-ItemProperty -Path $path -Name $name -Value $value -ErrorAction Stop
    }
}

function Test-MDIRemoteSAM {
    [CmdletBinding()]
    param(
        [switch] $Detailed,
        [string] $Identity,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        $myDomain
    )
    Write-Verbose -Message $strings['RemoteSAM_Validate']
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $mdiRemoteSamParams = @{
        Identity = $Identity
    }; if (-not [string]::IsNullOrEmpty($Server)) { $mdiRemoteSamParams.Add("Server", $Server) }
    $remoteSAMSettings = Get-MDIRemoteSAM @mdiRemoteSamParams -myDomain $myDomain
    $status = @($remoteSAMSettings | Where-Object { $_.ActualValue -match $_.ExpectedValue }).Count -eq $settings.RemoteSAM.RegistrySet.Count
    Write-Verbose (Get-MDIValidationMessage $status)
    if ($Detailed) {
        [PSCustomObject]([ordered]@{
                Status  = $status
                Details = $remoteSAMSettings
            })
    } else {
        $status
    }
}

function Get-MDIRemoteSAMGPO {
    [CmdletBinding()]
    param(
        [string] $GpoNamePrefix,
        [string] $Identity,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $mdiDsaParams = @{
        Identity = $Identity
    }; if (-not [string]::IsNullOrEmpty($Server)) { $mdiDsaParams.Add("Server", $Server) }
    $identitySid = (Get-MDIDSA @mdiDsaParams -myDomain $myDomain).objectSid.value
    $gpoName = Get-MDIGPOName -Name $settings.RemoteSAM.GpoName -GpoNamePrefix $GpoNamePrefix
    $mdiGpoParams = @{
        Name = $gpoName
    }; if (-not [string]::IsNullOrEmpty($Server)) { $mdiGpoParams.Add("Server", $Server) }
    $gpo = Get-MDIGPO @mdiGpoParams -myDomain $myDomain
    if ($gpo) {
        $gpoReportParams = @{
            Guid       = $gpo.Id
            ReportType = "Xml"
        }
        if (-not [string]::IsNullOrEmpty($Server)) { $gpoReportParams.Add("Server", $Server) }
        if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $gpoReportParams.Add("Domain", $myDomain.DNSRoot) }
        $report = [xml](Get-GPOReport @gpoReportParams)

        $options = $report.GPO.Computer.ExtensionData.Extension.SecurityOptions | Where-Object { $_.KeyName -Match 'RestrictRemoteSAM' }
        $RegistryValue = foreach ($opt in $options) {
            $valueName = ($opt.KeyName -split '\\')[-1]
            $path = $opt.KeyName -replace '(.*)\\(\w+)', '$1'
            [PSCustomObject]@{
                KeyName       = $path
                ValueName     = $valueName
                Value         = $opt.Display.DisplayString
                ExpectedValue = (($settings.RemoteSAM.RegistrySet.GetEnumerator() |
                            Where-Object { ('MACHINE\{0}' -f $_.Name) -eq (Join-Path -Path $path -ChildPath $valueName) }).Value -f $identitySid)
            }
        }
        $gpo | Select-Object -Property *, @{N = 'RegistryValue'; E = { $RegistryValue } }
    }
}

function Set-MDIRemoteSAMGPO {
    [CmdletBinding()]
    param(
        [string] $Identity,
        [switch] $SkipGpoLink,
        [switch] $CreateGpoDisabled,
        [string] $GpoNamePrefix,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $mdiDsaParams = @{
        Identity = $Identity
    }; if (-not [string]::IsNullOrEmpty($Server)) { $mdiDsaParams.Add("Server", $Server) }
    $identitySid = (Get-MDIDSA @mdiDsaParams -myDomain $myDomain).objectSid.value
    $gpoName = Get-MDIGPOName -Name $settings.RemoteSAM.GpoName -GpoNamePrefix $GpoNamePrefix
    $mdiGpoParams = @{
        Name = $gpoName
    }; if (-not [string]::IsNullOrEmpty($Server)) { $mdiGpoParams.Add("Server", $Server) }
    $gpo = Get-MDIGPO @mdiGpoParams -myDomain $myDomain
    if ($null -eq $gpo) {
        $mdiGpoParams.Add("CreateGpoDisabled", $CreateGpoDisabled)
        $gpo = New-MDIGPO @mdiGpoParams -myDomain $myDomain
    }

    $filePath = '{0}\Machine\Microsoft\Windows NT\SecEdit' -f $gpo.gPCFileSysPath
    try {
        New-Item -Path $filePath -ItemType Directory -Force | Out-Null
    } catch {}

    $fileContent = @'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[Registry Values]
'@

    $settings.RemoteSAM.GpoRegSet.GetEnumerator() | ForEach-Object {
        $value = $_.Value -f $identitySid
        $fileContent += '{2}MACHINE\{0}={1}' -f $_.Name, $Value, [System.Environment]::NewLine
    }
    [System.Io.File]::WriteAllLines((Join-Path -Path $filePath -ChildPath 'GptTmpl.inf'), $fileContent, (New-Object System.Text.UnicodeEncoding))
    if (-not ($CreateGpoDisabled)) { $gpo.GpoStatus = [Microsoft.GroupPolicy.GpoStatus]::UserSettingsDisabled }
    $gpo.MakeAclConsistent()
    $mdiGpoMachineExtensionParams = @{
        Guid      = $gpo.Id.Guid
        Extension = @($settings.gpoExtensions['Security'], $settings.gpoExtensions['Computer Restricted Groups'])
    }; if (-not [string]::IsNullOrEmpty($Server)) { $mdiGpoMachineExtensionParams.Add("Server", $Server) }
    $gpoUpdated = Set-MDIGPOMachineExtension @mdiGpoMachineExtensionParams -myDomain $myDomain

    $settings.RemoteSAM.DenyGPPermissions.GetEnumerator() | ForEach-Object {
        $adObjectParams = @{
            LDAPFilter = "(objectSid=$($_.Name -f $($myDomain.DomainSid)))"
            Properties = "samaccountname"
        }; if (-not [string]::IsNullOrEmpty($Server)) { $adObjectParams.Add("Server", $Server) }
        $identitySamAccountName = (Get-ADObject @adObjectParams).samaccountname
        $mdiApplyParams = @{
            Guid           = $gpo.Id.Guid
            Identity       = $identitySamAccountName
            PermissionType = "Deny"
        }; if (-not [string]::IsNullOrEmpty($Server)) { $mdiApplyParams.Add("Server", $Server) }
        $gpoAclUpdate = Set-MDIGpoApplyPermission @mdiApplyParams -myDomain $myDomain
        if (-not $gpoAclUpdate) {
            Write-Warning $strings['GPO_UnableToSetPermissions']
        }
    }

    if ($null -ne $gpoUpdated) {
        if (-not $SkipGpoLink) {
            if (-not $SkipGpoLink) {
                Write-Warning -Message ($strings['GPO_ManualLinkRequired'] -f $GPO.DisplayName)
            }
        }
    } else {
        Write-Warning $strings['GPO_UnableToSetExtension']
    }
}

function Test-MDIRemoteSAMGPO {
    [CmdletBinding()]
    param(
        [switch] $Detailed,
        [string] $Identity,
        [string] $GpoNamePrefix,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $gpoName = Get-MDIGPOName -Name $settings.RemoteSAM.GpoName -GpoNamePrefix $GpoNamePrefix
    Write-Verbose -Message ($strings['GPO_Validate'] -f $gpoName)
    $mdiGpoParams = @{
        Identity      = $Identity
        GpoNamePrefix = $GpoNamePrefix
    }; if (-not [string]::IsNullOrEmpty($Server)) { $mdiGpoParams.Add("Server", $Server) }
    $state = $false
    $gpo = Get-MDIRemoteSAMGPO @mdiGpoParams -myDomain $myDomain

    if ($gpo) {
        $gpSetOk = @($gpo.RegistryValue | Where-Object {
                ([string]::Compare($_.Value, $_.ExpectedValue) -eq 0)
            }).Count -eq $settings.RemoteSAM.RegistrySet.Count
        if ($gpSetOk) {
            $mdiGpoCheckParams = @{
                GPO                = $gpo
                ManualLinkRequired = $true
            }; if (-not [string]::IsNullOrEmpty($Server)) { $mdiGpoCheckParams.Add("Server", $Server) }
            $state = Test-MDIGPOEnabledAndLink @mdiGpoCheckParams -myDomain $myDomain
        } else {
            Write-Verbose -Message $strings['GPO_SettingsMismatch']
        }
    }
    Write-Verbose -Message (Get-MDIValidationMessage $state)
    if ($Detailed) {
        $RegistryValue = $gpo.RegistryValue
        [PSCustomObject]([ordered]@{
                Status  = $state
                Details = if ($gpo) { $gpo | Select-Object DisplayName, Id, GpoStatus, @{N = 'RegistryValue'; E = { [string]($gpo.RegistryValue -join ',') } } }
                else { "'{0}' - {1}" -f $gpoName, $strings['GPO_NotFound'] }
            })
    } else {
        $state
    }
}

#endregion

#region EntraConnect Auditing helper functions
function Add-MDIServiceLogonRight {
    [CmdletBinding()]
    param(
        [string] $Identity,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $identitySamAccountName = (Get-MDIDSA -Identity $Identity -myDomain $myDomain).sAMAccountName
    $secPol = Get-MDIServiceLogonRight
    $filePath = '{0}\secpol.inf' -f $env:temp
    $dbPath = '{0}\secpol.db' -f $env:temp
    ($secPol) -replace '^SeServiceLogonRight .+', "`$0,$identitySamAccountName" | Set-Content "$filePath" -Force
    $null = & "$($env:SystemRoot)\system32\secedit.exe" @('/import', '/cfg', "$filePath", '/db', "$dbPath", '/areas', 'USER_RIGHTS', '/overwrite', '/quiet')
    $null = & "$($env:SystemRoot)\system32\secedit.exe" @('/configure', '/cfg', "$filePath", '/db', "$dbPath", '/areas', 'USER_RIGHTS', '/overwrite', '/quiet')
    Remove-Item $filePath -ErrorAction SilentlyContinue
    Remove-Item $dbPath -ErrorAction SilentlyContinue
}

function Get-MDIServiceLogonRight {
    [CmdletBinding()]
    param()
    $filePath = '{0}\secpol.inf' -f $env:temp
    $null = & "$($env:SystemRoot)\system32\secedit.exe" @('/export', '/cfg', "$filePath")
    $content = Get-Content $filePath
    Remove-Item $filePath -ErrorAction SilentlyContinue
    return $content
}

function Get-MDIEntraConnectAuditing {
    [CmdletBinding()]
    param()
    $relevantGUIDs = @($settings.EntraConnectAuditing.AuditSet | ConvertFrom-Csv) | Select-Object -ExpandProperty 'Subcategory GUID' -Unique
    $auditResult = Get-MDIAdvAuditPolicy | Where-Object { $_.'Subcategory GUID' -in $relevantGUIDs }
    $secPol = ((Get-MDIServiceLogonRight) -match 'SeServiceLogonRight')
    return [PSCustomObject](@{
            AuditSettings = $auditResult
            GptSettings   = $secPol
        })
}

function Test-MDIEntraConnectAuditing {
    [CmdletBinding()]
    param(
        [switch] $Detailed,
        [string] $Identity,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        $myDomain
    )
    Write-Verbose -Message $strings['AdvancedPolicyEntra_Validate']
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $mdiDsaParams = @{
        Identity = $Identity
    }; if (-not [string]::IsNullOrEmpty($Server)) { $mdiDsaParams.Add("Server", $Server) }
    $identitySid = (Get-MDIDSA @mdiDsaParams -myDomain $myDomain).objectSid.value
    $existingEntraConnectSettings = Get-MDIEntraConnectAuditing
    $result = Test-MDIAdvAuditPolicy -ExpectedAuditing @($settings.EntraConnectAuditing.AuditSet | ConvertFrom-Csv) -Detailed:$Detailed
    if ($Detailed) {
        Write-Verbose -Message (Get-MDIValidationMessage $result.Status)
    } else {
        Write-Verbose -Message (Get-MDIValidationMessage $result)
    }
    $result | Add-Member -MemberType NoteProperty -Name GptSettings -Value $existingEntraConnectSettings.GptSettings
    $result.Status = $result.status -and ($($result.GptSettings) -match $identitySid)
    return $result
}

function Set-MDIEntraConnectAuditing {
    [CmdletBinding()]
    param(
        [string] $Identity,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        $myDomain
    )
    Write-Verbose -Message $strings['AdvancedPolicyEntra_Set']
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    Add-MDIServiceLogonRight -Identity $Identity -myDomain $myDomain
    $settings.EntraConnectAuditing.AuditSet | ConvertFrom-Csv | ForEach-Object {
        $param = @{
            SubcategoryGUID  = $_.'Subcategory GUID'
            InclusionSetting = $_.'Inclusion Setting'
        }
        Set-MDIAdvAuditPolicy @param
    }
}

function Get-MDIEntraConnectAuditingGPO {
    [CmdletBinding()]
    param(
        [string] $Identity,
        [string] $GpoNamePrefix,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        [PSCustomObject] $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $mdiDsaParams = @{
        Identity = $Identity
    }; if (-not [string]::IsNullOrEmpty($Server)) { $mdiDsaParams.Add("Server", $Server) }
    $identitySid = (Get-MDIDSA @mdiDsaParams -myDomain $myDomain).objectSid.value
    $gpoName = Get-MDIGPOName -Name $settings.EntraConnectAuditing.GpoName -GpoNamePrefix $GpoNamePrefix
    $mdiGpoParams = @{
        Name = $gpoName
    }
    if (-not [string]::IsNullOrEmpty($Server)) { $mdiGpoParams.Add("Server", $Server) }
    if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $mdiGpoParams.Add("Domain", $myDomain.DNSRoot) }
    $gpo = Get-MDIGPO @mdiGpoParams -myDomain $myDomain
    if ($gpo) {
        $gpoReportParams = @{
            Guid       = $gpo.Id
            ReportType = "Xml"
        }
        if (-not [string]::IsNullOrEmpty($Server)) { $gpoReportParams.Add("Server", $Server) }
        if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $gpoReportParams.Add("Domain", $myDomain.DNSRoot) }
        $report = [xml](Get-GPOReport @gpoReportParams)
        $currentSettings = $report.GPO.Computer.ExtensionData.Extension.AuditSetting
        $expectedSettings = $settings.EntraConnectAuditing.AuditSet | ConvertFrom-Csv
        $AuditSettings = foreach ($audit in $expectedSettings) {
            [PSCustomObject]@{
                PolicyTarget    = $audit.'Policy Target'
                SubcategoryName = $audit.'Subcategory'
                SubcategoryGuid = $audit.'Subcategory GUID'
                SettingValue    = $audit.'Setting Value'
                ExpectedValue   = ($currentSettings | Where-Object { -not [string]::IsNullOrEmpty($_) } | Where-Object {
                    ($_.SubcategoryGuid).ToUpper() -eq ($audit.'Subcategory GUID').ToUpper() -and
                        $_.PolicyTarget -eq $audit.'Policy Target' }).SettingValue
            }
        }
        $currentSettings = ($report.GPO.Computer.ExtensionData.Extension.UserRightsAssignment | Where-Object { $_.name -eq 'SeServiceLogonRight' }).member.sid.'#text' | sort
        $expectedSettings = (($settings.EntraConnectAuditing.GptSet['SeServiceLogonRight'] -split ',').trim('*') -f $identitySid) -split ' ' | sort
        $GptSettings = [PSCustomObject]@{
            UserRightsAssignment = 'Logon as a Service'
            SettingValue         = [string]$expectedSettings -join ','
            ExpectedValue        = [string]$(foreach ($gpt in $expectedSettings) { $currentSettings | Where-Object { -not [string]::IsNullOrEmpty($_) } | Where-Object { $_ -eq $gpt } }) -join ','
        }
    }
    $gpo | Select-Object -Property *, @{N = 'AuditSettings'; E = { $AuditSettings } }, @{N = 'GptSettings'; E = { $GptSettings | select SettingValue, ExpectedValue } }
}

function Test-MDIEntraConnectAuditingGPO {
    [CmdletBinding()]
    param(
        [switch] $Detailed,
        [string] $Identity,
        [string] $GpoNamePrefix,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        [PSCustomObject] $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $gpoName = Get-MDIGPOName -Name $settings.EntraConnectAuditing.GpoName -GpoNamePrefix $GpoNamePrefix
    Write-Verbose -Message ($strings['GPO_Validate'] -f $gpoName)
    $mdiGpoParams = @{
        Identity      = $Identity
        GpoNamePrefix = $GpoNamePrefix
    }
    if (-not [string]::IsNullOrEmpty($Server)) { $mdiGpoParams.Add("Server", $Server) }
    if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $mdiGpoParams.Add("Domain", $myDomain.DNSRoot) }
    $state = $false
    $gpo = Get-MDIEntraConnectAuditingGPO @mdiGpoParams -myDomain $myDomain

    if ($gpo) {
        $expectedSettings = @($settings.EntraConnectAuditing.AuditSet | ConvertFrom-Csv)
        $gpSetOk = ((@(($gpo.GptSettings | Where-Object { $_.SettingValue -match $_.ExpectedValue })).count -eq 1)) -and (@($gpo.AuditSettings | Where-Object { $_.SettingValue -match $_.ExpectedValue }).Count -eq $expectedSettings.Count)
        if ($gpSetOk) {
            $mdiGpoCheckParams = @{
                GPO                = $gpo
                ManualLinkRequired = $true
            }
            if (-not [string]::IsNullOrEmpty($Server)) { $mdiGpoCheckParams.Add("Server", $Server) }
            if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $mdiGpoCheckParams.Add("Domain", $myDomain.DNSRoot) }
            $state = Test-MDIGPOEnabledAndLink @mdiGpoCheckParams -myDomain $myDomain
        } else {
            Write-Verbose -Message $strings['GPO_SettingsMismatch']
        }
    }
    Write-Verbose -Message (Get-MDIValidationMessage $state)
    if ($Detailed) {
        [PSCustomObject]([ordered]@{
                Status  = $state
                Details = if ($gpo) { $gpo | Select-Object DisplayName, Id, GpoStatus, @{N = "AuditSettings"; E = { [string]($gpo.AuditSettings -join ',') } }, @{N = "GptSettings"; E = { [string]($gpo.GptSettings -join ',') } } }
                else { "'{0}' - {1}" -f $gpoName, $strings['GPO_NotFound'] }
            })
    } else {
        $state
    }
}

function Set-MDIEntraConnectAuditingGPO {
    [CmdletBinding()]
    param(
        [switch] $SkipGpoLink,
        [string] $Identity,
        [switch] $CreateGpoDisabled,
        [string] $GpoNamePrefix,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        [PSCustomObject] $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $mdiDsaParams = @{
        Identity = $Identity
    }; if (-not [string]::IsNullOrEmpty($Server)) { $mdiDsaParams.Add("Server", $Server) }
    $identitySid = (Get-MDIDSA @mdiDsaParams -myDomain $myDomain).objectSid.value
    if ($null -eq $identitySid) {
        throw
    }
    $gpoName = Get-MDIGPOName -Name $settings.EntraConnectAuditing.GpoName -GpoNamePrefix $GpoNamePrefix
    $mdiGpoParams = @{
        Name = $gpoName
    }
    if (-not [string]::IsNullOrEmpty($Server)) { $mdiGpoParams.Add("Server", $Server) }
    if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $mdiGpoParams.Add("Domain", $myDomain.DNSRoot) }
    $gpo = Get-MDIGPO @mdiGpoParams -myDomain $myDomain
    if ($null -eq $gpo) {
        $mdiGpoParams.Add("CreateGpoDisabled", $CreateGpoDisabled)
        $gpo = New-MDIGPO @mdiGpoParams -myDomain $myDomain
    }

    $filePath = '{0}\Machine\Microsoft\Windows NT\SecEdit' -f $gpo.gPCFileSysPath
    try {
        New-Item -Path $filePath -ItemType Directory -Force | Out-Null
    } catch {}

    $fileContent = @'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[Privilege Rights]
'@

    $settings.EntraConnectAuditing.GptSet.GetEnumerator() | ForEach-Object {
        $fileContent += '{2}{0}={1}' -f $_.Name, $($_.Value -f $identitySid), [System.Environment]::NewLine
    }
    [System.Io.File]::WriteAllLines((Join-Path -Path $filePath -ChildPath 'GptTmpl.inf'), $fileContent, (New-Object System.Text.UTF8Encoding))

    $auditFilePath = '{0}\Machine\Microsoft\Windows NT\Audit' -f $gpo.gPCFileSysPath
    try {
        New-Item -Path $auditFilePath -ItemType Directory -Force | Out-Null
    } catch {}
    [System.io.file]::WriteAllLines((Join-Path -Path $auditFilePath -ChildPath 'audit.csv'), $settings.EntraConnectAuditing.AuditSet, (New-Object System.Text.ASCIIEncoding))

    if (-not ($CreateGpoDisabled)) { $gpo.GpoStatus = [Microsoft.GroupPolicy.GpoStatus]::UserSettingsDisabled }
    $gpo.MakeAclConsistent()
    $stringBuilderGpc = [System.Text.StringBuilder]::new()
    [void]$stringBuilderGpc.Append("{$($settings.gpoExtensions['Security'])}")
    [void]$stringBuilderGpc.Append("{$($settings.gpoExtensions['Computer Restricted Groups'])}")
    $stringBuilderAudit = [System.Text.StringBuilder]::new()
    [void]$stringBuilderAudit.Append("{$($settings.gpoExtensions['Audit Policy Configuration'])}")
    [void]$stringBuilderAudit.Append("{$($settings.gpoExtensions['Audit Configuration Extension'])}")
    $mdiGpoMachineExtensionParams = @{
        Guid         = $gpo.Id.Guid
        RawExtension = '[{0}][{1}]' -f $stringBuilderGpc.ToString(), $stringBuilderAudit.ToString()
    }
    if (-not [string]::IsNullOrEmpty($Server)) { $mdiGpoMachineExtensionParams.Add("Server", $Server) }
    if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $mdiGpoMachineExtensionParams.Add("Domain", $myDomain.DNSRoot) }
    $gpoUpdated = Set-MDIGPOMachineExtension @mdiGpoMachineExtensionParams -myDomain $myDomain

    if ($null -ne $gpoUpdated) {
        if (-not $SkipGpoLink) {
            Write-Warning -Message ($strings['GPO_ManualLinkRequired'] -f $GPO.DisplayName)
        }
    } else {
        Write-Warning $strings['GPO_UnableToSetExtension']
    }
}

#endregion

#region NTLM Auditing helper functions

function Get-MDINTLMAuditing {
    [CmdletBinding()]
    param()
    $settings.NTLMAuditing.RegistrySet.GetEnumerator() | ForEach-Object {
        $name = ($_.Name -split '\\')[-1]
        $path = 'HKLM:\{0}' -f ($_.Name -replace $name)
        $value = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $name
        $expected = $_.Value
        [PSCustomObject]@{
            Path          = $path
            Name          = $name
            ActualValue   = $value
            ExpectedValue = $expected
        }
    }
}

function Test-MDINTLMAuditing {
    [CmdletBinding()]
    param(
        [switch] $Detailed
    )
    Write-Verbose -Message $strings['NTLM_ValidateAuditing']
    $ntlmAuditing = Get-MDINTLMAuditing
    $status = @($ntlmAuditing | Where-Object { $_.ActualValue -match $_.ExpectedValue }).Count -eq $settings.NTLMAuditing.RegistrySet.Count
    Write-Verbose (Get-MDIValidationMessage $status)
    if ($Detailed) {
        [PSCustomObject]([ordered]@{
                Status  = $status
                Details = $ntlmAuditing
            })
    } else {
        $status
    }
}

function Set-MDINTLMAuditing {
    [CmdletBinding()]
    param()
    $settings.NTLMAuditing.RegistrySet.GetEnumerator() | ForEach-Object {
        $name = ($_.Name -split '\\')[-1]
        $path = 'HKLM:\{0}' -f ($_.Name -replace $name)
        $value = ($_.Value -split '\|')[0]
        Set-ItemProperty -Path $path -Name $name -Value $value -ErrorAction Stop
    }
}

function Get-MDINTLMAuditingGPO {
    [CmdletBinding()]
    param(
        [string] $GpoNamePrefix,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        [PSCustomObject] $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $gpoName = Get-MDIGPOName -Name $settings.NTLMAuditing.GpoName -GpoNamePrefix $GpoNamePrefix
    $mdiGpoParams = @{
        Name = $gpoName
    }
    if (-not [string]::IsNullOrEmpty($Server)) { $mdiGpoParams.Add("Server", $Server) }
    if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $mdiGpoParams.Add("Domain", $myDomain.DNSRoot) }
    $gpo = Get-MDIGPO @mdiGpoParams -myDomain $myDomain
    if ($gpo) {
        $gpoReportParams = @{
            Guid       = $gpo.Id
            ReportType = "Xml"
        }
        if (-not [string]::IsNullOrEmpty($Server)) { $gpoReportParams.Add("Server", $Server) }
        if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $gpoReportParams.Add("Domain", $myDomain.DNSRoot) }
        $report = [xml](Get-GPOReport @gpoReportParams)

        $options = $report.GPO.Computer.ExtensionData.Extension.SecurityOptions | Where-Object { $_.KeyName -Match 'AuditReceivingNTLMTraffic|RestrictSendingNTLMTraffic|AuditNTLMInDomain' }
        $RegistryValue = foreach ($opt in $options) {
            $valueName = ($opt.KeyName -split '\\')[-1]
            $path = $opt.KeyName -replace '(.*)\\(\w+)', '$1'
            [PSCustomObject]@{
                KeyName       = $path
                valueName     = $valueName
                Value         = $opt.SettingNumber
                valueDisplay  = $opt.Display.DisplayString
                ExpectedValue = ($settings.NTLMAuditing.RegistrySet.GetEnumerator() |
                        Where-Object { ('MACHINE\{0}' -f $_.Name) -eq (Join-Path -Path $path -ChildPath $valueName) }).Value
            }
        }
        $gpo | Select-Object -Property *, @{N = 'RegistryValue'; E = { $RegistryValue } }
    }
}

function Test-MDINTLMAuditingGPO {
    [CmdletBinding()]
    param(
        [switch] $Detailed,
        [string] $GpoNamePrefix,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        [PSCustomObject] $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $gpoName = Get-MDIGPOName -Name $settings.NTLMAuditing.GpoName -GpoNamePrefix $GpoNamePrefix
    Write-Verbose -Message ($strings['GPO_Validate'] -f $gpoName)
    $mdiGpoParams = @{
        GpoNamePrefix = $GpoNamePrefix
    }
    if (-not [string]::IsNullOrEmpty($Server)) { $mdiGpoParams.Add("Server", $Server) }
    if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $mdiGpoParams.Add("Domain", $myDomain.DNSRoot) }
    $state = $false
    $gpo = Get-MDINTLMAuditingGPO @mdiGpoParams -myDomain $myDomain

    if ($gpo) {
        $gpSetOk = @($gpo.RegistryValue | Where-Object {
                $_.Value -match $_.ExpectedValue
            }).Count -eq $settings.NTLMAuditing.RegistrySet.Count
        if ($gpSetOk) {
            $mdiGpoCheckParams = @{
                GPO = $gpo
            }
            if (-not [string]::IsNullOrEmpty($Server)) { $mdiGpoCheckParams.Add("Server", $Server) }
            if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $mdiGpoCheckParams.Add("Domain", $myDomain.DNSRoot) }
            $state = Test-MDIGPOEnabledAndLink @mdiGpoCheckParams -myDomain $myDomain
        } else {
            Write-Verbose -Message $strings['GPO_SettingsMismatch']
        }
    }
    Write-Verbose -Message (Get-MDIValidationMessage $state)
    if ($Detailed) {
        [PSCustomObject]([ordered]@{
                Status  = $state
                Details = if ($gpo) { $gpo | Select-Object DisplayName, Id, GpoStatus, RegistryValue }
                else { "'{0}' - {1}" -f $gpoName, $strings['GPO_NotFound'] }
            })
    } else {
        $state
    }
}

function Set-MDINTLMAuditingGPO {
    [CmdletBinding()]
    param(
        [switch] $SkipGpoLink,
        [switch] $CreateGpoDisabled,
        [string] $GpoNamePrefix,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        [PSCustomObject] $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $gpoName = Get-MDIGPOName -Name $settings.NTLMAuditing.GpoName -GpoNamePrefix $GpoNamePrefix
    $mdiGpoParams = @{
        Name = $gpoName
    }
    if (-not [string]::IsNullOrEmpty($Server)) { $mdiGpoParams.Add("Server", $Server) }
    if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $mdiGpoParams.Add("Domain", $myDomain.DNSRoot) }
    $gpo = Get-MDIGPO @mdiGpoParams -myDomain $myDomain
    if ($null -eq $gpo) {
        $mdiGpoParams.Add("CreateGpoDisabled", $CreateGpoDisabled)
        $gpo = New-MDIGPO @mdiGpoParams -myDomain $myDomain
    }

    $filePath = '{0}\Machine\Microsoft\Windows NT\SecEdit' -f $gpo.gPCFileSysPath
    try {
        New-Item -Path $filePath -ItemType Directory -Force | Out-Null
    } catch {}

    $fileContent = @'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[Registry Values]
'@

    $settings.NTLMAuditing.RegistrySet.GetEnumerator() | ForEach-Object {
        $value = ($_.Value -split '\|')[0]
        $fileContent += '{2}MACHINE\{0}=4,{1}' -f $_.Name, $Value, [System.Environment]::NewLine
    }
    [System.Io.File]::WriteAllLines((Join-Path -Path $filePath -ChildPath 'GptTmpl.inf'), $fileContent, (New-Object System.Text.UnicodeEncoding))
    if (-not ($CreateGpoDisabled)) { $gpo.GpoStatus = [Microsoft.GroupPolicy.GpoStatus]::UserSettingsDisabled }
    $gpo.MakeAclConsistent()
    $mdiGpoMachineExtensionParams = @{
        Guid      = $gpo.Id.Guid
        Extension = @($settings.gpoExtensions['Security'], $settings.gpoExtensions['Computer Restricted Groups'])
    }
    if (-not [string]::IsNullOrEmpty($Server)) { $mdiGpoMachineExtensionParams.Add("Server", $Server) }
    if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $mdiGpoMachineExtensionParams.Add("Domain", $myDomain.DNSRoot) }
    $gpoUpdated = Set-MDIGPOMachineExtension @mdiGpoMachineExtensionParams -myDomain $myDomain

    if ($null -ne $gpoUpdated) {
        if (-not $SkipGpoLink) {
            $gpLinkParams = @{
                Guid        = $gpo.Id.Guid
                LinkEnabled = [Microsoft.GroupPolicy.EnableLink]::Yes
                Enforced    = [Microsoft.GroupPolicy.EnforceLink]::Yes
                Target      = 'OU=Domain Controllers,{0}' -f $myDomain.DistinguishedName
            }
            if (-not [string]::IsNullOrEmpty($Server)) {
                Start-Sleep -Milliseconds 500
                $gpLinkParams.Add("Server", $Server)
            }
            if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $gpLinkParams.Add("Domain", $myDomain.DNSRoot) }
            Set-MDIGPOLink @gpLinkParams -myDomain $myDomain
        }
    } else {
        Write-Warning $strings['GPO_UnableToSetExtension']
    }
}

#endregion

#region Advanced Auditing Policy helper functions

function Get-MDIAdvAuditPolicySetting {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Guid
    )
    $TypeDefinition = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Audit
{
    public class AuditPol
    {
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U1)]
        public static extern bool AuditQuerySystemPolicy(
            [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1), In]
            Guid[] pSubCategoryGuids,
            uint dwPolicyCount,
            out IntPtr ppAuditPolicy);

        public static IEnumerable<AUDIT_POLICY_INFORMATION> AuditQuerySystemPolicy([In] Guid[] pSubCategoryGuids)
        {
            IntPtr ppAuditPolicy;
            if (!AuditQuerySystemPolicy(pSubCategoryGuids, (uint) pSubCategoryGuids.Length, out ppAuditPolicy))
                return new AUDIT_POLICY_INFORMATION[0];

            return ToIEnum<AUDIT_POLICY_INFORMATION>(ppAuditPolicy, pSubCategoryGuids.Length);
        }

        public static IEnumerable<T> ToIEnum<T>(IntPtr ptr, int count, int prefixBytes = 0)
        {
            if (count != 0 && !(ptr == IntPtr.Zero))
            {
                int stSize = Marshal.SizeOf(typeof(T));
                for (int i = 0; i < count; ++i)
                    yield return ToStructure<T>(new IntPtr(ptr.ToInt64() + prefixBytes + i * stSize));
            }
        }

        public static T ToStructure<T>(IntPtr ptr, long allocatedBytes = -1)
        {
            Type type = typeof(T).IsEnum ? Enum.GetUnderlyingType(typeof(T)) : typeof(T);
            if (allocatedBytes < 0L || allocatedBytes >= (long) Marshal.SizeOf(type))
            {
                return (T) Marshal.PtrToStructure(ptr, type);
            }

            throw new InsufficientMemoryException();
        }

        public struct AUDIT_POLICY_INFORMATION
        {
            public Guid AuditSubCategoryGuid;
            public AuditCondition AuditingInformation;
            public Guid AuditCategoryGuid;
        }

        public enum AuditCondition : uint
        {
            POLICY_AUDIT_EVENT_UNCHANGED = 0,
            POLICY_AUDIT_EVENT_SUCCESS = 1,
            POLICY_AUDIT_EVENT_FAILURE = 2,
            POLICY_AUDIT_EVENT_NONE = 4,
            PER_USER_POLICY_UNCHANGED = 0,
            PER_USER_AUDIT_SUCCESS_INCLUDE = POLICY_AUDIT_EVENT_SUCCESS, // 0x00000001
            PER_USER_AUDIT_SUCCESS_EXCLUDE = POLICY_AUDIT_EVENT_FAILURE, // 0x00000002
            PER_USER_AUDIT_FAILURE_INCLUDE = POLICY_AUDIT_EVENT_NONE, // 0x00000004
            PER_USER_AUDIT_FAILURE_EXCLUDE = 8,
            PER_USER_AUDIT_NONE = 16, // 0x00000010
        }

        public static int GetPolicy(String uid)
        {
            var guid = new Guid(uid);
            var result = AuditQuerySystemPolicy(new[] {guid});
            foreach (var info in result)
            {
                return (int) info.AuditingInformation;
            }
            return -1;
        }
    }
}
'@
    try {
        Add-Type -TypeDefinition $TypeDefinition -Language CSharp
    } catch {
        $result = -1
    } finally {
        $result = [Audit.AuditPol]::GetPolicy($Guid)
    }
    $result
}

function Get-MDIAdvAuditPolicy {
    [CmdletBinding()]
    param()
    & "$($env:SystemRoot)\system32\auditpol.exe" @('/get', '/category:*', '/r') | ConvertFrom-Csv |
        Select-Object *, @{N = 'Setting Value'; E = {
                $setting = Get-MDIAdvAuditPolicySetting(([regex]::Matches((($_[0] -join '')).split(';')[3], '(?<=\{).+?(?=\})').Value))
                $setting
            }
        }
}

function Test-MDIAdvAuditPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]] $ExpectedAuditing,
        [switch] $Detailed
    )
    $AppliedAuditing = Get-MDIAdvAuditPolicy
    $status = @(foreach ($applied in $AppliedAuditing) {
            $ExpectedAuditing | Where-Object {
                (($applied -join '').trim('@').trim('{').trim('}').split(';')[3].split('=')[1]) -eq (($_ -join '').trim('@').trim('{').trim('}').split(';')[3].split('=')[1]) -and
                (($applied -join '').trim('@').trim('{').trim('}').split(';')[6].split('=')[1]) -eq (($_ -join '').trim('@').trim('{').trim('}').split(';')[6].split('=')[1])
            }
        }).Count -ge $ExpectedAuditing.Count
    if ($Detailed) {
        [PSCustomObject]([ordered]@{
                Status  = $status
                Details = $AppliedAuditing
            })
    } else {
        $status
    }
}

function Set-MDIAdvAuditPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $SubcategoryGUID,
        [string] $InclusionSetting
    )
    if ($SubcategoryGUID -notmatch '^{.*}$') { $SubcategoryGUID = "{$SubcategoryGUID}" }
    $success = if ($InclusionSetting -match 'Success') { 'enable' } else { 'disable' }
    $failure = if ($InclusionSetting -match 'Failure') { 'enable' } else { 'disable' }
    $null = & "$($env:SystemRoot)\system32\auditpol.exe" @('/set', "/subcategory:$SubcategoryGUID", "/success:$success", "/failure:$failure")
}

#endregion

#region Advanced Auditing Policy for DCs Settings

function Get-MDIAdvancedAuditPolicyDCsGPO {
    [CmdletBinding()]
    param(
        [string] $GpoNamePrefix,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        [PSCustomObject] $myDomain

    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $gpoName = Get-MDIGPOName -Name $settings.AdvancedAuditPolicyDCs.GpoName -GpoNamePrefix $GpoNamePrefix
    $mdiGpoParams = @{
        Name = $gpoName
    }
    if (-not [string]::IsNullOrEmpty($Server)) { $mdiGpoParams.Add("Server", $Server) }
    if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $mdiGpoParams.Add("Domain", $myDomain.DNSRoot) }
    $gpo = Get-MDIGPO @mdiGpoParams -myDomain $myDomain
    if ($gpo) {
        $gpoReportParams = @{
            Guid       = $gpo.Id
            ReportType = "Xml"
        }
        if (-not [string]::IsNullOrEmpty($Server)) { $gpoReportParams.Add("Server", $Server) }
        if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $gpoReportParams.Add("Domain", $myDomain.DNSRoot) }
        $report = [xml](Get-GPOReport @gpoReportParams)
        $currentSettings = $report.GPO.Computer.ExtensionData.Extension.AuditSetting
        $expectedSettings = $settings.AdvancedAuditPolicyDCs.PolicySettings | ConvertFrom-Csv
        $AuditSettings = foreach ($audit in $expectedSettings) {
            [PSCustomObject]@{
                PolicyTarget    = $audit.'Policy Target'
                SubcategoryName = $audit.'Subcategory'
                SubcategoryGuid = $audit.'Subcategory GUID'
                SettingValue    = $audit.'Setting Value'
                ExpectedValue   = ($currentSettings | Where-Object { -not [string]::IsNullOrEmpty($_) } | Where-Object {
                    ($_.SubcategoryGuid).ToUpper() -eq ($audit.'Subcategory GUID').ToUpper() -and
                        $_.PolicyTarget -eq $audit.'Policy Target' }).SettingValue
            }
        }
        $gpo | Select-Object -Property *, @{N = 'AuditSettings'; E = { $AuditSettings } }
    }
}

function Test-MDIAdvancedAuditPolicyDCsGPO {
    [CmdletBinding()]
    param(
        [switch] $Detailed,
        [string] $GpoNamePrefix,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        [PSCustomObject] $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $gpoName = Get-MDIGPOName -Name $settings.AdvancedAuditPolicyDCs.GpoName -GpoNamePrefix $GpoNamePrefix
    Write-Verbose -Message ($strings['GPO_Validate'] -f $gpoName)
    $state = $false
    $mdiGpoParams = @{
        GpoNamePrefix = $GpoNamePrefix
    }
    if (-not [string]::IsNullOrEmpty($Server)) { $mdiGpoParams.Add("Server", $Server) }
    if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $mdiGpoParams.Add("Domain", $myDomain.DNSRoot) }
    $gpo = Get-MDIAdvancedAuditPolicyDCsGPO @mdiGpoParams -myDomain $myDomain
    if ($gpo) {
        $expectedSettings = @($settings.AdvancedAuditPolicyDCs.PolicySettings | ConvertFrom-Csv)
        $gpSetOk = @($gpo.AuditSettings | Where-Object {
                $_.SettingValue -match $_.ExpectedValue
            }).Count -eq $expectedSettings.Count

        if ($gpSetOk) {
            $mdiGpoCheckParams = @{
                GPO = $gpo
            }
            if (-not [string]::IsNullOrEmpty($Server)) { $mdiGpoCheckParams.Add("Server", $Server) }
            if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $mdiGpoCheckParams.Add("Domain", $myDomain.DNSRoot) }
            $state = Test-MDIGPOEnabledAndLink @mdiGpoCheckParams -myDomain $myDomain
        } else {
            Write-Verbose -Message $strings['GPO_SettingsMismatch']
        }
    }
    Write-Verbose -Message (Get-MDIValidationMessage $state)
    if ($Detailed) {
        [PSCustomObject]([ordered]@{
                Status  = $state
                Details = if ($gpo) { $gpo | Select-Object DisplayName, Id, GpoStatus, AuditSettings }
                else { "'{0}' - {1}" -f $gpoName, $strings['GPO_NotFound'] }
            })
    } else {
        $state
    }
}

function Set-MDIAdvancedAuditPolicyDCsGPO {
    [CmdletBinding()]
    param(
        [switch] $SkipGpoLink,
        [switch] $CreateGpoDisabled,
        [string] $GpoNamePrefix,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        [PSCustomObject] $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $gpoName = Get-MDIGPOName -Name $settings.AdvancedAuditPolicyDCs.GpoName -GpoNamePrefix $GpoNamePrefix
    $mdiGpoParams = @{
        Name = $gpoName
    }
    if (-not [string]::IsNullOrEmpty($Server)) { $mdiGpoParams.Add("Server", $Server) }
    if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $mdiGpoParams.Add("Domain", $myDomain.DNSRoot) }

    $gpo = Get-MDIGPO @mdiGpoParams -myDomain $myDomain
    if ($null -eq $gpo) {
        $mdiGpoParams.Add("CreateGpoDisabled", $CreateGpoDisabled)
        $gpo = New-MDIGPO @mdiGpoParams -myDomain $myDomain
    }

    $filePath = '{0}\Machine\Microsoft\Windows NT\Audit' -f $gpo.gPCFileSysPath
    try {
        New-Item -Path $filePath -ItemType Directory -Force | Out-Null
    } catch {}
    [System.io.file]::WriteAllLines((Join-Path -Path $filePath -ChildPath 'audit.csv'), $settings.AdvancedAuditPolicyDCs.PolicySettings, (New-Object System.Text.ASCIIEncoding))

    if (-not ($CreateGpoDisabled)) { $gpo.GpoStatus = [Microsoft.GroupPolicy.GpoStatus]::UserSettingsDisabled }
    $gpo.MakeAclConsistent()
    $mdiGpoMachineExtensionParams = @{
        Guid      = $gpo.Id.Guid
        Extension = @($settings.gpoExtensions['Audit Policy Configuration'], $settings.gpoExtensions['Audit Configuration Extension'])
    }
    if (-not [string]::IsNullOrEmpty($Server)) { $mdiGpoMachineExtensionParams.Add("Server", $Server) }
    if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $mdiGpoMachineExtensionParams.Add("Domain", $myDomain.DNSRoot) }
    $gpoUpdated = Set-MDIGPOMachineExtension @mdiGpoMachineExtensionParams -myDomain $myDomain

    if ($null -ne $gpoUpdated) {
        if (-not $SkipGpoLink) {
            $gpLinkParams = @{
                Guid        = $gpo.Id.Guid
                LinkEnabled = [Microsoft.GroupPolicy.EnableLink]::Yes
                Enforced    = [Microsoft.GroupPolicy.EnforceLink]::Yes
                Target      = 'OU=Domain Controllers,{0}' -f $myDomain.DistinguishedName
            }
            if (-not [string]::IsNullOrEmpty($Server)) {
                Start-Sleep -Milliseconds 500
                $gpLinkParams.Add("Server", $Server)
            }
            if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $gpLinkParams.Add("Domain", $myDomain.DNSRoot) }
            Set-MDIGPOLink @gpLinkParams -myDomain $myDomain
        }
    } else {
        Write-Warning $strings['GPO_UnableToSetExtension']
    }
}

function Get-MDIAdvancedAuditPolicyDCs {
    [CmdletBinding()]
    param()
    $relevantGUIDs = @($settings.AdvancedAuditPolicyDCs.PolicySettings | ConvertFrom-Csv) | Select-Object -ExpandProperty 'Subcategory GUID' -Unique
    Get-MDIAdvAuditPolicy | Where-Object { $_.'Subcategory GUID' -in $relevantGUIDs }
}

function Test-MDIAdvancedAuditPolicyDCs {
    [CmdletBinding()]
    param(
        [switch] $Detailed
    )
    Write-Verbose -Message $strings['AdvancedPolicyDCs_Validate']
    $result = Test-MDIAdvAuditPolicy -ExpectedAuditing @($settings.AdvancedAuditPolicyDCs.PolicySettings | ConvertFrom-Csv) -Detailed:$Detailed
    if ($Detailed) {
        Write-Verbose -Message (Get-MDIValidationMessage $result.Status)
    } else {
        Write-Verbose -Message (Get-MDIValidationMessage $result)
    }
    $result
}

function Set-MDIAdvancedAuditPolicyDCs {
    Write-Verbose -Message $strings['AdvancedPolicyDCs_Set']
    $settings.AdvancedAuditPolicyDCs.PolicySettings | ConvertFrom-Csv | ForEach-Object {
        $param = @{
            SubcategoryGUID  = $_.'Subcategory GUID'
            InclusionSetting = $_.'Inclusion Setting'
        }
        Set-MDIAdvAuditPolicy @param
    }
}

#endregion

#region Advanced Auditing Policy for CAs Settings

function Get-MDIAdvancedAuditPolicyCAsGPO {
    [CmdletBinding()]
    param(
        [string] $GpoNamePrefix,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        [PSCustomObject] $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $gpoName = Get-MDIGPOName -Name $settings.AdvancedAuditPolicyCAs.GpoName -GpoNamePrefix $GpoNamePrefix
    $mdiGpoParams = @{
        Name = $gpoName
    }
    if (-not [string]::IsNullOrEmpty($Server)) { $mdiGpoParams.Add("Server", $Server) }
    if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $mdiGpoParams.Add("Domain", $myDomain.DNSRoot) }
    $gpo = Get-MDIGPO @mdiGpoParams -myDomain $myDomain
    if ($gpo) {
        $gpoReportParams = @{
            Guid       = $gpo.Id
            ReportType = "Xml"
        }; if (-not [string]::IsNullOrEmpty($Server)) { $gpoReportParams.Add("Server", $Server) }
        if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $gpoReportParams.Add("Domain", $myDomain.DNSRoot) }
        $report = [xml](Get-GPOReport @gpoReportParams)
        $currentSettings = $report.GPO.Computer.ExtensionData.Extension.AuditSetting
        $expectedSettings = $settings.AdvancedAuditPolicyCAs.PolicySettings | ConvertFrom-Csv
        $AuditSettings = foreach ($audit in $expectedSettings) {
            [PSCustomObject]@{
                PolicyTarget    = $audit.'Policy Target'
                SubcategoryName = $audit.'Subcategory'
                SubcategoryGuid = $audit.'Subcategory GUID'
                SettingValue    = $audit.'Setting Value'
                ExpectedValue   = ($currentSettings | Where-Object {
                        $_.SubcategoryName -eq ($audit.Subcategory) -and
                        ($_.SubcategoryGuid).ToUpper() -eq ($audit.'Subcategory GUID').ToUpper() -and
                        $_.PolicyTarget -eq $audit.'Policy Target' }).SettingValue
            }
        }
        $delegation = $settings.AdvancedAuditPolicyCAs.GPPermissions.GetEnumerator() | ForEach-Object {
            $mdiGpPermissionParams = @{
                Guid       = $gpo.Id.Guid
                TargetType = "Group"
                TargetName = Get-MDIADObjectName -SidMask $_.Key -Server $Server -myDomain $myDomain
            }
            if (-not [string]::IsNullOrEmpty($Server)) { $mdiGpPermissionParams.Add("Server", $Server) }
            if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $mdiGpPermissionParams.Add("Domain", $myDomain.DNSRoot) }
            Get-GPPermission @mdiGpPermissionParams
        }
        $gpo = $gpo | Select-Object -Property *, @{N = 'AuditSettings'; E = { $AuditSettings } }, @{N = 'Delegation'; E = { $delegation } }
    }
    $gpo
}

function Test-MDIAdvancedAuditPolicyCAsGPO {
    [CmdletBinding()]
    param(
        [switch] $Detailed,
        [string] $GpoNamePrefix,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        [PSCustomObject] $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $gpoName = Get-MDIGPOName -Name $settings.AdvancedAuditPolicyCAs.GpoName -GpoNamePrefix $GpoNamePrefix
    Write-Verbose -Message ($strings['GPO_Validate'] -f $gpoName)
    $mdiGpoParams = @{
        GpoNamePrefix = $GpoNamePrefix
    }
    if (-not [string]::IsNullOrEmpty($Server)) { $mdiGpoParams.Add("Server", $Server) }
    if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $mdiGpoParams.Add("Domain", $myDomain.DNSRoot) }
    $state = $false
    $gpo = Get-MDIAdvancedAuditPolicyCAsGPO @mdiGpoParams -myDomain $myDomain

    if ($gpo) {
        $expectedSettings = @($settings.AdvancedAuditPolicyCAs.PolicySettings | ConvertFrom-Csv)
        $gpSetOk = @($gpo.AuditSettings | Where-Object {
                $_.SettingValue -match $_.ExpectedValue
            }).Count -eq $expectedSettings.Count

        if ($gpSetOk) {
            $mapping = @{}; $settings.AdvancedAuditPolicyCAs.GPPermissions.GetEnumerator() | ForEach-Object {
                $mapping[(Get-MDIADObjectName -SidMask $_.Key -Server $Server -myDomain $myDomain)] = $_.Key
            }

            $gpDelegationOk = @($gpo.Delegation | Where-Object {
                    $settings.AdvancedAuditPolicyCAs.GPPermissions[$mapping[$_.Trustee.Name]] -eq $_.Permission
                }).Count -eq $settings.AdvancedAuditPolicyCAs.GPPermissions.Count

            if (-not $gpDelegationOk) {
                Write-Verbose -Message $strings['GPO_DelegationMismatch']
            } else {
                $mdiGpoCheckParams = @{
                    GPO = $gpo
                }
                if (-not [string]::IsNullOrEmpty($Server)) { $mdiGpoCheckParams.Add("Server", $Server) }
                if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $mdiGpoCheckParams.Add("Domain", $myDomain.DNSRoot) }
                $state = Test-MDIGPOEnabledAndLink @mdiGpoCheckParams -myDomain $myDomain
            }

        } else {
            Write-Verbose -Message $strings['GPO_SettingsMismatch']
        }
    }
    Write-Verbose -Message (Get-MDIValidationMessage $state)
    if ($Detailed) {
        [PSCustomObject]([ordered]@{
                Status  = $state
                Details = if ($gpo) { $gpo | Select-Object DisplayName, Id, GpoStatus, AuditSettings }
                else { "'{0}' - {1}" -f $gpoName, $strings['GPO_NotFound'] }
            })
    } else {
        $state
    }
}

function Set-MDIAdvancedAuditPolicyCAsGPO {
    [CmdletBinding()]
    param(
        [switch] $SkipGpoLink,
        [switch] $CreateGpoDisabled,
        [string] $GpoNamePrefix,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        [PSCustomObject] $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $gpoName = Get-MDIGPOName -Name $settings.AdvancedAuditPolicyCAs.GpoName -GpoNamePrefix $GpoNamePrefix
    $mdiGpoParams = @{
        Name = $gpoName
    }
    if (-not [string]::IsNullOrEmpty($Server)) { $mdiGpoParams.Add("Server", $Server) }
    if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $mdiGpoParams.Add("Domain", $myDomain.DNSRoot) }
    $gpo = Get-MDIGPO @mdiGpoParams -myDomain $myDomain
    if ($null -eq $gpo) {
        $mdiGpoParams.Add("CreateGpoDisabled", $CreateGpoDisabled)
        $gpo = New-MDIGPO @mdiGpoParams -myDomain $myDomain
    }
    if ($gpo) {
        $filePath = '{0}\Machine\Microsoft\Windows NT\Audit' -f $gpo.gPCFileSysPath
        try {
            Test-Path $filePath | Out-Null
        } catch {
            Start-Sleep 3
        }
        try {
            New-Item -Path $filePath -ItemType Directory -Force | Out-Null
            Start-Sleep -Milliseconds 500
        } catch {}
        [System.io.file]::WriteAllLines((Join-Path -Path $filePath -ChildPath 'audit.csv'), $settings.AdvancedAuditPolicyCAs.PolicySettings, (New-Object System.Text.ASCIIEncoding))

        if (-not ($CreateGpoDisabled)) { $gpo.GpoStatus = [Microsoft.GroupPolicy.GpoStatus]::UserSettingsDisabled }
        $gpo.MakeAclConsistent()
        $mdiGpoMachineExtensionParams = @{
            Guid      = $gpo.Id.Guid
            Extension = @($settings.gpoExtensions['Audit Policy Configuration'], $settings.gpoExtensions['Audit Configuration Extension'])
        }
        if (-not [string]::IsNullOrEmpty($Server)) { $mdiGpoMachineExtensionParams.Add("Server", $Server) }
        if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $mdiGpoMachineExtensionParams.Add("Domain", $myDomain.DNSRoot) }
        $gpoUpdated = Set-MDIGPOMachineExtension @mdiGpoMachineExtensionParams -myDomain $myDomain
        Write-Verbose -Message $strings['GPO_SetDelegation']
        $settings.AdvancedAuditPolicyCAs.GPPermissions.GetEnumerator() | ForEach-Object {
            $TargetName = Get-MDIADObjectName -SidMask $_.Key -Server $Server -myDomain $myDomain
            $PermissionLevel = $($_.Value)
            $mdiGpPermissionParams = @{
                Guid            = $gpo.Id.Guid
                TargetType      = "Group"
                TargetName      = "$TargetName"
                PermissionLevel = "$PermissionLevel"
                Replace         = $true
            }
            if (-not [string]::IsNullOrEmpty($Server)) { $mdiGpPermissionParams.Add("Server", $Server) }
            if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $mdiGpPermissionParams.Add("Domain", $myDomain.DNSRoot) }
            Start-Sleep -Milliseconds 500
            Set-GPPermission @mdiGpPermissionParams | Out-Null
        }

        if ($null -ne $gpoUpdated) {
            if (-not $SkipGpoLink) {
                $gpLinkParams = @{
                    Guid        = $gpo.Id.Guid
                    LinkEnabled = [Microsoft.GroupPolicy.EnableLink]::Yes
                    Enforced    = [Microsoft.GroupPolicy.EnforceLink]::Yes
                    Target      = $myDomain.DistinguishedName
                }
                if (-not [string]::IsNullOrEmpty($Server)) {
                    Start-Sleep -Milliseconds 500
                    $gpLinkParams.Add("Server", $Server)
                }
                if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $gpLinkParams.Add("Domain", $myDomain.DNSRoot) }
                Set-MDIGPOLink @gpLinkParams -myDomain $myDomain
            }
        } else {
            Write-Warning $strings['GPO_UnableToSetExtension']
        }
    }

}

function Get-MDIAdvancedAuditPolicyCAs {
    [CmdletBinding()]
    param()
    $relevantGUIDs = @($settings.AdvancedAuditPolicyCAs.PolicySettings | ConvertFrom-Csv) | Select-Object -ExpandProperty 'Subcategory GUID' -Unique
    Get-MDIAdvAuditPolicy | Where-Object { $_.'Subcategory GUID' -in $relevantGUIDs }
}

function Test-MDIAdvancedAuditPolicyCAs {
    [CmdletBinding()]
    param(
        [switch] $Detailed
    )
    Write-Verbose -Message $strings['AdvancedPolicyCAs_Validate']
    if (Test-MDICAServer) {
        $result = Test-MDIAdvAuditPolicy -ExpectedAuditing @($settings.AdvancedAuditPolicyCAs.PolicySettings | ConvertFrom-Csv) -Detailed:$Detailed
    } else {
        Write-Verbose -Message $strings['CAAuditing_NotCAServer']
        $result = [PSCustomObject]([ordered]@{
                Status  = $true
                Details = $strings['CAAuditing_NotCAServer']
            })
    }

    if ($Detailed) {
        Write-Verbose -Message (Get-MDIValidationMessage $result.Status)
    } else {
        Write-Verbose -Message (Get-MDIValidationMessage $result)
    }
    $result
}

function Set-MDIAdvancedAuditPolicyCAs {
    Write-Verbose -Message $strings['AdvancedPolicyCAs_Set']
    $settings.AdvancedAuditPolicyCAs.PolicySettings | ConvertFrom-Csv | ForEach-Object {
        $param = @{
            SubcategoryGUID  = $_.'Subcategory GUID'
            InclusionSetting = $_.'Inclusion Setting'
        }
        Set-MDIAdvAuditPolicy @param
    }
}

#endregion

#region CA Audit configuration helper functions

function Get-MDICAAuditing {
    [CmdletBinding()]
    param()
    $certSvcConfigPath = $settings.CAAuditing.RegPathActive
    $name = ($certSvcConfigPath -split '\\')[-1]
    $activePath = 'HKLM:\{0}' -f ($certSvcConfigPath -replace $name)
    $activeValue = Get-ItemProperty -Path $activePath -Name $name -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $name

    $settings.CAAuditing.RegistrySet.GetEnumerator() | ForEach-Object {
        $name = ($_.Name -split '\\')[-1]
        $path = 'HKLM:\{0}' -f (($_.Name -replace $name) -f $activeValue)
        $value = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $name
        $expected = $_.Value
        [PSCustomObject]@{
            Path          = $path
            Name          = $name
            ActualValue   = $value
            ExpectedValue = $expected
        }
    }
}

function Test-MDICAAuditing {
    [CmdletBinding()]
    param(
        [switch] $Detailed
    )
    Write-Verbose -Message $strings['CAAuditing_Validate']
    if (Test-MDICAServer) {
        $caAuditing = Get-MDICAAuditing
        $caAuditingOk = @($caAuditing | Where-Object { $_.ActualValue -match $_.ExpectedValue }).Count -eq $settings.CAAuditing.RegistrySet.Count
    } else {
        Write-Verbose -Message $strings['CAAuditing_NotCAServer']
        $caAuditing = $strings['CAAuditing_NotCAServer']
        $caAuditingOk = $true
    }
    Write-Verbose -Message (Get-MDIValidationMessage $caAuditingOk)

    if ($Detailed) {
        [PSCustomObject]([ordered]@{
                Status  = $caAuditingOk
                Details = $caAuditing
            })
    } else {
        $caAuditingOk
    }
}

function Set-MDICAAuditing {
    [CmdletBinding()]
    param(
        [switch] $SkipServiceRestart
    )
    if (Get-Service CertSvc -ErrorAction SilentlyContinue) {
        $certSvcConfigPath = $settings.CAAuditing.RegPathActive
        $name = ($certSvcConfigPath -split '\\')[-1]
        $activePath = 'HKLM:\{0}' -f ($certSvcConfigPath -replace $name)
        $activeValue = Get-ItemProperty -Path $activePath -Name $name -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $name

        $settings.CAAuditing.RegistrySet.GetEnumerator() | ForEach-Object {
            $name = ($_.Name -split '\\')[-1]
            $path = 'HKLM:\{0}' -f (($_.Name -replace $name) -f $activeValue)
            $value = ($_.Value -split '\|')[0]
            Write-Verbose -Message ('Setting {0}{1} to {2}' -f $path, $name, $value)
            Set-ItemProperty -Path $path -Name $name -Value $value -Type DWord -ErrorAction Stop
        }
        if (-not $SkipServiceRestart) { Restart-Service -Name CertSvc -Force -Verbose:$VerbosePreference }
    } else {
        Write-Warning $strings['CAAuditing_NotCAServer']
    }
}

function Get-MDICAAuditingGPO {
    [CmdletBinding()]
    param(
        [string] $GpoNamePrefix,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        [PSCustomObject] $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $gpoName = Get-MDIGPOName -Name $settings.CAAuditing.GpoName -GpoNamePrefix $GpoNamePrefix
    $mdiGpoParams = @{
        Name = $gpoName
    }
    if (-not [string]::IsNullOrEmpty($Server)) { $mdiGpoParams.Add("Server", $Server) }
    if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $mdiGpoParams.Add("Domain", $myDomain.DNSRoot) }
    $gpo = Get-MDIGPO @mdiGpoParams -myDomain $myDomain

    if ($gpo) {
        $params = @{
            Guid      = $gpo.Id
            Context   = 'Computer'
            Key       = 'HKEY_LOCAL_MACHINE\{0}' -f $settings.CAAuditing.GpoReg
            ValueName = ($settings.CAAuditing.GpoVal).Keys[0]
        }
        if (-not [string]::IsNullOrEmpty($Server)) { $params.Add("Server", $Server) }
        if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $params.Add("Domain", $myDomain.DNSRoot) }
        $GPPrefRegistryValue = Get-GPPrefRegistryValue @params -ErrorAction SilentlyContinue
        $delegation = $settings.CAAuditing.GPPermissions.GetEnumerator() | ForEach-Object {
            $mdiGpPermissionParams = @{
                Guid       = $gpo.Id.Guid
                TargetType = "Group"
                TargetName = Get-MDIADObjectName -SidMask $_.Key -Server $Server -myDomain $myDomain
            }
            if (-not [string]::IsNullOrEmpty($Server)) { $mdiGpPermissionParams.Add("Server", $Server) }
            if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $mdiGpPermissionParams.Add("Domain", $myDomain.DNSRoot) }
            Get-GPPermission @mdiGpPermissionParams
        }
        $gpo = $gpo | Select-Object -Property *, @{N = 'GPPrefRegistryValue'; E = { $GPPrefRegistryValue } }, @{N = 'Delegation'; E = { $delegation } }
    }
    $gpo
}

function Test-MDICAAuditingGPO {
    [CmdletBinding()]
    param(
        [switch] $Detailed,
        [string] $GpoNamePrefix,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        [PSCustomObject] $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $gpoName = Get-MDIGPOName -Name $settings.CAAuditing.GpoName -GpoNamePrefix $GpoNamePrefix
    Write-Verbose -Message ($strings['GPO_Validate'] -f $gpoName)
    $state = $false
    $mdiGpoParams = @{
        GpoNamePrefix = $GpoNamePrefix
    }
    if (-not [string]::IsNullOrEmpty($Server)) { $mdiGpoParams.Add("Server", $Server) }
    if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $mdiGpoParams.Add("Domain", $myDomain.DNSRoot) }
    $gpo = Get-MDICAAuditingGPO @mdiGpoParams -myDomain $myDomain
    $gpSetOk = @()

    if ($gpo -and $gpo.GPPrefRegistryValue) {
        $settings.CAAuditing.GpoVal.GetEnumerator() | ForEach-Object {
            $expected = [PSCustomObject]@{
                DisabledDirectly = $false
                Type             = 'DWord'
                Action           = 'Update'
                Hive             = 'LocalMachine'
                FullKeyPath      = 'HKEY_LOCAL_MACHINE\{0}' -f $settings.CAAuditing.GpoReg
                ValueName        = $_.Key
                Value            = $_.Value
            }
            $properties = $expected | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
            $applied = $gpo.GPPrefRegistryValue | Select-Object -Property $properties
            $gpSetOk += ($null -ne (Compare-Object -ReferenceObject $applied -DifferenceObject $expected -Property $properties -IncludeEqual -ExcludeDifferent))
        }

        if (($gpSetOk -eq $false).Count -eq 0) {
            $mapping = @{}; $settings.CAAuditing.GPPermissions.GetEnumerator() | ForEach-Object {
                $mapping[(Get-MDIADObjectName -SidMask $_.Key -Server $Server -myDomain $myDomain)] = $_.Key
            }

            $gpDelegationOk = @($gpo.Delegation | Where-Object {
                    $settings.CAAuditing.GPPermissions[$mapping[$_.Trustee.Name]] -eq $_.Permission
                }).Count -eq $settings.CAAuditing.GPPermissions.Count

            if (-not $gpDelegationOk) {
                Write-Verbose -Message $strings['GPO_DelegationMismatch']
            } else {
                $mdiGpoParams.Add("GPO", $gpo)
                $mdiGpoParams.Remove("GpoNamePrefix")
                $state = Test-MDIGPOEnabledAndLink @mdiGpoParams -myDomain $myDomain
            }

        } else {
            Write-Verbose -Message $strings['GPO_SettingsMismatch']
        }
    }
    Write-Verbose -Message (Get-MDIValidationMessage $state)
    if ($Detailed) {
        [PSCustomObject]([ordered]@{
                Status  = $state
                Details = if ($gpo) { $gpo | Select-Object DisplayName, Id, GpoStatus, GPPrefRegistryValue }
                else { "'{0}' - {1}" -f $gpoName, $strings['GPO_NotFound'] }
            })
    } else {
        $state
    }
}

function Set-MDICAAuditingGPO {
    [CmdletBinding()]
    param(
        [switch] $SkipGpoLink,
        [switch] $CreateGpoDisabled,
        [string] $GpoNamePrefix,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        [PSCustomObject] $myDomain
    )

    $gpoName = Get-MDIGPOName -Name $settings.CAAuditing.GpoName -GpoNamePrefix $GpoNamePrefix
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $mdiGpoParams = @{
        Name = $gpoName
    }
    if (-not [string]::IsNullOrEmpty($Server)) { $mdiGpoParams.Add("Server", $Server) }
    if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $mdiGpoParams.Add("Domain", $myDomain.DNSRoot) }
    $gpo = Get-MDIGPO @mdiGpoParams -myDomain $myDomain

    if ($null -eq $gpo) {
        $mdiGpoParams.Add("CreateGpoDisabled", $CreateGpoDisabled)
        $gpo = New-MDIGPO @mdiGpoParams -myDomain $myDomain
    }

    $settings.CAAuditing.GpoVal.GetEnumerator() | ForEach-Object {
        $params = @{
            Guid      = $gpo.Id
            Context   = 'Computer'
            Key       = 'HKEY_LOCAL_MACHINE\{0}' -f $settings.CAAuditing.GpoReg
            ValueName = $_.Name
            Order     = -1
        }
        if (-not [string]::IsNullOrEmpty($Server)) {
            Start-Sleep -Milliseconds 500
            $params.Add("Server", $Server)
        }
        if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $params.Add("Domain", $myDomain.DNSRoot) }
        if (Get-GPPrefRegistryValue @params -ErrorAction SilentlyContinue) { $gpo = Remove-GPPrefRegistryValue @params }

        $params += @{
            Value  = [int]$_.Value
            Type   = 'DWord'
            Action = 'Update'
        }
        Set-GPPrefRegistryValue @params | Out-Null
    }

    if (-not ($CreateGpoDisabled)) { $gpo.GpoStatus = [Microsoft.GroupPolicy.GpoStatus]::UserSettingsDisabled }
    $gpo.MakeAclConsistent()
    $gpoUpdated = Set-MDIGPOMachineExtension -Server $Server -Domain $myDomain.DNSRoot -myDomain $myDomain -Guid $gpo.Id.Guid -Extension @(
        $settings.gpoExtensions['Preference CSE GUID Registry'], $settings.gpoExtensions['Preference Tool CSE GUID Registry'])

    Write-Verbose -Message $strings['GPO_SetDelegation']
    $settings.CAAuditing.GPPermissions.GetEnumerator() | ForEach-Object {
        $TargetName = Get-MDIADObjectName -SidMask $_.Key -Server $Server -myDomain $myDomain
        $PermissionLevel = $($_.Value)
        $mdiGpPermissionParams = @{
            Guid            = $gpo.Id.Guid
            TargetType      = "Group"
            TargetName      = "$TargetName"
            PermissionLevel = "$PermissionLevel"
            Replace         = $true
        }
        if (-not [string]::IsNullOrEmpty($Server)) { $mdiGpPermissionParams.Add("Server", $Server) }
        if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $mdiGpPermissionParams.Add("Domain", $myDomain.DNSRoot) }
        Start-Sleep -Milliseconds 500
        Set-GPPermission @mdiGpPermissionParams | Out-Null
    }

    if ($null -ne $gpoUpdated) {
        if (-not $SkipGpoLink) {
            $gpLinkParams = @{
                Guid        = $gpo.Id.Guid
                LinkEnabled = [Microsoft.GroupPolicy.EnableLink]::Yes
                Enforced    = [Microsoft.GroupPolicy.EnforceLink]::Yes
                Target      = $myDomain.DistinguishedName
            }
            if (-not [string]::IsNullOrEmpty($Server)) {
                Start-Sleep -Milliseconds 500
                $gpLinkParams.Add("Server", $Server)
            }
            if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $gpLinkParams.Add("Domain", $myDomain.DNSRoot) }
            Set-MDIGPOLink @gpLinkParams -myDomain $myDomain
        }
    } else {
        Write-Warning $strings['GPO_UnableToSetExtension']
    }
}

#endregion

#region Domain helper functions

function Get-MDIDomain {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [PSCustomObject] $myDomain
    )
    if ($null -eq $myDomain) {
        $successServer = $false
        $successPdc = $false
        if ([string]::IsNullOrEmpty($Domain)) {
            $Domain = $env:USERDNSDOMAIN
        }
        if (-not ([string]::IsNullOrEmpty($Server))) {
            if (Test-MDIDC -Server $Server) {
                $successServer = $true
                $chosenDc = $Server
            }
        } else {
            $pdc = Get-ADDomainController -DomainName $Domain -Service primarydc, adws -Discover -ForceDiscover -ErrorAction SilentlyContinue
            if (-not [string]::IsNullOrEmpty(($pdc.HostName))) {
                $successPdc = $true
                $chosenDc = $pdc.HostName[0]
            }
        }
        if ((-not $successServer) -and (-not $successPdc)) {
            $possibleDC = Get-ADDomainController -DomainName $Domain -Service adws -Discover -ForceDiscover
            if (-not [string]::IsNullOrEmpty($possibleDC.HostName)) {
                $chosenDc = $possibleDC.HostName[0]
            }
        }
        try {
            if ([string]::IsNullOrEmpty($chosenDc)) { throw }
            $domainInfo = Get-ADDomain -Server $chosenDc
            $ipTest = [ipaddress]::Any
            if ($null -ne $domainInfo) {
                switch ($chosenDc) {
                    { $([system.net.ipaddress]::tryparse($chosenDc, [ref]$ipTest)) } {
                        $nameHost = (Resolve-DnsName -Name $chosenDc -ErrorAction SilentlyContinue).NameHost
                        if ($nameHost.Contains(".")) {
                            $chosenDcHostName = $nameHost
                        } else {
                            $chosenDcHostName = ('{0}.{1}' -f $nameHost, $domainInfo.DNSRoot)
                        }
                        break
                    }
                    { $(-not $chosenDc.Contains(".")) } {
                        $chosenDcHostName = ('{0}.{1}' -f $chosenDc, $domainInfo.DNSRoot)
                        break
                    }
                    { $($chosenDc.Contains(".")) } {
                        $chosenDcHostName = $chosenDc
                        break
                    }
                }
            }
            $wellKnownObjects = (Get-ADObject -Server $chosenDcHostName -filter 'ObjectClass -eq "domain"' -Properties wellKnownObjects).wellKnownObjects
            $wellKnownObjects | ForEach-Object {
                if ($_ -match '^B:32:A9D1CA15768811D1ADED00C04FD8D5CD:(.*)$') {
                    $usersContainer = $matches[1]
                }
            }
            try {
                $schemaVersion = (Get-MDIDomainSchemaVersion -Server $chosenDcHostName).schemaVersion
            } catch {
                $schemaVersion = $null
            }
            $myDomain = [PSCustomObject][ordered]@{
                ChosenDC                = $chosenDcHostName
                DeletedObjectsContainer = $domainInfo.DeletedObjectsContainer
                DistinguishedName       = $domainInfo.DistinguishedName
                DNSRoot                 = $domainInfo.DNSRoot
                DomainFunctionality     = (([adsi]"LDAP://$chosenDc/rootDSE").properties["domainFunctionality"]).value
                DomainSid               = $domainInfo.DomainSid.value
                Forest                  = $domainInfo.Forest
                ForestFunctionality     = (([adsi]"LDAP://$chosenDc/rootDSE").properties["forestFunctionality"]).value
                ForestSid               = $(try { (Get-ADDomain -server $domainInfo.Forest).DomainSID.value } catch { $null })
                NetBIOSName             = $domainInfo.NetBIOSName
                ParentDomain            = $domainInfo.ParentDomain
                PDCEmulator             = $domainInfo.PDCEmulator
                ReplicaDirectoryServers = $domainInfo.ReplicaDirectoryServers
                SchemaVersion           = $schemaVersion
                UsersContainer          = $usersContainer
            }
            if (-not ($myDomain.ChosenDC -in $myDomain.ReplicaDirectoryServers)) {
                $myDomain.ChosenDC = $myDomain.PDCEmulator
            }
        } catch {
            Write-Warning -Message $strings['DomainControllerUnavailable']
        }
    }
    return $myDomain
}

function Test-MDIDC {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $Server
    )
    & {
        $VerbosePreference = 'SilentlyContinue'
        $returnVal = $false
        try {
            $socket = New-Object -TypeName System.Net.Sockets.TcpClient
            $socket.SendTimeout = 3000
            $socket.ReceiveTimeout = 3000
            $socket.Connect($Server, 9389)
            if ($socket.Connected) {
                $returnVal = $true
            }
            $socket.Close()
        } catch {
            $returnVal = $false
        }
        return $returnVal
    }
}

function Get-MDIDomainSchemaVersion {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)] [string] $Server
    )
    $schemaVersions = @{
        13 = 'Windows 2000 Server'
        30 = 'Windows Server 2003'
        31 = 'Windows Server 2003 R2'
        44 = 'Windows Server 2008'
        47 = 'Windows Server 2008 R2'
        56 = 'Windows Server 2012'
        69 = 'Windows Server 2012 R2'
        87 = 'Windows Server 2016'
        88 = 'Windows Server 2019 / 2022'
        90 = 'Windows Server vNext'
    }
    $schemaNamingContextBind = 'LDAP://{0}/rootDSE' -f $Server
    $schema = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList (
        'LDAP://{0}' -f ([adsi]$schemaNamingContextBind).Properties['schemaNamingContext'].Value
    )
    $schemaVersion = $schema.Properties['objectVersion'].Value

    $return = @{
        schemaVersion = $schemaVersion
        details       = $schemaVersions[$schemaVersion]
    }
    $return
}

function Get-MDIADObjectName {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)] [ValidatePattern('^S-1-\d{1}(-\d+){1,2}$|^\{0\}-\d{3}$')] [string] $SidMask,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(DontShow)]
        [AllowNull()]
        [PSCustomObject] $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $null
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    if ($SidMask -match '^\{0\}-\d{3}$') {
        $sid = $SidMask -f $myDomain.DomainSid
        Get-ADObject -Filter { objectSid -eq $sid } -Server $Server | Select-Object -ExpandProperty Name
    } else {
        (New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $SidMask
            ).Translate([System.Security.Principal.NTAccount]).Value -replace '(.*)\\(.*)', '$2';
    }
}
#endregion

#region DSA helper functions

function Get-MDIDeletedObjectsContainerPermission {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        [PSCustomObject] $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    if ($myDomain.DNSRoot -eq $ENV:USERDNSDOMAIN) {
        $deletedObjectsDN = 'CN=Deleted Objects,{0}' -f $($myDomain.DistinguishedName)
        $output = & "$($env:SystemRoot)\system32\dsacls.exe" @($deletedObjectsDN)
        ($output -join [System.Environment]::NewLine) -split '(?=Allow\s)' | Where-Object { $_ -match 'Allow' } | ForEach-Object {
            if ($_ -match 'Allow\s(?<Identity>(NT AUTHORITY\\\w+)|([^\s]+))\s+(?<Permissions>.*(?:\n\s+.*)*)') {
                [PSCustomObject]@{
                    Identity    = $Matches.Identity
                    Permissions = $Matches.Permissions -split '\s{2,}' | ForEach-Object { $_.Trim() }
                }
            }
        }
    } else {
        Write-Warning $strings['DeletedObjectsPermissions_CrossDomain']
    }

}

function Set-MDIDeletedObjectsContainerPermission {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory = $True, Position = 1)]
        [string]$Identity,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow)]
        [AllowNull()]
        $myDomain
    )
    $returnVal = $false
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($myDomain.DNSRoot -eq $env:USERDNSDOMAIN) {
        if (-not $Identity.Contains('\')) {
            $mdiDsaParams = @{
                Identity = $Identity
            }; if (-not [string]::IsNullOrEmpty($Server)) { $mdiDsaParams.Add("Server", $Server) }
            $mdiDsa = Get-MDIDSA @mdiDsaParams
            $Identity = '{0}\{1}' -f $myDomain.NetBIOSName, $mdiDsa.SamAccountName
        }
        if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
        try {
            $parameters = @{
                ScriptBlock  = {
                    Param ($param1, $param2)
                    $deletedObjectsDN = "\\$Server\CN=Deleted Objects,{0}" -f $param1
                    $params = @("$deletedObjectsDN", '/takeOwnership')
                    & "$($env:SystemRoot)\system32\dsacls.exe" $params
                    $params = @("$deletedObjectsDN", '/G', "$($param2):LCRP")
                    & "$($env:SystemRoot)\system32\dsacls.exe" $params
                }
                ArgumentList = $($myDomain.distinguishedName), $Identity
            }
            $command = "Invoke-command @parameters"
            $dsaclCheck = Invoke-Expression $command
            $returnVal = $true
        } catch {
            Write-Error $strings['DeletedObjectsPermissions_StatusFail']
        }
    } else {
        Write-Warning $strings['DeletedObjectsPermissions_CrossDomain']
    }
    return $returnVal
}

function Test-MDIDeletedObjectsContainerPermission {
    [CmdletBinding(DefaultParameterSetName = 'SingleIdentity')]
    param (
        [parameter(Mandatory = $True, ParameterSetName = 'SingleIdentity')]
        [string]$Identity,
        [parameter(Mandatory = $True, ParameterSetName = 'MultipleIdentities')]
        [string[]]$msDSPrincipalNamesToCheck,
        [Parameter(Mandatory = $false, ParameterSetName = 'SingleIdentity')]
        [Parameter(Mandatory = $false, ParameterSetName = 'MultipleIdentities')]
        [switch] $Detailed,
        [Parameter(Mandatory = $false, ParameterSetName = 'SingleIdentity')]
        [Parameter(Mandatory = $false, ParameterSetName = 'MultipleIdentities')]
        [AllowEmptyString()]
        [string] $Server,
        [Parameter(Mandatory = $false, ParameterSetName = 'SingleIdentity')]
        [Parameter(Mandatory = $false, ParameterSetName = 'MultipleIdentities')]
        [AllowEmptyString()]
        [string] $Domain,
        [Parameter(DontShow, ParameterSetName = 'SingleIdentity')]
        [Parameter(DontShow, ParameterSetName = 'MultipleIdentities')]
        [AllowNull()]
        [PSCustomObject] $myDomain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($myDomain.DNSRoot -eq $env:USERDNSDOMAIN) {
        if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
        if ($PSCmdlet.ParameterSetName -eq 'SingleIdentity') {
            $mdiDsaParams = @{
                Identity = $Identity
            }; if (-not [string]::IsNullOrEmpty($Server)) { $mdiDsaParams.Add("Server", $Server) }
            $mdiDsa = Get-MDIDSA @mdiDsaParams
            $msDSPrincipalNamesToCheck = @()
            $msDSPrincipalNamesToCheck += $mdiDsa.'msDS-PrincipalName'
        }
        $appliedAsExpected = $false
        $expectedDsacls = @('SPECIAL ACCESS', 'LIST CONTENTS', 'READ PROPERTY')
        $appliedDsacls = Get-MDIDeletedObjectsContainerPermission -myDomain $myDomain
        if ([string]::IsNullOrEmpty($appliedDsacls)) {
            Write-Warning -Message $strings['DSA_CannotReadDeletedObjectsContainer']
        } else {
            $dsaDsacls = $appliedDsacls | Where-Object { $msDSPrincipalNamesToCheck -contains $_.Identity } | Select-Object -ExpandProperty Permissions
            if ($null -eq $dsaDsacls) {
                $dsaDsacls = $strings['DSA_DeletedObjectsPermissionNotFound']
            } else {
                $dsaDsacls = $dsaDsacls | Select-Object -Unique
                $appliedAsExpected = (Compare-Object -ReferenceObject $dsaDsacls -DifferenceObject $expectedDsacls -IncludeEqual -ExcludeDifferent).Count -eq $expectedDsacls.Count
            }
        }
        $return = [PSCustomObject][ordered]@{
            Test    = 'DeletedObjectsContainerPermission'
            Status  = $appliedAsExpected
            Details = $dsaDsacls
        }
    } else {
        Write-Warning $strings['DeletedObjectsPermissions_CrossDomain']
        $return = [PSCustomObject][ordered]@{
            Test    = 'DeletedObjectsContainerPermission'
            Status  = $false
            Details = $strings['DSA_CannotReadDeletedObjectsContainer']
        }
    }
    if ($Detailed) {
        return $return
    } else {
        return $return.status
    }
}

function Test-MDIDSA {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $Identity,
        [switch] $Detailed,
        [Parameter(Mandatory = $false)]
        [string] $Server,
        [Parameter(Mandatory = $false)]
        [string] $Domain
    )
    $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
    if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
    $return = @()
    $mdiDsaParams = @{
        Identity = $Identity
    }; if (-not [string]::IsNullOrEmpty($Server)) { $mdiDsaParams.Add("Server", $Server) }
    $account = (Get-MDIDSA @mdiDsaParams -myDomain $myDomain)
    if ($null -eq $account) {
        $return += [PSCustomObject][ordered]@{
            Test    = 'AccountExists'
            Status  = $false
            Details = $strings['ServiceAccount_NotFound']
        }
    } else {

        Write-Verbose -Message $strings['DSA_TestGroupMembership']
        $memberOf = @{}
        $filter = '(&(objectCategory=group)(objectClass=group)(member:1.2.840.113556.1.4.1941:={0}))' -f $account.DistinguishedName
        $searcher = [adsisearcher]$filter
        'objectSid', 'distinguishedName', 'msDS-PrincipalName' | ForEach-Object { [void]($searcher.PropertiesToLoad.Add($_)) }
        $searcher.FindAll() | ForEach-Object {
            $memberOf.Add($_.Properties['distinguishedname'][0],
                [PSCustomObject]@{
                    'objectSid'          = (New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList @($_.Properties['objectSid'][0], 0)).Value
                    'msDS-PrincipalName' = $_.Properties['msDS-PrincipalName'][0]
                })
        }

        $domainSid = $myDomain.DomainSid
        $forestSid = $myDomain.ForestSid
        $sensitiveGroups = @{}
        $settings.SensitiveGroups.GetEnumerator() | ForEach-Object {
            if ($_.key -match "Enterprise Admins" -or $_.key -match "Schema Admins") {
                $sensitiveGroups.Add(($_.Value -f $forestSid), $_.Key)
            } else {
                $sensitiveGroups.Add(($_.Value -f $domainSid), $_.Key)
            }
        }

        $sensitiveGroupsMembership = @(
            $memberOf.GetEnumerator() | Where-Object {
                $sensitiveGroups.ContainsKey($_.Value.objectSid)
            } | Select-Object -ExpandProperty Name
        )
        $return += [PSCustomObject][ordered]@{
            Test    = 'SensitiveGroupsMembership'
            Status  = $sensitiveGroupsMembership.Count -eq 0
            Details = $sensitiveGroupsMembership
        }

        Write-Verbose -Message $strings['DSA_TestDelegation']
        $sidsToCheck = @($account.ObjectSid.Value)
        $sidsToCheck += ($memberOf.GetEnumerator() | Where-Object {
                $sensitiveGroupsMembership -notcontains $_.Key }).Value.Value

        $filter = '(|(objectClass=domain)(objectClass=organizationalUnit)(objectClass=group))'
        $searcher = [adsisearcher]"LDAP://$($myDomain.ChosenDC)/$($myDomain.DistinguishedName)"
        $searcher.Filter = $filter
        $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
        $delegatedObjects = $searcher.FindAll() | ForEach-Object {
            $de = $_.GetDirectoryEntry()
            $permissions = $de.PsBase.ObjectSecurity.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])
            if ($permissions | Where-Object { ($_.AccessControlType -eq 'Allow') -and ($sidsToCheck -contains $_.IdentityReference.Value) }) {
                $de.distinguishedName.Value
            }
        }
        $return += [PSCustomObject][ordered]@{
            Test    = 'ExplicitDelegation'
            Status  = $delegatedObjects.Count -eq 0
            Details = @($delegatedObjects | Select-Object -Unique)
        }

        Write-Verbose -Message $strings['DSA_TestDeletedObjectsAccess']
        $msDSPrincipalNamesToCheck = @($memberOf.GetEnumerator() | ForEach-Object { $_.Value.'msDS-PrincipalName' })
        $msDSPrincipalNamesToCheck += $account.'msDS-PrincipalName'
        $return += Test-MDIDeletedObjectsContainerPermission -myDomain $myDomain -msDSPrincipalNamesToCheck $msDSPrincipalNamesToCheck -Detailed

        if ($account.ObjectClass -eq 'user') {
            Write-Verbose -Message $strings['DSA_TestManager']
            $filter = '(|(managedBy={0})(manager={0}))' -f ($account.DistinguishedName -replace '\s', '\20')
            $searcher = [adsisearcher]"LDAP://$($myDomain.ChosenDC)/$($myDomain.DistinguishedName)"
            $searcher.Filter = $filter
            $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
            $managerOf = $searcher.FindAll()
            $return += [PSCustomObject][ordered]@{
                Test    = 'ManagerOf'
                Status  = $managerOf.Count -eq 0
                Details = @($managerOf | ForEach-Object { $_.Properties['distinguishedname'] })
            }
        } else {
            Write-Warning $strings['DSA_SkipGmsaTests']
            Write-Verbose -Message $strings['DSA_TestPasswordRetrieval']
            try {
                if ($env:USERDNSDOMAIN -eq $myDomain.DNSRoot) {
                    $pwdCheck = Test-ADServiceAccount -Identity $($account.samaccountname)
                    $return += [PSCustomObject][ordered]@{
                        Test    = 'PasswordRetrieval'
                        Status  = $pwdCheck
                        Details = $null
                    }
                } else {
                    Write-Warning $strings['DSA_CannotTestGMSAAccount']
                    throw
                }
            } catch {
                $return += [PSCustomObject][ordered]@{
                    Test    = 'PasswordRetrieval'
                    Status  = $false
                    Details = $null
                }
            }
        }

    }
    $overallStatus = ($return.Status -eq $false).Count -eq 0
    if (-not $Detailed) { $overallStatus }
    else { $return }
    Write-Verbose -Message (Get-MDIValidationMessage $overallStatus)
}

#endregion

#region Connectivity helper functions

function Test-MDISensorApiConnection {
    [CmdletBinding(DefaultParameterSetName = 'UseCurrentConfiguration')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'BypassConfiguration')]
        [switch] $BypassConfiguration,

        [Parameter(Mandatory = $true, ParameterSetName = 'BypassConfiguration')]
        [string] $SensorApiUrl,

        [Parameter(Mandatory = $true, ParameterSetName = 'BypassConfiguration')]
        [ValidateSet('Classic', 'Unified')]
        [string] $SensorType,

        [Parameter(Mandatory = $false, ParameterSetName = 'BypassConfiguration')]
        [string] $ProxyUrl,

        [Parameter(Mandatory = $false, ParameterSetName = 'BypassConfiguration')]
        [PSCredential] $ProxyCredential
    )

    $protocol = @{
        80  = 'http'
        443 = 'https'
    }

    if ($PSCmdlet.ParameterSetName -eq 'BypassConfiguration') {
        if ($SensorType -eq 'Classic') {
            $sensorApiPath = 'tri/sensor/api/ping'
        } else {
            $sensorApiPath = 'cnc/identity/api'
        }
        $params = @{ URI = '{0}/{1}' -f $SensorApiUrl, $sensorApiPath }
        if ($ProxyUrl) { $params.Add('Proxy', $ProxyUrl) }
        if ($ProxyCredential) { $params.Add('ProxyCredential', $ProxyCredential) }
    } else {
        $sensorProcesses = Get-MDISensorProcessInformation
        $sensorConfiguration = Get-MDISensorConfiguration
        if ($sensorProcesses.SenseIdentity -eq 'Running') {
            $sensorApiPath = 'cnc/identity/api'
            $URI = '{0}{1}' -f $sensorConfiguration.geoLocationUrl, $sensorApiPath
        } else {
            $sensorApiPath = 'tri/sensor/api/ping'
            $URI = '{0}://{1}' -f $protocol[$sensorConfiguration.WorkspaceApplicationSensorApiWebClientConfigurationServiceEndpoint.Port],
            $sensorConfiguration.WorkspaceApplicationSensorApiWebClientConfigurationServiceEndpoint.Address
        }
        if ([string]::IsNullOrEmpty($sensorConfiguration)) {
            Write-Error $strings['Sensor_ErrorReadingSensorConfiguration'] -ErrorAction Stop
        } else {
            $params = @{
                URI = $URI
            }
            $params.Add("UseBasicParsing", $true)
            if ($sensorConfiguration.SensorProxyConfiguration.IsProxyEnabled) {
                $params.Add('Proxy', $sensorConfiguration.SensorProxyConfiguration.Url)

                if ($sensorConfiguration.SensorProxyConfiguration.IsAuthenticationProxyEnabled) {
                    $decryptParams = @{
                        CertificateThumbprint = $sensorConfiguration.SensorProxyConfiguration.CertificateThumbprint
                        EncryptedString       = $sensorConfiguration.SensorProxyConfiguration.EncryptedUserPasswordData
                    }
                    $passwd = Get-MDIDecryptedPassword @decryptParams
                    $proxyCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList @(
                        $sensorConfiguration.SensorProxyConfiguration.UserName,
                        ($passwd | ConvertTo-SecureString -AsPlainText -Force)
                    )
                    $params.Add('ProxyCredential', $proxyCredential)
                }
            }
        }
    }
    try {
        if ($params.URI -notmatch "$sensorApiPath`$") {
            $params.URI = '{0}/{1}' -f $params.URI, $sensorApiPath
        }
        $response = Invoke-WebRequest @params
        if ($params.URI -match "(\/tri\/sensor\/api\/ping)$") {
            (200 -eq $response.StatusCode)
        } else {
            throw
        }
    } catch {
        if (($params.URI -match "(\/cnc\/identity\/api)$") -and ($_.Exception.Response.StatusCode -eq 'InternalServerError')) {
            $true
        } else {
            Write-Verbose -Message $_.Exception.Message
            $false
        }
    }
}

#endregion

#region Post deployment configuration helper functions

function Use-MDIConfigName {
    param(
        [Parameter(Mandatory)] [string[]] $Configuration,
        [Parameter(Mandatory)] [string[]] $ActionItem
    )
    $ActionItem += 'All'
    @(Compare-Object -ReferenceObject $Configuration -DifferenceObject $ActionItem -ExcludeDifferent -IncludeEqual).Count -gt 0
}

function Get-MDIConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [ValidateSet('Domain', 'LocalMachine')] [string] $Mode,
        [Parameter(Mandatory = $true)] [ValidateSet('AdfsAuditing', 'AdRecycleBin', 'AdvancedAuditPolicyCAs', 'AdvancedAuditPolicyDCs',
            'CAAuditing', 'ConfigurationContainerAuditing', 'DeletedObjectsContainerPermission', 'DomainObjectAuditing', 'EntraConnectAuditing', 'NTLMAuditing', 'ProcessorPerformance', 'RemoteSAM', 'All')] [string[]] $Configuration
    )
    DynamicParam {
        $paramDictionary = New-Object -Type System.Management.Automation.RuntimeDefinedParameterDictionary
        $paramAttributes = New-Object -Type System.Management.Automation.ParameterAttribute
        $paramAttributes.Mandatory = $false
        $paramAttributesCollect = New-Object -Type System.Collections.ObjectModel.Collection[System.Attribute]
        $paramAttributesCollect.Add($paramAttributes)
        $dynParam1 = New-Object -Type System.Management.Automation.RuntimeDefinedParameter("GpoNamePrefix", [string], $paramAttributesCollect)
        $paramAttributes = New-Object -Type System.Management.Automation.ParameterAttribute
        $paramAttributes.Mandatory = $false
        $paramAttributesCollect = New-Object -Type System.Collections.ObjectModel.Collection[System.Attribute]
        $paramAttributesCollect.Add($paramAttributes)
        $dynParam3 = New-Object -Type System.Management.Automation.RuntimeDefinedParameter("Server", [string], $paramAttributesCollect)
        $paramAttributes = New-Object -Type System.Management.Automation.ParameterAttribute
        $paramAttributes.Mandatory = $true
        $paramAttributesCollect = New-Object -Type System.Collections.ObjectModel.Collection[System.Attribute]
        $paramAttributesCollect.Add($paramAttributes)
        $dynParamIdentity = New-Object -Type System.Management.Automation.RuntimeDefinedParameter("Identity", [string], $paramAttributesCollect)
        $paramAttributes = New-Object -Type System.Management.Automation.ParameterAttribute
        $paramAttributes.Mandatory = $false
        $paramAttributesCollect = New-Object -Type System.Collections.ObjectModel.Collection[System.Attribute]
        $paramAttributesCollect.Add($paramAttributes)
        $dynParam4 = New-Object -Type System.Management.Automation.RuntimeDefinedParameter("Domain", [string], $paramAttributesCollect)
        if ($Mode -eq 'Domain') {
            $paramDictionary.Add("GpoNamePrefix", $dynParam1)
            $paramDictionary.Add("Domain", $dynParam4)
            $paramDictionary.Add("Server", $dynParam3)
        }
        if ([bool](($($Configuration -join ',')) -match 'DeletedObjectsContainerPermission|EntraConnectAuditing|RemoteSAM|All')) {
            $paramDictionary.Add("Identity", $dynParamIdentity)
        }
        return $paramDictionary
    }
    begin {
        foreach ($key in $PSBoundParameters.Keys) {
            if ($MyInvocation.MyCommand.Parameters.$key.isDynamic) {
                Set-Variable -Name $key -Value $PSBoundParameters.$key
            }
        }
    }
    process {
        if ($Mode -eq 'Domain') {
            $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
            if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
            $mdiParams = @{
                Detailed      = $true
                GpoNamePrefix = $GpoNamePrefix
            }
            if (-not [string]::IsNullOrEmpty($Server)) { $mdiParams.Add("Server", $Server) }
            if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $mdiParams.Add("Domain", $myDomain.DNSRoot) }
            if ($null -ne $myDomain) { $mdiParams.Add("myDomain", $myDomain) }
        }
        $results = @{}
        if (Use-MDIConfigName $Configuration 'AdfsAuditing') {
            $results.Add('AdfsAuditing', (Test-MDIAdfsAuditing -Detailed -myDomain $myDomain))
        }
        if (Use-MDIConfigName $Configuration 'AdRecycleBin') {
            $adRecycleBinParams = @{
                Detailed = $true
            }; if (-not [string]::IsNullOrEmpty($Server)) { $adRecycleBinParams.Add("Server", $Server) }
            if ($null -ne $myDomain) { $adRecycleBinParams.Add("myDomain", $myDomain) }
            $results.Add('AdRecycleBin', (Test-MDIAdRecycleBin @adRecycleBinParams))
        }
        if (Use-MDIConfigName $Configuration 'AdvancedAuditPolicyCAs') {
            if ($Mode -eq 'LocalMachine') {
                $results.Add('AdvancedAuditPolicyCAs', (Test-MDIAdvancedAuditPolicyCAs -Detailed))
            } else {
                $results.Add('AdvancedAuditPolicyCAs', (Test-MDIAdvancedAuditPolicyCAsGPO @mdiParams))
            }
        }
        if (Use-MDIConfigName $Configuration 'AdvancedAuditPolicyDCs') {
            if ($Mode -eq 'LocalMachine') {
                $results.Add('AdvancedAuditPolicyDCs', (Test-MDIAdvancedAuditPolicyDCs -Detailed))
            } else {
                $results.Add('AdvancedAuditPolicyDCs', (Test-MDIAdvancedAuditPolicyDCsGPO @mdiParams))
            }
        }
        if (Use-MDIConfigName $Configuration 'CAAuditing') {
            if ($Mode -eq 'LocalMachine') {
                $results.Add('CAAuditing', (Test-MDICAAuditing -Detailed))
            } else {
                $results.Add('CAAuditing', (Test-MDICAAuditingGPO @mdiParams))
            }
        }
        if (Use-MDIConfigName $Configuration 'ConfigurationContainerAuditing') {
            $results.Add('ConfigurationContainerAuditing', (Test-MDIConfigurationContainerAuditing -Detailed -myDomain $myDomain))
        }
        if (Use-MDIConfigName $Configuration 'DeletedObjectsContainerPermission') {
            $results.Add('DeletedObjectsContainerPermission', (Test-MDIDeletedObjectsContainerPermission -Detailed -myDomain $myDomain -Identity $Identity))
        }
        if (Use-MDIConfigName $Configuration 'DomainObjectAuditing') {
            $results.Add('DomainObjectAuditing', (Test-MDIDomainObjectAuditing -Detailed -myDomain $myDomain))
        }
        if (Use-MDIConfigName $Configuration 'EntraConnectAuditing') {
            if ($Mode -eq 'LocalMachine') {
                $results.Add('EntraConnectAuditing', (Test-MDIEntraConnectAuditing -Detailed -Identity $Identity))
            } else {
                $results.Add('EntraConnectAuditing', (Test-MDIEntraConnectAuditingGPO @mdiParams -Identity $Identity))
            }
        }
        if (Use-MDIConfigName $Configuration 'NTLMAuditing') {
            if ($Mode -eq 'LocalMachine') {
                $results.Add('NTLMAuditing', (Test-MDINTLMAuditing -Detailed))
            } else {
                $results.Add('NTLMAuditing', (Test-MDINTLMAuditingGPO @mdiParams))
            }
        }
        if (Use-MDIConfigName $Configuration 'ProcessorPerformance') {
            if ($Mode -eq 'LocalMachine') {
                $results.Add('ProcessorPerformance', (Test-MDIProcessorPerformance -Detailed))
            } else {
                $results.Add('ProcessorPerformance', (Test-MDIProcessorPerformanceGPO @mdiParams))
            }
        }
        if (Use-MDIConfigName $Configuration 'RemoteSAM') {
            if ($Mode -eq 'LocalMachine') {
                $results.Add('RemoteSAM', (Test-MDIRemoteSAM -Detailed -Identity $Identity))
            } else {
                $results.Add('RemoteSAM', (Test-MDIRemoteSAMGPO @mdiParams -Identity $Identity))
            }
        }
        if ($Configuration -contains 'All') {
            $Configuration += $results.GetEnumerator() | Select-Object -ExpandProperty Name
        }
        $Configuration | Select-Object -Unique | Sort-Object -Property Configuration | Where-Object { $_ -ne 'All' } | ForEach-Object {
            [PSCustomObject]@{
                Configuration = $_
                Mode          = $Mode
                Status        = $results[$_].Status
                Details       = $results[$_].Details
            }
        }
    }

}

function Test-MDIConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [ValidateSet('Domain', 'LocalMachine')] [string] $Mode,
        [Parameter(Mandatory = $true)] [ValidateSet('AdfsAuditing', 'AdRecycleBin', 'AdvancedAuditPolicyCAs', 'AdvancedAuditPolicyDCs',
            'CAAuditing', 'ConfigurationContainerAuditing', 'DeletedObjectsContainerPermission', 'DomainObjectAuditing', 'EntraConnectAuditing', 'NTLMAuditing', 'ProcessorPerformance', 'RemoteSAM', 'All')] [string[]] $Configuration
    )
    DynamicParam {
        $paramDictionary = New-Object -Type System.Management.Automation.RuntimeDefinedParameterDictionary
        $paramAttributes = New-Object -Type System.Management.Automation.ParameterAttribute
        $paramAttributes.Mandatory = $false
        $paramAttributesCollect = New-Object -Type System.Collections.ObjectModel.Collection[System.Attribute]
        $paramAttributesCollect.Add($paramAttributes)
        $dynParam1 = New-Object -Type System.Management.Automation.RuntimeDefinedParameter("GpoNamePrefix", [string], $paramAttributesCollect)
        $paramAttributes = New-Object -Type System.Management.Automation.ParameterAttribute
        $paramAttributes.Mandatory = $false
        $paramAttributesCollect = New-Object -Type System.Collections.ObjectModel.Collection[System.Attribute]
        $paramAttributesCollect.Add($paramAttributes)
        $dynParam3 = New-Object -Type System.Management.Automation.RuntimeDefinedParameter("Server", [string], $paramAttributesCollect)
        $paramAttributes = New-Object -Type System.Management.Automation.ParameterAttribute
        $paramAttributes.Mandatory = $true
        $paramAttributesCollect = New-Object -Type System.Collections.ObjectModel.Collection[System.Attribute]
        $paramAttributesCollect.Add($paramAttributes)
        $dynParamIdentity = New-Object -Type System.Management.Automation.RuntimeDefinedParameter("Identity", [string], $paramAttributesCollect)
        $paramAttributes = New-Object -Type System.Management.Automation.ParameterAttribute
        $paramAttributes.Mandatory = $false
        $paramAttributesCollect = New-Object -Type System.Collections.ObjectModel.Collection[System.Attribute]
        $paramAttributesCollect.Add($paramAttributes)
        $dynParam4 = New-Object -Type System.Management.Automation.RuntimeDefinedParameter("Domain", [string], $paramAttributesCollect)
        if ($Mode -eq 'Domain') {
            $paramDictionary.Add("GpoNamePrefix", $dynParam1)
            $paramDictionary.Add("Domain", $dynParam4)
            $paramDictionary.Add("Server", $dynParam3)
        }
        if ([bool](($($Configuration -join ',')) -match 'DeletedObjectsContainerPermission|EntraConnectAuditing|RemoteSAM|All')) {
            $paramDictionary.Add("Identity", $dynParamIdentity)
        }
        return $paramDictionary
    }
    begin {
        foreach ($key in $PSBoundParameters.Keys) {
            if ($MyInvocation.MyCommand.Parameters.$key.isDynamic) {
                Set-Variable -Name $key -Value $PSBoundParameters.$key
            }
        }
    }
    process {
        $results = if ($Mode -eq 'Domain') {
            $mdiParams = @{
                Configuration = $Configuration
                Mode          = "Domain"
                GpoNamePrefix = $GpoNamePrefix
            }
            if (-not [string]::IsNullOrEmpty($Server)) { $mdiParams.Add("Server", $Server) }
            if (-not [string]::IsNullOrEmpty($Identity)) { $mdiParams.Add("Identity", $Identity) }
            if (-not [string]::IsNullOrEmpty($Domain)) { $mdiParams.Add("Domain", $Domain) }
            Get-MDIConfiguration @mdiParams
        } else {
            Get-MDIConfiguration -Configuration $Configuration -Mode LocalMachine
        }

        if ('All' -eq $Configuration) {
            @($results | Where-Object { $_.Status -eq $false }).Count -eq 0
        } else {
            $results.Status
        }
    }
}

function Set-MDIConfiguration {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)] [ValidateSet('Domain', 'LocalMachine')] [string] $Mode,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)] [ValidateSet('AdfsAuditing', 'AdRecycleBin', 'AdvancedAuditPolicyCAs', 'AdvancedAuditPolicyDCs',
            'CAAuditing', 'ConfigurationContainerAuditing', 'DeletedObjectsContainerPermission', 'DomainObjectAuditing', 'EntraConnectAuditing', 'NTLMAuditing', 'ProcessorPerformance', 'RemoteSAM', 'All')] [string[]] $Configuration,
        [Parameter(Mandatory = $false)] [switch] $Force
    )
    DynamicParam {
        $paramDictionary = New-Object -Type System.Management.Automation.RuntimeDefinedParameterDictionary
        $paramAttributes = New-Object -Type System.Management.Automation.ParameterAttribute
        $paramAttributes.Mandatory = $false
        $paramAttributesCollect = New-Object -Type System.Collections.ObjectModel.Collection[System.Attribute]
        $paramAttributesCollect.Add($paramAttributes)
        $dynParam1 = New-Object -Type System.Management.Automation.RuntimeDefinedParameter("GpoNamePrefix", [string], $paramAttributesCollect)
        $paramAttributes = New-Object -Type System.Management.Automation.ParameterAttribute
        $paramAttributes.Mandatory = $false
        $paramAttributesCollect = New-Object -Type System.Collections.ObjectModel.Collection[System.Attribute]
        $paramAttributesCollect.Add($paramAttributes)
        $dynParam2 = New-Object -Type System.Management.Automation.RuntimeDefinedParameter("CreateGpoDisabled", [switch], $paramAttributesCollect)
        $paramAttributes = New-Object -Type System.Management.Automation.ParameterAttribute
        $paramAttributes.Mandatory = $false
        $paramAttributesCollect = New-Object -Type System.Collections.ObjectModel.Collection[System.Attribute]
        $paramAttributesCollect.Add($paramAttributes)
        $dynParam3 = New-Object -Type System.Management.Automation.RuntimeDefinedParameter("SkipGpoLink", [switch], $paramAttributesCollect)
        $paramAttributes = New-Object -Type System.Management.Automation.ParameterAttribute
        $paramAttributes.Mandatory = $false
        $paramAttributesCollect = New-Object -Type System.Collections.ObjectModel.Collection[System.Attribute]
        $paramAttributesCollect.Add($paramAttributes)
        $dynParam5 = New-Object -Type System.Management.Automation.RuntimeDefinedParameter("Server", [string], $paramAttributesCollect)
        $paramAttributes = New-Object -Type System.Management.Automation.ParameterAttribute
        $paramAttributes.Mandatory = $true
        $paramAttributesCollect = New-Object -Type System.Collections.ObjectModel.Collection[System.Attribute]
        $paramAttributesCollect.Add($paramAttributes)
        $dynParamIdentity = New-Object -Type System.Management.Automation.RuntimeDefinedParameter("Identity", [string], $paramAttributesCollect)
        $paramAttributes = New-Object -Type System.Management.Automation.ParameterAttribute
        $paramAttributes.Mandatory = $false
        $paramAttributesCollect = New-Object -Type System.Collections.ObjectModel.Collection[System.Attribute]
        $paramAttributesCollect.Add($paramAttributes)
        $dynParam4 = New-Object -Type System.Management.Automation.RuntimeDefinedParameter("Domain", [string], $paramAttributesCollect)
        if ($Mode -eq 'Domain') {
            $paramDictionary.Add("GpoNamePrefix", $dynParam1)
            $paramDictionary.Add("CreateGpoDisabled", $dynParam2)
            $paramDictionary.Add("SkipGpoLink", $dynParam3)
            $paramDictionary.Add("Domain", $dynParam4)
            $paramDictionary.Add("Server", $dynParam5)
        }
        if ([bool](($($Configuration -join ',')) -match 'DeletedObjectsContainerPermission|EntraConnectAuditing|RemoteSAM|All')) {
            $paramDictionary.Add("Identity", $dynParamIdentity)
        }
        return $paramDictionary
    }
    begin {
        foreach ($key in $PSBoundParameters.Keys) {
            if ($MyInvocation.MyCommand.Parameters.$key.isDynamic) {
                Set-Variable -Name $key -Value $PSBoundParameters.$key
            }
        }
    }
    Process {
        if ($Mode -eq 'Domain') {
            $myDomain = Get-MDIDomain -myDomain $myDomain -Server $Server -Domain $Domain
            if ($null -ne $myDomain) { $Server = $myDomain.ChosenDC }
        }
        foreach ($config in $Configuration) {
            $mdiParams = @{
                CreateGpoDisabled = $CreateGpoDisabled
                SkipGpoLink       = $SkipGpoLink
                GpoNamePrefix     = $GpoNamePrefix
            }
            if (-not [string]::IsNullOrEmpty($Server)) { $mdiParams.Add("Server", $Server) }
            if (-not [string]::IsNullOrEmpty($myDomain.DNSRoot)) { $mdiParams.Add("Domain", $myDomain.DNSRoot) }
            if ($null -ne $myDomain) { $mdiParams.Add("myDomain", $myDomain) }
            $adRecycleBinParams = @{

            }; if (-not [string]::IsNullOrEmpty($Server)) { $adRecycleBinParams.Add("Server", $Server) }
            Write-Verbose ($strings['Configuration_Set'] -f $config)
            if (Use-MDIConfigName $config 'AdfsAuditing') { Set-MDIAdfsAuditing -myDomain $myDomain }
            if (Use-MDIConfigName $config 'AdRecycleBin') {
                if (-not (Test-MDIAdRecycleBin @adRecycleBinParams -myDomain $myDomain)) {
                    Set-MDIAdRecycleBin
                }
            }
            if (Use-MDIConfigName $config 'AdvancedAuditPolicyCAs') {
                if ($Mode -eq 'LocalMachine') {
                    Set-MDIAdvancedAuditPolicyCAs
                } else {
                    Set-MDIAdvancedAuditPolicyCAsGPO @mdiParams
                }
            }

            if (Use-MDIConfigName $config 'AdvancedAuditPolicyDCs') {
                if ($Mode -eq 'LocalMachine') {
                    Set-MDIAdvancedAuditPolicyDCs
                } else {
                    Set-MDIAdvancedAuditPolicyDCsGPO @mdiParams
                }
            }

            if (Use-MDIConfigName $config 'CAAuditing') {
                if ($Mode -eq 'LocalMachine') {
                    Set-MDICAAuditing
                } else {
                    Set-MDICAAuditingGPO @mdiParams
                }
            }

            if (Use-MDIConfigName $config 'ConfigurationContainerAuditing') { Set-MDIConfigurationContainerAuditing -Force:$Force -myDomain $myDomain }

            if (Use-MDIConfigName $config 'DeletedObjectsContainerPermission') { Set-MDIDeletedObjectsContainerPermission -myDomain $myDomain -Identity $Identity }

            if (Use-MDIConfigName $config 'DomainObjectAuditing') { Set-MDIDomainObjectAuditing -myDomain $myDomain }

            if (Use-MDIConfigName $config 'EntraConnectAuditing') {
                if ($Mode -eq 'LocalMachine') {
                    Set-MDIEntraConnectAuditing -Identity $Identity
                } else {
                    Set-MDIEntraConnectAuditingGPO @mdiParams -Identity $Identity
                }
            }

            if (Use-MDIConfigName $config 'NTLMAuditing') {
                if ($Mode -eq 'LocalMachine') {
                    Set-MDINTLMAuditing
                } else {
                    Set-MDINTLMAuditingGPO @mdiParams
                }
            }

            if (Use-MDIConfigName $config 'ProcessorPerformance') {
                if ($Mode -eq 'LocalMachine') {
                    Set-MDIProcessorPerformance
                } else {
                    Set-MDIProcessorPerformanceGPO @mdiParams
                }
            }

            if (Use-MDIConfigName $config 'RemoteSAM') {
                Write-Warning -Message $strings['RemoteSAM_NTLMWarn']
                if ($Mode -eq 'LocalMachine') {
                    Set-MDIRemoteSAM -Identity $Identity
                } else {
                    Set-MDIRemoteSAMGPO @mdiParams -Identity $Identity
                }
            }
        }
    }
}

function New-MDIConfigurationReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory = $false)] [ValidateSet('Domain', 'LocalMachine')] [string] $Mode = 'Domain',
        [switch] $OpenHtmlReport
    )
    DynamicParam {
        $paramDictionary = New-Object -Type System.Management.Automation.RuntimeDefinedParameterDictionary
        $paramAttributes = New-Object -Type System.Management.Automation.ParameterAttribute
        $paramAttributes.Mandatory = $false
        $paramAttributesCollect = New-Object -Type System.Collections.ObjectModel.Collection[System.Attribute]
        $paramAttributesCollect.Add($paramAttributes)
        $dynParam1 = New-Object -Type System.Management.Automation.RuntimeDefinedParameter("GpoNamePrefix", [string], $paramAttributesCollect)
        $paramAttributes = New-Object -Type System.Management.Automation.ParameterAttribute
        $paramAttributes.Mandatory = $false
        $paramAttributesCollect = New-Object -Type System.Collections.ObjectModel.Collection[System.Attribute]
        $paramAttributesCollect.Add($paramAttributes)
        $dynParam3 = New-Object -Type System.Management.Automation.RuntimeDefinedParameter("Server", [string], $paramAttributesCollect)
        $paramAttributes = New-Object -Type System.Management.Automation.ParameterAttribute
        $paramAttributes.Mandatory = $true
        $paramAttributesCollect = New-Object -Type System.Collections.ObjectModel.Collection[System.Attribute]
        $paramAttributesCollect.Add($paramAttributes)
        $dynParamIdentity = New-Object -Type System.Management.Automation.RuntimeDefinedParameter("Identity", [string], $paramAttributesCollect)
        $paramAttributes = New-Object -Type System.Management.Automation.ParameterAttribute
        $paramAttributes.Mandatory = $false
        $paramAttributesCollect = New-Object -Type System.Collections.ObjectModel.Collection[System.Attribute]
        $paramAttributesCollect.Add($paramAttributes)
        $dynParam4 = New-Object -Type System.Management.Automation.RuntimeDefinedParameter("Domain", [string], $paramAttributesCollect)
        if ($Mode -eq 'Domain') {
            $paramDictionary.Add("Identity", $dynParamIdentity)
            $paramDictionary.Add("Domain", $dynParam4)
            $paramDictionary.Add("Server", $dynParam3)
        }
        return $paramDictionary
    }
    begin {
        foreach ($key in $PSBoundParameters.Keys) {
            if ($MyInvocation.MyCommand.Parameters.$key.isDynamic) {
                Set-Variable -Name $key -Value $PSBoundParameters.$key
            }
        }
    }
    process {
        if (-not(Test-Path -Path $Path)) { [void](New-Item -Path $Path -ItemType Directory -Force -ErrorAction SilentlyContinue) }
        $reportTarget = if ($Mode -eq 'Domain') { if ([string]::IsNullOrEmpty($Domain)) { $env:USERDNSDOMAIN } } else { '{0}.{1}' -f $env:COMPUTERNAME, $env:USERDNSDOMAIN }
        $getMdiConfigParams = @{
            Configuration = "All"
            Mode          = $Mode
            GpoNamePrefix = $GpoNamePrefix
        }
        if (-not [string]::IsNullOrEmpty($Server)) { $getMdiConfigParams.Add("Server", $Server) }
        if (-not [string]::IsNullOrEmpty($Identity)) { $getMdiConfigParams.Add("Identity", $Identity) }
        if (-not [string]::IsNullOrEmpty($Domain)) { $getMdiConfigParams.Add("Domain", $Domain) }
        $configurations = Get-MDIConfiguration @getMdiConfigParams

        $jsonReportFile = Resolve-MDIPath -Path (
            Join-Path -Path $Path -ChildPath ('MDI-configuration-report-{0}.json' -f $reportTarget))
        $htmlReportFile = Resolve-MDIPath -Path (
            Join-Path -Path $Path -ChildPath ('MDI-configuration-report-{0}.html' -f $reportTarget))

        $css = @'
<style>
body { font-family: Arial, sans-serif, 'Open Sans'; }
table { border-collapse: collapse; }
td, th { border: 1px solid #aeb0b5; padding: 5px; text-align: left; vertical-align: middle; }
tr:nth-child(even) { background-color: #f2f2f2; }
th { padding: 8px; text-align: left; background-color: #e4e2e0; color: #212121; }
.red    {background-color: #cd2026; color: #ffffff; }
.green  {background-color: #4aa564; color: #212121; }
ul { list-style: none; padding-left: 0.5em;}
</style>
'@
        $colors = @{$true = 'green'; $false = 'red' }
        $status = @{$true = $strings['DomainReport_StatusPass']; $false = $strings['DomainReport_StatusFail'] }
        $tblHeader = '<tr><th>{0}</th><th>{1}</th><th>{2}</th><th>{3}</th></tr>' -f $strings['DomainReport_Configuration'],
        $strings['DomainReport_Status'], $strings['DomainReport_GpoHeader'], $strings['DomainReport_CommandToFix']
        $tblContent = @($configurations | Sort-Object Configuration | ForEach-Object {
                $gpoPrefixIfUsed = if ([string]::IsNullOrEmpty($GpoNamePrefix)) { '' } else { " -GpoNamePrefix $GpoNamePrefix" }
                if ([string]::IsNullOrEmpty($_.Details.DisplayName)) {
                    try {
                        $gpoNameTemp = $_.Details.ToString()
                    } catch {
                        $gpoNameTemp = $null
                    }
                } else {
                    try {
                        if (-not [string]::IsNullOrEmpty($_.Details.DisplayName)) {
                            $gpoNameTemp = $_.Details.DisplayName
                        }
                    } catch {
                        $gpoNameTemp = $null
                    }
                }
                try {
                    $gpoNameTemp = $gpoNameTemp.replace("'", '')
                } catch {
                    $gpoNameTemp = $gpoNameTemp
                }
                if ($gpoPrefixIfUsed) {
                    $matchString = "^($GpoNamePrefix \- )"
                } else {
                    $matchString = "^(Microsoft Defender for Identity \- )"
                }
                $gpoNameTested = if ($gpoNameTemp -match $matchString) { try { $gpoNameTemp.replace(" - GPO not found", '') } catch { $null } } else { $null }
                "<tr><td><a href='https://aka.ms/mdi/{0}'>{0}</a></td><td class='{1}'>{2}</td><td>{5}</td><td>{3}{0}{4}</td></tr>" -f `
                    $_.Configuration, $colors[$_.Status], $status[$_.Status], 'Set-MDIConfiguration -Mode Domain -Configuration ', $gpoPrefixIfUsed, $(if ([string]::IsNullOrEmpty($gpoNameTested)) { $strings['DomainReport_GpoNotApplicable'] } else { $gpoNameTested })
            }) -join [environment]::NewLine

        $htmlContent = @'
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>{0}</head><body>
<h2>{1}</h2>
{2}
<br/><br/>
<table>
{3}
{4}
</table>
<br/>
<hr>
<ul>
<li>{5}</li>
</ul>
<hr>
<br/>{6} <a href='{7}'>{7}</a><br/>
<br/>{8}
'@ -f $css, ($strings['DomainReport_Title'] -f $reportTarget), $strings['DomainReport_Subtitle'],
        $tblHeader, $tblContent, $strings['DomainReport_NoteMessage'], $strings['DomainReport_DetailsMessage'],
        $jsonReportFile, ($strings['DomainReport_CreatedBy'] -f "<a href='https://aka.ms/mdi/psmodule'>DefenderForIdentity</a>")

        Write-Verbose ('{0}: {1}' -f $strings['DomainReport_JsonMessage'], $jsonReportFile)
        $configurations | ConvertTo-Json -Depth 5 | Format-Json | Out-File -FilePath $jsonReportFile -Force -Encoding utf8

        Write-Verbose ('{0}: {1}' -f $strings['DomainReport_HtmlMessage'], $htmlReportFile)
        $htmlContent | Out-File -FilePath $htmlReportFile -Force -Encoding utf8

        $reportPath = (Resolve-Path -Path $htmlReportFile).Path
        if ($OpenHtmlReport) { Invoke-Item -Path $reportPath }
    }

}

#endregion
# SIG # Begin signature block
# MIIoQwYJKoZIhvcNAQcCoIIoNDCCKDACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA9z4GX2DK1oR4z
# axKkBhSeHw6zRyfsC/R3QhllNAh9gaCCDXYwggX0MIID3KADAgECAhMzAAAEBGx0
# Bv9XKydyAAAAAAQEMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjQwOTEyMjAxMTE0WhcNMjUwOTExMjAxMTE0WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC0KDfaY50MDqsEGdlIzDHBd6CqIMRQWW9Af1LHDDTuFjfDsvna0nEuDSYJmNyz
# NB10jpbg0lhvkT1AzfX2TLITSXwS8D+mBzGCWMM/wTpciWBV/pbjSazbzoKvRrNo
# DV/u9omOM2Eawyo5JJJdNkM2d8qzkQ0bRuRd4HarmGunSouyb9NY7egWN5E5lUc3
# a2AROzAdHdYpObpCOdeAY2P5XqtJkk79aROpzw16wCjdSn8qMzCBzR7rvH2WVkvF
# HLIxZQET1yhPb6lRmpgBQNnzidHV2Ocxjc8wNiIDzgbDkmlx54QPfw7RwQi8p1fy
# 4byhBrTjv568x8NGv3gwb0RbAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQU8huhNbETDU+ZWllL4DNMPCijEU4w
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzUwMjkyMzAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAIjmD9IpQVvfB1QehvpC
# Ge7QeTQkKQ7j3bmDMjwSqFL4ri6ae9IFTdpywn5smmtSIyKYDn3/nHtaEn0X1NBj
# L5oP0BjAy1sqxD+uy35B+V8wv5GrxhMDJP8l2QjLtH/UglSTIhLqyt8bUAqVfyfp
# h4COMRvwwjTvChtCnUXXACuCXYHWalOoc0OU2oGN+mPJIJJxaNQc1sjBsMbGIWv3
# cmgSHkCEmrMv7yaidpePt6V+yPMik+eXw3IfZ5eNOiNgL1rZzgSJfTnvUqiaEQ0X
# dG1HbkDv9fv6CTq6m4Ty3IzLiwGSXYxRIXTxT4TYs5VxHy2uFjFXWVSL0J2ARTYL
# E4Oyl1wXDF1PX4bxg1yDMfKPHcE1Ijic5lx1KdK1SkaEJdto4hd++05J9Bf9TAmi
# u6EK6C9Oe5vRadroJCK26uCUI4zIjL/qG7mswW+qT0CW0gnR9JHkXCWNbo8ccMk1
# sJatmRoSAifbgzaYbUz8+lv+IXy5GFuAmLnNbGjacB3IMGpa+lbFgih57/fIhamq
# 5VhxgaEmn/UjWyr+cPiAFWuTVIpfsOjbEAww75wURNM1Imp9NJKye1O24EspEHmb
# DmqCUcq7NqkOKIG4PVm3hDDED/WQpzJDkvu4FrIbvyTGVU01vKsg4UfcdiZ0fQ+/
# V0hf8yrtq9CkB8iIuk5bBxuPMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGiMwghofAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAAQEbHQG/1crJ3IAAAAABAQwDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIL809sTVTtXUXqrRy/IPWjYa
# eOkgE7QOBp4rj73pV2AsMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEArmNAAeTS2H6R/9GfFBDk/CHdJnvJPji0HfSfkF1K59ocXP0yitIp7iVW
# RVAfAXgkSoxkg4vRYGxtXNSVrXXJiz0CP4kW64j79J9Ty7rKLZGtzhdlAbVHdiDO
# 4rZkU2FKzDMh2BhshFb9ZfkLYYxKbsvvjx+D7CftNEUJr8DxwJ3qAIyS/zyNIZ/m
# lcoCkfMh7g/ZOcZ80kw9oPkcdG2f4/30fw30ILq/dna/sm+RmaklY+ElDZ5XDogI
# PpkUCnRyqWeWbhZynpNOgUeW+XJ8eRmP4cL2gaeRhStus/wr7fqPqH5FJdeyuaL3
# qyoTWlIcZSAUX4mCi8K8dNQwc7PUGqGCF60wghepBgorBgEEAYI3AwMBMYIXmTCC
# F5UGCSqGSIb3DQEHAqCCF4YwgheCAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFaBgsq
# hkiG9w0BCRABBKCCAUkEggFFMIIBQQIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCD+k38dYeeosOqWJCcZNtrIQ8lpg54SIG3UxMm0zXFBAwIGaC3xZOXS
# GBMyMDI1MDUyOTA4MjIxNS41NDJaMASAAgH0oIHZpIHWMIHTMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJl
# bGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVT
# TjoyQTFBLTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# U2VydmljZaCCEfswggcoMIIFEKADAgECAhMzAAAB+R9njXWrpPGxAAEAAAH5MA0G
# CSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTI0
# MDcyNTE4MzEwOVoXDTI1MTAyMjE4MzEwOVowgdMxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9w
# ZXJhdGlvbnMgTGltaXRlZDEnMCUGA1UECxMeblNoaWVsZCBUU1MgRVNOOjJBMUEt
# MDVFMC1EOTQ3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtD1MH3yAHWHNVslC+CBT
# j/Mpd55LDPtQrhN7WeqFhReC9xKXSjobW1ZHzHU8V2BOJUiYg7fDJ2AxGVGyovUt
# gGZg2+GauFKk3ZjjsLSsqehYIsUQrgX+r/VATaW8/ONWy6lOyGZwZpxfV2EX4qAh
# 6mb2hadAuvdbRl1QK1tfBlR3fdeCBQG+ybz9JFZ45LN2ps8Nc1xr41N8Qi3KVJLY
# X0ibEbAkksR4bbszCzvY+vdSrjWyKAjR6YgYhaBaDxE2KDJ2sQRFFF/egCxKgogd
# F3VIJoCE/Wuy9MuEgypea1Hei7lFGvdLQZH5Jo2QR5uN8hiMc8Z47RRJuIWCOeyI
# J1YnRiiibpUZ72+wpv8LTov0yH6C5HR/D8+AT4vqtP57ITXsD9DPOob8tjtsefPc
# QJebUNiqyfyTL5j5/J+2d+GPCcXEYoeWZ+nrsZSfrd5DHM4ovCmD3lifgYnzjOry
# 4ghQT/cvmdHwFr6yJGphW/HG8GQd+cB4w7wGpOhHVJby44kGVK8MzY9s32Dy1THn
# Jg8p7y1sEGz/A1y84Zt6gIsITYaccHhBKp4cOVNrfoRVUx2G/0Tr7Dk3fpCU8u+5
# olqPPwKgZs57jl+lOrRVsX1AYEmAnyCyGrqRAzpGXyk1HvNIBpSNNuTBQk7FBvu+
# Ypi6A7S2V2Tj6lzYWVBvuGECAwEAAaOCAUkwggFFMB0GA1UdDgQWBBSJ7aO6nJXJ
# I9eijzS5QkR2RlngADAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUF
# BwMIMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEAZiAJgFbkf7jf
# hx/mmZlnGZrpae+HGpxWxs8I79vUb8GQou50M1ns7iwG2CcdoXaq7VgpVkNf1uvI
# hrGYpKCBXQ+SaJ2O0BvwuJR7UsgTaKN0j/yf3fpHD0ktH+EkEuGXs9DBLyt71iut
# Vkwow9iQmSk4oIK8S8ArNGpSOzeuu9TdJjBjsasmuJ+2q5TjmrgEKyPe3TApAio8
# cdw/b1cBAmjtI7tpNYV5PyRI3K1NhuDgfEj5kynGF/uizP1NuHSxF/V1ks/2tCEo
# riicM4k1PJTTA0TCjNbkpmBcsAMlxTzBnWsqnBCt9d+Ud9Va3Iw9Bs4ccrkgBjLt
# g3vYGYar615ofYtU+dup+LuU0d2wBDEG1nhSWHaO+u2y6Si3AaNINt/pOMKU6l4A
# W0uDWUH39OHH3EqFHtTssZXaDOjtyRgbqMGmkf8KI3qIVBZJ2XQpnhEuRbh+Agpm
# Rn/a410Dk7VtPg2uC422WLC8H8IVk/FeoiSS4vFodhncFetJ0ZK36wxAa3FiPgBe
# bRWyVtZ763qDDzxDb0mB6HL9HEfTbN+4oHCkZa1HKl8B0s8RiFBMf/W7+O7EPZ+w
# MH8wdkjZ7SbsddtdRgRARqR8IFPWurQ+sn7ftEifaojzuCEahSAcq86yjwQeTPN9
# YG9b34RTurnkpD+wPGTB1WccMpsLlM0wggdxMIIFWaADAgECAhMzAAAAFcXna54C
# m0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZp
# Y2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5MzAxODIyMjVaFw0zMDA5MzAxODMy
# MjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciELeaLL1yR5vQ7VgtP97pwHB9KpbE51
# yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa4n5KWv64NmeFRiMMtY0Tz3cywBAY
# 6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxRMTegCjhuje3XD9gmU3w5YQJ6xKr9
# cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEBydUv626GIl3GoPz130/o5Tz9bshVZN
# 7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi947SHJMPgyY9+tVSP3PoFVZhtaDua
# Rr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJiss254o2I5JasAUq7vnGpF1tnYN74
# kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2
# K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY7afomXw/TNuvXsLz1dhzPUNOwTM5
# TI4CvEJoLhDqhFFG4tG9ahhaYQFzymeiXtcodgLiMxhy16cg8ML6EgrXY28MyTZk
# i1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9Q
# BXpsxREdcu+N+VLEhReTwDwV2xo3xwgVGD94q0W29R6HXtqPnhZyacaue7e3Pmri
# Lq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUC
# BBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0GA1UdDgQWBBSfpxVdAF5iXYP05dJl
# pxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9y
# eS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUA
# YgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU
# 1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2Ny
# bC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIw
# MTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0w
# Ni0yMy5jcnQwDQYJKoZIhvcNAQELBQADggIBAJ1VffwqreEsH2cBMSRb4Z5yS/yp
# b+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRsfNB1OW27DzHkwo/7bNGhlBgi7ulm
# ZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6Ce5732pvvinLbtg/SHUB2RjebYIM
# 9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveVtihVJ9AkvUCgvxm2EhIRXT0n4ECW
# OKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKBGUIZUnWKNsIdw2FzLixre24/LAl4
# FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoyGtmW9I/2kQH2zsZ0/fZMcm8Qq3Uw
# xTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQEcb9k+SS+c23Kjgm9swFXSVRk2XPX
# fx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFUa2pFEUep8beuyOiJXk+d0tBMdrVX
# VAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+k77L+DvktxW/tM4+pTFRhLy/AsGC
# onsXHRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU
# 5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEG
# ahC0HVUzWLOhcGbyoYIDVjCCAj4CAQEwggEBoYHZpIHWMIHTMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJl
# bGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVT
# TjoyQTFBLTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# U2VydmljZaIjCgEBMAcGBSsOAwIaAxUAqs5WjWO7zVAKmIcdwhqgZvyp6UaggYMw
# gYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQsF
# AAIFAOviUnkwIhgPMjAyNTA1MjkwMzI2NDlaGA8yMDI1MDUzMDAzMjY0OVowdDA6
# BgorBgEEAYRZCgQBMSwwKjAKAgUA6+JSeQIBADAHAgEAAgIVNjAHAgEAAgISNjAK
# AgUA6+Oj+QIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIB
# AAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBCwUAA4IBAQAjZ1c6wtOT8SdR
# DX1JkBifGB5AO2HkUwZTQSzl95CchktxEtVA4iNmBQ2Gtec68DJ6S13XbnHm/8bh
# YiozcizqfISNJ7YGw6zimjp9ZQSkML4SMaQoYLxWX/sYwefuc1SLUuGQlMbucpI4
# s1ik74QZ/ax4oovY73Z2T3WHQaq+rPM5qTy95AkedY9hW8nPE3A7MezNshYgxbVD
# R7h1cbjg+gWYVyNsHySrCgf9PEAlBZjbnG2ix7Du+v9i7ioBpgyF0NZh4XUsVhZz
# k7scLA9l4YQpGg0atHCcch+DdR2NRmsM3J3gHYtdDCfzoH5GNPpPJIlaIPD6QaXN
# IL3mOspcMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTACEzMAAAH5H2eNdauk8bEAAQAAAfkwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqG
# SIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgmSwepzvctJ25
# AzQi7ftF4OjCoN0ObZYDG1jL9BdnnLMwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHk
# MIG9BCA5I4zIHvCN+2T66RUOLCZrUEVdoKlKl8VeCO5SbGLYEDCBmDCBgKR+MHwx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAB+R9njXWrpPGxAAEAAAH5
# MCIEIORTxGPdBgVq1cCsT8DrUAi6oFqlD2CPUB+/9ox/+gr+MA0GCSqGSIb3DQEB
# CwUABIICAD6fGwvBE6hMrbjnc2tiEtpHo/mXVcxP4O19SvXanAb2NBr37UQznQqz
# Qvp+KOiKlsRKi829Uo0tcQrQlkOC1pjqpmxDS5DWu3oLZLIUgAMHYamGAxJaui3D
# 4YufDAh6FzdP81QVpFPgzLQWVFlziKny1hhdRpABf4r4jpzQk3WJ7m0zU16uEHk2
# QXEql/FLbSqhjXOZhdhd9gdT1XA5CnncdQY54sqjHz3eqKJgkRCnJ1LS2fHb9U6J
# nnQfscMxBjhK5CQrulCVXKl+hJS3HjsSYOFMTf25t+VaOzcJaRunP+jhWJlmJMRm
# WDw/n/zFOCANehIVrIZalNcvgAY+yR7RkcWA6k2rp4lW3M1yYVvGhgOVyIXtL1cE
# /3eUrZWNsoKZfJEs3duUJSm8CltFEYCMgpJ533iITn+xtnInm1qU1LQbCfP2kAxX
# 2e4rYJ3pgvuhIeBWaTKwmxQz7Q3o2Swzz4G7f8NxzxkajLCEcRC5lbrSzOB7WN33
# PvlJSQY4BOMGDanobTyzNE9TEvCvaRQ7gS4igOf+6Vy3GJXnlIb6m/KcP0Qt0ib8
# 53fcs8ntv0uYs2fzwbVHoLy2qLuwjdwmV8bhTVomJU7u2Ejwz4lUayxxSUrNngwz
# g4sxvdJB5R7VqtkHhlZY3uhXu5H+YOHEfhK925G0e/hzaUIcQFlF
# SIG # End signature block
