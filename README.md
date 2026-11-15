# Ludus Defender Lab

Ludus range config and Ansible roles for a Windows security lab pre-staged for MDE and MDI, with a fully misconfigured ADCS installation for detection coverage testing.

| Config | VMs | Purpose |
|---|---|---|
| `zsec-mde-mdi-lab.yml` | DC01 + WKS01 | MDE/MDI detection lab with ADCS ESC1-ESC11 and ESC13-ESC15 |

## Requirements

- [Ludus](https://docs.ludus.cloud) installed and configured
- `LUDUS_API_KEY` set in your environment
- VM template: `win2022-server-x64-template`

## Deploy

```bash
# Install roles (run on Ludus host with API key set)
cd roles/
./install-roles.sh

# Set config and deploy
ludus range config set -f zsec-mde-mdi-lab.yml
ludus range deploy
```

To update roles after pulling a new version of this repo:

```bash
cd roles/
./install-roles.sh --update
ludus range deploy --tags user-defined-roles   # re-runs roles without VM rebuild
```

MDE and MDI are not auto-installed. Onboard from [security.microsoft.com](https://security.microsoft.com) after the range is up:

1. **Patch** - Ensure the September 2026+ cumulative update is installed (required for MDI v3).
2. **MDE** - Endpoints -> Device management -> Onboarding -> Windows Server 2022. Run the onboarding script on both DC01 and WKS01.
3. **MDI v3** - Settings -> Identities -> Sensors -> select DC01 -> Activate. No standalone installer needed; the v3 sensor is built into MDE.
4. **Action account** - Settings -> Identities -> Manage action accounts -> add `svc_mdi` for automated response.
5. **Honeytokens** - Settings -> Identities -> Entity tags -> Honeytoken -> tag `svc_honey`.

```bash
# Snapshot after onboarding so you can revert without repeating the process
ludus range snapshot create --name post-onboarding
```

## Environment settings

Environment-specific values (domain name, passwords, hostnames) appear inline throughout the config. A reference table at the top of the file lists every value and where it's used - update with find-and-replace before deploying.

Shared MDE prerequisite settings live in `global_role_vars` (applied to all VMs). DC-specific overrides live in DC01's `role_vars` and take precedence automatically.

Compound FQDNs in `dns_rewrites` and SPN strings need updating separately.

## Roles

All roles live in `roles/`. The install script handles everything. Role order in the YAML matters - `enable_mdi_gpo` requires the AD and GroupPolicy PowerShell modules (present on DCs by default, installed by `rsat` on member servers).

| Role | Used in | Purpose |
|---|---|---|
| `mde_prereqs` | DC01, WKS01 | Defender config, audit policy, logging, LSA hardening, TLS 1.2 |
| `wef` | DC01, WKS01 | Windows Event Forwarding (collector on DC01, forwarder on WKS01) |
| `sysmon` | DC01, WKS01 | Sysmon install and config |
| `adcs_lab` | DC01 | ADCS ESC1-ESC11 and ESC13-ESC15 misconfiguration setup |
| `ad_population` | DC01 | Users, groups, OUs, Kerberoastable/ASREPRoastable accounts |
| `smb_shares` | DC01, WKS01 | SMB shares including honeypot share |
| `enable_mdi_gpo` | DC01 | MDI audit GPO via DefenderForIdentity module |
| `enable_asr` | WKS01 | Attack Surface Reduction rules |
| `rsat` | WKS01 | Remote Server Administration Tools |
| `pivot_tools` | Kali (optional) | Chisel, Ligolo-ng, proxychains for pivoting |

Community role installed via Ansible Galaxy: `badsectorlabs.ludus_adcs` (DC01).

## Lab accounts

Default credentials for the `zsec.local` domain. Update these in `zsec-mde-mdi-lab.yml` before deploying.

| Account | Password | Purpose |
|---|---|---|
| `domainadmin` | `D0main@dmin2026` | Domain admin |
| `domainuser` | `Summer2026!` | Standard domain user |
| `jsmith` | `Summer2026!` | IT-Admins member, ADCS test user |
| `svc_backup` | `SvcBackup2026!` | Kerberoastable (SPN: `backup/DC01.zsec.local`) |
| `svc_sql` | `SqlService2026!` | Kerberoastable (SPN: `MSSQLSvc/DC01.zsec.local:1433`) |
| `svc_legacy` | `Legacy2026!` | AS-REP roastable (pre-auth disabled) |
| `svc_deploy` | `D3pl0y@utomation!` | Backup-Operators member |
| `svc_mdi` | `MdiSensor2026!@` | MDI action account (configure in portal) |
| `svc_honey` | `H0neyP0t2026!@` | Honeytoken (tag in portal) |

Planted credentials are also seeded in SMB shares (`C:\Shares\IT\`, `C:\Shares\Backups\`) for discovery scenarios.

## Telemetry stack

What's collecting what after deployment:

| Layer | Coverage | Config |
|---|---|---|
| **Sysmon** | Process, network, registry, file, DNS, named pipe, LSASS access, WMI | Both hosts |
| **WEF** | Security/System/Sysmon/PS/Defender/WMI/BITS/RDP/NTLM/CAPI2 forwarded to DC01 | DC01 collector, WKS01 forwarder |
| **Advanced Audit** | 23+ subcategories incl. DS Access, Kerberos, Credential Validation, Process Creation | Both hosts (DC gets extras) |
| **MDI GPO** | Domain object SACLs, NTLM auditing, advanced audit for DCs | DC01 only |
| **PowerShell** | Script Block (4104), Module (4103), Transcription to `C:\PSTranscripts` | Both hosts |
| **DC-specific** | Kerberos (4768-4771), NTLM (8004), LDAP diag (1644), DNS query logging, ADCS CA audit | DC01 only |
| **Firewall** | Blocked connection logging on all profiles (32 MB per profile) | Both hosts |
| **ASR** | 17 Attack Surface Reduction rules in Enabled mode | WKS01 only |

## Verification

Quick post-deploy sanity checks (run on DC01 unless noted):

```powershell
# Sysmon running
Get-Service Sysmon64

# WEF subscriptions (collector)
wecutil es
wecutil gs ZSec-MDI-Events

# Audit policy
auditpol /get /category:* | Select-String "Success and Failure"

# MDI GPO applied
Get-GPO -All | Where-Object { $_.DisplayName -like 'MDI*' }

# Defender health
Get-MpComputerStatus | Select AntivirusEnabled, RealTimeProtectionEnabled, AMRunningMode

# Event log sizes
wevtutil gl Security | Select-String maxSize
wevtutil gl "Microsoft-Windows-Sysmon/Operational" | Select-String maxSize

# PowerShell logging
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'

# NTLM auditing (DC only)
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' | Select AuditReceivingNTLMTraffic, AuditNTLMInDomain

# MDI v3 sensor status (after onboarding)
Get-Service SenseIdentity, Sense | Format-Table Name, Status, StartType
```

## Credits

`enable_asr` and `enable_mdi_gpo` are derived from [@curi0usJack](https://github.com/curi0usJack)'s work at [curi0usJack/Ludus-MDE-MDI-Roles](https://github.com/curi0usJack/Ludus-MDE-MDI-Roles). This repo extends those roles into a unified DC<->WKS setup and adds the ADCS misconfiguration layer, MDE prerequisites hardening, WEF pipeline, and additional roles.

AD CS lab is a [snippet from my course](https://lms.zsec.red)
