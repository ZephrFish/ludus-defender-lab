# Ludus Defender Lab

Ludus range config and Ansible roles for a Windows security lab pre-staged for MDE and MDI, with a fully misconfigured ADCS installation for detection coverage testing.

| Config | VMs | Purpose |
|---|---|---|
| `zsec-mde-mdi-lab.yml` | DC01 + WKS01 | MDE/MDI detection lab with ADCS ESC1–ESC15 |

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

MDE and MDI are not auto-installed. Onboard both from [security.microsoft.com](https://security.microsoft.com) after the range is up:

1. **MDE** — Endpoints → Device management → Onboarding → Windows Server 2022. Run the onboarding script on both DC01 and WKS01.
2. **MDI** — Settings → Identities → Sensors → Add sensor. Download and run the sensor installer on DC01.

```bash
# Snapshot after onboarding so you can revert without repeating the process
ludus range snapshot create --name post-onboarding
```

## Environment settings

All environment-specific values are defined as YAML anchors at the top of the config. Edit before deploying:

```yaml
x-domain:      &domain      "zsec.local"
x-dc-hostname: &dc-hostname "DC01"
x-admin-pass:  &admin-pass  "D0main@dmin2026"
# ...
```

Compound FQDNs in `dns_rewrites` and SPN strings need updating separately — YAML does not support string interpolation.

## Roles

All roles live in `roles/`. The install script handles everything.

| Role | Used in | Purpose |
|---|---|---|
| `mde_prereqs` | DC01, WKS01 | Defender config, audit policy, logging, LSA hardening, TLS 1.2 |
| `wef` | DC01, WKS01 | Windows Event Forwarding (collector on DC01, forwarder on WKS01) |
| `sysmon` | DC01, WKS01 | Sysmon install and config |
| `adcs_lab` | DC01 | ADCS ESC1–ESC15 misconfiguration setup |
| `ad_population` | DC01 | Users, groups, OUs, Kerberoastable/ASREPRoastable accounts |
| `smb_shares` | DC01, WKS01 | SMB shares including honeypot share |
| `enable_mdi_gpo` | DC01 | MDI audit GPO |
| `enable_asr` | WKS01 | Attack Surface Reduction rules |
| `rsat` | WKS01 | Remote Server Administration Tools |

Community role installed via Ansible Galaxy: `badsectorlabs.ludus_adcs` (DC01).

## Credits

`enable_asr` and `enable_mdi_gpo` are derived from [@curi0usJack](https://github.com/curi0usJack)'s work at [curi0usJack/Ludus-MDE-MDI-Roles](https://github.com/curi0usJack/Ludus-MDE-MDI-Roles). This repo extends those roles into a unified DC↔WKS setup and adds the ADCS misconfiguration layer, MDE prerequisites hardening, WEF pipeline, and additional roles.

AD CS lab is a [snippet from my course](https://lms.zsec.red)
