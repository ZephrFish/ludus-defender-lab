# Ludus Defender Lab

Ludus range configs and Ansible roles for a Windows security lab pre-staged for MDE and MDI, with a fully misconfigured ADCS installation for detection coverage testing.

Two configs:

| Config | VMs | Purpose |
|---|---|---|
| `zsec-mde-mdi-lab.yml` | DC01 + WKS01 | MDE/MDI detection lab with ADCS ESC1–ESC15 |

## Requirements

- [Ludus](https://docs.ludus.cloud) installed and configured
- `LUDUS_API_KEY` set in your environment
- VM templates: `win2022-server-x64-template` (+ `debian-12-x64-server-template` for ADCS lab)

## Deploy

```bash
# Install roles (run on Ludus host with API key set)
cd roles/
./install-roles.sh

# Set config and deploy
ludus range config set -f zsec-mde-mdi-lab.yml
ludus range deploy

# Post-onboarding snapshot (after MDE/MDI are onboarded from security.microsoft.com)
ludus range snapshot create --name post-onboarding
```

## Environment settings

All environment-specific values are defined as YAML anchors at the top of each config. Edit before deploying:

```yaml
x-domain:      &domain      "zsec.local"
x-dc-hostname: &dc-hostname "DC01"
x-admin-pass:  &admin-pass  "D0main@dmin2026"
# ...
```

Compound FQDNs in `dns_rewrites` and SPN strings need updating separately — YAML doesn't support string interpolation.

## Roles

All 10 roles live in `roles/`. The install script picks everything up automatically.

| Role | Purpose |
|---|---|
| `mde_prereqs` | Defender config, audit policy, logging, LSA hardening, TLS 1.2 |
| `wef` | Windows Event Forwarding (collector and forwarder modes) |
| `sysmon` | Sysmon install and config |
| `adcs_lab` | ADCS ESC1–ESC15 misconfiguration setup |
| `ad_population` | Users, groups, OUs, Kerberoastable/ASREPRoastable accounts |
| `smb_shares` | SMB shares including honeypot share |
| `enable_mdi_gpo` | MDI audit GPO |
| `enable_asr` | Attack Surface Reduction rules |
| `rsat` | Remote Server Administration Tools |
| `pivot_tools` | Attacker tooling (certipy, impacket, netexec, bloodhound, etc.) |

## Credits

`enable_asr` and `enable_mdi_gpo` are derived from [@curi0usJack](https://github.com/curi0usJack)'s original work at [curi0usJack/Ludus-MDE-MDI-Roles](https://github.com/curi0usJack/Ludus-MDE-MDI-Roles). This repo builds on those foundations, restructures them into a unified DC↔WKS setup, and adds the ADCS misconfiguration layer, MDE prerequisites hardening, WEF pipeline, and additional roles.

AD CS lab is a [snippet from my course](https://lms.zsec.red)
