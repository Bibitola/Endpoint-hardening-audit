# endpoint-hardening-audit

CIS-inspired hardening audits for the two endpoint platforms I administer:
one script per OS, each checking 18 baseline controls and printing a
PASS/FAIL report. Companion to my
[endpoint-provisioning](https://github.com/Bibitola/endpoint-provisioning)
and [intune-remediations](https://github.com/Bibitola/intune-remediations)
repos — provisioning sets machines up, remediations keep them compliant,
and this answers "how hardened is this box right now?"

**Read-only by default.** Running either script changes nothing — it reads
state and reports. Fix mode (`--apply` / `-Apply`) is behind an explicit
flag, prompts per control, and only changes controls with a low-risk scripted
remediation. Controls such as FileVault/BitLocker enablement, SIP, Secure
Boot, password policy, and account lockout policy deliberately report only
because recovery-key, firmware, or identity-policy decisions belong to a
human/change process.

## Usage

macOS (sudo for full coverage; a few controls read root-only state):

```sh
sudo ./macos/audit.sh            # report only
sudo ./macos/audit.sh --apply    # prompt per failed control with safe fixes
```

Windows (elevated PowerShell):

```powershell
.\windows\Audit-Hardening.ps1            # report only
.\windows\Audit-Hardening.ps1 -Apply     # prompt per failed control with safe fixes
```

Both exit `1` when any control fails, so they slot into a scheduled job or
an RMM check as-is.

## Controls

| macOS | Windows |
|---|---|
| Application firewall | Firewall profiles (domain/private/public) |
| Firewall stealth mode | BitLocker system drive *(no scripted fix)* |
| FileVault *(no scripted fix)* | Microsoft Defender real-time protection |
| Gatekeeper | Defender signatures current |
| System Integrity Protection *(no live fix)* | Guest account |
| Guest account | Automatic logon |
| Automatic login | Machine inactivity lock |
| Remote Login (SSH) | SMBv1 disabled |
| Remote Apple Events | RDP off, or on with NLA |
| Remote Management (ARD) | User Account Control |
| Screen-lock password | USB storage policy |
| Automatic update check | Windows Update automatic updates |
| Automatic update download/install | Password minimum length *(report only)* |
| Critical update install | Account lockout threshold *(report only)* |
| Network time | PowerShell Script Block Logging |
| Root account disabled | LLMNR disabled |
| Bluetooth Sharing disabled | Secure Boot *(report only where unsupported)* |
| Password minimum length *(report only)* | Event Log service running |

"CIS-inspired" means the controls track CIS benchmark themes at Level-1
depth; this is not a certified benchmark implementation.

## Caveat

Authored and lint-checked (shellcheck + PSScriptAnalyzer via CI); this
public copy is a work sample, not a compliance product. Audit thresholds
reflect one fleet's baseline — read the scripts before trusting the report,
and doubly before `--apply`.
