# endpoint-hardening-audit

CIS-inspired hardening audits for the two endpoint platforms I administer:
one script per OS, each checking ten baseline controls and printing a
PASS/FAIL report. Companion to my
[endpoint-provisioning](https://github.com/Bibitola/endpoint-provisioning)
and [intune-remediations](https://github.com/Bibitola/intune-remediations)
repos — provisioning sets machines up, remediations keep them compliant,
and this answers "how hardened is this box right now?"

**Read-only by default.** Running either script changes nothing — it reads
state and reports. Fix mode (`--apply` / `-Apply`) prompts per control, and
two controls deliberately have **no scripted fix**: FileVault/BitLocker
enablement involves a recovery-key decision that belongs to a human, and
System Integrity Protection can only be re-enabled from Recovery.

## Usage

macOS (sudo for full coverage; a couple of controls read root-only state):

```sh
sudo ./macos/audit.sh            # report only
sudo ./macos/audit.sh --apply    # prompt per failed control
```

Windows (elevated PowerShell):

```powershell
.\windows\Audit-Hardening.ps1            # report only
.\windows\Audit-Hardening.ps1 -Apply     # prompt per failed control
```

Both exit `1` when any control fails, so they slot into a scheduled job or
an RMM check as-is.

## Controls

| macOS | Windows |
|---|---|
| Application firewall | Firewall profiles (all three) |
| FileVault *(no scripted fix)* | BitLocker system drive *(no scripted fix)* |
| Gatekeeper | Defender real-time protection |
| System Integrity Protection *(no live fix)* | Guest account |
| Guest account | Automatic logon |
| Automatic login | Machine inactivity lock |
| Remote Login (SSH) | SMBv1 disabled |
| Screen-lock password | RDP off, or on with NLA |
| Automatic update check | User Account Control |
| Firewall stealth mode | USB storage policy |

"CIS-inspired" means the controls track CIS benchmark themes at Level-1
depth; this is not a certified benchmark implementation.

## Caveat

Authored and lint-checked (shellcheck + PSScriptAnalyzer via CI); this
public copy is a work sample, not a compliance product. Audit thresholds
reflect one fleet's baseline — read the scripts before trusting the report,
and doubly before `--apply`.
