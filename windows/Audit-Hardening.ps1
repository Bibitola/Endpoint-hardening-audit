#Requires -RunAsAdministrator

# Audit-Hardening.ps1
#
# Read-only hardening audit for a Windows endpoint, CIS-inspired. Prints
# PASS/FAIL per control and a summary; exits 1 if anything failed.
#
# -Apply enables fix mode: each failed control that has a safe fix asks for
# confirmation before changing anything. Without -Apply, nothing is written.

param (
    [switch]$Apply
)

$script:pass = 0
$script:fail = 0

function Report {
    param ([string]$Status, [string]$Control, [string]$Detail)
    "{0,-6} {1,-38} {2}" -f $Status, $Control, $Detail | Write-Output
    if ($Status -eq "PASS") { $script:pass++ } else { $script:fail++ }
}

function Confirm-Fix {
    param ([string]$Description)
    if (-not $Apply) { return $false }
    $answer = Read-Host "  fix: $Description (y/n)"
    return $answer -eq "y"
}

$os = Get-CimInstance Win32_OperatingSystem
Write-Output "Hardening audit - $($os.Caption) - $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
if ($Apply) { Write-Output "APPLY MODE: failed controls with safe fixes will prompt individually" }
Write-Output ""

# 1. Firewall profiles
$profiles = Get-NetFirewallProfile
$disabled = $profiles | Where-Object { -not $_.Enabled }
if ($disabled) {
    Report FAIL "Windows Firewall" "disabled profiles: $($disabled.Name -join ', ')"
    if (Confirm-Fix "enable all firewall profiles") {
        Set-NetFirewallProfile -All -Enabled True
    }
} else {
    Report PASS "Windows Firewall" "all profiles enabled"
}

# 2. BitLocker on the system drive
try {
    $blv = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    if ($blv.ProtectionStatus -eq "On") {
        Report PASS "BitLocker (system drive)" "protection on"
    } else {
        # No auto-fix: enabling BitLocker needs a recovery-key decision, not a script
        Report FAIL "BitLocker (system drive)" "protection off - enable deliberately (no scripted fix by design)"
    }
} catch {
    Report FAIL "BitLocker (system drive)" "not available on this edition"
}

# 3. Defender real-time protection
$mp = Get-MpComputerStatus
if ($mp.RealTimeProtectionEnabled) {
    Report PASS "Defender real-time protection" "enabled"
} else {
    Report FAIL "Defender real-time protection" "disabled"
    if (Confirm-Fix "enable Defender real-time protection") {
        Set-MpPreference -DisableRealtimeMonitoring $false
    }
}

# 4. Guest account
$guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
if ($guest -and $guest.Enabled) {
    Report FAIL "Guest account" "enabled"
    if (Confirm-Fix "disable Guest account") {
        Disable-LocalUser -Name "Guest"
    }
} else {
    Report PASS "Guest account" "disabled or absent"
}

# 5. Automatic logon
$winlogon = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
if ($winlogon.AutoAdminLogon -eq "1") {
    Report FAIL "Automatic logon" "enabled for '$($winlogon.DefaultUserName)'"
    if (Confirm-Fix "disable automatic logon") {
        Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon -Value "0"
    }
} else {
    Report PASS "Automatic logon" "disabled"
}

# 6. Machine inactivity lock
$inactivity = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name InactivityTimeoutSecs -ErrorAction SilentlyContinue).InactivityTimeoutSecs
if ($inactivity -and $inactivity -gt 0 -and $inactivity -le 900) {
    Report PASS "Inactivity lock" "${inactivity}s"
} else {
    Report FAIL "Inactivity lock" "unset or over 900s"
    if (Confirm-Fix "set inactivity lock to 900s") {
        Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name InactivityTimeoutSecs -Value 900 -Type DWord
    }
}

# 7. SMBv1
$smb1 = (Get-SmbServerConfiguration).EnableSMB1Protocol
if ($smb1) {
    Report FAIL "SMBv1 protocol" "enabled"
    if (Confirm-Fix "disable SMBv1 server protocol") {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    }
} else {
    Report PASS "SMBv1 protocol" "disabled"
}

# 8. RDP Network Level Authentication (only matters if RDP is on)
$rdpEnabled = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections -eq 0
if ($rdpEnabled) {
    $nla = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication
    if ($nla -eq 1) {
        Report PASS "RDP" "enabled with Network Level Authentication"
    } else {
        Report FAIL "RDP" "enabled WITHOUT Network Level Authentication"
        if (Confirm-Fix "require NLA for RDP") {
            Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication -Value 1
        }
    }
} else {
    Report PASS "RDP" "disabled"
}

# 9. UAC
$uac = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA
if ($uac -eq 1) {
    Report PASS "User Account Control" "enabled"
} else {
    Report FAIL "User Account Control" "disabled"
    if (Confirm-Fix "re-enable UAC (takes effect after reboot)") {
        Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -Value 1 -Type DWord
    }
}

# 10. USB storage policy (fleet default: blocked)
$usbStart = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name Start -ErrorAction SilentlyContinue).Start
if ($usbStart -eq 4) {
    Report PASS "USB mass storage" "blocked (fleet default)"
} else {
    Report FAIL "USB mass storage" "allowed (start type $usbStart) - expected on exempted machines only"
}

Write-Output ""
Write-Output "Summary: $script:pass pass, $script:fail fail"
if ($script:fail -gt 0) { exit 1 }
exit 0
