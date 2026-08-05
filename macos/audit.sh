#!/bin/bash
#
# audit.sh — read-only hardening audit for a macOS endpoint, CIS-inspired.
# Prints PASS/FAIL/SKIP per control and a summary; exits 1 if anything failed.
# Run with sudo for full coverage (a few controls read root-only state).
#
# --apply enables fix mode: each failed control that has a safe fix asks for
# confirmation before changing anything. Without --apply, nothing is written.

apply=0
[ "$1" = "--apply" ] && apply=1

pass=0; fail=0; skip=0

report() { # status, control, detail
	printf '%-6s %-38s %s\n' "$1" "$2" "$3"
	case $1 in
		PASS) pass=$((pass+1)) ;;
		FAIL) fail=$((fail+1)) ;;
		SKIP) skip=$((skip+1)) ;;
	esac
}

confirm_apply() { # description, then command via eval on yes
	[ $apply -eq 1 ] || return 1
	read -r -p "  fix: $1 (y/n)? " a
	[ "$a" = "y" ]
}

is_root=0
[ "$(id -u)" -eq 0 ] && is_root=1

echo "Hardening audit — $(sw_vers -productName) $(sw_vers -productVersion) — $(date '+%Y-%m-%d %H:%M')"
[ $apply -eq 1 ] && echo "APPLY MODE: failed controls with safe fixes will prompt individually"
echo

# 1. Application firewall
fw=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)
if echo "$fw" | grep -q "enabled"; then
	report PASS "Application firewall" "enabled"
else
	report FAIL "Application firewall" "disabled"
	if confirm_apply "enable application firewall"; then
		/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
	fi
fi

# 2. FileVault
fv=$(fdesetup status 2>/dev/null)
if echo "$fv" | grep -q "FileVault is On"; then
	report PASS "FileVault disk encryption" "on"
else
	# No auto-fix: enabling FileVault needs a recovery-key conversation, not a script
	report FAIL "FileVault disk encryption" "off - enable via System Settings (no scripted fix by design)"
fi

# 3. Gatekeeper
if spctl --status 2>/dev/null | grep -q "assessments enabled"; then
	report PASS "Gatekeeper" "assessments enabled"
else
	report FAIL "Gatekeeper" "disabled"
	if confirm_apply "re-enable Gatekeeper"; then
		spctl --master-enable
	fi
fi

# 4. System Integrity Protection
if csrutil status 2>/dev/null | grep -q "enabled"; then
	report PASS "System Integrity Protection" "enabled"
else
	report FAIL "System Integrity Protection" "disabled - re-enable from Recovery (csrutil enable); no live fix exists"
fi

# 5. Guest account
guest=$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null)
if [ "$guest" = "1" ]; then
	report FAIL "Guest account" "enabled"
	if confirm_apply "disable guest account"; then
		defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false
	fi
else
	report PASS "Guest account" "disabled"
fi

# 6. Automatic login
autologin=$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null)
if [ -n "$autologin" ]; then
	report FAIL "Automatic login" "enabled for '$autologin'"
	if confirm_apply "disable automatic login"; then
		defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser
	fi
else
	report PASS "Automatic login" "disabled"
fi

# 7. Remote Login (SSH)
if [ $is_root -eq 1 ]; then
	rl=$(systemsetup -getremotelogin 2>/dev/null)
	if echo "$rl" | grep -qi "off"; then
		report PASS "Remote Login (SSH)" "off"
	else
		report FAIL "Remote Login (SSH)" "on - turn off unless this endpoint needs it"
		if confirm_apply "turn off Remote Login"; then
			systemsetup -setremotelogin off
		fi
	fi
else
	report SKIP "Remote Login (SSH)" "needs sudo to query"
fi

# 8. Screen-lock password requirement (current user)
ask=$(sysadminctl -screenLock status 2>&1)
if echo "$ask" | grep -qi "screenLock delay is immediate\|screenLock delay is [0-9]"; then
	report PASS "Screen lock password" "$(echo "$ask" | grep -oi 'screenLock.*$')"
else
	report FAIL "Screen lock password" "not requiring password after sleep/screensaver"
fi

# 9. Software update: automatic check
autochk=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null)
if [ "$autochk" = "1" ]; then
	report PASS "Automatic update check" "enabled"
else
	report FAIL "Automatic update check" "disabled"
	if confirm_apply "enable automatic update checks"; then
		defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true
	fi
fi

# 10. Firewall stealth mode
stealth=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null)
if echo "$stealth" | grep -q "enabled"; then
	report PASS "Firewall stealth mode" "enabled"
else
	report FAIL "Firewall stealth mode" "disabled"
	if confirm_apply "enable stealth mode"; then
		/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on
	fi
fi

# 11. Automatic update download/install
config_data_install=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall 2>/dev/null)
auto_download=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload 2>/dev/null)
if [ "$config_data_install" = "1" ] && [ "$auto_download" = "1" ]; then
	report PASS "Automatic update download" "enabled"
else
	report FAIL "Automatic update download" "disabled or partially configured"
	if confirm_apply "enable automatic update downloads"; then
		defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true
		defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true
	fi
fi

# 12. Critical update install
critical_install=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null)
if [ "$critical_install" = "1" ]; then
	report PASS "Critical update install" "enabled"
else
	report FAIL "Critical update install" "disabled"
	if confirm_apply "enable critical update installs"; then
		defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true
	fi
fi

# 13. Network time
using_ntp=$(systemsetup -getusingnetworktime 2>/dev/null)
if echo "$using_ntp" | grep -qi "on"; then
	report PASS "Network time" "enabled"
else
	report FAIL "Network time" "disabled"
	if confirm_apply "enable network time"; then
		systemsetup -setusingnetworktime on
	fi
fi

# 14. Root account
root_auth=$(dscl . -read /Users/root AuthenticationAuthority 2>/dev/null)
if echo "$root_auth" | grep -q ";DisabledUser;" || [ -z "$root_auth" ]; then
	report PASS "Root account" "disabled"
else
	report FAIL "Root account" "may be enabled - validate with Directory Utility (report only)"
fi

# 15. Bluetooth Sharing
bt_share=$(defaults -currentHost read com.apple.Bluetooth PrefKeyServicesEnabled 2>/dev/null)
if [ "$bt_share" = "1" ]; then
	report FAIL "Bluetooth Sharing" "enabled"
	if confirm_apply "disable Bluetooth Sharing for current host"; then
		defaults -currentHost write com.apple.Bluetooth PrefKeyServicesEnabled -bool false
	fi
else
	report PASS "Bluetooth Sharing" "disabled or not configured"
fi

# 16. Remote Apple Events
rae=$(systemsetup -getremoteappleevents 2>/dev/null)
if echo "$rae" | grep -qi "off"; then
	report PASS "Remote Apple Events" "off"
else
	report FAIL "Remote Apple Events" "on"
	if confirm_apply "turn off Remote Apple Events"; then
		systemsetup -setremoteappleevents off
	fi
fi

# 17. Remote Management (ARD)
if [ -x /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart ]; then
	ard=$(/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -status 2>&1)
	if echo "$ard" | grep -qi "not running\|currently off\|disabled"; then
		report PASS "Remote Management" "off"
	else
		report FAIL "Remote Management" "on"
		if confirm_apply "turn off Remote Management"; then
			/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop
		fi
	fi
else
	report SKIP "Remote Management" "kickstart tool unavailable"
fi

# 18. Password minimum length
pwpolicy=$(pwpolicy getaccountpolicies 2>/dev/null)
min_chars=$(printf '%s\n' "$pwpolicy" | awk -F'[<>]' '/policyAttributePassword matches/ {found=1} found && /minimumLength/ {print $3; exit}')
if [ -n "$min_chars" ] && [ "$min_chars" -ge 14 ] 2>/dev/null; then
	report PASS "Password minimum length" "$min_chars characters"
else
	report FAIL "Password minimum length" "${min_chars:-unknown} characters - expected 14+ (report only)"
fi

echo
echo "Summary: $pass pass, $fail fail, $skip skipped"
[ $fail -eq 0 ]
