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

echo
echo "Summary: $pass pass, $fail fail, $skip skipped"
[ $fail -eq 0 ]
