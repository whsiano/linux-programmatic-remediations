#!/bin/bash
#
# .SYNOPSIS
#     Remediates UBTU-24-900600: Ubuntu 24.04 LTS must generate audit records
#     showing start and stop times for user access to the system via the
#     /var/run/utmp file.
#
# .NOTES
#     Author          : Wilson Siano
#     LinkedIn        : linkedin.com/in/whsianoo/
#     GitHub          : github.com/whsiano
#     Date Created    : 2026-09-23
#     Last Modified   : 2026-09-23
#     Version         : 1.0
#     CVEs            : N/A
#     Plugin IDs      : N/A
#     STIG-ID         : UBTU-24-900600
#     Documentation   : https://stigviewer.com/stigs/canonical_ubuntu_24.04_lts
#
# .TESTED ON
#     Date(s) Tested  : 2026-09-23
#     Tested By       : Wilson Siano
#     Systems Tested  : Ubuntu 24.04 LTS (Azure VM)
#     Bash Ver.       : 5.2.21
#
# .USAGE
#     Requires root. Requires the auditd package to be installed.
#     Example syntax:
#     $ sudo ./UBTU-24-900600.sh
#

set -euo pipefail

RULES_FILE="/etc/audit/rules.d/stig.rules"
RULE_LINE="-w /var/run/utmp -p wa -k logins"

# --- Preflight -------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "[-] Must be run as root. Try: sudo $0" >&2
    exit 1
fi

if ! command -v augenrules >/dev/null 2>&1; then
    echo "[-] auditd not installed. Run: apt install -y auditd audispd-plugins" >&2
    exit 1
fi

# --- Remediate -------------------------------------------------------------

mkdir -p "$(dirname "${RULES_FILE}")"
touch "${RULES_FILE}"

if grep -qE '^\s*-w\s+/var/run/utmp\s+-p\s+wa(\s|$)' "${RULES_FILE}"; then
    echo "[*] Rule already present in ${RULES_FILE}"
else
    echo "[*] Adding rule: ${RULE_LINE}"
    echo "${RULE_LINE}" >> "${RULES_FILE}"
fi

echo "[*] Loading audit rules..."
augenrules --load

# --- Verify ----------------------------------------------------------------

if auditctl -l | grep -q '/var/run/utmp'; then
    echo "[+] UBTU-24-900600 remediated:"
    auditctl -l | grep '/var/run/utmp'
else
    echo "[-] Rule did not load. Manual review required." >&2
    exit 1
fi
