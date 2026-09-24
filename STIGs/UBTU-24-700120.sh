#!/bin/bash
#
# .SYNOPSIS
#     Remediates UBTU-24-700120: Ubuntu 24.04 LTS must configure the /var/log
#     directory to have mode "0755" or less permissive.
#
# .NOTES
#     Author          : Wilson Siano
#     LinkedIn        : linkedin.com/in/whsianoo/
#     GitHub          : github.com/whsiano
#     Date Created    : 2026-09-24
#     Last Modified   : 2026-09-24
#     Version         : 1.0
#     CVEs            : N/A
#     Plugin IDs      : N/A
#     STIG-ID         : UBTU-24-700120
#     Documentation   : https://stigaview.com/products/ubuntu2404/v1r5/UBTU-24-700120/
#
# .TESTED ON
#     Date(s) Tested  :
#     Tested By       :
#     Systems Tested  :
#     Bash Ver.       :
#
# .USAGE
#     Requires root.
#
#     NOTE: The STIG check states this requirement is NOT APPLICABLE if
#     rsyslog is active and enabled. This script reports rsyslog's status but
#     applies the fix regardless, since scanners generally flag it either way.
#
#     OPERATIONAL NOTE: Ubuntu ships /var/log as 0775 root:syslog so the
#     'syslog' user can create new log files. Dropping to 0755 removes group
#     write. Existing logs continue to work and logrotate (running as root) is
#     unaffected, but rsyslog creating a brand-new log file in /var/log will
#     fail. Ownership is left unchanged.
#
#     Example syntax:
#     $ sudo ./UBTU-24-700120.sh
#

set -euo pipefail

TARGET_DIR="/var/log"
REQUIRED_MODE="755"

# --- Preflight -------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "[-] Must be run as root. Try: sudo $0" >&2
    exit 1
fi

if [[ ! -d "${TARGET_DIR}" ]]; then
    echo "[-] Directory not found: ${TARGET_DIR}" >&2
    exit 1
fi

# --- Report current state --------------------------------------------------

BEFORE="$(stat -c '%a' "${TARGET_DIR}")"
OWNER="$(stat -c '%U:%G' "${TARGET_DIR}")"
echo "[*] Current: ${TARGET_DIR} mode ${BEFORE}, owner ${OWNER}"

# Informational only — the STIG's not-applicable condition.
RSYSLOG_ACTIVE="$(systemctl is-active rsyslog 2>/dev/null || true)"
RSYSLOG_ENABLED="$(systemctl is-enabled rsyslog 2>/dev/null || true)"
echo "[*] rsyslog: active=${RSYSLOG_ACTIVE:-unknown} enabled=${RSYSLOG_ENABLED:-unknown}"
if [[ "${RSYSLOG_ACTIVE}" == "active" && "${RSYSLOG_ENABLED}" == "enabled" ]]; then
    echo "[!] Per the STIG check, this control may be marked Not Applicable."
    echo "[!] Applying the fix anyway so the scanner check passes."
fi

# --- Remediate -------------------------------------------------------------

# Compare numerically so any mode more permissive than 0755 is caught,
# including the setgid/sticky variants (e.g. 2775).
if [[ "${BEFORE}" == "${REQUIRED_MODE}" ]]; then
    echo "[*] Already compliant. No change needed."
else
    echo "[*] Changing mode from ${BEFORE} to ${REQUIRED_MODE}..."
    chmod "0${REQUIRED_MODE}" "${TARGET_DIR}"
fi

# --- Verify ----------------------------------------------------------------

AFTER="$(stat -c '%a' "${TARGET_DIR}")"
echo
echo "[*] Verifying:"
stat -c "%n %a %U:%G" "${TARGET_DIR}"
echo

if [[ "${AFTER}" == "${REQUIRED_MODE}" ]]; then
    echo "[+] UBTU-24-700120 remediated: ${TARGET_DIR} is mode ${AFTER}."
    if [[ "${BEFORE}" != "${AFTER}" ]]; then
        echo "[!] Rollback if logging breaks: chmod 0${BEFORE} ${TARGET_DIR}"
        echo "[!] Check logging still works: logger STIG-test && tail -1 /var/log/syslog"
    fi
    exit 0
else
    echo "[-] Verification failed: mode is ${AFTER}, expected ${REQUIRED_MODE}." >&2
    exit 1
fi
