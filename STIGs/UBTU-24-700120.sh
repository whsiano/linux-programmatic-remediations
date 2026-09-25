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
#     Version         : 1.1
#     CVEs            : N/A
#     Plugin IDs      : N/A
#     STIG-ID         : UBTU-24-700120
#     Documentation   : https://stigaview.com/products/ubuntu2404/v1r5/UBTU-24-700120/
#
# .CHANGELOG
#     1.1 - chmod alone did not persist. systemd-tmpfiles re-applies 0775 from
#           /usr/lib/tmpfiles.d/00rsyslog.conf at every boot, so the fix
#           reverted on reboot. This version installs an override in
#           /etc/tmpfiles.d/ with the same filename, which takes precedence.
#     1.0 - Initial version (chmod only; did not survive reboot).
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
PKG_TMPFILES="/usr/lib/tmpfiles.d/00rsyslog.conf"
OVERRIDE_TMPFILES="/etc/tmpfiles.d/00rsyslog.conf"
STAMP="$(date +%Y%m%d-%H%M%S)"

# --- Preflight -------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "[-] Must be run as root. Try: sudo $0" >&2
    exit 1
fi

if [[ ! -d "${TARGET_DIR}" ]]; then
    echo "[-] Directory not found: ${TARGET_DIR}" >&2
    exit 1
fi

BEFORE="$(stat -c '%a' "${TARGET_DIR}")"
OWNER="$(stat -c '%U:%G' "${TARGET_DIR}")"
echo "[*] Current: ${TARGET_DIR} mode ${BEFORE}, owner ${OWNER}"

RSYSLOG_ACTIVE="$(systemctl is-active rsyslog 2>/dev/null || true)"
RSYSLOG_ENABLED="$(systemctl is-enabled rsyslog 2>/dev/null || true)"
echo "[*] rsyslog: active=${RSYSLOG_ACTIVE:-unknown} enabled=${RSYSLOG_ENABLED:-unknown}"
if [[ "${RSYSLOG_ACTIVE}" == "active" && "${RSYSLOG_ENABLED}" == "enabled" ]]; then
    echo "[!] Per the STIG check, this control may be marked Not Applicable."
    echo "[!] Applying the fix anyway so the scanner check passes."
fi

# --- Report what enforces the mode at boot ---------------------------------

echo "[*] tmpfiles entries governing ${TARGET_DIR}:"
grep -rHE "^[[:space:]]*[a-zA-Z]+[[:space:]]+${TARGET_DIR}[[:space:]]" \
    /usr/lib/tmpfiles.d/ /etc/tmpfiles.d/ /run/tmpfiles.d/ 2>/dev/null | grep . \
    || echo "    (none found)"

# --- Install the tmpfiles override -----------------------------------------

# systemd-tmpfiles reads /etc/tmpfiles.d first; a file there with the same
# name as one in /usr/lib/tmpfiles.d replaces it entirely. So the package file
# is copied wholesale and only the /var/log mode is changed — that keeps every
# other entry the package defines intact.
if [[ -f "${PKG_TMPFILES}" ]]; then
    if [[ -f "${OVERRIDE_TMPFILES}" ]]; then
        cp -p "${OVERRIDE_TMPFILES}" "${OVERRIDE_TMPFILES}.bak.${STAMP}"
        echo "[*] Existing override backed up: ${OVERRIDE_TMPFILES}.bak.${STAMP}"
    fi

    mkdir -p /etc/tmpfiles.d

    {
        echo "# UBTU-24-700120 override of ${PKG_TMPFILES}"
        echo "# Managed by linux-programmatic-remediations"
        echo "# Only the ${TARGET_DIR} mode differs from the packaged file."
        sed -E "s|^([[:space:]]*[a-zA-Z]+[[:space:]]+${TARGET_DIR}[[:space:]]+)0?[0-7]{3}|\10${REQUIRED_MODE}|" \
            "${PKG_TMPFILES}"
    } > "${OVERRIDE_TMPFILES}"

    chmod 644 "${OVERRIDE_TMPFILES}"
    echo "[*] Wrote override: ${OVERRIDE_TMPFILES}"
    echo "[*] Override contents for ${TARGET_DIR}:"
    grep -E "${TARGET_DIR}" "${OVERRIDE_TMPFILES}" | sed 's/^/      /' || true
else
    echo "[!] ${PKG_TMPFILES} not found; skipping override."
    echo "[!] If the mode reverts on reboot, check which tmpfiles entry applies."
fi

# --- Apply now -------------------------------------------------------------

if [[ "${BEFORE}" == "${REQUIRED_MODE}" ]]; then
    echo "[*] Mode already ${REQUIRED_MODE}."
else
    echo "[*] Changing mode from ${BEFORE} to ${REQUIRED_MODE}..."
    chmod "0${REQUIRED_MODE}" "${TARGET_DIR}"
fi

# Re-run tmpfiles so the result matches what a boot would produce. If the
# override is wrong, this reverts the mode immediately and the verify below
# catches it — rather than the problem surfacing after the next reboot.
if command -v systemd-tmpfiles >/dev/null 2>&1; then
    echo "[*] Re-applying systemd-tmpfiles to simulate boot behaviour..."
    systemd-tmpfiles --create >/dev/null 2>&1 || true
fi

# --- Verify ----------------------------------------------------------------

AFTER="$(stat -c '%a' "${TARGET_DIR}")"
echo
echo "[*] Verifying:"
stat -c "%n %a %U:%G" "${TARGET_DIR}"
echo

if [[ "${AFTER}" == "${REQUIRED_MODE}" ]]; then
    echo "[+] UBTU-24-700120 remediated: ${TARGET_DIR} is mode ${AFTER}."
    echo "[+] Mode survived a systemd-tmpfiles run, so it should survive reboot."
    echo "[!] Confirm after reboot with: stat -c '%n %a' ${TARGET_DIR}"
    echo "[!] Check logging still works: logger STIG-test && tail -1 /var/log/syslog"
    echo "[!] Rollback: rm -f ${OVERRIDE_TMPFILES} && chmod 0${BEFORE} ${TARGET_DIR}"
    exit 0
else
    echo "[-] Verification failed: mode is ${AFTER}, expected ${REQUIRED_MODE}." >&2
    echo "[-] systemd-tmpfiles likely re-applied a different mode." >&2
    echo "[-] Rollback: rm -f ${OVERRIDE_TMPFILES} && chmod 0${BEFORE} ${TARGET_DIR}" >&2
    exit 1
fi
