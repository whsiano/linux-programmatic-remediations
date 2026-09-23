#!/bin/bash
#
# .SYNOPSIS
#     Remediates UBTU-24-200610: Ubuntu 24.04 LTS must automatically lock an
#     account until the locked account is released by an administrator when
#     three unsuccessful logon attempts occur.
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
#     STIG-ID         : UBTU-24-200610
#     Documentation   : https://stigaview.com/products/ubuntu2404/v1r5/UBTU-24-200610/
#
# .TESTED ON
#     Date(s) Tested  :
#     Tested By       :
#     Systems Tested  :
#     Bash Ver.       :
#
# .USAGE
#     Requires root.
#     WARNING: This script modifies the PAM authentication stack. Keep an
#     existing root session open while testing so you can roll back if
#     authentication breaks. Backups are written alongside the originals.
#
#     Example syntax:
#     $ sudo ./UBTU-24-200610.sh
#

set -euo pipefail

PAM_FILE="/etc/pam.d/common-auth"
FAILLOCK_CONF="/etc/security/faillock.conf"
STAMP="$(date +%Y%m%d-%H%M%S)"

AUTHFAIL_LINE="auth [default=die] pam_faillock.so authfail"
AUTHSUCC_LINE="auth sufficient pam_faillock.so authsucc"

# --- Preflight -------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "[-] Must be run as root. Try: sudo $0" >&2
    exit 1
fi

for f in "${PAM_FILE}" "${FAILLOCK_CONF}"; do
    if [[ ! -f "${f}" ]]; then
        echo "[-] Required file not found: ${f}" >&2
        exit 1
    fi
done

if ! ls /usr/lib/*/security/pam_faillock.so >/dev/null 2>&1; then
    echo "[-] pam_faillock.so module not found on this system." >&2
    exit 1
fi

# --- Backup ----------------------------------------------------------------

cp -p "${PAM_FILE}"      "${PAM_FILE}.bak.${STAMP}"
cp -p "${FAILLOCK_CONF}" "${FAILLOCK_CONF}.bak.${STAMP}"
echo "[*] Backups created with suffix .bak.${STAMP}"

rollback() {
    echo "[-] Error detected. Rolling back ${PAM_FILE}..." >&2
    cp -p "${PAM_FILE}.bak.${STAMP}" "${PAM_FILE}"
    echo "[-] Rollback complete. Review the file manually." >&2
}

# --- Remediate: /etc/security/faillock.conf --------------------------------

# set_kv <keyword> <value-or-empty>
# Handles three cases: commented out, present with wrong value, or absent.
set_kv() {
    local key="$1" val="${2:-}" line
    if [[ -n "${val}" ]]; then
        line="${key} = ${val}"
    else
        line="${key}"
    fi

    if grep -qE "^\s*#?\s*${key}\b" "${FAILLOCK_CONF}"; then
        sed -i -E "s|^\s*#?\s*${key}\b.*|${line}|" "${FAILLOCK_CONF}"
        echo "[*] Set: ${line}"
    else
        echo "${line}" >> "${FAILLOCK_CONF}"
        echo "[*] Added: ${line}"
    fi
}

echo "[*] Configuring ${FAILLOCK_CONF}..."
set_kv "audit"
set_kv "silent"
set_kv "deny" "3"
set_kv "fail_interval" "900"
set_kv "unlock_time" "0"

# --- Remediate: /etc/pam.d/common-auth -------------------------------------

echo "[*] Configuring ${PAM_FILE}..."

trap rollback ERR

if grep -qE '^\s*auth\s+\[default=die\]\s+pam_faillock\.so\s+authfail' "${PAM_FILE}"; then
    echo "[*] authfail line already present."
else
    # Insert directly after the last auth line referencing pam_unix.so
    if grep -qE '^\s*auth\s+.*pam_unix\.so' "${PAM_FILE}"; then
        LAST_UNIX="$(grep -nE '^\s*auth\s+.*pam_unix\.so' "${PAM_FILE}" | tail -1 | cut -d: -f1)"
        sed -i "${LAST_UNIX}a ${AUTHFAIL_LINE}" "${PAM_FILE}"
        echo "[*] Added authfail line after line ${LAST_UNIX}."
    else
        echo "[-] No pam_unix.so auth line found. Manual review required." >&2
        exit 1
    fi
fi

if grep -qE '^\s*auth\s+sufficient\s+pam_faillock\.so\s+authsucc' "${PAM_FILE}"; then
    echo "[*] authsucc line already present."
else
    LAST_FAIL="$(grep -nE 'pam_faillock\.so\s+authfail' "${PAM_FILE}" | tail -1 | cut -d: -f1)"
    sed -i "${LAST_FAIL}a ${AUTHSUCC_LINE}" "${PAM_FILE}"
    echo "[*] Added authsucc line after line ${LAST_FAIL}."
fi

trap - ERR

# --- Verify ----------------------------------------------------------------

echo
echo "[*] Verifying ${PAM_FILE}:"
grep faillock "${PAM_FILE}" || true

echo
echo "[*] Verifying ${FAILLOCK_CONF}:"
grep -E '^(audit|silent|deny|fail_interval|unlock_time)\b' "${FAILLOCK_CONF}" || true

echo
PASS=1
grep -qE '^\s*auth\s+\[default=die\]\s+pam_faillock\.so\s+authfail' "${PAM_FILE}" || PASS=0
grep -qE '^\s*auth\s+sufficient\s+pam_faillock\.so\s+authsucc'      "${PAM_FILE}" || PASS=0
grep -qE '^audit\b'                    "${FAILLOCK_CONF}" || PASS=0
grep -qE '^silent\b'                   "${FAILLOCK_CONF}" || PASS=0
grep -qE '^deny\s*=\s*[1-3]\b'         "${FAILLOCK_CONF}" || PASS=0
grep -qE '^fail_interval\s*=\s*900\b'  "${FAILLOCK_CONF}" || PASS=0
grep -qE '^unlock_time\s*=\s*0\b'      "${FAILLOCK_CONF}" || PASS=0

if [[ ${PASS} -eq 1 ]]; then
    echo "[+] UBTU-24-200610 remediated."
    echo "[!] Test authentication in a SECOND session before closing this one."
    echo "[!] Rollback if needed: cp ${PAM_FILE}.bak.${STAMP} ${PAM_FILE}"
    exit 0
else
    echo "[-] Verification failed. Manual review required." >&2
    exit 1
fi
