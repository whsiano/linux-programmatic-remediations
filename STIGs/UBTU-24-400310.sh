#!/bin/bash
#
# .SYNOPSIS
#     Remediates UBTU-24-400310: Ubuntu 24.04 LTS must enforce a 60-day
#     maximum password lifetime for new user accounts.
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
#     STIG-ID         : UBTU-24-400310
#     Documentation   : https://stigaview.com/products/ubuntu2404/v1r5/UBTU-24-400310/
#
# .TESTED ON
#     Date(s) Tested  :
#     Tested By       :
#     Systems Tested  :
#     Bash Ver.       :
#
# .USAGE
#     Requires root.
#     NOTE: /etc/login.defs applies to NEWLY created accounts only. Existing
#     accounts keep their current setting unless changed with chage.
#
#     Example syntax:
#     $ sudo ./UBTU-24-400310.sh
#

set -euo pipefail

LOGIN_DEFS="/etc/login.defs"
PARAM="PASS_MAX_DAYS"
VALUE="60"
STAMP="$(date +%Y%m%d-%H%M%S)"

# --- Preflight -------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "[-] Must be run as root. Try: sudo $0" >&2
    exit 1
fi

if [[ ! -f "${LOGIN_DEFS}" ]]; then
    echo "[-] File not found: ${LOGIN_DEFS}" >&2
    exit 1
fi

# --- Backup ----------------------------------------------------------------

cp -p "${LOGIN_DEFS}" "${LOGIN_DEFS}.bak.${STAMP}"
echo "[*] Backup created: ${LOGIN_DEFS}.bak.${STAMP}"

# --- Remediate -------------------------------------------------------------

if grep -qE "^\s*#?\s*${PARAM}\b" "${LOGIN_DEFS}"; then
    # Replace the first occurrence, comment out any duplicates after it
    sed -i -E "0,/^\s*#?\s*${PARAM}\b.*/s||${PARAM}\t${VALUE}|" "${LOGIN_DEFS}"
    echo "[*] Set: ${PARAM} ${VALUE}"
else
    printf '%s\t%s\n' "${PARAM}" "${VALUE}" >> "${LOGIN_DEFS}"
    echo "[*] Added: ${PARAM} ${VALUE}"
fi

# --- Verify ----------------------------------------------------------------

echo
echo "[*] Verifying ${LOGIN_DEFS}:"
grep -i "^${PARAM}" "${LOGIN_DEFS}" || true
echo

FOUND="$(grep -iE "^${PARAM}\s+" "${LOGIN_DEFS}" | head -1 | awk '{print $2}')"

if [[ "${FOUND}" == "${VALUE}" ]]; then
    echo "[+] UBTU-24-400310 remediated: ${PARAM} = ${FOUND}"
    echo "[!] This applies to NEW accounts only."
    echo "[!] To apply to an existing account: chage -M ${VALUE} <username>"
    echo "[!] To audit existing accounts:      chage -l <username>"
    exit 0
else
    echo "[-] Verification failed. Found value: '${FOUND:-none}'. Manual review required." >&2
    exit 1
fi
