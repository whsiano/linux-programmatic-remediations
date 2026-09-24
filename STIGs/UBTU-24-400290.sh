#!/bin/bash
#
# .SYNOPSIS
#     Remediates UBTU-24-400290: Ubuntu 24.04 LTS must require the change of
#     at least eight characters when passwords are changed (difok=8).
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
#     STIG-ID         : UBTU-24-400290
#     Documentation   : https://stigaview.com/products/ubuntu2404/v1r5/UBTU-24-400290/
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
#     NOTE: This affects password CHANGES going forward. Existing passwords
#     are unaffected until the next time they are changed.
#
#     Example syntax:
#     $ sudo ./UBTU-24-400290.sh
#

set -euo pipefail

PWQ_CONF="/etc/security/pwquality.conf"
PARAM="difok"
VALUE="8"
STAMP="$(date +%Y%m%d-%H%M%S)"

# --- Preflight -------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "[-] Must be run as root. Try: sudo $0" >&2
    exit 1
fi

if [[ ! -f "${PWQ_CONF}" ]]; then
    echo "[-] File not found: ${PWQ_CONF}" >&2
    echo "[-] Is libpam-pwquality installed? Try: apt install -y libpam-pwquality" >&2
    exit 1
fi

# --- Backup ----------------------------------------------------------------

cp -p "${PWQ_CONF}" "${PWQ_CONF}.bak.${STAMP}"
echo "[*] Backup created: ${PWQ_CONF}.bak.${STAMP}"

# --- Remediate -------------------------------------------------------------

# Count ACTIVE definitions only. The leading [^#] guard keeps Ubuntu's stock
# commented examples (e.g. '# difok = 1') out of the match, so they are
# neither counted nor deleted.
BEFORE="$(grep -cE "^[[:space:]]*${PARAM}[[:space:]]*=" "${PWQ_CONF}" || true)"
echo "[*] Active ${PARAM} entries found: ${BEFORE}"

# Remove every active definition, then write exactly one.
sed -i -E "/^[[:space:]]*${PARAM}[[:space:]]*=/d" "${PWQ_CONF}"

# Guarantee a trailing newline before appending, so the new setting cannot be
# concatenated onto whatever the last line happens to be.
if [[ -s "${PWQ_CONF}" && -n "$(tail -c 1 "${PWQ_CONF}")" ]]; then
    echo "[*] File lacked a trailing newline. Adding one."
    echo >> "${PWQ_CONF}"
fi

printf '%s=%s\n' "${PARAM}" "${VALUE}" >> "${PWQ_CONF}"
echo "[*] Wrote: ${PARAM}=${VALUE}"

# --- Verify ----------------------------------------------------------------

echo
echo "[*] Verifying ${PWQ_CONF}:"
grep -in "${PARAM}" "${PWQ_CONF}" || echo "    (no matches)"
echo

COUNT="$(grep -cE "^[[:space:]]*${PARAM}[[:space:]]*=" "${PWQ_CONF}" || true)"
FOUND="$(grep -E "^[[:space:]]*${PARAM}[[:space:]]*=" "${PWQ_CONF}" \
         | sed -E "s/^[[:space:]]*${PARAM}[[:space:]]*=[[:space:]]*//" | tr -d '[:space:]' || true)"

if [[ "${COUNT}" -eq 1 && "${FOUND}" == "${VALUE}" ]]; then
    echo "[+] UBTU-24-400290 remediated: ${PARAM}=${FOUND}"
    echo "[!] Applies to password CHANGES from now on; existing passwords are unaffected."
    echo "[!] Rollback if needed: cp ${PWQ_CONF}.bak.${STAMP} ${PWQ_CONF}"
    exit 0
else
    echo "[-] Verification failed: ${COUNT} entry/entries, value '${FOUND:-none}'." >&2
    echo "[-] Restore with: cp ${PWQ_CONF}.bak.${STAMP} ${PWQ_CONF}" >&2
    exit 1
fi
