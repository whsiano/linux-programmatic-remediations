#!/bin/bash
#
# .SYNOPSIS
#     Remediates UBTU-24-900280: Ubuntu 24.04 LTS must generate audit records
#     for successful/unsuccessful uses of the unix_update command.
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
#     STIG-ID         : UBTU-24-900280
#     Documentation   : https://stigaview.com/products/ubuntu2404/v1r5/UBTU-24-900280/
#
# .TESTED ON
#     Date(s) Tested  :
#     Tested By       :
#     Systems Tested  :
#     Bash Ver.       :
#
# .USAGE
#     Requires root. Requires the auditd package.
#
#     Example syntax:
#     $ sudo ./UBTU-24-900280.sh
#

set -euo pipefail

RULES_DIR="/etc/audit/rules.d"
RULES_FILE="${RULES_DIR}/stig.rules"
TARGET_PATH="/sbin/unix_update"
RULE_LINE="-a always,exit -F path=${TARGET_PATH} -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-unix-update"
STAMP="$(date +%Y%m%d-%H%M%S)"

# --- Preflight -------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "[-] Must be run as root. Try: sudo $0" >&2
    exit 1
fi

if ! command -v augenrules >/dev/null 2>&1 || ! command -v auditctl >/dev/null 2>&1; then
    echo "[-] auditd not installed. Run: apt install -y auditd audispd-plugins" >&2
    exit 1
fi

if [[ ! -e "${TARGET_PATH}" ]]; then
    echo "[!] Warning: ${TARGET_PATH} does not exist on this system."
    echo "[!] The rule will still be written, but nothing will trigger it."
fi

mkdir -p "${RULES_DIR}"
touch "${RULES_FILE}"

# --- Backup ----------------------------------------------------------------

cp -p "${RULES_FILE}" "${RULES_FILE}.bak.${STAMP}"
echo "[*] Backup created: ${RULES_FILE}.bak.${STAMP}"

# --- Remediate -------------------------------------------------------------

# Count active rules referencing this path. Commented lines are excluded by
# anchoring on the leading '-a', so documentation is left alone.
BEFORE="$(grep -cE "^[[:space:]]*-a[[:space:]].*path=${TARGET_PATH}([[:space:]]|$)" "${RULES_FILE}" || true)"
echo "[*] Active rules for ${TARGET_PATH} found: ${BEFORE}"

# Remove every active rule for this path, then write exactly one.
# '#' is used as the sed delimiter because the path contains slashes.
sed -i "\#^[[:space:]]*-a[[:space:]].*path=${TARGET_PATH}\([[:space:]]\|$\)#d" "${RULES_FILE}"

# Guarantee a trailing newline before appending, so the rule cannot be
# concatenated onto whatever the last line happens to be.
if [[ -s "${RULES_FILE}" && -n "$(tail -c 1 "${RULES_FILE}")" ]]; then
    echo "[*] File lacked a trailing newline. Adding one."
    echo >> "${RULES_FILE}"
fi

printf '%s\n' "${RULE_LINE}" >> "${RULES_FILE}"
echo "[*] Wrote rule: ${RULE_LINE}"

# --- Load ------------------------------------------------------------------

echo "[*] Loading audit rules with augenrules..."
if ! augenrules --load; then
    echo "[-] augenrules failed. Restoring backup." >&2
    cp -p "${RULES_FILE}.bak.${STAMP}" "${RULES_FILE}"
    augenrules --load || true
    exit 1
fi

# --- Verify ----------------------------------------------------------------

echo
echo "[*] Verifying ${RULES_FILE}:"
grep -n "unix_update" "${RULES_FILE}" || echo "    (no matches)"

echo
echo "[*] Verifying loaded rules (auditctl -l):"
auditctl -l | grep -w "unix_update" || echo "    (no matches)"
echo

PASS=1

FILE_COUNT="$(grep -cE "^[[:space:]]*-a[[:space:]].*path=${TARGET_PATH}([[:space:]]|$)" "${RULES_FILE}" || true)"
if [[ "${FILE_COUNT}" -ne 1 ]]; then
    echo "[-] Expected 1 rule in ${RULES_FILE}, found ${FILE_COUNT}." >&2
    PASS=0
fi

# The kernel normalises the rule when it loads, so check the key components
# rather than an exact string match.
LOADED="$(auditctl -l | grep -w "unix_update" || true)"
for token in "path=${TARGET_PATH}" "perm=x" "auid>=1000" "unix-update"; do
    if ! printf '%s' "${LOADED}" | grep -q -- "${token}"; then
        echo "[-] Loaded rule missing expected component: ${token}" >&2
        PASS=0
    fi
done

if [[ ${PASS} -eq 1 ]]; then
    echo "[+] UBTU-24-900280 remediated. Rule is active."
    echo "[!] Rollback if needed:"
    echo "      cp ${RULES_FILE}.bak.${STAMP} ${RULES_FILE} && augenrules --load"
    exit 0
else
    echo "[-] Verification failed. Manual review required." >&2
    echo "[-] Rollback:" >&2
    echo "      cp ${RULES_FILE}.bak.${STAMP} ${RULES_FILE} && augenrules --load" >&2
    exit 1
fi
