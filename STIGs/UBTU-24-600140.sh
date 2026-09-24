#!/bin/bash
#
# .SYNOPSIS
#     Remediates UBTU-24-600140: Ubuntu 24.04 LTS must restrict access to the
#     kernel message buffer (kernel.dmesg_restrict = 1).
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
#     STIG-ID         : UBTU-24-600140
#     Documentation   : https://stigaview.com/products/ubuntu2404/v1r5/UBTU-24-600140/
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
#     The check has two parts: the RUNTIME value must be 1, and a CONFIG FILE
#     must set it so the value survives a reboot. A system can pass the first
#     and fail the second.
#
#     Conflicting entries in package-owned directories (/usr/lib/sysctl.d,
#     /lib/sysctl.d) are reported but NOT edited — those files belong to
#     packages and are restored on upgrade. The file this script writes sorts
#     last and takes precedence over them anyway.
#
#     Example syntax:
#     $ sudo ./UBTU-24-600140.sh
#

set -euo pipefail

PARAM="kernel.dmesg_restrict"
VALUE="1"
STIG_CONF="/etc/sysctl.d/99-stig-dmesg-restrict.conf"
STAMP="$(date +%Y%m%d-%H%M%S)"

# Writable locations this script will edit
EDITABLE_DIRS=("/etc/sysctl.d" "/run/sysctl.d" "/usr/local/lib/sysctl.d")
EDITABLE_FILES=("/etc/sysctl.conf")

# Package-owned locations — reported only
READONLY_DIRS=("/usr/lib/sysctl.d" "/lib/sysctl.d")

# --- Preflight -------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "[-] Must be run as root. Try: sudo $0" >&2
    exit 1
fi

if ! command -v sysctl >/dev/null 2>&1; then
    echo "[-] sysctl command not found." >&2
    exit 1
fi

RUNTIME_BEFORE="$(sysctl -n "${PARAM}" 2>/dev/null || echo "unset")"
echo "[*] Current runtime value: ${PARAM} = ${RUNTIME_BEFORE}"

# --- Survey existing configuration -----------------------------------------

# Collect every file that holds an ACTIVE (uncommented) entry.
mapfile -t FOUND_FILES < <(
    {
        for d in "${EDITABLE_DIRS[@]}" "${READONLY_DIRS[@]}"; do
            [[ -d "${d}" ]] && grep -lE "^[[:space:]]*${PARAM}[[:space:]]*=" "${d}"/*.conf 2>/dev/null || true
        done
        for f in "${EDITABLE_FILES[@]}"; do
            [[ -f "${f}" ]] && grep -lE "^[[:space:]]*${PARAM}[[:space:]]*=" "${f}" 2>/dev/null || true
        done
    } | sort -u
)

if [[ ${#FOUND_FILES[@]} -eq 0 ]]; then
    echo "[*] No existing ${PARAM} entries found in any sysctl location."
else
    echo "[*] Existing ${PARAM} entries found in:"
    for f in "${FOUND_FILES[@]}"; do
        echo "      ${f}: $(grep -hE "^[[:space:]]*${PARAM}[[:space:]]*=" "${f}" | tr '\n' ';')"
    done
fi

# --- Remove conflicting entries from writable locations --------------------

for f in "${FOUND_FILES[@]}"; do
    # Skip the file this script owns; it is rewritten below.
    [[ "${f}" == "${STIG_CONF}" ]] && continue

    IS_READONLY=0
    for d in "${READONLY_DIRS[@]}"; do
        [[ "${f}" == "${d}"/* ]] && IS_READONLY=1
    done

    if [[ ${IS_READONLY} -eq 1 ]]; then
        echo "[!] Package-owned, not editing: ${f}"
        echo "[!]   ${STIG_CONF} sorts later and overrides it."
        continue
    fi

    cp -p "${f}" "${f}.bak.${STAMP}"
    # Comment out rather than delete, so the original intent stays visible.
    sed -i -E "s|^([[:space:]]*${PARAM}[[:space:]]*=.*)$|# Disabled by UBTU-24-600140 remediation: \1|" "${f}"
    echo "[*] Commented out entry in ${f} (backup: ${f}.bak.${STAMP})"
done

# --- Write the authoritative setting ---------------------------------------

if [[ -f "${STIG_CONF}" ]]; then
    cp -p "${STIG_CONF}" "${STIG_CONF}.bak.${STAMP}"
fi

cat > "${STIG_CONF}" <<EOF
# UBTU-24-600140 - restrict access to the kernel message buffer
# Managed by linux-programmatic-remediations
${PARAM} = ${VALUE}
EOF
chmod 644 "${STIG_CONF}"
echo "[*] Wrote ${STIG_CONF}"

# --- Apply -----------------------------------------------------------------

echo "[*] Reloading sysctl settings..."
sysctl --system >/dev/null

# --- Verify ----------------------------------------------------------------

RUNTIME_AFTER="$(sysctl -n "${PARAM}" 2>/dev/null || echo "unset")"

echo
echo "[*] Runtime value: ${PARAM} = ${RUNTIME_AFTER}"
echo "[*] Active config entries:"
grep -rHE "^[[:space:]]*${PARAM}[[:space:]]*=" \
    /run/sysctl.d/ /etc/sysctl.d/ /usr/local/lib/sysctl.d/ \
    /usr/lib/sysctl.d/ /lib/sysctl.d/ /etc/sysctl.conf 2>/dev/null \
    || echo "    (none)"
echo

PASS=1

if [[ "${RUNTIME_AFTER}" != "${VALUE}" ]]; then
    echo "[-] Runtime value is '${RUNTIME_AFTER}', expected ${VALUE}." >&2
    PASS=0
fi

# Any active entry set to something other than 1 is a finding.
CONFLICTS="$(grep -rhE "^[[:space:]]*${PARAM}[[:space:]]*=" \
    /run/sysctl.d/ /etc/sysctl.d/ /usr/local/lib/sysctl.d/ \
    /usr/lib/sysctl.d/ /lib/sysctl.d/ /etc/sysctl.conf 2>/dev/null \
    | grep -vE "=[[:space:]]*${VALUE}[[:space:]]*$" || true)"

if [[ -n "${CONFLICTS}" ]]; then
    echo "[-] Conflicting entries remain:" >&2
    printf '      %s\n' "${CONFLICTS}" >&2
    PASS=0
fi

# At least one config file must set it, or the value will not survive reboot.
CONF_COUNT="$(grep -rhE "^[[:space:]]*${PARAM}[[:space:]]*=[[:space:]]*${VALUE}" \
    /run/sysctl.d/ /etc/sysctl.d/ /usr/local/lib/sysctl.d/ \
    /usr/lib/sysctl.d/ /lib/sysctl.d/ /etc/sysctl.conf 2>/dev/null | wc -l)"

if [[ "${CONF_COUNT}" -lt 1 ]]; then
    echo "[-] No config file sets ${PARAM}=${VALUE}." >&2
    PASS=0
fi

if [[ ${PASS} -eq 1 ]]; then
    echo "[+] UBTU-24-600140 remediated: ${PARAM} = ${RUNTIME_AFTER} (persisted in ${STIG_CONF})"
    echo "[!] Verify after reboot with: sysctl ${PARAM}"
    echo "[!] Rollback: rm ${STIG_CONF} && sysctl --system"
    exit 0
else
    echo "[-] Verification failed. Manual review required." >&2
    echo "[-] Rollback: rm ${STIG_CONF} && sysctl --system" >&2
    exit 1
fi
