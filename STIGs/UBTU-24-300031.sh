#!/bin/bash
#
# .SYNOPSIS
#     Remediates UBTU-24-300031: Ubuntu 24.04 LTS must not allow unattended or
#     automatic login via SSH (PermitEmptyPasswords no, PermitUserEnvironment no).
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
#     STIG-ID         : UBTU-24-300031
#     Documentation   : https://stigaview.com/products/ubuntu2404/v1r5/UBTU-24-300031/
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
#     WARNING: This modifies the SSH daemon configuration. Keep a SECOND
#     session open while running so you can roll back if SSH breaks. The
#     config is validated with 'sshd -t' before the service is restarted, and
#     the backup is restored automatically if validation fails.
#
#     NOTE: Both values are already sshd's compiled-in defaults, so setting
#     them explicitly should not change behaviour. The STIG requires them to
#     be stated in the file rather than left implicit.
#
#     NOTE: Ubuntu 24.04 includes /etc/ssh/sshd_config.d/*.conf from the top
#     of sshd_config, and sshd uses the FIRST value it obtains. A drop-in can
#     therefore override this file. Conflicts are reported.
#
#     Example syntax:
#     $ sudo ./UBTU-24-300031.sh
#

set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
DROPIN_DIR="/etc/ssh/sshd_config.d"
STAMP="$(date +%Y%m%d-%H%M%S)"

# Keyword / required value pairs
declare -A SETTINGS=(
    ["PermitEmptyPasswords"]="no"
    ["PermitUserEnvironment"]="no"
)

# --- Preflight -------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "[-] Must be run as root. Try: sudo $0" >&2
    exit 1
fi

if [[ ! -f "${SSHD_CONFIG}" ]]; then
    echo "[-] File not found: ${SSHD_CONFIG}" >&2
    exit 1
fi

if ! command -v sshd >/dev/null 2>&1 && [[ ! -x /usr/sbin/sshd ]]; then
    echo "[-] sshd binary not found." >&2
    exit 1
fi
SSHD_BIN="$(command -v sshd || echo /usr/sbin/sshd)"

# --- Backup ----------------------------------------------------------------

cp -p "${SSHD_CONFIG}" "${SSHD_CONFIG}.bak.${STAMP}"
echo "[*] Backup created: ${SSHD_CONFIG}.bak.${STAMP}"

# --- Report drop-in conflicts ----------------------------------------------

if [[ -d "${DROPIN_DIR}" ]]; then
    for key in "${!SETTINGS[@]}"; do
        HITS="$(grep -rHiE "^[[:space:]]*${key}[[:space:]]+" "${DROPIN_DIR}"/*.conf 2>/dev/null || true)"
        if [[ -n "${HITS}" ]]; then
            echo "[!] ${key} is also set in a drop-in, which takes precedence:"
            printf '      %s\n' "${HITS}"
        fi
    done
fi

# --- Remediate -------------------------------------------------------------

# set_sshd_option <Keyword> <value>
# Removes every active definition, then writes one. If the file contains any
# Match blocks, the directive is inserted BEFORE the first one — a directive
# placed after a Match applies only within that block.
set_sshd_option() {
    local key="$1" val="$2" line="$1 $2" match_line

    local before
    before="$(grep -ciE "^[[:space:]]*${key}[[:space:]]" "${SSHD_CONFIG}" || true)"
    echo "[*] ${key}: ${before} active definition(s) found."

    # 'I' makes the address match case-insensitively (sshd keywords are).
    sed -i -E "/^[[:space:]]*${key}[[:space:]]/Id" "${SSHD_CONFIG}"

    # Guarantee a trailing newline before any append
    if [[ -s "${SSHD_CONFIG}" && -n "$(tail -c 1 "${SSHD_CONFIG}")" ]]; then
        echo >> "${SSHD_CONFIG}"
    fi

    match_line="$(grep -niE '^[[:space:]]*Match[[:space:]]' "${SSHD_CONFIG}" | head -1 | cut -d: -f1 || true)"

    if [[ -n "${match_line}" ]]; then
        sed -i "$((match_line - 1))a ${line}" "${SSHD_CONFIG}"
        echo "[*] Inserted before Match block at line ${match_line}: ${line}"
    else
        printf '%s\n' "${line}" >> "${SSHD_CONFIG}"
        echo "[*] Appended: ${line}"
    fi
}

for key in "${!SETTINGS[@]}"; do
    set_sshd_option "${key}" "${SETTINGS[$key]}"
done

# --- Validate before restarting --------------------------------------------

echo "[*] Validating configuration with sshd -t..."
if ! "${SSHD_BIN}" -t 2>/tmp/sshd_test_err; then
    echo "[-] Configuration is INVALID. Restoring backup and NOT restarting." >&2
    cat /tmp/sshd_test_err >&2
    cp -p "${SSHD_CONFIG}.bak.${STAMP}" "${SSHD_CONFIG}"
    rm -f /tmp/sshd_test_err
    exit 1
fi
rm -f /tmp/sshd_test_err
echo "[*] Configuration is valid."

# --- Restart ---------------------------------------------------------------

SSH_UNIT="ssh"
systemctl list-unit-files | grep -q '^sshd\.service' && SSH_UNIT="sshd"

echo "[*] Restarting ${SSH_UNIT}..."
if ! systemctl restart "${SSH_UNIT}"; then
    echo "[-] Restart failed. Restoring backup." >&2
    cp -p "${SSHD_CONFIG}.bak.${STAMP}" "${SSHD_CONFIG}"
    systemctl restart "${SSH_UNIT}" || true
    exit 1
fi

# --- Verify ----------------------------------------------------------------

echo
echo "[*] Verifying ${SSHD_CONFIG}:"
grep -inE '^[[:space:]]*Permit(EmptyPasswords|UserEnvironment)[[:space:]]' "${SSHD_CONFIG}" | grep . \
    || echo "    (no matches)"
echo

PASS=1

for key in "${!SETTINGS[@]}"; do
    val="${SETTINGS[$key]}"
    count="$(grep -ciE "^[[:space:]]*${key}[[:space:]]" "${SSHD_CONFIG}" || true)"
    if [[ "${count}" -ne 1 ]]; then
        echo "[-] ${key}: expected 1 definition, found ${count}." >&2
        PASS=0
    elif ! grep -qiE "^[[:space:]]*${key}[[:space:]]+${val}[[:space:]]*$" "${SSHD_CONFIG}"; then
        echo "[-] ${key}: not set to '${val}'." >&2
        PASS=0
    fi
done

# Confirm the running daemon agrees, accounting for drop-in overrides.
echo "[*] Effective values reported by sshd:"
"${SSHD_BIN}" -T 2>/dev/null | grep -iE '^permit(emptypasswords|userenvironment)' || echo "    (unavailable)"

for key in "${!SETTINGS[@]}"; do
    val="${SETTINGS[$key]}"
    eff="$("${SSHD_BIN}" -T 2>/dev/null | grep -i "^${key} " | awk '{print $2}' || true)"
    if [[ -n "${eff}" && "${eff,,}" != "${val}" ]]; then
        echo "[-] Effective ${key} is '${eff}', expected '${val}'. Check ${DROPIN_DIR}." >&2
        PASS=0
    fi
done

echo
if [[ ${PASS} -eq 1 ]]; then
    echo "[+] UBTU-24-300031 remediated."
    echo "[!] TEST A NEW SSH SESSION before closing this one."
    echo "[!] Rollback if needed:"
    echo "      cp ${SSHD_CONFIG}.bak.${STAMP} ${SSHD_CONFIG} && systemctl restart ${SSH_UNIT}"
    exit 0
else
    echo "[-] Verification failed. Manual review required." >&2
    echo "[-] Rollback:" >&2
    echo "      cp ${SSHD_CONFIG}.bak.${STAMP} ${SSHD_CONFIG} && systemctl restart ${SSH_UNIT}" >&2
    exit 1
fi
