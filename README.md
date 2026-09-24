# Linux (Ubuntu 24.04) STIG Remediations

Bash scripts that remediate select findings from the DISA Canonical Ubuntu 24.04 LTS STIG (V1R5). Each script follows a standard header format (`.SYNOPSIS` / `.NOTES` with STIG-ID and documentation link / `.TESTED ON` / `.USAGE`) and is designed to be pulled directly onto a test VM and run.

## Usage

```bash
curl -O https://raw.githubusercontent.com/whsiano/linux-programmatic-remediations/main/STIGs/<script-name>.sh
chmod +x <script-name>.sh
sudo ./<script-name>.sh
```

Tested on an Ubuntu 24.04 Azure VM accessed via Azure Bastion.

## Scripts

| STIG-ID | Remediation |
|---|---|
| UBTU-24-200610 | Lock account after 3 unsuccessful logon attempts (`pam_faillock`) |
| UBTU-24-300031 | Disable unattended/automatic SSH login (`PermitEmptyPasswords`, `PermitUserEnvironment`) |
| UBTU-24-400280 | Enforce password complexity — require at least one numeric character |
| UBTU-24-400290 | Require at least 8 changed characters when passwords are changed |
| UBTU-24-400310 | Enforce a 60-day maximum password lifetime for new user accounts (`PASS_MAX_DAYS` in `/etc/login.defs`) |
| UBTU-24-600140 | Restrict access to the kernel message buffer (`dmesg_restrict`) |
| UBTU-24-700120 | Set `/var/log` directory permissions to 0755 or less permissive |
| UBTU-24-900280 | Generate audit records for use of the `unix_update` command |
| UBTU-24-900600 | Generate audit records for `/var/run/utmp` (login/logout tracking) |


## Disclaimer

These scripts remediate individual STIG findings for lab/training purposes and are not a substitute for a full STIG compliance scan or organizational hardening process.
