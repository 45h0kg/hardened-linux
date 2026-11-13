# SCAP profile and tailoring

The image is remediated at build time against the **DISA STIG for Red Hat
Enterprise Linux 10** as published in the SCAP Security Guide (package
`scap-security-guide`, data stream `ssg-cs10-ds.xml`, the CentOS Stream 10
build of the RHEL 10 content). `oscap-im` applies it in the Containerfile;
`tests/scap-scan.sh` evaluates the result.

## Why the STIG

The SCAP Security Guide ships these profiles for CentOS Stream 10: ANSSI-BP-028
(minimal, intermediary, enhanced, high), BSI SYS.1.1/SYS.1.3, CIS Level 1 and
2 (server and workstation), ACSC Essential Eight, HIPAA, ACSC ISM (Official,
Secret, Top Secret), PCI-DSS v4.0.1 and DISA STIG (with and without GUI). The
STIG selects 473 rules, more than any other server profile here, and covers
the controls this image also configures by hand (audit, AIDE, fapolicyd,
USBGuard, faillock, crypto policy, SELinux), so the scan is a meaningful
second opinion on them.

## Deviations (`tailoring.xml`)

| Change | STIG says | This image | Why |
|---|---|---|---|
| `sysctl_crypto_fips_enabled` deselected, `var_system_crypto_policy` = `FUTURE:INTERNET-COMPAT` | FIPS mode, crypto policy `FIPS` | `FUTURE:INTERNET-COMPAT`, no `fips=1` | CentOS Stream ships no FIPS 140-3 validated modules. Turning FIPS mode on would make the system *behave* as FIPS without the validation that gives FIPS its meaning. FUTURE gives TLS 1.3 only, AES-256/ChaCha20 only and post-quantum hybrid key exchange; the INTERNET-COMPAT module adds classical ECDHE after the hybrids and accepts RSA-2048, because pure FUTURE could not reach quay.io or three of four NTS servers (docs/verification/crypto-policy.txt). On RHEL with validated modules, FIPS is the right choice for regulated work. |
| `var_accounts_passwords_pam_faillock_unlock_time` = 900 | `never` (an administrator must unlock) | 15 minutes | With `even_deny_root`, "never" lets anyone at the console lock every account, root included, permanently. Network logins are key-only, so faillock only guards the console and `sudo`. |

## Deliberate differences that are not tailored

These rules stay selected and fail in the scan on purpose, so the report
shows the gap rather than hiding it:

- `banner_etc_issue`: the STIG wants the exact US Government banner text.
  This image is not a US Government system; it ships a short neutral banner.
- `sshd_*`/`harden_sshd_*_crypto_policy`: these check for the STIG's
  FIPS cipher lists; with FUTURE the lists differ (see above).
- `installed_OS_is_vendor_supported`, `ensure_redhat_gpgkey_installed`:
  CentOS Stream is not RHEL.

## Results

See `docs/verification/` for the scan outputs (stock base image vs this
image, in a container; and on the booted VM, if the boot test completed).
