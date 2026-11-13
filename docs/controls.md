# Controls

Every control in the image: where it lives, what it stops, what it costs, and
how far it was verified.

**Verification levels**

- **Container**: checked by `tests/container-checks.sh` (or the SCAP scan)
  inside a container of the built image. Proves the files, values, packages
  and policy are in the image and that each program accepts its
  configuration. A container shares Docker's kernel and has no systemd, so
  it cannot prove anything about the kernel or running services.
- **Boot**: observed on the image booted in a QEMU VM (`boot/`), in
  `docs/verification/boot-report.txt`.
- **Configured**: in the image or repository, not exercised by any test here.

<!-- BOOT-STATUS -->

## 1. Mandatory access control: SELinux

| Item | Where | Verified |
|---|---|---|
| Enforcing, targeted policy | `/etc/selinux/config` (Containerfile step 5) | Container (config), Boot |
| fapolicyd and USBGuard policy modules | `fapolicyd-selinux`, `usbguard-selinux` packages | Container (`semodule -l`) |
| Confined users: `%wheel` → `staff_u`, everyone else → `user_u` | `semanage import`, step 5 | Container (`semanage login -l`), Boot |
| sudo lands in `sysadm_r`/`sysadm_t` | `/etc/sudoers.d/00-hardening` | Container (`visudo -c`); not exercised with a real login |
| Booleans `deny_ptrace`, `deny_execmem`, `secure_mode_policyload` on; `selinuxuser_execmod/execstack/execheap`, `user_exec_content`, `ssh_sysadm_login` off | step 5 | Container (compiled policy via `seinfo`), Boot (`getsebool`) |

**Stops**: a compromised service reading or writing outside its type
(`httpd_t` cannot read `shadow_t`); users running downloaded programs from
their home; root switching SELinux off at runtime (`secure_mode_policyload`).
**Costs**: custom services need policy or run as `unconfined_service_t`;
`deny_ptrace` breaks `gdb`/`strace` on other processes until the boolean is
changed, and with `secure_mode_policyload` it cannot be changed without a new
image. **MLS**: the `mls` policy enforces Bell-LaPadula levels (no read up,
no write down) and is meant for systems handling several classification
levels; it needs labelled networking and printing, breaks most third-party
software, and is not used here.

## 2. Kernel command line (`/usr/lib/bootc/kargs.d/`)

| Argument | Stops | Cost |
|---|---|---|
| `lockdown=confidentiality` | root modifying or reading kernel memory (/dev/mem, kprobes, unsigned kexec, /proc/kcore, hibernation) | no hibernation; some eBPF tracing (`bpf_probe_read_kernel`) refused |
| `module.sig_enforce=1` | loading unsigned kernel modules (rootkits) | out-of-tree drivers (NVIDIA, ZFS, VirtualBox) need signing with an enrolled key |
| `lsm=lockdown,yama,integrity,selinux,bpf,landlock` | a kernel default silently dropping an LSM | none (same as the kernel's own default) |
| `init_on_alloc=1 init_on_free=1 page_poison=1` | uninitialised-memory and use-after-free info leaks | a few percent on allocation-heavy work |
| `slab_nomerge page_alloc.shuffle=1 randomize_kstack_offset=on` | heap grooming and predictable stack offsets | small |
| `mitigations=auto,nosmt` | CPU side channels; cross-hyperthread leaks | x86 with SMT loses half its logical CPUs |
| `debugfs=off` | debugfs info leaks and bugs | some tracing and debugging tools |
| `iommu.strict=1 iommu.passthrough=0 efi=disable_early_pci_dma` (+ `intel_iommu=on amd_iommu=force_isolation` on x86) | DMA attacks from malicious devices | some I/O throughput |
| `audit=1 audit_backlog_limit=8192` | early-boot events going unaudited | memory for the backlog |
| `random.trust_cpu=off random.trust_bootloader=off` | trusting a backdoored RDRAND or bootloader seed alone | marginally slower early entropy |
| x86 only: `vsyscall=none pti=on ia32_emulation=0 tsx=off` | vsyscall gadgets, Meltdown, 32-bit syscall bugs, TAA | very old binaries using vsyscall; 32-bit programs |

Verified: Container (files and values), Boot (`/proc/cmdline`,
`/sys/kernel/security/lockdown`, `/sys/kernel/security/lsm`).

## 3. Kernel tunables (`/etc/sysctl.d/zz-hardening.conf`)

`kptr_restrict=2`, `dmesg_restrict=1`, `unprivileged_bpf_disabled=1`,
`bpf_jit_harden=2`, `yama.ptrace_scope=2`, `kexec_load_disabled=1`,
`perf_event_paranoid=2`, `sysrq=0`, `randomize_va_space=2`,
`io_uring_disabled=2`, `unprivileged_userfaultfd=0`, `ldisc_autoload=0`,
`legacy_tiocsti=0`, `user.max_user_namespaces=0`, `fs.protected_*`,
`suid_dumpable=0`, `core_pattern=|/bin/false`, and network settings (no
forwarding, redirects, source routing or router advertisements; rp_filter,
syncookies, martian logging).

Two lessons from building this, both caught by the tests: systemd applies
every sysctl.d file from all directories in file-name order, so the STIG's
`/etc/sysctl.d/kernel_kptr_restrict.conf` (value 1) beat a file named
`90-hardening.conf` (value 2). And the SCAP check requires every file in
`/etc/sysctl.d` to agree, so the build deletes the STIG's per-key files for
keys this file sets.

`user.max_user_namespaces=0` disables user namespaces for everyone, root
included, so systemd units with `PrivateUsers=yes` would fail; the build
writes a `PrivateUsers=no` drop-in for each (chrony-wait, irqbalance,
nm-cloud-setup) and a test checks the list is complete. Rootless Podman,
Flatpak and Chromium's sandbox stop working.

Verified: Container (effective value after merging every file), Boot
(`sysctl` on the live kernel).

## 4. Kernel modules (`/usr/lib/modprobe.d/90-hardening-blacklist.conf`)

`install <module> /bin/false` for rare file systems (cramfs, freevxfs, hfs,
hfsplus, jffs2, udf, squashfs, gfs2, f2fs, nilfs2, ksmbd), rare network
protocols (dccp, sctp, rds, tipc, ax25, x25, can, atm, l2tp...), DMA buses
(FireWire, Thunderbolt), Bluetooth, USB storage, and a few buggy legacy
drivers. erofs and overlay are deliberately allowed: composefs needs them.
Verified: Container (`modprobe --showconfig`), Boot (`modprobe sctp` fails).

## 5. Crypto policy: `FUTURE:INTERNET-COMPAT`

TLS 1.3 only; AES-256-GCM, AES-256-CCM, ChaCha20-Poly1305; post-quantum hybrid
key exchange (ML-KEM-768 + X25519) preferred; no SHA-1; one setting for
OpenSSL, GnuTLS, NSS, OpenSSH, libssh, Kerberos and Java. The
`INTERNET-COMPAT` module exists because pure `FUTURE` in this release could
not complete a handshake with quay.io, github.com or three of the four NTS
servers (no shared group; RSA-2048 certificates below FUTURE's 3072-bit
minimum). See `docs/verification/crypto-policy.txt`.

**FIPS**: on RHEL, `fips=1` plus the `FIPS` policy restricts crypto to the
validated modules, which regulated environments require. CentOS Stream's
modules are not validated, so FIPS mode here would be a claim without the
certificate behind it. **Cost**: TLS 1.2-only servers and old SSH clients
(no `curve25519`/`mlkem` KEX, no AES-GCM/ChaCha20) cannot connect.
Verified: Container (policy, back-end files, live handshakes), Boot.

## 6. SSH (`/etc/ssh/sshd_config.d/00-hardening.conf`)

Keys only (`AuthenticationMethods publickey`), no root, `AllowGroups wheel`,
no forwarding of any kind, `MaxAuthTries 3`, `LoginGraceTime 30`, idle
timeout, `LogLevel VERBOSE` (key fingerprints in the log), banner. The
STIG's own `00-complianceascode-hardening.conf` sorts first and sets
`ClientAliveInterval 600`, which wins over this file's 300.
Verified: Container (`sshd -t`, `sshd -T` effective values), Boot (service
active).

## 7. Accounts, PAM and sudo

- authselect `local` + `with-faillock` + `with-pwhistory`, run *before* the
  STIG step (running it after reset the STIG's PAM changes in an earlier
  build).
- faillock: 3 failures in 15 min lock for 15 min, root included.
- pwquality: 15+ characters, all four classes, dictionary check, root too.
- login.defs: SHA-512 with 100000 rounds, `UMASK 077`, 60-day maximum age
  (STIG).
- `/etc/profile.d/90-hardening.sh`: `umask 077`, readonly `TMOUT=900`.
- sudo: `use_pty`, log file plus subcommand logging, password on every use
  (`timestamp_timeout=0`), `requiretty`, `secure_path`, wheel only and only
  into `sysadm_r`.

Verified: Container (PAM files, `pwscore`, `visudo -c`).

## 8. Audit (`/etc/audit/rules.d/`)

`10-base.rules` (buffer, failure mode, backlog wait), `30-hardening.rules`
(time, identity, privilege configuration, MAC policy, logins, modules and
kexec, mounts, permission changes, failed access, deletions, every root
command run by a human, setuid use, ptrace injection, eBPF loads), the
STIG's own rule files, and `99-finalize.rules` with `-e 2` (rules locked
until reboot). Legacy syscalls that do not exist on aarch64 are on separate
lines, because auditctl drops a whole rule when one name is unknown.

Verified: Container (merged rule count; every syscall name checked against
the aarch64 and x86_64 tables with `ausyscall`), Boot (`auditctl -s`,
`auditctl -l`, `auditctl -D` refused).

## 9. Integrity: composefs, AIDE, fapolicyd

- **composefs** (`/usr/lib/ostree/prepare-root.conf`, `enabled = yes`, from
  the base image) mounts `/usr` read-only from a content-addressed image.
  `enabled = verity`/`signed` would add fs-verity enforcement so a modified
  object fails to read; it needs fs-verity on the root file system (XFS in
  this kernel does not have it) and, for `signed`, a key in the initramfs.
  Not enabled; noted as future work.
- **AIDE** watches what composefs does not (`/etc`, `/boot`, `/var` state):
  `hardened-aide-init.service` builds the baseline on first boot,
  `hardened-aide-check.timer` checks daily. The STIG's build-time database
  is deleted because it describes the build container, not the machine.
- **fapolicyd**: deny-by-default execution and interpreter allow-listing
  from the RPM database, `integrity = sha256`.

Verified: Container (configs parse: `aide --config-check`,
`fapolicyd-cli --check-config`), Boot (untrusted binary refused).

## 10. Devices: USBGuard

Default `block`; on first boot `usbguard-firstboot.service` generates an
allow-list from the devices present, before the daemon enforces. IPC limited
to root and wheel; decisions go to the audit log.
Verified: Container (config), Boot (service active, device list).

## 11. Network: firewalld

Default zone `drop` (no reply to unsolicited packets) with only `ssh`
allowed, `LogDenied=all`. Verified: Container (`firewall-offline-cmd
--check-config`, zone listing), Boot (`firewall-cmd`).

## 12. Time: chrony with NTS

Four NTS servers, `minsources 2`, no DHCP-provided servers, no NTP server
port, no network command port. Verified: Container (`chronyd -p`, NTS-KE
handshakes), Boot (`chronyc authdata`).

## 13. Services, sandboxing, core dumps, mounts

- Enabled: auditd, fapolicyd, usbguard, firewalld, chronyd, rsyslog, sshd.
- Masked: kdump, debug-shell, ctrl-alt-del.target, systemd-coredump.socket.
- rsyslog sandbox drop-in (`systemd-analyze security` exposure 3.0).
- No core dumps: coredump.conf `Storage=none`, `DefaultLimitCORE=0`,
  limits.d, `core_pattern=|/bin/false`, `suid_dumpable=0`.
- `/tmp` tmpfs `nosuid,nodev,noexec`; `/dev/shm` remounted the same.
- journald persistent, compressed, forwarded to rsyslog; remote TLS
  forwarding as a template in `/usr/share/hardened-linux/examples/`.

## 14. Updates and image trust

- bootc image-mode: `bootc upgrade` stages a new image and boots into it;
  `bootc rollback` returns to the previous deployment.
- `/etc/containers/policy.json`: default `reject`; images from the
  project's registry path must carry a sigstore signature from
  `/etc/pki/containers/hardened-linux.pub`. The key in the repository is a
  demonstration key whose private half is not kept: replace it.
- bootc only enforces this policy when the deployment was installed or
  switched with `--enforce-container-sigpolicy`.

Verified: Container (policy parses; an unsigned pull is rejected).

## 15. Disk encryption, Secure Boot, measured boot

- `/usr/lib/bootc/install/50-hardening.toml`: `block = ["tpm2-luks"]`, so
  `bootc install to-disk` encrypts the root file system with LUKS2 and
  enrolls the TPM2 (`systemd-cryptenroll --wipe-slot=all
  --tpm2-device=auto`, adding `luks.options=tpm2-device=auto,headless=true`
  to the kernel command line). bootc-image-builder's disk images do not use
  this path and are not encrypted.
- `install/kickstart.ks`: Anaconda example with LUKS2 and a %post TPM2
  enrollment.
- Secure Boot: CentOS ships a shim signed by Microsoft's UEFI CA and a
  signed kernel; Secure Boot is a firmware setting. Measured boot: the
  firmware and shim extend PCRs; binding LUKS to PCR 7 (Secure Boot state)
  survives kernel updates, binding to PCRs 4/9/11 does not unless the PCR
  policy is signed.

Verified: Configured only.
