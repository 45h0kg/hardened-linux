# Threat model

What this image is for: a general-purpose Linux server (or VM) that runs a
small number of services, is administered over SSH by a few people, and is
updated by replacing the whole OS image. It is not a desktop and not a
container host for untrusted workloads.

## Assets

- Data on the machine's disks, and the credentials it holds (SSH host keys,
  service secrets, TLS keys, tokens).
- The integrity of the OS: the kernel, `/usr`, the boot chain, the update
  channel.
- The integrity of the record of what happened (audit trail, logs, time).

## Attackers and what stops them

| Attacker / situation | Main controls | Notes |
|---|---|---|
| **Remote, unauthenticated**, scanning or brute-forcing | firewalld `drop` zone with only SSH open; sshd keys-only, no root, `AllowGroups wheel`, `MaxAuthTries 3`, `LoginGraceTime 30`; sysctl network hardening (no redirects, source routing, RA; syncookies, rp_filter) | Leaves the SSH daemon and the application's own port as attack surface. |
| **Remote code execution in a network service** (a bug in the app or in sshd) | SELinux confinement of the service's domain; systemd sandboxing (rsyslog, chronyd, usbguard); fapolicyd (a dropped binary or script does not run); `/tmp` and `/dev/shm` `noexec`; read-only `/usr` (composefs) | An unconfined or custom service gets far less from SELinux; write a policy module or at least run it under a confined domain. |
| **Local unprivileged user → root** (kernel or setuid exploits) | No unprivileged user namespaces, eBPF, userfaultfd, io_uring; `ptrace_scope=2`; `kptr_restrict=2`, `dmesg_restrict`; module blacklist + `module.sig_enforce`; `init_on_alloc/free`, `slab_nomerge`, `randomize_kstack_offset`; SELinux `user_u` (no setuid transitions, no exec from home with `user_exec_content=off`) | Reduces reachable kernel code and makes many public exploits fail; does not make the kernel bug-free. |
| **Root on the running system** (post-exploitation persistence, covering tracks) | `lockdown=confidentiality` (no /dev/mem, no unsigned kexec, no reading kernel memory); signed modules only; audit rules locked with `-e 2`; `secure_mode_policyload` (no `setenforce 0`, no policy reload); read-only `/usr` and image-based updates (persistence in `/usr` is wiped by the next image); remote log shipping (template) | Root can still read all data, kill processes, change `/etc` and `/var`, and reboot. Lockdown and immutable audit only force the attacker to reboot, which is visible. |
| **Physical access to a powered-off disk** | LUKS2 full-disk encryption bound to the TPM2 (`bootc install` with `block = ["tpm2-luks"]`) | Configured, not verified in this repository's tests. A TPM-only unlock protects a stolen *disk*; a stolen *machine* boots and unlocks. Add a PIN (`systemd-cryptenroll --tpm2-with-pin=yes`) if that matters. |
| **Evil maid / boot chain tampering** | UEFI Secure Boot with the distribution's shim and signed kernel; measured boot into the TPM (PCRs gate the LUKS key) | Depends on firmware settings outside the image. Not verified here. |
| **Malicious USB device** (BadUSB keyboard, rogue storage) | USBGuard default-block with an allow-list generated on first boot; `usb-storage`, `uas`, FireWire, Thunderbolt modules blocked; IOMMU strict | A device that clones the descriptors of an allowed keyboard can still pass. |
| **Network time attacker** (shift the clock to replay or invalidate certificates) | chrony with NTS only, `minsources 2`, no DHCP-provided servers | |
| **Compromised update channel / registry** | `/etc/containers/policy.json` rejects everything except images signed with the project's key; bootc must be told to enforce it (`--enforce-container-sigpolicy`) | The shipped key is a placeholder you replace. A stolen signing key defeats it. |
| **Weak or reused passwords** | Keys only over the network; pwquality (15+ chars, 4 classes), pwhistory, faillock | |

## Out of scope (not defended, or barely)

- Attacks on the application itself (SQL injection, auth bugs) beyond
  containing the process that runs it.
- A malicious administrator in `wheel`. They are confined to `sysadm_r`, logged
  by sudo and audit, but they can change the system.
- Firmware, BMC/IPMI, and hardware implants.
- Side channels beyond what the kernel's `mitigations=` and `nosmt` cover.
- Denial of service. Several controls make DoS easier, not harder: faillock
  lockouts, the audit backlog, `-e 2` (rules can't be fixed without a
  reboot), strict USBGuard.
- Supply chain of the base image and packages: trust in CentOS Stream's
  build and signing is assumed.

## Assumptions

- The machine's firmware has Secure Boot on and a TPM 2.0.
- Administrators use SSH keys kept on hardware tokens or at least
  passphrase-protected.
- Logs are shipped somewhere the machine cannot rewrite.
