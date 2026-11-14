# hardened-linux

A hardened Linux server OS, built as a single bootable container image
(bootc, "image mode") on CentOS Stream 10. One `Containerfile` produces an
OCI image that runs under Docker or Podman for inspection and tests, and
becomes a bootable disk with `bootc-image-builder` or `bootc install`.

The image applies the DISA STIG for RHEL 10 at build time with `oscap-im`,
then layers its own configuration on top: SELinux confined users and locked
booleans, kernel lockdown and memory-safety boot arguments, a strict sysctl
set, module blacklisting, a post-quantum-preferring crypto policy, key-only
SSH, faillock and pwquality, a locked audit rule set, AIDE, fapolicyd,
USBGuard, a default-drop firewall, NTS time, systemd sandboxing, no core
dumps, `noexec` temporary file systems, container signature enforcement,
and a TPM2-bound LUKS2 install configuration.

- [`docs/controls.md`](docs/controls.md): every control, what it stops,
  what it costs, and how far it was verified.
- [`docs/threat-model.md`](docs/threat-model.md): what this defends against
  and what it does not.
- [`scap/README.md`](scap/README.md): the SCAP profile and the deliberate
  deviations from it.
- [`docs/verification/`](docs/verification/): real outputs of every test.

## Why CentOS Stream 10 bootc

- **Image mode.** The OS is an OCI image. Every machine runs exactly what
  was built and tested, `/usr` is read-only (composefs), updates replace the
  whole image atomically (`bootc upgrade`), and the previous image stays one
  `bootc rollback` away. Persistence an attacker plants in `/usr` disappears
  at the next update.
- **SCAP content exists for it.** The SCAP Security Guide ships CentOS
  Stream 10 content with STIG, CIS, ANSSI-BP-028, BSI, ISM, PCI-DSS, HIPAA
  and Essential Eight profiles, and `oscap-im` applies them to bootc images
  at build time. Fedora bootc has far less SCAP content.
- **SELinux and the RHEL security stack**: targeted policy with confined
  user roles, fapolicyd, USBGuard, crypto-policies, authselect, all
  maintained as one system.
- **Multi-architecture.** The base image is published for x86_64 and
  aarch64; this repository was built and tested on aarch64 (Apple silicon).

CentOS Stream is the upstream of RHEL and is not FIPS-validated or
commercially supported. For production with compliance requirements, the
same `Containerfile` should build on `registry.redhat.io/rhel10/rhel-bootc`
with the `ssg-rhel10-ds.xml` data stream and the `FIPS` crypto policy.

## Layout

```
Containerfile                 the image, step by step, each step commented
rootfs/                       files copied into the image as-is
  etc/audit/rules.d/          audit rules (locked with -e 2)
  etc/containers/             signature policy and sigstore lookup
  etc/crypto-policies/        INTERNET-COMPAT subpolicy module
  etc/fapolicyd/ etc/usbguard/ etc/chrony.conf
  etc/security/ etc/sudoers.d/ etc/ssh/sshd_config.d/ etc/profile.d/
  etc/sysctl.d/zz-hardening.conf
  etc/systemd/system/         sandbox and mount drop-ins
  usr/lib/bootc/kargs.d/      kernel command line
  usr/lib/bootc/install/      tpm2-luks install requirement
  usr/lib/modprobe.d/         module blacklist
  usr/lib/systemd/            journald, coredump, units (AIDE, USBGuard, /dev/shm)
scap/                         STIG tailoring and its rationale
tests/                        container checks, SCAP scan, TLS policy probe
boot/                         boot test: report unit, QEMU, run script
install/                      kickstart (LUKS2 + TPM2) and image-builder config
docs/                         controls, threat model, verification outputs
```

## Build

```console
docker build --platform linux/arm64 -f Containerfile -t hardened-linux:latest .
```

(`linux/amd64` works the same way; the x86-only kernel arguments are in
their own file and only apply there.) `podman build` works too.

## Test

```console
# static checks of the image (packages, policy, configs, each daemon's own config check)
docker run --rm -v "$PWD/tests:/tests:ro" hardened-linux:latest /tests/container-checks.sh

# OpenSCAP scan with the tailored STIG profile
docker run --rm -v "$PWD/tests:/tests:ro" -v "$PWD/scap:/scap:ro" -v "$PWD/out:/out" \
  hardened-linux:latest /tests/scap-scan.sh /out

# which TLS endpoints each crypto policy can reach
docker run --rm -v "$PWD/tests:/tests:ro" hardened-linux:latest /tests/tls-policy-probe.sh

# boot it: bootc-image-builder -> qcow2 -> QEMU, report on the serial console
boot/run-boot-test.sh output
```

## Install

- **Encrypted, on real hardware:** boot any CentOS Stream 10 live
  environment with Podman and run the image's own installer:
  `podman run --rm --privileged --pid=host -v /dev:/dev -v /var/lib/containers:/var/lib/containers --security-opt label=type:unconfined_t <image> bootc install to-disk --enforce-container-sigpolicy /dev/<disk>`.
  The image's `block = ["tpm2-luks"]` makes this encrypt the root file
  system and bind it to the TPM2. Or use `install/kickstart.ks` with
  Anaconda.
- **VM or cloud images:** `bootc-image-builder` with
  `install/bib-config.toml` (`--type qcow2`, `raw`, `ami`, ...). These disk
  images are not encrypted.

## Update

Sign each release and let machines verify it:

```console
cosign sign --key cosign.key registry.example.com/hardened/hardened-linux:latest
# on the machine (once): enforce /etc/containers/policy.json for this deployment
bootc switch --enforce-container-sigpolicy registry.example.com/hardened/hardened-linux:latest
bootc upgrade        # stage the next image; reboot to apply
bootc rollback       # go back to the previous image
```

Replace `rootfs/etc/pki/containers/hardened-linux.pub` and the registry
path in `rootfs/etc/containers/policy.json` with your own. The committed key
is a demonstration key; its private half was not kept.

## What was verified, and where

Full outputs are in `docs/verification/`.

- **Container checks** (`tests/container-checks.sh`): 153 passed, 0 failed.
- **`bootc container lint`**: 13 passed, 1 skipped, 1 warning (`var-tmpfiles`).
- **OpenSCAP, tailored STIG, in a container**: stock base 130/296 rules
  pass (43.9%, score 31.11); hardened image 341/390 (87.4%, score 72.37).
  Most remaining failures need a running system.
- **Booted in QEMU** (arm64, TCG, UEFI; three boots, each after fixing what
  the previous one found): lockdown `confidentiality`, SELinux enforcing
  and `setenforce` refused, audit rules locked (`auditctl -D` refused),
  all sysctls effective, user namespaces and blocked modules refused,
  `/usr` read-only, `/tmp` and `/dev/shm` noexec, fapolicyd refusing
  untrusted binaries and scripts, firewalld's drop zone loaded into
  nftables, chrony synchronised from four NTS-authenticated servers, no
  failed units. Live STIG scan: 378/393 rules pass (96.2%, score 94.36);
  every remaining failure is explained in `docs/controls.md`.
- **Fixed because of the boots**: fapolicyd's stock rule letting root run
  programs from `/var/tmp`; rsyslog failing under the first sandbox; the
  STIG's placeholder `logcollector` log host; an nftables/libnftnl mismatch
  that left firewalld "active" with no rules loaded; the faillock tally on
  a tmpfs; a duplicated sudo setting.
- **Worked around**: `bootc status` failed from a system service under
  SELinux (`execve: Permission denied`): a shell wrapper leaves bootc
  outside `install_t`. The image carries the policy module from
  [bootc PR #2366](https://github.com/bootc-dev/bootc/pull/2366) until
  bootc or selinux-policy ships it; boot 4 verifies the fix. Not yet tested
  from an administrator login.
- **Not verified**: TPM2-bound LUKS2, Secure Boot, measured boot, signed
  updates end to end, USBGuard with real devices, packets dropped from
  outside, remote TLS log forwarding, the kickstart, x86-only kernel
  arguments.
