# hardened-linux: a hardened, image-mode (bootc) CentOS Stream 10.
#
# One OCI image. It runs as a container (for inspection and tests) and
# becomes a bootable disk with bootc-image-builder or `bootc install`.
# Every control is either a file under rootfs/ (copied as-is) or a step
# below. docs/controls.md explains each one: the attack, the cost.
#
# Build:   docker build --platform linux/arm64 -t hardened-linux:latest .
#          (or linux/amd64; nothing here is architecture-specific)

FROM quay.io/centos-bootc/centos-bootc:stream10

LABEL org.opencontainers.image.title="hardened-linux" \
      org.opencontainers.image.description="Hardened CentOS Stream 10 bootc image" \
      containers.bootc=1

# ---------------------------------------------------------------------------
# 1. Security tooling the base image does not ship.
#    audit         kernel audit daemon and augenrules
#    aide          file integrity checker for /etc and the mutable state
#    fapolicyd     application allow-listing (with its SELinux module)
#    usbguard      USB device allow-listing (with its SELinux module)
#    firewalld     host firewall (nftables backend)
#    rsyslog       local syslog plus TLS forwarding to a log server
#    openscap-*    SCAP scanner, oscap-im, and the SCAP Security Guide
#    setools       seinfo/sesearch, used by the tests to inspect policy
# ---------------------------------------------------------------------------
RUN dnf -y install \
        audit audit-rules \
        aide \
        fapolicyd fapolicyd-selinux \
        usbguard usbguard-selinux \
        firewalld \
        rsyslog rsyslog-gnutls \
        openscap-scanner openscap-utils scap-security-guide \
        setools-console \
    && dnf clean all \
    && rm -rf /var/cache/dnf /var/lib/dnf /var/log/dnf* /var/log/hawkey.log

# ---------------------------------------------------------------------------
# 2. Apply the DISA STIG for RHEL 10 (SCAP Security Guide content for
#    CentOS Stream 10) at build time with oscap-im. oscap-im evaluates the
#    image, installs packages the profile requires, and runs the
#    profile's remediation scripts. The tailoring file records the few
#    places this image deliberately deviates (see scap/README.md).
#    oscap-im refuses to run unless /run/.containerenv exists, a marker
#    Podman creates in every container and Docker's builder does not; it is
#    created for this step only and removed afterwards. oscap-im itself
#    treats "some rules still fail" (oscap exit 2) as success; anything
#    else stops the build.
# ---------------------------------------------------------------------------
COPY scap/tailoring.xml /usr/share/hardened-linux/scap/tailoring.xml
RUN touch /run/.containerenv \
 && { oscap-im --profile xccdf_org.ssgproject.content_profile_stig_hardened_linux \
        --tailoring-file /usr/share/hardened-linux/scap/tailoring.xml \
        /usr/share/xml/scap/ssg/content/ssg-cs10-ds.xml \
        > /usr/share/hardened-linux/scap/oscap-im.log 2>&1 \
      || { tail -n 30 /usr/share/hardened-linux/scap/oscap-im.log; exit 1; }; } \
 && rm -f /run/.containerenv \
 && dnf clean all && rm -rf /var/cache/dnf /var/lib/dnf /var/log/dnf* /var/log/hawkey.log /tmp/*

# ---------------------------------------------------------------------------
# 3. This image's own configuration, layered over the STIG result. Where a
#    file here and the STIG remediation touch the same setting, this file
#    wins, and the scan in tests/ shows the effect.
# ---------------------------------------------------------------------------
COPY rootfs/ /

# Files copied from a build context get the builder's modes; set the ones
# the consuming programs check.
RUN chmod 0440 /etc/sudoers.d/00-hardening \
 && chmod 0600 /etc/ssh/sshd_config.d/00-hardening.conf \
               /etc/usbguard/usbguard-daemon.conf \
 && chmod 0640 /etc/audit/rules.d/*.rules \
 && chown root:fapolicyd /etc/fapolicyd/fapolicyd.conf \
 && chmod 0644 /etc/fapolicyd/fapolicyd.conf \
 && chmod 0644 /etc/pki/containers/hardened-linux.pub /etc/containers/policy.json \
 && touch /etc/usbguard/rules.conf && chmod 0600 /etc/usbguard/rules.conf \
 && visudo -c -q

# ---------------------------------------------------------------------------
# 4. SELinux: enforcing, targeted policy, confined users, locked booleans.
#    - Administrators (members of wheel) log in as staff_u and reach
#      sysadm_r only through sudo (see sudoers.d). Everyone else is user_u:
#      no sudo, no setuid transitions, no network services.
#    - Booleans: no ptrace between processes, no writable+executable memory
#      for unconfined domains, no executable stacks/heaps for users, users
#      cannot run programs from their home or /tmp, sysadm cannot log in
#      directly over SSH, and secure_mode_policyload forbids switching to
#      permissive or loading new policy at runtime: on an image-mode system
#      policy changes ship in a new image, not by hand.
#    All changes go through one `semanage import` so the policy is rebuilt
#    once.
# ---------------------------------------------------------------------------
RUN sed -i 's/^SELINUX=.*/SELINUX=enforcing/; s/^SELINUXTYPE=.*/SELINUXTYPE=targeted/' /etc/selinux/config \
 && printf '%s\n' \
      'login -a -s staff_u -r s0-s0:c0.c1023 %wheel' \
      'login -m -s user_u -r s0 __default__' \
      'boolean -m --on deny_ptrace' \
      'boolean -m --on deny_execmem' \
      'boolean -m --off selinuxuser_execmod' \
      'boolean -m --off selinuxuser_execstack' \
      'boolean -m --off selinuxuser_execheap' \
      'boolean -m --off user_exec_content' \
      'boolean -m --off ssh_sysadm_login' \
      'boolean -m --on secure_mode_policyload' \
    | semanage import \
 && semanage login -l && semanage boolean -l -C

# ---------------------------------------------------------------------------
# 5. System-wide crypto policy FUTURE: TLS 1.2+ only, no SHA-1 signatures,
#    RSA and DH keys of at least 3072 bits, 128-bit minimum symmetric
#    strength. Applies to OpenSSL, GnuTLS, NSS, OpenSSH, libssh, Kerberos
#    and Java at once. FIPS mode is discussed in docs/controls.md and is
#    not used: CentOS Stream is not a FIPS-validated module.
# ---------------------------------------------------------------------------
RUN update-crypto-policies --no-reload --set FUTURE && update-crypto-policies --show

# ---------------------------------------------------------------------------
# 6. PAM: lock accounts after failed logins (faillock.conf) and remember
#    old passwords. Password hashing (SHA-512, 100000 rounds) and the
#    umask in login.defs come from the STIG remediation above.
# ---------------------------------------------------------------------------
RUN authselect select local with-faillock with-pwhistory --force \
 && authselect apply-changes \
 && authselect current

# ---------------------------------------------------------------------------
# 7. Host firewall: the default zone is "drop" (unsolicited inbound packets
#    are discarded without a reply), with only SSH allowed in, and every
#    dropped packet logged.
# ---------------------------------------------------------------------------
RUN firewall-offline-cmd --set-default-zone=drop \
 && firewall-offline-cmd --zone=drop --add-service=ssh \
 && sed -i 's/^LogDenied=.*/LogDenied=all/' /etc/firewalld/firewalld.conf \
 && firewall-offline-cmd --check-config \
 && firewall-offline-cmd --get-default-zone \
 && firewall-offline-cmd --zone=drop --list-all

# ---------------------------------------------------------------------------
# 8. Services. Enable the security daemons; disable or mask what an
#    attacker could use: kdump (writes full memory images to disk), the
#    debug shell on tty9 (a root shell without a password), Ctrl-Alt-Del
#    reboot, and systemd-coredump.
#
#    user.max_user_namespaces=0 (sysctl.d) makes PrivateUsers= fail, so
#    every unit that asks for it gets a drop-in turning it off; the sandbox
#    loses one layer, and the whole system loses unprivileged user
#    namespaces, which is the larger gain. tests/ checks the list is
#    complete.
# ---------------------------------------------------------------------------
RUN systemctl enable auditd fapolicyd usbguard usbguard-firstboot firewalld \
        chronyd rsyslog sshd harden-dev-shm tmp.mount \
 && rm -f /etc/systemd/system/ctrl-alt-del.target \
 && systemctl mask kdump.service debug-shell.service ctrl-alt-del.target \
        systemd-coredump.socket \
 && for u in $(grep -lE '^PrivateUsers=(yes|true|self|identity|full)' /usr/lib/systemd/system/*.service); do \
        n=$(basename "$u"); mkdir -p "/etc/systemd/system/$n.d"; \
        printf '%s\n' '# Generated at build: user namespaces are disabled system-wide.' \
            '[Service]' 'PrivateUsers=no' > "/etc/systemd/system/$n.d/50-no-userns.conf"; \
        echo "PrivateUsers=no drop-in: $n"; \
    done

# ---------------------------------------------------------------------------
# 9. AIDE. /usr is already protected by composefs (the deployed tree is
#    content-addressed and read-only), but AIDE also covers /etc, /boot
#    and state under /var, which composefs does not. Its database cannot
#    be built into the image (it would describe the build, not the
#    machine), so hardened-aide-init.service creates it on first boot and
#    hardened-aide-check.timer compares against it daily.
# ---------------------------------------------------------------------------
RUN systemctl enable hardened-aide-init.service hardened-aide-check.timer

# ---------------------------------------------------------------------------
# 10. Rebuild the initramfs so it carries the new sysctl, modprobe and
#     crypto settings that apply before the root file system is mounted.
# ---------------------------------------------------------------------------
RUN kver=$(ls /usr/lib/modules) \
 && dracut --force --no-hostonly --reproducible "/usr/lib/modules/$kver/initramfs.img" "$kver" 2>&1 | tail -n 2

# ---------------------------------------------------------------------------
# 11. Final checks that must pass for the image to be usable with bootc.
# ---------------------------------------------------------------------------
#     Build leftovers are removed first: authselect's backups under /var
#     (on a bootc system /var belongs to the machine, not the image), the
#     AIDE database the STIG remediation built from the build container
#     (a baseline must describe the deployed machine; see step 9), and
#     runtime files that package scripts left in /run.
RUN rm -rf /var/log/* /var/cache/* /tmp/* /var/lib/authselect/backups /var/lib/aide/* \
 && find /run -mindepth 1 -maxdepth 1 ! -name secrets -exec rm -rf {} + \
 && bootc container lint
