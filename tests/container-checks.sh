#!/bin/bash
# Static checks of the built image, run INSIDE a container of it:
#   docker run --rm -v "$PWD/tests:/tests:ro" hardened-linux:latest /tests/container-checks.sh
#
# A container shares the host's kernel and is not booted by systemd, so
# nothing here can prove a kernel-level control is active (SELinux
# enforcing, lockdown, sysctl values, loaded audit rules). Those are
# checked by boot/boot-report.sh on a booted machine. What this script can
# prove is that the image carries the right packages, files, values and
# policy, and that each program accepts its own configuration.

set -u
PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); echo "PASS  $*"; }
fail() { FAIL=$((FAIL+1)); echo "FAIL  $*"; }
section() { echo; echo "== $*"; }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else fail "$d"; fi; }

KVER=$(ls /usr/lib/modules)

section "Image"
grep -E '^(NAME|VERSION)=' /etc/os-release
echo "kernel package: $KVER ($(uname -m))"

section "Packages"
for p in audit aide fapolicyd fapolicyd-selinux usbguard usbguard-selinux firewalld \
         rsyslog rsyslog-gnutls chrony openscap-scanner scap-security-guide \
         openssh-server sudo authselect crypto-policies selinux-policy-targeted \
         policycoreutils-python-utils cryptsetup tpm2-tools; do
  check "package $p installed ($(rpm -q --qf '%{VERSION}-%{RELEASE}' $p 2>/dev/null))" rpm -q "$p"
done
for p in telnet-server tftp-server vsftpd gdm nfs-utils tuned; do
  check "package $p absent" bash -c "! rpm -q $p"
done

section "SELinux (policy in the image; enforcement needs a booted kernel)"
grep -E '^SELINUX(TYPE)?=' /etc/selinux/config
check "SELINUX=enforcing in /etc/selinux/config" grep -qx 'SELINUX=enforcing' /etc/selinux/config
check "SELINUXTYPE=targeted" grep -qx 'SELINUXTYPE=targeted' /etc/selinux/config
POL=$(ls /etc/selinux/targeted/policy/policy.* | tail -1)
echo "policy file: $POL"
seinfo "$POL" | sed -n '1,8p'
for m in fapolicyd usbguard; do
  check "SELinux module $m present" bash -c "semodule -l | grep -qx $m"
done
semanage login -l
check "wheel mapped to staff_u" bash -c "semanage login -l | grep -E '^%wheel +staff_u'"
check "__default__ mapped to user_u" bash -c "semanage login -l | grep -E '^__default__ +user_u'"
echo "booleans as compiled into the policy file:"
for b in deny_ptrace deny_execmem selinuxuser_execmod selinuxuser_execstack selinuxuser_execheap user_exec_content ssh_sysadm_login secure_mode_policyload; do
  seinfo "$POL" -b "$b" -x 2>/dev/null | grep -E "^ +$b:" | sed 's/^ */  /'
done
check "deny_ptrace on"             bash -c "seinfo $POL -b deny_ptrace -x | grep -q 'bool deny_ptrace true;'"
check "deny_execmem on"            bash -c "seinfo $POL -b deny_execmem -x | grep -q 'bool deny_execmem true;'"
check "secure_mode_policyload on"  bash -c "seinfo $POL -b secure_mode_policyload -x | grep -q 'bool secure_mode_policyload true;'"
check "user_exec_content off"      bash -c "seinfo $POL -b user_exec_content -x | grep -q 'bool user_exec_content false;'"
check "ssh_sysadm_login off"       bash -c "seinfo $POL -b ssh_sysadm_login -x | grep -q 'bool ssh_sysadm_login false;'"
echo "file contexts the policy assigns:"
for f in /usr/sbin/auditd /usr/sbin/fapolicyd /usr/sbin/usbguard-daemon /usr/sbin/sshd /usr/sbin/chronyd \
         /etc/shadow /etc/audit/audit.rules /var/log/audit/audit.log /etc/fapolicyd/fapolicyd.conf \
         /etc/usbguard/rules.conf /usr/bin/bootc; do
  printf '  %-34s %s\n' "$f" "$(matchpathcon -n "$f" 2>&1)"
done
check "auditd labelled auditd_exec_t"       bash -c "matchpathcon -n /usr/sbin/auditd | grep -q auditd_exec_t"
check "fapolicyd labelled fapolicyd_exec_t" bash -c "matchpathcon -n /usr/sbin/fapolicyd | grep -q fapolicyd_exec_t"
check "usbguard labelled usbguard_exec_t"   bash -c "matchpathcon -n /usr/sbin/usbguard-daemon | grep -q usbguard_exec_t"
check "shadow labelled shadow_t"            bash -c "matchpathcon -n /etc/shadow | grep -q shadow_t"
echo "ptrace allowed from user_t, staff_t, sysadm_t (conditional on deny_ptrace):"
sesearch "$POL" -A -s sysadm_t -t user_t -c process -p ptrace 2>/dev/null | head -3 | sed 's/^/  /'

section "Kernel arguments (bootc kargs.d)"
python3 - <<'EOF'
import tomllib, glob, platform
for f in sorted(glob.glob('/usr/lib/bootc/kargs.d/*.toml')):
    d = tomllib.load(open(f, 'rb'))
    arch = d.get('match-architectures', ['all'])
    print(f"{f}  (architectures: {', '.join(arch)})")
    print('   ' + ' '.join(d['kargs']))
EOF
for k in lockdown=confidentiality module.sig_enforce=1 init_on_alloc=1 init_on_free=1 slab_nomerge \
         page_alloc.shuffle=1 randomize_kstack_offset=on debugfs=off audit=1 audit_backlog_limit=8192 \
         iommu.strict=1 lsm=lockdown,yama,integrity,selinux,bpf,landlock; do
  check "karg $k" grep -q "\"$k\"" /usr/lib/bootc/kargs.d/10-hardening.toml
done
check "vsyscall=none (x86_64 only)" grep -q '"vsyscall=none"' /usr/lib/bootc/kargs.d/20-x86_64.toml
echo "kernel build options the arguments rely on:"
grep -E '^CONFIG_(LSM|SECURITY_LOCKDOWN_LSM|MODULE_SIG|MODULE_SIG_ALL|SHUFFLE_PAGE_ALLOCATOR|RANDOMIZE_KSTACK_OFFSET|SECURITY_LANDLOCK|BPF_LSM|LEGACY_TIOCSTI|IO_URING)=' /usr/lib/modules/$KVER/config | sed 's/^/  /'

section "sysctl (effective value after merging every sysctl.d file in systemd order)"
python3 - <<'EOF' > /tmp/sysctl.eff
import glob, os, fnmatch
dirs = ['/usr/lib/sysctl.d', '/run/sysctl.d', '/etc/sysctl.d']
files = {}
for d in dirs:
    for f in glob.glob(d + '/*.conf'):
        files[os.path.basename(f)] = f          # later dirs override same name
order = [files[k] for k in sorted(files)]
if os.path.exists('/etc/sysctl.conf'): order.append('/etc/sysctl.conf')
eff = {}
for f in order:
    for line in open(f):
        line = line.strip()
        if not line or line[0] in '#;' or '=' not in line: continue
        k, v = (x.strip() for x in line.split('=', 1))
        k = k.lstrip('-').replace('/', '.')
        eff[k] = (' '.join(v.split()), f)
for k in sorted(eff): print(f"{k} = {eff[k][0]}\t{eff[k][1]}")
EOF
want="kernel.kptr_restrict=2 kernel.dmesg_restrict=1 kernel.unprivileged_bpf_disabled=1 net.core.bpf_jit_harden=2
kernel.yama.ptrace_scope=2 kernel.kexec_load_disabled=1 kernel.perf_event_paranoid=2 kernel.sysrq=0
kernel.randomize_va_space=2 kernel.io_uring_disabled=2 vm.unprivileged_userfaultfd=0 dev.tty.ldisc_autoload=0
dev.tty.legacy_tiocsti=0 user.max_user_namespaces=0 fs.protected_symlinks=1 fs.protected_hardlinks=1
fs.protected_fifos=2 fs.protected_regular=2 fs.suid_dumpable=0 net.ipv4.ip_forward=0
net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.all.accept_redirects=0 net.ipv6.conf.all.accept_redirects=0
net.ipv4.conf.all.send_redirects=0 net.ipv4.conf.all.accept_source_route=0 net.ipv4.conf.all.log_martians=1
net.ipv4.tcp_syncookies=1 net.ipv6.conf.all.accept_ra=0"
for kv in $want; do
  k=${kv%%=*}; v=${kv#*=}
  line=$(grep -E "^$k = " /tmp/sysctl.eff)
  got=$(echo "$line" | sed -E 's/^[^=]+= ([^\t]*)\t.*/\1/')
  src=$(echo "$line" | cut -f2)
  if [ "$got" = "$v" ]; then pass "sysctl $k = $v  ($src)"; else fail "sysctl $k: want $v, got '${got}' ($src)"; fi
done
echo "files contributing: $(cut -f2 /tmp/sysctl.eff | sort -u | tr '\n' ' ')"

section "Kernel module blacklist"
for m in cramfs freevxfs hfs hfsplus jffs2 udf squashfs dccp sctp rds tipc firewire-core thunderbolt bluetooth usb-storage; do
  inst=$(modprobe -S "$KVER" --showconfig 2>/dev/null | grep -E "^install ${m//-/_} " | head -1)
  shipped=$(find /usr/lib/modules/$KVER -name "${m}.ko*" -o -name "${m//-/_}.ko*" 2>/dev/null | head -1)
  [ -n "$shipped" ] && s="ships with kernel" || s="not shipped"
  if echo "$inst" | grep -q '/bin/false\|/bin/true'; then pass "module $m blocked: '$inst' ($s)"; else fail "module $m not blocked ($s)"; fi
done

section "Audit rules (merged as augenrules would; the kernel is not consulted)"
cat /etc/audit/rules.d/*.rules | grep -E '^-' > /tmp/audit.merged
echo "rules.d files: $(ls /etc/audit/rules.d | tr '\n' ' ')"
echo "rule lines after merge: $(wc -l < /tmp/audit.merged)  (syscall rules: $(grep -c -- '-S ' /tmp/audit.merged), watches: $(grep -c -- '^-w ' /tmp/audit.merged))"
check "last control line is -e 2 (immutable)" bash -c "grep -E '^-e ' /tmp/audit.merged | tail -1 | grep -qx -- '-e 2'"
check "-b 8192 present" grep -qx -- '-b 8192' /tmp/audit.merged
for arch in aarch64 x86_64; do
  bad=0; dropped=""
  while read -r line; do
    sc=$(echo "$line" | sed -nE 's/.* -S ([^ ]+).*/\1/p'); [ -z "$sc" ] && continue
    a=$(echo "$line" | sed -nE 's/.*arch=(b32|b64).*/\1/p')
    aa=$arch; [ "$a" = b32 ] && { [ $arch = x86_64 ] && aa=i386 || aa=arm; }
    for s in ${sc//,/ }; do
      if ! ausyscall "$aa" "$s" >/dev/null 2>&1; then bad=$((bad+1)); dropped="$dropped $a:$s"; break; fi
    done
  done < /tmp/audit.merged
  echo "  $arch: $bad syscall rules contain a name unknown on that arch and would be skipped (-i):${dropped:- none}"
done
missing=$(grep -E '^-w ' /tmp/audit.merged | awk '{print $2}' | while read -r p; do [ -e "$p" ] || echo "$p"; done | sort -u | tr '\n' ' ')
echo "  watched paths that do not exist in the image (fine if created at runtime): ${missing:-none}"

section "firewalld (offline)"
check "firewall-offline-cmd --check-config" firewall-offline-cmd --check-config
echo "default zone: $(firewall-offline-cmd --get-default-zone)"
firewall-offline-cmd --zone=drop --list-all | sed 's/^/  /'
check "default zone is drop" bash -c "[ \$(firewall-offline-cmd --get-default-zone) = drop ]"
check "LogDenied=all" grep -qx 'LogDenied=all' /etc/firewalld/firewalld.conf

section "sshd"
mkdir -p /tmp/hk && ssh-keygen -q -t ed25519 -N '' -f /tmp/hk/ssh_host_ed25519_key && ssh-keygen -q -t ecdsa -N '' -f /tmp/hk/ssh_host_ecdsa_key
SSHD="/usr/sbin/sshd -h /tmp/hk/ssh_host_ed25519_key -h /tmp/hk/ssh_host_ecdsa_key"
check "sshd -t accepts the configuration" $SSHD -t
$SSHD -T -C user=admin,host=client,addr=192.0.2.1 2>/dev/null | grep -E '^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication|authenticationmethods|allowgroups|maxauthtries|allowtcpforwarding|x11forwarding|disableforwarding|clientaliveinterval|clientalivecountmax|loglevel|ciphers|macs|kexalgorithms|hostkeyalgorithms|pubkeyacceptedalgorithms) ' | sed 's/^/  /'
for kv in "permitrootlogin no" "passwordauthentication no" "kbdinteractiveauthentication no" "allowtcpforwarding no" "x11forwarding no" "maxauthtries 3"; do
  check "sshd effective: $kv" bash -c "$SSHD -T -C user=admin,host=client,addr=192.0.2.1 2>/dev/null | grep -qx '$kv'"
done

section "Crypto policy"
echo "current policy: $(update-crypto-policies --show)"
check "policy is FUTURE" bash -c "[ \$(update-crypto-policies --show) = FUTURE ]"
grep -E '^(MinProtocol|CipherString|Groups|SignatureAlgorithms)' /etc/crypto-policies/back-ends/opensslcnf.config 2>/dev/null | cut -c1-160 | sed 's/^/  openssl: /'
echo "  openssl TLS 1.2+1.3 cipher suites allowed: $(openssl ciphers -s -tls1_2 2>/dev/null | tr ':' '\n' | wc -l) (TLS1.2) / $(openssl ciphers -s -tls1_3 2>/dev/null | tr ':' '\n' | wc -l) (TLS1.3 incl.)"

section "PAM, passwords, login"
authselect current | sed 's/^/  /'
check "pam_faillock in system-auth" grep -q pam_faillock /etc/pam.d/system-auth
check "pam_pwhistory in system-auth" grep -q pam_pwhistory /etc/pam.d/system-auth
check "pam_pwquality in system-auth" grep -q pam_pwquality /etc/pam.d/system-auth
grep -vE '^#|^$' /etc/security/faillock.conf | tr '\n' ' ' | sed 's/^/  faillock.conf: /'; echo
grep -hvE '^#|^$' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null | tr '\n' ' ' | sed 's/^/  pwquality: /'; echo
grep -E '^(UMASK|ENCRYPT_METHOD|SHA_CRYPT_MIN_ROUNDS|PASS_MAX_DAYS|PASS_MIN_DAYS)' /etc/login.defs | sed 's/^/  login.defs: /'
for pw in 'password' 'Summer2026!' 'correct horse battery staple' 'k7#Vq9!rT2m@Lx4p'; do
  printf '  pwscore %-32s -> %s\n' "'$pw'" "$(echo "$pw" | pwscore 2>&1 | head -1)"
done

section "sudo"
check "visudo -c (all sudoers files parse)" visudo -c -q
grep -hE '^(Defaults|%)' /etc/sudoers.d/* | sed 's/^/  /'
check "no NOPASSWD rule (comments ignored)" bash -c "! grep -rhs NOPASSWD /etc/sudoers /etc/sudoers.d | grep -vq '^ *#'"

section "chrony (NTS)"
check "chronyd -p parses the configuration" chronyd -p -f /etc/chrony.conf
grep -E '^(server|minsources|port|cmdport)' /etc/chrony.conf | sed 's/^/  /'
check "every server uses nts" bash -c "! grep -E '^(server|pool)' /etc/chrony.conf | grep -vq ' nts'"

section "fapolicyd, USBGuard, AIDE"
check "fapolicyd-cli --check-config" fapolicyd-cli --check-config
grep -E '^(permissive|integrity|trust) ' /etc/fapolicyd/fapolicyd.conf | sed 's/^/  /'
echo "  fapolicyd rule files: $(ls /etc/fapolicyd/rules.d | tr '\n' ' ')"
grep -E '^(ImplicitPolicyTarget|PresentDevicePolicy|InsertedDevicePolicy|AuditBackend|IPCAllowedGroups)=' /etc/usbguard/usbguard-daemon.conf | sed 's/^/  /'
check "aide --config-check" aide --config-check

section "systemd units"
for u in auditd fapolicyd usbguard usbguard-firstboot firewalld chronyd rsyslog sshd harden-dev-shm tmp.mount \
         hardened-aide-init hardened-aide-check.timer bootc-fetch-apply-updates.timer; do
  st=$(systemctl is-enabled "$u" 2>&1); [ "$st" = enabled ] && pass "$u enabled" || fail "$u: $st"
done
for u in kdump.service debug-shell.service ctrl-alt-del.target systemd-coredump.socket; do
  st=$(systemctl is-enabled "$u" 2>&1); [ "$st" = masked ] && pass "$u masked" || fail "$u: $st"
done
need=$(grep -lE '^PrivateUsers=(yes|true|self|identity|full)' /usr/lib/systemd/system/*.service | xargs -n1 basename)
for n in $need; do check "PrivateUsers=no drop-in for $n" test -f /etc/systemd/system/$n.d/50-no-userns.conf; done
echo "tmp.mount: $(grep -h '^Options=' /usr/lib/systemd/system/tmp.mount /etc/systemd/system/tmp.mount.d/*.conf | tail -1)  (drop-in wins)"
check "tmp.mount drop-in sets noexec,nosuid,nodev" bash -c "grep -q 'nosuid,nodev,noexec' /etc/systemd/system/tmp.mount.d/90-hardening.conf"
echo "systemd-analyze security --offline (exposure 0 = fully sandboxed, 10 = none):"
for u in chronyd rsyslog auditd fapolicyd usbguard firewalld sshd; do
  f=$(systemctl show -P FragmentPath $u 2>/dev/null); [ -z "$f" ] && f=/usr/lib/systemd/system/$u.service
  score=$(systemd-analyze security --offline=true --root=/ "$u.service" 2>/dev/null | grep -E 'Overall exposure' | sed 's/.*: //')
  printf '  %-12s %s\n' "$u" "${score:-n/a}"
done

section "Core dumps, journald, mounts"
systemd-analyze cat-config systemd/coredump.conf 2>/dev/null | grep -E '^(Storage|ProcessSizeMax)=' | sed 's/^/  coredump: /'
systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -E '^(Storage|Compress|ForwardToSyslog|Seal|SystemMaxUse)=' | sed 's/^/  journald: /'
check "DefaultLimitCORE=0" bash -c "systemd-analyze cat-config systemd/system.conf | grep -qx 'DefaultLimitCORE=0'"

section "Image integrity and updates"
grep -vE '^#|^$' /usr/lib/ostree/prepare-root.conf | sed 's/^/  prepare-root.conf: /'
check "composefs enabled" bash -c "grep -A1 '\[composefs\]' /usr/lib/ostree/prepare-root.conf | grep -q 'enabled = yes'"
check "policy.json parses" python3 -c "import json; json.load(open('/etc/containers/policy.json'))"
check "policy.json default is reject" python3 -c "import json,sys; sys.exit(json.load(open('/etc/containers/policy.json'))['default'][0]['type']!='reject')"
check "signing public key is a valid EC key" openssl pkey -pubin -in /etc/pki/containers/hardened-linux.pub -noout
echo "  skopeo pulling an unsigned image from a registry not in policy.json:"
skopeo inspect --raw docker://quay.io/centos-bootc/centos-bootc:stream10 >/dev/null 2>/tmp/sk.err; echo "  (inspect, which does not apply policy) exit $?"
skopeo copy docker://quay.io/libpod/busybox:latest oci:/tmp/bb:latest >/dev/null 2>/tmp/sk.err; rc=$?
echo "  skopeo copy exit $rc: $(tail -1 /tmp/sk.err | cut -c1-200)"
[ $rc -ne 0 ] && grep -qi 'rejected' /tmp/sk.err && pass "unsigned pull rejected by policy.json" || fail "unsigned pull was not rejected"
cat /usr/lib/bootc/install/*.toml | grep -vE '^#|^$' | sed 's/^/  bootc install: /'
check "bootc install requires tpm2-luks" grep -q 'block = \["tpm2-luks"\]' /usr/lib/bootc/install/50-hardening.toml

echo
echo "SUMMARY: $PASS passed, $FAIL failed"
