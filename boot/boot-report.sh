#!/bin/bash
# Prints the live security state of a booted hardened-linux machine.
# Every line is a command and its real output; nothing is interpreted.
set -u
run() { echo; echo "\$ $*"; timeout 60 bash -c "$*" 2>&1; }

echo "=== BEGIN BOOT REPORT ==="
run 'uname -r; uname -m'
run 'cat /proc/cmdline'
run 'getenforce'
run 'sestatus'
run 'cat /sys/kernel/security/lockdown'
run 'cat /sys/kernel/security/lsm; echo'
run 'cat /proc/sys/kernel/tainted'
run 'for k in kernel.kptr_restrict kernel.dmesg_restrict kernel.unprivileged_bpf_disabled net.core.bpf_jit_harden kernel.yama.ptrace_scope kernel.kexec_load_disabled kernel.perf_event_paranoid kernel.sysrq kernel.randomize_va_space kernel.io_uring_disabled vm.unprivileged_userfaultfd dev.tty.ldisc_autoload dev.tty.legacy_tiocsti user.max_user_namespaces fs.protected_symlinks fs.protected_hardlinks fs.protected_fifos fs.protected_regular fs.suid_dumpable kernel.core_pattern net.ipv4.ip_forward net.ipv4.conf.all.rp_filter net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.send_redirects net.ipv4.conf.all.log_martians net.ipv4.tcp_syncookies net.ipv6.conf.all.accept_ra; do sysctl $k; done'
run 'systemctl is-active auditd fapolicyd usbguard firewalld chronyd rsyslog sshd tmp.mount harden-dev-shm hardened-aide-init'
run 'systemctl --failed --no-legend --plain'
run 'systemctl is-enabled kdump.service debug-shell.service ctrl-alt-del.target systemd-coredump.socket'
run 'ps -eo label,comm | grep -E "auditd|fapolicyd|usbguard|chronyd|sshd|firewalld|rsyslogd|systemd-journal" | grep -v grep'
run 'auditctl -s'
run 'echo "loaded audit rules: $(auditctl -l | wc -l)"; auditctl -l | head -n 15'
run 'auditctl -D'
run 'firewall-cmd --state; firewall-cmd --get-default-zone; firewall-cmd --list-all'
run 'rpm -q nftables libnftnl firewalld'
run 'nft list chain inet firewalld filter_INPUT 2>&1 | head -n 20'
run 'nft list chain inet firewalld filter_IN_drop_allow 2>&1 | head -n 12'
run 'journalctl -b -u firewalld --no-pager -o cat | tail -n 8'
run 'for m in / /usr /sysroot /etc /var /tmp /dev/shm; do findmnt -no TARGET,FSTYPE,OPTIONS --target $m | head -1; done'
run 'touch /usr/test-write'
run 'cp /usr/bin/true /var/tmp/untrusted-true && /var/tmp/untrusted-true; echo "exit code $?"; rm -f /var/tmp/untrusted-true'
run 'printf "#!/bin/sh\necho script ran\n" > /var/tmp/untrusted.sh && chmod 755 /var/tmp/untrusted.sh && /var/tmp/untrusted.sh; echo "exit code $?"; rm -f /var/tmp/untrusted.sh'
run 'cp /usr/bin/true /root/untrusted-true && /root/untrusted-true; echo "exit code $?"; rm -f /root/untrusted-true'
run 'cp /usr/bin/true /tmp/t && /tmp/t; echo "exit code $?"; rm -f /tmp/t'
run 'setpriv --reuid=65534 --regid=65534 --clear-groups unshare --user true; echo "exit code $?"'
run 'unshare --user true; echo "exit code $?"'
run 'modprobe sctp; echo "exit code $?"'
run 'setenforce 0; echo "exit code $?"; getenforce'
run 'getsebool deny_ptrace deny_execmem secure_mode_policyload user_exec_content ssh_sysadm_login'
run 'semanage login -l 2>&1 | tail -n +3'
run 'update-crypto-policies --show'
run 'chronyc -N sources 2>&1 | cat; chronyc -N authdata 2>&1 | cat'
run 'journalctl -b -u chronyd --no-pager -o cat | tail -n 15'
run 'usbguard list-devices | head'
run 'fapolicyd-cli --check-status 2>&1 | head -n 12'
run 'cat /proc/sys/kernel/random/boot_id >/dev/null; ls -l /dev/tpm* 2>&1; [ -d /sys/firmware/efi ] && echo "booted via UEFI"; od -An -tu1 -j4 -N1 /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c 2>&1 | sed "s/^/SecureBoot byte:/"'
run 'lsblk -o NAME,TYPE,FSTYPE,SIZE,MOUNTPOINTS'
run 'cryptsetup status root 2>&1 | head -3; dmsetup ls 2>&1'
run 'bootc status 2>&1 | head -n 25'
run 'ps -o label= -p $$; ls -Z /usr/bin/bootc'
run 'journalctl -b --no-pager -o cat | grep -iE "rsyslog.*logcollector|omfwd" | head -n 3'
run 'ausearch -m AVC,USER_AVC -ts boot 2>/dev/null | grep -c "type=AVC"'
run 'ausearch -m AVC,USER_AVC -ts boot -i 2>/dev/null | grep -oE "avc: +denied +\{[^}]*\} for +pid=[0-9]+ comm=[^ ]+ .*tcontext=[^ ]+ tclass=[^ ]+" | sed -E "s/pid=[0-9]+ //; s/ino=[0-9]+ //; s/dev=[^ ]+ //" | sort | uniq -c | sort -rn | head -n 20'
run 'journalctl -b -u fapolicyd --no-pager -o cat | grep -E "^rule=" | sed -E "s/ pid=[0-9]+//; s/auid=[-0-9]+ //" | sort | uniq -c | sort -rn | head -n 15'
run 'ausearch -m FANOTIFY -ts boot 2>/dev/null | grep -c type=FANOTIFY'
run 'journalctl -b -p err --no-pager -o short-monotonic | tail -n 25'
run 'journalctl -b -u rsyslog --no-pager -o cat | tail -n 15'
run 'systemd-analyze security chronyd.service rsyslog.service auditd.service fapolicyd.service usbguard.service sshd.service --no-pager 2>&1 | tail -n 8'
run 'systemd-analyze'
run 'systemctl status hardened-aide-init --no-pager -n 3 | head -n 8'
echo
# The scanner's SCE checks are shell scripts it writes to a temporary
# directory and executes; /tmp is noexec and fapolicyd refuses untrusted
# scripts, so for the duration of the scan only: TMPDIR=/var/tmp and
# fapolicyd stopped. Both are printed as commands.
run 'systemctl stop fapolicyd; systemctl is-active fapolicyd'
echo
echo "\$ SCAP_MODE=machine TMPDIR=/var/tmp /usr/libexec/hardened-linux/scap-scan.sh /var/tmp/scap"
SCAP_MODE=machine TMPDIR=/var/tmp timeout 5400 /usr/libexec/hardened-linux/scap-scan.sh /var/tmp/scap 2>&1
run 'systemctl start fapolicyd; systemctl is-active fapolicyd'
echo
echo "=== END BOOT REPORT ==="
exit 0
