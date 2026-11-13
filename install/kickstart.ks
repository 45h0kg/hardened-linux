# Anaconda kickstart: install hardened-linux on a machine with full-disk
# encryption, then bind the LUKS key to the TPM2.
#
# NOT TESTED in this repository (the boot test uses a bootc-image-builder
# qcow2, which is not encrypted). Read before use; replace every CHANGE-ME.
#
# Use with bootc-image-builder --type anaconda-iso and this file as the
# [customizations.installer.kickstart] contents, or on a stock CentOS
# Stream 10 boot ISO with inst.ks=.

text
lang en_US.UTF-8
keyboard us
timezone UTC --utc
network --bootproto=dhcp --activate

# Wipe the target disk and create an encrypted LUKS2 root. The passphrase
# becomes the recovery key: keep it offline. After the TPM enrollment below,
# normal boots do not ask for it.
zerombr
clearpart --all --initlabel --disklabel=gpt
reqpart --add-boot
part / --fstype=xfs --grow --encrypted --luks-version=luks2 --passphrase=CHANGE-ME-recovery-passphrase

# Install the signed image, enforcing the signature policy for later
# upgrades too.
ostreecontainer --url=registry.example.com/hardened/hardened-linux:latest --transport=registry

# No root password; one administrator in wheel with an SSH key.
rootpw --lock
user --name=CHANGE-ME-admin --groups=wheel --lock
sshkey --username=CHANGE-ME-admin "ssh-ed25519 AAAA...CHANGE-ME"

reboot

%post --erroronfail
# Bind the root volume to the TPM2, sealed against PCR 7 (Secure Boot
# state and keys). PCR 7 stays the same across kernel updates, which an
# image-based system does often; binding to PCRs 4, 9 or 11 would need a
# re-enrollment or a signed PCR policy after every update.
dev=$(blkid -t TYPE=crypto_LUKS -o device | head -n 1)
PASSWORD='CHANGE-ME-recovery-passphrase' \
  systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7 "$dev"
# Tell the initramfs to try the TPM before asking for a passphrase.
sed -i 's/\(luks-[^ ]*\s\+UUID=[^ ]*\s\+none\s\+\)\(.*\)/\1\2,tpm2-device=auto/' /etc/crypttab
%end
