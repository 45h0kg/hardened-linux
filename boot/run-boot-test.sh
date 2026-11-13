#!/bin/bash
# Boot the hardened image in a VM and capture the live security report.
#
#   1. build hardened-linux:boottest (boot/Containerfile.boottest)
#   2. copy it into a containers-storage volume, which bootc-image-builder
#      reads its source image from
#   3. bootc-image-builder: OCI image -> qcow2 disk (privileged container)
#   4. QEMU (TCG software emulation; Docker Desktop exposes no /dev/kvm)
#      boots the disk with UEFI firmware; the serial console is saved to
#      $OUT/serial.log. The report unit powers the VM off when done.
#
# Usage: boot/run-boot-test.sh [output-dir]      (default: ./output)
# Set DOCKER to wrap docker, e.g. DOCKER="timeout 3600 docker".
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=$(mkdir -p "${1:-output}" && cd "${1:-output}" && pwd)
D=${DOCKER:-docker}
BIB=quay.io/centos-bootc/bootc-image-builder:latest
VOL=hardened-linux-cstorage

$D build --platform linux/arm64 --label lab=hardened -f boot/Containerfile.boottest -t hardened-linux:boottest .
$D build --platform linux/arm64 --label lab=hardened -f boot/qemu/Containerfile -t hardened-linux:qemu boot/qemu

$D volume create --label lab=hardened "$VOL" >/dev/null
$D save hardened-linux:boottest | $D run --rm -i --privileged --label lab=hardened \
  -v "$VOL":/var/lib/containers/storage --entrypoint podman "$BIB" load

# --cgroupns=host: bootc-image-builder starts its build root with Podman,
# which needs to create cgroups; inside Docker Desktop's private cgroup
# namespace that failed ("controller `pids` is not available").
$D run --rm --privileged --cgroupns=host --name hardened-linux-bib --label lab=hardened \
  --security-opt label=type:unconfined_t \
  -v "$VOL":/var/lib/containers/storage -v "$OUT":/output \
  "$BIB" build --type qcow2 --rootfs xfs --progress verbose \
  docker.io/library/hardened-linux:boottest 2>&1 | tee "$OUT/bib.log"

# -cpu max,pauth-impdef=on: all features QEMU can emulate, with a cheaper
#   pointer-authentication algorithm (much faster under TCG).
# -bios QEMU_EFI.silent.fd: EDK II UEFI firmware for the virt machine, the
#   quiet build (Fedora's QEMU_EFI.fd is a debug build that floods the
#   serial console and slows boot under emulation).
$D run --rm --name hardened-linux-qemu --label lab=hardened -v "$OUT":/work hardened-linux:qemu \
  qemu-system-aarch64 -machine virt -cpu max,pauth-impdef=on -smp 4 -m 3072 \
    -bios /usr/share/edk2/aarch64/QEMU_EFI.silent.fd \
    -drive file=/work/qcow2/disk.qcow2,if=virtio,format=qcow2 \
    -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
    -device virtio-rng-pci \
    -display none -serial file:/work/serial.log -no-reboot

sed -n '/=== BEGIN BOOT REPORT ===/,/=== END BOOT REPORT ===/p' "$OUT/serial.log" | tr -d '\r' > "$OUT/boot-report.txt"
echo "report: $OUT/boot-report.txt"
