#!/bin/bash
# Runs the laboratory in a virtual machine, for the parts that need a kernel
# with IPv6 when the machine this runs on has none (a container's often has
# it disabled). Everything is the guest kernel's: the same network
# namespaces, veth pairs and nftables rules as natlab.py makes on a host.
#
#     scripts/natlab/vm/run.sh v6 --scenario "dual stack" --direct-only
#     scripts/natlab/vm/run.sh portmap6
#     VM_SCRIPT=commands.sh scripts/natlab/vm/run.sh     # many commands, one boot
#
# The arguments are natlab.py's. Needs qemu-system-x86_64 and the image built
# as scripts/natlab/vm/README.md says; VM_DIR names where it is
# (default: ./natlab-vm), BIN_DIR where the release binaries are
# (default: target/release). Without KVM the guest is emulated (TCG), which
# is slow and, for what is measured here, good enough: nothing in the
# results below depends on speed.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
VM_DIR=${VM_DIR:-$PWD/natlab-vm}
BIN_DIR=${BIN_DIR:-$REPO/target/release}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/extra/lab"
cp "$BIN_DIR"/sharp-{relay,sender,receiver,probe} "$WORK/extra/lab/"
cp "$HERE/../natlab.py" "$HERE/../dht_node.py" "$WORK/extra/lab/"
cp "$HERE/init" "$WORK/extra/init"
chmod +x "$WORK/extra/init"
if [ -n "${VM_SCRIPT:-}" ]; then
  # Several commands in one boot: a file of shell lines, run in /lab.
  { printf '#!/bin/sh\ncd /lab\n'; cat "$VM_SCRIPT"; } > "$WORK/extra/lab/run.sh"
else
  {
    printf '#!/bin/sh\nexec env NATLAB_DIAG=%s python3 /lab/natlab.py ' "${NATLAB_DIAG:-}"
    printf '%q ' "$@"
    printf '\n'
  } > "$WORK/extra/lab/run.sh"
fi
(cd "$WORK/extra" && find . | busybox cpio -o -H newc 2>/dev/null | gzip -1) > "$WORK/extra.gz"
cat "$VM_DIR/base.gz" "$WORK/extra.gz" > "$WORK/initrd.gz"
KVM=()
[ -w /dev/kvm ] && KVM=(-enable-kvm -cpu host)
[ ${#KVM[@]} -eq 0 ] && KVM=(-accel tcg,thread=multi -cpu "${VM_CPU:-qemu64}")
timeout "${VM_TIMEOUT:-3000}" qemu-system-x86_64 \
  -kernel "$VM_DIR"/kernel/vmlinuz-* -initrd "$WORK/initrd.gz" \
  -append "console=ttyS0 quiet panic=-1" -nographic -m 3072 -smp 4 -no-reboot "${KVM[@]}" \
  2>&1 | grep -a --line-buffered -v "^$"
