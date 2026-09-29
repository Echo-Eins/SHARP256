# The IPv6 laboratory in a virtual machine

The scenarios that need IPv6 (`v6`, `portmap6`, the IPv6 variants of `lan`,
`matrix --via turn` and `--via dht`) need a kernel that has it. A machine that
runs the rest of the laboratory in a container may have IPv6 switched off in
its kernel; a virtual machine has its own, and the laboratory runs in it
unchanged: `run.sh` boots it, runs `natlab.py` with the arguments given, and
powers it off.

## The image

Built once, from the distribution's own packages (Ubuntu 24.04 was used):

1. A root file system with `debootstrap noble`, and in it, from the
   distribution: `python3 nftables iproute2 miniupnpd-nftables coturn
   busybox kmod iputils-ping`.
2. A kernel and its modules: the `linux-image-*-generic` and
   `linux-modules-*-generic` packages, unpacked (`dpkg-deb -x`); the kernel
   goes to `natlab-vm/kernel/`, and its `lib/modules` into the root file
   system.
3. The root file system as a gzip-ed cpio archive (`find . | cpio -o -H newc
   | gzip`), `natlab-vm/base.gz`.

`init` (in this directory) is what the guest runs: it mounts the pseudo file
systems, loads the netfilter and veth modules, and runs the laboratory. The
release binaries and `natlab.py` are put in a second archive by `run.sh` each
time and concatenated to the first — the kernel accepts an initramfs made of
several.

Nothing here is specific to the results: it is the same kernel code doing the
same translation and filtering, and the virtual machine is only a way to have
IPv6 where the host has none.
