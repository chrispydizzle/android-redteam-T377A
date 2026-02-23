# Building the QEMU ARM Kernel Image

Step-by-step record of how the QEMU ARM kernel fuzzing VM was built from scratch.
This documents every decision, dead end, and fix so you can reproduce or modify it.

## Goal

Build a QEMU virtual machine running **Linux 3.10.x** on **ARM** — the same kernel
version family as the Samsung SM-T377A (kernel 3.10.9). The VM needs to:

- Boot to a root shell with no authentication
- Expose `/proc/kallsyms` with real addresses (no `kptr_restrict`)
- Expose `/proc/slabinfo` (SLUB allocator details)
- Support loadable kernel modules (for the Mali stub)
- Include Android-specific drivers: **binder** and **ashmem**

## Environment

| Component | Version |
|-----------|---------|
| Host OS | Windows 11 |
| WSL distro | Ubuntu 22.04 |
| QEMU | 6.2.0 (from Ubuntu repos) |
| Kernel source | Linux 3.10.108 (last 3.10.x release, "END-OF-LIFE") |
| Cross-compiler | Linaro GCC 4.9.4 (2017.01) |
| Rootfs | BusyBox (static ARM binary) |
| QEMU machine | `vexpress-a9` (ARM Cortex-A9, versatile express) |

## Step 1: Install QEMU

```bash
sudo apt-get update
sudo apt-get install -y qemu-system-arm
qemu-system-arm --version
# QEMU emulator version 6.2.0
```

## Step 2: Download Kernel Source

Linux 3.10.108 is the final release of the 3.10 LTS branch. Downloaded from kernel.org:

```bash
mkdir -p ~/kernel-fuzz && cd ~/kernel-fuzz
wget https://cdn.kernel.org/pub/linux/kernel/v3.x/linux-3.10.108.tar.xz
tar xf linux-3.10.108.tar.xz
```

## Step 3: Cross-Compiler Selection

### Why not system GCC?

The system GCC in Ubuntu 22.04 is **GCC 11**. It **cannot** compile kernel 3.10:

- **Struct assertion failures** in ARM assembly — GCC 10+ changed how it handles
  certain inline assembly constraints that kernel 3.10 relies on
- The kernel's build system assumes GCC 4.x/5.x era behavior

### Why Linaro GCC 4.9.4?

- Era-correct for kernel 3.10 (Samsung used a similar vintage compiler)
- Linaro maintains ARM-specific patches and optimizations
- The 2017.01 release is the last 4.9 release, well-tested

```bash
cd ~/kernel-fuzz
wget https://releases.linaro.org/components/toolchain/binaries/4.9-2017.01/arm-linux-gnueabi/gcc-linaro-4.9.4-2017.01-x86_64_arm-linux-gnueabi.tar.xz
tar xf gcc-linaro-4.9.4-2017.01-x86_64_arm-linux-gnueabi.tar.xz
mv gcc-linaro-4.9.4-2017.01-x86_64_arm-linux-gnueabi gcc-linaro-4.9.4

# Verify
~/kernel-fuzz/gcc-linaro-4.9.4/bin/arm-linux-gnueabi-gcc --version
# arm-linux-gnueabi-gcc (Linaro GCC 4.9-2017.01) 4.9.4
```

## Step 4: Configure the Kernel

Started with the `vexpress_defconfig` base, then customized:

```bash
cd ~/kernel-fuzz/linux-3.10.108
export ARCH=arm
export CROSS_COMPILE=$HOME/kernel-fuzz/gcc-linaro-4.9.4/bin/arm-linux-gnueabi-

# Start from vexpress default config
make vexpress_defconfig

# Enable features we need
./scripts/config --enable DEBUG_INFO         # Full debug symbols
./scripts/config --enable PANIC_ON_OOPS      # Crash hard on kernel bugs (good for fuzzing)
./scripts/config --enable DEVTMPFS           # Auto-populate /dev
./scripts/config --enable DEVTMPFS_MOUNT     # Auto-mount devtmpfs
./scripts/config --enable MODULES            # Loadable modules (for mali_stub.ko)

# Enable Android staging drivers
./scripts/config --enable STAGING
./scripts/config --enable ANDROID
./scripts/config --enable ANDROID_BINDER_IPC # /dev/binder
./scripts/config --enable ASHMEM             # /dev/ashmem

# Finalize config (resolve dependencies)
make olddefconfig
```

### Config choices explained

| Option | Why |
|--------|-----|
| `DEBUG_INFO=y` | Full DWARF symbols for crash analysis and GDB |
| `PANIC_ON_OOPS=y` | Kernel panics on any oops — lets QEMU detect crashes |
| `DEVTMPFS=y` | Auto-creates device nodes, no need for `mknod` |
| `MODULES=y` | Required to load `mali_stub.ko` at runtime |
| `STAGING=y` + `ANDROID=y` | Prerequisite for binder/ashmem |
| `ANDROID_BINDER_IPC=y` | Creates `/dev/binder` — Android's IPC mechanism |
| `ASHMEM=y` | Creates `/dev/ashmem` — Android shared memory |

### What we did NOT enable

- **ION** (`CONFIG_ION`) — Not present in kernel 3.10 source tree (added in 3.14)
- **KASLR** — Not available for 32-bit ARM in 3.10
- **Stack canaries** — Would hide the exact vulnerability class we're studying

## Step 5: Fix Build Errors

### DTC `yylloc` multiple definition

Modern toolchains expose a bug in the Device Tree Compiler bundled with 3.10.
The flex-generated lexer declares `YYLTYPE yylloc` as a global, which conflicts
with the definition in the parser:

```bash
# Fix: change definition to extern declaration
sed -i "s/^YYLTYPE yylloc;/extern YYLTYPE yylloc;/" scripts/dtc/dtc-lexer.lex.c_shipped
```

Without this fix, you get:
```
multiple definition of `yylloc'; dtc-lexer.lex.o:(.bss+0x0): first defined here
```

This is a well-known issue when building old kernels with new toolchains. The DTC
in newer kernels (4.x+) already has this fix.

## Step 6: Build the Kernel

```bash
cd ~/kernel-fuzz/linux-3.10.108
make -j$(nproc) zImage dtbs

# Results:
# arch/arm/boot/zImage                          — 2.6 MB (compressed kernel)
# arch/arm/boot/dts/vexpress-v2p-ca9.dtb        — 12 KB (device tree blob)
```

Build takes about 5-10 minutes on a modern machine.

## Step 7: Create the Root Filesystem

The rootfs is a minimal initramfs (loaded into RAM, no disk image needed):

### Download BusyBox

```bash
cd ~/kernel-fuzz
# Pre-built static ARM busybox (no cross-compilation needed)
wget https://busybox.net/downloads/binaries/1.35.0-armv7l/busybox -O busybox-arm
chmod +x busybox-arm
```

### Build the rootfs directory structure

```bash
ROOTFS=~/kernel-fuzz/rootfs
mkdir -p $ROOTFS/{bin,sbin,usr/bin,usr/sbin,proc,sys,dev,tmp,lib/modules,dev/pts,dev/shm}
cp busybox-arm $ROOTFS/bin/busybox
chmod +x $ROOTFS/bin/busybox
```

### Create the init script

The init script is what the kernel runs as PID 1:

```bash
cat > $ROOTFS/init << 'EOF'
#!/bin/busybox sh
/bin/busybox --install -s /bin
/bin/busybox --install -s /sbin
/bin/busybox --install -s /usr/bin
/bin/busybox --install -s /usr/sbin

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /dev/pts /dev/shm
mount -t devpts devpts /dev/pts
mount -t tmpfs tmpfs /tmp

hostname qemu-fuzz

echo "=================================="
echo " QEMU ARM Kernel Fuzzing VM"
echo " Kernel: $(uname -r)"
echo " Arch:   $(uname -m)"
echo "=================================="

# Load Mali stub module
if [ -f /lib/modules/mali_stub.ko ]; then
    echo "[*] Loading mali_stub.ko..."
    insmod /lib/modules/mali_stub.ko
    if [ $? -eq 0 ]; then
        echo "[+] Mali stub loaded — /dev/mali0 available"
    else
        echo "[-] Failed to load mali_stub.ko"
    fi
fi

# Show available device nodes
echo ""
echo "Device nodes:"
ls -la /dev/mali0 /dev/binder /dev/ashmem 2>/dev/null || echo "(some nodes missing)"

# Auto-run /bin/autorun if it exists
if [ -x /bin/autorun ]; then
    echo ""
    echo "[*] Running /bin/autorun..."
    /bin/autorun
    echo "[*] autorun finished (exit=$?)"
fi

exec /bin/sh
EOF
chmod +x $ROOTFS/init
```

### Pack the initramfs

```bash
cd $ROOTFS
find . | cpio -o -H newc 2>/dev/null | gzip > ~/kernel-fuzz/initramfs.cpio.gz
# Result: ~660 KB (without mali_stub.ko), ~3.9 MB (with)
```

## Step 8: Boot Test

```bash
cd ~/kernel-fuzz
qemu-system-arm \
  -M vexpress-a9 \
  -kernel linux-3.10.108/arch/arm/boot/zImage \
  -dtb linux-3.10.108/arch/arm/boot/dts/vexpress-v2p-ca9.dtb \
  -initrd initramfs.cpio.gz \
  -append "console=ttyAMA0 root=/dev/ram rdinit=/init" \
  -m 256M \
  -nographic
```

Boot time: **~3 seconds** to shell prompt.

### Expected warnings (harmless)

```
CPU1: failed to boot: -38
CPU2: failed to boot: -38
CPU3: failed to boot: -38
```

The vexpress-a9 config tries to boot 4 CPUs but QEMU's emulation only supports 1.
This is cosmetic — the kernel continues fine with 1 CPU.

```
/bin/sh: can't access tty; job control turned off
```

BusyBox shell notes there's no controlling TTY on serial console. Job control
(Ctrl-Z, `bg`/`fg`) won't work but everything else does.

### Exit QEMU

Press `Ctrl-A` then `X` to quit.

## Step 9: Verify the Environment

From inside the VM shell:

```sh
# Kernel symbols with real addresses (not zeroed)
head -3 /proc/kallsyms
# 80008240 T asm_do_IRQ

# SLUB slab allocator info
cat /proc/slabinfo | head -5

# Device nodes
ls -la /dev/binder /dev/ashmem /dev/mali0

# Kernel version
uname -a
# Linux qemu-fuzz 3.10.108 #2 SMP ... armv7l GNU/Linux
```

## Final File Layout in WSL

```
~/kernel-fuzz/
├── linux-3.10.108/           Kernel source tree
│   ├── .config               Current kernel configuration
│   ├── arch/arm/boot/
│   │   ├── zImage            Compressed kernel (2.6 MB)
│   │   └── dts/
│   │       └── vexpress-v2p-ca9.dtb  Device tree (12 KB)
│   └── ...
├── gcc-linaro-4.9.4/         Cross-compiler toolchain
│   └── bin/
│       └── arm-linux-gnueabi-gcc
├── rootfs/                   Rootfs directory
│   ├── init                  PID 1 init script
│   ├── bin/
│   │   ├── busybox           Static ARM busybox
│   │   ├── ioctl_enum        Ioctl enumerator binary
│   │   ├── probe             Device node probe binary
│   │   └── autorun           → symlink or copy of test binary
│   └── lib/modules/
│       └── mali_stub.ko      Mali stub kernel module (95 KB)
├── mali_stub/                Module build directory
│   ├── mali_stub.c           Module source (copied from Windows)
│   ├── Makefile              Kbuild makefile
│   └── mali_stub.ko          Compiled module
├── busybox-arm               Downloaded static busybox
└── initramfs.cpio.gz         Packed rootfs (3.9 MB)
```

## Troubleshooting

### "GCC internal error" or struct assertion failures during kernel build

You're using a GCC version that's too new. Kernel 3.10 requires GCC 4.x or 5.x.
Use the Linaro 4.9.4 toolchain as documented above.

### "multiple definition of yylloc"

Apply the DTC fix from Step 5. This happens with any modern binutils/flex.

### QEMU hangs with no output

Make sure you're passing `-nographic` (interactive) or `-serial file:output.txt`
(headless). Without either, output goes to a graphical window that may not exist
in WSL.

### Module fails to load with "invalid module format"

The module must be compiled against the **exact same** kernel source tree that
produced the running zImage. If you rebuild the kernel, rebuild the module too.

### PowerShell mangles `$()` in WSL commands

PowerShell interprets `$()` as its own subexpression syntax. Solutions:
- Use single quotes: `wsl -- bash -c 'echo $(uname)'`
- Write a `.sh` script file and run it: `wsl -- bash /path/to/script.sh`
- Use `wslpath -a "C:/path"` with forward slashes (backslashes also get mangled)
