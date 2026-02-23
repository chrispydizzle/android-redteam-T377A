# QEMU ARM Kernel Fuzzing Environment

A local ARM kernel fuzzing lab running Linux 3.10.108 (same version family as the Samsung SM-T377A) in QEMU. Safe to crash repeatedly — it's just a VM.

## Quick Start

```bat
REM Launch interactive QEMU VM (Ctrl-A X to quit)
run-qemu.bat

REM Or headless (output to ~/kernel-fuzz/serial.log in WSL)
run-qemu.bat headless
```

## Architecture

```
android-redteam/
├── qemu/                       ← Scripts and module source (this directory)
│   ├── build-arm.bat               Compile C → ARM binary, push to physical device
│   ├── push-to-qemu.bat            Compile C → ARM binary, inject into QEMU rootfs
│   ├── run-qemu.bat                Launch QEMU ARM VM
│   ├── rebuild-kernel.bat           Rebuild the 3.10.108 kernel
│   ├── mali_stub.c                  Mali r7p0 stub kernel module source
│   └── build_mali_stub.sh           Build mali_stub.ko + repack rootfs
├── src/                         C source files for the VM
│
└── WSL Ubuntu-22.04 (~/kernel-fuzz/)
    ├── linux-3.10.108/              Kernel source (vexpress-a9 config)
    ├── gcc-linaro-4.9.4/            Cross-compiler (GCC 4.9, era-correct for 3.10)
    ├── mali_stub/                   Module build directory
    ├── rootfs/                      Busybox-based initramfs
    │   ├── bin/autorun              Auto-executed on boot (optional)
    │   └── lib/modules/mali_stub.ko Loaded by init
    └── initramfs.cpio.gz            Packed rootfs
```

## VM Details

| Property | Value |
|----------|-------|
| **Machine** | QEMU vexpress-a9 (ARM Cortex-A9) |
| **Kernel** | Linux 3.10.108 (Linaro GCC 4.9.4) |
| **RAM** | 256 MB |
| **Root** | initramfs (busybox, no disk) |
| **Console** | Serial on ttyAMA0 |
| **Root access** | Boots directly as UID 0 |
| **kallsyms** | Full addresses visible (no kptr_restrict) |
| **slabinfo** | Readable (full SLUB cache layout) |
| **/dev/binder** | ✅ Android Binder IPC (built-in) |
| **/dev/ashmem** | ✅ Android shared memory (built-in) |
| **/dev/mali0** | ✅ Mali r7p0 stub (loaded via mali_stub.ko) |
| **SLUB_DEBUG** | ✅ Free poison + red zones + user tracking (`slub_debug=FZPU`) |
| **LOCKDEP** | ✅ Full lock dependency validator |
| **DEBUG_OBJECTS** | ✅ Object lifecycle tracking (UAF detection) |
| **DEBUG_PAGEALLOC** | ✅ Page-level use-after-free detection |
| **DEBUG_CREDENTIALS** | ✅ Credential structure corruption detection |
| **KMEMLEAK** | ✅ Available (boot with `kmemleak=on`) |
| **FAULT_INJECTION** | ✅ Available via debugfs |

## Workflow: Writing and Testing Programs

```bat
REM 1. Write your C program (e.g., mytest.c)

REM 2. Compile and add to QEMU rootfs
push-to-qemu.bat mytest.c mytest

REM 3. Boot the VM — it auto-runs /bin/autorun if present
run-qemu.bat

REM 4. Or manually run in the VM shell
/ # /bin/mytest
```

To set a program as auto-run:
```bat
REM In WSL:
wsl -d Ubuntu-22.04 -- bash -c "cp ~/kernel-fuzz/rootfs/bin/mytest ~/kernel-fuzz/rootfs/bin/autorun"
REM Then rebuild initramfs:
wsl -d Ubuntu-22.04 -- bash -c "cd ~/kernel-fuzz/rootfs && find . | cpio -o -H newc 2>/dev/null | gzip > ~/kernel-fuzz/initramfs.cpio.gz"
```

## Mali Stub Driver

The real Mali Midgard r7p0 driver can't run without GPU hardware, so we use a stub
kernel module (`mali_stub.ko`) that registers `/dev/mali0` with the **same ioctl
interface** as the real Samsung driver:

- Uses the UK (User-Kernel) protocol: single ioctl with variable-size payload
- First 8 bytes carry a `uk_header` with function ID
- Implements all 40+ function IDs from the real dispatch table
- Simulates MEM_ALLOC/FREE/QUERY with fake GPU addresses
- Logs every call to kernel dmesg for analysis

Source: `mali_stub.c` (derived from Samsung's GPL kernel source for SM-T377A)

To rebuild after changes:
```bash
wsl -d Ubuntu-22.04 -- bash /mnt/c/InfoSec/android-redteam/build_mali_stub.sh
```

## Enabling Android Drivers (Binder, Ashmem, ION)

The default vexpress kernel doesn't include Android-specific drivers. To enable them:

```bat
REM Open kernel menuconfig
rebuild-kernel.bat menuconfig

REM Navigate to:
REM   Device Drivers → Staging drivers → Android
REM   Enable: Binder IPC Driver, ashmem, ION Memory Manager
REM Save and exit, then rebuild:

rebuild-kernel.bat
```

Or manually in WSL:
```bash
cd ~/kernel-fuzz/linux-3.10.108
export ARCH=arm CROSS_COMPILE=$HOME/kernel-fuzz/gcc-linaro-4.9.4/bin/arm-linux-gnueabi-

# Enable Android staging drivers
./scripts/config --enable STAGING
./scripts/config --enable ANDROID
./scripts/config --enable ANDROID_BINDER_IPC
./scripts/config --enable ASHMEM
./scripts/config --enable ION

make olddefconfig
make -j$(nproc) zImage
```

## Kernel Reconfiguration

```bat
REM Full menuconfig
rebuild-kernel.bat menuconfig

REM Just rebuild (after editing .config)
rebuild-kernel.bat
```

## Files

| File | Purpose |
|------|---------|
| `mali_stub.c` | Mali r7p0 stub kernel module (ioctl interface) |
| `build_mali_stub.sh` | Build mali_stub.ko and inject into rootfs |
| `run-qemu.bat` | Launch the QEMU VM |
| `rebuild-kernel.bat` | Rebuild kernel after config changes |
| `push-to-qemu.bat` | Cross-compile for QEMU VM (initramfs inject) |
| `build-arm.bat` | Cross-compile for physical Android device (ADB push) |
| `../src/ioctl_enum.c` | Binder + ashmem + Mali ioctl enumerator |
| `../src/probe-devnodes.c` | Opens /dev nodes, reads kallsyms/slabinfo |
| `../src/hello.c` | Minimal ARM test program |
