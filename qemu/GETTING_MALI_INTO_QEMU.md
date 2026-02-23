# Getting Mali into the QEMU Image

How `/dev/mali0` was added to the QEMU kernel fuzzing VM — including the approaches
that were tried and why the stub driver was the final solution.

## The Problem

The Samsung SM-T377A has a Mali T720 GPU running the **Midgard kbase r7p0** driver.
On the real device, `/dev/mali0` is world-writable and openable from the ADB shell
with no SELinux denial — making it a prime target for ioctl-based kernel exploitation.

We wanted the QEMU VM to have the same `/dev/mali0` device node so we could exercise
the ioctl interface in a safe, crashable environment.

**The challenge:** the Mali driver needs actual GPU hardware to initialize. QEMU's
`vexpress-a9` machine has no Mali GPU.

## Approach 1: Mainline Kernel (no Mali)

Linux 3.10 mainline does not include the Mali driver at all. ARM distributes it
separately. The kernel tree has:

- `drivers/gpu/arm/` — **empty** in vanilla 3.10.108

The open-source **Panfrost** driver exists in modern kernels (5.x+) but doesn't
support kernel 3.10.

**Result:** Dead end.

## Approach 2: Community Mali Driver Repos

Checked GitHub mirrors of ARM's open-source Mali releases:

| Repository | Versions Available |
|------------|-------------------|
| [LibreELEC/mali-midgard](https://github.com/LibreELEC/mali-midgard) | r26p0, r27p0, r28p0 |
| [EasyNetDev/mali-midgard](https://github.com/EasyNetDev/mali-midgard) | r26p0, r28p0 |

Both repos only carry recent driver versions (r26+). We need **r7p0** to match
the Samsung device. ARM's official developer site has older releases but
downloads require registration and the r7p0 archives aren't easily accessible.

**Result:** Wrong versions available.

## Approach 3: Samsung GPL Kernel Source (jackpot — partially)

Samsung is required by the GPL to release kernel source for their devices. Found
a GitHub mirror of the exact kernel:

```
https://github.com/jcadduono/android_kernel_samsung_universal3475
```

This is the **SM-T377A kernel source** (Exynos 3475 / universal3475 platform).

### Sparse checkout (only the Mali driver)

The full kernel is huge. We only need the GPU driver:

```bash
cd /tmp
git clone --depth 1 --filter=blob:none --sparse \
    https://github.com/jcadduono/android_kernel_samsung_universal3475.git samsung-kernel
cd samsung-kernel
git sparse-checkout set drivers/gpu/arm
git checkout
```

This pulled ~1.5 MB (844 objects) — just the GPU drivers.

### What's inside

```
drivers/gpu/arm/
├── Kconfig          # Top-level GPU menu
├── Kbuild
├── mali400/         # Older Mali 400 driver
├── midgard/         # Generic Midgard driver
├── midgard_wk04/    # Another Midgard variant
├── t6xx/            # Mali T6xx series
├── t72x/            # ← This is what we want
│   ├── r5p0/        # Older driver version
│   └── r7p0/        # ← Exact match: r7p0-03rel0
└── t7xx/            # Mali T7xx series
```

The `t72x/r7p0/` directory has **428 source files** — the complete Mali Midgard
kbase driver, version r7p0-03rel0, exactly matching the Samsung device.

### Examining the real driver's ioctl interface

The key file is `mali_kbase_core_linux.c`. The ioctl design is unusual:

```c
// Single ioctl handler — all functions go through here
static long kbase_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    u64 msg[(CALL_MAX_SIZE + 7) >> 3];      // 536-byte buffer on stack
    u32 size = _IOC_SIZE(cmd);               // size from ioctl command number

    if (size > CALL_MAX_SIZE) return -ENOTTY;
    copy_from_user(&msg, (void __user *)arg, size);

    kbase_dispatch(kctx, &msg, size);        // dispatch by uk_header.id

    copy_to_user((void __user *)arg, &msg, size);
}
```

The first 8 bytes of the payload are a `uk_header` containing a function ID.
The `kbase_dispatch` function is a giant switch statement over ~40 function IDs
(MEM_ALLOC, MEM_FREE, JOB_SUBMIT, etc.).

### Trying to compile the real driver

Two problems prevented using the real driver:

**1. Kconfig dependency on `SOC_EXYNOS3475`:**

```kconfig
# drivers/gpu/arm/Kconfig
if SOC_EXYNOS3475
source "drivers/gpu/arm/t72x/Kconfig"
endif
```

The driver menu is gated behind the Exynos 3475 SoC config, which doesn't
exist on vexpress-a9.

**2. Hardware probe failure:**

Even after removing the Kconfig guard, the driver's `kbase_platform_init()`
reads GPU identification registers at specific MMIO addresses. These registers
don't exist in QEMU, so the probe would fail with a bus error or return garbage.

### The `CONFIG_MALI_NO_MALI` option

The Kbuild file references a `CONFIG_MALI_NO_MALI` option that would use a
**dummy hardware model** (`mali_kbase_model_dummy.c`, `mali_kbase_model_linux.c`):

```makefile
ifeq ($(CONFIG_MALI_NO_MALI),y)
    BACKEND += backend/gpu/mali_kbase_model_dummy.c
    BACKEND += backend/gpu/mali_kbase_model_linux.c
    BACKEND += backend/gpu/mali_kbase_model_error_generator.c
endif
```

This would have been perfect — a software model of the GPU for testing. But
**Samsung's GPL release doesn't include these files**. They exist in ARM's
internal releases but are not part of the open-source distribution.

**Result:** Have the source, can't compile it for QEMU.

## Approach 4: Stub Kernel Module (the solution)

Since we have the complete ioctl interface from Samsung's source but can't run
the real driver, we built a **stub kernel module** that:

1. Registers `/dev/mali0` as a misc device (same as real driver)
2. Implements the same `kbase_ioctl()` entry point
3. Dispatches by `uk_header.id` through the same function IDs
4. Simulates state (version handshake, memory allocation tracking)
5. Logs every call to dmesg

### What was extracted from the real driver

From `mali_uk.h`:
- `union uk_header` structure (8 bytes: id + ret + alignment)
- `UK_FUNC_ID = 512` base offset
- `struct uku_version_check_args`

From `mali_kbase_uku.h`:
- All 40+ `KBASE_FUNC_*` constants (MEM_ALLOC = 512, MEM_IMPORT = 513, etc.)
- Argument structures for each function

From `mali_kbase_core_linux.c`:
- `CALL_MAX_SIZE = 536` max payload
- `kbase_ioctl()` copy_from_user / dispatch / copy_to_user flow
- `kbase_dispatch()` version handshake requirement
- SET_FLAGS must be called before any other operation
- Per-context state (api_version, setup_complete)

### Building the module

The module is built out-of-tree against the same kernel source:

```bash
# The build script (build_mali_stub.sh) does:
make -C ~/kernel-fuzz/linux-3.10.108 \
     M=~/kernel-fuzz/mali_stub \
     ARCH=arm \
     CROSS_COMPILE=~/kernel-fuzz/gcc-linaro-4.9.4/bin/arm-linux-gnueabi- \
     modules

# Result: mali_stub.ko (95 KB)
```

One compile fix was needed: adding `#include <linux/sched.h>` for `current->pid`
(kernel 3.10 doesn't transitively include it like newer kernels do).

### Loading in the VM

The init script loads it automatically:

```sh
insmod /lib/modules/mali_stub.ko
# mali_stub: /dev/mali0 registered (r7p0 stub, 57 functions)
```

## How the Stub Compares to the Real Driver

| Aspect | Real Driver | Stub |
|--------|-------------|------|
| Device node | `/dev/mali0` | `/dev/mali0` ✅ |
| Ioctl protocol | UK header + payload | Same ✅ |
| Function IDs | 40+ KBASE_FUNC_* | Same ✅ |
| Version handshake | Required before ops | Same ✅ |
| SET_FLAGS gate | Required after version | Same ✅ |
| MEM_ALLOC | Real GPU VA allocation | Simulated (fake addresses) |
| MEM_FREE | Real GPU VA teardown | Tracked (counter only) |
| JOB_SUBMIT | Queues GPU work | Returns error (no GPU) |
| HWCNT_* | Reads HW counters | Returns error (no HW) |
| copy_from_user | Real | Same ✅ |
| copy_to_user | Real | Same ✅ |
| Size validation | Checks per function | Same ✅ |
| NULL ptr handling | EFAULT | Same ✅ |
| dmesg logging | Sparse | Verbose (every call logged) |

The stub faithfully reproduces the **ioctl entry surface** — the part of the
driver that processes untrusted userspace data. It does not reproduce the GPU
memory management internals or hardware interaction, since those require actual
hardware and aren't reachable from the ioctl parsing layer without a valid
GPU context.

## Rebuilding After Changes

Edit `mali_stub.c` on the Windows side, then:

```bash
wsl -d Ubuntu-22.04 -- bash /mnt/c/InfoSec/android-redteam/build_mali_stub.sh
```

This copies the source, compiles the module, copies it into the rootfs, and
repacks the initramfs. Then just `run-qemu.bat` to test.

## Source Files

| File | Purpose |
|------|---------|
| `mali_stub.c` | The stub kernel module source |
| `build_mali_stub.sh` | Build script (compile + inject into rootfs) |
| `ioctl_enum.c` | Userspace test program that exercises the Mali ioctl interface |

## References

- Samsung GPL kernel source: https://github.com/jcadduono/android_kernel_samsung_universal3475
- Driver location in source tree: `drivers/gpu/arm/t72x/r7p0/`
- Key files consulted: `mali_kbase_core_linux.c`, `mali_kbase_uku.h`, `mali_uk.h`
- ARM Mali Midgard architecture: https://developer.arm.com/ip-products/graphics-and-multimedia/mali-gpus
