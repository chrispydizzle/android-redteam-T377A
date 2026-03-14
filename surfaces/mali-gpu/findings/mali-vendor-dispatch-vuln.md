# ⚠ DEBUNKED — Mali Samsung Vendor Dispatch Vulnerability

## ⚠⚠⚠ THIS FINDING IS INCORRECT ⚠⚠⚠

**The "vulnerability" described below was caused by a bug in our test code (wrong ION allocation struct for ARM32), NOT by a kernel bug.**

### What Actually Happened

1. `ion_alloc_fd()` used `uint64_t` fields on ARM32 where `size_t` is 4 bytes
2. The misaligned struct caused `heap_id_mask` to receive value 0x1000 (bit 12) instead of 0x01
3. Bit 12 maps to a Samsung TrustZone/secure heap that crashes during allocation
4. The crash occurred in ION_IOC_ALLOC, BEFORE any Mali operation ran
5. Mali MEM_IMPORT was called with fd=-1 and returned error safely

### Why Magic Byte Is Irrelevant

Kernel source analysis (`kbase_ioctl()` in `mali_kbase_core_linux.c`):
- Only `_IOC_SIZE(cmd)` is extracted from the ioctl command
- The magic byte (`_IOC_TYPE`) is NEVER checked
- Both `_IOC(3, 'M', 0, 48)` and `_IOC(3, 0x80, 0, 48)` produce size=48
- ALL dispatch goes through `kbase_dispatch()` regardless of magic

### Verified With Correct Code

After fixing `ion_alloc_fd()` to use correct ARM32 struct:
- Test 1 (magic 'M', correct import): **SUCCESS** (result_id=0)
- Test 7 (magic 0x80, correct import): **SUCCESS** (result_id=0) — identical behavior
- Tests 2-6,8-9 (various phandle values): **ERROR** (result_id=3) — safe rejection

### The Real Bug

The ION heap DoS (heap bits 2 and 12 crash kernel) IS a real bug, but:
- It's in the ION driver, not Mali
- It's DoS only (fixed semaphore in TrustZone path)
- The crash address is not controllable
- No code execution possible

---

## ~~Original (Incorrect) Finding Below~~

~~The following analysis was based on the wrong ION struct bug and is kept for reference only.~~

## ~~Summary~~

A kernel panic vulnerability exists in Samsung's vendor extension to the Mali r7p0 GPU driver on the SM-T377A (kernel 3.10.9-11788437, SPL 2017-07-01). An unprivileged user (UID 2000, shell) can trigger a kernel panic by sending a MEM_IMPORT ioctl via the Samsung vendor dispatch path (magic 0x80 instead of standard 'M'/0x4D).

## Impact

- **Severity**: Critical (kernel panic from unprivileged user)
- **Type**: Wild pointer dereference / Use-After-Free in semaphore
- **Trigger**: Single ioctl call, no race condition needed
- **Prerequisites**: Access to `/dev/mali0` (DAC world-RW, SELinux allows shell domain)
- **Reliability**: 100% reproducible (crashed device 5+ times during testing)

## Technical Details

### Root Cause

The Samsung Mali driver registers two ioctl dispatch paths on `/dev/mali0`:
1. **Standard kbase dispatch** via ioctl magic `'M'` (0x4D)
2. **Samsung vendor dispatch** via ioctl magic `0x80`

Both dispatchers handle the same set of function IDs (MEM_ALLOC=512, MEM_IMPORT=513, etc.). However, the vendor dispatch path has a critical difference in how it processes the `phandle` field of the `kbase_uk_mem_import` struct.

In the standard path (magic 'M'), the `phandle` field is treated as a **user pointer** and properly validated via `copy_from_user()`. In the vendor dispatch path (magic 0x80), the field appears to be **dereferenced directly as a kernel pointer** without `copy_from_user()` validation.

### Crash Signature

```
Fatal exception
PC is at _raw_spin_lock_irqsave+0x30/0x6c
LR is at down+0x18/0x54
```

This indicates the kernel followed the `phandle` value as a pointer to a `struct file`, then tried to acquire a semaphore (`down()`) on the file's `f_lock` or similar structure. Since the `phandle` contains a small integer (the dma_buf fd number, e.g., 4 or 5), the kernel reads from near-null memory and hits a corrupted/uninitialized spinlock.

### Affected Ioctl Parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| Device | `/dev/mali0` | Mali-T720 GPU |
| Ioctl magic | 0x80 | Samsung vendor dispatch |
| Func ID | 513 | MEM_IMPORT |
| Struct size | 48 bytes | Standard import struct |
| phandle (offset 8) | Any non-zero value | Treated as kernel pointer |

### What Works vs What Crashes

| Magic | Func | Size | phandle | Result |
|-------|------|------|---------|--------|
| 'M' | 513 | 48 | ptr to fd | result=3 (not supported) |
| 'M' | 513 | 48 | raw fd | result=3 (safe) |
| 0x80 | 513 | 48 | all zeros | result=3 (safe) |
| 0x80 | 513 | 48 | raw fd | **KERNEL PANIC** |
| 0x80 | 513 | 16 | any | errno=14 (too small) |
| 0x80 | most | 16 | zeros | errno=14 or result=0/3 |

### Vendor Dispatch Surface Map (magic 0x80, size=16)

| Func ID | Ioctl Result | Mali Result | Function |
|---------|-------------|-------------|----------|
| 0 | 0 | 0 | VERSION_CHECK (succeeds) |
| 516 | 0 | 3 | MEM_FREE (fails, invalid VA) |
| 521 | 0 | 0 | POST_TERM (succeeds) |
| 541 | 0 | 0 | DISJOINT_QUERY (succeeds) |
| 550 | 0 | 0 | Unknown Samsung function |
| Others | -1 (EFAULT) | N/A | Buffer too small |

## Exploitation Potential

### DoS (Confirmed)
- One-shot kernel panic from unprivileged shell
- Requires only `/dev/mali0` access (granted to shell domain)
- No interaction or prerequisites needed

### Privilege Escalation (Theoretical)
The wild pointer dereference could potentially be controlled:
1. **mmap address control**: If the attacker can mmap a page at a controlled low address (mmap_min_addr=32768 on this device), they could place a fake `struct file` with a controlled semaphore spinlock
2. **Heap spray**: If the phandle is used after `copy_from_user` validates it, a TOCTOU race could redirect it to attacker-controlled kernel memory
3. **Kernel info leak**: Accessing partially-initialized memory near the pointer address could leak kernel data through the ioctl response buffer

### Mitigations on This Device
- `mmap_min_addr` = 32768 (prevents mapping below 0x8000)
- SELinux enforcing (limits some primitives)
- NO KASLR, NO PXN, NO stack canaries — exploit development simplified

## Reproduction

### Minimal Crash PoC

```c
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/ioctl.h>

int main(void) {
    int fd = open("/dev/mali0", O_RDWR);
    
    /* Handshake (standard magic) */
    uint8_t hb[16] = {0};
    *(uint32_t*)hb = 0; hb[8] = 10;
    ioctl(fd, _IOC(3, 'M', 0, 16), hb);
    memset(hb, 0, 16);
    *(uint32_t*)hb = 530;
    ioctl(fd, _IOC(3, 'M', 0, 16), hb);
    
    /* Trigger: vendor dispatch MEM_IMPORT */
    uint8_t buf[48] = {0};
    *(uint32_t*)buf = 513;          /* MEM_IMPORT */
    *(uint64_t*)(buf+8) = 0x1234;   /* phandle = wild pointer */
    *(uint32_t*)(buf+16) = 2;       /* type = UMM */
    ioctl(fd, _IOC(3, 0x80, 0, 48), buf);  /* KERNEL PANIC */
    
    return 0;  /* never reached */
}
```

## Files

- `src/mali_vendor_crash.c` — Systematic analysis tool (5 tests)
- `src/mali_import_safe.c` — Step-by-step isolation (7 tests)
- `src/mali_import_v2.c` — Correct ARM32 import (control test)
- `src/mali_race_exploit.c` — Original race fuzzer that discovered the crash
- `src/mali_import_crash.c` — Crash reproducer with iteration tracking
- `src/mali_import_min.c` — Minimal reproducer

## Timeline

1. mali_race_exploit.c Test 7 → first kernel panic (during ION+Mali import race)
2. mali_import_crash.c → second panic (suspected ION struct misalignment)
3. mali_import_min.c → third panic (isolated to single import)
4. mali_import_safe.c → fourth panic (confirmed new ION API as trigger)
5. Root cause identified: wrong ioctl magic (0x80) in mali_fuzz_multithreaded.c
   was inherited by mali_race_exploit.c, causing vendor dispatch path
6. mali_vendor_crash.c → confirmed vendor dispatch processes standard kbase
   functions without proper user pointer validation
7. mali_import_v2.c → confirmed correct magic 'M' path is safe
