# Kernel Source Audit: Binder, Mali, Ashmem, USB Gadget Drivers
## Samsung Exynos 3475 — Kernel 3.10.9/3.10.108
## Date: 2025-07-18

---

## Executive Summary

Source audit of four kernel driver subsystems in the Samsung GPL release
(`github.com/Exynos3475/android_kernel_samsung_exynos3475`, branch `clean_base`).

**Verdict**: Two findings rated **MEDIUM** exploitability from ADB shell, one **LOW-MEDIUM**, 
and several informational issues. No single finding is a clean one-shot root, but the 
binder `proc->files` race (Finding #1) is the most promising avenue for further research.

---

## Finding #1: Binder — proc->files TOCTOU Race in File Descriptor Operations (MEDIUM)

### Location
`drivers/staging/android/binder.c` — `task_get_unused_fd_flags()`, `task_fd_install()`, `task_close_fd()`

### Description
The binder driver stores `proc->files` (a reference to the files_struct) during `binder_mmap()` 
and uses it later during transaction processing to install file descriptors into the target 
process's file table. The `proc->files` pointer is set to NULL asynchronously via 
`binder_vma_close()` → `binder_defer_work(BINDER_DEFERRED_PUT_FILES)` → deferred worker.

The critical race window:

1. `binder_mmap()` sets `proc->files = get_files_struct(current)` (with binder_mmap_lock)
2. `binder_vma_close()` sets `proc->vma = NULL` and defers `PUT_FILES`
3. The deferred worker (running on `binder_deferred_workqueue`) acquires `binder_main_lock`, 
   grabs `proc->files`, sets it to NULL, then releases lock and calls `put_files_struct()`
4. Meanwhile, `task_get_unused_fd_flags()` reads `proc->files` **without holding 
   binder_main_lock** — it's called from `binder_transaction()` which holds the lock, 
   BUT `task_fd_install()` does:
   ```c
   if (proc->files) {
       preempt_enable_no_resched();
       __fd_install(proc->files, fd, file);  // proc->files could be freed here
       preempt_disable();
   }
   ```
   The check-then-use of `proc->files` is not atomic. Between checking `proc->files` and 
   calling `__fd_install()`, the deferred worker could set `proc->files = NULL` and call 
   `put_files_struct()`, freeing the underlying structure.

### Exploitability Assessment
- **Triggerable from UID 2000**: YES — open /dev/binder, mmap, then munmap while a 
  transaction with file descriptors is in flight from another thread
- **Race window**: The window between `proc->files` check and `__fd_install()` is very small 
  (a few instructions), but preemption is enabled during this window (`preempt_enable_no_resched()`)
- **Impact**: Use-after-free on files_struct → could corrupt file table → potential fd hijack
- **Difficulty**: HIGH — requires winning a tight race; panic_on_oops=1 means any oops = device reboot
- **Samsung-specific**: The `preempt_enable/disable` wrappers around copy operations 
  (`copy_to_user_preempt_disabled`, etc.) create additional preemption windows that may 
  widen the race

### Recommendation
Research a multi-threaded PoC: Thread A sends a transaction containing a BINDER_TYPE_FD to 
the target proc. Thread B rapidly munmaps the binder buffer in the target proc. Use fork() 
for safety. This is conceptually similar to CVE-2019-2215 but targeting files_struct rather 
than wait_queue_entry.

---

## Finding #2: Binder — BC_INCREFS_DONE / BC_ACQUIRE_DONE Reference Confusion (LOW)

### Location
`drivers/staging/android/binder.c` — `binder_thread_write()`, BC_INCREFS_DONE/BC_ACQUIRE_DONE handler

### Description
The handler for BC_INCREFS_DONE and BC_ACQUIRE_DONE:
```c
node = binder_get_node(proc, node_ptr);
if (node == NULL) { break; }  // user_error, but no return
if (cookie != node->cookie) { break; }
if (cmd == BC_ACQUIRE_DONE) {
    if (node->pending_strong_ref == 0) { break; }  // user_error
    node->pending_strong_ref = 0;
} else {
    if (node->pending_weak_ref == 0) { break; }
    node->pending_weak_ref = 0;
}
binder_dec_node(node, cmd == BC_ACQUIRE_DONE, 0);
```

The `pending_strong_ref` and `pending_weak_ref` fields are simple integers (not atomics) 
protected only by `binder_main_lock`. If a node transitions through 
BR_INCREFS → BC_INCREFS_DONE → BR_ACQUIRE → BC_ACQUIRE_DONE rapidly, and the server process 
has multiple binder threads, there's a theoretical issue where `pending_*_ref` could be 
decremented below zero (wrapping to 0xFFFFFFFF) if the node is concurrently being destroyed.

However, `binder_main_lock` serializes all operations, making this race infeasible in practice.

### Exploitability Assessment
- **Triggerable**: Theoretically yes, but lock serialization prevents the race
- **Impact**: If refs underflow → node freed while still referenced → UAF on binder_node
- **Difficulty**: INFEASIBLE with current locking (single global mutex)

---

## Finding #3: Binder — binder_mmap / binder_ioctl Buffer Allocation Race (LOW-MEDIUM)

### Location
`drivers/staging/android/binder.c` — `binder_mmap()` and `binder_alloc_buf()`

### Description
In `binder_mmap()`, after `mutex_unlock(&binder_mmap_lock)`, the function continues to 
set up `proc->pages`, `proc->buffer_size`, and eventually `proc->vma`. Between the 
`mutex_unlock(&binder_mmap_lock)` and `proc->vma = vma`, there's a window where 
`proc->buffer` is set but `proc->vma` is NULL.

If `binder_alloc_buf()` is called (via `binder_transaction()` from another thread) during 
this window:
```c
if (proc->vma == NULL) {
    pr_err("binder_alloc_buf, no vma\n");
    return NULL;
}
```
This is handled safely — alloc returns NULL, transaction fails.

However, `binder_update_page_range()` (called from binder_alloc_buf) does:
```c
mm = get_task_mm(proc->tsk);
down_write(&mm->mmap_sem);
vma = proc->vma;
if (vma && mm != proc->vma_vm_mm) { vma = NULL; }
```
If `proc->vma` is set but `proc->vma_vm_mm` hasn't been set yet (they're set in sequence, 
not atomically), the mismatch check could trigger, but this is a benign path (just logs error, 
doesn't allocate).

### Exploitability Assessment
- **Triggerable from UID 2000**: Yes in theory, requires fork() + mmap racing with ioctl
- **Impact**: No memory corruption found; just allocation failures
- **Verdict**: Not directly exploitable, but the non-atomic initialization of related fields 
  is a code smell worth noting

---

## Finding #4: Mali T72x — Alias Region TOCTOU on alloc->nents (MEDIUM)

### Location
`drivers/gpu/arm/t72x/r5p0/mali_kbase_mem_linux.c` — `kbase_mem_alias()`

### Description
When creating an alias, the driver validates:
```c
if (ai[i].offset > alloc->nents) goto bad_handle;
if (ai[i].offset + ai[i].length > alloc->nents) goto bad_handle;
```

This validates against `alloc->nents` (the current backing page count). However, the 
aliased region is `KBASE_MEM_TYPE_NATIVE` with `GROWABLE` flag. The original region can be 
**shrunk** after the alias is created (via `KBASE_FUNC_SET_FLAGS` or memory pressure), 
reducing `alloc->nents` below the aliased offset+length.

When the alias is later mapped (`kbase_gpu_mmap`), it reads:
```c
reg->alloc->imported.alias.aliased[i].alloc->pages + 
    reg->alloc->imported.alias.aliased[i].offset
```
If the original allocation was shrunk, `alloc->pages[offset]` could reference freed pages 
or read beyond the valid page array.

The alias takes a reference (`kbase_mem_phy_alloc_get`) which prevents the alloc struct 
itself from being freed, but **doesn't prevent the backing pages from being freed** by 
`kbase_free_phy_pages_helper()` when the original region shrinks.

### Exploitability Assessment
- **Triggerable from UID 2000**: YES — Mali device is accessible (`/dev/mali0`). 
  Create native region, alias it, then shrink the original via `KBASE_FUNC_SET_FLAGS` 
  or trigger shrink through memory reclaim
- **Impact**: Stale page references → GPU could access freed physical pages. If those pages 
  are reallocated for kernel data structures, GPU can read/write them (no SMMU on this SoC)
- **Difficulty**: MEDIUM — need to:
  1. Open Mali, create growable native region
  2. Create alias pointing at end of region
  3. Shrink original region (reduce backed size)
  4. GPU-map the alias → accesses stale pages
  5. Wait for those physical pages to be reused
- **SELinux**: `shell` domain can open `/dev/mali0` (confirmed from prior recon)
- **Caveat**: The 30K-op fuzzer didn't trigger this because it requires specific 
  alias→shrink→map sequencing, not random ops

---

## Finding #5: Mali T72x — Samsung `MALI_SEC_INTEGRATION` Modified Flag Validation (LOW-MEDIUM)

### Location
`drivers/gpu/arm/t72x/r5p0/mali_kbase_mem.c` — `kbase_check_alloc_flags()`

### Description
Samsung modified the flag validation:
```c
#ifdef MALI_SEC_INTEGRATION
    /* meminfo patch needs additional input bits */
    if (flags & ~((1ul << BASE_MEM_FLAGS_NR_INPUT_BITS) - 1))
        return MALI_FALSE;
#endif
```
The standard ARM Mali driver checks against `BASE_MEM_FLAGS_NR_BITS`, but Samsung uses 
`BASE_MEM_FLAGS_NR_INPUT_BITS` which allows **additional input flag bits** that wouldn't 
pass the upstream check. This widens the attack surface — Samsung-specific flags like 
`BASE_MEM_SAME_VA`, `BASE_MEM_CUSTOM_PMEM`, `BASE_MEM_CUSTOM_TMEM` may trigger 
Samsung-specific code paths in memory allocation.

Additionally, `kbase_free_phy_pages_helper_gpu()` and `kbase_alloc_phy_pages_helper_gpu()` 
are Samsung-added wrappers (marked with `/* MALI_SEC_INTEGRATION */`) that may have 
different semantics from the upstream functions.

### Exploitability Assessment
- **Research needed**: Audit the Samsung-specific flag handling paths to see if any 
  combination of Samsung-extended flags causes unexpected behavior
- **Triggerable**: Yes, via Mali ioctl
- **Impact**: Unknown — depends on what the Samsung-specific flags actually do

---

## Finding #6: Ashmem — Race Between set_prot_mask and mmap (LOW)

### Location
`drivers/staging/android/ashmem.c` — `set_prot_mask()` and `ashmem_mmap()`

### Description
Both `set_prot_mask()` and `ashmem_mmap()` are protected by `ashmem_mutex`. The mmap function 
checks:
```c
if (unlikely((vma->vm_flags & ~calc_vm_prot_bits(asma->prot_mask)) &
    calc_vm_prot_bits(PROT_MASK))) {
    ret = -EPERM;
}
vma->vm_flags &= ~calc_vm_may_flags(~asma->prot_mask);
```

And `set_prot_mask` validates:
```c
if (unlikely((asma->prot_mask & prot) != prot)) {
    ret = -EINVAL;  // can only remove, not add bits
}
asma->prot_mask = prot;
```

Both are under the same mutex, so there's no race between them. The pin/unpin operations 
are similarly serialized. After 100K+ fuzzing ops with clean results, and with proper 
mutex serialization in the source, **ashmem is confirmed clean** for race conditions.

### Exploitability Assessment
- **NOT exploitable** — proper locking throughout
- **The deadlock comment** (mmap_sem vs ashmem_mutex) in `set_name` is interesting but 
  Samsung already fixed this by doing strncpy_from_user outside the lock

---

## Finding #7: USB Gadget — conn_gadget Missing access_ok() Check (LOW)

### Location
`drivers/usb/gadget/f_conn_gadget.c` — `conn_gadget_ioctl()`, `conn_gadget_bind_status_copy_to_user()`

### Description
The `conn_gadget_ioctl()` function:
1. **No `access_ok()` check** before `copy_to_user()` calls. While `copy_to_user()` itself 
   does `access_ok()` internally on modern kernels, the absence of an explicit check in the 
   ioctl handler is a code quality issue.
2. **The `CONN_GADGET_IOCTL_SUPPORT_LIST` handler** copies the entire `IOCTL_ARRAY` 
   (`sizeof(int) * (CONN_GADGET_IOCTL_MAX_NR+1)` = 16 bytes) regardless of the `size` 
   parameter extracted from the ioctl cmd. This is a fixed-size copy so not exploitable, 
   but shows sloppy coding.
3. **The developer's own comment**: `"I think, memorized and online variable should be 
   atomic variable. talk to choi"` — `dev->memorized` and `dev->online` are accessed 
   without locks in the ioctl wait condition and from USB callbacks. This is a data race, 
   but only causes missed wakeups, not corruption.

### Exploitability Assessment
- **Device node**: `/dev/android_ssusbconn` — need to verify if shell can open it
- **Impact**: No memory corruption; at worst, information leak of 16 bytes of known constants
- **NOT useful for privilege escalation**

---

## Finding #8: USB Gadget — f_dm.c Serial Port (INFORMATIONAL)

### Location
`drivers/usb/gadget/f_dm.c`

### Description
Samsung DM (Diagnostic Monitor) function is bound to `/dev/ttyGS1`. This is Samsung's 
diagnostic port accessible via USB composite device (DM mode). The implementation is a thin 
wrapper around `gserial` — it inherits all serial gadget operations without adding custom 
ioctls or data handling.

### Exploitability Assessment
- **Not directly exploitable from ADB shell** — requires USB host-side interaction
- **However**: If we can write to `/dev/ttyGS1` from ADB, we could inject diagnostic commands 
  that the USB host interprets. This is more relevant for the DM/AT command injection vector 
  (already documented in STATUS.md).

---

## No Samsung-Specific Binder Modifications Found

Searched for "SAMSUNG", "SEC_", "samsung", "sec_" in binder.c — **zero matches**. 
The Samsung binder is essentially stock Android binder for kernel 3.10 with Samsung's 
preempt_disable wrappers. The epoll whead fix mentioned in the task description is confirmed 
present (not re-audited as known).

---

## Prioritized Recommendations

### Top Priority: Finding #4 — Mali Alias TOCTOU
- Write a PoC that creates native region, aliases it, shrinks original, then GPU-maps alias
- This doesn't need kernel code execution — just Mali ioctl sequence
- Test in QEMU first (no Mali, but can verify the ioctl interface)
- **Risk**: Low — worst case is a GPU fault, not a kernel panic

### Second Priority: Finding #1 — Binder files_struct Race
- More complex to exploit but more impactful
- Requires fork-in-child approach (panic_on_oops safety)
- Multi-threaded: one thread doing transactions with FDs, another doing munmap
- **Risk**: MEDIUM — could trigger kernel oops → panic → reboot

### Third Priority: Finding #5 — Samsung Mali Flag Investigation
- Enumerate what Samsung-specific flags exist
- Test each flag combination through Mali ioctl
- Safe to test (flag validation happens before any dangerous operations)

---

## Files Audited

| File | Lines (approx) | Samsung Mods | Findings |
|------|--------|--------------|----------|
| `drivers/staging/android/binder.c` | ~3700 | preempt wrappers only | #1, #2, #3 |
| `drivers/staging/android/ashmem.c` | ~800 | None | #6 (clean) |
| `drivers/gpu/arm/t72x/r5p0/mali_kbase_mem.c` | ~800 | MALI_SEC_INTEGRATION | #5 |
| `drivers/gpu/arm/t72x/r5p0/mali_kbase_mem_linux.c` | ~1500 | Minimal | #4 |
| `drivers/gpu/arm/t72x/r5p0/mali_kbase_core_linux.c` | ~3000 | Minimal | — |
| `drivers/gpu/arm/t72x/r5p0/mali_kbase_mmu.c` | ~1500 | — | — |
| `drivers/usb/gadget/android.c` | ~2500 | CONFIG_USB_ANDROID_SAMSUNG_COMPOSITE | #8 |
| `drivers/usb/gadget/f_conn_gadget.c` | ~1000 | All Samsung | #7 |
| `drivers/usb/gadget/f_dm.c` | ~300 | Samsung | #8 |
