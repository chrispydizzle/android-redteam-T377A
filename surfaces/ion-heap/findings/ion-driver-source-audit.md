# ION Driver Source Code Audit — Exynos 3475

**Date**: 2026-07-11
**Target**: Samsung SM-T377A, Android 6.0.1, Kernel 3.10.9
**Source**: `github.com/Exynos3475/android_kernel_samsung_exynos3475` branch `clean_base`
**Context**: Existing 91% reliable ION UAF in kmalloc-64, seeking exploitation paths + new vulns

---

## Executive Summary

Audited 9 ION driver source files (~4500 lines). Found **7 distinct findings**, including one
new vulnerability (import race → infinite kernel loop), confirmation that the custom ioctl
path is dead, and critical exploitation analysis for the existing kmalloc-64 UAF. The
fundamental blocker for the ION UAF remains the IDR-based handle validation, but two new
exploitation strategies are identified below.

---

## FINDING 1: ION_IOC_CUSTOM Is Dead (No Samsung Custom Ioctl)

**Files**: `exynos/exynos_ion_v2.c` Makefile, `ion.c` ion_ioctl()
**Severity**: Informational (eliminates an attack surface)

The Exynos 3475 builds `exynos_ion_v2.c` (the old `exynos_ion.c` with its `exynos_ion_ioctl`
handler is commented out in the Makefile: `#obj-y += exynos_ion.o`).

The v2 probe creates the ION device with:
```c
ion_exynos = ion_device_create(NULL);  // NULL = no custom ioctl
```

In `ion_ioctl()`, the `ION_IOC_CUSTOM` case checks:
```c
if (!dev->custom_ioctl)
    return -ENOTTY;
```

**Conclusion**: `ION_IOC_CUSTOM` returns `-ENOTTY`. The Samsung-specific `ION_IOC_EXYNOS_SYNC`
command (which existed in the old exynos_ion.c with a user-controlled `addr`+`size` sync
that called `__dma_map_area` on arbitrary userspace addresses) is **unreachable**. Do not
pursue this path.

---

## FINDING 2: `user_ion_free_nolock` Operator Precedence Bug

**File**: `ion.c`, `user_ion_free_nolock()`
**Severity**: Low (cosmetic, accidentally correct)

```c
static void user_ion_free_nolock(struct ion_client *client, struct ion_handle *handle)
{
    ...
    if (!handle->user_ref_count > 0) {   // BUG: parsed as (!x) > 0
        WARN(1, "%s: User does not have access!\n", __func__);
        return;
    }
    user_ion_handle_put_nolock(handle);
}
```

Due to C operator precedence, `!handle->user_ref_count > 0` parses as
`(!handle->user_ref_count) > 0`, which equals `(handle->user_ref_count == 0)`.
The intended check was `!(handle->user_ref_count > 0)` which for `unsigned int`
is equivalent to `user_ref_count == 0`. So the bug **accidentally produces correct
behavior**.

**Exploitability**: None. The check works as intended despite the precedence error.
However, this confirms the codebase has sloppy review — look for similar patterns.

---

## FINDING 3: `user_ion_handle_put_nolock` Uninitialized Return Value

**File**: `ion.c`, `user_ion_handle_put_nolock()`
**Severity**: Low (info leak or undefined behavior)

```c
static int user_ion_handle_put_nolock(struct ion_handle *handle)
{
    int ret;
    if (--handle->user_ref_count == 0) {
        ret = ion_handle_put_nolock(handle);
    }
    return ret;  // BUG: ret uninitialized if user_ref_count != 0 after decrement
}
```

If `user_ref_count` was > 1 before decrement (not reaching 0), `ret` is never assigned.
The function returns stack garbage. Currently the return value is not checked by any
caller in the ION_IOC_FREE path, so this is not exploitable. But it indicates the code
was not carefully reviewed.

---

## FINDING 4: `ion_import_dma_buf` TOCTOU Race → Infinite Kernel Loop (NEW VULN)

**File**: `ion.c`, `ion_import_dma_buf()`
**Severity**: HIGH (DoS — infinite loop with mutex held)
**Trigger**: Two threads import the same dma_buf fd simultaneously

```c
struct ion_handle *ion_import_dma_buf(struct ion_client *client, int fd)
{
    ...
    mutex_lock(&client->lock);
    handle = ion_handle_lookup(client, buffer);
    if (!IS_ERR(handle)) {
        handle = ion_handle_get_check_overflow(handle);
        mutex_unlock(&client->lock);
        goto end;                              // existing handle found
    }
    mutex_unlock(&client->lock);               // *** UNLOCK ***

    handle = ion_handle_create(client, buffer); // creates handle outside lock

    mutex_lock(&client->lock);                  // *** RE-LOCK ***
    ret = ion_handle_add(client, handle);       // adds to rb tree
    mutex_unlock(&client->lock);
    ...
}
```

**Race window**: Between the first `mutex_unlock` and the `mutex_lock` before `ion_handle_add`,
another thread can also fail the lookup, create a handle, and add it first. When the second
thread adds its handle, `ion_handle_add` encounters a duplicate buffer in the rb tree:

```c
// In ion_handle_add:
if (handle->buffer < entry->buffer)
    p = &(*p)->rb_left;
else if (handle->buffer > entry->buffer)
    p = &(*p)->rb_right;
else
    WARN(1, "%s: buffer already found.", __func__);  // p NOT updated!
```

When `buffer == entry->buffer`, the WARN fires but `p` is **not modified**. The while loop
re-evaluates `*p` (still non-NULL), enters the body again, finds the same duplicate, WARNs
again — **infinite loop**. The client mutex is held, making the client permanently stuck.

**Impact**: Denial of service. With `panic_on_oops=1`, the soft lockup detector will
eventually trigger a panic. **DO NOT trigger this on the physical device.**

**Safe testing**: Can be validated in the QEMU lab kernel (3.10.108 has similar ION code).

**Exploitation potential**: Pure DoS. The infinite loop doesn't corrupt memory. However, if
there's a code path where the WARN is skipped (e.g., a different kernel config), the duplicate
handle would corrupt the rb tree, potentially leading to UAF on the buffer via double-put.

---

## FINDING 5: `ion_phys` Unlocked Callback Invocation

**File**: `ion.c`, `ion_phys()`
**Severity**: Low (kernel-only API, not reachable from ioctl)

```c
int ion_phys(struct ion_client *client, struct ion_handle *handle,
             ion_phys_addr_t *addr, size_t *len)
{
    mutex_lock(&client->lock);
    if (!ion_handle_validate(client, handle)) { ... }
    buffer = handle->buffer;
    mutex_lock(&buffer->lock);
    ion_buffer_make_ready(buffer);
    mutex_unlock(&buffer->lock);
    mutex_unlock(&client->lock);
    // Both locks released before callback:
    ret = buffer->heap->ops->phys(buffer->heap, buffer, addr, len);
    return ret;
}
```

The `phys` callback runs after both locks are released. If the buffer is freed between
unlock and the callback, this is UAF. However, `ion_phys` is not exposed via any ioctl —
it's an in-kernel API only used by DMA framework consumers.

**Exploitability from ADB**: None directly. Would require a kernel driver to call
`ion_phys` on a buffer we control, which isn't reachable from userspace.

---

## FINDING 6: `ion_unmap_kernel` Missing Handle Validation

**File**: `ion.c`, `ion_unmap_kernel()`
**Severity**: Low (kernel-only API)

```c
void ion_unmap_kernel(struct ion_client *client, struct ion_handle *handle)
{
    struct ion_buffer *buffer;
    mutex_lock(&client->lock);
    buffer = handle->buffer;      // NO validation before this access!
    mutex_lock(&buffer->lock);
    ion_handle_kmap_put(handle);
    mutex_unlock(&buffer->lock);
    mutex_unlock(&client->lock);
}
```

Compare with `ion_map_kernel` which validates the handle before accessing `handle->buffer`.
The unmap path skips validation entirely. If an invalid/freed handle is passed, this reads
from freed memory.

**Exploitability from ADB**: None. `ion_unmap_kernel` is in-kernel only. But this indicates
that kernel drivers using ION (Mali, camera, MFC) might pass invalid handles here.

---

## FINDING 7: ION mmap Integer Overflow in Bounds Check

**File**: `ion.c`, `ion_mmap()`
**Severity**: Low (theoretical, constrained by VMA subsystem)

```c
if ((((vma->vm_pgoff << PAGE_SHIFT) >= buffer->size)) ||
    ((vma->vm_end - vma->vm_start) >
         (buffer->size - (vma->vm_pgoff << PAGE_SHIFT)))) {
```

If `vma->vm_pgoff << PAGE_SHIFT` overflows on 32-bit (requires pgoff > 0xFFFFF), the
first comparison passes if the wrapped value < buffer->size. The subtraction
`buffer->size - wrapped_value` then produces a large value, potentially passing the
second check and allowing mapping beyond buffer boundaries.

**Exploitability**: The kernel VMA subsystem constrains `vm_pgoff` during `do_mmap`,
making overflow impractical. **Not exploitable in practice** on this kernel.

---

## EXPLOITATION ANALYSIS: Existing kmalloc-64 ION UAF

### Why the ION Handle UAF Is Blocked (Confirmation)

The `ion_handle_get_by_id()` → `ion_share_dma_buf()` path has a **drop-and-reacquire
lock gap** between getting the handle pointer and using it:

1. `ion_handle_get_by_id`: locks client, idr_find, **kref_get (atomic_inc at offset 0)**, unlocks
2. `ion_share_dma_buf`: locks client, **`ion_handle_validate` (idr_find check)**, accesses handle->buffer

After the handle is freed (destroyed in ION_IOC_FREE), it's **removed from the IDR** in
`ion_handle_destroy`. Any subsequent `idr_find` returns NULL, so `ion_handle_validate`
fails. The stale reference **cannot pass validation**.

The ONLY write to the reclaimed slot is `atomic_inc` at offset 0 from step 1. This happens
BEFORE validation, so it always executes. But incrementing offset 0 by 1 provides an
extremely limited corruption primitive.

### Strategy A: `atomic_inc` at Offset 0 of pipe_buffer[2] (NEW)

**pipe_buffer[2]** is confirmed in kmalloc-64 (STATUS.md). Each `pipe_buffer` is 28 bytes:
```
offset  0: struct page *page           (4 bytes)
offset  4: unsigned int offset         (4 bytes)
offset  8: unsigned int len            (4 bytes)
offset 12: const struct pipe_buf_operations *ops  (4 bytes) ← FUNCTION POINTERS
offset 16: unsigned int flags          (4 bytes)
offset 20: unsigned long private       (4 bytes)
```

If the freed ion_handle slot is reclaimed by a pipe_buffer[2] array, the `atomic_inc`
corrupts `pipe_buffer[0].page` (offset 0). This increments the raw page pointer value by 1.

**Problem**: Incrementing a `struct page *` by 1 (raw integer +1) produces a misaligned
page pointer. On ARM32, subsequent page dereference causes a data abort → kernel panic.
**Not safe with panic_on_oops=1.**

**Potential mitigation**: If the page pointer's lowest bit is 0 and the struct page array
is densely packed, adding 1 might still point within a valid page struct... but the
offset would be wrong. This requires extremely precise heap layout knowledge.

### Strategy B: Reclaim with add_key for Info Leak (LIMITED - 198 MAX)

`add_key("user", ...)` is allowed up to 198 times before SELinux blocks. Each creates a
`user_key_payload` in kmalloc-64:
```
offset  0: struct rcu_head (8 bytes: next + func pointers)
offset  8: unsigned short datalen (2 bytes)
offset 10: char data[] (controlled, up to ~52 bytes)
```

The `atomic_inc` at offset 0 increments `rcu_head.next` by 1. When the key is later freed
via RCU, the corrupted `next` pointer causes a traversal error — potentially exploitable
as a controlled write-what-where if we can predict the RCU list layout.

**Assessment**: Speculative. Requires deep understanding of RCU callback scheduling on
this kernel version. Worth investigating in QEMU.

### Strategy C: Target pipe_buffer[2].ops via DIFFERENT Write Primitive (RECOMMENDED)

Instead of using the ION UAF's limited atomic_inc, find a **different vulnerability** that
provides a stronger write primitive to kmalloc-64. Then corrupt `pipe_buffer[0].ops`
(offset 12) to point to a fake `pipe_buf_operations` in userspace (possible: no PXN/PAN).

The fake ops table would contain:
```c
struct pipe_buf_operations fake_ops = {
    .confirm = shellcode_addr,  // called during pipe_read → ops->confirm()
    ...
};
```

The shellcode performs ret2usr:
```c
void shellcode(void) {
    commit_creds(prepare_kernel_cred(0));  // 0xC0054328(0xC00548E0(0))
}
```

**Candidate write primitives for kmalloc-64**:
1. **timerfd CANCEL_ON_SET (CVE-2017-10661)**: STATUS.md confirms this works. If this
   CVE provides a write primitive (not just DoS), it could write to reclaimed pipe_buffer.
2. **setxattr on tmpfs**: Allocates controlled data in kmalloc caches. If SELinux allows
   `setxattr` on `/data/local/tmp`, this provides temporary controlled data in kmalloc-64
   (33-64 byte values). Verify with: `setfattr -n user.test -v "AAAA..." /data/local/tmp/testfile`
3. **BPF filter (SO_ATTACH_FILTER)**: `setsockopt(SO_ATTACH_FILTER)` allocates
   `struct sock_fprog_kern` + instruction array. For small filters, the instruction array
   can land in kmalloc-64 with semi-controlled content (BPF instructions).

### Strategy D: Cross-Cache — Promote UAF to kmalloc-192 (CREATIVE)

The ION import race (Finding 4) can create duplicate handles for the same buffer.
Although it currently causes an infinite loop, if a variant exists where the duplicate
is silently added (e.g., via tree corruption or a different code path), the buffer
would have its refcount decremented twice when both handles are freed.

`struct ion_buffer` is ~160-180 bytes → **kmalloc-192**. STATUS.md shows kmalloc-192
contains **binder_thread** (the CVE-2019-2215 target). A buffer double-free in kmalloc-192
could be reclaimed by binder_thread structures with controlled function-related fields.

**This is speculative** and requires the import race to not infinite-loop. Test in QEMU
first by patching out the WARN to see if a clean double-add is achievable.

---

## Recommended Next Steps (Priority Order)

1. **Verify setxattr availability from shell** — `setfattr -n user.x -v "$(python -c 'print "A"*48')"`
   on a file in /data/local/tmp. If it works, this is the easiest controlled kmalloc-64 spray.

2. **Audit CVE-2017-10661 (timerfd) for write primitive** — STATUS.md says timerfd
   CANCEL_ON_SET works. Research whether this CVE provides memory corruption beyond DoS.
   If it corrupts a kmalloc-64 object, combine with pipe_buffer[2] spray for code exec.

3. **Test pipe_buffer[2] creation in QEMU** — Create pipe, `fcntl(fd, F_SETPIPE_SZ, 8192)`,
   verify allocation lands in kmalloc-64 via /proc/slabinfo monitoring.

4. **Test import race in QEMU** — Two threads calling ION_IOC_IMPORT with the same fd.
   Verify infinite loop behavior. Patch WARN to a break to see if double-handle/double-free
   on the buffer is achievable.

5. **Investigate BPF filter spray** — `setsockopt(SO_ATTACH_FILTER)` with a ~4-instruction
   filter (32 bytes instruction data + 8 byte header = 40 bytes → kmalloc-64). BPF
   instructions provide semi-controlled content that could be crafted to look like a
   valid pipe_buf_operations pointer.

6. **Do NOT test the import race on the physical device** — infinite loop with mutex held
   will trigger soft lockup → potential panic.

---

## Structure Sizes (ARM32, confirmed)

| Structure | Size (bytes) | Slab Cache | Notes |
|-----------|-------------|------------|-------|
| `ion_handle` | 36 | kmalloc-64 | kref + client + buffer + rb_node + kmap_cnt + id |
| `ion_buffer` | ~160-180 | kmalloc-192 | Large struct with mutex, lists, task_comm |
| `pipe_buffer[2]` | 56 | kmalloc-64 | **HAS ops function pointer at offset 12** |
| `user_key_payload` | 10 + data | kmalloc-64 (for ≤54B data) | rcu_head + datalen + data |
| `msg_msg` | 24 + data | kmalloc-64 (for ≤40B data) | **SELinux BLOCKED** |
| `ion_handle.buffer` | offset 12 | — | Overlaps with pipe_buffer[0].ops at offset 12 |

---

## Files Audited

| File | Lines | Key Findings |
|------|-------|-------------|
| `ion.c` | 2753 | Findings 2, 3, 4, 5, 6, 7; all ioctl handlers |
| `ion_priv.h` | ~450 | Structure definitions, heap_ops with function pointers |
| `ion.h` | ~180 | Public API (kernel-only) |
| `exynos/exynos_ion_v2.c` | ~600 | Finding 1 (NULL custom_ioctl); heap setup |
| `exynos/exynos_ion.c` | ~700 | Old code (NOT compiled); had ION_IOC_EXYNOS_SYNC |
| `ion_system_heap.c` | ~500 | System heap ops, page pool, preload (no vulns found) |
| `ion_cma_heap.c` | ~250 | CMA heap (requires ION_FLAG_PROTECTED for interesting paths) |
| `ion_carveout_heap.c` | ~250 | Carveout heap (gen_pool, no vulns found) |
| `compat_ion.c` | ~200 | 32-bit compat (clean translation, no vulns found) |
| `uapi/ion.h` | ~180 | UAPI definitions |
| `include/linux/exynos_ion.h` | ~200 | Samsung ION extensions, custom ioctl definitions |
