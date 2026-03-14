# Why Heap Spray is Required for Code Execution

## The Challenge: Stale Data vs. Controlled Data
When `ION_IOC_FREE` frees the `ion_handle`, the kernel marks that memory slot in the `kmalloc-64` slab as "free".
However, the **data** inside that slot is not zeroed out immediately. It remains there until another object is allocated in that same slot.

### Scenario A: No Heap Spray (Current State)
1. `free(handle)` happens.
2. We call `mmap(fd)`.
3. The kernel reads `handle->buffer`.
4. Since we haven't overwritten the slot, `handle->buffer` still points to the **original, valid buffer**.
5. `mmap` succeeds!
   - **Proof of UAF**: We are using a freed object.
   - **No Code Execution**: We are just using the old valid object.

### Scenario B: Heap Spray (Exploit)
To execute code, we must force the kernel to use **our** fake object instead of the stale data.
1. `free(handle)` happens.
2. We immediately allocate 1000s of new objects of size 64 bytes (using `sendmsg` or `setxattr`).
3. One of our new objects lands in the **exact same slot** as the freed handle.
4. We write our fake data: `handle->buffer = 0xDEADBEEF`.
5. We call `mmap(fd)`.
6. The kernel reads `handle->buffer` and gets `0xDEADBEEF`.
7. It jumps to `0xDEADBEEF->ops->mmap`.
8. **CRASH** (or Execution if `0xDEADBEEF` is valid user memory).

## Why We Can't Easily Do It "Just a Bit"
Heap grooming is precise.
- We need to know **exactly** which slab cache `ion_handle` lives in (verified: `kmalloc-64`).
- We need a primitive to allocate objects of that **exact size** with **controlled content**.
- Common primitives:
  - `sendmsg` (control size via `msg_control`, content via `cmsg`)
  - `setxattr` (control size via value length, content via value)
  - `keyctl` (add key)

## Proof of Concept Strategy
If we implement a simple `sendmsg` spray loop targeting `kmalloc-64`, we can overwrite the handle with `0x41414141`.
Then `mmap` will crash accessing `0x41414141`.
**This crash confirms we control the object.**
Running this risks panicking the device, requiring a reboot.
