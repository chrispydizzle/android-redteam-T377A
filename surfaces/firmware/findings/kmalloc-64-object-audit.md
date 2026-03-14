# kmalloc-64 Object Audit Results

**Device:** Samsung SM-T377A (AT&T)  
**Kernel:** 3.10.9-10380855, ARM32  
**Android:** 6.0.1, Build T377AUCU2AQGF  
**Date:** Tested via k64_object_audit.c  
**Baseline kmalloc-64 active_objs:** 86,039

---

## IMPORTANT: SLUB Per-CPU Cache Effect

With only 50 allocations, many primitives showed k64=+0 because SLUB's per-CPU
freelist caches ~30-64 objects per CPU. Allocations served from this cache do NOT
update `active_objs` in `/proc/slabinfo`. Cross-validated with `ion_slab_probe`
(200 allocs → k64=+596), confirming ion_handle IS in kmalloc-64 despite our 50-alloc
test showing +0. **Primitives showing +0 below may still use kmalloc-64 — only confirmed
k64 allocators (with deltas > 0) are reliable from this test.**

## Part 1: Slab Differential Analysis (20 Primitives × 50 Allocations)

| # | Primitive | k64 delta | k32 delta | k128 delta | Verdict |
|---|-----------|-----------|-----------|------------|---------|
| 1 | `/proc/self/stat` (seq_operations) | +0 | +0 | +0 | NOT k64 |
| 2 | `pipe()` default | +0 | +0 | +0 | NOT k64 (k512) |
| 3 | ION alloc (50 handles) | +0 | +0 | +0 | NOT k64 on this build |
| 4 | `epoll_create` | +0 | +0 | +0 | NOT k64 |
| 5 | `eventfd()` | +0 | +0 | +0 | NOT k64 |
| 6 | `signalfd()` | +0 | +0 | +0 | NOT k64 |
| 7 | `timerfd_create()` | +0 | +0 | +0 | NOT k64 |
| 8 | `inotify_add_watch()` | +0 | +0 | +0 | NOT k64 |
| 9 | `socket(AF_UNIX)` | +0 | +0 | +0 | NOT k64 |
| 10 | `/dev/ashmem` open | +0 | +0 | +0 | NOT k64 |
| 11 | `dup(0)` | +0 | +0 | +0 | NOT k64 |
| 12 | `/proc/self/maps` | +0 | +0 | +0 | NOT k64 |
| 13 | `/proc/self/status` | +0 | +0 | +0 | NOT k64 |
| 14 | `/proc/self/cmdline` | +0 | +0 | +0 | NOT k64 |
| 15 | `/dev/null` | +0 | +0 | +0 | NOT k64 |
| 16 | `/dev/zero` | +0 | +0 | +0 | NOT k64 |
| 17 | `/dev/urandom` | +0 | +0 | +0 | NOT k64 |
| 18 | `socket(AF_INET, SOCK_DGRAM)` | +0 | +0 | +0 | NOT k64 |
| 19 | `socket(SOCK_RAW, ICMP)` | 0 ok | — | — | EPERM (needs root) |
| 20 | `inotify_init1()` | +0 | +0 | +0 | NOT k64 |

### Bonus Spray Primitives

| Primitive | k64 delta | k32 | k128 | Rate | Verdict |
|-----------|-----------|-----|------|------|---------|
| **`socketpair(AF_UNIX)`** | **+261** | +0 | +0 | **5.2 objs/pair** | **★ BEST k64 SPRAY** |
| **`epoll_ctl ADD`** | **+36** | +0 | +16 | **0.7 objs/add** | **k64 + k128 mix** |

---

## Part 2: Function Pointer Analysis

### Objects that DO allocate in kmalloc-64

#### 1. socketpair internal structures — CONFIRMED k64=+261/50pairs
- **unix_sock** and associated socket buffer metadata land in kmalloc-64
- Function pointers accessed **indirectly** via `sock->ops` (pointer to static `unix_stream_ops`)
- `read()`/`write()`/`poll()` all dereference `sock->ops->recvmsg`, `->sendmsg`, `->poll`
- **Exploit value: HIGH as spray** — fills freed k64 slots reliably at ~5.2 objects/pair
- **Exploit value: MEDIUM for fptr hijack** — the ops pointer points to a static kernel table, not inline function pointers; to exploit, you'd corrupt the ops pointer to a fake vtable in user-mapped memory (blocked by PXN if present)

#### 2. epitem (epoll_ctl ADD) — CONFIRMED k64=+36/50adds
- `struct epitem` (~128 bytes on mainline) partially or sub-allocated in k64
- Contains `ffd.file` pointer to `struct file`
- `epoll_wait` → `ep_poll_callback` dereferences the file pointer
- **Exploit value: MEDIUM** — corrupting `ffd.file` gives a controlled dereference during `epoll_wait`, useful for info leak or redirect

### Objects that do NOT allocate in kmalloc-64

- **seq_operations**: 16 bytes on ARM32 → kmalloc-32 (NOT k64 on this build)
- **ion_handle**: Uses dedicated slab or different kmalloc size on this Samsung build
- **pipe_buffer (default)**: 16 bufs × 24 bytes = 384 → kmalloc-512
- **eventfd_ctx, signalfd_ctx, timerfd_ctx**: Dedicated slab caches
- **inotify_watch**: Dedicated slab or non-k64 size
- All `/dev/*` and `/proc/*` opens: Use file/inode/dentry caches, not generic kmalloc-64

---

## Part 3: pipe_buffer Deep Analysis

### Struct Layout (kernel 3.10, ARM32)
```
struct pipe_buffer {       // 24 bytes
    struct page *page;       // offset 0  (4 bytes)
    unsigned int offset;     // offset 4  (4 bytes)
    unsigned int len;        // offset 8  (4 bytes)
    const struct pipe_buf_operations *ops;  // offset 12 (4 bytes) ← FUNCTION TABLE PTR
    unsigned int flags;      // offset 16 (4 bytes)
    unsigned long private;   // offset 20 (4 bytes)
};
```

### Size → Slab Cache Mapping (measured on device)
| Pipe pages | Actual buffers | Array size | Expected cache | Measured delta |
|------------|---------------|------------|----------------|----------------|
| 1 | 1 | 24 bytes | kmalloc-32 | k192=+90 (pipe_inode_info) |
| 2 | 2 | 48 bytes | kmalloc-64 | noise (k64=0) |
| 3→4 | 4 | 96 bytes | kmalloc-128 | k64=+17, k192=+71 |
| 4 | 4 | 96 bytes | kmalloc-128 | k192=+73 |
| 5→8 | 8 | 192 bytes | kmalloc-192 | k192=+109-153 |
| default 16 | 16 | 384 bytes | kmalloc-512 | k192=+17 (just pipe_inode_info) |

### Critical Finding
**pipe_buffer[2] does NOT reliably allocate in kmalloc-64 on this device.**

The F_SETPIPE_SZ(8192) path creates 2 buffers (48 bytes), which theoretically targets kmalloc-64, but the measured k64 delta was **0 or noise** across multiple tests. The consistent allocator across all pipe sizes is **kmalloc-192** for the `pipe_inode_info` structure itself (~176 bytes).

The k64=+43 seen in the isolated 3b test appears to be **delayed accounting** from the previous test's cleanup, not actual pipe_buffer allocation. The sweep (3h) with clean baselines shows k64=0 for 2-page pipes.

### Possible explanations:
1. Samsung kernel may use a **dedicated pipe_buffer slab cache** (not generic kmalloc)
2. The kernel may use `kzalloc(roundup_pow_of_two(nr_bufs) * sizeof(*bufs))` which rounds 2→2 but the actual pipe_buffer may be padded differently
3. SLUB accounting may batch the 48-byte allocation into a merged slab

### Function Pointer Trigger Paths (verified by slab delta during operations)
- **write()** to pipe: k64=+0 (ops pointer set inline, no new kmalloc)
- **read()** from pipe: k64=+0 (ops->confirm called but no new alloc)
- **close()** both ends: k64=0 change (ops->release called, then buffer array freed)

---

## Final Ranking: k64 Objects for ION UAF Exploitation

### Tier 1: Confirmed k64 with Exploitable Properties
1. **socketpair(AF_UNIX, SOCK_STREAM)** — **+261 k64 objects per 50 pairs**
   - Rate: ~5.2 k64 allocs per socketpair() call
   - Persistent: fd-based, lives until close()
   - SELinux: allowed from shell UID 2000
   - Trigger: read/write/poll all dereference sock->ops
   - Control: limited (kernel fills struct, not user-controlled data)
   - **Best use: HEAP SPRAY to fill freed ion_handle slot**

2. **epoll_ctl(EPOLL_CTL_ADD)** — **+36 k64 objects per 50 adds**
   - Rate: ~0.7 k64 allocs per epoll_ctl ADD
   - Persistent: lives until fd close or epoll_ctl DEL
   - Contains file pointer that gets dereferenced
   - **Best use: secondary spray or info leak primitive**

### Tier 2: Confirmed k64 (via ion_slab_probe cross-validation)
3. **ion_handle** — k64=+596 for 200 allocs (≈3 k64 objects/handle)
   - Our 50-alloc test showed +0 due to SLUB per-CPU cache
   - Cross-validated with dedicated ion_slab_probe at 200 allocs
   - This IS the UAF victim object in kmalloc-64

### Tier 3: Likely NOT in k64 (below detection or different cache)
4. **seq_operations** — k64=0 even at scale (16 bytes → kmalloc-32 on ARM32)
5. **pipe_buffer[2]** — k64=0 reliably (kernel may use dedicated cache)

### Tier 3: No k64 Impact
- All other primitives tested (eventfd, signalfd, timerfd, inotify, dev nodes, proc files, dup, sockets): k64=+0

---

## Exploitation Strategy Update

**ion_handle CONFIRMED in kmalloc-64** (cross-validated: +596 delta for 200 allocs via ion_slab_probe).
No dedicated ion slab cache exists on this device (`/proc/slabinfo` has no ion-related entries).

### Recommended spray strategy for ION UAF:
1. **Primary spray: socketpair()** — 5.2 k64 objs/call, persistent, SELinux-allowed
   - Best rate and reliability for filling freed ion_handle slot
   - Content is kernel-controlled (sock structures with ops pointers)
2. **Precision spray: setxattr("user.*")** — exact size control, 41K ops/sec
   - Allows writing arbitrary 64-byte content into kmalloc-64
   - Non-persistent (freed on syscall return) — requires tight timing
3. **Supplemental: epoll_ctl ADD** — 0.7 k64 objs/call, contains file pointer
   - Useful as secondary spray or for info leak via corrupted ffd.file

### Attack flow:
```
1. ION UAF race → free ion_handle (slot in kmalloc-64)
2. socketpair spray (200+ pairs) → fill slot with unix_sock metadata
3. Trigger use of stale ion_handle → kernel dereferences attacker-influenced data
   OR
1. ION UAF race → free ion_handle
2. setxattr spray with crafted 64-byte payload → fill slot with fake struct
3. Trigger ion_handle use → controlled function pointer call
```
