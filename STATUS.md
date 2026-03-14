# Samsung SM-T377A — Security Assessment Status

> **Last updated:** 2026-03-09
> **Target:** Samsung Galaxy Tab E 8.0 (SM-T377A), AT&T carrier-locked
> **Goal:** Privilege escalation from ADB shell (UID 2000) to root

---

## ⚠ CRITICAL WARNINGS

- **Physical device** — fork-bombs, aggressive races, and `adbd_root` CRASH it
- **DO NOT run**: `/data/local/tmp/adbd_root`, `su-v1`, `su-v2`, `rageagainstthecage` (all crash/fail)
- **DO NOT broadcast**: `android.intent.action.MASTER_CLEAR` (reboots device)
- **DO NOT send AT**: `AT$ARMEE=1` (enters download mode), `*2767*2878#` (potential wipe)
- **DO NOT rapid-cycle CFUN modes** — rapid AT+CFUN switching + AT command floods cause **CP WDOG Reset** (modem watchdog crash → upload mode). Add 5+ second delays between CFUN switches. Limit AT throughput to ~1 cmd/sec.
- **Conservative testing only** — fork in child processes, use timeouts
- **ION heap bits 2 (0x0004) and 12 (0x1000)** cause kernel panic — DoS only, avoid
- **DO NOT run**: `setprop sys.powerctl reboot` — shell UID 2000 CAN set this property, triggers immediate reboot
- **Check `/src` and `/findings` before new work** to avoid duplicating effort

---

## Device Profile

| Property | Value |
|----------|-------|
| Model | Samsung SM-T377A (Galaxy Tab E 8.0) |
| Carrier | AT&T (carrier-locked bootloader) |
| SoC | Exynos 3475 (ARMv7 Cortex-A7, 4 cores) |
| Android | 6.0.1 (Marshmallow), Build MMB29K.T377AUCU2AQGF |
| Kernel | 3.10.9-11788437, compiled 2017-07-05 |
| Security patch | 2017-07-01 |
| SELinux | Enforcing (`u:r:shell:s0`) |
| Shell UID | 2000 (groups: input, log, adb, sdcard_rw, sdcard_r, net_bt_admin, net_bt, inet, net_bw_stats) |
| Encryption | **Unencrypted** (`ro.crypto.state=unencrypted`) |
| Build type | `user` (NOT debug/eng) |
| Platform key | Samsung proprietary (NOT AOSP test key) |
| Knox warranty | Fuse intact (`warranty_bit=0`) |
| OEM unlock | Toggle ON but **cosmetic** — carrier lock blocks all unsigned images |
| Modem | Shannon 308, firmware T377AUCU2AQGF |
| BT chip | BCM43454, firmware V0100.0131 |
| WiFi | wlan0, p2p0 (WiFi Direct dormant) |
| Physical memory | 0x20000000–0x7F4FFFFF (1.5GB) |
| Previous root attempts | Magisk v30.6, z4root, SuperSU, KingRoot — all installed but INACTIVE |

---

## Confirmed Kernel Addresses

> **NO KASLR** — addresses are static. TIMA paddr leak in dmesg confirms.

| Symbol | Virtual Address | Source |
|--------|----------------|--------|
| `commit_creds` | `0xC0054328` | Firmware symbol table |
| `prepare_kernel_cred` | `0xC00548E0` | Firmware symbol table |
| `selinux_enforcing` | **`0xC0B7AD18`** | TIMA paddr leak (0x20B7AD18 + 0xA0000000) |
| `selinux_enabled` | `0xC0AB00A8` | TIMA paddr leak (0x20AB00A8 + 0xA0000000) |
| TIMA `write_ptr` | `0xC7403580` | TIMA paddr leak (0x27403580 + 0xA0000000) |
| PAGE_OFFSET | `0xC0000000` | Standard ARM32 |
| PHYS_OFFSET | `0x20000000` | Confirmed |
| Conversion | `vaddr = paddr + 0xA0000000` | Confirmed |
| `task_struct->cred` | offset `0x164` | Firmware analysis |
| `thread_info->addr_limit` | offset `8`, KERNEL_DS=**`0x00000000`** | Kernel source (`arch/arm/include/asm/uaccess.h`) |

> ⚠ Previous estimate of `selinux_enforcing` at `0xC0B7AD54` was **WRONG** (off by 60 bytes). Use `0xC0B7AD18`.
> ⚠ Previous claim of `KERNEL_DS=0xFFFFFFFF` was **WRONG**. Samsung defines `KERNEL_DS` as `0x00000000`. `set_fs(0)` sets `DOMAIN_MANAGER` (full access). Exploit must write `0` to `addr_limit`, not `0xFFFFFFFF`.

---

## Kernel Mitigations

| Mitigation | Status | Notes |
|-----------|--------|-------|
| KASLR | ❌ NOT present | Addresses confirmed static via TIMA leak |
| PXN | ❌ NOT present | Can execute userspace code in kernel mode |
| Stack canaries | ❌ NOT present | Direct PC control on stack overflow |
| HARDENED_USERCOPY | ❌ NOT present | No bounds checking on copy_to/from_user |
| kptr_restrict | ✅ ACTIVE | /proc/kallsyms zeroed |
| SELinux | ✅ ENFORCING | Blocks msgget, add_key >198, mobicore, abstract sockets |
| mmap_min_addr | ✅ 32768 (0x8000) | Can map at 0x8000+ |
| TIMA | ✅ ACTIVE | TrustZone integrity check every 5 min; detects SELinux modification |
| /dev/mem, /dev/kmem | ❌ DO NOT EXIST | No direct memory access |
| /proc/self/pagemap | ✅ BLOCKED (EPERM) | Requires CAP_SYS_ADMIN |

---

## CVE Status (17 Tested)

| CVE | Vulnerability | Status | Details |
|-----|---------------|--------|---------|
| CVE-2016-5195 | Dirty COW | ❌ PATCHED | MAP_PRIVATE not modified after racing. Do not retry. |
| CVE-2015-1805 | pipe iov double-advance | ❌ PATCHED | readv/writev returns EFAULT correctly. Do not retry. |
| CVE-2014-3153 | Towelroot/futex | ❌ PATCHED | `FUTEX_CMP_REQUEUE_PI` returns EINVAL on ALL calls (tested: separate virtual pages, PRIVATE+SHARED flags, victim confirmed in futex). Samsung blanket-patched requeue_pi. Do not retry. |
| CVE-2015-3636 | ping socket UAF | ❌ PATCHED | LIST_POISON2 page not written. Do not retry. |
| CVE-2013-2094 | perf_event_open OOB | ❌ PATCHED | OOB config values return ENOENT. Do not retry. |
| CVE-2014-0196 | n_tty write race | ❌ LIKELY PATCHED | Process hung but no crash. |
| CVE-2016-0728 | Keyring overflow | ❌ NOT VIABLE | 26,502 ops/sec too slow (2701 min), EDQUOT at 198. |
| CVE-2017-7533 | inotify/rename race | ❌ SURVIVED | 558K events, 56K renames, 0 crashes in 4 rounds. |
| CVE-2017-11176 | mq_notify | ❌ N/A | POSIX MQ returns ENOSYS (not compiled). |
| CVE-2016-4557 | eBPF UAF | ❌ N/A | No eBPF syscall (only seccomp_bpf). |
| **CVE-2019-2215** | **binder UAF** | **⚠ UNPATCHED but UNEXPLOITABLE** | Samsung patched binder_free_thread (nullifies whead). UIO_FASTIOV=32 blocks iovec spray. BPF spray reclaims k256 but no trigger path. |
| **CVE-2017-1000251** | **BlueBorne L2CAP stack overflow** | **❌ KERNEL UNREACHABLE** | Android 6.0.1 uses Bluedroid (userspace L2CAP). Kernel `l2cap_parse_conf_rsp()` is NEVER called. Live test: EFS overflow sent, logcat shows `bt_l2cap: rcvd cfg rsp for unknown CID` in userspace PID 3691. Device survived (uptime unchanged). **DEAD END.** |
| CVE-2017-0781/0782 | BlueBorne BNEP (userspace) | **❌ BLOCKED** | Samsung Bluedroid validates UUID sizes ("Bad UID len"), rejects invalid ctrl types, checks packet lengths, and caps filter-set payloads to small ordered tables. BNEP channel opens but the old heap-overflow payload families are BLOCKED. |
| CVE-2015-8966 | ARM OABI fcntl64 bypass | ❌ N/A | OABI compat NOT compiled — `swi 0x900018` returns EFAULT (-14). |
| CVE-2017-2636 | n_hdlc UAF race | ❌ N/A | Only `n_tty` (0) and `input` (2) line disciplines registered. n_hdlc not compiled. |
| CVE-2016-4997 | netfilter compat setsockopt | ❌ BLOCKED | IPT_SO_SET_REPLACE returns EPERM (requires CAP_NET_ADMIN). |
| CVE-2015-8543 | Protocol NULL check bypass | ❌ PATCHED | proto=0 socket creation succeeds on INET/UNIX (expected), but no NULL fn ptrs reached. |
| CVE-2017-16939 | XFRM netlink UAF | ❌ BLOCKED | NETLINK_XFRM socket creation blocked by SELinux (EPERM). Only NETLINK_ROUTE accessible. |

---

## Confirmed Vulnerabilities (Non-Exploitable)

### ION UAF (kmalloc-64)
- **Race win rate**: 91% (ION_IOC_FREE vs ION_IOC_SHARE)
- **Spray**: socketpair best (+1169 k64 per 200 ops)
- **Blocked**: No victim object with callable function pointers in kmalloc-64
- **Blocked**: seq_operations is static `.rodata`, NOT heap-allocated
- **Blocked**: msgsnd/msgget blocked by SELinux (EPERM)
- **Blocked**: ION driver mutex prevents handle UAF exploitation

### CVE-2019-2215 Binder UAF (kmalloc-256)
- **UAF confirmed**: binder_thread freed while epoll holds dangling wait_queue ref
- **binder_thread**: 252 bytes → kmalloc-256
- **BPF spray**: 26-insn BPF filter reclaims kmalloc-256 (cross-allocation confirmed)
- **Blocked**: Samsung binder_free_thread nullifies `eppoll_entry->whead` before kfree
- **Blocked**: UIO_FASTIOV=32 (writev ≤32 uses stack, ≥33 → kmalloc-512 wrong cache)
- **Blocked**: close(epfd) list_del is self-referential, wake_up never triggered
- **Tested**: 48 offsets × 6 trigger methods = 288 combinations → ZERO crashes

### ION Heap DoS
- **heap bit 2 (0x0004) and bit 12 (0x1000)** cause kernel panic from unprivileged shell
- Crash: PC at `_raw_spin_lock_irqsave`, LR at `down()` — TrustZone/secure heap semaphore
- **DoS only** — no code execution, fixed semaphore address

### tee() ABBA Deadlock (Zero-Day, DoS Only)
- SPLICE_F_NONBLOCK ignored when both pipes full → hang
- Circular tee(p1→p2)+tee(p2→p1) → classic ABBA deadlock
- Propagates across processes via shared pipe fds
- 17% slab anomaly rate but confirmed to be SLUB caching noise
- **DoS only** — no memory corruption, pipe refcounting is correct

### Mali MEM_IMPORT Crash (Corrected)
- **Original "Mali vendor dispatch" zero-day was FALSE** — caused by ION struct bug in test code
- ARM32 ION struct uses `uint32_t` (4 bytes), NOT `uint64_t` — misalignment caused heap_id_mask to hit secure heap
- Mali `kbase_ioctl` ignores magic byte — both `'M'` and `0x80` dispatch identically through `kbase_dispatch`
- With correct ION struct, Mali MEM_IMPORT works normally
- Mali race fuzzing: 1150 trials, 0 anomalies

### Mali Live Exploit State (2026-03-07)
- JOB_SUBMIT works live with the **32-byte Samsung submit struct** and **56-byte old56 atom layout**
- WRITE_VALUE jobs are real and GPU-visible, but on this T72x path they act as an **8-byte zero-write** only
- Direct `MEM_JIT_INIT` variants all fail with `EFAULT`, and `SOFT_JIT_ALLOC` / `SOFT_JIT_FREE` atoms return `0x4003` (`JOB_INVALID`)
- **Implication**: GHSL-style JIT softjob exploitation is not available on this UK 10.0 stack
- New positive signal: an earlier WRITE_VALUE atom can zero a later atom's JC page before it runs; zeroing atom2's payload type (`jc+40`) makes atom1 complete `DONE` and atom2 fail with `DATA_INVALID_FAULT`
- Submitted atom metadata is **copied at submit time**, not consumed live from userspace/GPU-shared atom buffers:
  - zeroing atom2 `jc`, `udata[0]`, or `core_req+deps` inside the shared atom array does **not** change atom2 execution or event udata
- JC live-field matrix:
  - zeroing atom2 JC qword `+16` (packed header flags/index) → atom2 `DATA_INVALID_FAULT`
  - zeroing atom2 JC qword `+32` (payload address) → atom2 `JOB_CANCELLED`
  - zeroing atom2 JC qword `+40` (payload type) → atom2 `DATA_INVALID_FAULT`
  - zeroing qwords `+0`, `+8`, `+24`, or `+48` leaves atom2 `DONE`
- Multi-descriptor JC chains are confirmed:
  - a single atom can execute at least three chained WRITE_VALUE descriptors via header `next`
  - control case zeroes scratch, mid, and dest pages
  - zeroing descriptor0 `next` at `chain + 24` before execution zeroes only scratch; mid/dest stay untouched; atom2 still returns `DONE`
  - zeroing descriptor1 `next` at `chain + 64 + 24` zeroes scratch and mid; dest stays untouched; atom2 still returns `DONE`
  - zeroing descriptor2 type at `chain + 128 + 40` before execution leaves earlier descriptors working, faults descriptor2 with `DATA_INVALID_FAULT`, and leaves dest unchanged
- MTP / special-handle reality check:
  - MTP maps only via fallback `pgoff=3` on this device
  - CPU reads from the mapped MTP page fault (`SIGBUS`/`SIGSEGV`) even with `PROT_READ`
  - normal GPU jobs do not make it directly readable
  - WRITE_VALUE targets `0x2000` and `0x3000` return `JOB_CANCELLED`, so the special mmap handles are not trivially usable as low GPU VAs
- Cross-context reclaim reality check (`src\mali\mali_xctx_jc_reclaim_probe.c`):
  - `ctx2 MEM_FREE(ctx1_gpu_va)` returns `ret=0x3` (`INVALID_PARAMETER`) when checked via `header.ret`
  - ctx2's first allocation still gets `0x102000000`, but that is just normal per-context VA reuse, not proof of overlap
  - ctx1's stale CPU map keeps reading its own tag after the rejected free, and a stale ctx1 write does **not** change ctx2's claim page
  - reclaiming a "freed" ctx1 JC page from ctx2 does **not** steer execution: the ctx1 job still zeros its original scratch target, while the attacker-chosen dest target stays untouched
  - **Implication**: the old cross-context free / overlapping-VA story was a false positive caused by checking ioctl return status without validating `header.ret`; do not spend more time on the xctx reclaim path
- Header/result-code audit (`src\mali\mali_header_ret_audit.c`):
  - same-context double free is **rejected** on the second free: `free#2 ret=0x3`
  - `MEM_FLAGS_CHANGE` is not a live primitive here: all tested changes (`+CPU_WR`, `+GPU_EX`, `+GROW_ON_GPF`) fail at the ioctl layer, and a writable remap still fails with `EPERM`
  - `MEM_FLAGS_CHANGE` on a freed region also fails at the ioctl layer
  - `MEM_COMMIT(-1)` and `MEM_COMMIT(0x7fffffff)` both return `ret=0x3` with subcode `0xfffffffc`, and the commit size stays unchanged at `1`
  - **Implication**: older Mali exploit helpers that relied on double free, flags-change escalation, or commit underflow were also false positives from incomplete result checking
- MEM_IMPORT reality check (`src\mali\mali_import_jc_probe.c`):
  - the **working** layout is:
    - `phandle=&fd`
    - `type=2`
    - flags packed at offset `+24`
    - flags value `0x0000000F` (`CPU_RD|CPU_WR|GPU_RD|GPU_WR`)
  - this returns a valid GPU VA (`0x102000000` in the live test), and CPU mapping that VA aliases the ION `mmap()`:
    - writing `import_map[1] = 0xCAFEBABE` is immediately visible at `ion_map[1]`
  - but imported pages are **not** valid WRITE_VALUE destinations or JC fetch pages on this stack:
    - a normal Mali JC targeting the imported GPU VA returns `JOB_CANCELLED`
    - using the imported page itself as the JC page also returns `JOB_CANCELLED`
  - **Implication**: dma-buf import is real and gives a controllable GPU VA alias to ION memory, but imported pages are not directly usable as WRITE_VALUE targets or executable JC pages
- MEM_IMPORT + MEM_ALIAS reality check (`src\mali\mali_import_alias_probe.c`):
  - imported GPU VAs are **not aliasable** through the live MEM_ALIAS path on this stack
  - with `handle=import_gpu_va`, all tested alias flag sets fail cleanly with `header.ret=0x3`:
    - `0x0F`, `0x0D`, `0x0C`, `0x07`, `0x03`
  - same probe confirms the alias ABI itself is live for native Mali allocations:
    - `handle=native_gpu_va`, `flags=0x0F` returns a new alias GPU VA successfully
  - **Implication**: import-backed pages are rejected earlier than ordinary native allocations by MEM_ALIAS bookkeeping, so `MEM_IMPORT -> MEM_ALIAS` is not the bridge from controllable ION memory to an executable/targetable GPU control page
- External-resource path reality check (`src\mali\mali_extres_probe.c`, `src\mali\mali_extres_import_target_probe.c`, `src\mali\mali_extres_import_jc_probe.c`, `src\mali\mali_extres_import_chain_probe.c`, `src\mali\mali_extres_chain_matrix_probe.c`):
  - baseline WRITE_VALUE atom still returns `DONE` and zeroes its native destination
  - native extres is still rejected:
    - one native-handle extres list returns `JOB_INVALID`
  - soft external-resource map/unmap atoms (`BASE_JD_REQ_SOFT_EXT_RES_MAP/UNMAP`) still return `JOB_INVALID` in the current UK 10.0 ABI/layout
  - but **hardware extres over imported UMM is real and useful**:
    - imported target without extres returns `JOB_CANCELLED`
    - imported JC page without extres returns `JOB_CANCELLED`
    - `BASE_JD_REQ_EXTERNAL_RESOURCES` + imported handle list makes the imported GPU VA usable as a WRITE_VALUE target (`DONE`, ION buffer zeroed)
    - the same flag also makes the imported GPU VA usable as a JC page (`DONE`, native destination zeroed)
    - both shared (`import_gpu_va|0`) and exclusive (`import_gpu_va|1`) imported extres variants work
  - imported extres pages remain **live later control pages**, not just accepted inputs:
    - an earlier atom can zero imported JC `+40` before the imported extres atom runs, causing `DATA_INVALID_FAULT`
    - a 3-descriptor chain stored entirely in imported ION memory runs cleanly under extres and zeroes scratch/mid/dest
    - zeroing descriptor1 `next` at imported `jc + 64 + 24` truncates that imported chain after mid while the atom still reports `DONE`
    - zeroing descriptor1 `target` at imported `jc + 64 + 32` yields `JOB_CANCELLED` after scratch only
    - zeroing descriptor2 `target` at imported `jc + 128 + 32` yields `JOB_CANCELLED` after scratch+mid
  - imported chains also expose a **prefetch boundary**:
    - within a single imported extres atom, descriptor0 can zero descriptor1 `next`, descriptor1 `type`, or descriptor2 `type` in memory
    - the targeted qwords are visibly zero afterward, but the chain still completes all later descriptors and returns `DONE`
    - this means later imported chain descriptors are snapshotted/prefetched before earlier descriptors finish executing
  - **Implication**: imported UMM-backed memory is now a validated GPU-fetched control surface under `BASE_JD_REQ_EXTERNAL_RESOURCES`, but useful steering still has to happen **before atom start**; once the imported chain is running, self-modification lands in memory yet no longer changes execution. Soft extres remains broken, but hardware extres is the strongest current bridge from controllable ION data into live Mali control flow
- Special-handle alias reality check (`src\mali\mali_write_alloc_probe.c`):
  - direct low-handle WRITE_VALUE targets `0x1000/0x2000/0x3000/0x4000` all return `JOB_CANCELLED`
  - `mmap2` low-offset probing only succeeds for `pgoff=2`; `pgoff=3` fails with `EFAULT`, `pgoff=4` with `EINVAL`
  - but `MEM_ALIAS` reveals one **special** GPU-owned page class:
    - only handle `0x4000` (`BASE_MEM_WRITE_ALLOC_PAGES_HANDLE`) aliases successfully
    - handles `0x1000`, `0x2000`, `0x3000`, and scanned handles `0x5000`..`0x10000` all fail with `header.ret=0x3`
    - `0x4000` with len=1 and flags `0x0F/0x0D/0x0C` returns a real GPU VA, but CPU mmap of that alias fails with `EPERM`
    - `MEM_QUERY` on the aliased page reports `COMMIT_SIZE=1`, `VA_SIZE=1`, `FLAGS=0xC`, i.e. the kernel strips CPU access and leaves it as GPU RD|WR only
    - that aliased GPU VA is still accepted as a WRITE_VALUE target and returns `DONE`
    - `0x4000` alias len=2 is rejected (`header.ret=0x3`)
  - **Implication**: the driver exposes a single validated non-JC, GPU-owned write sink through `MEM_ALIAS(BASE_MEM_WRITE_ALLOC_PAGES_HANDLE)`, but it is currently GPU-only and not yet an executable/control page
- Write-alloc side-effect isolation (`src\mali\mali_write_alloc_sidefx_probe.c`):
  - rerunning one offset per child process removes the earlier cross-offset false positive
  - the refined result, combined with `src\mali\mali_write_alloc_oneshot_probe.c`, is:
    - back-to-back WRITE_VALUE jobs to the **same** `MEM_ALIAS(0x4000)` alias all return `DONE` for tested offsets `0x000..0x800`
    - if an unrelated native WRITE_VALUE job runs in between, returning to the old alias through the **stale original JC page** yields `DATA_INVALID_FAULT`
    - a freshly re-aliased `0x4000` page in the same context still returns `DONE`
  - `src\mali\mali_write_alloc_ordering_probe.c` and `src\mali\mali_write_alloc_reuse_probe.c` refine that further:
    - the old alias itself is still usable after the intervening native job if it is driven through a **freshly rebuilt JC page**
    - the fault depends on reusing the **stale old JC contents**, not on alias lifetime alone
  - `src\mali\mali_write_alloc_jc_refresh_probe.c` makes that explicit:
    - no-refresh retry => `DATA_INVALID_FAULT`
    - rewriting the same JC descriptor bytes before retry => `DONE`
    - `msync()` alone without rewriting still faults
  - `src\mali\mali_write_alloc_minimal_touch_probe.c` and
    `src\mali\mali_write_alloc_region_touch_probe.c` narrow the refresh rule further:
    - rewriting individual active words (`jc[4]`, `jc[8]`, `jc[9]`, `jc[10]`) does **not** help
    - rewriting the **first 16 bytes** of the stale JC page is already sufficient to restore `DONE`
    - rewriting the second 16 bytes, the last 24 bytes, or the active 28-byte region is **not** sufficient
  - `src\mali\mali_write_alloc_epoch_probe.c` shows what changed inside those first 16 bytes:
    - after the first successful submit, `jc[0]` is no longer zero — the GPU writes `0x00000001` there
    - zeroing only `jc[0]` before retry is enough to restore `DONE`
    - leaving `jc[0]=1`, or writing arbitrary nonzero first-16-byte patterns, still faults
  - `src\mali\mali_exception_status_probe.c` shows this is a **generic descriptor reuse rule**, not a write-alloc-specific quirk:
    - an ordinary native-destination descriptor also faults on reuse after an intervening job if `jc[0]` is left at `1`
    - clearing only `jc[0]` back to `0` restores success for both native targets and the `0x4000` write-alloc alias
  - **Implication**: the interesting state transition is pinned to **generic stale JC reuse across an intervening job**, and the refresh boundary is the descriptor's `exception_status` word rather than any unique state in the `0x4000` alias. This demotes the earlier write-alloc “side effect” into ordinary descriptor hygiene rather than a special exploit signal
- JC chain field matrix (`src\mali\mali_jc_chain_matrix_probe.c`):
  - on descriptor1 and descriptor2 of a 3-descriptor chain, qwords `+0`, `+8`, and `+48` are inert: the full chain still completes and zeroes scratch/mid/dest
  - qword `+16` still yields `DATA_INVALID_FAULT`
  - qword `+32` still yields `JOB_CANCELLED`
  - qword `+40` still yields `DATA_INVALID_FAULT`
  - qword `+24` is the **only** non-fault steering field:
    - zeroing descriptor1 `next` truncates the chain after mid and still returns `DONE`
    - zeroing descriptor2 `next` is inert because the last descriptor already ends the chain
  - **Implication**: within validated live JC-chain corruption, the zero-write primitive can currently **truncate** later control flow but still cannot redirect a later descriptor to a new target
- **Next Mali focus**: extres is no longer a dead end. Imported ION pages can now serve as valid WRITE_VALUE targets, valid JC pages, and valid later multi-descriptor control pages under hardware extres, with proven pre-start truncation/cancel steering on imported memory. The newest limit is that intra-atom self-modification is too late: later chain descriptors are already snapshotted once the imported atom starts. The write-alloc retry behavior remains demoted to generic descriptor hygiene (`jc[0]` / `exception_status`), so the priority should shift to paths that can exploit this **pre-start** imported-control boundary: alias/reclaim interaction, targetable MMU/page-table-adjacent pages, or any way to corrupt imported control data before the driver snapshots it.
- `src\mali\mali_prestart_race.c` is now a higher-signal timing probe instead of a single immediate rewrite attempt:
  - atom A's runway now spans **4 native JC pages** (`DEFAULT_CHAIN_OPS=192`) instead of one page / 64 ops
  - it runs baseline + pre-submit control first, then sweeps post-submit rewrite delays of `0`, `100`, and `500` microseconds
  - each trial now prints CSV-style `submit_to_write_us` / `submit_to_finish_us` timing so the next live run can distinguish "snapshotted at submit" from "still live shortly after submit"
  - the updated source cross-compiles cleanly with `arm-linux-gnueabi-gcc -static -pie -fPIE -march=armv7-a -mfloat-abi=soft -O2 -Wall -Wextra -pthread`
  - live run result on 2026-03-08: baseline and pre-submit control both passed, but **all 60/60 post-submit rewrite trials stayed on the original JC** (`DONE/DONE`, target_A zeroed, target_B unchanged) across `0`, `100`, and `500` microsecond rewrite delays
  - measured submit-to-write windows were roughly `6.7-9.2 us` for the immediate case, `194.5-225.2 us` for the nominal `100 us` delay, and `601.3-611.7 us` for the nominal `500 us` delay
  - the first implementation initially faulted after trial 1 because atom A reused stale chain descriptors; rebuilding the chain each trial fixed that and confirmed the negative result is real rather than descriptor-hygiene noise
  - **Implication**: post-submit CPU rewrites to an imported extres JC do **not** propagate on SM-T377A; the imported control page is effectively snapshotted no later than submit/driver acceptance, so the next Mali step should move to alias-race GPU-access validation
- `src\mali\mali_alias_gpu_access_probe.c` is now the first concrete follow-up for that next step:
  - it now tags source pages 8-15 uniquely, reserves the full stale alias VA window with a `commit=0` MEM_ALLOC when the race wins, and then only accepts reclaim candidates whose GPU VA range is fully disjoint from the old alias window
  - live rerun result on 2026-03-08: the race still wins reliably, the full stale alias window can be re-reserved at the same GPU VA with `commit=0`, all 8 tagged source pages reclaim immediately at a disjoint VA (`0x102018000` in the live run), and a direct WRITE_VALUE control to that reclaim allocation zeroes the expected tagged page
  - matching stale **native tail** and stale **alias** targets still return `DONE`, but once the overlap confound is removed they do **not** zero any tagged reclaim page
  - **Implication**: the alias-VA-reuse confound is now resolved and both stale native-tail and stale alias write paths are negative in this controlled-reclaim model; the next Mali follow-up should move to page-reuse timing / controlled-content injection rather than more stale-alias writes
- `src\mali\mali_alias_reuse_timing_probe.c` now measures how quickly the freed pages recycle under that safer model:
  - it wins the same alias free/shrink race, reserves the old alias VA window with a zero-commit allocation, then allocates fresh 8-page CPU/GPU regions sequentially and checks which source-page tags reappear
  - live run result on 2026-03-08: **16/20 race wins**, and on **all 16 wins** the full stale alias window re-reserved cleanly at `0x102010000` with `commit=0`
  - on those same 16/16 wins, the **first disjoint 8-page allocation** at `0x102018000` immediately reclaimed **all 8 tagged source pages** (`0..7`) with no overlap back into the stale alias VA window
  - measured reuse cadence is therefore maximally favorable under the current model: `first_hit=1`, `first_disjoint_hit=1`, and `unique_pages=8/8` on every successful race
  - **Implication**: immediate, fully disjoint controlled reclaim is now confirmed on SM-T377A once the race wins. The next Mali follow-up should stop asking whether reclaim is possible and instead test **controlled-content injection** (e.g. attacker-written reclaim buffers or imported control pages that consume those recycled physical pages)
- `src\mali\mali_alias_controlled_injection_probe.c` now turns that reclaim result into a later control-surface test:
  - it wins the same alias free/shrink race, reserves the stale alias VA window with `commit=0`, seeds one reclaimed page with a WRITE_VALUE descriptor plus sentinel, frees that reclaim buffer, then allocates fresh victim buffers until the seed reappears
  - live run result on 2026-03-08: **iter 1** won the race immediately, re-pinned the stale alias window at `0x102010000`, seeded reclaim alloc `0x102019000` page `0` / source page `6`, and then saw the first victim allocation preserve that seed on victim page `7`
  - submitting that preserved victim page as JC returned `DONE` and zeroed scratch target `0x102018000`
  - **Implication**: same-context controlled-content injection is now confirmed. The next Mali step is no longer "can attacker data survive reclaim?" but "can a surviving consumer (imported control page, retained driver pointer, or another non-direct path) ingest those seeded pages without us directly resubmitting the JC page?"
- `src\mali\mali_alias_chain_consumer_probe.c` now confirms the first non-direct consumer on top of that seeded reclaim:
  - it wins the same alias free/shrink race, reserves the stale alias VA window with `commit=0`, seeds one reclaimed page, frees that reclaim buffer, and waits for the seed to reappear in a later victim allocation
  - live run result on 2026-03-08: **iter 1** again won the race immediately, re-pinned the stale alias window at `0x102010000`, seeded reclaim alloc `0x10201a000` page `0` / source page `5`, and then saw the first victim allocation preserve that seed on victim page `7`
  - instead of directly resubmitting the seeded page, the probe submitted a separate local head descriptor whose `next` pointer targeted the preserved victim page; the job returned `DONE` and zeroed both scratch target `0x102018000` and dest target `0x102019000`
  - **Implication**: the attacker-seeded reclaimed page is now confirmed as a later chain descriptor consumer, not just a directly resubmitted JC page. The next Mali step should target an **imported or otherwise driver-retained consumer** instead of another same-context chain handoff

---

## Fuzzing Summary (240M+ Operations)

| Target | Tests | Operations | Crashes | Bugs |
|--------|-------|-----------|---------|------|
| mmap/ioctl races | 6 | 225M+ | 0 | 0 |
| splice/tee races | 8 | 2.9M+ | 0 | 2 (deadlock, DoS) |
| Deep race conditions | 8 | 1.3M+ | 0 | 1 (deadlock confirm) |
| tee exploitation | 18 | 400+ iters | 0 | DoS only |
| BPF filter races | 7 | 16K+ cycles | 0 | 0 (SLUB noise) |
| Additional surfaces | 6 | 5K+ | 0 | 0 |
| Mali GPU | 29K+ ops + 1150 race trials | 30K+ | 0 | 0 |
| PTMX/TTY | 7 | 700 | 0 | 0 |
| Ashmem | N/A | 100K+ | 0 | 0 |
| Binder | N/A | 72K+ | 0 | DoS only |
| ION | Multiple | 50K+ | 0 (except DoS) | UAF (blocked) |
| **NETLINK_ROUTE** | 4 | **7.2M+** | 0 | 0 |
| **SO_ATTACH_FILTER race** | 1 | 10s | 0 | 0 |
| **SCM_RIGHTS fd race** | 1 | 22.7K iters | 0 | 0 |

---

## Capabilities Achieved (Non-Root)

### From ADB Shell (UID 2000)
- Install APKs: `pm install -r -g`
- Grant development permissions: WRITE_SECURE_SETTINGS, READ_LOGS, DUMP, SET_DEBUG_APP, INTERACT_ACROSS_USERS
- Modify settings: Global and Secure settings writable
- Input injection: full touchscreen/keyboard control via `/dev/input/event0-5`
- dmesg access: kernel log readable (TIMA address leak)
- debugfs read access: binder, ion, mali, tracing stats
- ftrace partial: buffer_size_kb, tracing_on, trace, trace_marker writable
- ctl.start/ctl.stop: DAC passes but SELinux denies all init services
- Content providers: contacts, media accessible
- DM port AT commands: full modem command access via COM11
- **ptrace on own children**: PTRACE_ATTACH, GETREGS, PEEKDATA all work; /proc/child/mem opens O_RDWR
- **NETLINK_ROUTE**: Full access — RTM_GETLINK/GETADDR/GETROUTE/GETNEIGH/NEWROUTE/DELROUTE/NEWRULE
- **fcntl F_SETOWN**: Can set file owner to any PID including init (PID 1) — sends SIGIO
- **setsockopt**: SO_PRIORITY, SO_TIMESTAMP, IP_OPTIONS, IP_TOS, IP_TTL all work on INET UDP
- **PR_SET_NO_NEW_PRIVS, PR_SET_CHILD_SUBREAPER**: Both work
- **CapBnd=0xC0**: CAP_SETUID (7) + CAP_SETGID (6) in capability bounding set

### From Installed APK (com.privesc.agent, UID 10139)
- **Device owner**: `isDeviceOwner=true`, `isProfileOwner=true`
- **Device admin**: reset-password, force-lock, wipe-data policies
- **31 permissions** including WRITE_SECURE_SETTINGS, READ_LOGS, DUMP
- **Accessibility service**: bound and active, reads ALL screen content
- **enableSystemApp()**: re-enabled 12 disabled system apps (DLP, Knox BT, etc.)
- **PackageInstaller**: can create silent install sessions (installs as untrusted_app only)
- **setGlobalSetting/setSecureSetting**: most settings writable
- Native code execution from app sandbox
- mprotect RWX: can create executable memory
- Read /proc/self/maps: library layout visible
- Connect to dnsproxyd and logd sockets
- Read world-readable /data/system/ files (enterprise.conf, uiderrors.txt, fota.xml)

### What's NOT Achievable Without Root
- USB config change (blocked by SELinux and DPM API)
- System UID code execution (SmartcomRoot features disabled, DLP binding blocked)
- Install as system UID (requires Samsung platform signing key)
- Enable ftrace function tracing (only `nop` tracer compiled)
- Write /sys entries, /proc kernel parameters
- Mount filesystem read-write
- Read block devices, /proc/<root_pid>/maps
- Execute in diagexe or at_distributor domains (SELinux transition blocked)

---

## Accessible Attack Surfaces

### Binder Services (330 enumerated, key ones below)

| Service | UID | Methods | Status |
|---------|-----|---------|--------|
| SmartcomRoot (APNWidgetRootService) | 1000 | 15 | Callable but features disabled (iptables/tcpdump need root) |
| DLP (IDLPManager) | 1000 | 3 | Accessible, purpose unclear |
| EngineeringModeService | 1000 | 8 | **DEAD END**: M1=0 (eng OFF), M2=-1, M3-5,7=-1300 (Samsung auth), M6=-1, M8=UNKNOWN. Identical APK vs shell — auth is signature-based, not UID-based |
| DeviceRootKeyService | 1000 | 5 | **Decoded**: M1=0(ok), M2=-1, M3=-1, M4=0(ok), M5=-19(ENODEV). Returns status ints only, no key material exposed |
| execute (IExecuteManager) | — | 2 | Returns app list, no cmd exec |
| ABTPersistenceService | 1000 | 25 | **DEAD END (fully exhausted)**: ALL 26 methods (M1-M26) confirmed auth-gated. Auth gate: DER cert in Absolute Software table OR UID 1000. M7 getAllApplicationProfiles and M13 invokeMethodAsSystem also auth-gated. M13 null-spec → "Method Specification is null" (hits validation before auth, not exploitable). M10 has different logic (no cert check) but requires package in ABT OTA registry — populate path (M5) also auth-gated. Do not retry. |
| tima (ITimaService) | — | 3 | M1-M2 return -1, M3 empty |
| persona (IPersonaManager) | — | 30+ | **Typed read pass complete**: candidate ids `0/1/10/11/100/150` all fail `exists`; baseline `id=0` decodes as `getState=INVALID`, `getPreviousState=INVALID`, `getPersonaType=default`, `getNormalizedState=-1`, and creator lists for `uid 0/1000/10139` are empty. |
| gatekeeper (IGateKeeperService) | — | 5 | **Dead end / status only**: decompiled stub exposes only tx 1-5. Typed `M4(getSecureUserId)` returns `0` for uid `0`, `1000`, and app uid `10139`; blind `M1-M3` only reach `GateKeeperResponse(ERROR)`. |
| keystore (IKeystoreService) | — | 40 | **Downgraded after typed pass**: `getState(UID_SELF)` = `UNINITIALIZED`, `list(prefix,-1)` is empty for `""`, `USRPKEY_`, `USRSKEY_`, `USRCERT_`, `CACERT_`, tested aliases are `KEY_NOT_FOUND`, and typed export/begin did not expose any key material or operation token. |
| enterprise_policy (IEnterpriseDeviceManager) | — | 40 | **Policy-gated**: `M2` is a single admin `ComponentName` reply for `com.privesc.agent/.AgentDeviceAdmin`; `M5(ComponentName)` returns clean `1`, but no escalation yet. |
| remoteinjection (IRemoteInjection) | — | 15 | **Low-value partial access**: M1=0, M5=1; remaining methods mostly Knox permission or system-user gated. |
| SatsService (ISatsService) | — | 20 | **DEAD END**: binder reachable, but all tested calls return no data/false from APK context. |
| SEAMService (Knox SEAMS) | — | ~4 | Knox security |

### Sockets

| Socket | Type | Access | Service | Notes |
|--------|------|--------|---------|-------|
| /dev/socket/dnsproxyd | FS | ✅ Connected | netd (root, ALL caps) | FrameworkListener protocol, no crash on fuzzing |
| /dev/socket/logd | FS | ✅ Connected | logd | Log writing |
| /dev/socket/fwmarkd | FS | ✅ Accessible | netd | Firewall marks |
| /dev/socket/property_service | FS | ✅ World-RW | init | Can't set privileged props |
| @FactoryClientSend/Recv | Abstract | ❌ SELinux | at_distributor | EACCES from both shell and app |
| @ATDMultiClient | Abstract | ❌ SELinux | at_distributor | EACCES from both shell and app |
| @diag_mycmc_app2cp | Abstract | ❌ SELinux | diagexe | EACCES |
| /dev/socket/netd | FS | ❌ root:system | netd | Permission denied |

### Device Nodes

| Device | Access | Notes |
|--------|--------|-------|
| /dev/binder | ✅ RW | Binder IPC |
| /dev/ashmem | ✅ RW | Shared memory |
| /dev/ion | ✅ RW | ION allocator |
| /dev/mali0 | ✅ RW | Mali GPU |
| /dev/ptmx | ✅ RW | PTY multiplexer |
| /dev/input/event0-5 | ✅ RW | Touchscreen, sensors, keys |
| /dev/alarm | ✅ RO | Android alarm |
| /dev/mobicore-user | ❌ SELinux | World-RW on DAC, SELinux blocks shell |
| /dev/s5p-smem | ❌ | Permission denied |
| /dev/umts_* | ❌ | system:radio only |

### DM Port (COM11 / Shannon 308 Modem)
- Raw AT commands work (no DM framing needed)
- 177 AT commands available via AT+CLAC
- Key commands: AT+DEVCONINFO (full device info), AT+CLCK (lock status)
- Network lock (PN): ACTIVE — AT&T carrier lock
- **AT+DUMPCTRL**: Accepts ALL arguments but is a **no-op stub** — echoes `DUMPCTRL:OK` without action
- **CFUN modes 4-9, 11**: Accepted as transient engineering actions (CFUN stays 0). CFUN=9 → `CLPC OFF` (RF calibration). Modes 10, 12 rejected.
- **No new AT commands** appear in any CFUN mode — command surface is static
- **NV/EFS/memory access**: COMPLETELY BLOCKED (AT%NVREAD, AT+EGMR, AT$QCNVR, all ERROR)
- **All dump/trace/debug commands**: BLOCKED (XDUMPMEM, MEMDUMP, CPCRASH, SYSLOG, etc.)
- AT$ARMEE=1 triggers download mode (DANGEROUS!)
- No authentication required
- Aggressive probing disrupts USB composite device → ADB disconnect
- **AT command surface: EXHAUSTED** — focus on DM binary protocol (HDLC) fuzzing instead

### Critical Processes

| Process | PID | UID | Capabilities | SELinux Domain |
|---------|-----|-----|-------------|----------------|
| netd | 2191 | root | ALL (0x1fffffffff) | u:r:netd:s0 |
| diagexe | 2209 | 1000 | DAC_OVERRIDE, NET_ADMIN, NET_RAW, SYS_ADMIN, SYS_BOOT | u:r:diagexe:s0 |
| at_distributor | 2210 | 1001 | CHOWN, DAC_OVERRIDE, NET_ADMIN, NET_RAW, SYS_ADMIN, SYS_BOOT, SYS_TIME | u:r:at_distributor:s0 |
| SmartcomRoot | ~22696 | 1000 | — | — |
| MobiCore (TEE) | 2182 | — | — | — |

---

## Blocked Paths (Do Not Retry)

| Path | Why It Failed |
|------|--------------|
| Bootloader flash (Odin) | AT&T carrier lock rejects all unsigned images |
| Platform signing key forgery | Samsung proprietary key, not AOSP test key |
| SmartcomRoot command injection | `Runtime.exec(String[])` array form prevents metacharacter injection |
| Abstract socket access | SELinux blocks socket creation from both shell and untrusted_app |
| JDWP system app debugging | `ro.debuggable=0` — only user apps exposed |
| ctl.start/stop init services | DAC passes but SELinux denies all operations |
| /dev/mem, /dev/kmem | Do not exist |
| User namespaces | EINVAL (CONFIG_USER_NS not compiled) |
| AF_PACKET socket | EPERM (no CAP_NET_RAW, SELinux blocks) |
| eBPF | ENOSYS (not compiled) |
| POSIX message queues | ENOSYS (not compiled) |
| userfaultfd | ENOSYS (not compiled) |
| Keyring (add_key) | SELinux blocks after 198 keys |
| Factory app services | Require KEYSTRING permission (signature\|privileged) |
| DeviceKeystring activities | Not exported |
| ftrace function tracing | Only `nop` tracer compiled, can't enable events |
| mount -o remount,rw | Permission denied |
| Block device reads | SELinux blocks all |
| Backup transport | Inactive, no transports available |
| run-as | "Could not set capabilities: Operation not permitted" |
| ABTPersistenceService M5 install | Enforces auth with properly formatted Parcelable |
| Content provider SQL injection | Most blocked by permissions |
| OABI compat syscalls | NOT compiled — `swi 0x900018` returns EFAULT (-14) |
| n_hdlc line discipline | Not compiled — only `n_tty` and `input` ldiscs registered |
| prctl PR_SET_MM | All options EPERM (needs CAP_SYS_RESOURCE) |
| /proc/sys/* writes | ALL blocked by DAC/SELinux from shell |
| SUID/SGID binaries | NONE exist on the device |
| setsockopt netfilter (IPT_SO_SET_*) | EPERM (requires CAP_NET_ADMIN) |
| SO_BINDTODEVICE / SO_MARK | EPERM (requires CAP_NET_ADMIN) |
| PHONET/PNPipe sockets | SELinux EPERM on all (dgram, pipe, raw) |
| PPPoX sockets | SELinux EPERM on all (OE, L2TP, PPTP, OLAC, OPNS) |
| NETLINK_KOBJECT/GENERIC/AUDIT | SELinux EPERM |
| PF_KEY / XFRM sockets | EPERM |
| Property writes (persist.*, sys.*) | Most blocked; exception: `sys.powerctl` triggers reboot |
| Writable system/vendor files | None found — filesystem read-only |
| Cron / scheduled tasks | No cron on Android |
| Kernel module loading | Monolithic kernel, no /proc/modules |
| Symlinks in /data/log | SELinux blocks symlink creation (EPERM) |
| Mali JIT softjobs | UK reports 10.0; all `MEM_JIT_INIT` variants fail and `SOFT_JIT_ALLOC/FREE` return `JOB_INVALID (0x4003)` |
| Mali HWCNT_SETUP | Returns EFAULT (errno=14) from shell — security-gated regardless of dump_buffer value; uk_ret=522 (ID unchanged) confirms kernel rejected before writing return code. `src/mali/mali_samsung_ioctl_probe.c` confirms. |
| Samsung vendor Mali IOCTLs (CREATE_SURFACE, DESTROY_SURFACE, SECURE_WORLD_RENDERING) | CREATE_SURFACE→`kbase_mem_set_max_size`, DESTROY_SURFACE→`kbase_mem_free_list_cleanup`, SECURE_WORLD_RENDERING→SMC call. All three are no-ops: free_list ops gated on `#ifdef R7P0_EAC_BLOCK` AND only flush when list>16384 entries; secure_world gated on `kbdev->secure_mode_support==true` (false on this device). All return uk_ret=0 unconditionally. Confirmed dead ends. |
| Binder addService (handle exchange) | BR_FAILED_REPLY for shell (UID 2000); SecurityException for untrusted_app (UID 10139). Both domains lack `add` permission for `default_android_service`. Closes binder proc→files UAF race: shell cannot be a binder server, so no BINDER_TYPE_FD can be sent to trigger the files_struct race. |
| timerfd CVE-2017-10661 | PATCHED in Samsung kernel. `timerfd_setup_cancel` and `timerfd_remove_cancel` both acquire per-ctx `cancel_lock` before list operations — serializing setup/release. Race window eliminated. Natural CLOCK_REALTIME change rate ~1200–1700/sec confirms no CAP_SYS_TIME would be needed, but the race is patched regardless. timerfd_ctx→kmalloc-192, wqh.lock@104, might_cancel@156. |

---

## DRParser (Post-Root Goldmine)

- **Package**: `com.sec.android.app.parser`, UID 1000 (system)
- **Permissions**: AT_COMMAND, QCOM_DIAG, INSTALL_PACKAGES, MASTER_CLEAR, MODIFY_IPTABLES, MODIFY_PHONE_STATE
- **DM port**: Accessible on COM11 (was COM9, was COM5 — changes on USB disruption)
- **SecretCodeIME**: Protected by "normal" level permission (any app can request)
- **RSA private key**: In APK assets (keystring encryption reversible)
- **Keystring XML**: Loadable from `/sdcard/keystrings_EFS.xml` — potential custom keystring injection
- **UART switch**: `uart_sel=AP, uart_en=0` — requires root to toggle
- **DIAG daemon**: Running as system UID, proxies USB↔modem
- **Post-root value**: Can modify iptables, install packages, master clear, read modem DIAG

---

## SELinux Policy Analysis — COMPLETED

> **Parsed**: 10,896 of 29,594 avtab entries (37%) — remaining are xperms/IOCTL rules irrelevant to domain transitions
> **Method**: Custom C tool using patched libsepol + pure Python binary reader
> **Coverage**: ALL type_transition rules, ALL regular allow rules from first 4822 entries + 6074 entries after xperms section

### Key Findings

| Finding | Status | Impact |
|---------|--------|--------|
| Permissive types | ❌ **NONE** | No free bypass |
| Domain transitions from shell | ❌ **Only `runas`** | Dead end (see below) |
| Domain transitions from untrusted_app | ❌ **Only devpts** (file label, not domain) | Dead end |
| `su` domain | ❌ **DOES NOT EXIST** | Only `su_exec` file type exists |
| `rd_shell` domain | ❌ **DOES NOT EXIST** | Only `rd_shell_exec` file type exists |
| Transitions to kernel/init/recovery | ❌ **NONE** from any reachable domain | No multi-hop chains |
| Transitions to system_server | ❌ **NONE** from any reachable domain | No multi-hop chains |

### Shell Domain Transitions
```
type_transition shell runas_exec:process runas;   # run-as binary
type_transition shell tmpfs:file shell_tmpfs;      # file label only
```
**`runas` is a dead end**: Can read app data dirs and query security server, but has NO capabilities, NO execute permissions, NO transitions to elevated domains.

### Shell Allow Rules (66 total)
- Can execute 16 `*_exec` file types — ALL with `execute_no_trans` (stays in shell domain)
- Cannot execute `diagexe_exec`, `at_distributor_exec`, `su_exec`, `rd_shell_exec`
- Can read `persist_data_file`, `sysfs_lowmemorykiller`, `dumplog_data_file`
- Has rawip_socket, unix_dgram_socket, netlink_route_socket, netlink_selinux_socket on self
- Can set `csc_prop` and `shell_prop` only

### `su_exec` Rules (file type only, no domain)
```
auditdeny domain su_exec:file 0x00000000;           # deny all from all
allow root_detect su_exec:file 0x00000010;           # search only
allow at_distributor su_exec:file 0x00100053;         # read/open/getattr
```

### `rd_shell_exec` Rules (file type only, no domain)
```
allow kernel rd_shell_exec:file 0x00000100;           # kernel only
allow init rd_shell_exec:file 0x00102012;             # init only
```
**Both su and rd_shell are orphan file types** — no corresponding domain exists in the policy, so even if these binaries were executable, no transition would occur.

### diagexe SELinux Restrictions (8 allow rules only)
Despite having CAP_SYS_ADMIN + CAP_DAC_OVERRIDE at the Linux level, diagexe is tightly restricted by SELinux:
- File: `sysfs_ss_writable`, `media_rw_data_file` only
- Device: `ssipc_device` (chr_file) only
- Socket: rawip_socket (self), netlink_route (self), unix_stream to init
- **No binder access**, **no capability rules**, **no execute on any exec type**
- **Exploitation value reduced**: Code execution in diagexe is SELinux-jailed

### Bluetooth Domain (52 allow rules)
- `capability: net_admin` — more than shell has
- `rawip_socket`, `packet_socket`, `tun_socket` — full permissions on all
- Can connect to: `mwirelessd`, `secure_storage`, `qmuxd`, `init` unix sockets
- `capability2: wake_alarm`
- **Has more kernel attack surface than shell** — packet_socket gives raw L2 access
- **BlueBorne value CONFIRMED**: bluetooth domain has useful kernel primitives

### Samsung Domain Comparison
| Domain | Allow Rules | Capabilities | File Rules | Socket Rules |
|--------|------------|-------------|------------|-------------|
| untrusted_app | 52 | 0 | 12 | 7 |
| sec_untrusted_app | 70 | 0 | 14 | 17 |
| carrier_app | 103 | 0 | 33 | 12 |
| platform_app | 79 | 0 | 17 | 16 |
| sysaccess_platform_app | 77 | 0 | 16 | 17 |
| shell | 66 | 0 | 33 | 5 |

**No Samsung app domain has capabilities** — all are sandboxed equally at the capability level. `carrier_app` has the most rules but only for broader file/directory access, not privilege escalation.

### Domain Entrypoints
Only 2 found: `recovery <- healthd`, `recovery <- kernel`. No reachable entrypoints.

### Process Transition Permissions
- `platform_app -> sysaccess_platform_app:process` (only cross-domain transition found)
- All other domains have only self-transitions
- **No reachable domain can transition to any elevated domain**

### Conclusion
**SELinux policy is a CONFIRMED DEAD END for privilege escalation.** No domain transition path exists from shell or untrusted_app to any elevated domain. The policy is well-constructed with no permissive types, no orphan transitions, and no exploitable domain chains.

---

## TIMA (TrustZone Integrity Monitoring)

- Samsung TrustZone-based kernel integrity measurement
- MobiCore daemon (PID 2182) manages TEE operations
- Runs every 5 minutes via `TIMA_MEASURE_KERNEL_ONDEMAND`
- Verifies: kernel code integrity, SELinux enforcement status, SEAndroid
- **Leaks physical addresses** via dmesg accessible to shell and app
- Any write to `selinux_enforcing` detected within 5 minutes → device lockdown
- Must be neutralized BEFORE or simultaneously with SELinux disable for persistent root

---

## dnsproxyd Protocol (netd = root, ALL capabilities)

- Socket: `/dev/socket/dnsproxyd` (SOCK_STREAM)
- Protocol: FrameworkListener, commands null-terminated, NO sequence numbers
- Commands:
  - `getaddrinfo host service family socktype proto flags netid\0` (8 args)
  - `gethostbyname netid host af\0` (4 args)
  - `gethostbyaddr netid addr addrlen af\0` (5 args)
- `^` means NULL for service argument
- Format strings (%p, %n): NOT exploitable — treated as literal hostnames
- No crash on: 256-byte hostname, negative values, INT_MAX, buffer overflow attempts
- netd stayed alive through all fuzzing

---

## Build System

### C Binaries (ARM32)
```bash
# From Windows (uses WSL):
.\qemu\build-arm.bat src\file.c output_name
# Equivalent WSL command:
arm-linux-gnueabi-gcc -static -pie -fPIE -o output source.c -lpthread
# Deploy:
adb push compiled/output /data/local/tmp/ && adb shell chmod 755 /data/local/tmp/output
```

### APK (com.privesc.agent)
```bash
# Compile Java:
javac -source 1.8 -target 1.8 -classpath android.jar -d build/classes src/**/*.java
# DEX:
java -jar d8.jar --output build/ build/classes/**/*.class
# Package:
aapt package -f -M AndroidManifest.xml -I android.jar -F build/unsigned.apk
# CRITICAL: copy classes.dex to root (aapt add preserves full path):
copy build\classes.dex .\classes.dex
aapt add build/unsigned.apk classes.dex
# Sign:
apksigner sign --ks debug.keystore --ks-pass pass:android -out build/signed.apk build/unsigned.apk
# Deploy:
adb shell am force-stop com.privesc.agent
adb install -r build/signed.apk
```

### ION Struct (ARM32 — CRITICAL)
```c
// CORRECT for ARM32 (size_t = 4 bytes):
struct ion_allocation_data {
    uint32_t len;           // allocation length
    uint32_t align;         // alignment
    uint32_t heap_id_mask;  // which heap (bit 0 = system, bit 2/12 = CRASH)
    uint32_t flags;         // allocation flags
    uint32_t handle;        // output: handle
};  // 20 bytes total, then ION_IOC_SHARE to get fd

// WRONG (causes heap_id_mask misalignment → secure heap → kernel crash):
struct { uint64_t len; uint64_t align; ... };  // 28+ bytes
```

---

## Slab Cache Layout

| Cache | Size | Contents |
|-------|------|----------|
| kmalloc-64 | 52-64B | ION handles, Mali tracking, pipe_buffer[2], buffer_head |
| kmalloc-128 | 65-128B | Binder metadata |
| kmalloc-192 | 129-192B | ION buffers, binder metadata, **binder_thread (via epoll_ctl)** |
| kmalloc-256 | 193-256B | **binder_thread** (252 bytes, via BC_ENTER_LOOPER), BPF sk_filter (26 insns) |
| kmalloc-512 | 257-512B | readv iov array (iovcnt 33-64) |

> Note: binder_thread goes to kmalloc-192 when created via binder_poll in epoll_ctl (without BC_ENTER_LOOPER), and kmalloc-256 when created via normal BINDER_THREAD_EXIT path. The 252-byte kzalloc is confirmed from disassembly.

---

## Remaining Attack Vectors (Priority Order)

> **As of 2026-03-11:** All 13 kernel/driver/service vectors are exhausted or dead. The only surviving non-kernel vector is **Accessibility UI automation** (#2). The device has resisted 17+ CVE tests, 230+ source probes, and extensive driver fuzzing. All content providers are gated. See the table below for full disposition.

| # | Vector | Feasibility | Impact | Notes |
|---|--------|-------------|--------|-------|
| ~~1~~ | ~~**Binder proc→files UAF race**~~ | ~~N/A~~ | ~~DEAD END~~ | addService is BLOCKED for BOTH shell (BR_FAILED_REPLY) and untrusted_app (SecurityException). Shell cannot register as a binder server, so no sender can issue BINDER_TYPE_FD to trigger the files_struct UAF. Handle exchange mechanism is definitively exhausted for all contexts. |
| 2 | **Accessibility UI automation** | HIGH (already active) | Varies | Can interact with all windows. Could automate privileged UI actions, drive factory codes, etc. |
| ~~3~~ | ~~timerfd race (CVE-2017-10661)~~ | ~~N/A~~ | ~~PATCHED~~ | Samsung added per-ctx `cancel_lock` spinlock to `timerfd_ctx`. Both `timerfd_setup_cancel` and `timerfd_remove_cancel` acquire `ctx->cancel_lock` before list operations — serializing the setup/release race window. Natural CLOCK_REALTIME change rate is ~1200–1700/sec (no CAP_SYS_TIME needed), but the race itself is patched. Samsung `timerfd_ctx` struct differs from mainline: union{hrtimer, alarm} at offset 0 (88 bytes), wqh.lock@104, might_cancel@156, total~160 bytes → kmalloc-192. |
| ~~4~~ | ~~DRParser keystring injection~~ | ~~N/A~~ | ~~DEAD END~~ | Fully closed 2026-03-08: (1) `KeyStringUpdateReceiver` is dead code — never registered anywhere (no `<receiver>` in manifest, never instantiated dynamically). (2) `ParseService$1` handles SECRET_CODE broadcast but does nothing with it (only reacts to `SET_FACTORY_SIM_MODE`). (3) `ParseService$2` Messenger calls `process(keystring)` but `isKeyStringBlocked()` returns `true` unless a factory JIG cable is physically connected (`/sys/class/sec/switch/attached_dev` must return "JIG"). (4) Setting `isReceivedFactoryModeIntent=true` via broadcast only bypasses `isFactorySim()` check, NOT the JIG check. Requires factory hardware — permanently blocked without JIG cable. |
| ~~5~~ | ~~Bluedroid userspace Bluetooth RE~~ | ~~N/A~~ | ~~DEAD END~~ | Samsung backported UUID validation, ctrl type checks, packet length checks. PANU→NAP path exhausted: tablet rejects all host-originated SETUP_CONN_REQ traffic with CONN_NOT_ALLOWED. |
| ~~6~~ | ~~DM port DIAG binary protocol~~ | ~~N/A~~ | ~~DEAD END~~ | All 256 command bytes tested (Phase 4 of dm_fuzz.py), size up to 65535, format strings, delimiter abuse — zero crashes, diagexe PID stable. diagexe SELinux jail has only 8 allow rules; even code exec offers limited escalation. COM port now COM8 (changes on USB disruption). AT command surface (COM8): 180+ commands enumerated, all overflow candidates return CME ERROR: 50 (input validation), AT+CNUM with 512-byte arg silently dropped. CFUN=0 with no SIM blocks most commands. Shannon modem AT commands affect CP only, not AP kernel — not useful for UID 0. |
| ~~7~~ | ~~Mali alias TOCTOU / reclaim~~ | ~~N/A~~ | ~~EXHAUSTED (no kernel write primitive)~~ | Same-context controlled injection CONFIRMED (seeded page executes as JC, zeroes user-space targets). Cross-pool ION DISJOINT. Cross-process Mali reclaim DISJOINT (per-context pool isolation). Stale alias GPU writes return DONE but go nowhere (PTEs invalidated on free). No kernel write primitive reachable via Mali from userspace. |
| ~~8~~ | ~~Factory app broadcast~~ | ~~N/A~~ | ~~REDUCED~~ | Broadcast accepted but factory AT handlers unreachable. Socket /data/.socket_stream is system:system 0700. |
| ~~9~~ | ~~SELinux policy domain transitions~~ | ~~N/A~~ | ~~DEAD END~~ | No transitions from shell. No su/rd_shell domains. No permissive types. |
| ~~10~~ | ~~CVE-2016-6786 (perf SET_OUTPUT race)~~ | ~~N/A~~ | ~~PATCHED~~ | 7000 iterations clean. |
| ~~11~~ | ~~CVE-2017-6001 (perf move_group race)~~ | ~~N/A~~ | ~~PATCHED~~ | 10,000+ iterations clean. |
| ~~12~~ | ~~DCCP kernel surface~~ | ~~N/A~~ | ~~DEAD END~~ | SELinux blocks from ALL reachable contexts. |
| ~~13~~ | ~~Content provider / socket abuse via APK~~ | ~~N/A~~ | ~~DEAD END~~ | All top OEM provider candidates live-probed 2026-03-11: MTContentProvider (not exported, UID 1000), SoContentProvider (not exported, UID 1000), ExternalOEMControlProvider (custom sig perms, UID 5009), OpenContentProvider (custom sig perms). SOAgent MasterLogProvider also not exported (obfuscated authority `com.sec.android.log.gnj0zk4j42`). Knox SecContentProvider/SecContentProvider2 gated by `MDM_CONTENT_PROVIDER` (prot=normal but runtime enforcement blocks shell). untrusted_app has FEWER socket permissions than shell. |

---

## New Leads (2026-03-11 web research)

> These emerged from structured web research after all 13 original vectors were exhausted. The common theme: **the ION UAF 91% race win is still the best primitive** — the missing piece is a viable victim object in kmalloc-64.

### Lead A: `pipe_buffer` as kmalloc-64 victim (~~HIGH~~ **LOW PRIORITY — wrong slab**)

**Thesis**: ~~pipe_buffer on ARM32 kernel 3.10 is 40 bytes → lands in kmalloc-64~~. **DISPROVED**: pipe_buffer is 24 bytes on ARM32 but allocated as a contiguous 16-element array (16 × 24 = 384 bytes → kmalloc-512). Cannot be used to spray kmalloc-64.

**Chain**:
1. Win ION UAF race (91% — already have this)
2. Spray kmalloc-64 with `pipe_buffer` structs (`pipe()` + `write()` to fill pipe pages)
3. Corrupt `pipe_buffer->page` to point at target `thread_info`
4. Write `0x00000000` to offset 8 (`addr_limit`) via pipe write → sets `KERNEL_DS`
5. With `KERNEL_DS`, use `copy_to/from_user` to r/w all kernel memory
6. Zero `selinux_enforcing` at `0xC0B7AD18`, then `commit_creds(prepare_kernel_cred(0))`

**Status**: UNTESTED. Need to verify: (a) `pipe_buffer` size on this kernel, (b) whether pipe_buffer allocations land in the same kmalloc-64 slab as ION freed objects, (c) which field offset controls the `page` pointer.

**References**:
- [Interrupt Labs: pipe_buffer arbitrary read/write](https://www.interruptlabs.co.uk/articles/pipe-buffer)
- [USENIX Security 2024: Defects-in-Depth](https://www.usenix.org/system/files/usenixsecurity24-maar-defects.pdf)
- [cloudfuzz/android-kernel-exploitation](https://github.com/cloudfuzz/android-kernel-exploitation/blob/master/gitbook/chapters/exploitation.md)

### Lead B: `fasync_struct` as kmalloc-64 victim (MEDIUM PRIORITY)

**Thesis**: `fasync_struct` is ~48 bytes on ARM32, contains `fa_file` pointer and is linked via `fa_next`. Created via `fcntl(fd, F_SETFL, O_ASYNC)` + `fcntl(fd, F_SETOWN, pid)`. If the ION UAF overwrites a freed `fasync_struct`, and then `kill_fasync()` is triggered, it follows the corrupted `fa_file` pointer — potential controlled call.

**Status**: UNTESTED. Need to verify struct size and whether it's exploitable on 3.10.

### Lead C: `signalfd_ctx` as kmalloc-64 victim (MEDIUM PRIORITY)

**Thesis**: `signalfd_ctx` is ~64 bytes, created via `signalfd()` syscall. Contains `sigmask` and list pointers. Corruption could enable controlled kernel list operations.

**Status**: UNTESTED. Lower priority than pipe_buffer since no direct fn-ptr, but worth auditing.

### Lead D: `msg_msg` header spray (MEDIUM PRIORITY)

**Thesis**: `msgsnd()` allocations can be precisely sized to land in kmalloc-64. The `msg_msg` header contains `m_list`, `m_type`, `m_ts`, and `next`/`security` pointers. Corrupting `next` can chain to arbitrary read via `msgrcv()` with `MSG_COPY` flag (if available on 3.10).

**Status**: UNTESTED. `MSG_COPY` may not be available on 3.10; needs verification.

**References for all**:
- [CodeBlue 2023: Deep Kernel Treasure Hunt — systematic exploitable struct catalog](https://archive.codeblue.jp/2023/result/pdf/cb23-deep-kernel-treasure-hunt-finding-exploitable-structures-in-the-linux-kernel-by-yudai-fujiwara.pdf)
- [BlackHat EU 2021: Art of Exploiting UAF by Ret2bpf](https://i.blackhat.com/EU-21/Wednesday/EU-21-Jin-The-Art-of-Exploiting-UAF-by-Ret2bpf-in-Android-Kernel.pdf)
- [Lexfo: CVE-2017-11176 step-by-step exploitation](https://blog.lexfo.fr/cve-2017-11176-linux-kernel-exploitation-part3.html)
- [Linux kernel heap feng shui 2022](https://duasynt.com/blog/linux-kernel-heap-feng-shui-2022)

### Lead E: CVE-2024-44068 m2m1shot scaler (~~LOW~~ **HIGH PRIORITY — driver confirmed present**)

**Thesis**: Samsung m2m1shot_scaler0 PFNMAP UAF was exploited in the wild on newer Exynos (7420+). **The device nodes `/dev/m2m1shot_scaler0`, `/dev/m2m1shot_scaler1`, and `/dev/m2m1shot_jpeg` ALL EXIST on this Exynos 3475 device.** Kernel source analysis confirms the `VM_PFNMAP` check is ABSENT in `m2m1shot_buffer_check_userptr()` — the exact CVE-2024-44068 vulnerable pattern.

**Access gate**: Device is `media:graphics 0660`, SELinux label `u:object_r:m2m1shot_device:s0`. Shell (UID 2000) cannot open directly. Mediaserver (UID `media`, SELinux `mediaserver`) CAN access it. The question is whether untrusted_app can trigger mediaserver to use m2m1shot on attacker-controlled buffers via the standard Android MediaCodec/camera API surface.

**Attack chain concept**:
1. App creates a PFNMAP-backed VMA (e.g., via ION mmap or GPU mmap)
2. App triggers media processing (MediaCodec, image scaling) that causes mediaserver to pass the buffer to m2m1shot
3. m2m1shot accepts the PFNMAP buffer without checking VM_PFNMAP flag
4. Race condition: app unmaps the buffer while m2m1shot still holds a reference
5. Freed physical pages get reallocated → UAF in mediaserver/kernel context
6. Escalate from mediaserver (UID media) toward root

**Status**: CONFIRMED PRESENT but ACCESS GATED. Shell and untrusted_app cannot open directly (DAC: media:graphics 0660). `libhwjpeg.so` opens `/dev/m2m1shot_jpeg`, `libexynosscaler.so` opens `/dev/m2m1shot_scaler0-3`. SurfaceFlinger (UID 1000, GID 1003/graphics) confirmed loading `libexynosgscaler` during display composition. Mediaserver (UID 1013/media) can open via DAC owner. Camera photo capture triggers `libexynosgscaler` in surfaceflinger but shell cannot observe mediaserver FD usage (permission denied on `/proc/<mediaserver_pid>/fd`). **The vulnerability code is confirmed present but reaching it requires either (a) code exec in media/surfaceflinger context first, or (b) a novel way to make mediaserver pass attacker-controlled USERPTR buffers to m2m1shot — which the standard Android media framework does NOT do (it uses DMABUF).**

---

## Source Files Reference

### Key Exploit Code (in `src/`)

| File | Purpose | Key Result |
|------|---------|------------|
| **bluborne_efs_overflow.py** | **CVE-2017-0782 corrected exploit with EFS amplification** | **READY — needs Kali + BT proximity** |
| bluborne_hci.py | CVE-2017-0782 via raw HCI (most complete of originals) | Handles full signaling but lacks EFS amplification |
| bluborne_pwn.c | CVE-2017-0782 C version with raw L2CAP | Raw socket approach, needs SCID fix |
| bluborne_l2cap.c | CVE-2017-0782 HCI ACL injection | Doesn't handle target responses |
| bluborne_exploit.py | CVE-2017-0782 pybluez framework | Dry-run only, connectivity test |
| bluborne_scapy.py | CVE-2017-0782 via Scapy | Sends on data CID not signaling |
| bluborne_v3.py | CVE-2017-0782 hcitool + raw L2CAP | Kernel auto-handles config |
| cve_2017_0782.py | CVE-2017-0782 original exploit | MTU-only overflow, no raw socket |
| cve_2019_2215_hang.c | Definitive CVE-2019-2215 test with VALID BPF spray | Samsung patched (0 hangs) |
| cve_2016_6786_race.c | CVE-2016-6786 perf SET_OUTPUT race detector | **PATCHED** (7000 clean) |
| cve_2017_6001_race.c | CVE-2017-6001 perf move_group race detector | **PATCHED** (10K+ clean) |
| perf_event_probe.c | Comprehensive perf_event_open surface test | SW counters + mmap + groups work |
| perf_kaddr_leak.c | Kernel address leak via perf sampling | Kernel IPs excluded from samples |
| new_cve_probe.c | Multi-CVE surface (DCCP, timerfd, UDP, netlink, proc) | timerfd works, DCCP SELinux-blocked |
| dccp_probe.c | DCCP+MobiCore+socket test for untrusted_app domain | All blocked from APK too |
| socket_scan.c | Comprehensive socket connectivity scanner | APK has FEWER perms than shell |
| dnsproxyd_probe4.c | Final working netd protocol probe | Protocol reversed, no crash |
| mali_safe_probe.c | Corrected Mali+ION probe (fixed ARM32 struct) | Mali clean, ION struct was bug |
| ion_race_free_share.c | ION UAF race exploit | 91% win, no code exec |
| socket_probe.c | Abstract/filesystem socket connectivity test | All abstract BLOCKED |
| service_deep_probe.c | 15 high-value binder service prober | Ready for deployment |
| deep_race_fuzz.c | tee() deadlock discovery | ABBA deadlock confirmed |
| samsung_deep_probe.c | Samsung-specific deep probing (8 tests) | ION_IOC_CUSTOM=ENOTTY, mremap works |
| mali_race_fuzz.c | Mali GPU race fuzzer (8 tests, 1150 trials) | 0 anomalies |
| mali_job_submit_probe.c | Live Samsung JOB_SUBMIT ABI probe | 32-byte submit struct + 56-byte atom confirmed |
| mali_write_value_probe.c | Live write-value descriptor probe | Valid primitive is 8-byte zero-write to GPU VA |
| mali_jit_probe.c | JIT capability probe | JIT softjobs unsupported on UK 10.0 (`JOB_INVALID`) |
| mali_chain_corrupt_probe.c | Ordered atom self-corruption probe | Earlier WRITE_VALUE can corrupt later JC page and deterministically fault atom2 |
| mali_atom_metadata_probe.c | Shared atom-buffer metadata probe | Submitted atom metadata is copied at submit time |
| mali_jc_matrix_probe.c | Later-JC qword sweep | Only certain JC qwords are still live when later atom executes |
| mali_jc_chain_probe.c | Multi-descriptor JC chain probe | A single atom can run chained descriptors; later chain elements remain live enough to fault selectively |
| mali_mtp_probe.c | MTP/special-handle probe | MTP read faults on CPU; low targets 0x2000/0x3000 are not valid WRITE_VALUE GPU VAs |
| ptmx_race_fuzz.c | PTMX/TTY race fuzzer (7 tests, 700 trials) | 0 anomalies |
| bpf_filter_race.c | BPF sk_filter cleanup race (7 tests) | SLUB noise, not real leak |

### APK Components (in `work/privesc_apk/`)

| Component | Purpose |
|-----------|---------|
| CommandReceiver.java | Broadcast command dispatch (help, info, enable_app, exec, probe_kernel, dccp_test, bind_smartcom) |
| DeepProbeService.java | Background service: sockets, content providers, DLP, PackageInstaller |
| AndroidManifest.xml | 54 permissions, device admin, accessibility service, debuggable |

---

## Findings Reports (in `findings/`)

| Report | Key Content |
|--------|-------------|
| deep-attack-surface-session12.md | Session 12: perf_event, factory broadcasts, DCCP, timerfd, slab cache |
| comprehensive-recon-session10.md | 17+ findings from deep recon |
| smartcomroot-at-commands-session10h.md | SmartcomRoot, AT commands, dnsproxyd, TIMA leak |
| dm-port-system-recon-session10f.md | diagexe, at_distributor, DM protocol |
| deep-recon-session10g.md | Secret codes, ABT RE, platform key |
| drparser-security-assessment.md | DRParser permissions, DM port, keystrings |
| bluetooth-bluborne-audit.md | BlueBorne vulnerability assessment |
| **bluborne-l2cap-protocol-re.md** | **Complete L2CAP protocol RE, EFS amplification discovery, exploit audit** |
| mali-vendor-dispatch-vuln.md | Mali crash analysis (later CORRECTED — was ION bug) |
| ion-exploit-status.md | ION UAF analysis (NOTE: seq_operations claim is WRONG) |
| ion-uaf-verification.md | ION UAF confirmation (97% win, mmap+write works) |
| final-security-report.md | Overall assessment summary |

---

## Session History

| Session | Date | Focus | Key Outcomes |
|---------|------|-------|-------------|
| 1-2 | 2026-02-25 | Initial recon, CVE testing | 9 CVEs tested, device profiled |
| 3 | 2026-02-25 | Service mode, Knox, properties | All Samsung services secured |
| 4 | 2026-02-25 | App-context escalation | Custom APK deployed, accessibility+admin active |
| 5 | 2026-02-25 | CVE-2019-2215 + Mali | Binder UAF confirmed, Mali false positives corrected |
| 6 | 2026-02-25 | Network, DRParser, BlueBorne | BlueBorne likely vuln, DRParser goldmine |
| 7 | 2026-02-25 | Zero-day race fuzzing | tee() ABBA deadlock found (DoS), 233M+ ops |
| 8 | 2026-02-25 | CVE-2019-2215 deep exploit | Samsung proprietary fix discovered |
| 9 | 2026-02-25 | Corrections + exhaustive fuzz | Mali false positive corrected, BPF spray fix, all clean |
| 10a-h | 2026-02-26 | Comprehensive deep recon | SmartcomRoot, DM port, diagexe, dnsproxyd, device owner, TIMA leak |
| 11 | 2026-02-27 | SELinux policy deep analysis | Built custom parser (patched libsepol + Python), parsed 10,896 rules. **SELinux = DEAD END**: no transitions from shell, no su/rd_shell domains, no permissive types. diagexe SELinux-jailed. BlueBorne value confirmed. |
| 12 | 2026-02-27 | Deeper attack surface discovery | **5 NEW vectors found**: (1) perf_event_open accessible (security.perf_harden=0 settable), CVE-2016-6786 PATCHED. (2) timerfd CANCEL_ON_SET works (CVE-2017-10661). (3) CSC_MODEM_SETTING broadcast accepted by factory app (UID 1000). (4) DCCP compiled but SELinux-blocked from shell. (5) /proc/slabinfo readable for heap spray optimization. |
| 13 | 2026-03-03 | BlueBorne L2CAP protocol RE + exploit | **EFS amplification technique discovered**: `l2cap_parse_conf_rsp()` writes 18-byte EFS output from 3-byte input (6× amplification). UNACCEPT path 60-byte limit → 270 bytes output → 206 bytes past buf[64]. Full L2CAP protocol spec documented. All 6 existing exploit files audited. Corrected exploit `bluborne_efs_overflow.py` created with UNACCEPT+EFS and PENDING paths. **Historical only**: later live testing showed Android 6.0.1 on this device keeps L2CAP in Bluedroid userspace, so the kernel path is not directly reachable here. |
| 14 | 2026-03-07 | Binder typed probing (ABT v2 + 3 new services) | ABT dead end finalized (all M26 → "Not authorized"). EngineeringMode dead end confirmed (signature-auth, not UID). PersonaManager mapped: 30 methods, reads work, writes blocked — M1/M2 return [type=7 name="INVALID"]; M26="default". DeviceRootKeyService decoded: status ints only. |
| **15** | **2026-03-08** | **Binder typed follow-up: gatekeeper, keystore, persona, SatsService, enterprise_policy** | **gatekeeper fully mapped to tx 1-5 only; typed `getSecureUserId` returns `0` for `uid 0/1000/10139`. keystore typed pass shows `UID_SELF` state `UNINITIALIZED`, empty alias lists, tested aliases `KEY_NOT_FOUND`, and no exportable material/token. Persona typed pass finds no candidate personas in the current app context and baseline `id=0` decodes to `INVALID/default/-1`. `enterprise_policy` is still mostly Knox/admin gated, but `M2` is now confirmed as the single admin `ComponentName` `com.privesc.agent/.AgentDeviceAdmin` and `M5(ComponentName)` returns `1`; `SatsService` binder is a dead end. Binder work is effectively exhausted.** |
| **16** | **2026-03-07** | **ABT M7+M13 confirmation, binder probing complete** | **FINAL ABT EXHAUSTION**: M7 `getAllApplicationProfiles` auth-gated identical to all other calls. M13 `invokeMethodAsSystem` with null spec → "Method Specification is null" (hits validation before auth — not exploitable). M13 with non-null spec → "Not authorized". M10 bypasses cert-auth but requires package in ABT OTA registry (populate path M5 is auth-gated). All 26 ABT methods fully confirmed dead. Binder probing phase complete — pivot to Mali TOCTOU or DRParser. |
| **17** | **2026-03-08** | **BlueBorne userspace BNEP reverse-engineering** | **Confirmed the live Bluetooth target is `bluetooth.default.so`, not kernel `l2cap_parse_conf_rsp()`. Headless Ghidra decompilation of `bnep_process_control_packet()` / `bnep_process_setup_conn_req()` shows strict setup/filter validation, filter consumers show no obvious count/serializer overflow, and the `BNEP_Write*` nonzero-flag path is only extension-header normalization during PAN forwarding. The remaining live leads are both valid-frame logic bugs: (1) a deferred residual-control buffer saved after `SETUP_CONN_REQ` appears to be cleared on release/timeout without an obvious free, and (2) a second valid `SETUP_CONN_REQ` can plausibly overwrite live UUID state before the async auth/app callback completes.** |
| **18** | **2026-03-08** | **Live PAN bring-up via hidden BluetoothPan + persistent host NAP** | **The device-owner APK can now drive hidden `BluetoothPan` APIs from `DeepProbeService`: `setBluetoothTethering(true)` succeeds, `connect(28:16:AD:8B:87:AF)` reaches `state=2`, and the old `ReceiverCallNotAllowedException` path is gone. On the host side, short-lived `NetworkServer1.Register("nap","pan1")` calls were the reason for earlier `bridge not initialized` failures: BlueZ drops the bridge when the registering D-Bus client exits. Keeping a D-Bus client alive makes the PAN connection stick and host `bluetoothd` logs `bnep: bridge pan1: interface bnep0 added`. The remaining blocker is that once bluetoothd owns the live NAP service, an out-of-band root L2CAP listener and raw-HCI server probe do not receive the BNEP socket, so a custom BlueZ profile/server path is now the best next Bluetooth step.** |
| **19** | **2026-03-08** | **Custom BlueZ `Profile1` socket ownership + reverse BNEP injection** | **A repo-local host script, `src\bluetooth\bnep_bluez_profile_probe.py`, now registers the NAP UUID on PSM `0x000f` against a custom `bluetoothd -P network`, receives `org.bluez.Profile1.NewConnection(fd)`, captures the tablet's inbound setup request (`01010211161115`), and can answer it with a chosen `SETUP_CONN_RSP`. After sending a success response, the host-owned socket sees live follow-on BNEP traffic. A first host-initiated valid setup-request test over that accepted socket caused the tablet to log `bt_bnep: BNEP - Rcvd conn cnf with error: 0x2` and drop the PAN session, proving the host can now inject BNEP control packets back into the tablet on the PANU→NAP path. The socket-ownership blocker is therefore solved; the remaining Bluetooth question is how to adapt/interpret the double-setup and deferred-tail experiments on this accepted-socket direction.** |
| **20** | **2026-03-08** | **Accepted-socket double-setup / deferred-tail live adaptation** | **The accepted-socket host harness now supports shared UUID parsing, host-originated setup A/B packets, large extension-tail injection, and timed close-after-probe behavior. Live results narrow the Bluetooth lane sharply: (1) after a normal host success response, sending host-originated setup A=`1116:1115` and setup B=`1234:5678` yields two tablet `SETUP_CONN_RSP` packets `01020004` (`CONN_NOT_ALLOWED`); (2) if the host sends setup A/B before replying to the tablet's own request, the tablet logs `BNEP - setup request when we are originator` twice and still returns `CONN_NOT_ALLOWED`; and (3) a host-originated `SETUP_CONN_REQ` with a ~640-byte valid extension tail is likewise rejected with `CONN_NOT_ALLOWED`, with no Bluetooth-daemon crash or parser instability observed. Conclusion: the PANU→NAP `Profile1.NewConnection(fd)` path does **not** appear to reach the pending setup/auth windows behind the original double-setup or deferred-tail hypotheses, so further Bluetooth work likely requires a different role/path or a pivot back to the best non-Bluetooth fallback.** |
| **21** | **2026-03-08** | **Mali disjoint reuse timing confirmed** | **A new probe, `src\mali\mali_alias_reuse_timing_probe.c`, now measures how predictably the alias free/shrink race's freed pages recycle once the stale alias VA window is pinned back down with `commit=0`. Live results on SM-T377A were strongly positive: the race won `16/20` times, the stale alias window re-reserved cleanly on all wins, and the very first disjoint 8-page allocation (`0x102018000` in the live run) reclaimed all 8 tagged source pages on every win. This means immediate, fully disjoint page reuse is now confirmed, so the next Mali question is no longer "can we reclaim the pages?" but "can we drive controlled attacker content through that reclaim into a GPU-consumed control surface?"** |
| **22** | **2026-03-08** | **Mali controlled-content injection confirmed** | **A new follow-up probe, `src\mali\mali_alias_controlled_injection_probe.c`, now seeds attacker-controlled WRITE_VALUE JC content into a reclaimed alias-race page, frees that reclaim buffer, and waits for the seeded page to reappear inside a later victim allocation. Live result on the first attempt was positive: the race won, the stale alias window re-pinned cleanly, reclaim alloc `0x102019000` exposed tagged pages `0..6`, the probe seeded reclaim page `0` / source page `6`, the very first victim allocation preserved that seed on page `7`, and submitting that preserved page as JC returned `DONE` while zeroing scratch target `0x102018000`. Conclusion: same-context controlled-content injection through alias+reclaim is now real; the next question is whether a surviving consumer can ingest the same seeded content without direct JC resubmission.** |
| **23** | **2026-03-08** | **Mali indirect chain consumer confirmed** | **A new follow-up probe, `src\mali\mali_alias_chain_consumer_probe.c`, now proves a non-direct consumer on top of the same reclaim primitive. Live result on the first attempt was again positive: the race won, the stale alias window re-pinned cleanly, reclaim alloc `0x10201a000` exposed tagged pages `0..5`, the probe seeded reclaim page `0` / source page `5`, the first victim allocation preserved that seed on page `7`, and a separately submitted local head descriptor followed its `next` pointer into that preserved victim page. The job returned `DONE` while zeroing both scratch target `0x102018000` and dest target `0x102019000`. Conclusion: attacker-seeded reclaimed content is now confirmed as a later chain descriptor consumer; the next question is whether an imported or driver-retained consumer can ingest the same seeded content.** |
| **24** | **2026-03-08** | **Mali × ION cross-pool test: DISJOINT** | **A new probe, `src\mali\mali_alias_ion_cross_pool_probe.c`, tests whether physical pages freed from a Mali allocation after the alias race can be reclaimed by fresh ION system-heap allocations. ION import JC baseline was first validated (requires `BASE_JD_REQ_EXTERNAL_RESOURCES` — plain import_gpu_va JC returns JOB_CANCELLED). 17/20 race wins, 17 seeds planted, 0 sentinel hits across 240 total ION allocations (12 per iteration). Conclusion: Mali and ION system-heap use **disjoint physical page pools** on this device; freed Mali pages do not appear in ION system-heap allocs. The imported/ION cross-pool consumer path is **closed**.** |
| **26** | **2026-03-09** | **Binder addService BLOCKED, timerfd PATCHED** | addService returns BR_FAILED_REPLY for shell, SecurityException for untrusted_app. timerfd CVE-2017-10661 patched with per-ctx cancel_lock. Both vectors closed. |
| **27** | **2026-03-11** | **Content provider audit + m2m1shot discovery** | Live-probed all top OEM providers (MT, SOAgent, SCloud, OpenContentProvider) — ALL gated. Updated STATUS.md with full provider dispositions. Discovered `/dev/m2m1shot_scaler0` EXISTS on Exynos 3475. Kernel source confirms CVE-2024-44068 PFNMAP UAF pattern (missing VM_PFNMAP check in `m2m1shot_buffer_check_userptr`). `libhwjpeg.so` → m2m1shot_jpeg, `libexynosscaler.so` → m2m1shot_scaler0-3. Access gated by DAC (media:graphics 0660). Standard media framework uses DMABUF not USERPTR, so the vulnerable USERPTR path requires media-context code exec first (two-bug chain). Built and deployed m2m1shot_access_probe (C + Java agent command). Confirmed surfaceflinger (GID 1003) uses libexynosgscaler during display composition. Lead parked pending mediaserver entry point. Web research also identified kmalloc-64 victim candidates (pipe_buffer DISPROVED: array alloc → kmalloc-512; fasync_struct → kmalloc-32; signalfd_ctx → 8 bytes). Remaining unexplored: systematic kmalloc-64 struct audit, QEMU m2m1shot DMABUF fuzzing. |
| **25** | **2026-03-08** | **Mali cross-process reclaim test: DISJOINT** | **A new probe, `src\mali\mali_alias_xprocess_reclaim_probe.c`, tests whether physical pages freed from one Mali context (after the alias race) can be captured by a DIFFERENT process's Mali context. After the seeder wins the race, seeds a page with JC_SENTINEL + WRITE_VALUE descriptor, and closes its mali0 fd (triggering `kbase_context_term()` → `kbase_mem_pool_term()` → per-context pool drain), a child process opens its own mali0 and allocates 40 fresh pages checking each for the sentinel. Result: `NO_HIT allocs=40` — zero sentinel pages found in the child context after the seeder context closed. Conclusion: freed Mali pages do NOT reach the OS page allocator in the window used by a concurrent child process; the Mali per-context pool architecture keeps pages isolated between contexts. Cross-process Mali reclaim is **closed**. The Mali attack surface is now exhausted at the userspace level. (Note: binder proc→files UAF was subsequently also closed — see session 26.)** |

---

## Session 15 Detailed Findings — gatekeeper / keystore / Knox binder pass

### gatekeeper (IGateKeeperService)

- Binder reachable from the installed APK context.
- Decompiled framework stub proves the real surface is only tx `1-5`:
  - `1=enroll`
  - `2=verify`
  - `3=verifyChallenge`
  - `4=getSecureUserId`
  - `5=clearSecureUserId`
- Typed follow-up corrected the earlier lossy decode:
  - `M1`/`M2`/`M3` were just reaching a present `GateKeeperResponse(ERROR)` when blindly called without a real enrolled-handle blob.
  - `M4(getSecureUserId uid=0|1000|10139)` returns `0` as a real `long`, not the earlier raw two-int `[0,0]` interpretation.
  - `M5` was not re-run in the typed pass because it mutates gatekeeper state.
- Conclusion:
  - reachable, but now fully downgraded to status-only from the present APK context.
  - no evidence of a writable setup path, credential verification primitive, or meaningful SID disclosure.

### keystore (IKeystoreService)

- Framework stub mapping is now recovered locally for tx `24-30`, and the follow-up pass switched to typed, read-only inputs instead of blind no-arg sweeps.
- Typed read results:
  - `M1(getState uid=-1)` => `3` (`UNINITIALIZED`)
  - `M1(getState uid=1000)` => `3` (`UNINITIALIZED`)
  - `M6(list prefix, uid=-1)` returns empty arrays for:
    - `""`
    - `USRPKEY_`
    - `USRSKEY_`
    - `USRCERT_`
    - `CACERT_`
- Seed alias follow-up:
  - `USRPKEY_0`
  - `USRSKEY_0`
  - `USRCERT_0`
  - `CACERT_0`
  - `0_android-keystore__RSA__1`
- All tested seed aliases return:
  - `M5(exist)` => `7` (`KEY_NOT_FOUND`)
  - `M19(getmtime)` => `-1`
  - `M16(get_pubkey)` => no byte array (`pubLen=-1`)
  - `M25(getKeyCharacteristics)` => `7` (`KEY_NOT_FOUND`) with only empty trailing characteristics payload
- Additional typed checks on `USRPKEY_0`:
  - `M27(exportKey format=0)` => `result=7`, `exportLen=0`
  - `M28(begin purpose=SIGN)` => `result=6` (`PERMISSION_DENIED`), no returned operation token, handle `0`
- Current interpretation:
  - the service is callable and the typed tx map is now understood, but the device-owner app does **not** appear to have any self-owned aliases in this keystore namespace.
  - no readable/exportable key material surfaced, and no valid operation token was obtained from `begin`.
  - keystore is no longer the top binder lead; remaining binder effort should prioritize typed `persona` reads and only small `enterprise_policy` follow-up decodes.

### persona (IPersonaManager)

- Typed follow-up replaced the earlier lossy no-arg sweep with exact read probes on the most useful mapped methods.
- Low-risk read results:
  - `M12(isFOTAUpgrade)` => `false`
  - `M13(needToSkipResetOnReboot)` => `false`
  - `M24(getMoveToKnoxStatus)` => `false`
- Candidate persona-id pass on `0`, `1`, `10`, `11`, `100`, `150`:
  - `M16(exists)` => `false` for every tested id
  - because none existed, `id=0` was used as the baseline decode
- Baseline `id=0` decode:
  - `M1(getState)` => present `PersonaState.INVALID`
  - `M2(getPreviousState)` => present `PersonaState.INVALID`
  - `M26(getPersonaType)` => `"default"`
  - `M28(getNormalizedState)` => `-1`
- Creator-list readback:
  - `M18(getPersonasForCreator uid=0|1000|10139, excludeDying=false|true)` => empty list count `0` in all cases
- Current interpretation:
  - the installed device-owner app can reach the persona service, but there is no evidence of any active Samsung Knox / persona container state exposed to this caller through the tested ids or creator-uid combinations.
  - this downgrades persona from a “maybe richer readable surface” to another mostly informational dead end unless a new id-discovery source appears.

### enterprise_policy / remoteinjection (Knox)

- `enterprise_policy` is reachable and several read-like methods succeed, but most useful calls are blocked by Knox permissions, `BIND_DEVICE_ADMIN`, `MANAGE_USERS`-style admin checks, or null `ContextInfo` paths.
- `M2` is now decoded precisely:
  - the 120-byte reply is a single non-null `ComponentName`, not a typed list
  - parcel shape matches `present=1`, package string `"com.privesc.agent"`, class string `"com.privesc.agent.AgentDeviceAdmin"`
  - this is an admin-identity readback, not raw capability bits
- Important refinement result:
  - `M5(ComponentName)` using `com.privesc.agent.AgentDeviceAdmin` returns a clean `i0=1` instead of throwing `No active admin null`.
- `remoteinjection` remains low value:
  - `M1 deep` => `i0=0`
  - `M5 deep` => `i0=1`
  - remaining methods are mostly blocked by `android.permission.sec.MDM_REMOTE_CONTROL` or system-user checks.
- Conclusion:
  - useful for Knox surface mapping, but still policy-gated rather than exploitable from the present app context.
  - with `M2`/`M5` decoded, there is no meaningful binder follow-up left here beyond documentation cleanup.

### SatsService

- Binder descriptor confirmed as `com.samsung.android.service.sats.ISatsService`.
- Decompiled stub exposes no binder tx beyond the descriptor transaction.
- All tested low transactions, including string-argument variants, return no usable data.
- Conclusion: binder dead end from the current caller context; any remaining Sats work should move to the `@SatsService` local-socket / AT path instead.

### Immediate Next Step

- Do not broaden binder fuzzing further yet.
- If binder work continues at all, keep it extremely narrow:
  - decode `enterprise_policy` `M2` precisely as `ComponentName` vs typed list, and
  - keep `M5(ComponentName)` as the only meaningful component-sensitive follow-up there.
- Otherwise shift effort back to kernel memory-corruption paths and BlueBorne proximity testing.

---

## Session 12 Detailed Findings

### perf_event_open Attack Surface (NEW)

**Discovery**: Shell can set `security.perf_harden=0`, which unlocks `perf_event_open()` for unprivileged users.

**What works**:
- Software counters (CPU_CLOCK, TASK_CLOCK, PAGE_FAULTS, CTX_SWITCHES)
- mmap ring buffers (PROT_READ|PROT_WRITE, MAP_SHARED)
- `PERF_EVENT_IOC_SET_OUTPUT` (redirect event output to another event's buffer)
- Event groups (group leader + child events)
- Up to 1020 concurrent perf events
- Frequency-based sampling produces userspace IP samples

**What doesn't work**:
- Hardware counters: ENOENT (Exynos 3475 Cortex-A7 PMU not exposed)
- Kernel IP sampling: kernel enforces `exclude_kernel` regardless of perf_harden
- Tracepoints: EINVAL
- Hardware breakpoints: EINVAL on kernel addresses

**CVE status**:
- **CVE-2016-6786** (SET_OUTPUT race): **PATCHED** — 7000 iterations, 0 crashes/hangs
- **CVE-2017-6001** (move_group race): Untested at scale — event groups + CPU pinning accessible

### timerfd CVE-2017-10661 (NEW)

- `timerfd_create(CLOCK_REALTIME)` works from shell
- `timerfd_settime(TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET)` succeeds
- **Blocker**: Race requires `clock_settime()` which needs CAP_SYS_TIME
- Possible workarounds: NTP time sync trigger, APK with SET_TIME permission

### Factory App Broadcast Attack Surface (NEW)

- **CSC_MODEM_SETTING** broadcast reaches `com.sec.factory/.entry.FactoryTestBroadcastReceiver`
- Factory app runs as **UID 1000** (system) with permissions: MASTER_CLEAR, WRITE_SECURE_SETTINGS, MODIFY_PHONE_STATE, CALL_PRIVILEGED, REBOOT, CAMERA, NFC, INSTALL_PACKAGES
- On receive: checks `MODEL_COMMUNICATION_MODE=gsm`, checks `ro.factory.factory_binary`, binds SecPhone Service
- **Blocked**: GET_FTA, SECPHONE_READY require KEYSTRING (signature|privileged)
- **Next**: Reverse factory app DEX to find exploitable code paths via extras

### DCCP Kernel Surface (NEW)

- `socket(AF_INET, SOCK_DCCP, IPPROTO_DCCP)` returns **EPERM** (not ENOSYS/EPROTONOSUPPORT)
- This confirms **DCCP IS compiled** into the kernel — SELinux blocks socket creation from shell
- untrusted_app domain may have different socket allow rules → test from APK
- If accessible: **CVE-2017-8890** (double-free in `inet_csk_clone_lock`) is the target

### Kernel Information Accessible from Shell (NEW)

| Source | Content | Exploitation Value |
|--------|---------|-------------------|
| `/proc/slabinfo` | All slab cache sizes, active objects, pages | HIGH — exact heap spray targeting |
| `/proc/vmstat` | Virtual memory statistics | Medium — memory pressure info |
| `/proc/buddyinfo` | Free page counts per zone/order | Medium — allocation planning |
| `/proc/pagetypeinfo` | Page type distribution | Low |
| `/proc/zoneinfo` | Memory zone details | Low |
| `/proc/vmallocinfo` | vmalloc regions with **physical addrs + function names** (virtual zeroed) | Medium — confirms device tree, driver layout |
| `/proc/key-users` | Keyring user count | Low |
| `/proc/softirqs` | Softirq counts | Low |
| `/proc/interrupts` | IRQ counts per CPU | Low |
| `NETLINK_ROUTE` socket | Network routing tables | Low |
| `NETLINK_SELINUX` socket | SELinux audit events | Medium — monitor policy decisions |

### Slab Cache State (from /proc/slabinfo)

| Cache | Active | Total | Obj Size | Per Slab |
|-------|--------|-------|----------|----------|
| kmalloc-64 | 85,688 | 91,648 | 64 | 64 |
| kmalloc-128 | 13,545 | 14,304 | 128 | 32 |
| kmalloc-192 | 9,121 | 11,403 | 192 | 21 |
| kmalloc-256 | 910 | 1,264 | 256 | 16 |
| kmalloc-512 | 1,344 | 1,392 | 512 | 16 |
| kmalloc-1024 | 1,595 | 2,208 | 1,024 | 16 |
| task_struct | 1,222 | 1,770 | 1,088 | 30 |
| sock_inode_cache | 486 | 486 | 448 | 18 |

### Additional CVE Surface Check

| CVE | Surface | Status |
|-----|---------|--------|
| CVE-2017-8890 (DCCP double-free) | DCCP socket | Compiled, SELinux-blocked from shell |
| CVE-2017-9075 (SCTP UAF) | SCTP socket | NOT compiled (EPROTONOSUPPORT) |
| CVE-2017-10661 (timerfd race) | timerfd | REACHABLE but needs clock_settime |
| CVE-2017-1000112 (UDP race) | UDP socket | bind works, UDP_CORK ENOPROTOPT |
| CVE-2016-6786 (perf SET_OUTPUT) | perf_event | **PATCHED** (7000 clean) |
| CVE-2017-6001 (perf move_group) | perf_event | Surface accessible, untested at scale |

### Init/Service Findings

- **at_distributor** starts as root but drops to UID 1001 (radio)
- **diagexe** starts as root, drops to UID 1000, chmod 0777 in init
- **ddexe/smdexe/connfwexe/edmaudit** all start root, drop to system
- **SideSync socket** (`ss_conn_daemon`): NOT present on this device
- **MobiCore user device** (`/dev/mobicore-user`): world-RW permissions but SELinux blocks shell
- All `ctl.*` service control properties blocked by SELinux from shell
- `security.perf_harden` is `shell_prop` → **settable by shell**
- `service.adb.tcp.port` is `shell_prop` → settable but `ro.debuggable=0` prevents ADB TCP

### DCCP and Socket Comparison Results (Session 12 continued)

**DCCP**: Blocked from BOTH shell AND untrusted_app (errno=13 EPERM). CVE-2017-8890 NOT viable from any position.

**MobiCore**: Blocked from both shell and untrusted_app.

**Socket comparison (shell vs untrusted_app)**:

| Socket | Shell | untrusted_app | Notes |
|--------|-------|---------------|-------|
| dnsproxyd | ✅ CONNECTED | ✅ CONNECTED | Root netd, FrameworkListener |
| fwmarkd | ✅ CONNECTED | ✅ CONNECTED | Network marking |
| property_service | ✅ CONNECTED | ❌ EPERM | APK has LESS access than shell |
| /data/.socket_stream | ❌ EPERM | ❌ EPERM | at_distributor, system:system 0700 |
| All 21 others | ❌ EPERM | ❌ EPERM | |

**Factory AT commands via COM11**: NOT routed to FtClient. COM11 → ddexe (DataRouter) → echo back. AT commands registered by factory app only accessible via at_distributor socket.

**Factory app config decoded**: base.dat + samsung-sm-t377a.dat are base64-encoded XML. Contains:
- 60+ AT command handler definitions (AT+KSTRINGB, AT+EWRITECK, AT+FACTORST, AT+POWRESET, etc.)
- Property mappings to persist.* and ro.* values
- sysfs paths including /dev/block/param (Samsung PARAM partition)
- FactoryTestMenu with test item configurations

---

## Session 13 Detailed Findings — BlueBorne L2CAP Protocol RE

**Historical note**: keep this section as protocol-recovery context only. Later live testing and userspace reversing showed the exploitable kernel `l2cap_parse_conf_rsp()` path is not the live path on this device; current Bluetooth work targets Bluedroid userspace parsing in `bluetooth.default.so`.

**2026-03-08 userspace BNEP update**:
- `bnep_process_control_packet()` enforces per-command remaining-length checks before dispatch:
  - setup-connection requests only reach `bnep_process_setup_conn_req()` when the encoded UUID-length field fits inside the remaining control payload
  - peer-filter and multicast-filter set commands only dispatch when their declared payload lengths fit the remaining packet
  - bad control subtypes trigger `bnep_send_command_not_understood()`
- `bnep_process_setup_conn_req()` only accepts UUID-size classes `2`, `4`, or `16`; other sizes are rejected before a response is sent upstream.
- `bnepu_process_peer_filter_set()` requires payload length divisible by `4`, caps the table to at most five ranges, and rejects descending range pairs.
- `bnepu_process_peer_multicast_filter_set()` requires payload length divisible by `12`, caps the table to at most five ranges, and rejects descending MAC-range pairs.
- Downstream filter-consumer findings:
  - accepted peer protocol filters store a bounded count (`0..5`) and do not yield an obvious serializer/count overflow in the local send/response helpers
  - accepted peer multicast filters store either a bounded count (`0..5`) or a special `0xffff` sentinel when the peer sends `00:00:00:00:00:00`–`00:00:00:00:00:00`
  - that sentinel means **reject all multicast**, not allow-all
  - `bnepu_process_peer_multicast_filter_set()` also forwards a suspicious success callback tuple (end-pointer with original length), but the currently traced in-module path only forwards it and does not dereference it locally
  - `BNEP_Write()` / `BNEP_WriteBuf()` nonzero-flag follow-up is now understood:
    - the flag is the **BNEP extension-header-present bit**, propagated through PAN forwarding callbacks rather than ordinary local single-link egress
    - when a frame is rejected and that flag is nonzero, the code rewrites the outgoing packet into an extension-only (or extension + minimal VLAN shim) stub with protocol rewritten to `0`, instead of forwarding the blocked payload unchanged
    - this looks like extension/VLAN normalization during relay, not a convincing filter-bypass primitive
- Ingress dispatcher / deferred-control findings:
  - in `FUN_000c298c`, a valid control packet whose first subtype is `SETUP_CONN_REQ` can save residual extension controls into a deferred GKI buffer **only** when the outer BNEP extension bit is set, the session is not yet connected, and residual bytes remain after parsing the setup request
  - the dispatcher allocates that deferred buffer with the same residual length that it later copies, so the old overflow theory does **not** survive: there is no remaining alloc-vs-copy mismatch here
  - `BNEP_ConnectResp()` later replays the saved deferred controls through `bnep_process_control_packet(..., 1)`, then frees the saved buffer and clears the pointer
  - the remaining concern is lifetime/state management: the release/timeout path appears to clear the deferred pointer without an obvious matching free, making a valid-frame userspace leak / state bug plausible if setup is abandoned before `BNEP_ConnectResp()`
- Setup/auth state-machine findings:
  - BCBs are static 7-entry slots reused across connections; several failure paths callback before final release/reset
  - the strongest surviving logic-bug candidate is **double-setup overwrite / auth TOCTOU**:
    - during the inbound authorize / app-response window, a second valid `SETUP_CONN_REQ` is not obviously rejected
    - it can overwrite the live UUID fields stored in the BCB
    - the later async auth/app callback uses the current mutable BCB state rather than a request-generation cookie
  - this makes a valid-packet A-then-B overwrite probe the best next Bluetooth experiment
- Probe harnesses now added for the remaining live paths:
  - `src\bluetooth\bnep_double_setup_probe.py` sweeps A-then-B valid `SETUP_CONN_REQ` timing on one CID and logs setup responses
  - `src\bluetooth\bnep_deferred_tail_leak.py` sends valid `SETUP_CONN_REQ` plus a large valid extension tail, then abandons the session before replay to stress the deferred-buffer lifetime path
  - both probes now support `--transport auto|l2cap|raw-hci`; `auto` prefers plain L2CAP sockets when available, reducing reliance on Scapy/raw-HCI for basic live testing
- Live bring-up / host-role update:
  - the installed agent now uses `DeepProbeService` to drive hidden `BluetoothPan` APIs from a service context; `status`, `enable`, and `connect` all work, and the earlier receiver-context `ReceiverCallNotAllowedException` is no longer the active blocker
  - on Kali/BlueZ, `NetworkServer1.Register("nap", "pan1")` must stay owned by a live D-Bus client; one-shot `busctl` / short-lived helper calls explain the earlier `profiles/network/server.c:bnep_setup() Server error, bridge not initialized`
  - with a persistent D-Bus client holding that NAP registration open, the tablet now reaches `LOCAL_PANU_ROLE:REMOTE_NAP_ROLE state = 2`, host `bluetoothctl info` shows `Connected: yes`, and bluetoothd logs `bnep: bridge pan1: interface bnep0 added`
  - however, once bluetoothd owns the registered NAP service, a separate root L2CAP listener on PSM `0x000f` does not receive the inbound socket, and the raw-HCI inbound probe still times out before the BNEP channel opens
  - a repo-local host handler now exists: `src\bluetooth\bnep_bluez_profile_probe.py` registers the NAP UUID through `org.bluez.ProfileManager1`, receives `Profile1.NewConnection(fd)` on the custom bluetoothd, and captures the live inbound setup request/traffic on the accepted socket
  - the first captured tablet setup request on that path is `01010211161115` (UUID size 2; parsed by the host probe as `src=0x1116 dst=0x1115`), and a success `SETUP_CONN_RSP` keeps the session alive long enough to observe follow-on BNEP frames
  - the accepted-socket host harness has now been extended to send host-originated setup A/B packets, append large valid extension tails, and close the socket on controlled timing after probe traffic
  - after a normal host success response, host-originated setup A=`1116:1115` and setup B=`1234:5678` both elicit `SETUP_CONN_RSP code=4` (`CONN_NOT_ALLOWED`) from the tablet
  - if the host sends setup A/B before responding to the tablet's own setup request, the tablet logs `BNEP - setup request when we are originator` twice and still returns `SETUP_CONN_RSP code=4`
  - a host-originated setup request with a ~640-byte valid extension tail is also rejected with `CONN_NOT_ALLOWED`; no Bluetooth-daemon crash, parser abort, or obvious memory-instability signal was observed during repeated reconnects
  - implication: the Bluetooth lane is no longer blocked on host socket ownership, but the current PANU→NAP accepted-socket direction does **not** appear to exercise the pending setup/auth windows behind the double-setup or deferred-tail theories; continuing Bluetooth work now likely requires a different role/path rather than more setup replay on this one
- Implication: the old malformed-length BlueBorne BNEP payloads are blocked in userspace; the remaining Bluetooth work is now valid-frame and adjacent-state-machine bug hunting, not replaying the legacy overflow inputs.

### EFS Output Amplification (NEW TECHNIQUE)

**Discovery**: `l2cap_parse_conf_rsp()` in `net/bluetooth/l2cap_core.c` writes EFS option output based on `sizeof(struct l2cap_conf_efs)` = 16 bytes, regardless of input `olen`. When `olen != 16`, the `memcpy` is skipped but `l2cap_add_conf_opt` STILL writes 18 bytes.

| Input olen | Input bytes | Output bytes | Amplification |
|-----------|-------------|-------------|---------------|
| 16 (valid) | 18 | 18 | 1:1 |
| 1 (short) | 3 | 18 | **1:6** |

**UNACCEPT path attack (60-byte input limit)**:
- 1 × valid EFS (olen=16): 18 bytes in → 18 bytes out (initializes efs struct safely)
- 14 × short EFS (olen=1): 42 bytes in → 252 bytes out (amplified!)
- **Total**: 60 bytes input → 270 bytes output → 206 bytes past buf[64]

**PENDING path attack (no input limit)**: Requires `CONF_LOC_CONF_PEND` flag. Unlimited input, direct overflow with any option types.

### Two Exploit Paths in l2cap_config_rsp()

| Path | Result Code | Input Limit | Prerequisite | Viability |
|------|-------------|-------------|-------------|-----------|
| UNACCEPT | 0x0001 | 60 bytes (checked) | Channel in CONFIG state | **HIGH** — EFS amplification bypasses limit |
| PENDING | 0x0004 | **NONE** | `CONF_LOC_CONF_PEND` set (needs EFS/HS negotiation) | **MEDIUM** — may not be reachable if target doesn't support EFS |

### Kernel Source Audit (l2cap_core.c from Samsung GPL release)

Confirmed from `Exynos3475/android_kernel_samsung_exynos3475` branch `clean_base`:
- `l2cap_parse_conf_rsp()` writes into caller's stack buffer via `l2cap_add_conf_opt(&ptr, ...)`
- `ptr` starts at `data + 4` (after `struct l2cap_conf_req` header)
- NO bounds check between `ptr` and end of buffer
- ARM32 with no stack canaries → direct overwrite of saved `{r4-r11, lr}` → PC control

### Existing Exploit Audit (6 files)

| File | Best Feature | Critical Issue |
|------|-------------|----------------|
| `bluborne_hci.py` | Full signaling state machine | Doesn't use EFS amplification; PENDING path needs CONF_LOC_CONF_PEND |
| `bluborne_pwn.c` | Raw L2CAP + SDP dual socket | EFS spray correct but SCID handling unclear |
| `bluborne_l2cap.c` | HCI ACL frame builder | Hardcodes ident=1, doesn't receive responses |
| `bluborne_scapy.py` | Scapy integration | Sends on data CID, not signaling CID 0x0001 |
| `bluborne_v3.py` | hcitool ACL + kernel L2CAP | Kernel handles config automatically, can't inject |
| `cve_2017_0782.py` | pybluez + pwntools | Can't send raw L2CAP signaling via pybluez |

### Corrected Exploit: `bluborne_efs_overflow.py`

Created `src/bluborne_efs_overflow.py` (24KB) with:
- Full L2CAP signaling state machine (INFO_REQ/RSP, CONN_REQ/RSP, CONF_REQ/RSP)
- **EFS amplification overflow** for UNACCEPT path (primary)
- **PENDING overflow** as fallback (if target supports EFS/HS)
- Three modes: `crash` (0xDEADBEEF), `spray` (prepare_kernel_cred), `info` (connectivity test)
- Raw HCI socket via Python + hcitool for ACL connection
- Proper SCID handling (captures target's DCID from CONN_RSP)
- EFS struct crafted with stype=BESTEFFORT to pass kernel stype check
- Target address packed at 4-byte aligned fields (sdu_itime, acc_lat, flush_to)

### Kallsyms Analysis

- Address table found at file offset 0x87A554 in vmlinux_aqgf
- **43,664 kernel symbols** decoded from address table
- commit_creds confirmed at index 1955 (0xC0054328)
- prepare_kernel_cred at index 1963 (0xC00548E0)
- Token table at 0x925F44 — Samsung uses non-standard kallsyms compression
- Name decoding partially successful — full L2CAP function addresses not yet extracted
- **209 candidate functions** match stack pattern (PUSH+LR, SUB SP 56-160, CMP#1+CMP#4)

### Next Steps

1. **Test exploit from Kali** — need Linux machine with BT adapter within 10m of tablet
2. **Run `info` mode first** — verify L2CAP connectivity and check if target sends PENDING
3. **Run `crash` mode** — send 0xDEADBEEF spray, confirm device reboots (crash = exploitable)
4. **Determine exact LR offset** — from crash logs or QEMU testing
5. **Build ROP chain** — prepare_kernel_cred(0) → commit_creds() → return
6. **QEMU validation** — enable CONFIG_BT in QEMU kernel, test overflow geometry safely

### Session Findings (2026-03-08 Afternoon)

**DRParser Keystring Injection — DEAD END**
- `KeyStringUpdateReceiver` requires SECRET_CODE broadcast with host `873283`
- SECRET_CODE broadcast requires `com.sec.factory.permission.KEYSTRING` (signature|privileged)
- Shell (UID 2000) and untrusted_app (UID 10139) both get Permission Denial
- `/efs/FactoryApp/` not writable from shell or untrusted_app (SELinux)
- `isKeyStringBlocked : return true` — KEYSTRING_BLOCK file exists at `/efs/FactoryApp/keystr`
- ParseService.process() only broadcasts SECRET_CODE for codes IN the keystring table
- `873283` is NOT in the ATT keystring table — ParseService logs "Keystring not in the list" and drops it
- RSA encryption script verified (512-bit key, PKCS1v1.5, round-trip confirmed)
- **Vector closed: no path to trigger keystring copy or get custom keystrings loaded**

**DM/HDLC Binary Protocol — DEAD END**
- COM18 (DIAGSERD) detected as DM port, COM8 as AT modem
- USB functions: `acm,dm,adb` — DM gadget is enabled
- diagexe PID 2211, blocking on `__skb_recv_datagram` (socket recv, not serial read)
- All 256 command codes tested with 0x7E start flag (standard HDLC) — 0 responses
- All tested with 0x7F start flag (Samsung DM_MSG_START_FLAG) — 0 responses
- Also tested: raw AT, delimiter floods, Samsung proprietary ranges (0x80-0xFF)
- diagexe PID remained stable (no crashes from any payload)
- **Port appears to be modem-passthrough only or requires unknown activation handshake**
- **Vector closed: no responsive DM commands accessible from USB host**

**SysDump / Accessibility — CONFIRMED WORKING**
- Secret code mechanism proven: `secret_code` → SecretCodeIME → `input text '*#CODE#'`
- `*#9900#` (SysDump): Opens successfully, dumpstate triggered via accessibility click
- `*#197328640#` (Service Mode): Opens, engineering menus accessible
- `*#0808#` (USB Settings): Opens, USB mode configuration available
- `*#9090#` (Diagnostic Routing): Opens
- `*#4636#`: Not in ATT keystring table, SecretCodeIME keypad stays open
- Accessibility can click buttons in Samsung engineering apps even though window dump can't enumerate nodes
- Pulled from `/sdcard/log/`: dumpstate (16MB), AVC audit logs, sec_log (2MB), btsnoop captures
- Pulled from `/data/anr/`: traces.txt (795KB), traces_bugreport.txt (1.4MB) 
- TIMA paddr leaks confirmed in dumpstate: `selinux_enabled=0x20AB00A8`, `selinux_enforcing=0x20B7AD18`
- 92MB CP crash dump available at `/sdcard/log/cpcrash_dump_20260306-0142.log`


### Secret Code Exploration Results (2026-03-08)

**Mechanism**: `secret_code` command → SecretCodeIME opens → `input text '*#CODE#'` → ParseService processes → broadcasts SECRET_CODE from UID 1000

**46 production ATT keystrings** found in `/system/etc/ATT_keystrings.dat` (decrypted copy at `work/keystrings/ATT_keystrings_decrypted.xml`). No `common_keystrings.dat` exists on device.

| Code | Opens | Package | Security Value |
|------|-------|---------|---------------|
| `*#9900#` | SysDump | servicemodeapp | ✅ ROOT DUMPSTATE — 16MB dumps, kernel info |
| `#7465625*638*#` | Network Lock | personalization | ✅ CARRIER UNLOCK — NCK entry screen |
| `*#197328640#` | Service Mode | RilServiceModeApp | ✅ Modem engineering menus |
| `*#0808#` | USB Settings | usbsettings | ✅ USB mode reconfig (RNDIS, DM+ADB, etc.) |
| `*#9090#` | Diag Port Routing | RilServiceModeApp | ⚠ DM port routing changes |
| `*#*#4636#*#*` | Testing Settings | android.settings | ✅ RadioInfo — radio on/off, network type, IMS |
| `*#638#` | Factory Automation | sec.automation | ⚠ TetheringSettings activity |
| `*#7353#` | Quick Test | factorykeystring | Self-test menu |
| `*#22558463#` | Reset Call Timer | servicemodeapp | Low value |
| `*#2263#` | Band Selection | RilServiceModeApp | ⚠ Band locking |
| `*#0228#` | Battery Info | factorykeystring | Low value |
| `*#0011#` | Network Info | RilServiceModeApp | Signal/cell diagnostics |

**Key discoveries**:
- SIM Network Lock screen (`#7465625*638*#`) accepts NCK input — carrier unlock is possible with correct key
- IMEI: `353608074799027` (can be used to request AT&T unlock code)
- RadioInfo (`*#*#4636#*#*`) allows turning radio on/off and changing network type
- `*#877#` and `*#2627#` stayed on SecretCodeIME (codes not found in ParseService — may need different entry method)
- Accessibility click_text works on some Samsung engineering apps even when dump_ui can't enumerate nodes
- `uiautomator dump` provides full XML hierarchy where accessibility dump fails

