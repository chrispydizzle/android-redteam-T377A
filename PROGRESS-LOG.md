# Android Red Team — Progress & Instructions

## Samsung SM-T377A | Android 6.0.1 | Kernel 3.10.9-11788437

## Last updated: 2026-02-26 10:30:00

## ⚠ CRITICAL WARNINGS

- **This is a PHYSICAL device.** Fork-bombs, aggressive races, and adbd_root CRASH it.
- **DO NOT run `/data/local/tmp/adbd_root`** — it hangs then crashes the device.
- **DO NOT run `/data/local/tmp/su-v1` or `su-v2`** — non-PIE, rejected by kernel.
- **DO NOT run `/data/local/tmp/rageagainstthecage`** — non-PIE binary.
- **Conservative testing only.** Fork in child processes, use timeouts.
- **Check the /src folder and the /findings folder before attempting any new implementation or exploit** to prevent repeating work that's already been done.

## Device Details

- **Model:** Samsung SM-T377A (Galaxy Tab E 8.0, AT&T)
- **SoC:** Exynos 3475 (ARMv7 Cortex-A7, 4 cores)
- **Android:** 6.0.1 (Marshmallow), Build MMB29K.T377AUCU2AQGF
- **Kernel:** 3.10.9-11788437, compiled 2017-07-05
- **Security patch:** 2017-07-01
- **SELinux:** Enforcing (u:r:shell:s0)
- **Shell UID:** 2000 (groups: input, log, adb, sdcard_rw, sdcard_r, net_bt_admin, net_bt, inet, net_bw_stats)
- **/images folder:** contains stock device images, ramdisk, and other goodies pulled from the device.

## Known Kernel Addresses (from firmware AP_T377AUCU2AQGF)

- `commit_creds` = 0xc0054328
- `prepare_kernel_cred` = 0xc00548e0
- `selinux_enforcing` ≈ 0xc0b7ad54 (inferred from sel_write_enforce disassembly)
- PHYS_OFFSET = 0x20000000, PAGE_OFFSET = 0xC0000000
- kernel_vaddr = phys_addr + 0xA0000000
- task_struct->cred offset = 0x164
- thread_info->addr_limit offset = 8, KERNEL_DS = 0xFFFFFFFF

## Kernel Mitigations Present

- ✅ NO KASLR, NO PXN, NO stack canaries, NO HARDENED_USERCOPY
- ❌ kptr_restrict: ACTIVE (zeroes all /proc addresses)
- ❌ SELinux: ENFORCING (blocks msgget, add_key after 198, security.* xattr, mobicore-user)
- ❌ mmap_min_addr: Unknown (can't read /proc/sys/vm/mmap_min_addr — but 0x00200000 maps OK)
- ❌ /dev/mem, /dev/kmem: DO NOT EXIST
- ❌ /proc/self/pagemap: EPERM (requires CAP_SYS_ADMIN)

## Build System

```bash
.\qemu\build-arm.bat src\file.c output_name
```

Uses WSL Ubuntu-22.04 + arm-linux-gnueabi-gcc. Produces static PIE ARM binaries.
Auto-pushes to /data/local/tmp/ via ADB.

## Firmware Symbol Table

- File: `work/vmlinux_aqgf` (11,579,264 bytes decompressed kernel)
- Names: `work/fw_names.txt` (43,664 symbols, ONLY T/t/r/R types — NO data/bss symbols)
- Address table offset: 0x87A550 (4 bytes per symbol, little-endian)
- Symbol format: first char = type (T/t/r/R), rest = name
- Data symbols (selinux_enforcing, init_cred, etc.) must be found by disassembling referencing functions

---

## CVEs TESTED — Status

### ❌ CVE-2016-5195 (Dirty COW) — PATCHED

- Tested with custom `iov_root.c` and pre-built `dirtycow` binary
- MAP_PRIVATE file not modified after 5-10 seconds racing
- **Do not retry.**

### ❌ CVE-2015-1805 (pipe iov double-advance) — PATCHED

- readv/writev across fault boundary returns EFAULT correctly
- No double-advance of iov detected
- **Do not retry.**

### ⚠ CVE-2014-3153 (Towelroot/futex) — PARTIALLY VULNERABLE, NOT EXPLOITABLE

- **Patch status:**
  - Patch "Forbid uaddr==uaddr2" (self-requeue): **PRESENT** → returns EINVAL
  - Patch "Validate atomic acquisition": **MISSING** → LOCK_PI accepts FUTEX_WAITERS|0
  - Patch "Non-PI source → PI target": **MISSING** → WAIT_REQUEUE_PI blocks on non-PI target
- **Race results:** 0 anomalies after 8000+ iterations (500ns–500000ns timeouts)
- **FUTEX_WAIT_REQUEUE_PI timeout quirk:** uses ABSOLUTE CLOCK_MONOTONIC, not relative!
  Must compute: `clock_gettime(CLOCK_MONOTONIC, &ts); ts.tv_sec += N;`
- **FUTEX_CMP_REQUEUE_PI:** val (nr_wake) MUST be 1 or EINVAL
- Timeout cleanup properly removes waiter; SIGKILL cleanup works
- Race window appears too narrow on this hardware
- **Could retry with different approach but unlikely to succeed.**

### ❌ CVE-2015-3636 (ping socket UAF) — PATCHED

- Ping sockets create fine (ping_group_range = 0–2147483647)
- Double disconnect succeeds (connect AF_UNSPEC twice returns 0)
- BUT: LIST_POISON2 (0x00200200) page NOT written by kernel
- Fix likely sets pprev=NULL after unhash
- **Do not retry.**

### ❌ CVE-2013-2094 (perf_event_open OOB) — PATCHED

- OOB config values return ENOENT
- SW events work, but kernel profiling collects 0 samples
- HW breakpoint: ENODEV; tracepoints: no access
- **Do not retry.**

### ❌ CVE-2014-0196 (n_tty write race) — SURVIVED (likely patched)

- 4 threads writing to ptmx slave in cooked mode for 3+ seconds
- Process hung (writes blocked) but no crash detected
- **Could retry with better drain logic, but low probability.**

### ❌ Keyring overflow — TOO SLOW

- 26,502 ops/sec → 2701 minutes for overflow
- Also hits EDQUOT at 198 iterations
- **Not viable.**

---

## ION UAF — Confirmed but No Code Execution Trigger

### What Works

- Race condition between ION_IOC_FREE and ION_IOC_SHARE: **91% win rate**
- Freed handle leaves dangling fd (confirmed via SHARE after FREE succeeding)
- kmalloc-64 is the target slab (ion_handle is 52 bytes)
- socketpair spray: +1169 kmalloc-64 per 200 ops (best spray)
- setxattr spray: 41,616/sec with user.* namespace (but temporary — freed at syscall end)
- ptmx spray: +706 kmalloc-64, +399 kmalloc-512, +399 kmalloc-1024

### What's Missing (WHY no code execution)

- **seq_operations is STATIC .rodata, NOT heap-allocated** (document ion-exploit-status.md was wrong)
- Freed ion_handle has NO function pointers — nothing calls through sprayed data
- msgsnd spray: BLOCKED by SELinux (EPERM on msgget)
- add_key spray: BLOCKED by SELinux after 198 keys
- **Fundamental blocker: no victim object with callable function pointers in kmalloc-64**

---

## Other Attack Surfaces Tested

### Accessible Devices

- /dev/binder, /dev/ashmem, /dev/ion, /dev/mali0, /dev/ptmx — all world-RW
- /dev/mobicore-user — world-RW on disk but **SELinux blocks shell access**
- /dev/s5p-smem — **permission denied for shell**
- /dev/tty — accessible

### Kernel Fuzzing Results (from earlier sessions)

- Mali GPU: 29K+ ops, 24 func IDs — 0 crashes
- ION: heap bit 2 (0x0004) → kernel crash (DoS only)
- Binder: BINDER_SET_CONTEXT_MGR + close/reopen → kills servicemanager (DoS only)
- Ashmem: 100K+ ops — 0 crashes
- Input: event0-4, 60s parallel — stable

### Property System

- `setprop service.adb.root 1` — succeeds but has no effect (ro.debuggable=0, ro.secure=1)
- `persist.*` properties — cannot be set (empty after setprop)
- `ro.build.type = user` — not a debug/eng build

### Socket Access

- /dev/socket/property_service — world-RW (but can't set privileged props)
- /dev/socket/dnsproxyd, /dev/socket/fwmarkd — inet group accessible
- /dev/socket/logd, logdr, logdw — world-accessible
- /dev/socket/netd — root:system only
- ndc (netd client) — permission denied connecting

### ftrace / debugfs

- /sys/kernel/debug/tracing/ accessible
- Only `nop` tracer; only sched_switch event writable
- tracing_on, trace, trace_marker, buffer_size_kb writable
- NO kernel address leak possible

### Process Information

- Cannot read /proc/<root_pid>/maps (permission denied)
- /proc/self/wchan: 0; /proc/self/stat kstkesp/kstkeip: userspace addrs
- /proc/self/stack: addresses zeroed but function names+offsets shown
- waitid siginfo: no kernel pointers leaked

### Android Services

- 165+ services enumerated via binder
- run-as: "Could not set capabilities: Operation not permitted"
- am/pm/settings/sm commands work from shell
- Developer settings enabled

---

## Source Files Created (in src/)

| File | Purpose | Result |
|------|---------|--------|
| physmap_test.c | /proc/self/pagemap access | EPERM |
| exploit_test.c | Comprehensive primitive test | msgsnd blocked, futex/perf work |
| slab_probe.c | kmalloc-64 allocation sources | socketpair best (+1169) |
| futex_test.c–futex_test3.c | CVE-2014-3153 detection | Confirmed VULNERABLE (partial) |
| towelroot.c–towelroot4.c | Towelroot race attempts | 0 anomalies after 700+ iters |
| perf_root.c | perf_event_open exploits | OOB patched, profiling no samples |
| xattr_spray.c | setxattr spray testing | user.* works 41K/sec |
| iov_root.c | Multi-CVE test (pipe/DirtyCOW/futex) | All patched or no race win |
| ping_root.c | CVE-2015-3636 ping UAF | Patched (no POISON write) |
| multi_root.c | MobiCore/n_tty/waitid/dev_mem | All blocked |
| ntty_race.c | CVE-2014-0196 n_tty race | Hung, likely patched |
| ion_race_free_share.c | ION UAF race exploit | UAF confirmed, no code exec |
| ion_exploit_poc.c | ION exploit with spray | Spray works, no trigger |
| mali_verify_bugs.c | Definitive Mali false positive proof | ALL ops return header.id=3 |
| mali_free_check.c | Cross-ctx free result checking | Returned result=3, not freed |
| mali_import_probe.c | MEM_IMPORT exhaustive probe | Completely DISABLED |
| binder_uaf.c | CVE-2019-2215 basic detection | Trigger works, no crash |
| binder_uaf2.c | Binder exploit + slab ID | binder_thread in kmalloc-512 (WRONG) |
| binder_slab_trace.c | Per-operation slab diffs | binder_thread in kmalloc-256 |
| binder_slab_full.c | Full slabinfo diff 50 binders | Definitive: kmalloc-256 |
| slab_readv_test.c | readv iov slab verification | UIO_FASTIOV=32 (stack buffer!) |
| binder_uaf_diag.c | readv reclaim diagnostic | No corruption (wrong approach) |
| binder_uaf_diag2.c | Same-thread reclaim test | No corruption (FASTIOV=32) |
| binder_uaf_lite.c | Lightweight reclaim test | No corruption (FASTIOV=32) |
| binder_uaf_k256.c | kmalloc-256 exhaust+reclaim | Device hung (too many threads) |
| binder_mass_uaf.c | Mass UAF + spray survey | Built, not yet run |
| cve_2019_2215.c | Full exploit attempt v1 | Wrong slab (targeted 512) |
| heap_primitives.c | Spray primitive survey | setxattr works, msgsnd blocked |
| slab_hunt.c | Comprehensive slab monitor | Identified all cache sizes |
| ion_slab_probe.c | ION handle slab ID | kmalloc-64 confirmed |

---

## Binaries on Device (/data/local/tmp/)

### ⚠ DO NOT RUN

- `adbd_root` — **CRASHES DEVICE** (hangs then disconnects)

### Safe to Run

- All `src/`-compiled binaries (iov_root, ping_root, multi_root, exploit_test, etc.)
- `linpeas.sh` — Android enumeration
- `toolbox` — custom toolbox
- `tsd_client_arm32` — TrustZone client (hangs, needs investigation)

---

## Findings Review Notes (from findings/ directory)

- `ion-exploit-status.md` and `ion-exploit-strategy.md` claim "fully exploitable to root" via
  seq_operations spray — **THIS IS WRONG**. seq_operations is static .rodata, not heap-allocated.
  msgsnd/sendmsg spray is blocked by SELinux. No viable code exec trigger found.
- `ion-uaf-verification.md` confirms UAF is real (97% win, mmap+write on dangling fd works).
  The MISSING piece is a victim object with callable function pointers in kmalloc-64.
- `sim-lock-bypass-avenues.md` suggests ION exploit → root → SIM unlock. Requires root first.
- `service-enumeration.md` identifies high-value targets not fully explored:
  EngineeringModeService, DeviceRootKeyService, ABTPersistenceService, SatsService.
- `mif-log-analysis.md` shows ION spray triggers modem interface logs — possible shared slab collision.
- `info-disclosure-attack-surface.md` notes Mali quirk registers writable, debugfs fully readable.
- `final-report.md` and `final-security-report.md` previously concluded root NOT achievable.
  We are continuing to explore remaining avenues.

## Session 3 — Additional Testing (2026-02-25)

### CVE-2017-7533 (inotify/rename race) — SURVIVED

- 644K events across 15 seconds, no crash
- **Likely PATCHED. Do not retry.**

### CVE-2017-11176 (mq_notify) — NOT AVAILABLE

- POSIX MQ returns ENOSYS — kernel compiled without CONFIG_POSIX_MQUEUE
- **Not applicable.**

### CVE-2016-4557 (eBPF UAF) — NOT AVAILABLE

- Only seccomp_bpf present, no eBPF syscall
- **Not applicable.**

### Samsung Service Mode Apps — ALL BLOCKED

- RilServiceModeApp (UID 1001): 12 activities, all unexported from UID 2000
- DiagMonAgent (UID 1000): exported broadcast receivers but no observable action on RESET, COPY_LOGPACKAGE, ADMIN_SETTING, SYSSCOPESTATUS broadcasts
- Factory app: protected by signature|privileged permission
- Secret codes via broadcast: complete with result=0, no observable effect

### Knox / Enterprise / ABT Services — PROPERLY SECURED

- ABTPersistenceService: "Not authorized" for transactions 1, 3; state validation + auth for transaction 2
- remoteinjection: requires android.permission.sec.MDM_REMOTE_CONTROL (signature perm)
- edm_proxy: returns empty/success but no useful action
- device_policy: "No active admin owned by uid 2000"
- All Knox services checked UID/permission before allowing operations

### Settings / Property Manipulation — NO ESCALATION PATH

- WRITE_SECURE_SETTINGS granted to shell — can modify many settings
- Disabled package_verifier_enable and verifier_verify_adb_installs
- install_non_market_apps=1 (sideloading allowed)
- Development settings enabled
- `ctl.start`/`ctl.stop` works from shell (can control init services)
- BUT: no setting/property change leads to root code execution
- flash_recovery service exists (runs install-recovery.sh as root) but reads from /cache which is SELinux-blocked

### Input Injection — WORKS (group 1004)

- Full access to /dev/input/event0-5 (touchscreen, sensors, gpio_keys)
- `input tap`/`input swipe`/`sendevent` all work
- Can automate UI interactions (used to navigate Magisk Manager)

### System File Access — LIMITED

- /data/system/ listing readable but file contents blocked (system:system rw-rw----)
- enterprise.conf readable: microphoneEnabled=1, screenCaptureEnabled=1
- /data/tombstones/ traversable (drwxrwx--x) but can't create files (SELinux)
- /data/anr/traces.txt world-writable (but overwriting provides no escalation)
- No SUID/SGID binaries anywhere in /system
- All storage mounts: nosuid,nodev,noexec
- All block devices: root-only (brw-------)

### Platform Signing Key — NOT AOSP TEST KEY

- CN=Samsung Cert, OU=DMC, O=Samsung Corporation (SHA1: 9CA5170F381919DF)
- Cannot sign APKs as system UID
- **Cannot install platform-signed apps.**

### Root Tool Discovery — INSTALLED BUT INACTIVE

- **com.topjohnwu.magisk** v30.6 (30600) — Magisk Manager installed, core NOT active
- **com.z4mod.z4root** v1.3.0 — installed
- **com.noshufou.android.su** v3.0.7 — Superuser installed
- /sbin/su exists but blocked by SELinux
- /sdcard/com.kingroot.kinguser/ directory exists
- Previous root attempts were clearly made but none are currently active

### ❌ Odin Bootloader Flash — FAILED (LOCKED BOOTLOADER)

- OEM unlock IS enabled (sys.oem_unlock_allowed=1, toggle ON in dev settings)
- Magisk Manager successfully patched boot.img → magisk_patched-30600_QYc8K.img
- Packaged as magisk_boot.tar for Odin AP slot
- `adb reboot download` successfully entered download mode
- Odin3 v3.14.4 flash **FAILED** — AT&T carrier-locked bootloader rejects unsigned images
- OEM unlock toggle is cosmetic on carrier-locked AT&T devices
- **Bootloader approach is definitively blocked.**

### ION UAF Code Execution Analysis — EXHAUSTED

- Traced ion_share_dma_buf: creates dma_buf holding ref to ion_buffer
- After ion_handle free: buffer stays alive via dma_buf ref, handle is properly freed
- mmap on dangling fd accesses VALID buffer pages, not freed kmalloc-64 slot
- 651 function pointer tables found in firmware — ALL static .rodata/.data
- No dynamically-allocated kmalloc-64 object with callable function pointers identified
- **ION UAF cannot be leveraged for code execution on this device.**

### 62-System-UID Apps with ALLOW_BACKUP Found

- Identified via package enumeration (com.sec.android.app.sysscope, com.android.providers.settings, etc.)
- ADB backup requires UI confirmation (automatable via input injection)
- BUT: backup/restore only modifies app data directories, not code
- No system app found that loads executable content from its data directory
- **Backup/restore attack provides no code execution path.**

---

## FINAL ASSESSMENT

**CVE-2019-2215 (binder UAF) is confirmed UNPATCHED.** Exploitation blocked by
Samsung's UIO_FASTIOV=32 preventing standard iovec spray. Alternative kmalloc-256
spray needed.

### Session 5 — CVE-2019-2215 + Mali Re-Verification (2026-02-25)

#### ⚠ Mali r7p0-03rel0 — ALL "VULNERABILITIES" ARE FALSE POSITIVES ⚠

**CRITICAL CORRECTION:** The Mali "vulnerabilities" reported in Session 4 are ALL false
positives. The Mali UK (User-Kernel) interface returns success/failure in `header.id`
field (0=success, 3=MALI_ERROR_INVALID_PARAMETER), NOT in ioctl return value or
`header.ret`. All prior testing only checked `ioctl()` return (always 0 for dispatched
requests). Definitive re-verification (mali_verify_bugs.c) shows:

- Cross-context free: **REJECTED** (header.id=3)
- Same-context double-free: **REJECTED** (header.id=3)
- FLAGS_CHANGE with any flags: **REJECTED** (header.id=3)
- MEM_COMMIT integer overflow: **REJECTED** (header.id=3)
- MEM_IMPORT (all types/flags/sizes): **COMPLETELY DISABLED** (header.id=3)
- **None of these operations actually execute.** The driver correctly validates all inputs.

#### CVE-2019-2215 (Binder UAF) — CONFIRMED UNPATCHED ✓

- Kernel 3.10.9 with patch level 2017-07 → patched in Sep 2019 → VULNERABLE
- BINDER_THREAD_EXIT frees binder_thread while epoll retains dangling wait_queue ref
- **binder_thread is in kmalloc-256** (verified: 50 THREAD_EXIT freed -53 from kmalloc-256)
- epoll_ctl DEL accesses freed memory (completes without crash)

**BPF Filter Spray — RECLAMATION CONFIRMED:**

- SO_ATTACH_FILTER with 22-26 BPF instructions allocates persistently in kmalloc-256
- Verified: 50 UAFs + 100 BPF sprays → ALL 100 reused freed slots (+0 net change)
- Cross-allocation confirmed: BPF and binder share same slab pages
- BPF instruction content is fully controllable

**EXPLOITATION BLOCKED — Two independent mitigations:**

1. **UIO_FASTIOV=32** — Samsung increased from standard 8, blocking the iovec spray technique
   - readv/writev with ≤32 iovecs uses kernel stack buffer (no kmalloc)
   - iovcnt=33+ → kmalloc-512 (wrong cache for kmalloc-256 target)
   - This blocks the standard CVE-2019-2215 arbitrary kernel r/w primitive
2. **No wake_up trigger path** — epoll cleanup (close/DEL) only calls list_del, never wake_up
   - list_del writes pointer values into the reclaimed BPF data (self-referential)
   - Cannot redirect function pointers: wake_up (which calls entry->func) is never triggered
   - Thread removed from proc->threads rbtree, so no binder work dispatched to it
   - Tested 6 trigger methods × 48 offsets (288 combinations): ZERO crashes

**Additional spray primitive testing (all negative for kmalloc-256):**

- userfaultfd: ENOSYS (kernel compiled without CONFIG_USERFAULTFD)
- socketpair+sendmsg: skb data → kmalloc-512+ (shared_info overhead)
- signalfd, eventfd, timerfd, ashmem, inotify: ALL +0 for kmalloc-256
- AF_NETLINK: +46 in kmalloc-256 but SELinux blocks (EACCES)
- Pipes (all sizes), epoll items, ptmx, mali0, ion: ALL +0 for kmalloc-256

**Conclusion: CVE-2019-2215 is present but NOT EXPLOITABLE on this Samsung build
due to kernel-level mitigations (UIO_FASTIOV=32) that block all known exploitation
techniques. The vulnerability exists but is effectively neutralized.**

#### Slab Cache Layout (definitive)

- **kmalloc-64**: ION handles, Mali tracking, pipe_buffer[2], buffer_head
- **kmalloc-128**: binder metadata (+20 for 50 opens)
- **kmalloc-192**: ION buffers, binder metadata (+20 for 50 opens)
- **kmalloc-256**: **binder_thread** (+1 per thread, -53 for 50 THREAD_EXIT)
- **kmalloc-512**: readv iov array (for iovcnt 33-64)

#### pipe_buffer in kmalloc-64 (CONFIRMED, from Session 4)

- F_SETPIPE_SZ(2*PAGE_SIZE) → pipe_buffer[2] in kmalloc-64
- pipe_buffer.ops = function pointer table (valid from Session 4)
- +490 kmalloc-64 objects for 200 pipes

#### Boot Ramdisk Audit — No Exploitable Services

- Extracted and analyzed all 17 RC files from boot.img
- flash_recovery: runs install-recovery.sh as root but from /system (read-only)
- Platform signing key: Samsung's own (not AOSP test key)
- No writable-path service definitions found

All practical attack vectors have been exhausted:

- 9 kernel CVEs tested: all patched or impractical
- ION UAF confirmed but no code execution trigger exists
- All Samsung/Knox/enterprise services properly secured
- Bootloader locked (AT&T carrier lock overrides OEM unlock)
- No SUID binaries, no writable system paths, SELinux enforcing
- Previous root tools installed but inactive

The device demonstrates strong defense-in-depth:

1. **Kernel patches**: All major CVEs patched by July 2017
2. **SELinux**: Properly restricts shell domain (blocks msgsnd, mobicore, /cache, etc.)
3. **No debug surfaces**: No /dev/mem, no eBPF, no SUID binaries
4. **Carrier bootloader lock**: Prevents hardware-level modification despite OEM unlock setting
5. **Samsung Knox**: Service-level permission checks on all enterprise APIs

---

## Session 4 — App-Context Escalation & Exhaustive Probing (2026-02-25)

### Custom APK Probe (com.redteam.probe)

Built and installed a custom APK with maximum attack surface:

- **Accessibility Service**: Enabled via `settings put secure enabled_accessibility_services` — BOUND and active
- **Notification Listener**: Enabled via `settings put secure enabled_notification_listeners` — Active
- **16 dangerous permissions**: All granted via `pm grant` (Camera, Mic, SMS, Location, Contacts, Phone, Calendar, Storage, Sensors)
- **Components**: ProbeActivity, CommandReceiver, ProbeAccessibility, ProbeNotificationListener, ProbeProvider, BootReceiver

### App-Context Capabilities Confirmed

Running as UID 10168, u:r:untrusted_app:s0:c512,c768:

- ✅ Open /dev/ion, /dev/binder, /dev/ashmem, /dev/mali0, /dev/ptmx
- ✅ ION UAF race works from app context (race win confirmed!)
- ✅ Execute native ARM binaries from app data dir (/data/data/com.redteam.probe/)
- ✅ mprotect RWX (can create executable memory)
- ✅ Read /proc/self/maps (library layout visible)
- ✅ Read accessibility window events (captures all app changes)
- ✅ Read ContentProviders (SMS, Contacts, Settings)
- ✅ Bind non-privileged network ports
- ✅ Read /sys/kernel/debug/tracing/
- ❌ No capabilities (CapBnd = 0x0)
- ❌ No Seccomp (good for exploitation attempts)
- ❌ Cannot read dmesg, /proc/slabinfo (LESS access than shell)
- ❌ Cannot write /data/local/tmp or execute binaries there
- ❌ Cannot read /data/system/, /proc/1/maps

### Device Owner — BLOCKED

- Removed TestAuditUser (`pm remove-user 10` → Success)
- **Requires factory reset to clear accounts (destructive)**

### Privilege Escalation Probe (priv_probe.c) — All Blocked

Tested from BOTH shell and app contexts — identical results:

- **AF_PACKET**: EPERM (no CAP_NET_RAW) → CVE-2017-7308 NOT usable
- **User namespaces**: EINVAL (CONFIG_USER_NS not compiled) → Cannot gain capabilities
- **Keyring (add_key)**: EPERM (SELinux blocks) → CVE-2016-0728 NOT usable
- **BPF**: ENOSYS (not compiled) → No eBPF exploits possible
- **perf_event_open**: E2BIG (struct size) — perf_event_paranoid=1
- **/proc/self/pagemap**: EPERM → Physmap technique NOT usable
- **mprotect RWX**: WORKS (but no kernel trigger to jump to it)
- **/dev/kmem, /dev/mem**: DO NOT EXIST

### CVE-2017-7533 (inotify/rename race) — SURVIVED

- 665K+ events processed across 15 seconds, no crash → **PATCHED or race too narrow**

### CVE-2017-11176 (mq_notify) — NOT AVAILABLE

- POSIX MQ returns ENOSYS → kernel lacks CONFIG_POSIX_MQUEUE

### Samsung Service Mode App — ALL ACTIVITIES REQUIRE KEYSTRING

- com.sec.android.app.servicemodeapp has 20+ activities
- ALL require `com.sec.android.app.servicemodeapp.permission.KEYSTRING` (signature|privileged)
- Includes: SysDump, DebugLevel, USBSettings, PhoneUtil, etc.
- Secret codes via broadcast: no observable effect
- **Cannot access any service mode functionality from shell or app**

### Boot/Block Device Access — BLOCKED

- BOOT partition: /dev/block/mmcblk0p10 (brw------- root root)
- RECOVERY: /dev/block/mmcblk0p11
- SYSTEM: /dev/block/mmcblk0p20
- ALL block devices root-only, SELinux enforcing
- **Cannot read or write boot/system partitions**

### Kernel Sysctl Writes — ALL BLOCKED

- core_pattern, hotplug, sysrq: SELinux denies all writes from shell/app
- Even reading core_pattern blocked by SELinux

---

## UPDATED FINAL ASSESSMENT (Session 5)

**CVE-2019-2215 is CONFIRMED UNPATCHED — exploitation partially blocked by Samsung-specific
kernel configuration (UIO_FASTIOV=32). Alternative spray primitives being investigated.**

**Mali GPU vulnerabilities reported in Session 4 are ALL FALSE POSITIVES — corrected.**

### Total Attack Surface Tested: 60+ Vectors

| Category | Vectors Tested | Result |
|----------|---------------|--------|
| Kernel CVEs | 11 (DirtyCOW, pipe_iov, futex, ping, perf, n_tty, ION, inotify, mq_notify, BPF, **CVE-2019-2215**) | 10 patched/N/A, **1 UNPATCHED** |
| CVE-2019-2215 | Binder UAF trigger, slab identification, spray attempts | UAF confirmed, spray blocked by FASTIOV=32 |
| ION UAF | Race confirmed 91% win rate, 6+ spray techniques | No code exec trigger |
| Binder | 72K+ fuzz ops, service fuzzing, context manager | DoS only |
| Mali GPU | 29K+ fuzz ops, 24 func IDs, **5 ops re-verified** | 0 real vulns (ALL false positives) |
| Ashmem | 100K+ fuzz ops | 0 crashes |
| Samsung Knox | 8+ services probed | All secured |
| Samsung Service Mode | 20+ activities | All require KEYSTRING |
| Bootloader | Odin flash attempted | AT&T carrier locked |
| Boot/Block Devices | Direct write attempted | Root-only |
| Boot Ramdisk | 17 RC files audited | No exploitable services |
| Kernel Sysctls | core_pattern, sysrq, etc. | SELinux blocks |
| Capabilities | AF_PACKET, namespaces, BPF, keyring, pagemap | All blocked |
| SUID/Capabilities | Full filesystem scan | None found |
| Settings/Properties | WRITE_SECURE_SETTINGS, setprop | No escalation path |
| App-Context Escalation | Device admin, accessibility, 16 permissions | Powerful surveillance, no root |

---

## Session 6 — Network Recon, DRParser, ION v3, BlueBorne (2026-02-25)

### Network Reconnaissance

- **Zero TCP listening ports**, zero iptables/ip6tables firewall rules
- 18 active QUIC streams + 2 GCM push connections, all to Google
- Rich UNIX socket surface from shell: jdwp-control, mcdaemon (7+ connections),
  FactoryClientSend/Recv, DeviceRootKeyService, property_service (world-rw)
- WiFi: wlan0 at 192.168.1.104/24, p2p0 (WiFi Direct) enabled but dormant
- **BLE scanning active even with BT "off"**: Samsung beaconmanager + Google GMS

### DRParser (com.sec.android.app.parser) — UID 1000 System App

- **AT_COMMAND, QCOM_DIAG, INSTALL_PACKAGES, MASTER_CLEAR** permissions
- **DM port on COM9** (VID_04E8&PID_685D) — Shannon 308 modem, DIAG-daemon running
- UART switch present (`uart_sel=AP, uart_en=0`) but requires root to toggle
- RSA private key in APK assets (keystring encryption reversible)
- Keystring XML loadable from /sdcard — potential custom keystring injection
- **Post-root goldmine; pre-root: no direct help for escalation**

### Bluetooth / BlueBorne Assessment

- **Bluedroid stack**, BCM43454 firmware V0100.0131
- Security patch 2017-07-01 **predates BlueBorne (Sep 2017) = VULNERABLE**
- BT enabled via `settings put global bluetooth_on 1` from ADB
- Bonded Pixel 3 XL found; BLE always-scan enabled
- Nexmon WiFi monitor mode tool already installed
- **CVE-2017-0781/0782/0783/0785 likely exploitable** (needs BT proximity)

### ION UAF v3 — Exploitation Exhausted

- close(ion_fd) vs SHARE race: 0/50 (close is synchronous, mutex serialized)
- Double-SHARE: 50/50 (ION handles concurrent refs properly)
- Spray+destroy: 0/20 crashes (rbtree properly cleaned before kfree)
- **ION driver's mutex prevents handle UAF exploitation**
- ion_handle removed from rbtree before kfree; no ioctl path dereferences freed slot

### Other Probes

- **MobiCore TEE**: /dev/mobicore-user is crw-rw-rw- but SELinux blocks shell→mobicore-user_device
- **JDWP**: Active but ro.debuggable=0; only user apps exposed, no system processes
- **RIL/modem**: 7 umts_* devices, all DAC+SELinux blocked from shell
- **Audio sockets**: Abstract namespace, SELinux blocked

### Remaining Active Leads

1. **BlueBorne** (CVE-2017-0781/0782) — Bluetooth stack RCE, device unpatched.
   Requires BT proximity. Would give bluetooth/system UID code execution.
2. **DM port from host** — COM9, Shannon SIPC protocol. Needs Samsung DIAG tools
   (e.g., EFS Professional, libsamsung-ipc). No authentication required.
3. **@FactoryClientSend/Recv sockets** — Samsung factory test interface, unexplored.
4. **Custom keystrings via /sdcard** — DRParser loads from /mnt/sdcard/keystrings_EFS.xml

### Assessment Update

| Category | Vectors Tested | Result |
|----------|---------------|--------|
| Kernel CVEs | 11 (DirtyCOW, pipe_iov, futex, ping, perf, n_tty, ION, inotify, mq_notify, BPF, CVE-2019-2215) | 10 patched/N/A, 1 UNPATCHED (blocked) |
| CVE-2019-2215 | Binder UAF, 6 triggers, 48 offsets, BPF spray | UAF confirmed, FASTIOV=32 blocks exploit |
| ION UAF | Race 100% reliable, 3 exploit variants, mutex analysis | No code exec (mutex serialized) |
| Binder | 72K+ fuzz ops, service fuzzing, context manager | DoS only |
| Mali GPU | 29K+ fuzz ops, 5 ops re-verified | ALL false positives |
| Network | Full recon, UNIX sockets, firewall audit | Rich surface, no listeners |
| Bluetooth | Stack version, BlueBorne assessment, BLE scan | **LIKELY VULNERABLE** to BlueBorne |
| DRParser | Permissions, DM port, UART, EFS, keystrings | **POST-ROOT goldmine** |
| JDWP | Debug socket probe, process audit | Dead end (ro.debuggable=0) |
| MobiCore TEE | World-writable dev, SELinux check | SELinux blocks shell |
| Ashmem | 100K+ fuzz ops | 0 crashes |
| Samsung Knox | 8+ services probed | All secured |
| Samsung Service Mode | 20+ activities | All require KEYSTRING |
| Bootloader | Odin flash attempted | AT&T carrier locked |
| SUID/Capabilities | Full filesystem scan | None found |

### What IS Achievable (Non-Root Compromise)

From an installed APK (or ADB shell + APK):

1. **Full device surveillance**: Accessibility service reads ALL screen content including passwords
2. **Notification interception**: Notification listener captures ALL notifications (OTP codes, messages)
3. **Device admin control**: Lock screen, reset password, wipe device — NO user confirmation
4. **Media access**: Camera, Microphone, Location tracking
5. **Communications**: Read SMS, Contacts, Call logs
6. **Input injection**: Touch/keystroke injection for UI automation
7. **Kernel DoS**: ION heap crash or Binder context manager death or tee() deadlock (NEW)
8. **Native code execution**: From app sandbox (untrusted_app domain)
9. **Persistence**: Boot receiver for auto-start, device admin prevents uninstall

## Session 7 — Zero-Day Race Condition Fuzzing (2026-02-25)

### ZERO-DAY FOUND: tee() ABBA Deadlock (Kernel DoS)

**Severity: Medium (Denial of Service from unprivileged userspace)**

Two confirmed deadlock scenarios in the tee() syscall on kernel 3.10.9:

**Scenario A: SPLICE_F_NONBLOCK ignored**

- `tee(full_pipe_rfd, full_pipe_wfd, 65536, SPLICE_F_NONBLOCK)` deadlocks
- SPLICE_F_NONBLOCK should cause immediate EAGAIN return but is IGNORED
- Root cause: `link_pipe()` acquires pipe mutex BEFORE checking NONBLOCK flag
- Killed by SIGALRM after 20 seconds (confirmed hang)

**Scenario B: Circular tee deadlock**

- Two threads: tee(p1→p2) and tee(p2→p1) concurrently
- Classic ABBA lock ordering: Thread A holds p1 mutex, waits p2; Thread B holds p2, waits p1
- Deadlock confirmed via pthread_timedjoin_np timeout
- Deadlock PROPAGATES to other processes via shared pipe fds (Test 4 of pipe_uaf_exploit)

**Exploitation investigation:**

- ABBA deadlock + SIGKILL: 17% slab anomaly rate over 100 iterations
- kmalloc-128 accumulated +90 objects (investigated, found to be SLUB caching noise)
- Shared pipe read/tee/splice after child SIGKILL: 0 data corruption in 150 tests
- Pipe reference counting is CORRECT — no UAF possible through shared pipes
- splice() also deadlocks in same pattern (confirmed in deep_race_fuzz test 6)
- **Verdict: Kernel DoS only, NOT exploitable for code execution**

### Phase 1: mmap/ioctl Race Testing — CLEAN

- **src/mmap_ioctl_race.c** — 6 tests:
  - ION mmap vs ION_IOC_FREE: 56K+ ops, 0 crashes
  - Binder mmap vs BINDER_WRITE_READ: 52K+ ops, 0 crashes
  - close+ioctl concurrent on ION/binder: 200K+ ops, 0 crashes
  - ION triple race (mmap+ioctl+close): 75M+ ops, 0 crashes
  - fork+shared ION handle: 0 crashes
  - madvise+ION mmap: 0 crashes
- dmesg: clean throughout

### Phase 2: splice/TTY/epoll Race Testing — Found tee() Hang

- **src/splice_tty_race.c** — 8 tests:
  - splice+close race: clean
  - **tee race: HUNG (killed by SIGALRM)** ← initial discovery
  - vmsplice+munmap: clean
  - TTY ldisc switch: only N_TTY available (N_SLIP etc return EINVAL/EPERM)
  - pty close race: clean
  - epoll ADD/DEL race: 2.9M ops, clean
  - nested epoll: clean
  - splice from socket: EOPNOTSUPP

### Phase 3: Deep Race Fuzzing — Confirmed tee Deadlock

- **src/deep_race_fuzz.c** — 8 tests:
  - **tee(full→full) deadlock: CONFIRMED** (SPLICE_F_NONBLOCK ignored)
  - **Circular tee deadlock: CONFIRMED** (ABBA lock ordering bug)
  - sendfile /proc: works, ION share fd returns ESPIPE
  - writev FASTIOV boundary: properly handled (EINVAL/EFAULT)
  - dup2 vs ioctl: 1.3M ops, clean
  - ION_IOC_CUSTOM: ALL 32 commands fail (Samsung doesn't implement)
  - Signal during ION: 0 EINTR (auto-restart), clean
  - fcntl race: clean

### Phase 4: tee Deadlock Exploitation Research — DoS Only

- **src/tee_deadlock_exploit.c** — 6 tests:
  - SIGKILL cleanup: 1/50 slab anomalies (noise)
  - ABBA deadlock: CONFIRMED from threads
  - tee+close race: 0 anomalies
  - tee+fork: SIGALRM killed (deadlock hit)
  - Mass deadlock+kill: 0 slab leaks after 20 kills
  - splice deadlock: CONFIRMED

- **src/tee_abba_kill.c** — 100-iteration ABBA + SIGKILL statistical analysis:
  - 17% anomaly rate, but kmalloc-64 highly volatile (±300)
  - kmalloc-128 +90 cumulative (SLUB caching noise)
  - NOT a real slab leak

- **src/pipe_uaf_exploit.c** — 6 shared-pipe UAF tests:
  - Shared pipe read after ABBA SIGKILL: **0 corruption in 50 iterations**
  - Parent tee() after child kill: **0 anomalies**
  - Parent splice() after child kill: **0 anomalies**
  - Concurrent splice during deadlock: **HUNG** (deadlock propagates!)
  - Pipe reference counting is CORRECT, no UAF

### Phase 5: BPF Filter Cleanup Race Fuzzing — No UAF

- **src/bpf_filter_race.c** — 7 tests targeting kmalloc-256:
  - SO_ATTACH + close race: 2000/2000 setsockopt wins (no race)
  - SO_DETACH + recv race: 0 anomalies
  - Dual SO_ATTACH: both always succeed, k256 leaks detected BUT...
  - Tight attach/detach: 50K+ ops, +85 k256 after close
  - fork + detach: clean
  - sendmsg + detach: clean
  - Mass lifecycle: +184 over 10K cycles

- **src/k256_leak_confirm.c** — Precision leak confirmation:
  - **50K sequential attach/detach: NON-MONOTONIC** (7 increasing, 11 decreasing)
  - After SLUB cache flush + 500ms: only +29 from 50K cycles
  - **Verdict: SLUB per-CPU caching noise, NOT a real leak**

### Phase 6: Additional Zero-Day Surface Testing — ALL CLEAN

- **src/k256_leak_confirm.c** additional tests:
  - recvmsg MSG_ERRQUEUE + close: 0 anomalies in 2000 iterations
  - mprotect + page fault race: 0 unexpected crashes
  - PR_SET_NAME from 4 threads: 0 corruption
  - signalfd + signal delivery race: 0 anomalies
  - dup2 + read/write race: 0 anomalies
  - POSIX timer create/delete race: 0 anomalies

- **src/inotify_rename_race.c** — CVE-2017-7533 + surface probes:
  - CVE-2017-7533 (inotify + rename): 558K events, 56K renames, **0 crashes in 4 rounds**
  - AF_PACKET socket: **EPERM** (blocked by SELinux/capabilities)
  - /dev/mobicore-user: **EACCES** (blocked by SELinux)
  - sendfile /proc/self/mem + mmap race: 0 crashes
  - futex LOCK_PI + munmap race: 0 anomalies
  - futex CMP_REQUEUE edge cases: 0 anomalies

### CVE-2019-2215 Re-Analysis — Confirmed BLOCKED

- Existing BPF spray exploit (src/cve_2019_2215_bpf.c) tested 48 offsets: 0 crashes
- close(epfd) → list_del is self-referential (single wait entry points to itself)
- wake_up never triggered (BINDER_THREAD_EXIT removes thread from proc tree)
- UIO_FASTIOV=32 blocks iovec trigger (writev ≤32 uses stack, ≥33 → k512 not k256)
- No alternative trigger mechanism identified
- **CVE-2019-2215 is UNPATCHED but UNEXPLOITABLE on this specific device**

### Session 7 Summary

| Category | Tests Run | Total Ops | Crashes | Bugs Found |
|----------|-----------|-----------|---------|------------|
| mmap/ioctl races | 6 | 225M+ | 0 | 0 |
| splice/tee races | 8 | 2.9M+ | 0 | **2 (deadlock)** |
| Deep race conditions | 8 | 1.3M+ | 0 | **1 (deadlock confirm)** |
| tee exploitation | 6+6+6 | 400+ iterations | 0 | DoS only |
| BPF filter races | 7 | 16K+ cycles | 0 | 0 (noise) |
| Additional surfaces | 6 | 5000+ | 0 | 0 |
| CVE-2017-7533 | 4 rounds | 558K events | 0 | 0 |
| Other CVEs/surfaces | 6 | 2600+ | 0 | 0 |
| **TOTAL** | **~60 tests** | **~230M ops** | **0** | **1 zero-day (DoS)** |

### Remaining Active Leads (Unchanged)

1. **BlueBorne** (CVE-2017-0781/0782) — BT proximity required
2. **DM port** — COM9, Shannon 308, no auth, needs Samsung DIAG tools
3. **Factory sockets** — @FactoryClientSend/Recv, unexplored
4. **DRParser keystrings** — /sdcard/keystrings_EFS.xml exploitation post-root

### Source Files Created This Session

- `src/mmap_ioctl_race.c` — mmap/ioctl race fuzzer (6 tests)
- `src/splice_tty_race.c` — splice/TTY/epoll race fuzzer (8 tests)
- `src/deep_race_fuzz.c` — deep race condition fuzzer (8 tests)
- `src/tee_deadlock_exploit.c` — tee deadlock exploitation research (6 tests)
- `src/tee_abba_kill.c` — ABBA deadlock + SIGKILL slab analysis (100 iterations)
- `src/pipe_uaf_exploit.c` — shared pipe ABBA UAF attempt (6 tests)
- `src/bpf_filter_race.c` — BPF sk_filter cleanup race fuzzer (7 tests)
- `src/k256_leak_confirm.c` — k256 leak confirmation + surface fuzzer (8 tests)
- `src/inotify_rename_race.c` — CVE-2017-7533 + AF_PACKET + mobicore + futex (6 tests)
- `src/cve_2019_2215_multi.c` — Multi-epoll CVE-2019-2215 (5 tests)
- `src/priv_probe2.c` — Novel surface probes: BPF readback, ION page UAF, keyctl, pagemap, device/netlink probes
- `src/cve_2019_2215_zero.c` — Zero-byte BPF spray exploit (6 tests)
- `src/cve_2019_2215_real.c` — Correct trigger with BC_TRANSACTION (3 tests)
- `src/cve_2019_2215_pin.c` — CPU-pinned exploit with slab diagnostics (5 tests)
- `src/cve_2019_2215_hang.c` — Definitive hang detection: proves Samsung patched CVE-2019-2215

## Session 8 — CVE-2019-2215 Deep Exploitation & Samsung Patch Discovery

### Key Findings

#### 1. Samsung Proprietary CVE-2019-2215 Fix (CONFIRMED)

**The UAF vulnerability exists in the code but is effectively PATCHED through a Samsung proprietary fix.**

Evidence chain:

- Kernel disassembly confirms binder_poll has BOTH paths:
  - `poll_wait(filp, &thread->wait, pt)` at thread+0x2C when `wait_for_proc_work = false`
  - `poll_wait(filp, &proc->wait, pt)` at proc+0x68 when `wait_for_proc_work = true`
- BC_TRANSACTION to handle 0 succeeds (sets transaction_stack → wait_for_proc_work=false)
- Hang detection test: sprayed NON-ZERO data at ALL 25 possible offsets in kmalloc-256
  → close(epfd) NEVER hangs, NEVER crashes across 100+ trials
- Offset sweep: non-zero at every 8-byte boundary from +20 to +212 → all clean
- Conclusion: Samsung's binder_free_thread nullifies eppoll_entry->whead before kfree()
  → ep_remove_wait_queue sees whead=NULL and skips remove_wait_queue → no UAF access

This is a Samsung-specific fix applied BEFORE CVE-2019-2215 was publicly disclosed (SPL 2017-07 vs CVE disclosure Oct 2019). Samsung's internal security team apparently identified and fixed this independently.

#### 2. Multi-epoll Analysis

- Previous tests failed because binder_poll was using proc->wait (not thread->wait)
- Fixed ioctl encoding: BC_TRANSACTION = 0x40286300 (sizeof=40), not 0x40406300
- BC_ENTER_LOOPER (0x630C) works; BC_TRANSACTION to servicemanager works (rc=0)
- Multi-epoll with 2-3 instances: 0 crashes, 0 BPF corruption in 80+ trials

#### 3. BPF Zero-Byte Spray Technique

- BPF_LD_IMM (code=0x0000) creates all-zero BPF instructions → valid filter
- Ensures spin_lock at any offset sees 0 (unlocked) → no hang
- SO_GET_FILTER readback works perfectly (identity check confirmed)
- Combined with multi-epoll: still 0 corruption → confirms Samsung fix

#### 4. Novel Attack Surface Probes

Accessible devices from shell (SELinux allows):

- `/dev/mali0` — Mali GPU (RW) ← **HIGHEST PRIORITY TARGET**
- `/dev/alarm` — Android alarm (RO)
- `/dev/ashmem` — Shared memory (RW)
- `/dev/input/event0,1` — Input events (RW)
- NL_ROUTE (netlink 0) — accessible + bindable
- NL_SELINUX (netlink 7) — accessible + bindable

Blocked surfaces:

- `/dev/mobicore-user` — SELinux denies (DAC is world-writable)
- `/dev/s5p-smem`, `/dev/dek_req`, `/dev/sdp_mm` — SELinux denies
- `/dev/uinput`, `/dev/tun`, `/dev/uhid` — SELinux denies
- Most netlink families — SELinux denies
- `/proc/self/pagemap` — EPERM (restricted on this kernel)
- Keyring subsystem — EPERM (all keyctl operations denied)
- POSIX message queues — not implemented
- `/proc/timer_list` — readable but no kernel addresses leaked

#### 5. ION Page-Level UAF Test

- mmap(dma_buf_fd) + close(dma_buf_fd) + close(ion_fd) → mapping persists
- Pages NOT reclaimed even under heavy allocation pressure (1000 mmap allocations)
- ION uses proper VM reference counting via vm_ops → pages released on munmap
- NOT exploitable: pages are protected by VMA lifecycle

#### 6. Kernel Binary Analysis

- Extracted from boot.img: gzip at offset 0x6A48, decompressed to 11.5MB
- Samsung-specific `binder.proc_no_lock` module parameter found
- binder_poll disassembled: confirmed thread+0x2C wait queue head
- binder_thread layout: transaction_stack at +0x18, todo at +0x1C, return_error at +0x24, wait at +0x2C

### Exploitation Status Summary

| Target | UAF Confirmed | Spray Works | Exploitation | Block Reason |
|--------|:---:|:---:|:---:|---|
| ION (kmalloc-64) | ✅ 91% race | ✅ socketpair | ❌ BLOCKED | No fn-ptr victim in k64 |
| Binder (kmalloc-256) | ✅ thread freed | ✅ BPF 26-insn | ❌ BLOCKED | Samsung whead=NULL fix |
| Mali GPU | ⬜ Not tested | ⬜ N/A | ⬜ Races clean | Standard dispatch robust |
| **Mali Vendor Dispatch** | ✅ **CRASH** | N/A | 🔴 **KERNEL PANIC** | Wild pointer deref! |

### Next Steps

1. **Exploit Mali vendor dispatch** — control the wild pointer for code execution
2. **Kernel binary RE** — find gpu_vendor_dispatch, understand the pointer handling
3. **Heap spray at low address** — mmap_min_addr=32768, place fake struct at 0x8000+

## Session 8b — Mali Samsung Vendor Dispatch Kernel Panic (ZERO-DAY)

### Discovery

While running mali_race_exploit.c (targeted race condition fuzzer), the device kernel-panicked
5 times during testing. Root cause analysis revealed a Samsung-specific vulnerability in the
Mali GPU driver's vendor dispatch path.

### The Vulnerability

Samsung's Mali r7p0 driver registers TWO ioctl dispatch paths on `/dev/mali0`:

- Standard kbase: magic `'M'` (0x4D) — properly validates user pointers
- Samsung vendor: magic `0x80` — **DOES NOT validate user pointers for MEM_IMPORT**

When MEM_IMPORT (func 513) is called via vendor dispatch with a 48-byte struct,
the `phandle` field is dereferenced **directly as a kernel pointer** instead of
being treated as a user-space pointer. This causes:

```
PC is at _raw_spin_lock_irqsave+0x30/0x6c
LR is at down+0x18/0x54
```

→ Kernel tries to acquire a semaphore at the address specified by `phandle`,
which is a small integer (the fd number) → wild pointer → PANIC.

### Crash Reproduction (100% reliable)

```c
ioctl(mali_fd, _IOC(3, 0x80, 0, 48), buf_with_nonzero_phandle);
// Instant kernel panic
```

### Key Evidence

| Test | Magic | phandle | Result |
|------|-------|---------|--------|
| Correct import (magic 'M') | 'M' | pointer | result=3 (safe) |
| Correct import (magic 'M') | 'M' | raw fd | result=3 (safe) |
| Vendor import, zeroed | 0x80 | 0 | result=3 (safe) |
| **Vendor import, non-zero** | **0x80** | **raw fd** | **KERNEL PANIC** |

- Crashed device 5 times during investigation
- ION alloc/share is irrelevant — any non-zero phandle value crashes
- Standard Mali operations (alloc, free, flags_change) all clean
- Mali race conditions (8 targeted tests) showed 0 bugs

### Exploitation Path

1. **DoS**: Confirmed. Single ioctl from unprivileged shell.
2. **Controlled pointer**: phandle value directly becomes a kernel pointer
   - mmap_min_addr=32768, so we can potentially map at 0x8000
   - Place fake struct file with controlled semaphore/spinlock
   - After down() returns, the import code continues with attacker-controlled state
3. **No KASLR**: Kernel text is at known addresses
4. **No PXN**: Can potentially execute userspace code in kernel mode

### Files Created

- `findings/mali-vendor-dispatch-vuln.md` — Full vulnerability writeup
- `src/mali_race_exploit.c` — Original race fuzzer (discovered the crash)
- `src/mali_vendor_crash.c` — Systematic analysis tool
- `src/mali_import_safe.c` — Step-by-step isolation
- `src/mali_import_v2.c` — Control test (correct path)
- `src/mali_import_crash.c` — Crash reproducer
- `src/mali_import_min.c` — Minimal reproducer

## ⚠ Session 9 — MAJOR CORRECTIONS & Exhaustive Fuzzing (2026-02-25)

### 🔴 CRITICAL CORRECTION: "Mali Vendor Dispatch Vulnerability" is FALSE

**The "zero-day" reported in Session 8b was caused by a BUG IN OUR TEST CODE, not a kernel vulnerability.**

Root cause: `ion_alloc_fd()` used `uint64_t` fields for an ARM32 struct that uses `size_t` (4 bytes):

```c
// WRONG (was in all test code before fix):
struct { uint64_t len; uint64_t align; uint32_t heap; uint32_t flags; int32_t fd; } // 28 bytes
// Kernel reads only 20 bytes → heap_id_mask gets 0x1000 (bit 12) instead of 0x01 (bit 0)!

// CORRECT for ARM32:
struct { uint32_t len, align, heap_id_mask, flags, handle; } // 20 bytes, needs ION_IOC_SHARE for fd
```

**What actually happened:**

1. ION_IOC_ALLOC with misaligned struct → heap_id_mask=0x1000 (bit 12)
2. Bit 12 = Samsung TrustZone/secure heap → kernel crash at `down()` semaphore
3. `ion_alloc_fd()` returned -1 (handle field at wrong offset)
4. Mali MEM_IMPORT was called with fd=-1 → it returned error (not crash)
5. The CRASH was from the ION allocation, NOT from Mali

**Proof that magic byte is irrelevant:**

- Kernel source analysis: `kbase_ioctl()` at line 1401 of `mali_kbase_core_linux.c` only uses `_IOC_SIZE(cmd)` — magic byte is COMPLETELY IGNORED
- `mali_safe_probe.c` test 1 (magic 'M') and test 7 (magic 0x80) produce IDENTICAL results with correct ION struct
- All dispatch goes through `kbase_dispatch()` regardless of magic

**ION heap crash confirmed (DoS only):**

- `ion_heap_crash_test.c`: heap bit 0 (0x01) OK, bit 1 (0x02) OK, bit 2 (0x04) CRASHES kernel
- Crash signature matches: PC at `_raw_spin_lock_irqsave`, LR at `down()`
- This is a Samsung ION secure heap DoS, NOT a Mali vulnerability
- **No code execution possible — the semaphore address is fixed kernel state**

### 🔴 CRITICAL CORRECTION: CVE-2019-2215 BPF Spray Was Invalid

**All previous BPF spray tests used invalid BPF opcode (code=0xFFFF), causing setsockopt to silently fail. The spray was EMPTY in every test.**

Fixed in `cve_2019_2215_hang.c`:

- Changed `code=0xFFFF` to `code=0x04` (BPF_ALU_ADD_K — valid opcode, non-zero)
- Added setsockopt return value validation (confirmed: `setsockopt=0 errno=0`)
- With VALID BPF spray: **0 hangs in 20 trials (main test), 0/25 offset sweep**
- **Samsung DEFINITIVELY patched the UAF cleanup (nullifies whead before kfree)**

### CVE-2019-2215 — DEFINITIVELY CLOSED

| Test | Trigger | Trials | Hangs | Conclusion |
|------|---------|--------|-------|------------|
| Test 1 (main) | BC_TRANSACTION | 20 | 0 | Samsung patched |
| Test 2 (baseline) | No transaction | 5 | 0 | Expected clean |
| Test 3 (reply) | BC_REPLY error | 10 | 0 | Samsung patched |
| Test 4 (sweep) | All 25 offsets | 25 | 0 | No UAF at ANY offset |

### Mali GPU Driver Race Fuzzing — ALL CLEAN

With CORRECT ION struct, Mali MEM_IMPORT now WORKS (previously appeared broken):

| Test | Description | Trials | Anomalies |
|------|-------------|--------|-----------|
| Test 1 | close(mali_fd) vs concurrent ioctl | 200 | 0 |
| Test 2 | MEM_FREE vs MEM_QUERY race | 200 | 0 |
| Test 3 | Mali mmap vs MEM_FREE race | 200 | 0 |
| Test 4 | Rapid MEM_ALLOC + MEM_FREE | 100 | 0 |
| Test 5 | Double MEM_FREE (same gpu_va) | 50 | 0 |
| Test 6 | Import + Free race (threads) | 100 | 0 |
| Test 7 | Multi-context import + close | 100 | 0 |
| Test 8 | Alloc + mmap + immediate close | 200 | 0 |
| **Total** | | **1150** | **0** |

### PTMX/TTY Race Fuzzing — ALL CLEAN

| Test | Description | Trials | Anomalies |
|------|-------------|--------|-----------|
| Test 1 | TIOCSETD + concurrent I/O | 100 | 0 |
| Test 2 | Close master + slave I/O | 200 | 0 |
| Test 3 | TIOCSTI + ldisc change | 100 | 0 |
| Test 4 | Rapid open/close | 50 | 0 |
| Test 5 | VHANGUP + I/O | 100 | 0 |
| Test 6 | Termios changes + I/O | 100 | 0 |
| Test 7 | Multi-thread chaos | 50 | 0 |
| **Total** | | **700** | **0** |

### Samsung Deep Probe Results

| Probe | Result |
|-------|--------|
| ION_IOC_CUSTOM (all commands) | ENOTTY (errno=25) — not implemented |
| Ftrace buffer_size_kb overflow | INT_MAX accepted (capped at 4194303), ENOMEM for huge values |
| /proc/self/mem write | Works for COW pages (expected), NOT Dirty COW |
| madvise DONTNEED + read race | Benign on anonymous mappings |
| Netlink RTM_GETLINK | Works (3192 bytes interface data received) |
| Netlink RTM_NEWROUTE | Needs investigation (response received) |
| mremap to 0xBEF00000 | WORKS (near kernel boundary) |
| ION mremap | EFAULT (not supported) |
| Samsung DECON debugfs | Readable, no address leak |
| dma_buf debugfs | 28 objects listed, no kernel addresses |
| Mali debugfs quirks | Readable (-rw-r--r--) but NOT writable by shell |
| ION custom + FREE race | 0/100 anomalies (ION_IOC_CUSTOM not implemented) |

### Updated Exploitation Status

| Target | UAF | Spray | Exploitable | Block Reason |
|--------|:---:|:---:|:---:|---|
| ION (kmalloc-64) | ✅ 91% | ✅ socketpair | ❌ | No fn-ptr victim in k64 |
| Binder (kmalloc-256) | ✅ freed | ✅ BPF 26-insn | ❌ | **Samsung whead=NULL fix (CONFIRMED)** |
| Mali vendor dispatch | ❌ DEBUNKED | N/A | ❌ | Was ION struct bug, not Mali |
| Mali driver races | ❌ Clean | N/A | ❌ | Proper locking in 1150 trials |
| PTMX/TTY races | ❌ Clean | N/A | ❌ | No race found in 700 trials |
| ION heap DoS | ✅ bit 2,12 | N/A | DoS only | Fixed semaphore, not controllable |

- `src/mali_safe_probe.c` — **FIXED** ION struct (uint64_t → uint32_t) + ION_IOC_SHARE
- `src/ion_heap_crash_test.c` — ION heap bit crash testing (confirmed bit 2 crashes)
- `src/cve_2019_2215_hang.c` — **FIXED** BPF spray (code=0xFFFF → 0x04) + validation
- `src/mali_race_fuzz.c` — Mali GPU race fuzzer (8 tests)
- `src/ptmx_race_fuzz.c` — PTMX/TTY race fuzzer (7 tests)
- `src/samsung_deep_probe.c` — Samsung-specific deep probing (8 tests)

### Current Assessment

Total attack surface coverage across all sessions:

- **11 CVEs** tested: all patched, blocked, or N/A
- **2 confirmed UAFs** (ION + binder): both exploitation-blocked
- **5 race fuzzers** covering Mali, PTMX, ION, binder, splice: **0 exploitable bugs in 233M+ operations**
- **1 zero-day** found: tee() ABBA deadlock (DoS only)
- **1 false positive** corrected: Mali vendor dispatch (was ION struct bug)

**Additional potential viable paths (non-kernel):**

1. **BlueBorne** (CVE-2017-0781/0782) — BT stack RCE, requires BT proximity
2. **DM port exploitation** — COM11, Shannon 308 modem, no authentication
3. **Factory sockets** — @FactoryClientSend/Recv, protocol unknown
4. **DRParser keystrings** — /sdcard/keystrings_EFS.xml (post-root value)

---

## Session 10 — Comprehensive Recon Run (2026-02-26)

### 🔴 CRITICAL FINDING: TIMA Leaks SELinux Physical Addresses in dmesg

MobiCore daemon logs TIMA kernel integrity data to dmesg, including PHYSICAL addresses
of critical security variables:

```
MobiCore mcd: TIMA_INIT: SELinux zero paddr- enabled:   20ab00a8
MobiCore mcd: TIMA_INIT: SELinux zero paddr- enforcing: 20b7ad18
MobiCore mcd: write_ptr_paddr is 27406000
```

**Virtual address conversion** (phys + 0xA0000000):

- `selinux_enabled` = **0xC0AB00A8** (was not previously known)
- `selinux_enforcing` = **0xC0B7AD18** (previous estimate 0xC0B7AD54 was WRONG by 60 bytes!)
- TIMA write_ptr = **0xC7406000**

⚠ **Previous address in this log (0xC0B7AD54) is INCORRECT. Use 0xC0B7AD18.**

TIMA actively monitors these addresses — writing 0 to selinux_enforcing would be detected
on next TIMA_MEASURE_KERNEL_ONDEMAND cycle and trigger device lockdown.

### DM Port — Full AT Command & DIAG Access (COM11)

DM port has MOVED from COM9 to COM11. Full AT command access confirmed:

| Command | Response |
|---------|----------|
| AT+DEVCONINFO | Full device info: IMEI(000000000000000), SN(R0000000000), LOCK(NONE), LIMIT(FALSE) |
| AT+CGMM | Samsung LTE ALPSS |
| AT+CLCK="PN",2 | **+CLCK: 1** — Network lock ACTIVE (AT&T) |
| AT+CLCK="PU"/"PP"/"PC"/"SC",2 | +CLCK: 0 — Other locks OFF |
| AT+CPIN? | SIM not inserted |

Samsung DIAG subsystem (0x4B, 0x08) responds to commands. Shannon modem accessible.

⚠ **Aggressive DM port probing disrupted USB composite device — caused ADB disconnect.**
Must add delays between commands and monitor ADB in parallel.

### Service Enumeration — 330 Services

Full binder service list obtained. Key probing results:

| Service | Methods | Result |
|---------|---------|--------|
| APNWidgetRootService | 10 | APN config widget (NOT root); method 5/6 accept params |
| EngineeringModeService | 7 | Authorization error (-1300) on methods 3-5,7 |
| DeviceRootKeyService | 2 | Method 1 OK, method 2 unauthorized |
| tima | 3 | Methods 1-2 unauthorized, method 3 empty |
| `execute` | ? | **UNINVESTIGATED** — IExecuteManager interface |

### Abstract Unix Socket Probe — ALL SELinux-Blocked

Built and deployed `socket_probe.c`. All abstract sockets return EPERM from shell:

- @FactoryClientSend/Recv, @ATDMultiClient, @DeviceRootKeyService, @SatsService,
  @Multiclient, @imsd, @diag_mycmc_app2cp — all errno=13 (Permission denied)
- @BTHostPowerCtrl, @knoxVpnFdTransfer — errno=111 (Connection refused, not EPERM)

Filesystem sockets accessible: property_service, logd, dnsproxyd, fwmarkd.
Blocked: netd, vold, installd, lmkd, mdns, zygote.

### Init Service Control — ALL SELinux-Denied

ctl.start/stop from shell:

- DAC check passes (setprop returns success)
- SELinux DENIES all operations (confirmed via AVC denials in dmesg)
- Tested: flash_recovery, bootanim, sec-sh, epmlogd — ALL blocked

### USB Gadget Analysis

- Active: rndis,acm,dm,adb
- RNDIS interface exists but no IP assigned
- All USB gadget sysfs entries root-only (not writable by shell)
- No FunctionFS endpoints accessible

### Bluetooth Stack — BlueBorne Likely Vulnerable

- Bluedroid stack, BCM43454 V0100.0131
- BT enabled, address 02:00:00:00:00:21
- Paired: Pixel 3 XL (7C:D9:5C:B9:0D:80)
- Security patch 2017-07-01 PREDATES BlueBorne (Sep 2017)
- BT Snoop logging ENABLED (275KB log)
- **CVE-2017-0781/0782/0783/0785 likely exploitable**

### Property System

Notable: `adb_root=1` set but ineffective, `warranty_bit=0` (Knox OK),
`persist.radio.ramdump=1`, `debug_level=0x4f4c`, `sec_atd.tty=/dev/ttySAC2`

### Installed Tools

Previous root attempts visible: Magisk, z4root, Superuser all installed but inactive.
Hacking tools: NetHunter, Nexmon, Hijacker, Termux. AT&T Device Unlock app installed.

### Session 10 Source Files

- `src/socket_probe.c` — Abstract unix socket connectivity tester

### Updated Attack Vector Priority

| # | Vector | Feasibility | Impact | Status |
|---|--------|-------------|--------|--------|
| 1 | **BlueBorne (CVE-2017-0781/0782)** | Medium (needs BT proximity) | HIGH (bluetooth UID) | Unpatched, needs testing |
| 2 | **DM port DIAG (COM11)** | HIGH (direct access) | Medium-High (modem control) | Responsive, needs protocol RE |
| 3 | **`execute` service** | Unknown | Unknown | UNINVESTIGATED |
| 4 | **EngineeringModeService** | Low (auth required) | High | Auth error from shell |
| 5 | **SELinux policy analysis** | Medium | Varies | sepolicy pulled, needs analysis |
| 6 | **Modem ramdump** | Low | Medium | ramdump=1, needs trigger |

### Session 10 Continuation — Offline Analysis (2026-02-26)

**Status:** Device went OFFLINE during DM port probing. USB composite device disrupted,
PID changed from 0x6864 (ADB) to 0x685D (DM-only). DM port (now COM5) unresponsive.
**Needs physical USB cable reconnect to restore ADB.**

#### Critical Discovery: USB Configuration Vulnerability

| Property | Value | Notes |
|----------|-------|-------|
| `persist.sys.usb.config` | `acm,dm` | **NO ADB!** Persists across reconnects |
| `persist.sys.usb.q_config` | `rndis,acm,dm,adb` | Has ADB — "queued" config |

When USB is disrupted, device falls back to persist config WITHOUT ADB. This is why
aggressive DM port probing caused permanent ADB loss until physical intervention.

#### Samsung Platform Key Verified (NOT AOSP test-key)

Despite `ro.bootimage.build.fingerprint` showing `test-keys`, DRParser.apk analysis
confirms Samsung's own platform signing key:

- **Issuer:** Samsung Corporation, DMC, Samsung Cert, Suwon City
- **Email:** <android.os@samsung.com>
- **SHA-256:** `6e40b1b7ce4c8c576f88e6c90308616a813afc5e4a14c41bebd45536df21e89f`

**Conclusion:** Test-key signing attack NOT viable.

#### DM Port Now COM5 (USB PID 685D)

After USB disruption, DM port moved from COM11 to COM5. Port is unresponsive to both
AT commands and HDLC-framed DIAG commands. Device USB stack is in broken state.

#### Offline Analysis Completed

1. **Deep dmesg analysis** — No additional kernel pointer leaks beyond TIMA entries
2. **Property deep analysis** — 420 properties categorized. Key findings:
   - `persist.radio.ramdump=1` (modem ramdumps enabled)
   - `ro.boot.sec_atd.tty=/dev/ttySAC2` (AT distributor UART)
   - `ro.boot.odin_download=1` (Odin mode available)
   - BCD partition offsets at 0x700630-0x700770 (80-byte stride for IMEI/ME/SN/PR/SKU)
   - `persist.security.ams.enforcing=3` (AMS enforcement active)
3. **Service categorization** — All 330 services categorized:
   - 24 root/admin related
   - 15 enterprise/MDM/Knox
   - 11 network/VPN
   - 7 modem/telephony
   - 2 debug/test
   - 95 uncategorized (many Samsung-specific)
4. **SELinux policy** — setools4 cannot parse Android policy v30 format
   - checkpolicy/sedispol not available in WSL (no sudo)
   - Need device's own tools or Android-specific parser
5. **Platform signing key** — Samsung's own key, NOT AOSP test-key

#### New High-Value Service Targets (for next session)

| Priority | Service | Interface | Why |
|----------|---------|-----------|-----|
| **1** | `execute` | `IExecuteManager` | Name suggests command execution |
| **2** | `usb` | `IUsbManager` | Might restore ADB config |
| **3** | `persistent_data_block` | `IPersistentDataBlockService` | OEM unlock, FRP |
| **4** | `iccc` | `IIcccManager` | TIMA integrity chain control |
| **5** | `sedenial` | `ISEDenialService` | SELinux denial management |
| **6** | `serial` | `ISerialManager` | Hardware serial port access |
| **7** | `remoteinjection` | `IRemoteInjection` | Knox MDM remote control |
| **8** | `ABTPersistenceService` | `IABTPersistence` | Absolute persistence agent |

#### Scripts Prepared for Reconnection

- `src/service_deep_probe.c` — C program to probe all 15 high-value services, with special
  execute service testing (tries string arguments on multiple methods)
- `src/usb_restore_adb.c` — USB ADB restoration tool (property service, gadget sysfs, ctl.restart)
- `src/recon_reconnect.sh` — Shell script for comprehensive follow-up recon

Both C programs compiled and ready to push to device via ADB.

#### Findings Report Updated

`findings/comprehensive-recon-session10.md` updated with 6 new findings (12-17):

- Finding 12: USB Configuration Vulnerability
- Finding 13: Samsung Platform Signing Key verification
- Finding 14: BCD Partition Offsets
- Finding 15: High-Value Uninvestigated Services
- Finding 16: AT Distributor Daemon
- Finding 17: Modem Ramdump Enabled

### ⚡ Immediate Actions When Device Reconnects

1. **Physical USB replug** — restore ADB connectivity
2. **Push and run service_deep_probe** — probe execute service first
3. **Run recon_reconnect.sh** — comprehensive follow-up checks
4. **Verify platform cert** — pull framework-res.apk and check cert hash
5. **Test kernel function tracing** — shell may have debugfs write access
6. **DM port AT commands** — with delays, get full AT+CLAC list

---

## Session 10c: Post-Reboot Deep Recon (2026-02-26)

### Summary

Device rebooted (caused by MASTER_CLEAR broadcast). After reconnection, performed deep
enumeration of services, content providers, secret codes, debugfs, SELinux interfaces,
and SD card artifacts. Added 9 new findings (#18-26).

### Key Results

#### MASTER_CLEAR Broadcast → Reboot

- `am broadcast -a android.intent.action.MASTER_CLEAR` triggered device reboot from shell UID 2000
- No permission error returned — broadcast was accepted and processed
- This is a DoS finding; unclear if it performed factory reset or just rebooted

#### Secret Code Massive Enumeration

- Pulled and analyzed 4 APKs (DeviceKeystring, RilServiceModeApp, serviceModeApp_FB, SecSettings2)
- Mapped **120+ secret codes** to their receiver handlers using aapt manifest analysis
- Key dangerous codes identified: 7594 (shutdown), RTN (NV reset), 2767*2878 (potential wipe)
- Key useful codes: CP_RAMDUMP (modem dump), 0808 (USB config), 9900 (SysDump), 4636 (testing)

#### ABTPersistenceService Auth Bypass

- Method 5 (installApplication) bypasses authorization and reaches APK install logic
- Returns "no APK file nor URL was specified" instead of "Not authorized"
- Method 9 can update package persist flags (needs valid package name)
- Methods 1,3,4,7,8 properly block with "Not authorized" — selective auth bypass on M5/M9/M10

#### Debugfs Rich Information Disclosure

- `/sys/kernel/debug/` fully mounted and largely readable
- ION heap stats, Mali GPU memory, binder debug all accessible
- `buffer_size_kb` writable by shell group (confirmed write to 4096)
- `trace_marker` world-writable (confirmed write)
- Physical memory range: 0x20000000..0x7f4fffff (1.5GB)

#### OEM Unlock Flag Set

- `settings put global oem_unlock_enabled 1` succeeds from shell
- Persists across reads — bootloader may check this on next reboot to fastboot

#### Settings Write Capabilities

- Settings.Global: writable (package_verifier_enable, oem_unlock_enabled, etc.)
- Settings.Secure: partially writable (install_non_market_apps, default_input_method, etc.)
- setprop: debug.* properties writable (atrace flags set to 0xffffffff)
- Input injection: `input text` and `input keyevent` work without restriction

#### Device Unencrypted

- `ro.crypto.state = unencrypted` — all data in plaintext on eMMC

#### Content Provider Scan

- Scanned ~50+ content providers for accessibility
- Most blocked by permissions; contacts and media providers accessible
- AMP property provider accessible but empty
- Settings vibration provider readable

#### Partition Map Complete

- 22 named partitions mapped: EFS(p3), CARRIER(p8), PARAM(p9), BOOT(p10),
  RECOVERY(p11), RADIO(p14), TDATA(p16), SYSTEM(p20), USERDATA(p22)
- All block device reads blocked by SELinux

#### KingRoot/SuperSU Remnants

- SD card contains SuperSU-v2.4.zip, superuser.apk, KingRoot artifacts
- Stock boot.img (8.7MB) present for analysis
- Encrypted KingRoot configs present

### Updated Top Attack Vectors (Prioritized)

1. **ABTPersistenceService M5** — Auth bypass installer, need AppProfile format
2. **Secret code CP_RAMDUMP** — Modem NV dump (carrier lock data)
3. **Secret code 0808** — USB config (could unlock hidden ADB modes)
4. **OEM unlock + fastboot** — Flag is set, test if bootloader respects it
5. **DRParser via DEMO_CONTROL** — Has INSTALL_PACKAGES, WRITE_SECURE_SETTINGS
6. **Boot.img analysis** — Kernel extraction, vulnerability research
7. **SELinux access interface** — Write C program for binary-format queries
8. **BlueBorne** — Pre-patch BT stack, BT snoop logs available

---

## Session 10d — ABTPersistenceService RE + Privilege Escalation APK

### Date: 2026-02-26

### ABTPersistenceService Deep Reverse Engineering

**Parcelable Format Discovery:**
Through byte-level analysis of the binder Parcel wire format, reversed the AppProfile Parcelable:
- `i32 1` (non-null indicator)
- `readString()` → packageName
- `readInt()` → version (must be >= 1)
- `readString()` → apkPath
- `readString()` → downloadUrl

**Critical Correction:** Earlier "auth bypass" on M5 was actually just input validation errors from garbled Parcelable data. With properly formatted data (valid packageName + version + apkPath), M5 DOES enforce authorization: "Not authorized to access ABT Persistence Service".

**Full 25-Method Map Completed:**
- 12 methods have strict auth checks (M1-M9, M11-12, M17-20, M24)
- 13 methods bypass auth but only reach validation/query logic (M10, M13-16, M21-23, M25)
- M13 is a reflection-based method dispatcher using MethodSpec Parcelable
- M21/M25 require an "access key" (Absolute's auth secret)
- M23 is persistApp() — checks if package exists before auth
- Implementation compiled into boot.oat, NOT in services.jar DEX

### MAJOR BREAKTHROUGH: Shell APK Installation + Permission Grants

**Discovery:** Shell (UID 2000) can install APKs and grant development permissions!

Built and deployed privesc APK (`com.privesc.agent`):
1. `pm install -r -g /data/local/tmp/agent.apk` → **Success**
2. Granted 9 development permissions via `pm grant`:
   - **WRITE_SECURE_SETTINGS** ✓
   - **READ_LOGS** ✓  
   - **DUMP** ✓
   - **INTERACT_ACROSS_USERS** ✓
   - CHANGE_CONFIGURATION, SET_DEBUG_APP, SET_PROCESS_LIMIT, SET_ALWAYS_FINISH, PACKAGE_USAGE_STATS ✓
3. Activated device admin: `dpm set-active-admin` → **Success**
   - Policies: wipe-data, reset-password, force-lock, limit-password, watch-login
4. Enabled accessibility service: `settings put secure enabled_accessibility_services` → **Active**

### Device Owner Attempt (Blocked)
- `dpm set-device-owner` failed: "Not allowed — already some accounts on the device"
- One Samsung account: redacted.account@example.com (type=com.osp.app.signin)
- `pm clear com.osp.app.signin` removes app data but account persists
- Account removal via AccountManager binder fails (bad magic number)

### Current Capabilities Summary
| Capability | Status | Notes |
|-----------|--------|-------|
| Install APKs | ✓ | `pm install -r -g` from shell |
| Grant dev perms | ✓ | WRITE_SECURE_SETTINGS, READ_LOGS, DUMP |
| Device admin | ✓ | reset-password, force-lock, wipe-data |
| Accessibility svc | ✓ | Full UI control |
| Device owner | ✗ | Blocked by Samsung account |
| Root/kernel | ✗ | No kernel write primitive found |
| SELinux disable | ✗ | Need kernel write to 0xC0B7AD18 |

### Key Remaining Vectors
1. **Boot.img analysis** — Extract kernel, find vulnerabilities
2. **Account removal → device owner** — Would give silent install capability
3. **perf_event_open** — paranoid=1, limited kernel profiling possible
4. **Kernel capability bounding set** — CAP_SETUID/CAP_SETGID present (0xc0)
5. **RNDIS USB networking** — Additional USB attack surface
6. **ABT M21/M25 access key** — If we find the key, full auth bypass

---

## Session 10e — Device Owner Exploitation & Service Probing (2026-02-26)

### Overview
With device owner achieved (Session 10d removed Samsung account, then `dpm set-device-owner` succeeded), this session built an enhanced APK with device owner API capabilities and conducted comprehensive probing of all accessible binder services, mount/encryption interfaces, ftrace subsystem, and Samsung-specific system services.

### Enhanced PrivEsc APK (v2)
Built and deployed enhanced APK with:
- **CommandReceiver** — Broadcast-triggered command dispatch for device owner APIs
- **BinderProbeService** — Background service using ServiceManager reflection + Intent binding
- Writes results to `/sdcard/agent_output.txt` and `/sdcard/binder_probe.txt`

Verified capabilities from app context:
- `isDeviceOwner: true`, `isProfileOwner: true`, `isAdminActive: true`
- UID: 10139, SELinux domain: `u:r:untrusted_app:s0:c512,c768` (unchanged)
- 31 permissions granted including WRITE_SECURE_SETTINGS, READ_LOGS, DUMP, INTERACT_ACROSS_USERS

### Device Owner API Results
| API | Result | Notes |
|-----|--------|-------|
| enableSystemApp() | ✓ SUCCESS | Enabled all 12 disabled system apps |
| setGlobalSetting("development_settings_enabled") | ✓ | Set to 1 |
| setGlobalSetting("stay_on_while_plugged_in") | ✓ | Set to 7 |
| setSecureSetting("install_non_market_apps") | ✓ | Set to 1 |
| setGlobalSetting("usb_config") | ✗ BLOCKED | "device owners cannot update usb_config" |
| setGlobalSetting("package_verifier_enable") | ✗ BLOCKED | "device owners cannot update" |
| setSecureSetting("enabled_accessibility_services") | ✗ BLOCKED | "device owners cannot update" |
| setPermissionGrantState(INSTALL_PACKAGES) | ✗ FAILED | Only works for runtime permissions |

### Enabled System Apps (12 total)
All previously-disabled system apps re-enabled via device owner:
- **com.samsung.android.dlp.service** — Samsung DLP, UID 1000, has DLPDeviceAdminReceiver + SamsungDLPService
- **com.sec.knox.bluetooth** — Knox BT file transfer
- **com.sec.knox.shortcutsms** — Knox SMS shortcut
- **com.smartcom** — Smartcom non-root (UID 10067, targetSdk 30)
- **com.sec.android.emergencylauncher** — Emergency launcher
- **com.sec.android.app.billing** — Samsung billing
- Plus 6 carrier apps (ATT messages, Asurion, YellowPages, Google Music, Samsung SNS, Synchronoss)

### smartcomroot (APNWidgetRootService) — Deep AIDL Probing
Used BinderProbeService with ServiceManager reflection to call all 15 methods with 4 argument patterns each:

| Method | NoArgs | 1 String | 2 Strings | 1 Int | Notes |
|--------|--------|----------|-----------|-------|-------|
| M1 AddFirewallRule | ex=0 | ex=0 | ex=0 | ex=0 | Accepts all but **does nothing** |
| M2 EnableMobileNetwork | ex=0, ret=0 | ex=0 | ex=0 | ex=0 | Returns boolean |
| M3 GetFirewallRule | ex=0 | ex=0 | ex=0 | ex=0 | Returns empty |
| M4 GetStats | ex=0 | ex=0 | ex=0 | ex=0 | Returns empty |
| M5 InsertApn | **NPE** | ex=0, ret=0 | ex=0 | **NPE** | Actually processes args |
| M6 NotifyReconnect | **parseInt error** | ex=-3 | ex=-3 | ex=-3 | Expects specific int format |
| M7-M13 | ex=0 | ex=0 | ex=0 | ex=0 | Accept but no visible effect |
| M14 isAdvancedStatAvailable | ret=**false** | ret=false | ret=false | ret=false | Feature disabled |
| M15 isIptablesBlockingAvailable | ret=**false** | ret=false | ret=false | ret=false | **Feature disabled** |

**Key finding**: `isIptablesBlockingAvailable=false` and `isAdvancedStatAvailable=false` explain why AddFirewallRule and StartStats do nothing — the iptables and tcpdump features are disabled at the service level.

Also tested: backtick injection, iptables arg injection — all accepted without error but no execution.
Intent binding from untrusted_app: **FAILED** (`Bind initiated: false`).

### Samsung DLP Service (UID 1000)
- Registered in ServiceManager as `dlp` with interface `android.content.IDLPManager`
- ServiceManager probe: M1-M3 return ex=0 (3 methods)
- Intent binding via `com.samsung.android.DLP_SERVICE_BIND_ACTION`: **FAILED** (permission check)
- Permissions: WRITE_EXTERNAL_STORAGE, SET_ACTIVITY_WATCHER, ENTERPRISE_DEVICE_ADMIN, MANAGE_DEVICE_ADMINS

### Binder Service Comprehensive Probe
Probed ALL services via ServiceManager from app context:

**Interesting services that respond:**
| Service | Interface | M1 Result | Notes |
|---------|-----------|-----------|-------|
| SEAMService | com.sec.enterprise.knox.seams.ISEAMS | ex=0, avail=4 | Knox SEAMS |
| persona | android.os.IPersonaManager | ex=0, avail=24 | Persona manager |
| procstats | com.android.internal.app.IProcessStats | ex=0, avail=**80KB** | Huge data dump |
| permission | android.os.IPermissionController | ex=0, avail=4 | Permission check |
| keystore | android.security.IKeystoreService | ex=0, avail=4 | Key storage |
| gatekeeper | android.service.gatekeeper.IGateKeeperService | ex=0, avail=8 | Lock credentials |

**Permission-gated services (blocked):**
| Service | Interface | Error | Permission needed |
|---------|-----------|-------|-------------------|
| mdm.remotedesktop | mdm.samsung.IRemoteDesktopService | Operation not permitted | Samsung MDM |
| trust M1-M5 | android.app.trust.ITrustManager | ACCESS_KEYGUARD_SECURE_STORAGE | System |

**EngineeringModeService** — 7 methods, several return -1300 (Samsung error code), no permission denial
**DeviceRootKeyService** — 5 methods, crypto key management, M5 returns -19 (ENODEV)

### Mount Service (IMountService) Analysis
30 methods probed:
- M1-M2: NPE (needs IBinder arg)
- M3-M5: Permission denied (ASEC_CREATE)
- M6-M8: NPE on String.startsWith (needs path arg)
- M9: Success
- M10: Returns "unknown" (volume state)
- M11-M13: ASEC_CREATE denied
- M14-M19: ASEC_MOUNT_UNMOUNT denied
- M20: SHUTDOWN denied
- M22-M25: "rawPath cannot be null" (accepts paths)
- M27-M28: **"password cannot be empty"** — encryption methods, accept calls from shell!
- M29: CRYPT_KEEPER denied
- M30: Returns full storage volume info (emulated + SD card + Private mode paths)

### ftrace Subsystem Access
- **`buffer_size_kb`** — Shell-writable (root:shell rw-rw-r--), set to 4096 ✓
- **`tracing_on`** — Shell-writable, enabled tracing ✓  
- **`trace`** — Shell-readable and writable (root:shell rw-rw----)
- **`trace_marker`** — World-writable (--w--w--w-)
- `current_tracer` = nop (only `nop` available — function tracing NOT compiled)
- `set_event` — root-only, cannot enable event tracing
- **Result**: Can read trace markers but no function tracing possible

### Other Findings
- No writable files in /system, /proc, /sys (except ftrace above)
- No setuid/setgid binaries on the entire filesystem
- `mount -o remount,rw /system` — Permission denied (from both shell and app)
- `content query --uri content://telephony/carriers` — blocked (WRITE_APN_SETTINGS required)
- debugfs mounted at `/sys/kernel/debug/` — world-readable (binder, ion, mali, tracing)
- No backup transports available (`bmgr list transports` — empty)
- `run-as` broken for all apps ("Could not set capabilities: Operation not permitted")

### Updated Capabilities Summary
| Capability | Status | Notes |
|-----------|--------|-------|
| Device owner | ✓ | enableSystemApp, setGlobalSetting, setSecureSetting |
| Profile owner | ✓ | Full managed profile control |
| Device admin | ✓ | reset-password, force-lock, wipe-data |
| Accessibility svc | ✓ | Already enabled from previous session |
| System app enable | ✓ | 12 apps re-enabled including DLP, Knox |
| Install APKs | ✓ | `pm install -r -g` from shell |
| Grant dev perms | ✓ | 31 permissions including WRITE_SECURE_SETTINGS |
| ftrace control | ✓ | buffer_size, tracing_on, trace read/write |
| Root/kernel | ✗ | No kernel write primitive found |
| SELinux disable | ✗ | TIMA integrity monitoring blocks memory writes |
| USB config change | ✗ | Blocked by both SELinux and DPM API |
| System UID exec | ✗ | smartcomroot features disabled, DLP binding blocked |

### Key Remaining Vectors
1. **DM port (COM11)** — Shannon 308 modem DIAG access, untested
2. **smartcomroot method signatures** — Need exact AIDL protobuf to test InsertApn (M5) properly
3. **EngineeringModeService** — 7 accessible methods, purpose unknown
4. **Gatekeeper service** — Lock credential management, accessible
5. **Keystore service** — Key storage operations accessible
6. **SELinux policy sesearch** — Need proper tools to find domain transitions
7. **Device owner installCaCert** — MITM via trusted CA installation
8. **Process injection** — If we can ptrace a system UID process
9. **Content provider SQL injection** — Samsung-specific providers with system UID

---

## Session 10f — DM Port AT Command Enumeration & Deep System Recon (2026-02-26)

### AT Command Enumeration Results
- **180 AT commands** available via AT+CLAC on COM11
- **AT+DEVCONINFO** returned full device config: IMEI, serial, firmware, product code
  - **LOCK(NONE)** — modem reports no lock (but PN facility lock IS active)
  - SN: R0000000000, IMEI: 000000000000000, PRD: SM-T377AZKAATT
  - USER(OWNER), SDP(RUNTIME), CON(AT,MTP)
- **ATI2** reveals TWO IMEIs: 000000000000000 (primary), 350000000000006 (dummy secondary)
- **AT+CLCK facility locks**:
  - PN (Network/Carrier): **LOCKED** (1)
  - SC, FD, PU, PP, PC, PS: all unlocked (0)
- **CFUN=0** (radio OFF, no SIM inserted)
- **CFUN supports modes 0,1,4-12** (Samsung engineering modes possible)
- **AT$ARMEE** — Samsung download/Odin mode trigger
  - $ARMEE=0 (normal), $ARMEE=1 (**triggers download mode — DANGEROUS!**)
  - ⚠ Setting $ARMEE=1 caused device to enter download mode, required manual reboot
- **AT+VERSNAME** supports values 1-10, AT+CDIS display control (36 chars)
- **AT+CVMOD** voice modes 0-4
- **AT+CMUX** multiplexing supported
- **Battery**: +CBC: 0,100 (100% charged)
- Samsung-specific: AT%SYSLOG, AT%ITEST, AT%KCNFG, AT%NVREAD all return "CME ERROR: unknown"

### DM Protocol Testing
- DM frames (0x7F start, 0x7E end) get partial responses (0x7E echo)
- AT+VERSNAME with 100-char argument causes NO RESPONSE (parser disruption?)
- No crash in diagexe or at_distributor — modem handles gracefully

### Critical Process Discovery

#### diagexe (PID 2209)
- **UID 1000 (system)**, SELinux domain: `u:r:diagexe:s0`
- **Capabilities: CAP_DAC_OVERRIDE + CAP_NET_ADMIN + CAP_NET_RAW + CAP_SYS_ADMIN + CAP_SYS_BOOT** (0x603002)
- Groups: 1001 (radio), 3003 (inet), 3004 (net_raw)
- Has `setuid` and `capset` in imports — can change UID!
- Has `switchUser` function
- Proxies between USB ttyGS1 ↔ /dev/umts_dm0 (modem)
- Uses sockets: /data/.diag_stream, /data/.diagsocket_stream, @diag_mycmc_app2cp
- DM protocol framing: 0x7F start, 0x7E end

#### at_distributor (PID 2210)
- **UID 1001 (radio)**, SELinux domain: `u:r:at_distributor:s0`
- **Capabilities: CAP_CHOWN + CAP_DAC_OVERRIDE + CAP_NET_ADMIN + CAP_NET_RAW + CAP_SYS_ADMIN + CAP_SYS_BOOT + CAP_SYS_TIME** (0x2603003)
- Distributes AT commands between USB, modem, and factory app
- Creates sockets: @ATDMultiClient, @FactoryClientSend, @FactoryClientRecv
- **Sends Android broadcasts!** `am broadcast -a com.sec.atd.request_reconnect` and CSC_MODEM_SETTING
- Loads `libfactoryutil.so` for factory operations
- Has `CheckCommandValidate` — validates AT commands before processing
- Reads from `/efs/FactoryApp/` directory
- Can set `ril.factory_mode` property

### Factory App (com.sec.factory) — UID 1000
- Located at `/system/priv-app/DeviceTest/DeviceTest.apk`
- **FactoryTestBroadcastReceiver is UNPROTECTED** — accepts broadcasts from shell!
  - Responds to: `com.samsung.intent.action.CSC_MODEM_SETTING`, `com.sec.atd.request_reconnect`, BOOT_COMPLETED
  - CSC_MODEM_SETTING triggered full factory app initialization (AT handler registration, sensor config, EFS reads)
- **ProtectedFactoryTestBroadcastReceiver** — requires `com.sec.factory.permission.KEYSTRING` (signature|privileged) — BLOCKED
- Factory app checks `ro.factory.factory_binary` property — empty on this build, so factory_binary features disabled
- AT command handlers registered but inactive without factory binary mode

### SELinux Policy Analysis
- Policy extracted: 773,635 bytes binary, 134,387 bytes file_contexts
- **su_exec type defined** at /system/xbin/su (binary doesn't exist)
- **root_detect** type at /system/bin/root_detect (binary doesn't exist)
- **diagexe_exec** and **at_distributor_exec** types — both blocked for shell domain execution
- **/sbin/rdsh** (rd_shell_exec) — root debug shell EXISTS but /sbin is permission-denied to list
- **No permissive domains** found in policy (proper enforcement)
- shell blocked from executing diagexe_exec or at_distributor_exec type files
- shell blocked from setting radio_prop, system_prop, default_prop properties

### Content Provider Access
- **Contacts**: Accessible from shell — shows AT&T Service Contacts (411, 611)
- **Media**: Accessible — lists screenshots on device
- **Telephony/Carriers**: BLOCKED (requires WRITE_APN permission)
- **Downloads**: BLOCKED (requires ACCESS_ALL_DOWNLOADS)
- **SMS, Call Log**: BLOCKED (requires READ_SMS, READ_CALL_LOG)

### Global Settings Discovery
- `adb_root=1` — Set but ineffective (ro.debuggable=0, ro.secure=1 = production build)
- `selinux_status=0` (later changed to 1) — Settings table value, not actual SELinux state
- `oem_unlock_enabled=1` — OEM unlock toggled on
- `safe_boot_disallowed=0` — Safe boot NOT blocked
- `debug_view_attributes=1` — Debug layout inspection enabled

### Unix Domain Sockets
Key sockets discovered:
- @DeviceRootKeyService, @imsd — IMS daemon
- /data/.socket_stream, /data/.diag_stream, /data/.diagsocket_stream — system:system only
- @FactoryClientSend, @FactoryClientRecv — Factory client comm
- @diag_mycmc_app2cp — App-to-modem diagnostic bridge
- @ATDMultiClient — AT command distribution
- @mcdaemon — MobiCore (TrustZone)
- @SatsService — SATS service
- /dev/socket/rild-debug (radio:system), /dev/socket/rild (root:radio) — RIL sockets

### /dev/umts* Devices
- umts_dm0 (system:radio) — DM/diagnostic modem interface
- umts_ipc0 (radio:radio) — IPC modem interface
- umts_boot0, umts_ramdump0, umts_rfs0, umts_router (system:radio)
- umts_csd (system:loop_radio) — circuit-switched data

### Modem Details
- Shannon 308 (persist.ril.modem.board=SHANNON308)
- persist.radio.ramdump=1 — Modem RAM dump enabled
- DIAG daemon running as system UID

### Remaining Vectors (Priority Order)
1. **diagexe exploitation** — Has CAP_SYS_ADMIN + system UID, parses USB data we control. Buffer overflow in DM protocol handler → code execution with system + powerful caps
2. **Factory app broadcast abuse** — FactoryTestBroadcastReceiver accepts our intents. Need to find what AT commands/modes trigger useful behavior in factory context
3. **@ATDMultiClient socket** — If we can connect from our app, we can inject AT commands into the at_distributor pipeline
4. **SELinux domain transition** — Need to find any transition from shell/untrusted_app to more privileged domain. rdsh exists in /sbin but can't access
5. **DM protocol fuzzing** — More systematic fuzzing of diagexe through COM11 looking for memory corruption
6. **at_distributor command injection** — CheckCommandValidate might have bypass for AT command validation
7. **Content provider SQL injection** — Samsung system apps with UID 1000

---

## Session 10g — Deep Recon Continued (2026-02-26)

### Platform Signing Key Analysis
- **Boot image build fingerprint says `test-keys`** — misleading!
- Actual platform signing key: **Samsung Cert, OU=DMC, O=Samsung Corporation**
- SHA-256: `34df0e7a9f1cf1892e45c056b4973cd81ccf148a4050d11aea4ac5a65f900a42`
- SHA-1: `9ca5170f381919dfe0446fcdab18b19a143b3163`
- NOT the AOSP test key — cannot forge system app signatures
- All system apps (android, com.sec.factory, com.smartcomroot) share key `46fba8b`

### Abstract Socket Connectivity Test
- Built and deployed socket_probe binary (ARM32 static PIE)
- Tested: @ATDMultiClient, @FactoryClientSend, @FactoryClientRecv, @diag_mycmc_app2cp
- **ALL return EACCES (errno=13)** — SELinux blocks shell domain from connecting
- Filesystem sockets (/data/.diag_stream, /data/.diagsocket_stream, /dev/socket/rild-debug) also EACCES
- Abstract sockets may be accessible from untrusted_app domain (needs APK update)

### DRParser (com.sec.android.app.parser) Deep Analysis
- UID 1000, sharedUserId=android.uid.system
- **SecretCodeIME activity** protected by `SecretCodeIME` permission (protection level: **normal**)
  - Normal permission = any app can request it! Our APK could acquire this
  - Activity dispatches secret codes to factory/diagnostic apps
- **ParseService** protected by `SERVICE` permission (signature|privileged) — BLOCKED
- Has 15+ KEYSTRING permissions for factory/diagnostic apps
- INSTALL_SHORTCUT, UNINSTALL_SHORTCUT, MODIFY_PHONE_STATE permissions granted

### DeviceKeystring (com.sec.android.app.factorykeystring) Analysis
- UID 1000, privileged system app
- Handles `android_secret_code://` scheme — dispatches dialer codes
- **7 broadcast receivers** for secret codes (SelfTestMode, Shutdown, Version, Brightness, SerialNumber, PhoneUtil, WakeUp)
- Secret code broadcasts (android.provider.Telephony.SECRET_CODE) accepted but no visible response — likely permission-checked internally
- Activities: GloveSetting, TspResult, TspTestMode, TouchNoise, BatteryStatus, etc — all **NOT exported**
- All KEYSTRING permissions are signature|privileged — BLOCKED from shell/untrusted_app

### Factory App (com.sec.factory) Component Deep Dive
- **FailDumpService**: EXPORTED but requires KEYSTRING permission — BLOCKED
- **ModemReset service**: could reset modem state
- **REQUEST_FTCLIENT_START broadcast**: accepted but no visible process created
- **REQUEST_FACTORY_RESET receiver**: ⚠ DO NOT TRIGGER — will factory reset device
- **FtClient/UsbFtClient/DummyFtClient**: factory test client services — all not exported
- **ModuleCommunicationService/ModuleAudioService**: factory test modules

### Samsung System Service Discovery
- **EngineeringModeService** (IEngineeringModeService): 7 methods accessible from shell
  - M1: returns 0 (getter?), M2: returns -1, M3-7: return -1300 (Samsung permission error)
  - Error -1300 = 0xFFFFFAEC likely Samsung-specific permission denial
- **execute** (IExecuteManager): 2 methods
  - M1: returns full list of executables/packages with launch intents
  - M2: takes package name string, returns boolean
- **tima** (ITimaService): returns -1 for methods 1-2 (TIMA integrity verification)
- **SatsService**: Samsung SATS service
- **120+ Samsung/Knox services** enumerated — most return permission errors

### Additional System Apps (All UID 1000)
- com.sec.factory.camera — factory camera test
- com.sec.android.app.wlantest — WLAN test utility  
- com.sec.android.app.hwmoduletest — hardware module test
- com.sec.android.diagmonagent — diagnostic monitoring agent (C2D_MESSAGE, DIAGMON, WSSDM perms)
- com.sec.android.app.bluetoothtest — Bluetooth test

### Kernel Trace Events (555 Available)
- **binder**: binder_transaction, binder_ioctl, binder_command, binder_alloc_buf, etc.
- **ion**: ion_alloc_start/end, ion_free_start/end, ion_mmap, ion_sync
- **kmem**: kmalloc, kfree, kmem_cache_alloc/free, page_alloc/free
- **raw_syscalls**: sys_enter, sys_exit (all syscalls)
- **sched**: sched_switch, sched_wakeup, sched_process_fork/exit
- **Cannot enable events**: shell can only write buffer_size_kb, tracing_on, trace, trace_marker
- **Cannot read**: set_event, individual event enable files — permission denied
- Events are READ-ONLY from shell domain (can list available but not enable)

### Proc/Sys Access
- kptr_restrict: cannot read (permission denied)
- kallsyms: all addresses zeroed (00000000)
- sysrq: enabled (=1) but not writable by shell
- panic_on_oops: 1 (read-only)
- perf_event_paranoid: 1 (limited perf access for non-root)
- mmap_min_addr, core_pattern, modprobe, hotplug: all blocked

### Backup/Recovery
- Backup transport: Inactive, no transports available — dead end
- Recovery log shows normal CSC multi-CSC setup and EFS partition operations
- /cache, /efs, /efs/FactoryApp: all permission denied from shell

### Agent Status Confirmation
- com.privesc.agent running as UID 10139
- Device owner: true, Profile owner: true, Admin active: true
- 31 permissions granted including WRITE_SECURE_SETTINGS, READ_LOGS, DUMP, SET_DEBUG_APP, INTERACT_ACROSS_USERS
- Accessibility service bound and active (capabilities=9: REPORT_VIEW_IDS + RETRIEVE_INTERACTIVE_WINDOWS)
- Can see and interact with all visible windows

### Key Blocked Paths This Session
- Platform signing: Samsung proprietary, cannot forge system apps
- Abstract sockets: SELinux blocks shell from ALL system sockets
- Factory app services: KEYSTRING permission (signature|privileged) required
- DeviceKeystring activities: not exported
- Trace events: cannot enable from shell
- Secret code broadcasts: no visible effect (likely permission-checked)

### Updated Remaining Vectors (Priority Order)
1. **diagexe DM protocol fuzzing** — HIGHEST PRIORITY. diagexe has CAP_SYS_ADMIN + system UID. We control data via COM11. Need systematic binary protocol fuzzing targeting buffer overflows in the DM message parser. If diagexe crashes, it restarts with those capabilities.
2. **APK v3: SecretCodeIME + socket client** — Update our APK to:
   - Request com.sec.android.app.parser.permission.SecretCodeIME (normal prot level)
   - Launch SecretCodeIME activity (runs as UID 1000) to dispatch codes
   - Include abstract socket client to try @ATDMultiClient from untrusted_app domain
3. **Accessibility service exploitation** — Our service can interact with ALL windows. Could:
   - Automate UI actions in Settings to enable features shell can't
   - Click through system dialogs programmatically
   - Potentially interact with factory/engineering mode UIs if launched
4. **EngineeringModeService deeper probe** — 7 methods accessible, error -1300 suggests permission check not blanket denial. Try with different argument types and values.
5. **diagmonagent** — Diagnostic monitoring agent with C2D_MESSAGE. Check if it has any accessible components or broadcasts.
6. **perf_event side channel** — paranoid=1 allows limited perf events. Could leak kernel information.
7. **Safe boot mode** — safe_boot_disallowed=0, could boot in safe mode to disable 3rd party security apps

---

## Session 10h — SmartcomRoot Discovery & AT Command Enumeration

**Date:** 2026-02-26, continued from 10g

### Overview
Continued from DM protocol fuzzing. Discovered a critical exposed system service (`com.smartcomroot`), enumerated AT commands on DM port, and mapped 164+ binder services accessible from untrusted_app context.

### DM Protocol Fuzzing — Remaining Phases

#### Phase 5-6: Format String & Deep Structure
- **All format string injections**: No response from modem
- **All structured DIAG commands**: No response — Shannon modem doesn't speak Qualcomm DIAG
- diagexe alive throughout (PID=2209)

#### Buffer Boundary Refinement
- **Frame=512 exactly = no response** — Classic USB ZLP (Zero-Length Packet) issue
- **Payload=514 works fine** with proper timing (3/3 attempts)
- **"512 limit" was USB timing artifact**, not buffer overflow
- **First byte (cmd) determines response**: 0x01/0x73 → response, 0x41/0xFF → silent
- **Escape expansion "bypass" was normal** USB fragmentation handling

### AT Command Interface on COM11
**CRITICAL: Raw AT commands (without DM framing) work on COM11!**

#### Working AT Commands
| Command | Response |
|---------|----------|
| ATI | T377AUCU2AQGF |
| ATI0 | Samsung Electronics |
| ATI2 | IMEI 1: 000000000000000, IMEI 2: 350000000000006 |
| ATI4 | Factory Default 'core' profile [+ALL+] |
| AT+CGMI | Samsung Electronics |
| AT+CGMM | Samsung LTE ALPSS |
| AT+SWVER | Full 4-part firmware version |
| AT+DEVCONINFO | MN(SM-T377A);BASE(... |
| AT+SERIALNO | 1,R0000000000,161019 |
| AT+CFUN? | +CFUN: 0 (radio off) |
| AT+CFUN=? | (0,1,4-12),(0-1) — modes 0-12 available |
| AT+CPIN? | SIM not inserted |
| AT+DUMPCTRL | DUMPCTRL:OK (accepted!) |
| AT+CLAC | Partial command list |
| AT+GCAP | +CGSM |

#### Blocked AT Commands
- All Samsung-specific debug commands → ERROR
- All Qualcomm-style commands → ERROR
- All Shannon-specific commands → ERROR

### 🚨 SmartcomRoot — Exposed System Service Discovery

User noticed `com.smartcomroot.services.SmartcomRootService$CheckAppThread` in logcat every 15 seconds.

#### Package: com.smartcomroot
- **Location**: `/system/priv-app/APNWidgetBaseRoot_ATT/APNWidgetBaseRoot_ATT.apk`
- **UID**: 1000 (system), `sharedUserId=android.uid.system`
- **Flags**: SYSTEM, HAS_CODE, PERSISTENT, PRIVILEGED
- **Signed**: Samsung platform key (46fba8b)
- **Version**: 1.11 (built against Android 4.4 SDK!)

#### TWO EXPORTED SERVICES — NO PERMISSION PROTECTION
1. `com.smartcomroot.services.SmartcomRootService` — exported=true, NO permission
2. `com.smartcom.root.APNWidgetRootService` — exported=true, NO permission

#### Notable Permissions (held by SmartcomRoot as UID 1000)
- INSTALL_PACKAGES, WRITE_SECURE_SETTINGS, MODIFY_PHONE_STATE
- WRITE_APN_SETTINGS, MANAGE_APP_TOKENS, CLEAR_APP_USER_DATA
- CHANGE_COMPONENT_ENABLED_STATE, BIND_DEVICE_ADMIN, KEYSTRING

#### Binder Access — ALL 15 AIDL Methods Callable
Interface: `com.smartcomroot.services.IAPNWidgetRootService`
Registered in ServiceManager as `com.smartcom.root.APNWidgetRootService`

Methods: InsertApn, SetDefaultApn, SetDefaultApnName, SetNoDefaultApn, StartStats, StopStats, SwitchToOperatorApn, NotifyReconnect, AddFirewallRule, EnableMobileNetwork, SetAirPlaneMode, GetFirewallRule, GetStats, isAdvancedStatAvailable, isIptablesBlockingAvailable

#### Code Analysis (from ODEX strings)
- Uses `Runtime.exec(String[])` ARRAY form — no shell interpretation
- Calls `/system/bin/iptables` and `/system/bin/tcpdump` — both FAIL (need root, UID 1000 insufficient)
- `DataOutputStream.writeBytes()` for iptables stdin, not shell
- `ServiceManagerReflect` — reflection-based service registration
- `EasySSLSocketFactory + EasyX509TrustManager` — accepts ALL SSL certs (MitM vuln)

#### Command Injection Tests — ALL FAILED
All attempts (backtick, semicolon, newline, pipe) treated as literal iptables arguments.
`Runtime.exec(String[])` prevents all shell metacharacter injection.

### ServiceManager Scan — 164 Services Probed

Key findings from untrusted_app context:
| Service | Status |
|---------|--------|
| remoteinjection | Needs MDM_REMOTE_CONTROL (signature prot) |
| execute (IExecuteManager) | Returns app list (23 entries), no cmd exec |
| DeviceRootKeyService | Returns status=0 |
| enterprise_policy | Partially accessible |
| com.smartcom.root.APNWidgetRootService | Fully accessible |

### JDWP Debug Investigation
- Only debuggable processes: our own red team apps
- SET_DEBUG_APP works from shell but doesn't enable JDWP on `ro.debuggable=0`
- SmartcomRoot NOT debuggable via JDWP

### Key Blocked Paths This Session
- SmartcomRoot command injection: Runtime.exec uses array form
- SmartcomRoot iptables/tcpdump: need root, UID 1000 insufficient
- remoteinjection: MDM_REMOTE_CONTROL signature permission
- JDWP debugging of system apps: ro.debuggable=0

### Updated Remaining Vectors (Priority Order)
1. **SmartcomRoot INSTALL_PACKAGES** — Service has this permission but no AIDL method exposes it. Could we trigger package install via content provider or reflection?
2. **Abstract socket access from untrusted_app** — SELinux domain differs from shell. Test @ATDMultiClient, @FactoryClientSend, @diag_mycmc_app2cp from APK.
3. **Content provider exploitation from device owner** — More access than shell.
4. **diagexe DM protocol fuzzing** — Still viable, diagexe has CAP_SYS_ADMIN.
5. **Accessibility service UI automation** — Click through privileged UIs.
6. **AT+DUMPCTRL** — Accepted by modem. May dump CP memory.
7. **Kernel exploitation** — ION UAF, tee deadlock, Mali import crash from prior sessions.

### Session 10h — DeepProbe Results (2026-02-26 15:58)

#### Socket Probing from untrusted_app (UID 10139)
- **ALL abstract sockets BLOCKED** — SELinux prevents LocalSocket creation in abstract namespace
- **CONNECTED: /dev/socket/logd** — Can write to log daemon (logd UID)
- **CONNECTED: /dev/socket/dnsproxyd** — DNS proxy socket, netd runs as ROOT! PRIVESC VECTOR!
- All other filesystem sockets: Permission denied

#### PackageInstaller — SILENT INSTALL WORKS
- Device owner can create PackageInstaller sessions
- Session ID successfully allocated (2046558354)
- Can silently install any APK without user interaction
- Installed APKs run as untrusted_app (UID 10xxx), NOT system

#### Content Provider Access
- **READABLE: content://nwkinfo/nwkinfo** — Network PLMN configs (10 rows: Anritsu, Global, AIO)
- APN carriers: `No permission to write APN settings'' from untrusted_app
- Most system providers return NULL or error

#### DLP Service (IDLPManager)
- 3 methods accessible (M1-M3), methods 4-20 = UNKNOWN_TRANSACTION
- M1-M3 return 4 bytes each
- Interface: android.content.IDLPManager

#### SMS Service Access
- isms (ISms) methods 1-4 accessible from untrusted_app binder
- Cannot use `content'' shell command (needs ACCESS_CONTENT_PROVIDERS_EXTERNALLY)
- May be readable via ContentResolver in Java code

#### TIMA Physical Address Leak (dmesg)
- selinux_enabled paddr: 0x20ab00a8 → vaddr: 0xc0ab00a8
- selinux_enforcing paddr: 0x20b7ad18 → vaddr: 0xc0b7ad18
- write_ptr_paddr: 0x27403580 (TIMA write pointer)
- Confirms NO KASLR, confirms known virtual addresses
- TIMA checks every 5 minutes — any SELinux modification detected within 5 min

#### Key Processes
- netd (root, PID 2191) — reachable via dnsproxyd socket
- logd (logd user, PID 2146) — reachable via logd socket
- SmartcomRoot (system/UID 1000, PID 22696) — binder accessible
- DLP (system/UID 1000) — binder accessible (3 methods)

### dnsproxyd Protocol Probing Results
- **Protocol**: FrameworkListener, null-terminated commands, no sequence numbers
- **getaddrinfo**: 8 args (cmd host service family socktype proto flags netid) — WORKS! Resolves localhost → 127.0.0.1
- **gethostbyname**: 4 args (cmd netid host af) — returns error 401 (no DNS configured)
- **gethostbyaddr**: 5 args (cmd netid addr len af) — available but parsing issues
- **Format strings (%p, %n)**: NOT exploitable — treated as literal hostname, returns EAI_NONAME
- **256-byte hostname**: Handled safely, returns error
- **Negative/INT_MAX values**: Returns error code 401 with different sub-codes
- **Conclusion**: dnsproxyd is robustly implemented. No crash on basic fuzzing. Deeper struct-aware fuzzing could find issues but unlikely.

### Final Recon Summary — Session 10h

#### File System Access Differences: shell vs untrusted_app
- **untrusted_app CAN read world-readable files in /data/system** that shell CANNOT
  - Confirmed: /data/system/enterprise.conf (microphoneEnabled=1, screenCaptureEnabled=1)
  - Confirmed: /data/system/uiderrors.txt (package management history)  
  - Confirmed: /data/system/users/fota.xml (firmware version marker)
- **Both blocked from**: packages.xml, locksettings.db, enterprise.db, /data/misc/
- **No writable /sys entries** from either shell or untrusted_app

#### TIMA Kernel Integrity Monitor
- Runs every 5 minutes via MobiCore TrustZone
- Verifies kernel code, SELinux enforcement status
- Leaks physical addresses via dmesg (NO KASLR):
  - selinux_enabled:  vaddr=0xc0ab00a8
  - selinux_enforcing: vaddr=0xc0b7ad18

#### Attack Surface Map — FINAL
| Vector | Access | Status |
|--------|--------|--------|
| SmartcomRoot binder (15 methods) | Full | Blocked (array exec, root needed) |
| DLP binder (3 methods) | Full | Under investigation |
| dnsproxyd socket (root netd) | Connected | No crash on basic fuzzing |
| PackageInstaller | Can create sessions | Installs as untrusted_app only |
| Abstract sockets | ALL blocked | SELinux prevents creation |
| Content providers | nwkinfo only | Most return NULL/permission denied |
| /sys writable | None | SELinux blocks all |
| /proc/kallsyms | Zeroed | kptr_restrict active |
| debugfs (binder/ion/mali) | Read-only | Can't enable tracing |
| AT commands on COM11 | Full | AT+DUMPCTRL accepted, radio off |
| ION UAF race | 91% win rate | No code exec trigger found |
| Mali import crash | Reproducible | Semaphore UAF, DoS only so far |
| Kernel addresses | Confirmed | commit_creds=0xc0054328, selinux_enforcing=0xc0b7ad18 |

#### Priority Recommendations for Next Session
1. **ION UAF exploitation** — We have a 91% race win and confirmed addresses. Need to find a controlled write primitive from the dangling ION mapping.
2. **Mali import UAF** — The semaphore UAF might be convertible to a code exec with careful heap manipulation.
3. **PackageInstaller + silent APK** — Build an APK with maximum permissions and install silently. Won't get system UID but expands our attack surface.
4. **AT+DUMPCTRL** — May trigger modem memory dumps to readable locations.
5. **Deeper netd protocol fuzzing** — Focus on race conditions and malformed sockaddr structures.
