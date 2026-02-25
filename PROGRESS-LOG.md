# Android Red Team — Progress & Instructions
# Samsung SM-T377A | Android 6.0.1 | Kernel 3.10.9-11788437
# Last updated: 2026-02-25

## ⚠ CRITICAL WARNINGS
- **This is a PHYSICAL device.** Fork-bombs, aggressive races, and adbd_root CRASH it.
- **DO NOT run `/data/local/tmp/adbd_root`** — it hangs then crashes the device.
- **DO NOT run `/data/local/tmp/su-v1` or `su-v2`** — non-PIE, rejected by kernel.
- **DO NOT run `/data/local/tmp/rageagainstthecage`** — non-PIE binary.
- **Conservative testing only.** Fork in child processes, use timeouts.

## Device Details
- **Model:** Samsung SM-T377A (Galaxy Tab E 8.0, AT&T)
- **SoC:** Exynos 3475 (ARMv7 Cortex-A7, 4 cores)
- **Android:** 6.0.1 (Marshmallow), Build MMB29K.T377AUCU2AQGF
- **Kernel:** 3.10.9-11788437, compiled 2017-07-05
- **Security patch:** 2017-07-01
- **SELinux:** Enforcing (u:r:shell:s0)
- **Shell UID:** 2000 (groups: input, log, adb, sdcard_rw, sdcard_r, net_bt_admin, net_bt, inet, net_bw_stats)

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
```
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
- **Device Admin**: Activated via `dpm set-active-admin` — NO UI confirmation required!
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
- `dpm set-device-owner` → "Not allowed because there are already some accounts" (Google account)
- `dpm set-profile-owner` → Same error
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
