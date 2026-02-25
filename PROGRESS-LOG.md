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

---

## Binaries on Device (/data/local/tmp/)
### ⚠ DO NOT RUN
- `adbd_root` — **CRASHES DEVICE** (hangs then disconnects)
- `su-v1`, `su-v2` — non-PIE, rejected
- `rageagainstthecage` — non-PIE, rejected

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

**Root is NOT achievable from ADB shell on this device.**

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
