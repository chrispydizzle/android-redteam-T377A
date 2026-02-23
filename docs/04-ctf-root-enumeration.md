# CTF Root Path Enumeration (ADB Shell → Root)

## Samsung SM-T377A · Android 6.0.1 · Kernel 3.10.9

← [Back to Index](../README.md)

---

Comprehensive enumeration of all privilege escalation paths from an `adb shell` (UID 2000, SELinux `u:r:shell:s0`) to root.

### Paths Tested — All Blocked

| # | Path | Result | Blocker |
|---|------|--------|---------|
| 1 | **`/data/local/tmp/su`** | `1f 8b` magic — gzip blob, not ELF | Not an executable binary |
| 2 | **`/data/local/tmp/psneuter`** | `mmap() failed` | PIE enforcement rejects non-PIE ELF on Android 6.0.1 |
| 3 | **`/data/local/tmp/zergRush`** | `error: only PIE supported` | Non-PIE binary rejected by dynamic linker |
| 4 | **`/data/local/tmp/rageagainstthecage`** | `error: only PIE supported` | Non-PIE binary rejected by dynamic linker |
| 5 | **`/data/local/tmp/busybox`** | `1f 8b` magic — gzip blob | Not an executable binary |
| 6 | **`/data/local/tmp/tsd_client`** | 64-bit ELF on 32-bit device | `not executable: 64-bit ELF file` |
| 7 | **`/data/local/tmp/tsd_client_arm32`** | Runs but needs root + rsud socket | rsud daemon not running; requires `setenforce 0` |
| 8 | **`adb root`** | Rejected | `adbd cannot run as root in production builds` (`ro.debuggable=0`) |
| 9 | **`setprop service.adb.root 1`** | Property accepted | adbd checks `ro.debuggable` at startup, ignores runtime prop |
| 10 | **`setprop ctl.restart adbd`** | SELinux **DENIED** | `shell` context blocked from setting `ctl_default_prop` |
| 11 | **`setprop ro.debuggable 1`** | SELinux **DENIED** | `ro.*` props read-only + SELinux `default_prop` block |
| 12 | **`setprop persist.*`** | SELinux **DENIED** | `shell` can't write `system_prop` class |
| 13 | **`mount -o remount,rw /system`** | Permission denied | Not root; SELinux blocks mount operations from `shell` |
| 14 | **`run-as <pkg>`** (all 6 offensive apps) | `Could not set capabilities` | No installed packages have `DEBUGGABLE` flag set |
| 15 | **SUID/SGID binary search** | None found | No setuid escalation vectors on any partition |
| 16 | **`su` in system PATH** | Not found in `/system/bin`, `/system/xbin`, `/sbin` | No system-level su binary installed |
| 17 | **Magisk daemon** | Not running, `magisk` binary absent | App installed but **never activated** (boot image unpatched) |
| 18 | **Any binary in `/data`** with setuid | Blocked | `/data` mounted with `nosuid` — kernel ignores setuid bit |
| 19 | **World-writable files in `/system`** | None found | System partition integrity maintained |
| 20 | **debugfs write** | Permission denied | Shell can read debugfs but cannot write |

### World-Writable Kernel Device Nodes — Deep Dive

Five kernel device nodes are world-readable/writable and **confirmed openable from shell (UID 2000) with no SELinux denial**:

| Device | DAC Perms | SELinux Label | Driver | Version | Shell open()? |
|--------|-----------|---------------|--------|---------|--------------|
| `/dev/mali0` | `crw-rw-rw-` (system:system) | `u:object_r:gpu_device:s0` | Mali Midgard kbase | **r7p0-03rel0** (UK 10.0) | ✅ Yes |
| `/dev/ion` | `crw-rw-rw-` (system:system) | `u:object_r:ion_device:s0` | Samsung Exynos ION | Kernel 3.10.9 custom | ✅ Yes |
| `/dev/binder` | `crw-rw-rw-` (root:root) | `u:object_r:binder_device:s0` | Android Binder | Kernel 3.10.9 | ✅ Yes |
| `/dev/ashmem` | `crw-rw-rw-` (root:root) | `u:object_r:ashmem_device:s0` | Android ashmem | Kernel 3.10.9 | ✅ Yes |
| `/dev/mobicore-user` | `crw-rw-rw-` (radio:system) | `u:object_r:mobicore-user_device:s0` | Trustonic TEE | MobiCore | ✅ Yes |

#### `/dev/mali0` — Mali GPU Midgard r7p0

- **414 kbase kernel symbols** compiled into kernel (full Midgard driver)
- **ioctl handler:** `kbase_ioctl` (confirmed in kallsyms)
- **Memory mapping:** `kbase_mmap` and `kbase_gpu_mmap` available
- **debugfs readable:** Per-process GPU memory maps at `/sys/kernel/debug/mali/mem/<pid>/mem_view` — leaks GPU virtual addresses and what appear to be physical/kernel page frame pointers
- **secure_mode:** Disabled (`N`)
- **quirks_mmu/sc/tiler:** Readable (debugfs `rw` permissions but SELinux blocks write)
- **CVE status:** No publicly cataloged CVE specifically targets Mali r7p0 kbase on kernel 3.10 / Exynos 3475. CVE-2025-0072 (CSF queue UAF) and CVE-2022-38181 (freed memory access) target newer Bifrost/Valhall drivers. However, the Midgard kbase driver at r7p0 predates many security hardening patches applied to later versions. Memory mapping bugs and improper permission enforcement in the kbase driver were exploited in private rooting toolkits for Samsung J-series/Tab A devices.
- **Assessment:** 🟡 **Medium-High risk.** The driver is old, the ioctl surface is large (414 symbols), and no CVE tracking existed for this era. A custom ioctl fuzzer targeting `kbase_ioctl` could potentially find memory corruption bugs.

#### `/dev/ion` — Samsung Exynos ION Allocator

- **ION heaps present:** `common`, `ion_noncontig_heap`, `mfc_fw`, `mfc_nfw`, `video`, `video_ext`
- **ioctl handler:** `ion_ioctl` (confirmed), `ion_mmap`, `ion_open`, `ion_release`
- **Heap debug:** `/sys/kernel/debug/ion/heaps/ion_noncontig_heap` readable — shows per-process buffer allocations including PIDs and sizes
- **Client tracking:** `/sys/kernel/debug/ion/clients/` shows all ION clients including hardware drivers (`14400000.fimc_is`, `12c30000.mfc0`, `decon0`)
- **Samsung custom heaps:** The `mfc_fw`/`mfc_nfw`/`video`/`video_ext` heaps are Samsung-specific ION implementations
- **CVE-2017-0507:** Android ION kernel EoP — affects pre-2017-03-05 SPL. Device has 2017-07-01 SPL → **likely patched**
- **Black Hat 2017 (Keen Lab):** "Defeating Samsung KNOX With Zero Privilege" demonstrated CVE-2016-6787 (perf_event_open double-free) on Samsung kernel 3.10 devices, chaining with ION/DMA buffer manipulation for full root + Knox bypass
- **Assessment:** 🟡 **Medium risk.** The Samsung-custom ION heaps have historically contained bugs not present in upstream. Reference counting issues and initialization bugs in vendor heaps are a known attack class.

#### `/dev/binder` — Android Binder IPC

- **ioctl handler:** `binder_ioctl`, `binder_mmap`, `binder_open` (confirmed)
- **debugfs:** `/sys/kernel/debug/binder/stats` and `/sys/kernel/debug/binder/proc/<pid>` readable — shows per-process thread states, transaction counts, buffer usage
- **CVE-2019-2215:** Binder UAF in `binder_thread` + `epoll` interaction — targets kernels **3.18+**. This kernel is 3.10.9, which **predates the vulnerable `BINDER_THREAD_EXIT` ioctl** introduced later. Symbols `binder_poll` and `binder_thread_write` are present, but the specific vulnerable code path likely does not exist.
- **Assessment:** 🟢 **Low risk** for CVE-2019-2215 specifically. However, the 3.10 binder driver has its own era-specific bugs that were less publicly documented.

#### `/dev/mobicore-user` — Trustonic MobiCore TEE

- **Access:** `open()` succeeds from shell despite `radio:system` ownership (DAC world-rw overrides)
- **SELinux:** `u:object_r:mobicore-user_device:s0` — no denial logged for `open`, but ioctl may be restricted
- **RootPA DeveloperService:** Requires `DEVELOPER_PERMISSION` (prot=normal, auto-granted to any installed app). A custom APK could call this service.
- **TIMA dmesg leak:** MobiCore logs SELinux physical addresses: `enabled: 0x20ab00a8`, `enforcing: 0x20b7ad18`, `write_ptr_paddr: 0x27402500`
- **Assessment:** 🟡 **Medium risk.** The TEE communication channel is open. Combined with the physical address leaks, an attacker with TEE exploitation knowledge could potentially manipulate TrustZone state.

### Kernel Exploit Mitigation Assessment

| Mitigation | Status | Impact |
|-----------|--------|--------|
| **KASLR** | ❌ **ABSENT** — no KASLR symbols in kallsyms, 0 non-zero addresses | Kernel addresses are **static and deterministic** across reboots |
| **Stack Canaries** | ❌ **ABSENT** — no `__stack_chk_fail` or `__stack_chk_guard` in kallsyms | Stack buffer overflows are **trivially exploitable** |
| **HARDENED_USERCOPY** | ❌ **ABSENT** — no `hardened_usercopy` symbol | User↔kernel copy overflows are **not checked** |
| **RKP (Real-time Kernel Protection)** | ❌ **ABSENT** — 0 `rkp_` symbols (only on Exynos 7+ series) | Kernel credential structures are **unprotected in memory** |
| **DFI / cred_jar_ro** | ❌ **ABSENT** — no `cred_jar_ro` or `mark_creds_ro` | Credentials in **generic SLUB heap**, freely modifiable |
| **kptr_restrict** | ✅ Active — all 43,664 kallsyms addresses zeroed | Kernel addresses hidden... **but bypassed** (see below) |
| **SELinux** | ✅ **Enforcing** — blocks property writes, mount ops, debugfs writes | Primary defense layer. May block specific ioctl commands |
| **TIMA** | ⚠️ **Measurement only** — 9 symbols, periodic kernel integrity checks | Detects kernel **text** modification but **not data/heap** manipulation |
| **sec_restrict_uid** | ⚠️ Present — Samsung UID fork restriction | Limited scope — only restricts certain UID transitions |
| **PIE enforcement** | ✅ Active — linker rejects non-PIE ELF | Blocks legacy exploit binaries (not relevant for kernel exploits) |
| **nosuid on /data** | ✅ Active — kernel ignores setuid bit | Blocks setuid escalation (not relevant for kernel exploits) |

### Kernel Info Leak Chain (KASLR Bypass)

Even with `kptr_restrict` active, multiple information leaks provide kernel addresses:

| Leak Source | Data Leaked | Reliability |
|------------|-------------|-------------|
| `/proc/slabinfo` | **`nf_conntrack_c0afeb00`** — kernel function address `0xc0afeb00` embedded in slab cache name | ✅ Persistent, readable, survives reboots |
| `dmesg` (TIMA) | SELinux `enabled` paddr: `0x20ab00a8`, `enforcing` paddr: `0x20b7ad18`, `write_ptr_paddr`: `0x27402500` | ✅ Available after each TIMA measurement cycle |
| `dmesg` (stack traces) | Kernel text virtual addresses in `[<c0XXXXXX>]` format during allocation failures | ⚠️ Opportunistic — requires triggering OOM/warning |
| `/sys/kernel/debug/mali/mem/*/mem_view` | GPU virtual addresses and possible page frame numbers | ✅ Readable per-process |
| `/proc/slabinfo` (full) | Complete SLUB cache layout — object sizes, counts, slabs per cache | ✅ Full heap layout for heap spraying |
| `/proc/kallsyms` (names) | All 43,664 kernel symbol **names** (addresses zeroed) | ✅ Function/variable enumeration for ROP gadget identification |

**Combined impact:** Since KASLR is absent, the leaked address `0xc0afeb00` from slabinfo directly confirms the kernel base. All symbol offsets from kallsyms can be resolved to absolute addresses by correlating the `nf_conntrack` init function with its known offset in the kernel binary. This provides the addresses of `commit_creds`, `prepare_kernel_cred`, and any ROP gadgets needed for a kernel exploit payload.

### Key Defense Layers (Why Standard Paths Fail)

1. **PIE Enforcement** — Android 6.0.1 linker rejects all non-position-independent executables. The legacy exploit binaries (`psneuter`, `zergRush`, `rageagainstthecage`) are non-PIE and crash immediately.
2. **`nosuid` on `/data`** — Even if a valid `su` binary existed, the kernel ignores the setuid bit on execution from `/data`.
3. **SELinux Enforcing** — The `shell` domain is tightly constrained. Property writes, service restarts, mount operations, and debugfs writes are all denied by policy.
4. **Samsung Knox / TIMA** — Periodic kernel text integrity measurement (NOT real-time prevention on this chipset). Detects code modification but **not credential/data manipulation**.
5. **Production Build** — `ro.debuggable=0` + `release-keys` means `adb root` is permanently rejected and `run-as` requires the `DEBUGGABLE` app flag.
6. **Kernel "Sweet Spot"** — Version 3.10.9 (built July 2017) is patched against 2016 exploits (Dirty COW) but predates the buggy code introduced in later kernels (Binder UAF in 3.18+, inotify race in 3.14+).

### Additional Findings (Deep Dive)

#### Shell Capabilities (Not Root, But Powerful)

The `shell` user (UID 2000) has significant non-root capabilities that could assist an attacker:

| Capability | Evidence | Impact |
|-----------|---------|--------|
| **Keylogging** | Shell is in `input` group; `getevent` reads `/dev/input/event*` (touchscreen, buttons) | Can capture all touch input including PIN/pattern entry |
| **Screen Capture** | `screencap -p` works from shell | Can capture screen contents at any time |
| **Input Injection** | `input keyevent` / `input tap` / `sendevent` all work | Can simulate user interaction (unlock, app launch, tap "Allow") |
| **Package Install** | `pm install` works from shell (when `install_non_market_apps=1`) | Can sideload APKs — limited by signature checks for system apps |
| **dmesg Access** | `dmesg` readable — leaks SELinux denials, kernel pointers (though zeroed), driver info | Useful recon for crafting exploits |
| **debugfs Read** | `/sys/kernel/debug/` mounted and readable — binder state, mali GPU memory maps, ION heap info | Kernel memory layout recon |
| **SD Card Write** | Full read/write to `/sdcard/` | Can stage payloads, exfiltrate data |

#### SmartcomRoot — System-UID Service (Fully Reverse-Engineered)

| Property | Value |
|----------|-------|
| **Package** | `com.smartcomroot` |
| **UID** | `android.uid.system` **(UID 1000)** |
| **Location** | `/system/priv-app/APNWidgetBaseRoot_ATT` |
| **Flags** | `SYSTEM`, `PERSISTENT`, `HAS_CODE` |
| **Binder Service** | `com.smartcom.root.APNWidgetRootService` (registered, callable from shell) |
| **Key Permissions** | `MODIFY_PHONE_STATE`, `WRITE_APN_SETTINGS`, `WRITE_SECURE_SETTINGS`, `WRITE_SETTINGS`, `INTERACT_ACROSS_USERS` |
| **Code Location** | ODEX-only (no classes.dex) — `oat/arm/APNWidgetBaseRoot_ATT.odex` (94KB, 28 classes) |

**AIDL Interface — Complete Method Map** (reverse-engineered via `oatdump --list-methods`):

| TX Code | Method Signature | Result from Shell |
|---------|-----------------|-------------------|
| 1 | `AddFirewallRule(String)` | Calls `iptables <arg>` via `Runtime.exec(String[])` — iptables fails: "Permission denied (you must be root)" |
| 2 | `EnableMobileNetwork(boolean)` | Returns success parcel |
| 3 | `GetFirewallRule()` | Returns empty parcel |
| 4 | `GetStats(String)` | Returns success parcel |
| 5 | `InsertApn(String, String, String, String)` | NPE — expects 4 non-null string args |
| 6 | `NotifyReconnect()` | Returns success |
| 7 | `SetAirPlaneMode(boolean)` | Returns success |
| 8 | `SetDefaultApn(int)` | Expects integer arg |
| 9 | `SetDefaultApnName(String)` | Accepts string arg |
| 10 | `SetNoDefaultApn()` | Returns success |
| 11 | `StartStats()` | Attempts `tcpdump -q -i any` — fails (IOException) |
| 12 | `StopStats()` | Returns success |
| 13 | `SwitchToOperatorApn(String)` | Accepts string arg |
| 14 | `isAdvancedStatAvailable()` | Returns false (0) |
| 15 | `isIptablesBlockingAvailable()` | Returns false (0) |

**Key Internal Classes:**
- `IPTablesHelper` — has `runCmd(String)` method, but uses `Runtime.exec(String[])` (array form — shell metacharacter injection is **impossible**)
- `ServiceManagerReflect` — reflection wrapper with `addService(String, IBinder)` — internal use only
- `TelephonyCarriersReflect` — reflection accessor for telephony content provider fields
- `TCPDumpThread` — attempts to run `/system/bin/tcpdump` (fails without root)

**Why This Is NOT a Root Path:**
- Service runs as UID 1000 (system), **not UID 0 (root)**
- `iptables` and `tcpdump` calls fail because UID 1000 lacks `CAP_NET_ADMIN` and `CAP_NET_RAW`
- Command injection blocked by `Runtime.exec(String[])` array form (logcat confirms `&&`, `;`, and `|` are passed as literal arguments to iptables)
- No method executes arbitrary commands — only predefined binaries (`iptables`, `tcpdump`)
- Service **does** process all 15 transactions from shell — but outputs are limited to APN/telephony management

**Residual Value:** APN manipulation (InsertApn, SetDefaultApn, SwitchToOperatorApn) and airplane mode control via binder are achievable from shell through this service, which could support network-layer attacks but not privilege escalation.

#### Kernel Info Leak

| Item | Status | Notes |
|------|--------|-------|
| `/proc/kallsyms` | **Readable** — 43,664 symbol names (addresses zeroed by `kptr_restrict`) | Full function/variable enumeration for ROP gadget identification |
| `/proc/slabinfo` | **Readable** — full SLUB cache layout | **KASLR bypass:** `nf_conntrack_c0afeb00` leaks kernel address `0xc0afeb00` in slab cache name |
| `dmesg` | **Readable** | TIMA leaks SELinux physical addresses: `0x20ab00a8`, `0x20b7ad18`, `0x27402500` |
| ION heap debug | **Readable** | Per-process buffer allocations with PIDs, sizes, heap types |
| Mali GPU debug | **Readable** | Per-process GPU memory maps with virtual addresses and page frame pointers |
| `/proc/pagetypeinfo` | **Readable** | Physical memory page distribution and fragmentation data |

> **KASLR is ABSENT on this device (Exynos 3475).** All kernel addresses are static and deterministic. The `nf_conntrack_c0afeb00` slab name directly leaks a kernel text address, and combined with kallsyms symbol names, every kernel function address can be resolved.

#### Shell Settings/Property Write Capabilities

| Capability | Works? | SELinux Verdict |
|-----------|--------|-----------------|
| `settings put system <key> <val>` | ✅ Yes | Shell has `WRITE_SETTINGS` |
| `settings put secure <key> <val>` | ✅ Yes | Shell has `WRITE_SECURE_SETTINGS` (already granted) |
| `settings put global <key> <val>` | ✅ Yes | Shell can write all global settings |
| `setprop service.*` | ✅ Yes | `service_prop` allowed for shell |
| `setprop debug.*` | ✅ Yes | `debug_prop` allowed for shell |
| `setprop persist.*` | ❌ No | SELinux denies: `default_prop` class |
| `setprop ro.*` | ❌ No | Read-only + SELinux denies |
| `setprop ctl.*` | ❌ No | SELinux denies: `ctl_default_prop` class |

**Implications:** Shell can enable accessibility services, modify ADB settings, set ADB TCP port (`service.adb.tcp.port=5555`), toggle install verification, and write to all 3 settings namespaces. This gives near-system-level configuration control but **not root execution**.

#### DeviceRootKeyService (Samsung Key Attestation)

| TX Code | Result |
|---------|--------|
| 1 | Success (empty) |
| 2-3 | Returns `0xffffffff` (error/false) |
| 4 | Success (empty) |
| 5 | Returns `0xffffffed` (-19, ENODEV) |
| 6-10 | "Not a data message" (invalid TX) |

Service responds to shell calls but only handles 5 transactions. No exploitable behavior observed.

#### MobiCore / TrustZone

| Resource | Permissions | Shell Access |
|----------|-------------|-------------|
| `/dev/mobicore` | `crwx------` (system:system) | ❌ No access |
| `/dev/mobicore-user` | `crw-rw-rw-` (radio:system) | ✅ **open() succeeds** (no SELinux denial logged) |
| RootPA DeveloperService | `prot=normal` permission | ❌ Requires `DEVELOPER_PERMISSION` (installable APK could auto-grant it) |
| `@DeviceRootKeyService` socket | Abstract UNIX socket | ✅ Callable via binder (see above) |
| TIMA dmesg leaks | Physical addresses | ✅ `enabled: 0x20ab00a8`, `enforcing: 0x20b7ad18`, `write_ptr: 0x27402500` |

#### Additional Services & Vectors Checked

| Vector | Result |
|--------|--------|
| `dpm set-device-owner` | Blocked — existing accounts on device |
| `dpm set-profile-owner` | Blocked — existing accounts on profile |
| `run-as <any_package>` | "Could not set capabilities" — broken on this build |
| `pm grant shell INSTALL_PACKAGES` | "Not a changeable permission type" |
| World-writable files in `/system` | None found |
| SUID/SGID binaries anywhere | None found |
| `/dev/mem`, `/dev/kmem` | Do not exist |
| `/proc/config.gz` | Does not exist |
| Writable paths in `/sys` | None found from shell |
| `perf_event_paranoid` | Set to 1 (limited, not fully open) |
| Loaded kernel modules | `/proc/modules` does not exist |

### CTF Verdict

**No privilege escalation path to root (UID 0) exists** from `adb shell` on this device without a kernel-level 0-day exploit.

Every standard Android privesc technique was tested and blocked:
- **20 direct escalation paths** — all blocked (see table above)
- **SmartcomRoot AIDL interface** — fully reverse-engineered (15 methods), no command injection possible, iptables/tcpdump fail from UID 1000
- **Device owner/profile owner** — blocked by existing Google account
- **Property injection** — SELinux blocks all sensitive property classes from shell
- **Settings write** — works for all namespaces but cannot grant root execution
- **All decoy binaries** — confirmed non-functional (gzip blobs, non-PIE, wrong architecture)

**Remaining theoretical vectors (require exploit development — viability assessed):**

| # | Vector | Viability | Effort | Notes |
|---|--------|-----------|--------|-------|
| 1 | **Mali r7p0 kbase ioctl fuzzing** (`/dev/mali0`) | 🟡 **High** | Custom exploit needed | 414 kernel symbols, large ioctl surface, no stack canaries, no KASLR. r7p0 predates security hardening in later Mali drivers. Private rooting toolkits targeted this driver family on Samsung J-series/Tab A. |
| 2 | **ION heap manipulation** (`/dev/ion`) | 🟡 **High** | Custom exploit needed | Samsung-custom heaps (`mfc_fw`, `video`, etc.) with historical vendor bugs. Full SLUB layout visible via `/proc/slabinfo`. CVE-2016-6787 (perf_event) + ION chain was demonstrated on Samsung kernel 3.10 at Black Hat 2017. |
| 3 | **perf_event_open race** (CVE-2016-6787) | 🟡 **Medium** | Known technique, adaptation needed | `perf_event_paranoid=1` (allows limited access). Fix symbol `perf_event_ctx_lock` IS present in kallsyms — suggests patch was backported. However, the fix may be incomplete on this Samsung fork. Keen Lab's 2017 exploit targeted exactly this kernel version on Samsung. |
| 4 | **Binder driver bugs** (`/dev/binder`) | 🟢 **Low** | Research needed | CVE-2019-2215 targets 3.18+. Kernel 3.10 binder is an older codebase with less public scrutiny but also fewer features to exploit. |
| 5 | **MobiCore TEE + DeveloperService** | 🟡 **Medium** | Multi-step chain | `/dev/mobicore-user` opens from shell. Install custom APK → auto-grant `DEVELOPER_PERMISSION` → call `DeveloperService` → potential TEE interaction. TIMA physical address leaks aid exploitation. |

**Exploitation Enablers (why this kernel is soft-target):**
- ❌ No KASLR → deterministic addresses (`0xc0afeb00` leaked via slabinfo)
- ❌ No stack canaries → trivial stack overflow exploitation
- ❌ No HARDENED_USERCOPY → unchecked user↔kernel copies
- ❌ No RKP → credential structures freely writable in SLUB heap
- ❌ No cred_jar_ro → `commit_creds(prepare_kernel_cred(0))` is the standard payload
- ✅ `commit_creds` and `prepare_kernel_cred` symbols confirmed in kallsyms
- ✅ TIMA only measures kernel TEXT periodically — data/heap modifications are invisible to it

**Bottom Line:** While no *off-the-shelf* exploit achieves root, this kernel is **significantly weaker than previously assessed**. The absence of KASLR, stack canaries, HARDENED_USERCOPY, and RKP means that any memory corruption bug in the world-accessible device drivers (`/dev/mali0`, `/dev/ion`, `/dev/binder`) would be **straightforward to exploit** using standard kernel exploitation techniques (`commit_creds(prepare_kernel_cred(0))`). The Black Hat 2017 "Defeating Samsung KNOX with Zero Privilege" research demonstrated exactly this class of attack on the same kernel version (3.10) and Samsung device family. A motivated attacker with ioctl fuzzing capability could likely achieve root.
