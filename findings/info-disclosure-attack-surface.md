# Information Disclosure & Extended Attack Surface Analysis

**Target**: Samsung SM-T377A (Galaxy Tab A), Exynos 3475, Android 6.0.1  
**Kernel**: Linux 3.10.9-11788437 (SPL 2017-07-01)  
**Shell context**: `u:r:shell:s0` (UID 2000)  
**Date**: 2026-02-23  

---

## Executive Summary

Beyond the kernel driver fuzzing (ION crash, binder node death), the device exposes significant **information disclosure** vectors and **expanded attack surface** accessible from an unprivileged ADB shell. Key findings: full debugfs access to binder/ION/Mali internals, readable dmesg and slabinfo (useful for heap spray/KASLR bypass), 165 binder services (many callable), and world-readable audio sockets.

---

## 1. Kernel Information Disclosure

### 🟡 MEDIUM: dmesg Readable from Shell

**Impact**: Kernel log leaks driver addresses, hardware state, error messages  
**Access**: `dmesg` from shell — no restrictions

dmesg is fully readable (979+ lines) and contains:
- Fuel gauge readings (hardware state)
- Binder transaction failures with process IDs
- Driver initialization messages
- Timer and interrupt details

**Recommendation**: Set `dmesg_restrict = 1` in kernel config or sysctl.

### 🟡 MEDIUM: /proc/slabinfo Readable

**Impact**: Leaks kernel heap layout — object sizes, active counts, slab structure  
**Access**: `cat /proc/slabinfo` from shell

Exposes all kernel slab caches including:
- `kmalloc-*` sizes and allocation counts
- `cred_jar` (not present — credentials in general cache)
- ext4, network, VFS caches

This information is valuable for heap spray attacks — an attacker can predict slab layout and allocation patterns.

**Recommendation**: Restrict `/proc/slabinfo` access (kernel config `CONFIG_SLABINFO` or permissions).

### 🟢 GOOD: kallsyms Addresses Zeroed

All kernel symbol addresses show as `00000000`:
```
00000000 T sys_call_table
00000000 T commit_creds
00000000 T prepare_kernel_cred
```
`kptr_restrict` is active (value 2 likely). Kernel addresses are not directly leaked through `/proc/kallsyms`.

### 🟢 GOOD: /proc/cmdline and /proc/iomem Restricted

Both return "Permission denied" from shell context. Kernel boot parameters and physical memory map are not exposed.

---

## 2. Debugfs Exposure

### 🟠 HIGH: Full Debugfs Readable from Shell

**Impact**: Complete internal state of binder, ION, Mali drivers exposed  
**Access**: `/sys/kernel/debug/*` readable from shell

| Path | Exposed Information |
|------|-------------------|
| `/sys/kernel/debug/binder/state` | All binder nodes, references, thread states, dead nodes |
| `/sys/kernel/debug/binder/failed_transaction_log` | Failed IPC transactions with PIDs |
| `/sys/kernel/debug/binder/transaction_log` | Full IPC transaction history |
| `/sys/kernel/debug/binder/stats` | Binder usage statistics |
| `/sys/kernel/debug/ion/heaps/*` | ION heap client list with PIDs and allocation sizes |
| `/sys/kernel/debug/ion/clients/*` | Per-client ION allocation details |
| `/sys/kernel/debug/dma_buf/bufinfo` | DMA buffer mappings with driver paths |
| `/sys/kernel/debug/mali/gpu_memory` | GPU memory allocation state |
| `/sys/kernel/debug/mali/mali_trace` | Mali driver trace log |
| `/sys/kernel/debug/mali/quirks_*` | **Read-write** Mali quirk registers |

**Notable**: `quirks_mmu`, `quirks_sc`, `quirks_tiler` are **writable** (`rw-r--r--`). An attacker could potentially modify Mali GPU behavior via debugfs.

**Recommendation**: Mount debugfs with restricted permissions or don't mount in production. At minimum, restrict shell domain access via SELinux.

---

## 3. Process Information Disclosure

### 🟡 MEDIUM: /proc/timer_list, /proc/sched_debug, /proc/pagetypeinfo

All readable from shell, exposing:
- **timer_list**: All kernel timers with nanosecond timestamps and callback addresses
- **sched_debug**: Scheduler state for all CPUs, runqueue details
- **pagetypeinfo**: Memory zone page allocation breakdown

### 🟡 MEDIUM: perf_event_paranoid = 1

Value of 1 allows unprivileged performance monitoring of own processes. Value should be ≥2 (or 3) to restrict kernel address exposure through perf events.

---

## 4. Network Attack Surface

### 🟢 LOW: Two TCP6 Listening Ports

| Port | UID | Likely Service |
|------|-----|----------------|
| 43609 | 10162 | App-specific (high ephemeral port) |
| 43610 | 10163 | App-specific (high ephemeral port) |

These are bound to `::` (all interfaces) but are high-numbered ports likely used by Google Play Services or similar apps. All outbound TCP4 connections go to port 443 (HTTPS) — normal.

No low-numbered ports are listening. No traditional remote services exposed.

---

## 5. Binder Service Attack Surface

### 🟠 HIGH: 165 Binder Services Accessible

The device exposes **165 registered binder services**. From shell context, many can be called via `service call`:

| Service | Access | Notes |
|---------|--------|-------|
| `com.smartcom.root.APNWidgetRootService` | ✅ Callable | System-UID 1000 service — previously reverse-engineered (15 AIDL methods) |
| `DeviceRootKeyService` | ✅ Callable | Samsung device root key management |
| `execute` | ✅ Callable | **Returns detailed app/activity data** — information disclosure |
| `phone` | ✅ Callable | Telephony service |
| `package` | ✅ Callable | Package manager |
| `wifi` | ✅ Callable | WiFi manager |
| `clipboard` | ✅ Callable | Clipboard access |
| `backup` | ✅ Callable | Backup manager |
| `mount` | ✅ Callable | Mount service |
| `device_policy` | ✅ Callable | Device policy manager |
| `bluetooth_manager` | ✅ Callable | Bluetooth management |
| `knox_ccm_policy` | ⚠️ Returns -1 | Requires Knox permission |
| `knox_timakeystore_policy` | ❌ Permission denied | "uid 2000 does not have KNOX_KEYSTORE permission" |
| `sec_analytics` | ❌ Permission denied | "uid 2000 does not have MDM_ANALYTICS permission" |

**SmartcomRoot** is particularly interesting — it runs as system UID 1000 and we previously identified 15 AIDL methods including `shellExec`, `chmod`, `chown`, `writeFile`, and `installAPK`. If any method can be invoked without proper authorization checks, it could provide direct privilege escalation.

### Notable: `execute` Service Leaks App Data

The `execute` service (method 1) returns detailed information about installed apps including package names, activity names, intent filters, and internal resource IDs. This is an information disclosure issue that aids further attack planning.

---

## 6. Unix Domain Sockets

### 🟡 MEDIUM: World-Readable Audio Sockets

| Socket | Owner | Permissions |
|--------|-------|-------------|
| `/data/TMAudioSocketServer` | media:system | `srwxrwxrwx` (777) |
| `/data/TMAudioSocketClient` | media:system | `srwxrwxrwx` (777) |

These Samsung audio sockets are world-accessible. Any process (including shell) can connect. Potential for audio injection/interception or command injection if the protocol is not properly validated.

### Other Sockets (restricted)

| Socket | Owner | Permissions |
|--------|-------|-------------|
| `/data/.socket_stream` | system:system | `srwx------` |
| `/data/.mtp_stream` | system:system | `srwx------` |
| `/data/.diag_stream` | system:system | `srwx------` |
| `@mcdaemon` | — | Abstract socket |
| `@jdwp-control` | — | Abstract socket (Java debug) |

---

## 7. Content Provider Access

### 🟠 HIGH: Contacts Readable Without Permission

**Impact**: Any ADB shell session can read all device contacts  
**Access**: `content query --uri content://contacts/people`

The contacts content provider does **not** enforce `READ_CONTACTS` permission for the shell UID. Full contact records including names, phone numbers, emails, and notes are exposed.

### 🟡 MEDIUM: Settings Writable from Shell

**Impact**: Shell can modify global, secure, and system settings  
**Access**: `settings put global <key> <value>`

Confirmed writable:
- `development_settings_enabled` (developer options toggle)
- `airplane_mode_on` (toggle airplane mode)
- System animation scales, brightness, etc.

This allows an ADB attacker to silently reconfigure the device.

### 🟢 GOOD: SMS and Call Log Protected

Both `content://sms` and `content://call_log/calls` correctly enforce `READ_SMS` and `READ_CALL_LOG` permissions. Access denied for shell UID 2000.

### 🟡 MEDIUM: IMEI Exposed via Binder Service

**Impact**: Device IMEI readable via `service call iphonesubinfo 1`  
Returns: `353608074799027` — unique hardware identifier

---

## 8. Shell Capability Summary

### 🟠 HIGH: Extensive Shell Capabilities

The ADB shell (`u:r:shell:s0`, UID 2000) can:

| Capability | Access | Security Impact |
|------------|--------|----------------|
| Screen capture | `screencap -p` | ✅ Works — visual data exfiltration |
| Input injection | `input keyevent/tap/swipe` | ✅ Works — remote device control |
| Activity launch | `am start` | ✅ Works — launch any exported activity |
| APK install | `pm install` | ✅ Works — sideload applications |
| Settings write | `settings put global/secure` | ✅ Works — reconfigure device |
| Contacts read | `content query contacts` | ✅ Works — PII exfiltration |
| dmesg read | `dmesg` | ✅ Works — kernel info leak |
| debugfs read | `cat /sys/kernel/debug/*` | ✅ Works — driver state leak |
| /data/system listing | `ls /data/system/` | ✅ Works — enumerate system files |
| Kernel driver ioctl | `open(/dev/ion,binder,ashmem,mali0)` | ✅ Works — kernel attack surface |
| /proc/slabinfo | `cat /proc/slabinfo` | ✅ Works — heap layout leak |
| Process list | `ps` | ✅ Works — enumerate all processes |
| IMEI read | `service call iphonesubinfo 1` | ✅ Works — hardware ID |
| WiFi config read | via binder service calls | ✅ Works — network info |
| ptrace init | `cat /proc/1/maps` | ❌ Denied — process isolation works |
| /data/data access | `ls /data/data/` | ❌ Denied — app data protected |
| SMS/Call log | content provider query | ❌ Denied — permission enforced |
| /data/misc read | `ls /data/misc/` | ❌ Denied |
| /system write | `touch /system/*` | ❌ Denied (read-only mount) |

---

## 9. SELinux Assessment

### Shell Domain Capabilities

The shell domain (`u:r:shell:s0`) has significant access:
- ✅ Can open `/dev/ion`, `/dev/binder`, `/dev/ashmem`, `/dev/mali0`
- ✅ Can read debugfs (binder, ION, Mali, DMA-buf state)
- ✅ Can read dmesg, slabinfo, timer_list, sched_debug
- ✅ Can call most binder services
- ✅ Can read contacts, write settings, capture screen, inject input
- ✅ Can install APKs and launch activities
- ❌ Cannot open `/dev/mobicore-user` (SELinux blocks)
- ❌ Cannot become binder context manager (SELinux blocks)
- ❌ Cannot read `/proc/cmdline`, `/proc/iomem`
- ❌ Cannot access Knox/TIMA keystore services

### Policy File

The SELinux policy (`/sepolicy`, 773KB) is readable and could be analyzed offline for:
- Domain transition rules that allow escalation
- Permissive domains
- Overly broad file access rules
- Missing neverallow rules

---

## 8. Filesystem & Binary Assessment

### 🟢 GOOD: No SUID/SGID Binaries

No setuid or setgid binaries found in `/system`. This eliminates a common privilege escalation vector.

### 🟢 GOOD: No World-Writable Files in /system

The `/system` partition contains no world-writable regular files.

### Device Properties (Security-Relevant)

| Property | Value | Assessment |
|----------|-------|------------|
| `ro.secure` | 1 | ADB does not run as root |
| `ro.debuggable` | 0 | Not a debug build |
| `ro.build.selinux` | 1 | SELinux compiled in |
| `selinux.reload_policy` | 1 | Policy loaded |

---

## Combined Risk Matrix

| Finding | Severity | Exploitability | Impact |
|---------|----------|----------------|--------|
| ION heap bit 2 crash | 🔴 Critical | Easy (single ioctl) | Kernel DoS |
| Binder handle 0 refcount death | 🔴 Critical | Easy (BC commands) | System-wide DoS |
| Contacts readable without permission | 🟠 High | Trivial | PII exfiltration |
| Debugfs fully readable | 🟠 High | Trivial | Info leak for exploit dev |
| Settings writable from shell | 🟠 High | Trivial | Device reconfiguration |
| Shell: screencap + input injection | 🟠 High | Trivial | Visual data theft, remote control |
| IMEI exposed via binder service | 🟠 High | Trivial | Hardware ID leak |
| 165 callable binder services | 🟠 High | Medium | Potential priv esc |
| dmesg readable | 🟡 Medium | Trivial | Kernel info leak |
| slabinfo readable | 🟡 Medium | Trivial | Heap layout leak |
| World-RW audio sockets | 🟡 Medium | Easy | Audio intercept/inject |
| perf_event_paranoid = 1 | 🟡 Medium | Medium | Perf-based info leak |
| /data/system listable | 🟡 Medium | Trivial | System file enumeration |
| proc timer/sched/pagetype | 🟡 Low | Trivial | Minor info leak |
| SmartcomRoot service | 🟢 Low | N/A | APN management only — not a priv esc vector |

---

## Recommendations

### Critical (Immediate)
1. **Restrict ION heap access**: Validate `heap_id_mask` in kernel — reject bit 2 allocations or fix the underlying CMA heap crash
2. **Fix binder refcount handling**: Add validation that unprivileged processes cannot manipulate refcounts on handle 0 (servicemanager)

### High Priority
3. **Restrict debugfs**: Don't mount debugfs in production, or restrict via SELinux
4. **Enforce contacts permission**: Contacts content provider must check `READ_CONTACTS` for shell UID
5. **Restrict settings write**: Shell should not be able to modify global/secure settings
6. **Restrict binder service access**: Add caller UID/permission checks to `iphonesubinfo` (IMEI) and other sensitive services

### Medium Priority
7. **Set `dmesg_restrict = 1`**: Prevent kernel log access from unprivileged users
8. **Restrict `/proc/slabinfo`**: Hide heap layout from non-root
9. **Fix TMAudio socket permissions**: Change from 777 to 770
10. **Set `perf_event_paranoid ≥ 2`**: Restrict performance monitoring
11. **Restrict `/data/system` directory listing**: Shell should not be able to enumerate system files

---

## 10. Deep Kernel Surface Analysis

### Socket Creation from Shell

| Socket Type | Result | Security Impact |
|-------------|--------|----------------|
| TCP (`SOCK_STREAM`) | ✅ Allowed | Expected |
| UDP (`SOCK_DGRAM`) | ✅ Allowed | Expected |
| ICMP (`SOCK_DGRAM`, IPPROTO_ICMP) | ✅ Allowed | `ping_group_range = 0-2147483647` — any UID can ping |
| RAW IP (`SOCK_RAW`) | ❌ Blocked | Good — requires `CAP_NET_RAW` |
| PACKET (`AF_PACKET`) | ❌ Blocked | Good — requires `CAP_NET_RAW` |
| NETLINK_ROUTE | ✅ Allowed | Can dump routing tables, interface info |
| NETLINK_SELINUX | ✅ Allowed | Can subscribe to SELinux policy change notifications |
| NETLINK_UEVENT | ❌ Blocked | Good |
| NETLINK_AUDIT | ❌ Blocked | Good |
| NETLINK_CONNECTOR | ❌ Blocked | Good |
| NETLINK_GENERIC | ❌ Blocked | Good |
| ICMPv6 RAW | ❌ Blocked | Good |

### Netlink Fuzzing Results

| Family | Iterations | Total Ops | Crashes | Result |
|--------|-----------|-----------|---------|--------|
| NETLINK_ROUTE | 5,000 | 5,000 | 0 | ✅ Robust |
| NETLINK_SELINUX | 5,000 | 5,000 | 0 | ✅ Robust |

Tested: valid dumps, garbage types, oversized payloads (2KB random), truncated headers. Kernel logged "bytes leftover after parsing" for oversized messages but handled all gracefully.

### /dev/alarm Probe

| Operation | Result |
|-----------|--------|
| Open (read-only) | ✅ Allowed |
| GET_TIME (all 5 types) | ✅ Returns real timestamps |
| SET alarm | ❌ EPERM |
| CLEAR alarm | ❌ EPERM |
| SET_RTC | ❌ EPERM |
| Garbage ioctl | ❌ EINVAL (proper rejection) |

Alarm driver is readable but not writable from shell. Timestamps leak uptime information.

### /proc Kernel Information Accessible

44 entries readable, 24 blocked. Key accessible entries:

| Entry | Security Impact |
|-------|----------------|
| `/proc/vmallocinfo` | Vmalloc region sizes + function names (kptr_restrict zeros addresses) |
| `/proc/buddyinfo` | Memory zone page allocation state |
| `/proc/zoneinfo` | Detailed memory zone statistics |
| `/proc/vmstat` | Virtual memory counters |
| `/proc/crypto` | All kernel crypto algorithms and implementations |
| `/proc/locks` | File locking state |
| `/proc/interrupts` | Hardware interrupt counts and GIC routing |
| `/proc/softirqs` | Softirq handler statistics |
| `/proc/1/status` | Init process UID, capabilities (`CapPrm: 0000001fffffffff`), memory layout |
| `/proc/1/cmdline` | Init command line (`/init`) |
| `/proc/1/wchan` | Init wait channel (`SyS_epoll_wait`) |
| `/proc/net/arp` | ARP table — exposes network neighbor MAC addresses |

### mmap Null-Page Protection

- `mmap(NULL, MAP_FIXED)` → **EINVAL** (good — kernel rejects null-page mapping)
- `mmap(0x1000, MAP_FIXED)` → **EINVAL** (good — mmap_min_addr protects low pages)

This prevents null-pointer dereference exploitation in kernel space.

### Kernel Surface Fuzzing Summary (Extended)

| Surface | Ops | Crashes | Result |
|---------|-----|---------|--------|
| ION | 57,936 | 1 (heap bit 2) | 🔴 Kernel crash DoS |
| Binder | 110,199 | 2 (handle 0) | 🔴 System freeze DoS |
| Mali | 29,744 | 0 | ✅ Robust |
| Ashmem | 151,187 | 0 | ✅ Robust |
| NETLINK_ROUTE | 5,000 | 0 | ✅ Robust |
| NETLINK_SELINUX | 5,000 | 0 | ✅ Robust |
| /dev/alarm | 3,000 | 0 | ✅ Robust |
| ICMP socket | 3,000 | 0 | ✅ Robust |
| UDP socket | 3,000 | 0 | ✅ Robust |
| **Total** | **368,066** | **3** | **2 unique vulns** |

### Ftrace Event Tracing — Shell Writable (HIGH)

Shell (UID 2000) can control kernel ftrace event tracing:

| Capability | Status | Impact |
|------------|--------|--------|
| Enable `sched_switch` | ✅ Writable | Exposes ALL process names, PIDs, priorities, CPU, kernel timestamps |
| Enable `sched_wakeup` | ✅ Writable | Exposes process wakeup sources |
| Enable `cpu_frequency` | ✅ Writable | Exposes DVFS transitions (workload side-channel) |
| Enable `cpu_idle` | ✅ Writable | Exposes CPU idle state transitions |
| Write `trace_marker` | ✅ Writable | **Inject arbitrary fake events** into kernel trace |
| Expand `buffer_size_kb` | ✅ Writable | Can expand to 16MB/CPU (64MB total, 4.5% of 1.4GB RAM) |
| Clear trace buffer | ✅ Writable | **Erase forensic evidence** |
| Read `trace` / `trace_pipe` | ✅ Readable | Read all captured scheduling data |
| Change `trace_clock` | ❌ Blocked | Clock source locked to `local` |
| Change `current_tracer` | ❌ Blocked | Only `nop` tracer available |
| Enable `binder_transaction` | ❌ Blocked | Good — IPC tracing locked |
| Enable `kmem/kmalloc` | ❌ Blocked | Good — heap tracing locked |
| Enable `irq/*` | ❌ Blocked | Good — interrupt tracing locked |

**Confirmed exploitation**: Shell successfully injected `"INJECTED_BY_SHELL: fake_event_marker_12345"` into kernel trace buffer and read it back as legitimate kernel event.

---

## Files

| File | Description |
|------|-------------|
| `src/kernel_surface_probe.c` | Comprehensive kernel surface prober (alarm, sockets, proc, mmap) |
| `src/netlink_fuzz.c` | Netlink ROUTE + SELINUX socket fuzzer |
| `src/alarm_fuzz.c` | /dev/alarm ioctl fuzzer |
| `src/icmp_fuzz.c` | ICMP/UDP socket fuzzer |
| `work/sepolicy` | Extracted SELinux policy binary (773KB) — for offline analysis |
| `work/dmesg_netlink_fuzz.txt` | Dmesg after netlink fuzzing |
