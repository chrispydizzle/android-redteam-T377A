# JDWP Debug Access Assessment

**Device:** Samsung SM-T377A (AT&T)  
**Firmware:** T377AUCU2AQGF (Android 6.0.1, kernel 3.10.9)  
**Date:** 2025-02-25  
**Serial:** 52030d9842d7a3bd

## Executive Summary

JDWP (Java Debug Wire Protocol) is active on the device via the `@jdwp-control` abstract UNIX socket. However, the production build configuration (`ro.debuggable=0`, `release-keys`) severely limits its exploitation potential. **No system-UID processes are JDWP-debuggable**, making this a low-impact finding for privilege escalation.

## Key Properties

| Property | Value | Impact |
|---|---|---|
| `ro.debuggable` | **0** | Only explicitly debuggable apps exposed |
| `ro.secure` | **1** | ADB does not run as root |
| `ro.adb.secure` | **1** | ADB requires host authorization |
| `ro.build.type` | **user** | Production build (not userdebug/eng) |
| `ro.build.tags` | **release-keys** | Signed with release keys (not test-keys) |
| `persist.sys.usb.config` | acm,dm | USB configuration |
| SELinux | **Enforcing** | Shell domain: `u:r:shell:s0` |

## Findings

### 1. @jdwp-control Socket: ACCESSIBLE

The abstract UNIX socket `@jdwp-control` is reachable from shell context:
```
/proc/net/unix shows:
  @jdwp-control (listening, inode 7863)
  @jdwp-control (connected, inode 13789)
```

The on-device probe (`jdwp_probe`) successfully connected to the socket. ADB's `adb jdwp` command also works, listing debuggable PIDs.

### 2. JDWP-Debuggable Processes: ONLY USER APPS

Only **one** PID appeared in the JDWP list:

| PID | Process | UID | Impact |
|---|---|---|---|
| 3371 | com.redteam.probe | u0_a168 (10168) | Our own test app — no escalation |

**Zero system apps or framework processes are debuggable.** This is because:
- `ro.debuggable=0` on production builds
- Only apps compiled with `android:debuggable="true"` in their manifest appear
- All stock Samsung and Google apps use `debuggable=false`

### 3. JDWP Protocol: FULLY FUNCTIONAL

When forwarded via `adb forward tcp:8700 jdwp:3371`, the JDWP connection is fully operational:

```
Handshake:   JDWP-Handshake ✓
VM:          Android Runtime 2.1.0 (Dalvik)
JDWP:        Version 1.6
Threads:     9 active
Classes:     4,132 loaded
```

**Enabled capabilities:**
- canWatchFieldModification
- canWatchFieldAccess
- canGetBytecodes
- canGetSyntheticAttribute
- canGetOwnedMonitorInfo
- canGetCurrentContendedMonitor
- canGetMonitorInfo

This confirms full debug control — thread suspension, breakpoints, field watches, bytecode inspection, and **arbitrary code execution** via `ClassType.InvokeMethod` — but only within the debuggable app's own sandbox.

### 4. run-as: BROKEN

```
$ run-as com.android.shell id
run-as: Could not set capabilities: Operation not permitted

$ run-as com.redteam.probe id
run-as: Could not set capabilities: Operation not permitted
```

Samsung's SELinux policy appears to block `run-as` capability setting from shell domain. This eliminates `run-as` as a JDWP amplification vector.

### 5. System Process Analysis

Key system processes verified as **NOT debuggable**:

| PID | Process | UID | JDWP? |
|---|---|---|---|
| 2775 | system_server | system (1000) | NO |
| 3159 | com.android.systemui | u0_a47 | NO |
| 3502 | com.android.phone | radio (1001) | NO |
| 3648 | com.google.android.gms | u0_a8 | NO |
| 10323 | com.android.settings | system (1000) | NO |
| 3669 | com.sec.imsservice | system (1000) | NO |
| 4088 | com.smartcomroot | system (1000) | NO |

None of these appear in `adb jdwp` output.

## Escalation Viability

### Could JDWP help if combined with other primitives?

| Scenario | Feasible? | Notes |
|---|---|---|
| Debug system_server directly | **NO** | Not debuggable on production build |
| Install debuggable system app | **NO** | release-keys prevents unauthorized platform apps |
| Flip ro.debuggable via kernel write | **THEORETICAL** | Would require kernel exploit first (circular) |
| Use JDWP to amplify ION UAF | **NO** | ION exploit is kernel-level; JDWP is Java-level |
| Debug a UID-1000 Samsung app | **NO** | None are built with debuggable=true |
| Use JDWP post-root for persistence | **POSSIBLE** | After root, could set ro.debuggable=1 |

### Connection to ION Exploitation Chain

JDWP operates at the Java/Dalvik layer and does **not** provide:
- Kernel memory access
- ION heap manipulation capabilities
- Binder transaction injection
- SELinux policy modification

The ION UAF exploit chain works at the kernel level through `/dev/ion` ioctls. JDWP cannot assist with or amplify that attack path. They are orthogonal attack surfaces.

## Tools Produced

| Tool | Path | Purpose |
|---|---|---|
| jdwp_probe.c | `src/jdwp_probe.c` | On-device probe: connects to @jdwp-control, lists debuggable PIDs with UID/process info |
| jdwp_deep_probe.py | `work/jdwp_deep_probe.py` | Host-side Python: JDWP protocol handshake, VM info, capabilities enumeration |
| jdwp_probe (binary) | `/data/local/tmp/jdwp_probe` | Compiled ARM binary on device |

## Conclusion

**JDWP is a dead end for privilege escalation on this device.**

The production build configuration (`ro.debuggable=0`, `release-keys`, SELinux enforcing) ensures that:
1. No system-UID processes expose JDWP
2. No stock apps are debuggable
3. `run-as` is blocked by SELinux
4. The platform signing keys prevent installing custom system-level debuggable apps

JDWP would only be a significant finding on:
- **userdebug/eng builds** (`ro.debuggable=1`) — all Java processes become debuggable
- **Devices with test-keys** — could install platform-signed debuggable apps
- **Rooted devices** — could modify system properties to enable global debugging

**Risk Rating:** LOW (on this specific device configuration)  
**Recommendation:** Document as informational. Focus escalation efforts on kernel-level attack surfaces (ION, binder, mali).
