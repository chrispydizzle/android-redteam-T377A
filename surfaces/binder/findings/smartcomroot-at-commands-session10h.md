# SmartcomRoot & AT Command Findings — Session 10h

## Date: 2026-02-26
## Focus: SmartcomRoot system service exploitation, AT command enumeration, ServiceManager mapping

---

## Executive Summary

This session yielded two major findings:
1. **SmartcomRoot** (`com.smartcomroot`) — A Samsung system service running as UID 1000 with two exported, unpermissioned binder services. All 15 AIDL methods are callable from both shell (UID 2000) and untrusted_app (UID 10139). However, the most promising methods (iptables, tcpdump) require root and fail at UID 1000. Command injection is blocked because Runtime.exec() uses array form.
2. **Raw AT commands on COM11** — The DM port (COM11) accepts standard AT commands without DM framing. AT+DUMPCTRL is accepted by the modem, and AT+CFUN modes 0-12 are available. IMEI, serial number, and firmware versions were extracted.

Additionally, 164 ServiceManager binder services were mapped from untrusted_app context, identifying several partially accessible enterprise services but none with direct privesc capability.

---

## Finding 1: SmartcomRoot — Exposed System Service (CRITICAL)

**Severity**: High (exposed system service) / Medium (current exploitation limited)

### Discovery
User observed `com.smartcomroot.services.SmartcomRootService$CheckAppThread` in logcat, firing every 15 seconds. This is a persistent system service that auto-restarts.

### Package Details
```
Package: com.smartcomroot
Location: /system/priv-app/APNWidgetBaseRoot_ATT/APNWidgetBaseRoot_ATT.apk
UID: 1000 (system)
sharedUserId: android.uid.system
Flags: SYSTEM | HAS_CODE | PERSISTENT | PRIVILEGED
Version: 1.11
targetSdkVersion: 23 (built against Android 4.4 SDK!)
Signing: Samsung platform key (SHA-256 prefix: 46fba8b)
```

### Exported Services (No Permission Protection)
1. `com.smartcomroot.services.SmartcomRootService` — exported=true, permission=null
2. `com.smartcom.root.APNWidgetRootService` — exported=true, permission=null

Both can be started from any app or shell without any permission check.

### AIDL Interface: IAPNWidgetRootService
Registered in ServiceManager as `com.smartcom.root.APNWidgetRootService`

All 15 transaction codes accessible:
| Code | Method | Notes |
|------|--------|-------|
| 1 | AddFirewallRule | Calls iptables with user string |
| 2 | EnableMobileNetwork | Reflection to setMobileDataEnabled |
| 3 | GetFirewallRule | Query iptables rules |
| 4 | GetStats | Query network stats |
| 5 | InsertApn | Insert APN via ContentValues |
| 6 | NotifyReconnect | Expects integer argument |
| 7 | SetAirPlaneMode | Toggle airplane mode |
| 8 | SetDefaultApn | Set default APN |
| 9 | SetDefaultApnName | Set default APN name |
| 10 | SetNoDefaultApn | Remove default APN |
| 11 | StartStats | Start tcpdump capture |
| 12 | StopStats | Stop tcpdump/kill -9 |
| 13 | SwitchToOperatorApn | Switch to carrier APN |
| 14 | isAdvancedStatAvailable | Returns boolean |
| 15 | isIptablesBlockingAvailable | Returns boolean |

### Code Analysis (ODEX reverse engineering)
The APK has no classes.dex — code lives in ODEX at:
`/system/priv-app/APNWidgetBaseRoot_ATT/oat/arm/APNWidgetBaseRoot_ATT.odex` (94700 bytes)

Key findings from ODEX string extraction:
- **Runtime.exec() with array form**: `Runtime.getRuntime().exec(new String[]{"/system/bin/iptables", ...})`
  - This means NO shell interpretation — semicolons, backticks, pipes are literal characters
- **iptables fails**: `iptables v1.4.20: can't initialize iptables table 'filter': Permission denied (you must be root)`
  - UID 1000 cannot run iptables, despite the service running as system
- **tcpdump fails**: `Error running exec()` — same root requirement
- **EasySSLSocketFactory + EasyX509TrustManager**: Accepts ALL SSL certificates unconditionally
  - MitM vulnerability in APN management network traffic
- **ServiceManagerReflect**: Uses reflection to add/get/check services in ServiceManager

### Command Injection Testing
All injection attempts via `service call` with crafted string arguments:
- `` `id > /sdcard/pwned` `` → "Bad argument `id" (literal)
- `test; id` → "Bad argument 'test;'" (literal)
- `test\nid > /sdcard/...` → "Bad argument 'test'" (first line only)
- Pipe injection → literal argument
- Null byte injection → string terminated

**Conclusion**: Runtime.exec(String[]) completely prevents shell metacharacter injection. This is a dead end for command execution.

### Exploitable Capabilities
Despite blocked command execution, SmartcomRoot CAN:
1. **Manipulate APNs** — Insert rogue APNs, set them as default, redirect cellular traffic
2. **Toggle airplane mode** — Network disruption
3. **Enable/disable mobile data** — Network control
4. **Query network state** — Information disclosure

### Potential Further Exploitation Paths
1. **APN MitM attack**: Insert an APN pointing to attacker-controlled proxy. Combined with EasySSLSocketFactory vulnerability, could intercept all cellular data traffic.
2. **INSTALL_PACKAGES via alternative path**: SmartcomRoot runs as UID 1000 which inherits INSTALL_PACKAGES. While no AIDL method directly exposes package installation, the service could potentially be coerced through:
   - APN manipulation to trigger app download/install flow
   - Exploiting the EasySSLSocketFactory to serve malicious APK during APN provisioning

---

## Finding 2: AT Command Interface on DM Port (HIGH)

**Severity**: High (device information disclosure, modem control)

### Discovery
While testing DM protocol, discovered that COM11 (Samsung Mobile USB Modem) accepts raw AT commands without any DM framing. Previous attempts failed because they wrapped AT commands in DM frame delimiters (`7E ... 7E`), which corrupted the AT parser.

### Working AT Commands
```
ATI         → T377AUCU2AQGF (firmware version)
ATI0        → Samsung Electronics (manufacturer)
ATI2        → IMEI 1: 000000000000000, IMEI 2: 350000000000006
ATI4        → Factory Default 'core' profile [+ALL+]
AT+CGMI     → Samsung Electronics
AT+CGMM     → Samsung LTE ALPSS
AT+CGMR     → T377AUCU2AQGF
AT+SWVER    → T377AUCU2AQGF/T377AATT2AQGF/T377AUCU2AQGF/T377AUCU2AQGF
AT+DEVCONINFO → MN(SM-T377A);BASE(...)
AT+SERIALNO → 1,R0000000000,161019
AT+CFUN?    → +CFUN: 0 (phone offline)
AT+CFUN=?   → (0,1,4-12),(0-1) — modes 0-12 available
AT+CPIN?    → SIM not inserted
AT+CSQ      → 99,0 (no signal)
AT+GCAP     → +CGSM
AT+DUMPCTRL → DUMPCTRL:OK (accepted!)
AT+CLAC     → Partial command list (AT& prefix)
```

### Information Disclosed
- **IMEI** (both slots): 000000000000000 / 350000000000006
- **Serial number**: R0000000000, manufactured 2016-10-19
- **Firmware versions**: All 4 firmware components
- **Modem type**: Samsung LTE ALPSS (Shannon baseband)
- **Radio capabilities**: GSM (+CGSM)
- **Radio state**: Offline (CFUN=0)

### AT+DUMPCTRL — Potential Memory Dump Control
The modem accepted `AT+DUMPCTRL` and returned `DUMPCTRL:OK`. This command typically controls CP (Communication Processor) crash dump behavior on Samsung devices. Possible exploitation:
- `AT+DUMPCTRL=0` / `=1` — Enable/disable CP crash dumps
- If CP dumps are enabled and written to `/data/log/` or similar, could contain:
  - Modem firmware memory (Shannon baseband secrets)
  - SIM authentication data
  - Network keys

### AT+CFUN Modes
Modes 0-12 available, with mode 1 enabling full radio operation. Currently at mode 0 (offline). Enabling radio could unlock additional AT commands that require active registration.

### Blocked AT Commands
All non-standard commands returned ERROR:
- Samsung debug: AT+ENGMODE, AT+DEBUGMODE, AT+DIAGCFG
- Qualcomm: AT$QCVOLT, AT+QNVR, AT+QENG
- Shannon: AT+SHDEBUG, AT+SHFACTORY, AT+SHANNEL
- All brute-force prefix scans: AT@, AT%, AT!, AT*, AT#

---

## Finding 3: DM Protocol Buffer Behavior (INFORMATIONAL)

**Severity**: Low (corrects prior assessment)

### USB ZLP Issue at 512 Bytes
The previously reported "512 buffer limit" in DM protocol was misidentified. The actual issue:
- **Frame=512 bytes exactly** → No response (USB Zero-Length Packet needed but not sent)
- **Frame=513+ bytes** → Normal response
- This is a standard USB bulk transfer issue, not a buffer overflow boundary

### Escape Expansion Behavior
Previously identified "escape expansion bypasses 512 limit" was normal behavior:
- DM protocol encodes `7D/7E` bytes as two-byte sequences
- Expansion at 512 causes USB fragmentation
- Re-encoding on response path is standard protocol behavior

---

## Finding 4: ServiceManager — 164 Services Mapped (INFORMATIONAL)

**Severity**: Low-Medium (attack surface documentation)

### Accessible from untrusted_app (device owner)
From our privesc APK (UID 10139), probed all 164 ServiceManager-registered services:

**Partially accessible services (no SecurityException on some methods)**:
- `enterprise_policy` (IEnterpriseDeviceManager) — M1-M2 succeed
- `EngineeringModeService` (IEngineeringModeService) — M1 returns val=0
- `execute` (IExecuteManager) — Returns app list (23 items)
- `DeviceRootKeyService` (IDeviceRootKeyService) — Returns 0 for all methods
- `serial` (ISerialManager) — Accessible
- `usb` (IUsbManager) — Accessible

**Blocked by permission**:
- `remoteinjection` — Requires MDM_REMOTE_CONTROL (signature protection level)
- Most Knox enterprise services — Require signature-level MDM permissions

### JDWP Debug Status
- `ro.debuggable=0` — No system process debugging available
- SET_DEBUG_APP only shows "waiting for debugger" dialog, doesn't enable JDWP agent
- Only debuggable processes are our own red team apps

---

## Updated Attack Surface Assessment

### Viable Paths (Priority Order)
1. **SmartcomRoot INSTALL_PACKAGES via indirect path** — Find a way to trigger the package install permission
2. **Abstract socket probing from untrusted_app** — Different SELinux domain may allow different socket access
3. **Content provider exploitation from device owner** — Richer access than shell
4. **AT+DUMPCTRL modem dump** — Could leak baseband secrets
5. **diagexe DM protocol fuzzing** — CAP_SYS_ADMIN process, controllable via COM11
6. **Kernel exploitation** — ION UAF, Mali import crash from prior sessions

### Definitively Blocked
- SmartcomRoot command injection (Runtime.exec array form)
- SmartcomRoot iptables/tcpdump (need root, UID 1000 insufficient)
- remoteinjection (MDM_REMOTE_CONTROL signature permission)
- JDWP debugging of system apps (ro.debuggable=0)
- Platform signing key forging (Samsung proprietary)
- Abstract socket access from shell (SELinux denies all)

---

## Finding 5: dnsproxyd Socket — Root Process Accessible (CRITICAL)

**Severity**: Critical (potential root privesc)

The DNS proxy daemon socket (`/dev/socket/dnsproxyd`) is accessible from untrusted_app domain. `netd` runs as **root** (PID 2191) and handles DNS proxy requests. This is a well-known attack surface — any buffer overflow or format string vulnerability in netd's DNS handler would yield root code execution. On Android 6.0.1 (2017-07 patch), multiple netd CVEs may be unpatched.

## Finding 6: PackageInstaller — Silent APK Installation (HIGH)

**Severity**: High (arbitrary code installation)

Device owner can use `PackageInstaller` to silently install APKs. Session creation confirmed (ID 2046558354). While installed apps run as untrusted_app (not system), this enables:
- Installing keylogger/screen capture apps
- Replacing non-system apps
- Expanding attack surface with custom exploitation tools

## Finding 7: TIMA SELinux Address Leak (HIGH)

**Severity**: High (kernel exploitation enabler)

TIMA kernel integrity monitor leaks SELinux physical addresses via dmesg:
- `selinux_enabled` paddr: 0x20ab00a8 → vaddr: 0xc0ab00a8
- `selinux_enforcing` paddr: 0x20b7ad18 → vaddr: 0xc0b7ad18
- TIMA write pointer: 0x27403580

Confirms NO KASLR and provides exact addresses for SELinux bypass. TIMA checks every 5 minutes, so any modification must be timed.
