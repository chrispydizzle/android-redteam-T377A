# Session 14 — Log Analysis Pipeline & Live Exploit Monitoring

**Date:** 2026-03-06
**Focus:** Real-time logcat/dmesg security analysis pipeline, live exploit observation
**Device:** SM-T377A (0000000000000000), uptime 10+ hours, no reboots during session
**Monitoring stats:** 2,846 findings over ~10h continuous capture

---

## Hard Facts (with citations)

### 1. ADB logcat `-b crash` buffer kills streaming on Android 6.0.1

- **Finding:** `adb logcat -b crash` (without `-d` flag) exits immediately with code 0
- **Affected combos:** `main+system+crash` → DEAD, `main+system+crash+events` → DEAD
- **Working combos:** `main` → ALIVE, `main+system` → ALIVE, `main+system+events` → ALIVE
- **Citation:** Live test via `work/debug_buffers.py`, 5 buffer combinations tested with `subprocess.Popen` + `CREATE_NEW_PROCESS_GROUP`, each given 1.5s to stabilize. 100% reproducible.

### 2. Windows subprocess requires CREATE_NEW_PROCESS_GROUP (0x200) for adb

- **Finding:** Python `subprocess.Popen` spawning `adb logcat` exits immediately with code 0 unless `creationflags=0x00000200`
- **Root cause:** Parent process signal delivery kills adb child on Windows
- **Citation:** `work/debug_logcat2.py` with 0x200 → 2800+ lines read, stream alive after 15s. Without → 0 lines, immediate EOF, `poll()=0`.

### 3. TIMA integrity checks pass consistently (~5 min interval)

- **Finding:** TIMA TrustZone kernel verification succeeds on every observed check
- **Pattern:** `TimaService scheduler intialized` → `checkEvent op:50000 subj:10000` → `response_id=3` → `response ret=0, Kernel Verification Success`
- **TIMA leaks physical addresses every cycle:**
  - `enforcing: 20b7ad18` → vaddr `0xC0B7AD18` (selinux_enforcing) — **consistent across all 16 observed cycles**
  - `enabled: 20ab00a8` → vaddr `0xC0AB00A8` (selinux_enabled)
  - `write_ptr: 27405a80` → vaddr `0xC7405A80` (NOTE: differs from STATUS.md's `0xC7403580`)
- **Citation:** 219 TIMA_ALERT + 16 SELINUX_PERMISSIVE (false positive on TIMA paddr log) findings in `work/logs/security_findings.jsonl`. dmesg timestamps: 12022, 12325, 33325, 33622, 33925, 34222, 34525, 34822, 35125, 35422, 35725, 36022, 36325, 36622, 36925, 37222 (~297s interval = ~5 min).

### 4. SecretCodeIME attack chain works from privesc agent

- **Finding:** Broadcasting `cmd=secretcode_attack` to privesc agent launches `SecretCodeIME` (`com.sec.android.app.parser/.SecretCodeIME`) successfully
- **UI enumeration succeeded:** 2 windows, status bar elements visible via accessibility
- **Citation:**
  - logcat `03-06 11:25:10.070` — `PrivEscAgent: onReceive: cmd=secretcode_attack`
  - logcat `03-06 11:25:10.110` — `am_create_activity: [0,53382636,968,com.sec.android.app.parser/.SecretCodeIME,...]`
  - logcat `03-06 11:25:14.560` — `PrivEscAgent: === SECRETCODE IME ATTACK: 873283 ===` + full window enumeration

### 5. SELinux blocks FactoryApp/EFS access from shell domain

- **Finding:** Shell (`u:r:shell:s0`) denied read/search on FactoryApp dir on EFS partition
- **Target:** `u:object_r:app_efs_file:s0`, device `mmcblk0p3`, inode 21
- **Citation:**
  - logcat `03-06 11:25:55.220` — `avc: denied { read } for pid=19032 comm="sh" name="FactoryApp" dev="mmcblk0p3" ino=21`
  - logcat `03-06 11:25:55.245` — `avc: denied { search } for pid=19034 comm="ls" name="FactoryApp" dev="mmcblk0p3"`

### 6. Binder transaction failure during exploit activity window

- **Finding:** `binder: 2767:3402 transaction failed 291889, size 176-0` in dmesg
- **Context:** PID 2767 = system_server, thread 3402 = Binder_7, payload 176 bytes, no reply
- **Citation:** dmesg timestamp 33478.364405, correlates with 11:25 attack window

### 7. AT+DEVCONINFO sent via ATD, followed by NV write burst

- **Finding:** AT command sent through diagexe→ATD internal path. RILD then processed 5 NV writes via RFS protocol
- **NV writes (all cmd=0x02, offset=0x0, checksum-validated):**

  | Time | Bytes | Hex Size |
  |------|-------|----------|
  | 11:33:21 | 20,780 | 0x512C |
  | 11:33:26 | 20,782 | 0x512E |
  | 11:33:31 | 20,782 | 0x512E |
  | 11:33:41 | 20,784 | 0x5130 |
  | 11:33:47 | 20,782 | 0x512E |

- **Pattern:** ~5s cadence, sizes ±2 bytes, 11 RFS packets per write
- **Citation:** radio buffer `03-06 11:31:00.415` `ATD: Send Msg [DDEXE > ATD] 15 bytes <AT+DEVCONINFO>`. RILD `Nv::ProcessNvWrite` entries 11:33:21–11:33:47.

### 8. Mali TOCTOU exploit — rejected by driver flag validation

- **Finding:** `mali_alias_toctou` (PID 19504) triggered `kbase_mem_alloc called with bad flags (4020f)`
- **Flags 0x4020f:** Lower nibble 0xF invalid + GROW_ON_GPF(bit9) + NEED_MMAP(bit18) — driver rejects non-standard combo
- **Result:** Single kernel warning, no crash, no oops, no memory corruption
- **Citation:** dmesg `[34147.937824] [2:mali_alias_toct:19504] [c2] mali 11400000.mali: kbase_mem_alloc called with bad flags (4020f)`

### 9. SmartcomRoot polls every ~15 seconds continuously

- **Finding:** `SmartcomRootService$CheckAppThread.run()` fires `sendBroadcast()` on ~15s interval for 10+ hours continuously
- **Significance:** UID 1000 service with predictable timing — potential timing oracle or race sync
- **Citation:** 688 SMARTCOM_ROOT findings, consistent 15s cadence from 02:43 through 12:09+

### 10. Knox events triggered by SecretCodeIME launch

- **Finding:** Opening SecretCodeIME triggers KnoxTimeoutHandler and libpersona checks for UID 1000
- **Behavior:** `Fullscreen and mCurrent is not KNOX user. Hence hide keyguard`
- **Citation:** logcat 11:25:10.160–11:25:13.265, 12 KNOX_EVENT findings in 3s burst

---

## Assumptions (unverified, need confirmation)

### A1. NV writes are modem-initiated periodic journaling, not AT-triggered
- **Basis:** NV writes started ~2 min after AT+DEVCONINFO, use RFS protocol (CP→AP)
- **Verify:** Send AT+DEVCONINFO in isolation; wait 5 min; check for NV writes. Then wait 10 min without AT to check for independent NV writes.

### A2. Mali flag validation is the primary defense, not SMMU
- **Basis:** Driver rejected at flag stage; no SMMU/GPU/MMU fault in dmesg
- **Verify:** Enumerate all valid `kbase_mem_alloc` flag combos from kernel source. Test valid combos with GROW_ON_GPF in QEMU.

### A3. Binder transaction 291889 failure is caused by exploit activity
- **Basis:** Temporal correlation with 11:25 attack window
- **Verify:** Baseline failure rate from `/sys/kernel/debug/binder/transactions` during quiet period.

### A4. SecretCodeIME runs as UID 1000 (system)
- **Basis:** `com.sec.android.app.parser` is platform-signed; libpersona checked UID 1000
- **Verify:** Run `ps | grep parser` during SecretCodeIME launch.

### A5. TIMA write_ptr address may vary between check cycles
- **Basis:** Observed `0xC7405A80` vs STATUS.md's `0xC7403580`
- **Verify:** Collect write_ptr across 10+ consecutive TIMA cycles and compare.

---

## Infrastructure Built

### `src/logcat_security_monitor.py`
- 30 security detection rules (kernel, SELinux, privesc, binder, Samsung, BT, exploit tooling, memory, filesystem)
- Live stream (logcat main+system+events + dmesg 5s poll) and offline replay modes
- JSON findings output to `work/logs/security_findings.jsonl`
- Windows-compatible (UTF-8 stdout, CREATE_NEW_PROCESS_GROUP)
- Color-coded console, severity histograms, throughput metrics

### Helper Scripts
- `work/analyze_findings.py` — summarize findings by severity/rule
- `work/hot_findings.py` — tail recent CRITICAL/HIGH for quick triage

### Session Data
- 2,846 findings: 16 CRITICAL, 376 HIGH, 1211 MEDIUM, 1115 LOW, 128 INFO
- Top rules: SMARTCOM_ROOT(688), NETLINK_EVENT(616), WATCHDOG(499), TIMA_ALERT(219), KNOX_EVENT(151)

---

## Post-Session Implementation Results

### Mali TOCTOU Race — 91.2% Win Rate CONFIRMED

**Flag fix:** `0x20f` (GROW_ON_GPF without NEED_MMAP) passes `kbase_mem_alloc` validation. Driver has two guards: (1) flag validation at alloc rejects GROW_ON_GPF+NEED_MMAP/SAME_VA, (2) alias reference check at MEM_COMMIT denies shrink while alias exists.

**Race exploit:** `src/mali/mali_alias_race.c` — two threads race MEM_FREE(alias) vs MEM_COMMIT(shrink).

**Results (live device test, 2026-03-06):**
- **500 iterations, 456 wins = 91.2% win rate**
- MEM_COMMIT shrink (16→8 pages) passes while MEM_FREE(alias) in progress
- Physical pages 8-15 freed while alias GPU PTEs may still reference them
- Zero kernel crashes, zero dmesg warnings, device perfectly stable
- flags=0x20f, 16-page native, alias pages 8-15, shrink to 8

**Next steps:**
1. Verify GPU can read/write freed pages through stale alias PTEs
2. Reclaim freed pages with controlled content
3. Build kernel read/write primitive via GPU page table manipulation
4. Target: `selinux_enforcing` (0xC0B7AD18) or `addr_limit` (thread_info+8, KERNEL_DS=0x0)

### Monitor Pipeline Upgraded

- **37 rules** (was 30): added Mali GPU, DRParser/SecretCode, AT modem, NV write detection
- **Radio buffer** added to default stream (tested: `main+system+events+radio` is ALIVE)
- Verified: radio buffer does NOT cause the crash-buffer exit bug

### SysDump Full Exploitation (No OTP Required)

**Repeatable technique discovered** — no accessibility service needed:
1. Agent `secret_code` command launches SecretCodeIME (has permission)
2. `adb shell input keyevent 17 18 16 16 7 7 18` types `*#9900#` on calculator
3. SysDump opens WITHOUT OTP prompt (bypassed via DRParser internal dispatch)

**Successfully executed:**
- **Modem log dump** — "GET MODEM LOG SUCCESS"
- **TCP dump** — root pcap on all interfaces (confirmed button changed to STOP)
- **Kernel log copy to SD** — completed silently
- **Full COPY TO SDCARD** — 22 files: 2x dumpstate (16.5MB), 2x SELinux AVC logs, 2x radio, 4x BT HCI, IPC dumps, 92MB CP crash dump
- **Pulled to workstation:** dumpstate (16.5MB), avc_msg (224KB), radio log (612KB)

⚠️ **DEBUG LEVEL tap causes automatic reboot** — do not touch if already HIGH

### Secret Code Exploration

**46 secret codes** in ATT keystring list, all accessible via keyevent technique.

**Explored:**
- `*#0808#` → **USB Settings** opened (com.sec.usbsettings) — shows AP/CP toggle, DM+ACM+ADB (current), RNDIS options. Mode change requires reboot.
- `*#197328640#` → **Service Mode DEBUG SCREEN** (RilServiceModeApp) — 7 items: Basic Info, AS Info, NAS Info, Neighbour Cell, AMR, GPRS Info, Antenna. MORE menu has Key Input for hidden submenus.
- `#7465625*638*#` → **Network Lock** (Personalization) — NCK entry prompt. Validation is 100% modem-side (Shannon 308 HMAC). No brute-force counter visible from UI.
- Basic Info: `[Error] <RAT_NONE>`, `IMEI Status: OK` (no SIM)
- NAS Info: `MM_NULL`, `IMSI: DETACHED`, `Rej Type: REJECT_NONE`

**DRParser keystring injection BLOCKED:** AT&T stripped `*#873283#` (update code) from keystring list. `ParseService: Keystring not in the list`. SECRET_CODE broadcast requires `com.sec.factory.permission.KEYSTRING` (signature|privileged) — untrusted_app broadcasts silently dropped.

**Network lock (carrier unlock):** NCK validated entirely by modem firmware. All paths (AT+CLCK, RIL socket, Personalization UI) require valid NCK. No algorithm or keying material found.
