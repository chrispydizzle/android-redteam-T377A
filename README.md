# Samsung SM-T377A / Galaxy Tab E 8.0 Research Repo

Privilege-escalation, kernel-surface, Bluetooth, and firmware research for the
**Samsung SM-T377A / Galaxy Tab E 8.0 (AT&T)** running **Android 6.0.1** on
**kernel 3.10.9** / **Exynos 3475**.

**As of:** 2026-03-08  
**Primary goal:** achieve **root** from either **ADB shell** (`uid=2000`) or an
**installed APK/app context**  
**Source of truth:** [`STATUS.md`](STATUS.md)  
**Chronological log:** [`PROGRESS-LOG.md`](PROGRESS-LOG.md)

> If this README and `STATUS.md` ever disagree, trust `STATUS.md`.

---

## Quick Summary

- **Binder lane:** effectively **exhausted** after typed follow-up on `gatekeeper`,
  `keystore`, `persona`, `enterprise_policy`, and `SatsService`
- **Bluetooth lane:** still one of the best remaining vectors, but **not** via the
  old kernel BlueBorne L2CAP path
- **Bluetooth RE result:** `bluetooth.default.so` BNEP parsing is hardened enough to
  block the classic malformed BlueBorne payload families
- **Live PAN result:** hidden `BluetoothPan` control now works from the installed
  agent; the tablet can reach **PAN state 2** against a host NAP
- **Live host-socket result:** a repo-local **custom BlueZ `Profile1` NAP handler**
  now owns the inbound BNEP socket and can capture / answer the tablet's setup
  request
- **Accepted-socket result:** the remaining valid-frame probes were adapted, and the
  current **PANU -> host NAP** direction rejects host-originated `SETUP_CONN_REQ`
  traffic as `CONN_NOT_ALLOWED` / `setup request when we are originator`
- **Mali lane:** recent high-signal hypotheses tested **negative**:
  - imported-JC post-submit rewrite path
  - alias controlled-reclaim stale native-tail / stale alias writes
- **New Mali result:** when the alias race wins and the stale alias VA is pinned
   back down with `commit=0`, the **first disjoint 8-page allocation** immediately
   reclaims **all 8** freed source pages
- **Newest Mali result:** `src\mali\mali_alias_chain_consumer_probe.c`
  confirms a **non-direct chain consumer**: a separately submitted head
  descriptor can follow its `next` pointer into a preserved seeded victim page
- **Cross-pool result:** `src\mali\mali_alias_ion_cross_pool_probe.c` shows
  Mali and ION system-heap use **disjoint physical page pools** — seeded
  Mali pages never appear in ION allocs (0/240 sentinel hits over 17 race wins)
- **Best remaining vectors:** DM/HDLC binary protocol to diagexe,
  accessibility automation, timerfd, cross-process Mali reclaim (untested)

---

## Current Research Snapshot

### Completed / well-mapped

- Broad recon, service mapping, firmware collection, and kernel-surface auditing
- Typed binder follow-up confirming binder is now low-value for privesc
- Bluetooth userspace BNEP reversing focused on valid-frame logic instead of old
  malformed-packet replay
- Live PAN bring-up from the device-owner APK using hidden `BluetoothPan`
- Custom BlueZ `Profile1` NAP ownership proving the host can receive
  `NewConnection(fd)`, reply to setup, and observe live BNEP traffic
- Accepted-socket live experiments showing PANU -> NAP rejects host-originated
  setup replay with `CONN_NOT_ALLOWED` / originator-side rejection
- Mali validation that removed two previously attractive but now-invalidated stories
- Mali reuse-timing confirmation that immediate, disjoint reclaim is possible once
  the alias race wins
- Mali same-context controlled-injection confirmation that a seeded reclaimed page
  can survive free/realloc and later execute as a GPU-consumed JC page
- Mali indirect chain-consumer confirmation that a preserved seeded victim page
  can execute as a later descriptor without direct JC resubmission
- Mali × ION cross-pool test confirming that Mali and ION system-heap use
  **disjoint** physical page pools — freed Mali pages do not appear in fresh
  ION system-heap allocations (0/240 sentinel hits across 17 race wins)

### Closed or deprioritized

| Area | Status | Why |
| --- | --- | --- |
| Binder privesc follow-up | Closed for now | Typed follow-up produced no viable escalation path |
| Kernel BlueBorne L2CAP route | Closed | Android 6.0.1 keeps L2CAP in Bluedroid userspace here |
| Old malformed BlueBorne BNEP payloads | Closed | `bluetooth.default.so` validates the old payload families away |
| Mali imported-JC post-submit rewrite | Negative | Live tests did not preserve the expected steering window |
| Mali stale alias / stale native-tail writes | Negative | Signal disappeared after overlap confounds were removed |

### What still looks promising

| Area | Why it still matters |
| --- | --- |
| **Mali imported/retained consumer follow-up** | **CLOSED — disjoint pools.** ION system-heap does not share pages with Mali; 0/240 sentinel hits. Cross-process Mali reclaim (untested) remains as a possibility. |
| **Alternate-role Bluetooth coverage** | Socket ownership is solved, but PANU -> NAP rejects host setup replay; another role/path would be needed |
| **DM / HDLC binary protocol** | **Best remaining vector** — diagexe UID 1000 + SYS_ADMIN, completely unexplored HDLC binary protocol, AT surface only partially mapped |
| **Accessibility UI automation** | Already working and still useful as an enabler lane |
| **timerfd / diagexe DM protocol** | Still listed among the best remaining vectors |

### Immediate next steps

1. **Mali cross-process reclaim (optional):** explore whether seeded pages freed
   from our Mali context appear in a different process's Mali allocation (system
   service actively using GPU). If yes, this re-opens the retained-consumer lane.
2. **DM/HDLC main line:** HDLC binary protocol to diagexe is the single most
   attractive unexplored vector — UID 1000 + SYS_ADMIN, no SELinux block, binary
   protocol completely untouched. Send structured HDLC frames over the DM COM port
   and observe diagexe's response.
3. **Parallel fallback:** accessibility automation continues as a low-risk enabler
   stalls or proves too narrow to reach a surviving reference

### Important Bluetooth correction

Earlier README-era summaries that treated BlueBorne as a straightforward remote
kernel path are now **outdated for this device**. The live Bluetooth target is the
userspace stack in `bluetooth.default.so`, and the practical research focus is now
valid-frame BNEP logic/state behavior.

---

## Documentation

Many documents below are **phase-specific or historical**. Use them for depth and
artifact recovery, but use [`STATUS.md`](STATUS.md) for the current conclusion of
each lane.

### 📋 Final Report

| Document | Description |
| ---------- | ------------- |
| [**Final Security Assessment**](findings/recon/final-security-report.md) | Consolidated report: 4 critical + 12 high + 8 medium findings, 368K+ fuzz ops, 27 recommendations |

### Security Audit

| Document | Description |
| ---------- | ------------- |
| [**Device Audit**](docs/01-device-audit.md) | Full device audit: hardware, network, apps, permissions, services, security config, positive findings |
| [**Hardening Recommendations**](docs/02-hardening-recommendations.md) | Prioritized remediation steps (P1 Critical → P4 Maintenance) |
| [**CVE & APK Analysis**](docs/03-cve-and-apk-analysis.md) | CVE exposure mapping, APK static analysis (Androguard), security gap assessment |

### Exploitation Research

| Document | Description |
| ---------- | ------------- |
| [**CTF Root Enumeration**](docs/04-ctf-root-enumeration.md) | All privilege escalation paths tested, kernel device node deep-dive, mitigation assessment, info leak chain, SmartcomRoot AIDL, CTF verdict |
| [**Exploit Failure Analysis**](docs/05-exploit-failure-analysis.md) | Why legacy exploits (Dirty COW, psneuter, zergRush) fail — 5 defense layers, kernel build date analysis |

### Hardware / BootROM Research

| Document | Description |
| ---------- | ------------- |
| [**EUB/BootROM Consolidated Findings**](findings/firmware/eub-bootrom-consolidated.md) | Master summary: EDL inapplicability, EUB mode as carrier-lock bypass vector, MUIC chip (SM5502) verified state, boot chain architecture, 4 EUB entry methods, action plan |
| [**EDL Cable Research**](findings/firmware/edl-cable-research.md) | Deep dive: EDL fundamentals, Exynos alternatives (EUB, ISP/JTAG, JIG UART), Samsung JIG cable construction, firmware sources |
| [**EUB Mode Deep Dive**](findings/firmware/eub-mode-deep-dive.md) | Technical deep dive: Exynos 3475 hardware addresses, BootROM USB protocol (dldata), exynos-usbdl integer overflow, SBOOT RE approach, MUIC sysfs, combination firmware |

### QEMU Kernel Fuzzing Lab

| Document | Description |
| ---------- | ------------- |
| [**Fuzzing Lab Overview**](qemu/QEMU_FUZZING_LAB.md) | Quick start, VM details, workflow guide |
| [**Building the QEMU Image**](qemu/BUILDING_THE_QEMU_IMAGE.md) | Step-by-step build: kernel 3.10.108, Linaro GCC 4.9.4, busybox rootfs, troubleshooting |
| [**Getting Mali into QEMU**](qemu/GETTING_MALI_INTO_QEMU.md) | 4 approaches tried, Samsung GPL source analysis, stub driver design |
| [**Mali Fuzzing Results**](findings/mali/mali-fuzzing-results.md) | Full-coverage fuzzer results: 29K ops, 24 func IDs, UAF/double-free testing |
| [**ION Fuzzing Results**](findings/ion/ion-fuzzing-results.md) | ION allocator fuzzer: heap crash DoS, 57K+ ops, UAF testing, hardening recs |
| [**Binder & Ashmem Results**](findings/binder/binder-ashmem-fuzzing-results.md) | Binder + ashmem fuzzing: 110K+ ops, binder DoS root-caused, ashmem robust |
| [**Info Disclosure & Attack Surface**](findings/recon/info-disclosure-attack-surface.md) | Procfs/debugfs leaks, binder service access, network, SELinux, risk matrix |
| [**Service & AM/PM Analysis**](findings/binder/service-am-pm-analysis.md) | 164 binder services, pm grant/create-user, WiFi intel, AM capabilities |

---

## Directory Structure

```log
android-redteam/
├── README.md                    ← You are here
├── STATUS.md                    Consolidated current assessment state
├── PROGRESS-LOG.md              Detailed chronological research log
├── docs/                        Analysis docs + operator notes
│   ├── 01-device-audit.md
│   ├── 02-hardening-recommendations.md
│   ├── 03-cve-and-apk-analysis.md
│   ├── 04-ctf-root-enumeration.md
│   ├── 05-exploit-failure-analysis.md
│   ├── dashboards/              Interactive HTML visualizations
│   ├── handoff/                 Session-to-session context handoff
│   └── service-mode/            Service mode app analysis
├── src/                         Source code organized by attack surface
│   ├── binder/                  Binder IPC exploits, UAF, fuzzing (23 files)
│   ├── bluetooth/               BlueBorne, BNEP, L2CAP exploits (26 files)
│   ├── exploit-primitives/      Heap spray, slab reclaim, BPF (28 files)
│   ├── firmware-analysis/       Kernel/firmware analysis scripts (21 files)
│   ├── fuzzing/                 Generic kernel fuzzers (30 files)
│   ├── ion/                     ION heap exploits and UAF (21 files)
│   ├── kernel-cve/              CVE-specific exploits: towelroot, dirtycow, etc. (48 files)
│   ├── mali/                    Mali GPU driver exploits and fuzzing (50 files)
│   ├── modem-at/                AT command and DM port probes (12 files)
│   ├── recon/                   Device probes, enumeration, analysis (35 files)
│   └── selinux/                 SELinux policy analysis tools (18 files)
├── findings/                    Consolidated reports by topic
│   ├── binder/                  Binder/service fuzzing results
│   ├── bluetooth/               BlueBorne protocol RE and audit
│   ├── firmware/                Bootloader, EDL, EUB, kernel audit
│   ├── ion/                     ION heap exploitation research
│   ├── kernel/                  Input fuzzing, ioctl results
│   ├── mali/                    Mali driver fuzzing and vulns
│   ├── otp/                     OTP/diagexe string analysis
│   ├── recon/                   Recon sessions, audits, final reports
│   └── service-mode/            DRParser, SysDump, OTP bypass
├── device-data/                 Device filesystem and firmware
│   ├── extracted/               Pulled data: sboot, PIT, param, sysdump
│   ├── firmware-images/         Full firmware tars, boot.img, ramdisk
│   ├── priv-app/                Privileged APKs pulled from /system/priv-app
│   ├── system/                  System partition config (SW_Configuration, VODB)
│   └── system-libs/             Shared libraries from /system/lib
├── compiled/                    Pre-built ARM binaries for device
├── apk/                         Probe APK build project
├── qemu/                        QEMU ARM kernel fuzzing lab
├── exynos_src/                  Samsung GPL kernel source repos
├── work/                        Operational workspace
│   ├── privesc_apk/             PrivEsc agent APK (device owner)
│   ├── firmware/                Kernel images, vmlinux, SELinux policy
│   ├── decompile/               Decompiled APK/ODEX sources
│   ├── drparser/                DRParser reverse engineering
│   ├── recon/                   Raw device recon dumps
│   └── ...                      (smartcomroot, sysdump, logs, tools, etc.)
└── archive/                     Temp files, old logs, misc artifacts
```

### Layout Note (Why this organization)

- Root level is clean: just entry points (`README.md`, `STATUS.md`, `PROGRESS-LOG.md`) plus major working directories.
- `src/` is organized by **attack surface** (binder, mali, ion, bluetooth, kernel-cve, fuzzing, recon, etc.) for quick navigation of 300+ source files.
- `findings/` is organized by **topic** so related reports are grouped together.
- `device-data/` consolidates all device filesystem pulls and firmware images under one umbrella.
- `archive/` holds temp files, old logs, and misc artifacts that aren't actively needed.
- `work/`, `qemu/`, `apk/`, `exynos_src/` are self-contained workspaces left as-is.

---

## Tools Used

| Tool | Purpose |
| ------ | --------- |
| ADB | Device interrogation and data collection |
| [Androguard](https://github.com/androguard/androguard) 4.1.3 | APK static analysis |
| `oatdump` (on-device) | ODEX decompilation for SmartcomRoot reverse engineering |
| `service call` (on-device) | Binder IPC transaction testing |
| QEMU 6.2.0 | ARM kernel fuzzing VM |
| Linaro GCC 4.9.4 | Cross-compiler for kernel 3.10 |
| Samsung GPL kernel source | Mali r7p0 driver ioctl interface extraction |
