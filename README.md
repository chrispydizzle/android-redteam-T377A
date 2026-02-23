# Samsung SM-T377A Security Research

Security audit, CTF root path enumeration, and kernel fuzzing lab for a
Samsung Galaxy Tab A (SM-T377A) running Android 6.0.1 / Kernel 3.10.9.

**Audit Date:** 2026-02-18  
**Device:** Samsung SM-T377A (Galaxy Tab A) · AT&T · Exynos 3475  
**Android:** 6.0.1 (MMB29K.T377AUCU2AQGF) · SPL 2017-07-01  
**Kernel:** Linux 3.10.9-11788437 · ARMv7 Cortex-A7  
**Overall Risk:** 🔴 CRITICAL (unpatched since July 2017)

---

## Quick Summary

- **Local root exploits:** All 20+ paths tested — **blocked** (SELinux, PIE enforcement, nosuid, Knox)
- **Remote root (wireless):** **CRITICAL** — BlueBorne & KRACK unpatched
- **Kernel attack surface:** 5 world-writable `/dev` nodes openable from shell, **no KASLR, no stack canaries, no RKP**
- **SmartcomRoot:** System-UID binder service fully reverse-engineered (15 methods) — no root path
- **QEMU fuzzing lab:** ARM VM with Linux 3.10.108 + binder + ashmem + Mali stub driver

---

## Documentation

### Security Audit

| Document | Description |
|----------|-------------|
| [**Device Audit**](docs/01-device-audit.md) | Full device audit: hardware, network, apps, permissions, services, security config, positive findings |
| [**Hardening Recommendations**](docs/02-hardening-recommendations.md) | Prioritized remediation steps (P1 Critical → P4 Maintenance) |
| [**CVE & APK Analysis**](docs/03-cve-and-apk-analysis.md) | CVE exposure mapping, APK static analysis (Androguard), security gap assessment |

### Exploitation Research

| Document | Description |
|----------|-------------|
| [**CTF Root Enumeration**](docs/04-ctf-root-enumeration.md) | All privilege escalation paths tested, kernel device node deep-dive, mitigation assessment, info leak chain, SmartcomRoot AIDL, CTF verdict |
| [**Exploit Failure Analysis**](docs/05-exploit-failure-analysis.md) | Why legacy exploits (Dirty COW, psneuter, zergRush) fail — 5 defense layers, kernel build date analysis |

### QEMU Kernel Fuzzing Lab

| Document | Description |
|----------|-------------|
| [**Fuzzing Lab Overview**](qemu/QEMU_FUZZING_LAB.md) | Quick start, VM details, workflow guide |
| [**Building the QEMU Image**](qemu/BUILDING_THE_QEMU_IMAGE.md) | Step-by-step build: kernel 3.10.108, Linaro GCC 4.9.4, busybox rootfs, troubleshooting |
| [**Getting Mali into QEMU**](qemu/GETTING_MALI_INTO_QEMU.md) | 4 approaches tried, Samsung GPL source analysis, stub driver design |

---

## Directory Structure

```
android-redteam/
├── README.md                    ← You are here
├── device_forensics_data.txt    Raw device forensics (kernel, build, hardware)
│
├── docs/                        Security audit & analysis documents
│   ├── 01-device-audit.md           Device info, network, apps, permissions, services
│   ├── 02-hardening-recommendations.md  Prioritized remediation steps
│   ├── 03-cve-and-apk-analysis.md   CVE exposure, APK analysis, gap assessment
│   ├── 04-ctf-root-enumeration.md   All root paths tested, kernel deep-dive, verdict
│   └── 05-exploit-failure-analysis.md   Why legacy exploits fail (consolidated)
│
├── qemu/                        QEMU ARM kernel fuzzing lab
│   ├── QEMU_FUZZING_LAB.md         Quick start & overview
│   ├── BUILDING_THE_QEMU_IMAGE.md   Full build walkthrough
│   ├── GETTING_MALI_INTO_QEMU.md    Mali stub driver story
│   ├── mali_stub.c                  Mali r7p0 stub kernel module
│   ├── build_mali_stub.sh           Build & inject mali_stub.ko
│   ├── run-qemu.bat                 Launch QEMU VM
│   ├── rebuild-kernel.bat           Rebuild kernel (menuconfig)
│   ├── push-to-qemu.bat            Compile C → inject into rootfs
│   └── build-arm.bat               Cross-compile for physical device (ADB)
│
├── src/                         C source & binaries for the VM
│   ├── ioctl_enum.c                Binder + ashmem + Mali ioctl enumerator
│   ├── probe-devnodes.c            /dev node probe tool
│   ├── ioctlfuzz.c                 Simple ioctl fuzzer
│   └── hello.c                     ARM test program
│
└── findings/                    Raw audit data & pulled APKs
    ├── device-info.txt              Device properties
    ├── network-audit.txt            Network interfaces, ports, connections
    ├── app-audit.txt                Package listings, permissions
    ├── permissions-audit.txt        File permissions, mount options
    ├── services-audit.txt           Running processes, init services
    ├── config-audit.txt             Security configuration settings
    ├── apk-analysis.txt             Androguard APK analysis output
    ├── ioctl_fuzz.log               Ioctl fuzzing output log
    ├── apks/                        Pulled APK files (Hijacker, Magisk, cSploit, etc.)
    └── smartcomroot/                SmartcomRoot APK, ODEX, extracted assets
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| ADB | Device interrogation and data collection |
| [Androguard](https://github.com/androguard/androguard) 4.1.3 | APK static analysis |
| `oatdump` (on-device) | ODEX decompilation for SmartcomRoot reverse engineering |
| `service call` (on-device) | Binder IPC transaction testing |
| QEMU 6.2.0 | ARM kernel fuzzing VM |
| Linaro GCC 4.9.4 | Cross-compiler for kernel 3.10 |
| Samsung GPL kernel source | Mali r7p0 driver ioctl interface extraction |
