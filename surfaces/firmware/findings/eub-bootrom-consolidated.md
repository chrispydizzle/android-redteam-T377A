# EDL / EUB / BootROM Research — Consolidated Findings

> **Date:** 2026-02-28 — 2026-03-01
> **Device:** Samsung SM-T377A (Galaxy Tab E 8.0, AT&T)
> **SoC:** Exynos 3475 (ARMv7 Cortex-A7, codename "Island" / "universal3475")
> **Objective:** Evaluate hardware-level boot modes as carrier-lock bypass vectors

---

## Executive Summary

EDL (Emergency Download Mode) cables are **Qualcomm-only** and do not apply to the SM-T377A, which uses Samsung Exynos 3475. However, research uncovered **EUB (Exynos USB Boot)** — a BootROM-level fallback USB mode that operates **below all carrier lock enforcement**. This is the first identified path that could genuinely bypass the AT&T carrier lock.

**Key findings:**

| Finding | Impact | Risk | Status |
|---------|--------|------|--------|
| EDL cable inapplicable (Exynos, not Qualcomm) | N/A | N/A | ✅ Confirmed |
| EUB mode bypasses carrier lock (below sboot) | 🔴 CRITICAL | — | ✅ Confirmed architecturally |
| MUIC chip is SM5502 at I2C 0x25 | Enables UART research | — | ✅ Verified on device |
| `uart_en` sysfs exists but needs system/radio UID | Software UART blocked for shell | — | ✅ Verified on device |
| `*#0808#` USB settings needs KEYSTRING permission | Can't launch from ADB | — | ✅ Verified on device |
| Hardware JIG cable (619kΩ) enables UART | Boot log capture | Low | 🔲 Not yet tested |
| eMMC CLK test point triggers EUB | BootROM access | Medium | 🔲 Not yet tested |
| Bootloader corruption triggers EUB | BootROM access | VERY HIGH | 🔲 Not recommended yet |
| Early Exynos BootROMs potentially weaker | May have exploitable bugs | Unknown | 📋 Research finding |
| Combination firmware flashable on T377A | Engineering/debug mode | Low-Med | 📋 GSM-Forum confirmed |
| exynos-usbdl integer overflow | Unsigned code exec | N/A | ❌ Only 8890/8895 |

---

## Detailed Reports

This research is documented across two detailed reports:

| Report | Size | Contents |
|--------|------|----------|
| [**EDL Cable Research**](edl-cable-research.md) | 22KB | EDL fundamentals, why it doesn't apply, Exynos alternatives, EUB entry methods (4), Samsung JIG cable, ISP/JTAG, phased action plan |
| [**EUB Mode Deep Dive**](eub-mode-deep-dive.md) | 27KB | Boot chain architecture, BootROM protocol (dldata), hardware addresses, exynos-usbdl exploit details, MUIC chip analysis, device-verified sysfs state, combination firmware, SBOOT RE approach, comprehensive source index |

---

## Device-Verified State (2026-02-28)

All values confirmed via `adb shell` on the physical device:

### MUIC (Micro-USB Interface Controller)
```
Driver:       muic-universal
I2C address:  0x25 on bus 0 (13870000.hsi2c)
Sysfs:        /sys/class/sec/switch/

uart_en:      0 (disabled)
uart_sel:     AP
usb_sel:      PDA
attached_dev: USB
usb_state:    USB_STATE_CONFIGURED
adc:          0x1f (no accessory resistor detected)

Register dump: CT:1e IM1:dc IM2:0 MS1:25 MS2:0 ADC:1f DT1:4 DT2:0 DT3:0 RS1:3

Permissions:  uart_en, uart_sel, usb_sel = system:radio (rw-rw-r--)
              Shell (UID 2000) can READ but NOT WRITE
```

### USB Gadget
```
Config:     rndis,acm,dm,adb
State:      CONFIGURED
Functions:  rndis,acm,dm,adb (plus: mtp,ptp,midi,mass_storage,ncm available)
Global:     usb_config=rndis,acm,dm,adb  usb_mass_storage_enabled=1
```

### USB Settings Package
```
Package:    com.sec.usbsettings
Receiver:   UltraKeyStringBroadcastReceiver (android_secret_code scheme)
Permission: com.sec.modem.settings.permission.KEYSTRING (signature|privileged)
Status:     Cannot launch from ADB shell — requires dialer or privileged caller
```

---

## Exynos 3475 Hardware Map

| Component | Address | Notes |
|-----------|---------|-------|
| DWC2 USB Controller | `0x13500000` | Synopsys DesignWare USB 2.0 |
| eMMC Controller (DWMMC) | `0x15570000` | Samsung Exynos DWMMC |
| MUIC (SM5502) | I2C `0x25` on `13870000.hsi2c` | Silicon Mitus, extcon-sm5502 driver |
| BootROM (IROM) | `0x00000000` | Estimated 16-64KB, immutable |

Boot priority (e-fuse configured): **eMMC → USB (EUB) → SD → UART/SPI**

---

## Boot Chain & Carrier Lock Architecture

```
┌─────────────────────────────────────────────────────────┐
│  BootROM (IROM) — immutable, in-SoC                     │ ← EUB operates HERE
│  Loads BL1 from eMMC, falls back to USB if eMMC fails   │    (below carrier lock)
├─────────────────────────────────────────────────────────┤
│  BL1 / fwbl1 — first bootloader                         │
├─────────────────────────────────────────────────────────┤
│  BL2 — secondary bootloader, DRAM init                   │
├─────────────────────────────────────────────────────────┤
│  SBOOT — Samsung Secure Bootloader                       │ ← Carrier lock HERE
│  Contains: TrustZone OS, Knox, signature enforcement,    │    (AT&T restrictions)
│  carrier lock checks, boot image verification            │
├─────────────────────────────────────────────────────────┤
│  Android Kernel → Android OS                             │
└─────────────────────────────────────────────────────────┘
```

---

## EUB Entry Methods (Ranked)

| # | Method | Risk | Hardware Mod? | Status |
|---|--------|------|--------------|--------|
| 1 | **eMMC CLK test point short** | Medium | Yes (disassembly) | Need schematics |
| 2 | **Bootloader corruption via Odin** (cm.bin→sboot.bin swap) | VERY HIGH | No | Need ChimeraTool for recovery |
| 3 | **ChimeraTool "Switch to EUB"** | N/A | No | ❌ Not supported for Exynos 3475 |
| 4 | **Z3X SamsTool EUB** | N/A | No | ❌ Not supported for Exynos 3475 |

---

## Recommended Action Plan

### Phase 0 — Zero Risk (NOW)
- [x] Verify MUIC state via ADB ✅
- [x] Identify MUIC chip and sysfs paths ✅
- [x] Test `*#0808#` broadcast ✅ (blocked by permission)
- [ ] Try `*#0808#` from physical dialer on device screen
- [ ] Download T377AUCU2AQGF firmware from SamFrew → extract sboot.bin
- [ ] Analyze sboot.bin with binwalk + Ghidra
- [ ] Run `heimdall print-pit` in Download Mode to map partitions

### Phase 1 — Low Risk (Hardware, Non-Destructive)
- [ ] Build 619kΩ JIG UART cable (⚠ needs 1.8V UART adapter!)
- [ ] Capture boot logs via UART serial console
- [ ] Obtain SM-T377A schematics (RepairLap/Vinafix/Phonelumi)

### Phase 2 — Medium Risk (Disassembly)
- [ ] Disassemble tablet, photograph motherboard
- [ ] Locate eMMC chip and CLK test point
- [ ] Attempt EUB entry via CLK ground short
- [ ] If EUB detected, probe with USB sniffer / adapted exynos-usbdl

### Phase 3 — High Risk (Last Resort)
- [ ] Flash combination firmware via Odin (if carrier lock allows AP slot)
- [ ] Use bootloader corruption method + ChimeraTool boot repair

---

## Key Sources

| Topic | Source |
|-------|--------|
| Exynos BootROM USB stack RE | [fredericb.info](https://fredericb.info/2020/06/reverse-engineer-usb-stack-of-exynos-bootrom.html) |
| exynos-usbdl exploit | [GitHub](https://github.com/frederic/exynos-usbdl) |
| SBOOT reverse engineering | [Quarkslab Part I](https://blog.quarkslab.com/reverse-engineering-samsung-s6-sboot-part-i.html), [Part II](https://blog.quarkslab.com/reverse-engineering-samsung-s6-sboot-part-ii.html) |
| EUB mode entry | [ChimeraTool docs](https://chimeratool.com/en/docs/eub-mode), [GSM-Forum TP collection](https://forum.gsmhosting.com/vbb/f898/exynos-tp-collection-eub-mode-3147039/) |
| Software EUB (no disassembly) | [GSM-Forum method](https://forum.gsmhosting.com/vbb/f898/entering-exynos-port-mode-without-opening-phone-3234157/) |
| Samsung Download Mode protocol | [Heimdall source](https://github.com/Benjamin-Dobell/Heimdall) |
| SM5502 MUIC driver | [Linux mainline](https://github.com/torvalds/linux/blob/master/Documentation/devicetree/bindings/extcon/siliconmitus,sm5502-muic.yaml) |
| JIG UART cable | [grimler.se](https://grimler.se/posts/exynos-uart/), [postmarketOS wiki](https://wiki.postmarketos.org/wiki/Serial_debugging) |
| T377A schematics | [RepairLap](https://www.repairlap.com/threads/samsung-galaxy-tab-e-8-0-sm-t377a-service-manual.4218/), [Phonelumi](https://phonelumi.com/samsung-galaxy-tab-e-8-0-sm-t377-schematics/) |
| T377A ISP pinout | [HalabTech](https://support.halabtech.com/index.php?a=downloads&b=file&id=650466) |
| T377A firmware | [SamFrew](https://samfrew.com/firmware/model/SM-T377A/upload/Desc/0/10) |
| Combination firmware | [HalabTech](https://support.halabtech.com/index.php?a=downloads&b=folder&id=12418), [GSM-Forum](https://forum.gsmhosting.com/vbb/f453/sm-t377a-bit-3-plus-modem-combination-done-3000373/) |
| Kernel source | [Exynos3475 GitHub](https://github.com/Exynos3475/android_kernel_samsung_exynos3475) |
