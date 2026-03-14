# EDL Cable Research — Samsung SM-T377A (Exynos 3475)

> **Date:** 2026-02-28
> **Device:** Samsung SM-T377A (Galaxy Tab E 8.0, AT&T)
> **SoC:** Exynos 3475 (ARMv7 Cortex-A7)
> **Conclusion:** EDL cables are NOT applicable. Alternative low-level paths explored below.

---

## 1. Executive Summary

**EDL (Emergency Download Mode) is a Qualcomm-specific feature.** The SM-T377A uses a Samsung Exynos 3475 SoC, which does not support Qualcomm's EDL/9008 protocol. An EDL cable will have zero effect on this device.

However, this research uncovered several important findings:

1. **Widespread SoC misidentification** — Many spec databases incorrectly list the SM-T377A as Snapdragon 410 (MSM8916). Only the T377A (AT&T) variant uses Exynos 3475; other T377 variants (T377P, T377R, T377W) genuinely use MSM8916.
2. **Samsung has its own low-level boot mechanisms** — EUB (Exynos USB Boot) mode and ISP/JTAG test points exist for Exynos devices.
3. **Exynos BootROM exploits exist** — `exynos-usbdl` exploits a USB stack integer overflow in Exynos BootROM, but only for Exynos 8890/8895, NOT Exynos 3475.
4. **The device has ISP/eMMC test points** — HalabTech has documented SM-T377A ISP pinouts for direct eMMC access.

---

## 2. What is an EDL Cable?

### 2.1 Purpose
A "deep flash" or EDL cable forces Qualcomm-based devices into Emergency Download Mode (9008). In this mode, the device communicates via Qualcomm's Sahara/Firehose protocol, allowing low-level firmware flashing that bypasses the normal bootloader entirely.

### 2.2 How It Works
- A modified USB cable with a momentary switch that **shorts USB D+ to GND**
- When plugged into a powered-off Qualcomm device with the short active, the Primary Bootloader (PBL) detects the electrical condition and enters EDL mode
- The device appears as `Qualcomm HS-USB QDLoader 9008` in Device Manager
- Tools like QFIL, QPST, or bkerler/edl can then communicate with the device

### 2.3 Pinout
```
USB Pin 1 (VBUS/Red)   → +5V Power
USB Pin 2 (D-/White)   → Data minus
USB Pin 3 (D+/Green)   → Data plus  ← SHORTED TO GND
USB Pin 4 (GND/Black)  → Ground
```
The short is held for 2-3 seconds during cable insertion, then released.

### 2.4 Security Implications (Qualcomm Devices)
Aleph Security's 2017/2018 research demonstrated critical vulnerabilities:
- **Leaked Firehose programmers** with `peek`/`poke` commands allow arbitrary memory read/write
- **Secure Boot bypass** demonstrated on Nokia 6 (Snapdragon 425) — full boot chain compromise
- **No anti-rollback** on many 2017-era devices allowed downgrade attacks
- Affected devices: Xiaomi, OnePlus, Nokia, Nexus 6/6P, and Samsung Qualcomm variants

**Key tools:**
- [bkerler/edl](https://github.com/bkerler/edl) — Open-source Firehose/Sahara/Streaming tool
- [AlephGSM/SAMSUNG-EDL-Loaders](https://github.com/Alephgsm/SAMSUNG-EDL-Loaders) — Samsung Qualcomm EDL loaders
- [alephsecurity/firehorse](https://github.com/alephsecurity/firehorse) — Exploitation framework

---

## 3. Why EDL Does NOT Apply to the SM-T377A

### 3.1 SoC Confirmation
| Variant | SoC | EDL Applicable? |
|---------|-----|-----------------|
| **SM-T377A (AT&T)** | **Exynos 3475** | **❌ NO** |
| SM-T377P (Sprint) | Snapdragon 410 (MSM8916) | ✅ Yes |
| SM-T377R (US Cellular) | Snapdragon 410 (MSM8916) | ✅ Yes |
| SM-T377W (Canadian) | Snapdragon 410 (MSM8916) | ✅ Yes |

Our device is confirmed Exynos 3475 via:
- Kernel source: `android_kernel_samsung_exynos3475`
- Kernel version: 3.10.9 (typical for Exynos 3475; MSM8916 uses 3.10.49)
- ARM Cortex-A7 (MSM8916 uses Cortex-A53)
- Mali-T720 GPU (MSM8916 uses Adreno 306)
- Shannon 308 modem (MSM8916 uses integrated Qualcomm modem)

### 3.2 What `adb reboot edl` Does on Exynos
- **Nothing useful.** The command either reboots normally or is ignored entirely.
- Samsung Exynos equivalent: `adb reboot download` (enters Odin/Download Mode)

---

## 4. Samsung Exynos Low-Level Boot Alternatives

### 4.1 Samsung Download Mode (Odin Mode)
The standard Samsung flashing interface.

**Entry methods:**
- Button combo: Vol Down + Home + Power (then Vol Up to confirm)
- ADB: `adb reboot download`
- AT command: `AT$ARMEE=1` (⚠ DANGEROUS — enters download mode, DO NOT USE)

**Limitations for our purposes:**
- Only accepts Samsung-signed firmware
- AT&T carrier lock in bootloader rejects all unsigned images
- Odin flash was previously attempted and **FAILED** (documented in STATUS.md)
- Cannot flash custom recovery, custom kernel, or unsigned bootloader
- "OEM Unlock" toggle is cosmetic — carrier lock overrides it

### 4.2 EUB Mode (Exynos USB Boot)
Samsung's Exynos equivalent to Qualcomm's EDL — a BootROM-level USB recovery mode.

**How to enter:**
- Triggered when primary boot from eMMC fails
- Can be forced via **test points** on the motherboard (shorting specific pads)
- May also trigger if bootloader is deliberately corrupted
- Device appears as a USB device to the host (not Qualcomm 9008)

**Tools that support EUB:**
- **Chimera Tool** — Commercial repair tool with Exynos EUB boot repair capability
- **Passware Kit Mobile** — Forensic tool with Samsung Exynos test point gallery

**Status for SM-T377A:** Unknown if EUB is directly useful — entering it requires either hardware intervention (test points) or deliberate boot corruption, both of which are **RISKY** on our only physical device.

### 4.3 exynos-usbdl (Exynos BootROM Exploit)
An exploit for an integer overflow in the Exynos BootROM USB stack that allows unsigned code execution.

**Supported SoCs:**
- ✅ Exynos 8890
- ✅ Exynos 8895
- ❌ **Exynos 3475 — NOT SUPPORTED**

**How it works:**
1. Device must be in USB Download/BootROM mode (requires eMMC boot failure)
2. Sends oversized payload that triggers integer overflow in USB stack
3. Overwrites memory to redirect execution to attacker code
4. Executes unsigned payload in Secure World

**Relevance:** The bug is specific to Exynos 8890/8895 BootROMs. Whether a similar bug exists in Exynos 3475's BootROM is **unknown** — it would require independent reverse engineering of the 3475's BootROM code, which is not publicly available.

- GitHub: [frederic/exynos-usbdl](https://github.com/frederic/exynos-usbdl)
- Writeup: [fredericb.info](https://fredericb.info/2020/06/exynos-usbdl-unsigned-code-loader-for-exynos-bootrom.html)

### 4.4 ISP/JTAG Direct eMMC Access
The nuclear option — physically connecting to the eMMC chip's data lines.

**SM-T377A ISP Pinout:**
- Available from HalabTech: [T377A iSP Pinout](https://support.halabtech.com/index.php?a=downloads&b=file&id=650466) (may require paid access)
- Standard eMMC ISP pins: CLK, CMD, DATA0, VCC, VCCQ, GND

**Required hardware:**
- Easy JTAG Plus, UFI Box, or similar eMMC programmer (~$80-300)
- Soldering iron + fine-gauge wires
- Device disassembly tools

**What ISP can do:**
- Read/write ANY partition on the eMMC directly (bypasses all software security)
- Dump and modify boot partitions, kernel, system image
- Bypass carrier lock by modifying NV data
- Bypass FRP (Factory Reset Protection)
- Full forensic image extraction

**Risks:**
- Requires physical disassembly of the ONLY device we have
- Incorrect wiring can damage the eMMC or SoC
- A failed write can permanently brick the device beyond repair

### 4.5 Samsung JIG Cable
An older Samsung-specific concept (not EDL).

**How it works:**
- Micro-USB plug with a specific resistor value between USB ID and GND pins
- Samsung devices read the resistance to detect service accessories
- Different resistance values trigger different modes (UART debug, download mode, etc.)

**Known resistance values (older Samsung devices):**
| Resistance | Mode |
|-----------|------|
| 301kΩ | Download Mode |
| 150kΩ | UART (serial debug) |
| 619kΩ | Factory test |
| 523kΩ | USB boot |

**Status for SM-T377A:** JIG cable support varies by model and firmware. Newer Samsung devices have largely disabled JIG detection. Whether the SM-T377A responds to JIG resistance values is **untested**.

---

## 5. Relevance to Privilege Escalation Research

### 5.1 Direct Relevance: LOW
EDL and its equivalents are primarily hardware-level recovery/flashing tools. They don't provide a software-only privilege escalation path. Our current research goal is achieving root from ADB shell (UID 2000) without hardware modification.

### 5.2 Potential Indirect Value

| Approach | Value | Risk | Requires Hardware Mod? |
|----------|-------|------|----------------------|
| ISP eMMC dump | Could extract full filesystem + kernel for deeper analysis | High (device damage) | Yes |
| ISP boot partition mod | Could inject rooted kernel/boot image | Very high | Yes |
| EUB + BootROM RE | Could find Exynos 3475 BootROM bugs | Unknown | Yes (to enter EUB) |
| JIG UART | Could provide serial debug console | Low | Yes (JIG cable) |
| Samsung Download Mode | Already confirmed blocked by carrier lock | None | No |

### 5.3 Recommendation
**Do not pursue EDL/EUB/ISP paths** unless all software-only kernel exploitation vectors are exhausted. The current priority vectors per STATUS.md remain:
1. **BlueBorne (CVE-2017-0781/0782)** — BT stack overflow, requires proximity
2. **Mali T72x alias TOCTOU** — GPU driver race condition, most promising software vector
3. **DCCP UAF (CVE-2017-8824)** — Unpatched, network protocol exploitation

The JIG UART cable is the only hardware approach worth considering in the near term, as it:
- Is non-destructive (doesn't require disassembly)
- Could provide serial console output for kernel debugging
- Is cheap to make (~$1 in resistors)
- Doesn't risk bricking

---

## 6. Sources

### Primary References
- [Qualcomm EDL Mode — Wikipedia](https://en.wikipedia.org/wiki/Qualcomm_EDL_mode)
- [Aleph Security — EDL Firehose Peek/Poke](https://alephsecurity.com/vulns/aleph-2017028)
- [Aleph Security — Exploiting EDL Programmers (4-part series)](https://alephsecurity.com/2018/01/22/qualcomm-edl-1/)
- [bkerler/edl — GitHub](https://github.com/bkerler/edl)
- [frederic/exynos-usbdl — GitHub](https://github.com/frederic/exynos-usbdl)
- [fredericb.info — Exynos BootROM writeup](https://fredericb.info/2020/06/exynos-usbdl-unsigned-code-loader-for-exynos-bootrom.html)

### Device-Specific
- [SM-T377A XDA Recovery Thread](https://xdaforums.com/t/sm-t377a-recovery.3970221/)
- [HalabTech T377A ISP Pinout](https://support.halabtech.com/index.php?a=downloads&b=file&id=650466)
- [Chimera Tool — Samsung Exynos EUB Mode](https://chimeratool.com/docs/samsung-exynos-devices-connect-the-device-in-eub-mode)
- [Chimera Tool — Samsung Exynos Boot Repair](https://chimeratool.com/docs/samsung-exynos-boot-repair)
- [Passware — Samsung Exynos Test Point Gallery](https://support.passware.com/hc/en-us/articles/9171446187159-Samsung-Exynos-test-point-gallery)
- [GSM-Forum — Exynos TP Collection for EUB](https://forum.gsmhosting.com/vbb/f898/exynos-tp-collection-eub-mode-3147039/)
- [AlephGSM/SAMSUNG-EDL-Loaders — GitHub](https://github.com/Alephgsm/SAMSUNG-EDL-Loaders)
- [DeviceBeast — SM-T377A Specs (Exynos confirmed)](https://devicebeast.com/devices/samsung-sm-t377a-galaxy-tab-e-80-4g-lte)

### EUB Mode / Exynos Boot Research
- [ChimeraTool — Exynos EUB Mode](https://chimeratool.com/en/docs/eub-mode)
- [ChimeraTool — EUB Without Test Point](https://chimeratool.com/docs/eub-mode-without-test-point)
- [ChimeraTool — Samsung Exynos Boot Repair](https://chimeratool.com/docs/samsung-exynos-boot-repair)
- [ChimeraTool — Test Points Library](https://chimeratool.com/test-points/samsung)
- [GSM-Forum — EUB Without TP (135 models)](https://forum.gsmhosting.com/vbb/f475/chimera-samsung-eub-without-tp-135-models-supported-21-new-exynos-models-3305154/)
- [GSM-Forum — Entering Exynos Port Mode Without Opening Phone](https://forum.gsmhosting.com/vbb/f898/entering-exynos-port-mode-without-opening-phone-3234157/)
- [GSM-Forum — Exynos TP Collection for EUB Mode](https://forum.gsmhosting.com/vbb/f898/exynos-tp-collection-eub-mode-3147039/)
- [HalabTech — Samsung Test Point EUB Mode](https://support.halabtech.com/index.php?a=downloads&b=folder&id=177106)
- [fredericb.info — Reverse Engineer USB Stack of Exynos BootROM](https://fredericb.info/2020/06/reverse-engineer-usb-stack-of-exynos-bootrom.html)
- [XDA — Exynos USB Boot (EUB) Mode Discussion](https://xdaforums.com/t/exynos-usb-boot-eub-mode.4670684/)

### Device-Specific Hardware
- [SM-T377A Service Manual — RepairLap](https://www.repairlap.com/threads/samsung-galaxy-tab-e-8-0-sm-t377a-service-manual.4218/)
- [SM-T377A Service Manual — Vinafix](https://vinafix.com/threads/samsung-galaxy-tab-e-8-0-sm-t377a-service-manual.38981/)
- [SM-T377A Schematics — Phonelumi](https://phonelumi.com/samsung-galaxy-tab-e-8-0-sm-t377-schematics/)
- [SM-T377A Disassembly Video — YouTube](https://www.youtube.com/watch?v=zXx9xJ_TS24)
- [SM-T377V iFixit Teardown Guide (PDF)](https://documents.cdn.ifixit.com/pdf/ifixit/guide_114527_en.pdf)
- [SM-T377A Official Diagram — AT&T](https://www.att.com/device-support/devicediagram/Samsung/SamsungT377A)
- [SM-T377A User Manual — ManualsLib](https://www.manualslib.com/manual/3988332/Samsung-Sm-T377a.html)
- [Heimdall User Guide — GitHub](https://github.com/jeffjose/heimdall-userguide)

### General Samsung
- [XDA — Samsung Unbrick/Flash Guide](https://xdaforums.com/t/guide-repair-unbrick-unroot-re-lock-bootloader-and-flash-stock-firmware-in-samsung-devices.4452839/)
- [Cellebrite — EDL Mode Forensics](https://cellebrite.com/en/digital-forensics/edl-emergency-download-mode/)
- [Magnet Forensics — EDL in Investigations](https://www.magnetforensics.com/blog/qualcomm-phone-edl-mode/)
- [EDL Cable Construction — MobileRDX](https://www.mobilerdx.com/2023/12/guide-to-make-samsung-edl-cable-using-usb-cable.html)

---

---

## 7. Deep Dive: EUB (Exynos USB Boot) Mode Entry Methods

### 7.1 What is EUB Mode?

EUB mode is the Exynos BootROM's fallback USB download mode. It activates when the SoC's boot ROM **fails to initialize the eMMC** during early boot. In this state:
- The BootROM exposes a minimal USB stack (VID `04E8`, PID varies by model)
- The device appears as an "Exynos USB Device" in Windows Device Manager
- Low-level tools (ChimeraTool, Z3X, exynos-usbdl) can communicate directly with BootROM
- All normal boot chain security (sboot signature checks, carrier lock) is bypassed — we're BELOW sboot

### 7.2 Method 1: Hardware Test Points (eMMC CLK Ground Short)

**How it works:**
The eMMC CLK (clock) line test point on the PCB is shorted to ground while USB is connected. This prevents the BootROM from initializing eMMC, forcing fallback to USB boot.

**Procedure:**
1. Disassemble device to access motherboard
2. Locate the eMMC CLK test point (small copper pad near eMMC chip)
3. Disconnect battery
4. Short CLK pad to ground with tweezers or fine wire
5. Connect USB to PC while maintaining the short
6. Wait for PC to detect USB device (the BootROM EUB device)
7. Release the short

**SM-T377A specific:**
- ISP pinout available from [HalabTech](https://support.halabtech.com/index.php?a=downloads&b=file&id=650466) (paid access)
- Service manual/schematics from [RepairLap](https://www.repairlap.com/threads/samsung-galaxy-tab-e-8-0-sm-t377a-service-manual.4218/) and [Vinafix](https://vinafix.com/threads/samsung-galaxy-tab-e-8-0-sm-t377a-service-manual.38981/)
- [YouTube disassembly video](https://www.youtube.com/watch?v=zXx9xJ_TS24) specific to SM-T377A
- [iFixit teardown guide (PDF)](https://documents.cdn.ifixit.com/pdf/ifixit/guide_114527_en.pdf) for SM-T377V (nearly identical construction)
- Test point galleries: [ChimeraTool](https://chimeratool.com/test-points/samsung), [Passware](https://support.passware.com/hc/en-us/articles/9171446187159), [GSM-Forum](https://forum.gsmhosting.com/vbb/f898/exynos-tp-collection-eub-mode-3147039/), [HalabTech EUB folder](https://support.halabtech.com/index.php?a=downloads&b=folder&id=177106)

**Risk:** MEDIUM — Requires disassembly but doesn't modify any software. Non-destructive if done carefully.

### 7.3 Method 2: Software-Triggered Bootloader Corruption (via Download Mode)

**How it works:**
The device's bootloader partition (`SBOOT`) is intentionally corrupted by flashing a wrong binary through Download Mode (Odin/Heimdall). When the corrupted sboot fails to load on next boot, the BootROM falls back to EUB mode.

**Documented GSMHosting technique:**
1. Download official firmware for the device
2. Extract the `BL` tar — locate `cm.bin.lz4`
3. **Rename `cm.bin.lz4` to `sboot.bin.lz4`** (cross-partition binary swap)
4. Repackage as `.tar` archive
5. Flash via Odin in the `BL` slot
6. Device reboots → sboot is corrupted → BootROM EUB mode activates
7. Use ChimeraTool/Z3X for boot repair, then reflash correct firmware

**Carrier lock consideration:**
- Our device CAN enter Download Mode (Vol Down + Home + Power)
- Odin/Heimdall CAN flash the BL partition with signed Samsung firmware
- The carrier lock blocks **unsigned** images, but the `cm.bin` IS a signed Samsung binary — just for the wrong partition
- Key question: **Does the carrier lock validate BL partition content, or just signature?**
- If it only checks signature, flashing a valid-but-wrong Samsung binary could corrupt sboot while passing signature checks

**SM-T377A partition discovery:**
```bash
heimdall detect              # Verify device in Download Mode
heimdall print-pit           # Print partition table
heimdall download-pit --output t377a.pit  # Save PIT file
```

**Risk:** HIGH — Deliberately bricks the device. Recovery requires EUB mode tools (ChimeraTool ~$50-100) or ISP hardware. If EUB doesn't activate for Exynos 3475, the device may be permanently bricked.

### 7.4 Method 3: ChimeraTool "Switch to EUB" (Software, No Disassembly)

**How it works:**
ChimeraTool sends a proprietary/undocumented command sequence over USB while the device is in Download Mode. This triggers the bootloader to transition directly to EUB mode.

**Internal mechanism (reverse-engineered understanding):**
1. Tool establishes USB communication in Download Mode
2. Sends crafted "magic" USB bulk commands (likely exploiting factory/engineering access left in sboot)
3. Bootloader responds by rebooting into BootROM EUB mode
4. Tool proceeds with low-level operations

**SM-T377A / Exynos 3475 compatibility:**
- ❌ **NOT in the "EUB without TP" supported model list** (135+ models, primarily newer Exynos: A20, A21, A30, A50, A51, A71, M31, S20 series)
- ❌ No Exynos 3475 device (J200, J120, T377A) is listed
- This method is proprietary to ChimeraTool and Z3X (commercial, ~$50-100)

**Risk:** N/A — Not supported for this device.

### 7.5 Method 4: Z3X SamsTool EUB Switch

Same concept as ChimeraTool Method 3, different commercial tool. Also does NOT list Exynos 3475 support.

### 7.6 EUB Mode — What Can We Do Once In It?

If EUB mode is achieved, the possibilities are significant:

| Capability | Description |
|-----------|-------------|
| **Bypass carrier lock** | BootROM is BELOW the carrier-lock enforcement layer (sboot) |
| **Flash unsigned code** | If BootROM doesn't enforce signature (like exynos-usbdl on 8890/8895) |
| **Dump eMMC** | Read all partitions including boot, system, kernel |
| **Write partitions** | Potentially flash a rooted boot.img or modified kernel |
| **Boot repair** | Reflash correct sboot to recover from bricked state |

**Critical unknown:** Whether the Exynos 3475 BootROM enforces signature checks on what it loads via USB. The exynos-usbdl research showed that Exynos 8890/8895 had an integer overflow bug allowing unsigned code execution. Whether the 3475 has similar vulnerabilities is **completely unknown** — no public research exists.

### 7.7 Feasibility Assessment for SM-T377A

| Method | Feasibility | Risk | Reversible? | Tools Needed | Cost |
|--------|------------|------|-------------|-------------|------|
| Test Point (CLK ground) | **MEDIUM** — Need schematics, disassembly | Medium | Yes | Tweezers, USB cable | $0 + time |
| Bootloader corruption | **MEDIUM** — Odin can flash BL | **VERY HIGH** | Only with EUB tools | ChimeraTool license | ~$50-100 |
| ChimeraTool EUB switch | **NOT POSSIBLE** | N/A | N/A | N/A | N/A |
| Z3X EUB switch | **NOT POSSIBLE** | N/A | N/A | N/A | N/A |

### 7.8 Recommended Approach

**Phase 1 — Low-risk reconnaissance (no device modification):**
1. Obtain SM-T377A service manual/schematics (RepairLap, Vinafix, Phonelumi)
2. Use `heimdall print-pit` to dump the partition table from Download Mode
3. Identify exact partition names (SBOOT, BOOT, SYSTEM, etc.)
4. Research if identical Exynos 3475 devices (SM-J200, SM-J120) have documented EUB test points
5. Check if HalabTech ISP pinout docs also show the EUB/CLK test point location

**Phase 2 — Medium-risk (requires disassembly, no software modification):**
1. Disassemble the tablet following the iFixit guide
2. Photograph the motherboard, locate eMMC chip
3. Identify CLK test point (cross-reference with schematics)
4. Attempt EUB entry via CLK ground short
5. Monitor PC Device Manager for Samsung/Exynos USB device detection

**Phase 3 — High-risk (last resort only):**
1. Only if Phase 2 confirms EUB works AND ChimeraTool is available for recovery
2. Use bootloader corruption method to enter EUB from software
3. Attempt unsigned code loading or partition manipulation

---

## 8. Key Takeaway

**An EDL cable is useless for the SM-T377A.** The device runs Exynos 3475, not Qualcomm. The closest Exynos equivalents (EUB mode, exynos-usbdl) either require hardware intervention or don't support this SoC. The carrier-locked Odin/Download Mode rejects unsigned firmware.

**For EUB mode specifically**, the most viable path is the **hardware test point method** — shorting the eMMC CLK line to ground during USB connection. This requires disassembly and locating the correct test point. The software "EUB without TP" methods from ChimeraTool/Z3X do not support Exynos 3475.

**Before attempting any EUB entry**, obtain the SM-T377A schematics and use `heimdall print-pit` to map the partition table. A Samsung JIG/UART cable (resistor between USB ID and GND) remains the lowest-risk hardware approach for serial debug output without disassembly.
