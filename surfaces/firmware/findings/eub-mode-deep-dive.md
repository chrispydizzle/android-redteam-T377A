# EUB (Exynos USB Boot) Mode Deep Dive — SM-T377A

> **Date:** 2026-02-28
> **Device:** Samsung SM-T377A (Galaxy Tab E 8.0, AT&T)
> **SoC:** Exynos 3475 (ARMv7 Cortex-A7, codename "Island" / "universal3475")
> **Purpose:** Comprehensive technical analysis of EUB mode as a potential carrier-lock bypass vector

---

## 1. Exynos 3475 Boot Chain Architecture

### 1.1 Boot Sequence

```
Power On
  ↓
[BootROM / IROM] (immutable, in-SoC ROM at 0x00000000, est. 16-64KB)
  ↓ reads from eMMC
[BL1 / fwbl1] (first bootloader, minimal init, signature-checked by BootROM)
  ↓
[BL2] (secondary bootloader, DRAM init, loads sboot)
  ↓
[SBOOT] (Samsung Secure Bootloader — TrustZone, carrier lock, Knox, signature enforcement)
  ↓
[Android Kernel] → Android OS
```

**Key insight:** The carrier lock is enforced by SBOOT. If we can operate at the BootROM level (via EUB), we are BELOW all carrier lock enforcement.

### 1.2 Hardware Addresses (from Device Tree)

| Component | Address | Notes |
|-----------|---------|-------|
| DWC2 USB Controller | `0x13500000` | Synopsys DesignWare USB 2.0, size 0x10000 |
| eMMC Controller (DWMMC) | `0x15570000` | Samsung Exynos DWMMC, size 0x10000 |
| BootROM (IROM) | `0x00000000` | Estimated 16-64KB, immutable |
| SRAM | TBD | Used by BootROM for USB download buffer |

Sources: kernel device tree `exynos3475.dtsi`, community repos:
- [jcadduono/android_kernel_samsung_universal3475](https://github.com/jcadduono/android_kernel_samsung_universal3475)
- [Exynos3475/android_device_samsung_universal3475-common](https://github.com/Exynos3475/android_device_samsung_universal3475-common)

### 1.3 Boot Device Selection

The Exynos 3475 uses e-fuses to configure boot priority (OM pins are hardwired on production devices):

| Priority | Boot Device | Condition |
|----------|------------|-----------|
| 1 | eMMC (internal storage) | Default — loads BL1 from eMMC |
| 2 | **USB Boot (EUB mode)** | **Fallback if eMMC boot fails** |
| 3 | SD card | Typically only on dev boards |
| 4 | UART/SPI | Engineering only |

**This is the critical design feature:** EUB mode activates automatically when eMMC boot fails. We don't need to change any fuses — we just need to make eMMC boot fail.

---

## 2. EUB Mode Technical Details

### 2.1 What Happens in EUB Mode

When eMMC boot fails, the Exynos 3475 BootROM:

1. Initializes the DWC2 USB controller at `0x13500000`
2. Exposes a minimal USB device interface (VID: `04E8` = Samsung, PID: varies)
3. Implements a stripped-down USB stack with no OS features (no interrupts, no dynamic allocation)
4. Waits for a host to send a signed bootloader binary via USB bulk transfers

### 2.2 USB Download Protocol (dldata)

The BootROM accepts payloads in a simple structure:

```c
typedef struct dldata_s {
    uint32_t unknown0;       // header field
    uint32_t size;           // header(8) + data(n) + footer(2)
    uint8_t  data[n];        // payload (bootloader binary)
    uint16_t unknown1;       // footer
} dldata;
```

The BootROM has a designated receive buffer in SRAM. For Exynos 8890/8895, this was at `[0x02021800..0x02070000]` (0x4E800 = ~315KB). The Exynos 3475 likely has a similar but potentially smaller buffer at a different address.

### 2.3 Signature Verification

Under normal operation, the BootROM **cryptographically verifies** the uploaded binary against Samsung's signing key before executing it. This is the primary security gate.

**However:**
- Exynos 8890/8895 BootROMs have an **integer overflow vulnerability** in the size check that bypasses signature verification entirely
- Whether Exynos 3475 has the same or similar bug is **UNKNOWN** — no public research exists
- The Exynos 3475 is older and simpler than 8890/8895, which could mean EITHER less secure (fewer checks) OR different code (different bugs)

### 2.4 The exynos-usbdl Integer Overflow (Reference)

On Exynos 8890/8895, the size check works like this:

```c
if (dl_buf + dldata.size >= BUFFER_END) {
    status = ERROR;  // reject oversized payload
}
```

If `dldata.size` is large enough (e.g., > `0xFDFDE7FF`), `dl_buf + dldata.size` wraps around due to 32-bit unsigned integer overflow and appears smaller than `BUFFER_END`, passing the check. Combined with the "empty transfer trick" (advancing the write pointer without sending data), an attacker can target specific memory addresses for corruption and achieve arbitrary code execution in Secure World.

**Supported chips:** Exynos 8890, 8895 only. **NOT Exynos 3475.**

---

## 3. How to Enter EUB Mode on SM-T377A

### 3.1 Method A: eMMC CLK Line Ground Short (Test Point)

**Mechanism:** Shorting the eMMC clock line to ground prevents BootROM from reading eMMC → boot fails → EUB activates.

**Procedure:**
1. Power off device, disconnect battery
2. Disassemble tablet (back cover, then motherboard access)
3. Locate eMMC CLK test point (near eMMC chip, labeled "CLK" or "TP")
4. Short CLK pad to ground with tweezers
5. Connect USB to PC while maintaining short + hold power button
6. PC should detect new USB device (Samsung VID 04E8)
7. Release short

**Where to find test point location:**
- [HalabTech ISP Pinout for T377A](https://support.halabtech.com/index.php?a=downloads&b=file&id=650466) (may need paid access)
- [ChimeraTool Test Points Library](https://chimeratool.com/test-points/samsung)
- [GSM-Forum Exynos TP Collection](https://forum.gsmhosting.com/vbb/f898/exynos-tp-collection-eub-mode-3147039/)
- [Passware Samsung Exynos Test Point Gallery](https://support.passware.com/hc/en-us/articles/9171446187159)
- SM-T377A schematics from [RepairLap](https://www.repairlap.com/threads/samsung-galaxy-tab-e-8-0-sm-t377a-service-manual.4218/), [Vinafix](https://vinafix.com/threads/samsung-galaxy-tab-e-8-0-sm-t377a-service-manual.38981/), [Phonelumi](https://phonelumi.com/samsung-galaxy-tab-e-8-0-sm-t377-schematics/)

**Risk:** MEDIUM — Requires disassembly but software/eMMC untouched. Fully reversible.

### 3.2 Method B: Bootloader Corruption via Download Mode (Odin/Heimdall)

**Mechanism:** Flash a wrong binary to the SBOOT partition so it fails integrity check → BootROM can't load sboot → falls back to EUB.

**GSMHosting documented technique:**
1. Download official SM-T377A firmware (e.g., T377AUCU2AQGF from [SamFrew](https://samfrew.com/firmware/model/SM-T377A/upload/Desc/0/10))
2. Extract BL tar → locate `cm.bin.lz4`
3. Rename `cm.bin.lz4` → `sboot.bin.lz4`
4. Repackage as .tar
5. Flash via Odin in BL slot
6. Device reboots → sboot is corrupt → BootROM EUB mode

**Critical prerequisite:** Must first map partitions with:
```bash
heimdall detect                              # Verify device detected in Download Mode
heimdall print-pit                           # Print partition table
heimdall download-pit --output t377a.pit     # Save PIT file for analysis
```

**Key question:** Can Odin flash a Samsung-signed-but-wrong binary to the BL partition? The carrier lock blocks **unsigned** firmware, but `cm.bin` IS a signed Samsung binary. If the validation only checks signature (not content correctness), this could work.

**Risk:** VERY HIGH — Deliberately bricks the device. Recovery ONLY possible via:
- EUB mode + ChimeraTool ($50-100 license)
- ISP/JTAG direct eMMC access (requires programmer hardware)
- If neither works, device is permanently dead

### 3.3 Method C: ChimeraTool Software "Switch to EUB" 

**Status:** ❌ NOT AVAILABLE for Exynos 3475

ChimeraTool's "EUB without TP" feature sends proprietary USB commands while in Download Mode to trigger EUB entry. This exploits undocumented factory/engineering access features in the Samsung bootloader. However, support is limited to newer Exynos models (A20, A21, A30, A50, A51, A71, M31, S20 series). No Exynos 3475 device is supported.

---

## 4. Samsung Download Mode Protocol (for Reference)

Understanding Download Mode is important because Methods B and C operate through it.

### 4.1 Heimdall Protocol Overview

Heimdall reverse-engineered Samsung's "Odin protocol":

1. **USB enumeration:** Device in Download Mode exposes VID:PID `04E8:685D` (varies)
2. **Handshake:** Host sends magic string "ODIN" via USB bulk transfer
3. **Device responds** with protocol version and capabilities
4. **Session begin:** Commands for PIT download, firmware upload, etc.
5. **Flash operations:** BL, AP, CP, CSC partitions sent in chunks
6. **Session end:** Reboot command or disconnect

**Key source code:** `BridgeManager.cpp` in [Heimdall](https://github.com/Benjamin-Dobell/Heimdall)

### 4.2 Partition Table (PIT)

The SM-T377A partition table can be dumped via `heimdall print-pit` in Download Mode. Expected partitions include:

| Partition | Odin Slot | Contains |
|-----------|-----------|----------|
| SBOOT | BL | Samsung secure bootloader (sboot.bin) |
| BOOT | AP | Android kernel + ramdisk |
| RECOVERY | AP | Recovery image |
| SYSTEM | AP | Android OS |
| MODEM | CP | Shannon 308 modem firmware |
| CSC | CSC | Carrier/region configuration |

---

## 5. SBOOT Reverse Engineering (Background)

### 5.1 Quarkslab's Research

Quarkslab published detailed analysis of Samsung S6 SBOOT (Exynos 7420), which is architecturally similar to our Exynos 3475 SBOOT:

- SBOOT is a monolithic blob containing BL1, BL2, EL3 monitor, TrustZone OS (Kinibi/MobiCore), and trusted drivers
- Contains embedded MCLF (MobiCore Load Format) sections identifiable by "MCLF" magic bytes
- Can be analyzed with Ghidra + custom scripts from [quarkslab/samsung-trustzone-research](https://github.com/quarkslab/samsung-trustzone-research)

**Analysis approach for our SBOOT:**
1. Download T377AUCU2AQGF firmware → extract BL tar → extract sboot.bin
2. Use `binwalk -e sboot.bin` to identify embedded components
3. Load in Ghidra as ARM 32-bit (ARMv7) binary
4. Identify BL1 at offset 0x0 (est. 8-16KB)
5. Look for signature verification routines, carrier lock checks, and USB protocol code

### 5.2 Key Blog Posts
- [Quarkslab Part I: Loading SBOOT](https://blog.quarkslab.com/reverse-engineering-samsung-s6-sboot-part-i.html)
- [Quarkslab Part II: TrustZone Analysis](https://blog.quarkslab.com/reverse-engineering-samsung-s6-sboot-part-ii.html)
- [fredericb.info: Exynos BootROM USB Stack](https://fredericb.info/2020/06/reverse-engineer-usb-stack-of-exynos-bootrom.html)
- [fredericb.info: exynos-usbdl Exploit](https://fredericb.info/2020/06/exynos-usbdl-unsigned-code-loader-for-exynos-bootrom.html)

---

## 6. What We Can Do IF EUB Mode Is Achieved

### 6.1 With Signed Loader Only (No BootROM Exploit)

If the Exynos 3475 BootROM properly enforces signature checks:
- **ChimeraTool boot repair** — Uploads Samsung's signed BL1/sboot to repair the boot chain
- **Partition dump** — Tools may be able to read eMMC contents
- **Flash modified signed firmware** — If we have a signed firmware with modifications (unlikely without Samsung's key)

### 6.2 With BootROM Exploit (If Vulnerability Exists)

If the Exynos 3475 BootROM has a similar integer overflow bug (or any other vulnerability):
- **Arbitrary code execution in Secure World** — Full control below all security
- **Disable carrier lock** — Modify sboot or NV data to remove AT&T lock
- **Flash custom kernel** — Root the device permanently
- **Dump BootROM itself** — Enable further analysis and exploit development
- **Install custom bootloader** — Full control of boot chain

### 6.3 With ISP/eMMC Direct Access (No BootROM Needed)

If we connect directly to eMMC via ISP test points (bypassing the SoC entirely):
- **Full partition read/write** — No signature checks at all
- **Modify boot.img** — Inject root, disable SELinux
- **Modify sboot** — Remove carrier lock checks (but TIMA would detect on next boot)
- **Full forensic dump** — Extract everything

---

## 7. Recommended Action Plan

### Phase 0: Zero-Risk Recon (NOW)
- [ ] Run `heimdall detect` and `heimdall print-pit` in Download Mode to map partitions
- [ ] Download T377AUCU2AQGF firmware from SamFrew
- [ ] Extract and analyze sboot.bin with binwalk and Ghidra
- [ ] Obtain SM-T377A schematics (RepairLap/Vinafix)

### Phase 1: Low-Risk Hardware Recon
- [ ] Obtain or build a Samsung JIG UART cable (150kΩ between USB ID and GND)
- [ ] Test if UART serial output is available (debug console without disassembly)
- [ ] If UART works, capture boot logs for deeper understanding of boot chain

### Phase 2: Medium-Risk (Test Point EUB Entry)
- [ ] Disassemble tablet following iFixit guide
- [ ] Photograph motherboard, locate eMMC chip and CLK test point
- [ ] Attempt EUB entry via CLK ground short
- [ ] Monitor PC Device Manager for Samsung USB device (VID 04E8)
- [ ] If detected, identify PID and test with exynos-usbdl (adapted for 3475)

### Phase 3: High-Risk (Bootloader Corruption)
- [ ] ONLY if Phase 2 confirms EUB works and recovery tools are ready
- [ ] Use the cm.bin→sboot.bin swap technique via Odin
- [ ] Use ChimeraTool for boot repair once in EUB

---

## 8. Samsung JIG UART Cable — Lowest Risk Path

### 8.1 Overview
Samsung devices detect accessories via a resistor between the USB ID pin (Pin 4) and GND (Pin 5) on micro-USB. Specific resistance values trigger different modes:

| Resistor Value | Mode Triggered | Notes |
|---------------|---------------|-------|
| **0Ω (short)** | USB OTG Host | Standard USB OTG |
| **301kΩ** | Download Mode (JIG) | Forces Odin/Download Mode |
| **523kΩ** | UART Debug (some models) | Alternative UART value |
| **619kΩ** | **UART Serial Console** | **Enables AP serial debug output via USB D+/D-** |

### 8.2 UART JIG Cable Construction

**Materials needed (~$5 total):**
- 1x Micro-USB male connector/breakout
- 1x 619kΩ resistor (or 620kΩ standard value)
- 1x USB-to-UART adapter (FT232, CH340, CP2102 — **must support 1.8V logic!**)
- Soldering iron + solder

**Wiring:**
```
Micro-USB Pin 4 (ID) ---[619kΩ]--- Micro-USB Pin 5 (GND)
Micro-USB Pin 2 (D-)  -----------> UART adapter RX
Micro-USB Pin 3 (D+)  -----------> UART adapter TX
Micro-USB Pin 5 (GND) -----------> UART adapter GND
```

⚠ **CRITICAL:** Exynos UART is often **1.8V logic**. Using a 5V or 3.3V UART adapter directly may damage the SoC. Use a level shifter or a 1.8V-capable adapter.

### 8.3 What UART Gives Us
- **Boot logs** — Full BootROM → sboot → kernel boot sequence output
- **BootROM debug messages** — May reveal EUB triggering conditions, signature check results
- **Kernel dmesg** — Richer than what we see via `adb logcat`
- **Interactive shell** — Some Samsung devices expose a debug console on UART
- **Boot chain analysis** — Understand exact boot flow for our specific firmware

### 8.4 Why This Matters for EUB Research
A UART console during boot could reveal:
1. Whether the BootROM prints diagnostic messages about boot source selection
2. What happens when sboot signature check fails
3. Whether EUB mode is actually attempting to activate
4. The exact USB descriptor and protocol the BootROM uses in EUB mode
5. Memory addresses and buffer locations used by the BootROM USB stack

### 8.5 References
- [grimler.se — PCBite for UART Logs on Exynos](https://grimler.se/posts/exynos-uart/)
- [postmarketOS Wiki — Serial Debugging Cable Schematics](https://wiki.postmarketos.org/wiki/Serial_debugging/Cable_schematics)
- [postmarketOS Wiki — Serial Debugging](https://wiki.postmarketos.org/wiki/Serial_debugging)
- [pinoutguide.com — Samsung Mobile Phone Micro USB](https://pinoutguide.com/CellularPhones-A-N/samsung_cell_micro_usb_pinout.shtml)
- [XDA — DIY Download Mode JIG Dongle](https://xdaforums.com/t/how-to-diy-a-download-mode-jig-dongle.2121306/)
- [TI E2E — TSU8111 Micro USB Accessory Detection](https://e2e.ti.com/support/switches-multiplexers-group/switches-multiplexers/f/switches-multiplexers-forum/361091/)

---

## 9. Early Exynos BootROM Security Assessment

### 9.1 Key Finding: Early Exynos BootROMs Are WEAKER

Research indicates that **pre-Exynos 8890 BootROMs (including Exynos 3/4/5 families) have less mature secure boot implementations**. While the specific integer overflow exploit in exynos-usbdl was demonstrated on 8890/8895, security researchers believe earlier generations are **potentially MORE vulnerable**, not less:

- Earlier BootROMs had fewer security mitigations
- Simpler USB stacks with less validation
- Less scrutiny from security researchers (fewer public tools, not fewer bugs)
- Samsung progressively hardened BootROM security with each generation

### 9.2 Implication for Exynos 3475

The Exynos 3475 is a **budget SoC from 2015-2016**, making it one of the least hardened Exynos generations:
- Likely has a simpler BootROM than 8890/8895
- May have the SAME integer overflow (common codebase) or DIFFERENT bugs
- Samsung historically invested less security effort in budget chips
- No known public research exists — this is an unexplored attack surface

### 9.3 What Would Be Needed to Test

1. **Enter EUB mode** (via test point CLK short)
2. **Identify the USB device** that appears (VID/PID)
3. **Sniff USB traffic** to understand the download protocol
4. **Adapt exynos-usbdl** for Exynos 3475's buffer addresses
5. **Test the integer overflow** with adjusted parameters
6. If successful → arbitrary code execution in Secure World → root

---

## 10. Open Questions

1. **Does the Exynos 3475 BootROM have the same integer overflow as 8890/8895?**
   - No public research exists. Would need to dump and reverse-engineer the BootROM.
   - If yes → full arbitrary code execution from USB, game over for carrier lock.

2. **What USB PID does the SM-T377A expose in EUB mode?**
   - Varies by device. Need to actually enter EUB to find out.

3. **Can Odin flash a mismatched-but-signed binary to the BL partition?**
   - If carrier lock only validates signature (not content), the cm.bin→sboot.bin swap should work.
   - If it validates partition-specific content, this approach fails.

4. **Does the BootROM's USB download mode accept ANY signed Samsung binary, or does it need a specific BL1?**
   - This determines whether we need a device-specific signed loader or if any Samsung-signed BL1 would work.

5. **Is the SBOOT for T377AUCU2AQGF extractable and analyzable?**
   - Almost certainly yes. The firmware is downloadable from SamFrew.

---

## 11. MUIC Chip: Software UART Without Hardware JIG

### 11.1 MUIC Identification

The Exynos 3475 uses a **Silicon Mitus SM5502 or SM5504** MUIC (Micro-USB Interface Controller), NOT TI TSU6111. This chip:
- Controls USB/UART/charger path switching via I2C
- Detects accessory type via ID pin resistance
- Has mainline Linux driver: `extcon-sm5502` (device tree: `siliconmitus,sm5502-muic`)
- Is accessible from the kernel via `/sys/class/extcon/` or `/sys/class/muic/`

### 11.2 Software UART Switch (Potential Zero-Hardware Path!)

There are THREE possible ways to switch to UART mode via software:

**Method 1: `*#0808#` Dialer Code**
- Enter `*#0808#` in the phone dialer
- Presents a USB mode selection menu (DM+MODEM+ADB, UART, etc.)
- **Can potentially enable UART without any hardware modification**
- Works from normal Android, no root required for the menu itself

**Method 2: Sysfs MUIC Manual Switch (requires root/shell)**
```bash
# Find MUIC sysfs nodes
find /sys -name "*muic*" 2>/dev/null
find /sys -name "*extcon*" 2>/dev/null

# If manual_switch exists:
echo "uart_ap" > /sys/class/muic/*/manual_switch
# Or:
echo 1 > /sys/class/extcon/*/state
```

**Method 3: Direct I2C Write (requires root)**
```bash
# Identify MUIC I2C bus and address
find /sys/bus/i2c/devices -name "*5502*" -o -name "*5504*" 2>/dev/null

# Use i2cset to write mode register (chip-specific, need SM5502 datasheet)
i2cset -y <bus> <addr> <reg> <value>
```

### 11.3 Why This Matters

If we can switch to UART via `*#0808#` or sysfs, we get:
- **Serial boot logs WITHOUT disassembly**
- **WITHOUT building a JIG cable**
- **From normal ADB shell access we already have**
- Critical intelligence about the boot chain for EUB research

### 11.4 Immediate Actions (Can Do NOW via ADB)

```bash
# Check what MUIC nodes exist
adb shell "find /sys -name '*muic*' -o -name '*extcon*' -o -name '*sm5502*' -o -name '*sm5504*' 2>/dev/null"

# Check if *#0808# works via am broadcast
adb shell "am start -a android.intent.action.DIAL -d 'tel:*%230808%23'"

# Check USB configuration props
adb shell "getprop persist.sys.usb.config"
adb shell "getprop sys.usb.config"
```

### 11.7 VERIFIED ON DEVICE — MUIC and USB State

**Confirmed via ADB (2026-02-28):**

| Finding | Value | Path |
|---------|-------|------|
| MUIC driver | `muic-universal` | `/sys/bus/i2c/drivers/muic-universal` |
| MUIC I2C address | `0x25` on bus 0 | `/sys/devices/13870000.hsi2c/i2c-0/0-0025/` |
| MUIC I2C controller | `13870000.hsi2c` | HSI2C (high-speed I2C) |
| uart_en | `0` (disabled) | `/sys/class/sec/switch/uart_en` |
| uart_sel | `AP` | `/sys/class/sec/switch/uart_sel` |
| usb_sel | `PDA` | `/sys/class/sec/switch/usb_sel` |
| attached_dev | `USB` | `/sys/class/sec/switch/attached_dev` |
| usb_state | `USB_STATE_CONFIGURED` | `/sys/class/sec/switch/usb_state` |
| ADC value | `0x1f` (no accessory resistor) | `/sys/class/sec/switch/adc` |
| USB config | `rndis,acm,dm,adb` | `settings get global usb_config` |
| USB gadget functions | `rndis,acm,dm,adb` | `/sys/class/android_usb/android0/functions` |
| USB gadget state | `CONFIGURED` | `/sys/class/android_usb/android0/state` |

**MUIC Register Dump:**
```
CT:1e IM1:dc IM2:0 MS1:25 MS2:0 ADC:1f DT1:4 DT2:0 DT3:0 RS1:3
```
- CT=0x1e: Control register
- MS1=0x25: Manual Switch 1 (USB path active)
- ADC=0x1f: No resistor detected (open/floating ID pin)
- DT1=0x4: Device Type 1 — USB detected

**Permissions:** `uart_en`, `uart_sel`, `usb_sel` are owned by `system:radio` (rw-rw-r--). Shell (UID 2000) can READ but NOT WRITE.

**`*#0808#` status:** `com.sec.usbsettings` package exists with `UltraKeyStringBroadcastReceiver`. The activity requires `com.sec.modem.settings.permission.KEYSTRING` (signature|privileged). The SECRET_CODE broadcast was sent but did NOT open the UI — may need to be triggered via the phone dialer app directly (not via `am broadcast`).

**To enable UART, would need to write `1` to `/sys/class/sec/switch/uart_en`** — requires `system` or `radio` UID. Our privesc agent (UID 10139) likely cannot write this either unless it has `system` group membership.

The Galaxy J2 (same Exynos 3475 SoC) can be rooted on non-carrier-locked variants via:
1. Enable OEM Unlock in Developer Options
2. Flash TWRP via Odin
3. Flash Magisk/SuperSU from TWRP

**Our SM-T377A (AT&T) blocks step 2** — the carrier lock rejects custom recovery images. But this confirms the SoC itself has no hardware barrier to custom firmware; the barrier is purely the AT&T carrier lock in sboot. EUB mode bypasses sboot entirely.

### 11.6 Samsung Combination Firmware — Engineering Debug Mode

Samsung "combination firmware" is a special service build that:
- **Enables ADB access** even on FRP-locked devices
- **Disables certain security protections** for engineering use
- **Can be flashed via Odin** on the AP slot (enters Download Mode normally)
- Available for SM-T377A from [HalabTech](https://support.halabtech.com/index.php?a=downloads&b=folder&id=12418)
- **Does NOT root** but creates a less restrictive environment

**Key question for us:** Can combination firmware be flashed on our AT&T carrier-locked device? If the carrier lock only blocks unsigned BL (bootloader) images but allows signed AP (system) images, combination firmware MIGHT flash successfully and give us a more debug-friendly environment.

**GSM-Forum confirms:** [SM-T377A bit 3 plus modem combination](https://forum.gsmhosting.com/vbb/f453/sm-t377a-bit-3-plus-modem-combination-done-3000373/) — users have successfully flashed combination firmware on this exact model.

---

## 12. Comprehensive Source Index

### BootROM & EUB Internals
- [fredericb.info — Reverse Engineer USB Stack of Exynos BootROM](https://fredericb.info/2020/06/reverse-engineer-usb-stack-of-exynos-bootrom.html)
- [fredericb.info — exynos-usbdl Unsigned Code Loader](https://fredericb.info/2020/06/exynos-usbdl-unsigned-code-loader-for-exynos-bootrom.html)
- [frederic/exynos-usbdl — GitHub](https://github.com/frederic/exynos-usbdl)
- [sNegative/exynos-usbdl_V2 — GitHub](https://github.com/sNegative/exynos-usbdl_V2)
- [Linux Kernel — Exynos Bootloader Interface](https://docs.kernel.org/6.1/arm/samsung/bootloader-interface.html)

### SBOOT Reverse Engineering
- [Quarkslab — RE Samsung S6 SBOOT Part I](https://blog.quarkslab.com/reverse-engineering-samsung-s6-sboot-part-i.html)
- [Quarkslab — RE Samsung S6 SBOOT Part II](https://blog.quarkslab.com/reverse-engineering-samsung-s6-sboot-part-ii.html)
- [quarkslab/samsung-trustzone-research — GitHub](https://github.com/quarkslab/samsung-trustzone-research)
- [XDA — Repair Hard Bricked Devices with Deleted Bootloader](https://xdaforums.com/t/guide-repair-hard-bricked-devices-with-deleted-bootloader-sboot.3573865/)
- [XDA — Exynos 990 EUB Mode Layout and sboot.bin Offsets](https://xdaforums.com/t/exynos-990-9830-eub-mode-layout-configuration-and-sboot-bin-offsets.4716745/)

### EUB Mode Entry Methods
- [ChimeraTool — Exynos EUB Mode](https://chimeratool.com/en/docs/eub-mode)
- [ChimeraTool — EUB Without Test Point](https://chimeratool.com/docs/eub-mode-without-test-point)
- [ChimeraTool — Samsung Exynos Boot Repair](https://chimeratool.com/docs/samsung-exynos-boot-repair)
- [Cheetah Tool — EUB Connection Method](https://cheetah-tool.com/en/docs/45/eub-connection-method-exynos-usb-boot)
- [GSM-Forum — Entering Exynos Port Mode Without Opening Phone](https://forum.gsmhosting.com/vbb/f898/entering-exynos-port-mode-without-opening-phone-3234157/)
- [GSM-Forum — Exynos TP Collection for EUB Mode](https://forum.gsmhosting.com/vbb/f898/exynos-tp-collection-eub-mode-3147039/)

### Samsung Download Mode Protocol
- [Heimdall — GitHub](https://github.com/Benjamin-Dobell/Heimdall)
- [LineageOS Heimdall Fork](https://github.com/LineageOS/android_external_heimdall)
- [ge0n0sis — Lock Samsung Download Mode](https://ge0n0sis.github.io/posts/2016/05/how-to-lock-the-samsung-download-mode-using-an-undocumented-feature-of-aboot/)

### Device-Specific Hardware
- [HalabTech — T377A ISP Pinout](https://support.halabtech.com/index.php?a=downloads&b=file&id=650466)
- [HalabTech — Samsung Test Point EUB Mode](https://support.halabtech.com/index.php?a=downloads&b=folder&id=177106)
- [SM-T377A Schematics — Phonelumi](https://phonelumi.com/samsung-galaxy-tab-e-8-0-sm-t377-schematics/)
- [SM-T377A Service Manual — RepairLap](https://www.repairlap.com/threads/samsung-galaxy-tab-e-8-0-sm-t377a-service-manual.4218/)
- [SM-T377A Disassembly — YouTube](https://www.youtube.com/watch?v=zXx9xJ_TS24)
- [SM-T377A iFixit Teardown (PDF)](https://documents.cdn.ifixit.com/pdf/ifixit/guide_114527_en.pdf)

### Firmware Downloads
- [SamFrew — SM-T377A Firmware List](https://samfrew.com/firmware/model/SM-T377A/upload/Desc/0/10)
- [XDA — T377AUCU3BRD1 Stock Firmware](https://xdaforums.com/t/t377aucu3brd1-stock-firmware-speed-returned-with-native-hotspot-enabled.3843139/)

### Kernel Source
- [Exynos3475/android_kernel_samsung_exynos3475 — GitHub](https://github.com/Exynos3475/android_kernel_samsung_exynos3475)
- [jcadduono/android_kernel_samsung_universal3475 — GitHub](https://github.com/jcadduono/android_kernel_samsung_universal3475)
- [Exynos3475/android_device_samsung_universal3475-common — GitHub](https://github.com/Exynos3475/android_device_samsung_universal3475-common)
- [XDA — Porting for Exynos 3475](https://xdaforums.com/t/porting-for-exynos-3475.4659827/)
