# Comprehensive Research Report: Samsung Low-Level Diagnostic & BootROM Modes

**Target Device:** Samsung Galaxy Tab E 8.0 (SM-T377A)
**Chipset:** Exynos 3475 (32-bit ARMv7)
**Audit Context:** Red Team Hardware Surface Analysis
**Date:** 2026-02-28

---

## 1. The EDL vs. EUB/EROM Distinction
In the Samsung ecosystem, "EDL" specifically refers to Qualcomm's Emergency Download mode (PID 9008). For Exynos devices like the SM-T377A, the equivalent is **EUB (Exynos USB Booting)** or **EROM**.

| Feature | Samsung Exynos (EUB/EROM) | Qualcomm (EDL) |
| :--- | :--- | :--- |
| **USB Hardware ID** | `USB\VID_04E8&PID_1234` | `USB\VID_05C6&PID_9008` |
| **Boot Layer** | Silicon BootROM | Primary Bootloader (PBL) |
| **Entry (Cable)** | Short D+ to GND | Short D+ to GND (EDL Cable) |
| **Primary Tool** | ChimeraTool / Z3X / exynos-usbdl | QFIL / QPST / bkerler-edl |

---

## 2. Hardware Triggers & Resistor JIGs
The SM-T377A uses a Micro-USB Interface Controller (MUIC) to multiplex the port based on the resistance detected on the **ID Pin (Pin 4)**.

### **MUIC Resistance Table (ID to GND)**
| Resistance | Detected Mode | Red Team / Diagnostic Application |
| :--- | :--- | :--- |
| **301 kΩ** | **Download Mode** | Forces Odin mode; bypasses volume/power button combinations. |
| **523 kΩ** | **UART (Boot Off)** | Provides read-only serial logs from `sboot` and kernel during boot. |
| **619 kΩ** | **SBOOT Console** | **Interactive Shell:** Allows command input to the secondary bootloader. |
| **910 kΩ** | **Auto-Ignition** | Forces the device to power on immediately upon cable insertion. |
| **442 kΩ** | **Factory USB** | Enables specialized factory USB diagnostic interfaces. |

### **The "EDL Cable" (D+ Short) Trick**
On the Exynos 3475, shorting **USB Data+ (Pin 3)** to **GND (Pin 5)** during the initial power-on sequence acts as a hardware override. This forces the SoC to bypass the eMMC boot attempt and drop into **Exynos USB Booting (EUB)** mode. 

---

## 3. SBOOT Interactive Console (619k UART)
Accessing the SBOOT console is the most powerful non-destructive path for analysis. By using a **619kΩ JIG**, a researcher can interrupt the boot process to reach an interactive shell.

### **Restricted Command Unlock**
Production firmware often "locks" the console. Two strings are known to unlock advanced diagnostic commands on this chipset:
1.  **Static Unlock:** `!@#$ASDFGHJKL:`
2.  **Service Mode:** `UPLOAD` (Enters RAM dump state)

### **Key SBOOT Shell Commands**
*   **`help`**: Lists available commands (varies by `debug_level`).
*   **`printenv` / `setenv`**: View and modify boot environment variables.
    *   *Note:* `setenv debug_level 0x494d` is a common primitive to enable "High" debug mode.
*   **`md [addr] [len]`**: Memory Display (hex dump of physical RAM).
*   **`mw [addr] [val]`**: Memory Write (write to physical RAM).
*   **`mmc read/write`**: Direct interaction with eMMC blocks.

---

## 4. Advanced BootROM Vulnerabilities
The Exynos 3475 belongs to a generation of SoCs vulnerable to pre-authentication memory corruption in the USB stack.

### **The Integer Overflow Bug**
Like the Exynos 8890/8895 (vulnerable to `exynos-usbdl`), the 3475 BootROM often implements USB buffer size checks using 32-bit addition without overflow protection.
*   **Vulnerability:** `buffer_start + size < buffer_end`
*   **Exploitation:** Providing a `size` such as `0xFFFFFFFF` overflows the addition, passing the check and allowing an attacker to write arbitrary data over the BootROM stack or function pointers in SRAM.
*   **Payload:** Successful exploitation results in code execution in **Monitor Mode (EL3)**, the highest privilege level on the SoC.

---

## 5. Software-Level Hardware Control
For an attacker with local shell access (UID 2000), hardware modes can sometimes be toggled via the **Service Mode** menu (`*#197328640#`) or the configuration menu (`*#9090#`).

*   **UART Enable:** Navigating to `*#9090#` and selecting "UART" forces the MUIC to stay in serial mode, enabling the console even if a standard USB cable is used later.
*   **CP RAM Logging:** In the SysDump menu (`*#9900#`), enabling "CP RAM Logging" (after bypassing the OTP) prepares the modem to dump its entire memory space to the `/data/log/` directory upon the next crash.

---

## 6. Verification & Final Insights (On-Device)
*   **MUIC Confirmed:** The device uses a **Silicon Mitus SM5703** MUIC (`/sys/class/sec/switch`).
*   **UART Routing:** Current `uart_sel` is `AP`, confirming the UART path is routed to the Application Processor for SBOOT console access.
*   **Mali Vulnerability:** The driver version is **r7p0-03rel0**, confirming it predates the fix for **CVE-2021-28663** (Alias TOCTOU).
*   **DRParser Blocker:** While `SecretCodeIME` is a "normal" permission, it is not held by the `shell` user, and the `KeyStringUpdateReceiver` is protected by `KEYSTRING` (signature|privileged), preventing direct exploitation from an unprivileged shell.

**Conclusion:** The SM-T377A (Exynos 3475) has a significantly larger hardware attack surface than its Qualcomm-based counterparts. While the bootloader is strictly locked by AT&T, the hardware-level EUB mode and SBOOT console provide viable pathways for subverting the secure boot chain.
