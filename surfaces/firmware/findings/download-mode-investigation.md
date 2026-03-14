# SM-T377A Download Mode Investigation

## Date: 2026-03-02

## Summary

Device entered Download Mode. Investigation of USB interface, Odin protocol, and partition table.

## USB Device Profile

| Property | Value |
|----------|-------|
| VID:PID | 04E8:685D |
| Description | Samsung Mobile USB CDC Composite Device |
| Interfaces | 0: CDC Control (INT EP 0x83), 1: CDC Data (BULK OUT=0x02, IN=0x81) |
| MaxPacketSize | 512 bytes |
| Windows Driver | Samsung Mobile USB Modem (COM13) |
| COM Port | COM13 |

## Handshake Result

**ODIN/LOKE handshake confirmed successful on first attempt** — the device IS responsive in download mode and speaks the Odin protocol. The session subsequently became stuck due to a malformed session-start packet.

## PIT File (Partition Information Table)

**Extracted from CSC firmware tar** (`CSC_ATT_T377AATT2AQGF_CL11788437_QB14156771_REV00_user_low_ship.tar.md5`)

- File: `data/sm-t377a.pit` (3600 bytes)
- Magic: 0x12349876
- Project: LSI3475 (Exynos 3475)
- Gang: COM_TAR2
- 25 partitions on eMMC

### Partition Map

| # | Name | ID | Offset (blocks) | Blocks | Size | Flash File |
|---|------|----|-----------------|--------|------|------------|
| 0 | BOOTLOADER | 80 | 0 | 8192 | 4 MB | sboot.bin |
| 1 | PIT | 70 | 34 | 16 | 8 KB | - |
| 2 | MD5HDR | 71 | 50 | 2048 | 1 MB | md5.img |
| 3 | BOTA0 | 1 | 8192 | 8192 | 4 MB | - |
| 4 | BOTA1 | 2 | 16384 | 8192 | 4 MB | - |
| 5 | EFS | 3 | 24576 | 40960 | 20 MB | efs.img |
| 6 | CPEFS | 4 | 65536 | 16384 | 8 MB | cpefs.img |
| 7 | m9kefs1 | 5 | 81920 | 8192 | 4 MB | m9kefs1.bin |
| 8 | m9kefs2 | 6 | 90112 | 8192 | 4 MB | m9kefs2.bin |
| 9 | m9kefs3 | 7 | 98304 | 8192 | 4 MB | m9kefs3.bin |
| 10 | CARRIER | 8 | 106496 | 8192 | 4 MB | carrier.img |
| 11 | PARAM | 9 | 114688 | 16384 | 8 MB | param.bin |
| 12 | **BOOT** | **10** | **131072** | **26624** | **13 MB** | boot.img |
| 13 | **RECOVERY** | **11** | **157696** | **30720** | **15 MB** | recovery.img |
| 14 | OTA | 12 | 188416 | 16384 | 8 MB | - |
| 15 | CDMA-RADIO | 13 | 204800 | 8192 | 4 MB | modem_cdma.bin |
| 16 | **RADIO** | **14** | **212992** | **81920** | **40 MB** | modem.bin |
| 17 | TOMBSTONES | 15 | 294912 | 8192 | 4 MB | tombstones.img |
| 18 | TDATA | 16 | 303104 | 8192 | 4 MB | tdata.img |
| 19 | PERSISTENT | 17 | 311296 | 2048 | 1 MB | |
| 20 | PERSDATA | 18 | 313344 | 24576 | 12 MB | persdata.img |
| 21 | RESERVED2 | 19 | 337920 | 6144 | 3 MB | - |
| 22 | **SYSTEM** | **20** | **344064** | **6144000** | **3000 MB** | system.img |
| 23 | CACHE | 21 | 6488064 | 2097152 | 1024 MB | cache.img |
| 24 | **USERDATA** | **22** | **8585216** | **0** | **remaining** | userdata.img |

### Security-Relevant Partitions

- **BOOTLOADER (sboot.bin)**: Samsung secure bootloader — carrier lock enforcement lives here
- **PARAM (param.bin)**: Samsung parameters — boot flags, debug settings, warranty bit
- **EFS**: IMEI, modem calibration, network lock data (PN lock is here)
- **BOOT**: Kernel + ramdump — we already have this from firmware
- **SYSTEM**: Full Android system — we already have this from firmware
- **BOTA0/BOTA1**: Boot area for OTA updates — potential attack surface?
- **PERSISTENT/PERSDATA**: Persistent data across factory resets

## Driver Issue

Heimdall (v1.4.0) cannot access the device because Samsung's USB CDC driver claims the USB device, and libusb gets error -12 (NOT_SUPPORTED) when trying to open it.

### Solution: Install WinUSB via Zadig

1. Run: `C:\InfoSec\Samsung\Heimdall Suite\Drivers\zadig.exe`
2. Options → "List All Devices"
3. Select "SAMSUNG Mobile USB CDC Composite Device" (VID 04E8 / PID 685D)
4. Target driver: **WinUSB** (v6.x)
5. Click **"Replace Driver"**
6. After success, run: `data\download_mode_toolkit.bat detect`

### After Driver Install

```bat
REM Verify device detected
"C:\InfoSec\Samsung\Heimdall Suite\heimdall.exe" detect

REM Download PIT directly from device (to compare with firmware PIT)
"C:\InfoSec\Samsung\Heimdall Suite\heimdall.exe" download-pit --output data\sm-t377a-live.pit --no-reboot

REM Close download screen (stays in DL mode)
"C:\InfoSec\Samsung\Heimdall Suite\heimdall.exe" close-pc-screen --no-reboot
```

### Reverting Driver

Device Manager → Find Samsung device → Update Driver → "Let me pick" → Select original Samsung driver

Or unplug/replug USB and Windows should re-detect with Samsung driver.

## What Download Mode Can Do For Us

### Available Now (from firmware tars)
- ✅ PIT file extracted and parsed
- ✅ boot.img, recovery.img, system.img available from AP tar
- ✅ sboot.bin (bootloader), param.bin available from BL tar
- ✅ modem.bin available from CP tar

### Available After WinUSB Driver Install
- 📋 Download PIT directly from device (verify matches firmware)
- ⚠️ **Flash partitions** — but carrier lock blocks unsigned images
- ❓ **Dump live partitions** — Heimdall 1.4.0 lacks dump command; need 1.4.2+

### Potential Attack Vectors via Download Mode

1. **PARAM partition modification**: Could toggle debug flags, warranty bit, or boot parameters. `param.bin` from BL tar is 686KB — needs RE to understand format.

2. **Boot.img modification + flash**: If we could sign or bypass signature check, modifying boot.img to disable SELinux or add root shell would be trivial. **Blocked by carrier lock/signature verification.**

3. **EFS partition**: Contains network lock (PN) data. Modifying/reflashing EFS could remove carrier lock. **Extremely risky — can brick modem.**

4. **Bootloader analysis**: `sboot.bin` (1.4MB) can be reverse-engineered to understand:
   - Carrier lock enforcement mechanism
   - Signature verification implementation
   - Debug/engineering mode backdoors
   - JTAG/UART enable conditions

5. **Samsung ODIN protocol exploit**: The download mode bootloader itself could have vulnerabilities (buffer overflows in filename parsing, integer overflows in size fields, etc.). This runs BEFORE the carrier lock check.

## Bootloader (sboot.bin) Security Analysis

Extracted from BL firmware tar. 1,378 KB, ARM32. Contains full Samsung download mode handler.

### Function Names Found (security-relevant)

| Function | Purpose |
|----------|---------|
| `Verify_Binary_Signature` | Main binary signature verification |
| `Verify_Binary_Signature_spk` | Samsung Platform Key verification |
| `Verify_Binary_Config_bin_sw` | Config binary software verification |
| `board_uart_rustproof` | UART debug port protection |
| `board_pre_usb_download` | USB download preparation |
| `s5p_check_download` | Download mode permission check |
| `do_download` | Main download handler |
| `process_rqt_pit` | PIT request handler (Odin protocol) |
| `pit_check_integrity` | PIT integrity verification |
| `pit_check_signature` | PIT signature check |
| `pit_check_system_signature` | System PIT signature |
| `check_rustproof` | Rustproof mode check |
| `sm5703_check_jig_adc_value` | JIG cable ADC detection (SM5703 MUIC) |
| `update_frp_image_lock_value` | FRP image lock update |
| `update_frp_persist_lock_value` | FRP persistent lock update |
| `s5p_check_reboot_mode` | Reboot mode check |
| `load_kernel` | Kernel loading |
| `set_oneshot_recovery` | Recovery mode trigger |
| `emmc_rpmb_*` | eMMC Replay Protected Memory Block ops |

### Download Mode Blocking (3 Layers)

1. **CC Mode** (Country Code / Carrier):
   - `"Custom binary blocked by CC Mode"`
   - `"DOWNLOAD IS BLOCKED BY CC MODE"`
   - `"[CC MODE] Failed. decryption"` — involves decryption
   - `"[CC MODE] Failed. Invalid Magic"` — has magic validation
   - Reads from PARAM partition

2. **FRP Lock** (Factory Reset Protection):
   - `"Custom binary blocked by FRP Lock"`
   - `"Custom Binary(%s) Blocked By FRP Lock"`
   - `"FRP LOCK: %s"` — status display
   - `"FRP FAILURE!"` — on lock failure

3. **MDM Mode** (Mobile Device Management):
   - `"MDM MODE. CAN'T DOWNLOAD."`
   - `"MDM SET : PREVENT DOWNLOAD . CASE:%d"`

### eFuse Security Mechanisms

| eFuse Setting | Purpose |
|---------------|---------|
| `skip_aes` | **Skip AES verification** — `[EFUSE] Set skip_aes 0x%X - 0x%X!` |
| `jtag_lock` | JTAG hardware debug lock — `[EFUSE] Set jtag_lock 0x%X - 0x%X!` |
| `preorder_key` | OEM preorder key — `[EFUSE] Set preorder key 0x%X - 0x%X!` |
| `model_id` | Model identification — `[EFUSE] Set model_id(major) 0x%X - 0x%X!` |
| `warranty_bit` | Knox warranty fuse — `[EFUSE] Set warranty bit(%d)` |
| `commercial_bit` | Commercial vs engineering — `[EFUSE] commercial bit is not set. skip..` |
| `RB_count0/1` | Rollback counters — `[EFUSE] error: over RB_count0 (%d)!` |

**Critical**: `"[EFUSE] it's not commercial, skip..."` — non-commercial units skip security checks!

### PARAM Partition Stored Values

The PARAM partition (`param.bin` / `adv-env.img`) stores:

| Key | Purpose |
|-----|---------|
| `REBOOT_MODE` | Boot mode selection |
| `SWITCH_SEL` | USB/UART switch selection |
| `DEBUG_LEVEL` | Debug verbosity → `androidboot.debug_level=0x%x` |
| `SUD_MODE` | Samsung Upload Debug mode |
| `ODIN_DOWNLOAD` | Download flag → `androidboot.odin_download=%d` |

Current `adv-env.img` content: `console=ram loglevel=4` (stock values)

### Kernel Command Line Parameters (from sboot)

The bootloader passes to kernel:
- `androidboot.debug_level=0x%x` — from PARAM DEBUG_LEVEL
- `androidboot.odin_download=%d` — from PARAM ODIN_DOWNLOAD
- `androidboot.warranty_bit=%d` — from eFuse
- `androidboot.serialno=%x%08x` — from EXYNOS3475 LOT ID
- `softlockup_panic=0` — softlockup watchdog disabled
- `console=ram loglevel=4` — from adv-env.img

### Protocol Handlers

- **ODIN**: `"- Odin is connected!"` — standard Samsung download
- **THOR**: `"- Thor is connected!"` — alternate Samsung protocol
- Both handlers present in sboot

### JIG Cable Handling

- `"JIG cable was attached. reboot!!!"` — JIG cable triggers reboot
- `"non chargable jig, bypass check power"` — non-charging JIG bypasses power check
- `sm5703_check_jig_adc_value` — reads MUIC ADC for JIG detection
- MUIC chip confirmed as SM5703 (not SM5502 as previously thought — sboot strings say SM5703)

### Signature Bypass Strings

- `"custom binary! system rp skip checking.."` — system rustproof skip
- `"custom binary! kernel rp skip checking.."` — kernel rustproof skip
- `"Secure Download : Enabled"` — secure download is active
- Certificates found at offset 0x012c0d (1521 bytes)

### Potential Download Mode Attack Vectors

1. **Odin protocol buffer overflow**: The `process_rqt_pit` and `do_download` handlers parse binary data from USB. Buffer overflows in filename/size parsing could give code execution in sboot context (pre-kernel, no SELinux, no ASLR).

2. **CC Mode bypass**: CC Mode reads PARAM partition and does decryption + magic check. If we can understand the crypto or find the key, we could craft valid CC Mode data.

3. **PIT processing**: `pit_check_integrity`, `pit_flash_binary`, `pit_update_bootloader_ota` — malformed PIT data could trigger vulnerabilities.

4. **Signature verification weakness**: Three separate verification paths (`Verify_Binary_Signature`, `_spk`, `_Config_bin_sw`). Implementation flaws in any path could allow bypass.

5. **THOR protocol**: Less-tested alternative protocol. May have weaker validation.

**All of these require deeper RE with Ghidra/IDA on sboot.bin (ARM32, load at 0x02024000 typical for Exynos).**

## Tools Created

- `src/odin_proto.py` — Python Odin/LOKE protocol client (handshake, PIT download/parse)
- `src/extract_pit.py` — Extract PIT from Samsung firmware tar.md5 files
- `src/usb_enum.py` — USB device enumeration via pyusb
- `src/analyze_firmware.py` — Firmware binary analysis (sboot, param)
- `src/sboot_deep_analysis.py` — Deep sboot bootloader string analysis
- `data/download_mode_toolkit.bat` — Batch script for Heimdall operations
- `data/winusb_driver/samsung_dl_winusb.inf` — WinUSB INF (needs admin to install)
- `data/sm-t377a.pit` — Extracted PIT file (3600 bytes, 25 partitions)
- `data/sboot.bin` — Extracted bootloader (1.4 MB)
- `data/param.bin` — Extracted parameter partition (670 KB)
- `data/adv-env.img` — Kernel boot parameters from param
