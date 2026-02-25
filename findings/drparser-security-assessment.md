# DRParser Security Assessment — SM-T377A (AT&T)

**Date**: Assessment performed on device serial `52030d9842d7a3bd`
**Package**: `com.sec.android.app.parser` v1.0.06 (targetSdk 23)
**UID**: 1000 (android.uid.system shared UID)
**APK**: `/system/app/DRParser/DRParser.apk` (74 KB, ODEX at `oat/arm/DRParser.odex` 312 KB)
**Build path**: `vendor/samsung/prebuilts/apps/SCParser/DRParser/MAIN/DRParser-release.apk`
**Device codename**: `gteslteatt` (ARM Cortex-A7)

---

## 1. Components

### Activity
- **`SecretCodeIME`** — Main activity (disguised as calculator UI). Handles secret dial codes entered via dialer.
  - Permission: `com.sec.android.app.parser.permission.SecretCodeIME` (protection: **normal**)
  - Cannot be launched from shell (UID 2000) — requires the permission
  - Listens for `android.intent.action.MAIN`

### Service
- **`ParseService`** — Bound service for keystring parsing/dispatch
  - Permission: `com.sec.android.app.parser.permission.SERVICE` (protection: **signature|privileged**)
  - Not startable directly (Error: "no service started")
  - Connected by other Samsung system apps via bind

### Receivers
- **`SecretCodeIMEReceiver`** — Handles `android.provider.Telephony.SECRET_CODE` broadcasts
  - Matches URI scheme `android_secret_code://`
  - Known codes: `MSL_OTKSL` (OTA keystring), plus codes routed to factory/service mode apps
- **`KeyStringUpdateReceiver`** — Updates keystring definitions

### No ContentProviders registered.

---

## 2. Permissions (Critical Subset)

### Directly Security-Relevant
| Permission | Impact |
|---|---|
| `com.qualcomm.permission.QCOM_DIAG` | **Qualcomm DIAG protocol access** |
| `com.sec.android.phone.permission.AT_COMMAND` | **AT command execution** |
| `android.permission.MODIFY_PHONE_STATE` | Modem state control |
| `android.permission.INSTALL_PACKAGES` | Silent app installation |
| `android.permission.MASTER_CLEAR` | Factory reset |
| `android.permission.CLEAR_APP_USER_DATA` | Wipe any app's data |
| `android.permission.INTERNAL_SYSTEM_WINDOW` | Overlay any window |
| `com.sec.android.diagmonagent.permission.DIAGMON` | DiagMon agent control |
| `com.sec.android.diagmonagent.permission.PROVIDER` | DiagMon data access |
| `com.sec.android.SAMSUNG_MODIFY_IPTABLES` | Firewall rule modification |
| `android.permission.WRITE_MEDIA_STORAGE` | Raw storage write |
| `android.permission.COPY_PROTECTED_DATA` | DRM-protected data access |
| `com.sec.android.permission.KNOX` | Knox framework access |
| `android.permission.sec.ENTERPRISE_DEVICE_ADMIN` | Enterprise admin |
| `android.permission.MANAGE_PROFILE_AND_DEVICE_OWNERS` | Device owner mgmt |
| `com.sec.android.app.wlantest.permission.USE_WLAN_TEST` | WiFi test mode |

### KEYSTRING Permissions (routes to Samsung service apps)
- `factorymode`, `DataCreate`, `phoneutil`, `lcdtest`, `selftestmode`
- `servicemodeapp`, `factory`, `rmt_exercise`, `modem.settings`
- `testingsettings`, `hiddenmenu`, `voltesettings`, `personalization`
- `bluetoothtest`, `WRITE_OTA_KEYSTRING`, `diagsetting` (Marvell)

---

## 3. DM Port Analysis (CRITICAL FINDING)

### Status: ACTIVE AND ACCESSIBLE FROM HOST

| Property | Value |
|---|---|
| Device node | `/dev/umts_dm0` (system:radio, `ssipc_device`) |
| USB config | `acm,dm,adb` |
| DIAG daemon | `/system/bin/diagexe` (PID 2209, UID system) |
| Windows port | **COM9** (`VID_04E8&PID_685D&DIAGSERD`) |
| Host access | **CONFIRMED** — COM9 opens at 115200 baud |
| Modem | **Shannon 308** (Samsung Exynos baseband) |
| RIL | Samsung RIL v3.0 (`/system/lib/libsec-ril.so`) |

### What DM Port Provides
The Samsung DM (Diagnostic Monitor) port over USB exposes:
1. **Shannon DIAG protocol** — Samsung's proprietary diagnostic interface
2. **NV item read/write** — Non-volatile modem configuration (carrier settings, band configs, IMEI-adjacent data)
3. **AT command pass-through** — Modem AT commands via DIAG framing
4. **Modem log capture** — Raw baseband logging
5. **RF calibration data access** — `ril.rfcal_date: 20161020`

### Modem Device Nodes
```
/dev/umts_boot0    — Modem boot interface (system:radio)
/dev/umts_csd      — Circuit-switched data (system:loop_radio)
/dev/umts_dm0      — Diagnostic monitor (system:radio)
/dev/umts_ipc0     — IPC channel (radio:radio)
/dev/umts_ramdump0 — Modem ramdump (system:radio)
/dev/umts_rfs0     — Remote file system (system:radio)
/dev/umts_router   — Router interface (system:radio)
/dev/smd4          — Shared memory driver (root:root)
```

### USB Gadget Serial Ports
```
/dev/ttyGS0-3 — system:system, gadget_serial_device SELinux type
```

---

## 4. UART Analysis

| Property | Value |
|---|---|
| `uart_sel` | AP (Application Processor) |
| `uart_en` | **0 (disabled)** |
| `usb_sel` | PDA |
| sysfs entries | `uart_en`, `uart_sel`, `usb_sel`, `usb_state`, `attached_dev`, `otg_test` |

### UART Enable Blocked
- `uart_en = 0` means UART console is disabled
- Writing to `/sys/class/sec/switch/uart_en` requires **system UID or root**
- Shell (UID 2000) cannot modify these sysfs nodes
- DRParser (UID 1000) could potentially write to these nodes if it had a code path to do so

---

## 5. EFS Access

**Shell cannot access EFS** — all reads return permission denied:
- `/efs/FactoryApp/keystr` — inaccessible
- `/efs/FactoryApp/factorymode` — inaccessible
- `/efs/carrier/HiddenMenu` — inaccessible
- `/efs/nv_data*` — inaccessible

DRParser code references these EFS paths:
- `/efs/FactoryApp/factorymode`
- `/efs/FactoryApp/keystrings_EFS.xml`
- `/efs/FactoryApp/keystrings_EFS_temp.xml`
- `/efs/carrier/HiddenMenu`
- `/efs/imei/mps_code.dat`

---

## 6. APK Assets — RSA Key Material

The APK contains cryptographic assets:
- `assets/exp_pri_key.txt` — RSA private exponent
- `assets/mod_pri_key.txt` — RSA modulus

These are used by the `Encrypt64` class, likely for keystring validation/encryption. Having the private key in the APK means the encryption is **reversible by anyone with the APK**.

---

## 7. Secret Code Dispatch

DRParser handles secret codes from the dialer (`*#<code>#`). The ODEX reveals:
- `android_secret_code://MSL_OTKSL` — OTA keystring / Master Subsidy Lock
- Factory mode toggle: `com.sec.android.app.factorymode.SEND_SPECIAL_KEYSTRING_ENABLED/DISABLED`
- `handleTestmodeSecretCode()` — Routes test mode codes
- `SET_FACTORY_SIM_MODE` intent action
- Hidden menu enable/disable via `/efs/carrier/HiddenMenu`

### Keystring Block Mechanism
- `isKeystringBlocked()` — Checks if a keystring is blocked
- `isJigOn()` — JIG (USB test fixture) detection bypasses keystring blocking
- `isHiddenKeyString()` — Hidden menu dependent keystrings
- `isFactoryMode()` — Factory mode check via `/efs/FactoryApp/factorymode`

---

## 8. Exploitation Relevance

### DM Port → Host-Side Attack (HIGH VALUE)
The DM port on COM9 is the most immediately exploitable finding:
1. **No authentication** on the DIAG protocol
2. Host tools (Samsung proprietary or open-source `libsamsung-ipc`) can communicate
3. Shannon DIAG protocol allows NV item read/write
4. Carrier lock parameters are stored in NV items
5. Band selection/network configuration accessible

### DRParser as Pivot (if UID 1000 achieved)
If ION UAF exploit achieves kernel write → `commit_creds` → system UID:
1. DRParser's AT_COMMAND permission unlocks modem command interface
2. QCOM_DIAG permission gives full DIAG access from on-device
3. Can write to `/efs/` partition (factory mode, keystrings, carrier config)
4. Can enable UART (`/sys/class/sec/switch/uart_en`)
5. Can install packages silently
6. Can modify iptables rules
7. Can trigger MASTER_CLEAR

### DRParser Does NOT Directly Help ION UAF
- DRParser is a user-space system app — it doesn't provide kernel primitives
- It cannot open ION device nodes differently than shell can
- Its value is **post-exploitation**: after gaining system UID, its permissions become available

### Privilege Escalation Path
```
Current:  shell (UID 2000) → limited access
Target:   system (UID 1000) → DRParser permissions unlocked
Method:   ION UAF → kernel write → commit_creds(prepare_kernel_cred(0)) 
          OR: ION UAF → overwrite task->cred->uid to 1000
Payoff:   AT commands, NV items, EFS write, UART enable, package install
```

---

## 9. Immediate Action Items

1. **Use COM9 DM port from host** — Install Samsung DIAG tools or use `libsamsung-ipc` to probe Shannon 308 NV items. This requires NO privilege escalation.

2. **Probe DM protocol** — Send Shannon DIAG identification frames to COM9 to confirm protocol version and available commands.

3. **Continue ION UAF development** — System UID is the gateway to DRParser's full capability set.

4. **RSA key extraction** — Pull and decode the private key from `exp_pri_key.txt`/`mod_pri_key.txt` to understand keystring encryption.

---

## 10. Key Device Properties

```
Modem:     Shannon 308 (persist.ril.modem.board)
RIL:       Samsung RIL v3.0
Firmware:  T377AUCU2AQGF
CSC:       T377AATT2AQGF
Product:   SM-T377AZKAATT
HW Rev:    REV0.3
Serial:    R52HA1JT2HE
IMSI SIM:  Present (ril.hasisim=1)
MFG Date:  2016-10-19
RF Cal:    2016-10-20
DM Verify: ro.config.dmverity=true
```
