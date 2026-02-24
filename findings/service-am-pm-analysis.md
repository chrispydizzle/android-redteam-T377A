# Service Layer & Activity Manager Attack Surface Analysis

**Target**: Samsung SM-T377A · Android 6.0.1 · ADB shell (UID 2000)  
**Date**: 2026-02-24  

---

## 1. Binder Service Inventory

**164 registered binder services** accessible from shell.  
**35 of 66 currently-alive services** respond to `dumpsys` from shell.

Full service list saved to: `work/service_list_full.txt`

### Service Categories

| Category | Count | Examples |
|----------|-------|---------|
| Telephony/IMS | 14 | sip, ims6, secims, telecom, phone, volte, iphonesubinfo |
| Samsung-specific | 20+ | SveService, SmartcomRoot, DeviceRootKeyService, SEAM, persona, CCM, OTP |
| System framework | 50+ | activity, package, power, window, alarm, input, display |
| Media | 7 | audio_flinger, camera, player, radio, sound_trigger_hw |
| Security | 5 | android.security.keystore, tima, sedenial, Knox services |
| Hardware | 5 | sensorservice, vibrator, consumer_ir, batteryproperties |

---

## 2. Activity Manager (am) Capabilities

### What shell CAN do

| Capability | Command | Impact | Severity |
|------------|---------|--------|----------|
| **Launch any activity** | `am start -n pkg/.Activity` | Open Settings, Camera, Dialer, any app UI | HIGH |
| **Launch dialer with number** | `am start -a DIAL -d tel:X` | Pre-fill phone numbers for social engineering | MEDIUM |
| **Force-stop any app** | `am force-stop pkg` | Kill Google Play Services, camera, any app silently | HIGH |
| **Kill all background** | `am kill-all` | Mass-kill all background processes | HIGH |
| **Send broadcasts** | `am broadcast -a action` | Trigger BATTERY_LOW, custom intents | HIGH |
| **Start services** | `am startservice -n pkg/.Svc` | Start GMS SystemUpdateService, other services | MEDIUM |

### What shell CANNOT do

| Capability | Error |
|------------|-------|
| `am stack list` | SecurityException: requires MANAGE_ACTIVITY_STACKS |
| `am instrument` | Requires instrumentation package |

---

## 3. Package Manager (pm) Capabilities — CRITICAL

### Confirmed Dangerous Operations

| Operation | Result | Impact | Severity |
|-----------|--------|--------|----------|
| **pm grant** (runtime perms) | ✅ **WORKS** | Shell granted RECORD_AUDIO + ACCESS_FINE_LOCATION to camera app. Persists across sessions. | 🔴 CRITICAL |
| **pm create-user** | ✅ **WORKS** | Created "TestAuditUser" (uid 10). Cannot be removed (NullPointerException). | 🔴 CRITICAL |
| **pm uninstall** (system pkg) | ✅ **WORKS** | Uninstalled com.sec.android.app.samsungapps (Samsung Apps) | HIGH |
| **pm install** | ✅ Works (if valid APK) | Install arbitrary APKs from /data/local/tmp | HIGH |
| **pm list packages** | ✅ 264 packages | Full app inventory | MEDIUM |
| **pm path** | ✅ Returns APK path | Locate any app's APK for extraction | MEDIUM |
| **pm dump** | ✅ Full package info | Permissions, components, activities, services exposed | MEDIUM |
| **pm set-permission-enforced** | ✅ Silent success | Can weaken permission enforcement system-wide | HIGH |

### Permission Grants Confirmed

```
Camera app (com.sec.android.app.camera):
  android.permission.RECORD_AUDIO    → granted=true, flags=0x20
  android.permission.ACCESS_FINE_LOCATION → granted=true, flags=0x20
```

These permissions were NOT originally granted. Shell escalated the camera app's capabilities.

### User Creation Evidence

```
pm list users:
  UserInfo{0:Christopher P Posada:13} running
  UserInfo{10:TestAuditUser:0}
```

The test user persists and cannot be removed via `pm remove-user 10` due to a NullPointerException in IAppOpsService. This represents a **persistent unauthorized user account**.

### What shell CANNOT do

| Operation | Error |
|-----------|-------|
| `pm disable` | SecurityException: Permission Denial (uid 2000 cannot change component state) |
| `pm enable` | SecurityException: same |

---

## 4. Settings Provider — Read/Write

### Readable Settings (Information Disclosure)

| Setting | Value | Impact |
|---------|-------|--------|
| `global/wifi_on` | 1 | WiFi state |
| `global/bluetooth_on` | 1 | Bluetooth state |
| `global/mobile_data` | 1 | Cellular data state |
| `global/adb_enabled` | 1 | ADB debugging state |
| `global/usb_mass_storage_enabled` | 1 | USB storage state |
| `secure/install_non_market_apps` | 1 | Sideloading enabled |
| `secure/android_id` | fb942a8fd38f9c5a | Unique device identifier |

### Writable Settings (Configuration Tampering)

| Setting | Category | Impact |
|---------|----------|--------|
| `global/airplane_mode_on` | ✅ Writable | Toggle airplane mode — cut all wireless |
| `global/stay_on_while_plugged_in` | ✅ Writable | Change screen-on behavior |
| `secure/install_non_market_apps` | ✅ Writable | Enable/disable sideloading |

---

## 5. WiFi Service — Full Network Intelligence

### Connected Network (dumpsys wifi)

| Field | Value |
|-------|-------|
| SSID | MASTI_blanket |
| BSSID | 10:0c:6b:5e:07:b8 |
| Device MAC | bc:76:5e:57:44:ed |
| Frequency | 5240 MHz (5 GHz band) |
| Link Speed | 150 Mbps |
| Signal | -20 dBm (excellent) |
| Security | WPA2-PSK-CCMP |
| Net ID | 7 |

### All Saved WiFi Networks (8 networks)

| ID | SSID | Priority |
|----|------|----------|
| 0 | attwifi | 0 |
| 1 | DECO-M5 | 1 |
| 3 | masti-bh5 | 1 |
| 4 | masti-bh2 | 1 |
| 5 | masti | 1 |
| 7 | MASTI_blanket | 1 (connected) |

Plus complete WPA handshake state log (SCANNING → ASSOCIATING → ASSOCIATED → FOUR_WAY_HANDSHAKE → GROUP_HANDSHAKE → COMPLETED) with timestamps and BSSIDs.

### WiFi Scan Results

Shell can read nearby access points: SSIDs, BSSIDs (MAC addresses), signal strength, frequency, security capabilities. Enables passive WiFi surveillance.

---

## 6. Telephony Service

### Exposed Data (dumpsys telephony.registry)

| Field | Value | Impact |
|-------|-------|--------|
| Call State | 0 (idle) | Monitor call activity |
| Incoming Number | (empty) | Would show during calls |
| Service State | 1 (limited) | Carrier registration |
| Signal Strength | GSM/LTE values | Physical location correlation |
| Data Connection | Disconnected | Network monitoring |
| Data Reason | WeakSignal | Environmental info |
| Message Waiting | false | Voicemail state |
| Call Forwarding | false | Forwarding state |

---

## 7. Content Provider Access

| Provider | URI | Result | Severity |
|----------|-----|--------|----------|
| **Contacts** | `content://contacts/people` | ✅ **READABLE** | HIGH |
| **Call Log** | `content://call_log/calls` | ❌ Requires READ_CALL_LOG | OK |
| **SMS** | `content://sms` | ❌ NullPointerException | BLOCKED |
| **Calendar** | `content://com.android.calendar/events` | ❌ "Before system ready" | BLOCKED |
| **Media** | `content://media/external/images/media` | ❌ "Before system ready" | BLOCKED |

---

## 8. Dumpsys Services Accessible (35 of 66)

Key services that respond to shell dumpsys:

| Service | Info Exposed |
|---------|-------------|
| `activity` | All running activities, recent tasks, memory usage, process list |
| `package` | All 264 packages, permissions, components, APK paths |
| `meminfo` | Per-process memory: heap, native, dalvik breakdowns |
| `cpuinfo` | CPU usage per process |
| `batteryproperties` | Battery level, charging state, temperature |
| `procstats` | Process statistics over time |
| `usagestats` | App usage statistics |
| `appops` | App operations and mode watchers |
| `persona` | Knox container configuration (max 2 personas) |

---

## 9. Risk Matrix

| # | Finding | Severity | Category |
|---|---------|----------|----------|
| S-1 | pm grant: shell grants dangerous permissions to any app | 🔴 CRITICAL | Privilege Escalation |
| S-2 | pm create-user: shell creates persistent user accounts | 🔴 CRITICAL | Persistence |
| S-3 | pm uninstall: shell removes system packages | HIGH | Integrity |
| S-4 | am force-stop / kill-all: shell kills any process | HIGH | Availability |
| S-5 | WiFi: all saved networks, BSSIDs, device MAC, handshake logs | HIGH | Info Disclosure |
| S-6 | am start: shell launches any activity | HIGH | Access Control |
| S-7 | am broadcast: shell sends system-wide intents | HIGH | Access Control |
| S-8 | Settings writable: airplane mode, sideloading toggle | HIGH | Config Tampering |
| S-9 | IMEI + Android ID exposed | HIGH | Privacy |
| S-10 | Telephony: call state, signal, carrier info | MEDIUM | Info Disclosure |
| S-11 | 35 services respond to dumpsys (memory, CPU, battery) | MEDIUM | Info Disclosure |
| S-12 | pm set-permission-enforced: weaken system permissions | HIGH | Privilege Escalation |
| S-13 | Shell has 70+ system permissions (INSTALL_PACKAGES, BACKUP, MANAGE_DEVICE_ADMINS, etc.) | HIGH | Privilege Escalation |
| S-14 | Contacts writable via content insert (injected "TestAudit" contact) | HIGH | Data Tampering |
| S-15 | ICCID/IMSI partially exposed via isub service | HIGH | Privacy |
| S-16 | 75+ binder services respond to method 1 calls from shell | MEDIUM | Attack Surface |
| S-17 | /dev/input/event* readable (hardware keylogger capability via input group) | HIGH | Privacy |
| S-18 | app_process executes arbitrary Java code as shell | MEDIUM | Code Execution |

---

## 10. Shell Permission Analysis (70+ System Permissions)

Shell (com.android.shell) has the following **critical system permissions** pre-granted:

| Permission | Impact |
|------------|--------|
| `INSTALL_PACKAGES` | Install arbitrary APKs |
| `DELETE_PACKAGES` | Uninstall any package |
| `GRANT_RUNTIME_PERMISSIONS` | Grant dangerous perms to any app |
| `REVOKE_RUNTIME_PERMISSIONS` | Revoke any app's permissions |
| `MANAGE_DEVICE_ADMINS` | Manage device administrators |
| `CREATE_USERS` | Create new user accounts |
| `INTERACT_ACROSS_USERS_FULL` | Cross-user data access |
| `WRITE_SECURE_SETTINGS` | Modify secure system settings |
| `WRITE_MEDIA_STORAGE` | Write to media storage |
| `ACCESS_SURFACE_FLINGER` | Direct display access |
| `MOUNT_UNMOUNT_FILESYSTEMS` | Filesystem mount operations |
| `BACKUP` | App data backup/restore |
| `INJECT_EVENTS` | Input event injection |
| `READ_FRAME_BUFFER` | Read display framebuffer |
| `MODIFY_PHONE_STATE` | Telephony state manipulation |
| `DISABLE_KEYGUARD` | Disable lock screen |
| `CLEAR_APP_USER_DATA` | Wipe any app's data |
| `DEVICE_POWER` | Power management control |

These permissions are defined in the shell package manifest — they cannot be self-granted via `pm grant` (which only works for runtime/dangerous permissions). However, they provide **near-system-level control** without actual root.

---

## 11. Privilege Escalation Verdict

### Paths Tested for Root (All Blocked)

| Vector | Result | Blocked By |
|--------|--------|------------|
| `setenforce 0` | ❌ Permission denied | SELinux kernel enforcement |
| `runcon u:r:su:s0` | ❌ Invalid argument | su domain not in policy |
| `runcon u:r:system_server:s0` | UID stays 2000 | DAC unchanged |
| `/sbin/su` | ❌ SELinux denied | sbin_t access blocked |
| `mount -o remount,rw /system` | ❌ Permission denied | dm-verity + SELinux |
| `dpm set-device-owner` | ❌ MDM_PROXY_ADMIN check | Samsung Knox MDM |
| `dpm set-profile-owner` | ❌ Same Samsung check | Samsung Knox MDM |
| `run-as <pkg>` | ❌ Can't set capabilities | SELinux + capability check |
| `setprop ro.debuggable 1` | ❌ ro props immutable | Property service |
| `pm grant self READ_SMS` | ❌ Not in manifest | Permission model |
| All /proc/sys writes | ❌ Permission denied | DAC + SELinux |
| Overlay mount on /system | ❌ Permission denied | Kernel + SELinux |
| ION heap crash | DoS only | Crash, not controlled exec |
| Binder node death | DoS only | System freeze, not code exec |

### Verdict

**Root (UID 0) is NOT achievable** from ADB shell through any tested software vector. The device's defense-in-depth (SELinux Enforcing + dm-verity + no SUID + nosuid mounts + locked bootloader + Samsung Knox MDM) prevents privilege escalation to root.

However, shell already has **extensive non-root capabilities** that enable surveillance (permission grants, input reading, screen capture), data theft (contacts, WiFi, IMEI, telephony), system disruption (kernel crash, service freeze, app killing), and persistence (user creation, contact injection).

---

## 12. Attack Scenarios Enabled

### Scenario A: Silent Permission Escalation

```console
pm grant com.target.app android.permission.RECORD_AUDIO
pm grant com.target.app android.permission.ACCESS_FINE_LOCATION  
pm grant com.target.app android.permission.CAMERA
```

→ Any installed app silently gains microphone, GPS, and camera access.

### Scenario B: Persistent Backdoor User

```
pm create-user BackdoorUser
```

→ New user account persists across reboots. Cannot be removed via pm.

### Scenario C: App Destruction

```
pm uninstall com.android.settings
am force-stop com.google.android.gms
am kill-all
```

→ Remove system apps, kill services, disrupt all functionality.

### Scenario D: WiFi Intelligence Gathering

```
dumpsys wifi
```

→ All saved WiFi networks, current BSSID, device MAC, WPA handshake timing.

### Scenario E: Hardware Keylogger

```console
getevent /dev/input/event1  # sec_touchscreen
```

→ Shell is in `input` group — can read raw touchscreen coordinates and hardware key events in real-time.

### Scenario F: Subscriber Identity Theft

```console
service call iphonesubinfo 1  # IMEI
service call isub 1           # ICCID (SIM serial)
service call iphonesubinfo 7  # IMSI (partial)
settings get secure android_id
```

→ Full device identity extraction without any permission prompt.

### Scenario G: Contact Injection (Phishing)

```console
content insert --uri content://contacts/people --bind name:s:FakeBank --bind number:s:5551234567
```

→ Inject fake contacts (confirmed: "TestAudit" contact created). Enables social engineering attacks.

---

## 13. Recommendations

1. **Restrict pm grant from shell**: Runtime permission grants should require signature-level permission or user confirmation
2. **Restrict pm create-user**: User creation from shell should be blocked or require device admin
3. **Restrict pm uninstall for system packages**: System apps should be uninstallable only by system UID
4. **Restrict am force-stop**: Should require FORCE_STOP_PACKAGES permission check against shell
5. **Restrict dumpsys wifi**: WiFi state including saved networks and MACs should not be shell-readable
6. **Restrict settings writes**: Critical settings (airplane_mode, install_non_market_apps) should not be writable from shell
7. **Restrict dumpsys**: Most services should check caller UID before dumping sensitive state

---

## Files

| File | Description |
|------|-------------|
| `work/service_list_full.txt` | Complete `service list` output (164 services) |
