# Hardening Recommendations

**Samsung SM-T377A · Android 6.0.1 · SPL 2017-07-01**

← [Back to Index](../README.md)

---

### 🔴 Priority 1: Critical (Immediate Action Required)

#### 1.1 — Replace or Upgrade the Device
> Android 6.0.1 with July 2017 patches is **irrecoverably insecure**. No amount of configuration changes can mitigate the hundreds of unpatched CVEs. **The single most impactful action is to replace this device** with one running Android 13+ with current security patches.

#### 1.2 — Enable Full-Disk Encryption
```
# If the device must remain in service temporarily:
Settings → Security → Encrypt tablet
```
> The device stores all data in plaintext. If physically accessed, all data (including credentials, tokens, app data) can be trivially extracted.

#### 1.3 — Remove Privilege Escalation Tools
The following files in `/data/local/tmp/` should be **immediately deleted**:
- `su`, `superuser.apk`, `busybox`
- `psneuter`, `rageagainstthecage`, `zergRush`
- `tsd_client`, `tsd_client_arm32`

```bash
adb shell rm /data/local/tmp/su
adb shell rm /data/local/tmp/superuser.apk
adb shell rm /data/local/tmp/busybox
adb shell rm /data/local/tmp/psneuter
adb shell rm /data/local/tmp/rageagainstthecage
adb shell rm /data/local/tmp/zergRush
adb shell rm /data/local/tmp/tsd_client
adb shell rm /data/local/tmp/tsd_client_arm32
```

#### 1.4 — Uninstall Offensive Security Applications
Remove all penetration testing tools if the device is used for anything other than authorized security testing:
- Hijacker, cSploit, Nexmon, WiGLE
- Magisk, Z4Root, Superuser
- Kali NetHunter (Store + Terminal)
- Rucky, Gamma

### 🟠 Priority 2: High (Address Within 24-48 Hours)

#### 2.1 — Disable Wireless Attack Surfaces (Critical Mitigation)
Since the device is vulnerable to Remote Root via Bluetooth and WiFi, these **must** be disabled if not strictly required.

```bash
# Disable Bluetooth Service
adb shell service call bluetooth_manager 8  # disable()
adb shell pm disable com.android.bluetooth

# Disable WiFi (if offline use is acceptable)
adb shell svc wifi disable
adb shell pm disable com.android.providers.settings
```

#### 2.2 — Disable ADB and Developer Options
```bash
adb shell settings put global adb_enabled 0
adb shell settings put global development_settings_enabled 0
```
> Or: Settings → Developer Options → Toggle OFF, then Settings → About → tap Build Number 7x to re-hide.

#### 2.2 — Reduce Screen Lock Timeout
```bash
adb shell settings put secure lock_screen_lock_after_timeout 5000  # 5 seconds
adb shell settings put global stay_on_while_plugged_in 0           # Don't stay awake
```

#### 2.3 — Restrict USB Configuration
```bash
adb shell setprop persist.sys.usb.config "acm,dm"  # Remove ADB from USB config
```

#### 2.4 — Set Strong Screen Lock
Ensure a PIN (6+ digits), password, or pattern is configured:
> Settings → Lock Screen → Screen lock type → Password

### 🟡 Priority 3: Medium (Address Within 1 Week)

#### 3.1 — Disable Unnecessary Services
- Disable Bluetooth if not required
- Disable WiFi Direct (p2p0 interface)
- Disable NFC if present
- Review and disable unnecessary Samsung daemons

#### 3.2 — Enforce HTTPS-Only Traffic
- Install and configure a firewall app to block port 80 traffic
- Ensure all applications use TLS/HTTPS

#### 3.3 — Review Application Permissions
- Audit all 255 installed packages for excessive permissions
- Remove unused system bloatware where possible
- Disable `install_non_market_apps` (unknown sources)

#### 3.4 — Configure Backup Properly
- Ensure backups are encrypted
- Use only trusted backup transports
- Verify backup destination security

### 🟢 Priority 4: Ongoing Maintenance

#### 4.1 — Network Monitoring
- Monitor for unauthorized outbound connections
- Audit DNS queries for data exfiltration
- Verify all traffic to Meta/Facebook/Google is expected

#### 4.2 — Filesystem Integrity Monitoring
- Periodically check `/data/local/tmp/` for new binaries
- Monitor for unauthorized APK installations
- Verify `/system` partition remains read-only

#### 4.3 — Access Logging
- The `auditd` service is running — ensure logs are being collected and reviewed
- Forward logs to a central SIEM if available

---
