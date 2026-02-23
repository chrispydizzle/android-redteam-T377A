import sys, os
from androguard.core.apk import APK

apk_dir = r"C:\InfoSec\android-redteam\findings\apks"
results = []

for fname in os.listdir(apk_dir):
    if not fname.endswith('.apk'):
        continue
    fpath = os.path.join(apk_dir, fname)
    try:
        a = APK(fpath)
        pkg = a.get_package()
        ver = a.get_androidversion_name()
        min_sdk = a.get_min_sdk_version()
        target_sdk = a.get_target_sdk_version()
        perms = a.get_permissions()
        activities = a.get_activities()
        receivers = a.get_receivers()
        services = a.get_services()
        providers = a.get_providers()
        is_debuggable = a.get_effective_target_sdk_version() if hasattr(a, 'get_effective_target_sdk_version') else 'N/A'
        
        # Check for dangerous permissions
        dangerous = [p for p in perms if any(d in p.upper() for d in [
            'CAMERA', 'RECORD_AUDIO', 'READ_CONTACTS', 'WRITE_CONTACTS',
            'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION', 'READ_PHONE_STATE',
            'CALL_PHONE', 'READ_CALL_LOG', 'WRITE_CALL_LOG', 'READ_SMS', 'SEND_SMS',
            'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE', 'INTERNET',
            'ACCESS_WIFI_STATE', 'CHANGE_WIFI_STATE', 'BLUETOOTH', 'BLUETOOTH_ADMIN',
            'NFC', 'BODY_SENSORS', 'SYSTEM_ALERT_WINDOW', 'WRITE_SETTINGS',
            'INSTALL_PACKAGES', 'DELETE_PACKAGES', 'MOUNT_UNMOUNT_FILESYSTEMS',
            'ACCESS_SUPERUSER', 'RECEIVE_BOOT_COMPLETED'
        ])]
        
        # Check exported components
        exported_activities = []
        for act in activities:
            # Simple check
            exported_activities.append(act)
        
        print(f"\n{'='*80}")
        print(f"APK: {fname}")
        print(f"{'='*80}")
        print(f"Package: {pkg}")
        print(f"Version: {ver}")
        print(f"Min SDK: {min_sdk}")
        print(f"Target SDK: {target_sdk}")
        print(f"Total Permissions: {len(perms)}")
        print(f"Dangerous/Notable Permissions ({len(dangerous)}):")
        for p in sorted(dangerous):
            print(f"  - {p}")
        print(f"Activities: {len(activities)}")
        print(f"Services: {len(services)}")
        print(f"Receivers: {len(receivers)}")
        print(f"Providers: {len(providers)}")
        
        # Check for specific security concerns
        concerns = []
        perm_str = ' '.join(perms).upper()
        if 'ACCESS_SUPERUSER' in perm_str or 'SUPERUSER' in perm_str:
            concerns.append("Requests superuser/root access")
        if 'INSTALL_PACKAGES' in perm_str:
            concerns.append("Can install packages silently")
        if 'SYSTEM_ALERT_WINDOW' in perm_str:
            concerns.append("Can draw over other apps (overlay attack risk)")
        if 'WRITE_SETTINGS' in perm_str:
            concerns.append("Can modify system settings")
        if 'CHANGE_WIFI_STATE' in perm_str:
            concerns.append("Can modify WiFi configuration")
        if 'BLUETOOTH_ADMIN' in perm_str:
            concerns.append("Has Bluetooth admin control")
        if 'RECEIVE_BOOT_COMPLETED' in perm_str:
            concerns.append("Starts on boot")
        if 'MOUNT_UNMOUNT_FILESYSTEMS' in perm_str:
            concerns.append("Can mount/unmount filesystems")
        if min_sdk and int(min_sdk) < 17:
            concerns.append(f"Low min SDK ({min_sdk}) - may use insecure WebView defaults")
        if target_sdk and int(target_sdk) < 26:
            concerns.append(f"Low target SDK ({target_sdk}) - bypasses modern security features")
        
        if concerns:
            print(f"\nSECURITY CONCERNS:")
            for c in concerns:
                print(f"  ⚠️ {c}")
        
    except Exception as e:
        print(f"\nERROR analyzing {fname}: {e}")

