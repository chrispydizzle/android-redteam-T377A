import sys, os
sys.stdout.reconfigure(encoding='utf-8')
from androguard.core.apk import APK

apk_dir = r"C:\InfoSec\android-redteam\findings\apks"

for fname in sorted(os.listdir(apk_dir)):
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
        services = a.get_services()
        receivers = a.get_receivers()
        providers = a.get_providers()
        
        dangerous = [p for p in perms if any(d in p.upper() for d in [
            'CAMERA','RECORD_AUDIO','READ_CONTACTS','WRITE_CONTACTS',
            'ACCESS_FINE_LOCATION','ACCESS_COARSE_LOCATION','READ_PHONE_STATE',
            'CALL_PHONE','READ_SMS','SEND_SMS','READ_EXTERNAL_STORAGE',
            'WRITE_EXTERNAL_STORAGE','INTERNET','ACCESS_WIFI_STATE',
            'CHANGE_WIFI_STATE','BLUETOOTH','NFC','SYSTEM_ALERT_WINDOW',
            'WRITE_SETTINGS','INSTALL_PACKAGES','DELETE_PACKAGES',
            'ACCESS_SUPERUSER','RECEIVE_BOOT_COMPLETED','MOUNT_UNMOUNT'
        ])]
        
        concerns = []
        perm_str = ' '.join(perms).upper()
        if 'ACCESS_SUPERUSER' in perm_str or 'SUPERUSER' in perm_str:
            concerns.append("Requests superuser/root access")
        if 'INSTALL_PACKAGES' in perm_str:
            concerns.append("Can install packages")
        if 'SYSTEM_ALERT_WINDOW' in perm_str:
            concerns.append("Can draw over other apps (overlay attack risk)")
        if 'WRITE_SETTINGS' in perm_str:
            concerns.append("Can modify system settings")
        if 'CHANGE_WIFI_STATE' in perm_str:
            concerns.append("Can modify WiFi configuration")
        if 'RECEIVE_BOOT_COMPLETED' in perm_str:
            concerns.append("Starts on boot")
        if min_sdk and int(min_sdk) < 17:
            concerns.append(f"Low min SDK ({min_sdk}) - insecure WebView defaults")
        if target_sdk and int(target_sdk) < 26:
            concerns.append(f"Low target SDK ({target_sdk}) - bypasses modern security")
        
        print(f"\n--- {pkg} v{ver} ---")
        print(f"SDK: min={min_sdk} target={target_sdk}")
        print(f"Components: {len(activities)} activities, {len(services)} services, {len(receivers)} receivers, {len(providers)} providers")
        print(f"Permissions ({len(perms)} total, {len(dangerous)} dangerous):")
        for p in sorted(dangerous):
            print(f"  [!] {p}")
        if concerns:
            print("Security Concerns:")
            for c in concerns:
                print(f"  [WARN] {c}")
    except Exception as e:
        print(f"\nERROR: {fname}: {e}")
