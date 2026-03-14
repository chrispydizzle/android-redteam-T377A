#!/bin/sh
# recon_reconnect.sh - Run immediately after ADB reconnects
# Comprehensive probe of all missed targets from session 10
#
# Push to device: adb push recon_reconnect.sh /data/local/tmp/
# Run: adb shell sh /data/local/tmp/recon_reconnect.sh 2>&1 | tee work/recon_reconnect_output.txt

echo "=== RECONNECT RECON SCRIPT ==="
echo "Date: $(date)"
echo "UID: $(id)"
echo ""

echo "=== 1. USB CONFIG STATUS ==="
getprop sys.usb.config
getprop sys.usb.state
getprop persist.sys.usb.config
getprop persist.sys.usb.q_config
getprop init.svc.adbd

echo ""
echo "=== 2. PLATFORM SIGNING KEY VERIFICATION ==="
# Check if bootimage uses AOSP test-keys
echo "--- Build fingerprints ---"
getprop ro.build.fingerprint
getprop ro.bootimage.build.fingerprint
getprop ro.build.tags
echo ""

# Try to read the platform cert from PackageManager
echo "--- Platform certificate (from Settings app) ---"
dumpsys package com.android.settings 2>/dev/null | grep -A2 "signatures" | head -5
echo ""
echo "--- framework-res certificate ---"
dumpsys package android 2>/dev/null | grep -A2 "signatures" | head -5
echo ""
echo "--- System app signing info ---"
pm dump com.android.settings 2>/dev/null | grep -i "sign\|cert\|key" | head -10
echo ""

# Check for AOSP test-key cert hash
# AOSP test-key SHA1: 61:ED:37:7E:85:D3:86:A8:DF:EE:6B:86:4B:D8:5B:0B:FA:A5:AF:81
echo "--- Checking /system/etc/security ---"
ls -la /system/etc/security/ 2>/dev/null
echo ""
echo "--- APK signature on settings ---"
ls -la /system/priv-app/SecSettings/ 2>/dev/null
echo ""

echo "=== 3. EXECUTE SERVICE PROBE ==="
# Test the IExecuteManager service
echo "--- service call execute 1 ---"
service call execute 1 2>/dev/null
echo "--- service call execute 2 ---"
service call execute 2 2>/dev/null
echo "--- service call execute 3 ---"
service call execute 3 2>/dev/null
echo "--- service call execute 4 ---"
service call execute 4 2>/dev/null
echo "--- service call execute 5 ---"
service call execute 5 2>/dev/null

# Try with string argument
echo "--- execute with 'id' string arg ---"
service call execute 1 s16 "id" 2>/dev/null
service call execute 2 s16 "id" 2>/dev/null
service call execute 3 s16 "id" 2>/dev/null

echo ""
echo "=== 4. USB SERVICE PROBE ==="
service call usb 1 2>/dev/null
service call usb 2 2>/dev/null
service call usb 3 2>/dev/null
service call usb 4 2>/dev/null
service call usb 5 2>/dev/null

echo ""
echo "=== 5. SEDENIAL SERVICE ==="
service call sedenial 1 2>/dev/null
service call sedenial 2 2>/dev/null
service call sedenial 3 2>/dev/null

echo ""
echo "=== 6. ICCC SERVICE ==="
service call iccc 1 2>/dev/null
service call iccc 2 2>/dev/null
service call iccc 3 2>/dev/null

echo ""
echo "=== 7. PERSISTENT DATA BLOCK ==="
service call persistent_data_block 1 2>/dev/null
service call persistent_data_block 2 2>/dev/null
service call persistent_data_block 3 2>/dev/null
service call persistent_data_block 4 2>/dev/null
service call persistent_data_block 5 2>/dev/null

echo ""
echo "=== 8. SERIAL SERVICE ==="
service call serial 1 2>/dev/null
service call serial 2 2>/dev/null
service call serial 3 2>/dev/null

echo ""
echo "=== 9. SELINUX DOMAIN TRANSITIONS ==="
# Check what SELinux allows from shell domain
echo "--- Current context ---"
cat /proc/self/attr/current
echo ""

echo "--- /sys/fs/selinux available ---"
ls /sys/fs/selinux/ 2>/dev/null
echo ""

# Check if we can read access decisions
echo "--- SELinux access check: shell->su_exec:file:execute ---"
echo -n "u:r:shell:s0 u:object_r:su_exec:s0 file execute" > /sys/fs/selinux/access 2>/dev/null
if [ $? -eq 0 ]; then
    echo "ALLOWED or interface accessible"
else
    echo "Denied or interface not accessible"
fi

echo "--- Can shell exec su_exec? ---"
ls -laZ /system/xbin/su 2>/dev/null
ls -laZ /system/bin/su 2>/dev/null

echo ""
echo "--- SELinux contexts for interesting binaries ---"
for f in /system/xbin/su /system/bin/su /sbin/su /system/xbin/daemonsu \
         /system/bin/app_process /system/bin/app_process32 \
         /system/bin/toolbox /system/bin/toybox /system/bin/sh \
         /system/bin/run-as /system/bin/dumpstate; do
    if [ -f "$f" ]; then
        ls -laZ "$f" 2>/dev/null
    fi
done

echo ""
echo "=== 10. CONTENT PROVIDERS ==="
# Try reading from content providers that might expose sensitive data
echo "--- SMS ---"
content query --uri content://sms 2>/dev/null | head -5
echo "--- Contacts ---"
content query --uri content://contacts/phones 2>/dev/null | head -5
echo "--- Call log ---"
content query --uri content://call_log/calls 2>/dev/null | head -5
echo "--- Settings.Global ---"
content query --uri content://settings/global 2>/dev/null | head -20
echo "--- Settings.Secure ---"
content query --uri content://settings/secure 2>/dev/null | head -20
echo "--- Settings.System ---"
content query --uri content://settings/system 2>/dev/null | head -10

echo ""
echo "=== 11. WRITABLE PROC/SYS ==="
# Check writable entries in /proc and /sys that shell can modify
echo "--- Writable /proc entries ---"
for f in /proc/sys/kernel/* /proc/sys/net/* /proc/sys/vm/*; do
    if [ -w "$f" ] 2>/dev/null; then
        echo "  WRITABLE: $f = $(cat $f 2>/dev/null | head -1)"
    fi
done

echo ""
echo "--- Writable /sys entries ---"
find /sys -maxdepth 4 -writable -type f 2>/dev/null | head -30

echo ""
echo "=== 12. DEBUGFS WRITABLE ==="
echo "--- Writable debugfs entries ---"
find /sys/kernel/debug -maxdepth 3 -writable -type f 2>/dev/null | head -30

echo ""
echo "=== 13. TRACING CAPABILITY ==="
echo "--- Tracing directory ---"
ls -la /sys/kernel/debug/tracing/ 2>/dev/null | head -20
echo ""
echo "--- Can write trace_marker? ---"
echo "test_marker" > /sys/kernel/debug/tracing/trace_marker 2>/dev/null
echo "Result: $?"
echo ""
echo "--- Can set current_tracer? ---"
cat /sys/kernel/debug/tracing/available_tracers 2>/dev/null
echo ""
echo "--- Can enable function tracing? ---"
echo "function" > /sys/kernel/debug/tracing/current_tracer 2>/dev/null
echo "Result: $?"
cat /sys/kernel/debug/tracing/current_tracer 2>/dev/null

echo ""
echo "=== 14. DUMPSYS HIGH-VALUE ==="
echo "--- battery (for uid info) ---"
dumpsys battery 2>/dev/null
echo ""
echo "--- deviceidle ---"
dumpsys deviceidle 2>/dev/null | head -20

echo ""
echo "=== 15. DEV NODES ==="
echo "--- Readable/writable /dev nodes ---"
for d in /dev/binder /dev/ashmem /dev/ion /dev/mali0 /dev/pvrsrvkm \
         /dev/alarm /dev/null /dev/zero /dev/random /dev/urandom \
         /dev/fuse /dev/ptmx /dev/tty /dev/input/event* \
         /dev/block/mmcblk0 /dev/block/mmcblk0p* \
         /dev/ttyGS* /dev/ttySAC* /dev/usb-ffs/adb/ep0; do
    if [ -e "$d" ]; then
        r=""
        w=""
        [ -r "$d" ] && r="R"
        [ -w "$d" ] && w="W"
        if [ -n "$r" ] || [ -n "$w" ]; then
            echo "  $d: ${r}${w} $(ls -laZ $d 2>/dev/null | awk '{print $1, $4, $5}')"
        fi
    fi
done

echo ""
echo "=== 16. INIT RC FILES ==="
# Try to read init files
for f in /init.rc /init.environ.rc /init.usb.rc /init.usb.configfs.rc \
         /init.universal3475.rc /init.baseband.rc /init.wifi.rc \
         /fstab.* /init.recovery.* /init.carrier.rc; do
    if [ -r "$f" ]; then
        echo "--- $f (first 30 lines) ---"
        head -30 "$f"
        echo ""
    fi
done

echo ""
echo "=== 17. PARTITION INFO ==="
cat /proc/partitions 2>/dev/null
echo ""
echo "--- Mount points ---"
mount 2>/dev/null

echo ""
echo "=== DONE ==="
echo "Date: $(date)"
