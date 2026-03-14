# Samsung & Misc Driver Security Audit — Exynos 3475 Kernel Source

**Date:** 2025-07-17
**Kernel:** 3.10.9 (Samsung GPL release, `origin/clean_base`)
**Target:** SM-T377A, Android 6.0.1, Security Patch July 2017
**Attacker context:** ADB shell (UID 2000, SELinux `u:r:shell:s0`) or untrusted_app (UID 10139)

---

## EXECUTIVE SUMMARY

**High-value findings ranked by exploitability:**

| # | Finding | Severity | Accessible? | Exploit Primitive |
|---|---------|----------|-------------|-------------------|
| 1 | **DCCP CVE-2017-8824 UAF** | CRITICAL | Yes (socket) | Kernel code execution |
| 2 | **Melfas touchscreen 0666 sysfs** | HIGH | Likely (verify sysfs path) | FW injection, I2C cmd injection |
| 3 | **ICM MPU debug sysfs S_IWUGO** | HIGH | Likely (verify sysfs path) | Arbitrary I2C register writes |
| 4 | **TIMA debug logs world-readable** | MEDIUM | Yes (/proc) | TrustZone log info leak |
| 5 | **devfreq bw_mon 0666 sysfs** | LOW | Probably (sysfs) | Bus monitor config manipulation |
| 6 | **knox_kap memcpy from __user** | LOW | No (0660) | Kernel bug, not reachable |
| 7 | **sec_debug reset_reason S_IWUGO** | INFO | Read-only (no write fops) | None — permission mismatch |

---

## 1. DCCP USE-AFTER-FREE — CVE-2017-8824 (CRITICAL)

### Location
`net/dccp/proto.c` — `dccp_disconnect()` function

### Vulnerability
The `dccp_disconnect()` function does NOT clean up CCID (Congestion Control) state when disconnecting a socket. Specifically, it lacks calls to `ccid_hc_rx_delete()` and `ccid_hc_tx_delete()`. This allows a use-after-free when:

1. A DCCP socket connects and negotiates CCID features (allocating tx/rx CCID state)
2. `dccp_disconnect()` is called (state is NOT freed)
3. The socket reconnects or is reused — stale CCID pointers are dereferenced

The fix (upstream commit `69c64866ce07`) was merged December 2017. This kernel's security patches are from **July 2017** — the CVE is **NOT patched**.

### Code Evidence
```c
// net/dccp/proto.c — dccp_disconnect()
int dccp_disconnect(struct sock *sk, int flags)
{
    // ... sets state to DCCP_CLOSED
    // ... calls inet_csk_listen_stop() or dccp_send_reset()
    // ... purges queues
    // BUT: NO ccid_hc_rx_delete() or ccid_hc_tx_delete() calls!
    // Stale CCID pointers remain in dccp_sock
}
```

### Accessibility
- **DAC**: DCCP sockets can be created by any user via `socket(AF_INET, SOCK_DCCP, IPPROTO_DCCP)` — **accessible from UID 2000**
- **SELinux**: `shell` domain can create network sockets; DCCP may or may not be in the policy. Need to verify with `sesearch` or test on device.
- **Kernel config**: DCCP is confirmed compiled into this kernel (CONFIG_IP_DCCP=y confirmed in prior research)

### Exploitation Primitive
- **UAF → arbitrary kernel read/write → code execution**
- The freed CCID structures are in kmalloc-64 or kmalloc-128 slabs
- Heap spray with controlled data to overlap freed CCID structure
- When CCID function pointers (e.g., `ccid_hc_tx_send_packet`) are called, they dereference attacker-controlled memory
- **Can achieve `commit_creds(prepare_kernel_cred(0))` at known addresses** (no KASLR)

### Safety Risk
- **MODERATE**: If the UAF dereferences unmapped memory, it will oops → panic (panic_on_oops=1)
- Use heap spray to ensure controlled data is present before triggering
- Test in QEMU first

### Next Steps
1. Verify DCCP socket creation works from ADB shell (`socket(AF_INET, SOCK_DCCP, 33)`)
2. Check SELinux: `adb shell cat /sys/fs/selinux/policy | sesearch -A -s shell -c dccp_socket`
3. Build PoC in QEMU (no SELinux, root access, same kernel version)
4. Port to device if QEMU PoC succeeds

---

## 2. MELFAS TOUCHSCREEN — World-Writable Sysfs (HIGH)

### Location
`drivers/input/touchscreen/melfas_mms400/melfas_mms400.c`
`drivers/input/touchscreen/melfas_mms400/melfas_mms400_cmd.c`

### Vulnerability
Multiple sysfs attributes created with **0666 permissions** (world-readable AND world-writable):

| Sysfs Attribute | Permissions | Handler | Effect |
|----------------|-------------|---------|--------|
| `fw_update` | 0666 | `mms_sys_fw_update` (show) | Reads `/sdcard/melfas.bin` and flashes to touchscreen |
| `cmd` | 0666 | `mms_sys_cmd` (store) | Sends commands to touchscreen controller |
| `cmd_status` | 0666 | `mms_sys_cmd_status` (show) | Returns command status |
| `cmd_result` | 0666 | `mms_sys_cmd_result` (show) | Returns command results |
| `cmd_list` | 0666 | `mms_sys_cmd_list` (show) | Lists available commands |

### FW Update Attack Chain
```c
#define EXTERNAL_FW_PATH "/sdcard/melfas.bin"

int mms_fw_update_from_storage(struct mms_ts_info *info, bool force) {
    set_fs(KERNEL_DS);
    fp = filp_open(EXTERNAL_FW_PATH, O_RDONLY, S_IRUSR);
    fw_data = kzalloc(fw_size, GFP_KERNEL);
    nread = vfs_read(fp, (char __user *)fw_data, fw_size, &fp->f_pos);
    ret = mms_flash_fw(info, fw_data, fw_size, force, true);
}
```

Attack:
1. Write malicious firmware to `/sdcard/melfas.bin` (shell can write to sdcard)
2. Read the `fw_update` sysfs entry to trigger the update: `cat /sys/devices/.../fw_update`
3. The kernel reads the file with `set_fs(KERNEL_DS)` (bypasses address space checks) and passes to `mms_flash_fw()`

### Potential Kernel Memory Corruption via `mms_flash_fw`
The `kzalloc(fw_size, GFP_KERNEL)` with unvalidated `fw_size` (comes from inode size) could be interesting if `mms_flash_fw` has parsing bugs. The firmware data is processed in kernel context.

### `cmd` Interface
The `mms_sys_cmd` handler parses text commands (e.g., `fw_update`, `get_fw_ver_ic`, `get_rawdata`, etc.) and dispatches to handler functions. Some handlers:
- `cmd_fw_update` — triggers firmware update
- `cmd_module_off_master` / `cmd_module_on_master` — power control
- `cmd_read_rawdata` / `cmd_read_intensity` — reads sensor data

### Accessibility
- **DAC**: Sysfs attrs are 0666, so UID 2000 can read/write
- **SELinux**: Shell likely cannot access arbitrary sysfs_type entries; the touchscreen sysfs path needs verification
- **Sysfs path**: Under `/sys/devices/` somewhere on the I2C bus (e.g., `/sys/devices/12c70000.i2c/i2c-3/3-0048/`)
- **Note**: The SM-T377A may use the Imagis (ist30xxc) touchscreen instead of Melfas — **verify which driver is loaded**

### Safety Risk
- **LOW for cmd interface**: Commands go to I2C → touchscreen IC, not kernel memory
- **MODERATE for fw_update**: `kzalloc` + kernel processing of untrusted firmware data

---

## 3. ICM MPU (InvenSense IMU) — World-Writable Debug Sysfs (HIGH)

### Location
`drivers/iio/imu/icm_mpu/inv_mpu_core.c`

### Vulnerability
Dozens of IIO sysfs attributes with **S_IRUGO | S_IWUGO** (0666) permissions, including:

| Attribute | Handler | What It Does |
|-----------|---------|-------------|
| `debug_reg_write` | `inv_debug_store(ATTR_DEBUG_REG_WRITE)` | Writes arbitrary value to arbitrary IMU register via I2C |
| `debug_reg_write_addr` | `inv_debug_store(ATTR_DEBUG_REG_ADDR)` | Sets the target register address for reg_write |
| `debug_mem_write` | `inv_dmp_bias_store(ATTR_DMP_DEBUG_MEM_WRITE)` | Writes 2 bytes to DMP memory at specified address |
| `debug_mem_read` | read handler | Reads DMP memory |
| `debug_cfg_write` | `inv_debug_store(ATTR_DEBUG_WRITE_CFG)` | Writes config data |
| `debug_reg_dump` | `inv_reg_dump_show` | Dumps all IMU registers |
| `debug_suspend_resume` | `inv_debug_store` | Controls suspend/resume |

### Exploitation Primitive
- **Arbitrary I2C register writes** to the InvenSense IMU chip
- Cannot directly write kernel memory (writes go over I2C to the sensor chip)
- However, corrupting IMU firmware/DMP could potentially cause sensor driver code paths to behave unexpectedly
- The `inv_plat_single_write()` call chain could potentially be interesting if the I2C transfer causes a kernel code path to be vulnerable

### Accessibility
- **DAC**: S_IWUGO means world-writable
- **SELinux**: IIO sysfs paths may be blocked for shell domain
- **Sysfs path**: Under `/sys/bus/iio/devices/iio:device0/` or similar
- **Verify on device**: `find /sys -name debug_reg_write 2>/dev/null`

### Safety Risk
- **LOW**: I2C writes to a sensor chip. Worst case: sensor stops working, unlikely to panic

---

## 4. TIMA DEBUG LOGS — World-Readable Proc Entries (MEDIUM)

### Location
`drivers/misc/tima_debug_log.c`

### Vulnerability
Four proc entries created with **0644 permissions** (world-readable):

| Proc Entry | Physical Address | Size |
|-----------|-----------------|------|
| `/proc/tima_debug_log` | `phys_to_virt(0x27402000)` | 1 MB |
| `/proc/tima_secure_log` | `phys_to_virt(0x27502000)` | 1 MB |
| `/proc/tima_debug_rkp_log` | `phys_to_virt(0x32300000)` | 1 MB |
| `/proc/tima_secure_rkp_log` | `phys_to_virt(0x329F8000)` | 1 MB |

### What Leaks
- TIMA (TrustZone Integrity Measurement Architecture) debug messages
- RKP (Real-time Kernel Protection) log entries
- Log entries contain: timestamp, logger_id (1=TIMA, 2=LKMAUTH), 120-byte message
- **May contain kernel addresses, TZ state, and security check results**

### Code Path
```c
ssize_t tima_read(struct file *filep, char __user *buf, size_t size, loff_t *offset) {
    if (size > DEBUG_LOG_SIZE || (*offset) + size > DEBUG_LOG_SIZE)
        return -EINVAL;
    // Selects log based on filename
    copy_to_user(buf, (const char *)tima_log_addr + (*offset), size);
}
```

### Accessibility
- **DAC**: 0644 = world-readable ✓
- **SELinux**: shell may be blocked from reading proc entries of this type
- **Verify**: `adb shell cat /proc/tima_debug_log | head -c 256 | xxd`

### Exploitation Value
- Info leak to understand TIMA/RKP checking patterns
- Timing information for TIMA integrity checks (every 5 minutes)
- Possible kernel address leak in log messages
- Knowledge of what TIMA monitors could help bypass it

### Safety Risk
- **NONE**: Read-only operation

---

## 5. DEVFREQ BW_MON — World-Writable Sysfs (LOW)

### Location
`drivers/devfreq/monitor.c`

### Vulnerability
```c
static DEVICE_ATTR(bw_mon, 0666, NULL, store_bw_mon);

static ssize_t store_bw_mon(struct device *device,
    struct device_attribute *attr, const char *buf, size_t count) {
    int mode, log;
    sscanf(buf, "%d %d", &mode, &log);
    bw_monitor_config((enum bw_monitor_mode)mode, (enum bw_monitor_log)log);
}
```

### Analysis
- `sscanf` without bounds checking on parsed integers, but values are cast to enums and used in a switch
- `bw_monitor_config` controls bus frequency monitoring mode: OFF, STANDALONE (timer-based), USERCTRL, BUSFREQ
- No buffer overflow; values are integers parsed by sscanf
- Could enable/disable bus monitoring, potentially affecting performance but not security

### Accessibility
- Sysfs under devfreq subsystem; shell access uncertain
- **Low exploit value**: No memory corruption, no privilege escalation path

---

## 6. KNOX KAP — `memcpy` from `__user` without `copy_from_user` (LOW)

### Location
`drivers/char/knox_kap.c`, registered as `/dev/knox_kap` (minor 13)

### Vulnerability
```c
ssize_t knox_kap_write(struct file *file, const char __user *buffer,
                       size_t size, loff_t *offset) {
    string = kmalloc(size + sizeof(char), GFP_KERNEL);
    memcpy(string, buffer, size);  // BUG: should be copy_from_user()!
    // ...parses integer, calls turn_on_kap() or turn_off_kap()
}
```

Uses `memcpy` directly on a `__user` pointer instead of `copy_from_user`. On ARM with unified address space this "works" but:
- Bypasses access_ok() check
- Could crash if the userspace pointer is invalid

Also, `knox_kap_ioctl` has **no capability checks** — any opener can call `turn_off_kap()` / `turn_on_kap()`.

### Accessibility
- **Device permissions: 0660** (owner: root, group: system)
- **NOT accessible from UID 2000 (shell) or untrusted_app**
- If we could somehow open this device, we could toggle KAP mode

---

## 7. OTHER NOTABLE FINDINGS

### sec_debug reset_reason — Permission Mismatch
```c
proc_create("reset_reason", S_IWUGO, NULL, &sec_reset_reason_proc_fops);
```
Created with S_IWUGO (world-writable) but the fops only has `.read` — no `.write` handler. This is a coding error, not exploitable.

### Samsung Netfilter Interceptor
`net/netfilter/interceptor/kernelspd_procfs.c` creates a proc entry with **S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP** (0660) — not world-accessible.

### Imagis (ist30xxc) Touchscreen
All DEVICE_ATTRs are S_IRUGO (read-only) or S_IWUSR|S_IWGRP (root/group). **No world-writable entries.** This is the more likely touchscreen driver for SM-T377A (Exynos 3475 = budget device).

### MobiCore Driver
`/dev/mobicore` and `/dev/mobicore-user` — created via `device_create()` without explicit permissions. Default udev/ueventd rules on device determine actual permissions (typically root-only).

### Battery/Charger Drivers
No world-writable sysfs entries found in `drivers/battery/sec_battery.c` or `sec_charger.c`.

### MUIC Driver
No world-writable entries found in `drivers/muic/`.

---

## RECOMMENDED ATTACK PRIORITY

### Tier 1 — Most Promising (Test Immediately)
1. **DCCP CVE-2017-8824**: Verify DCCP socket creation from shell, build PoC in QEMU
2. **Melfas `fw_update` sysfs**: Check if melfas driver is loaded; verify sysfs accessibility from shell

### Tier 2 — Verify Accessibility First
3. **ICM MPU debug sysfs**: Find sysfs path on device, test write access
4. **TIMA debug logs**: Try reading, check for kernel address leaks

### Tier 3 — Research Value Only
5. **devfreq bw_mon**: Low impact
6. **knox_kap**: Not accessible from shell

### Device Verification Commands
```bash
# Check which touchscreen driver is loaded
cat /proc/bus/input/devices | grep -A5 -i touch

# Check melfas sysfs existence
find /sys -name fw_update 2>/dev/null
find /sys -path "*mms*" 2>/dev/null
find /sys -path "*melfas*" 2>/dev/null

# Check DCCP socket creation
cat /proc/net/protocols | grep DCCP

# Check TIMA logs
ls -la /proc/tima*
cat /proc/tima_debug_log | head -c 128 | xxd

# Check ICM MPU sysfs
find /sys -name debug_reg_write 2>/dev/null
find /sys -path "*iio*" -name "*debug*" 2>/dev/null

# Check devfreq bw_mon
find /sys -name bw_mon -path "*devfreq*" 2>/dev/null
```
