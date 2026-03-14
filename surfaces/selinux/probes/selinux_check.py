import subprocess, re

checks = [
    "u:r:shell:s0 u:r:su:s0 process transition",
    "u:r:shell:s0 u:object_r:su_exec:s0 file execute",
    "u:r:shell:s0 u:object_r:su_exec:s0 file execute_no_trans",
    "u:r:shell:s0 u:r:init:s0 process transition",
    "u:r:shell:s0 u:object_r:shell_exec:s0 file execute",
    "u:r:shell:s0 u:r:system_server:s0 process transition",
    "u:r:shell:s0 u:object_r:kernel:s0 system syslog_mod",
    "u:r:shell:s0 u:object_r:proc:s0 file read",
    "u:r:shell:s0 u:object_r:selinuxfs:s0 file write",
    "u:r:shell:s0 u:object_r:selinuxfs:s0 security load_policy",
    "u:r:shell:s0 u:object_r:selinuxfs:s0 security setenforce",
    "u:r:shell:s0 u:r:factory:s0 process transition",
    "u:r:shell:s0 u:object_r:factory_exec:s0 file execute",
    "u:r:shell:s0 u:r:install_recovery:s0 process transition",
    "u:r:shell:s0 u:r:system_server:s0 process ptrace",
    "u:r:shell:s0 u:r:servicemanager:s0 binder call",
    "u:r:shell:s0 u:r:init:s0 unix_stream_socket connectto",
    "u:r:shell:s0 u:r:vold:s0 unix_stream_socket connectto",
    "u:r:shell:s0 u:r:netd:s0 unix_stream_socket connectto",
    "u:r:shell:s0 u:r:zygote:s0 unix_stream_socket connectto",
    "u:r:shell:s0 u:object_r:default_prop:s0 property_service set",
    "u:r:shell:s0 u:object_r:system_prop:s0 property_service set",
    "u:r:shell:s0 u:object_r:ctl_default_prop:s0 property_service set",
    "u:r:shell:s0 u:object_r:diag_device:s0 chr_file read",
    "u:r:shell:s0 u:object_r:diag_device:s0 chr_file write",
    "u:r:shell:s0 u:r:rd_shell:s0 process transition",
    "u:r:shell:s0 u:object_r:rd_shell_exec:s0 file execute",
    "u:r:shell:s0 u:object_r:tima_dump_exec:s0 file execute",
    "u:r:shell:s0 u:object_r:sec-sh_exec:s0 file execute",
    "u:r:shell:s0 u:r:untrusted_app:s0 process transition",
]

for check in checks:
    cmd = f'adb shell "printf \'{check}\' > /sys/fs/selinux/access 2>/dev/null; cat /sys/fs/selinux/access 2>/dev/null"'
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        out = result.stdout.strip()
        if "allowed 1" in out or out.startswith("1"):
            status = "*** ALLOWED ***"
        elif "allowed 0" in out or out.startswith("0"):
            status = "DENIED"
        elif out:
            status = f"({out[:60]})"
        else:
            status = "NO OUTPUT"
        print(f"  {check}: {status}")
    except Exception as e:
        print(f"  {check}: ERROR ({e})")
