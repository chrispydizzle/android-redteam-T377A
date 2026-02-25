# SIM Lock Bypass & RIL Attack Surface

## Executive Summary

The Samsung SM-T377A exhibits a robust "Network Lock" implementation enforced by the Shannon 308 modem and the RIL daemon (`rild`). Direct manipulation of system properties (e.g., `gsm.sim.state`) is blocked by SELinux and lack of root privileges. However, three distinct avenues for bypassing or disabling the lock have been identified.

## 1. Service Mode Escalation (The "Official" Path)

The device contains privileged Samsung service applications capable of disabling the lock, modifying APNs, and accessing raw modem commands.

* **Targets**:
  * `com.sec.android.RilServiceModeApp` (UID 1001 / Radio)
  * `com.sec.android.app.servicemodeapp` (UID 1000 / System)
* **Protection**: Activities are protected by the `com.sec.android.app.servicemodeapp.permission.KEYSTRING` permission (Signature|Privileged).
* **Bypass Vector**:
  * **Root Exploit**: Using the **ION Race Condition** or **Heap Bit 2** vulnerabilities to gain kernel code execution allows bypassing the permission check.
  * **Post-Root Action**:

        ```bash
        # Disable Network Lock via ServiceMode (requires root/system)
        am start -n com.sec.android.app.servicemodeapp/com.sec.android.app.modemui.activities.PhoneUtil
        # Navigate to: [1] UMTS -> [1] Debug Screen -> [6] Phone Control -> [6] Network Lock -> [3] PERSO SHA256 OFF
        ```

## 2. Input Subsystem Bridge (The "Side-Channel")

Fuzzing revealed a direct path from the kernel input subsystem to the modem, bypassing the standard RIL stack.

* **Observation**: Fuzzing `/dev/input/event0` (Meta Event) generates `mif: LNK-TX` logs in `dmesg`.
* **Implication**: The kernel driver `drivers/input/keyboard/shannon_keys.c` (or similar) translates specific input events directly into modem commands (likely for power management or resets).
* **Bypass Vector**:
  * Replay specific event sequences to `/dev/input/event0` to trigger modem diagnostic modes or resets that might degrade the lock state.
  * This surface is reachable from the `shell` user (or any app with input injection capability).

## 3. RIL Socket Injection

The RIL daemon exposes UNIX domain sockets for communication with the framework.

* **Sockets**:
  * `/dev/socket/rild` (Standard RIL)
  * `/dev/socket/rild-debug` (Debug interface)
* **Bypass Vector**:
  * If the ION exploit yields a shell with `radio` or `root` privileges, one can talk directly to `rild-debug` to send AT commands.
  * **AT Commands of Interest**:
    * `AT+CLCK="PN",0,"<code">` (Unlock Network)
    * `AT+DEVCONINFO` (Device Connection Info)
    * Samsung-specific OEM commands (accessible via `RilServiceModeApp` analysis).

## Recommendations

1. **Prioritize ION Exploit**: The most reliable path to a SIM unlock is gaining root via the ION kernel vulnerability.
2. **Analyze RilServiceModeApp**: Decompile `ServiceModeApp_RIL.apk` to extract the exact OEM commands used for the "PERSO SHA256 OFF" function.
3. **Monitor Modem Logs**: Continue monitoring `dmesg` for `mif` logs while interacting with the lock screen to identify the specific checks being performed.
