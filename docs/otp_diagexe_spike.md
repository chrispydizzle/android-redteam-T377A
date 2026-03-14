# Technical Spike: OTP Service and Diagexe Analysis

## 1. Overview
Investigation into `OTP` service and `diagexe` binary on the target Android device. 
Goal: Identify vulnerabilities or bypasses for the OTP protection mechanism, particularly in the absence of kernel source code.

## 2. Research Questions
*   **OTP Service**:
    *   What are the valid transaction codes for the `OTP` binder service?
    *   Can we brute-force or fuzz these codes to trigger unexpected behavior or bypass checks?
    *   What arguments does the `OTP` service expect?
*   **Diagexe**:
    *   How does `diagexe` interact with `/dev/umts_dm0`?
    *   Does it use HDLC framing or a custom protocol?
    *   Can we inject malformed packets to crash it or gain code execution?
*   **SysDump Interaction**:
    *   What does a valid OTP transaction look like in `logcat`?
    *   Can we replay a valid transaction?

## 3. Investigation Plan

### Phase 1: Passive Analysis & Logging
*   [ ] **Logcat Capture**: Run `logcat -b radio -b system -b main -v threadtime > /sdcard/otp_investigation.log` in background.
*   [ ] **Manual Trigger**: Request user (or automate if possible) to trigger the SysDump OTP check on the device.
*   [ ] **Log Analysis**: Identify the specific service name (e.g., `SamsungOTP` or similar) and the transaction flow.

### Phase 2: OTP Service Fuzzing
*   [ ] **Service Enumeration**: Confirm the exact service name using `service list`.
*   [ ] **Binder Fuzzing**: Use `service call <service_name> <code> <args>` to brute-force transaction codes (1-100).
    *   *Risk*: This might crash system services.
*   [ ] **Argument Analysis**: If a code returns an interesting result (not "Parcel(Error)"), probe for argument types (int, string).

### Phase 3: Diagexe Reverse Engineering
*   [ ] **Binary Pull**: Ensure `diagexe` and dependent libs are pulled (already done?).
*   [ ] **Static Analysis**: Use `strings` and local decompilation tools (if available) to look for:
    *   Packet parsing logic (headers, magic bytes).
    *   Vulnerable C functions (`strcpy`, `sprintf`).
    *   Command dispatch tables.
*   [ ] **Protocol Dump**: If possible, `strace` the running `diagexe` process (requires root) to see raw reads/writes to `/dev/umts_dm0`.
*   [ ] **Socket Interaction**: Investigate access to `/data/.diag_stream` and `/data/.diagsocket_stream`.
    *   Check permissions: `ls -l /data/.diag*`
    *   Attempt connection if accessible.
*   [ ] **Framing Analysis**: Confirm usage of `0x7E` (End) and `0x7F` (Start) flags found in strings.

### Phase 4: Dynamic Instrumentation (Optional)
*   [ ] If we have root (e.g., via a temp exploit), use `gdbserver` or `frida` to hook `diagexe`.

## 4. External Resources
*   [Samsung IPC Protocol Documentation (Unofficial)](https://github.com/Grimler91/samsung-ipc-docs) - *Need to verify relevance*
*   [Android Binder Fuzzing Tools](https://github.com/google/project-zero/tree/master/project-zero/android-binder-fuzz)

## 5. Investigation Results
*   *Pending*

## 6. Todos
*   [ ] Create fuzzing script for `service call`.
*   [ ] Analyze `diagexe` strings for protocol hints.
*   [ ] Capture baseline logcat of OTP failure/success.
