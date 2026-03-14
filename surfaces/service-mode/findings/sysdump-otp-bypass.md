# Samsung SysDump OTP Authentication Bypass

> **Date**: 2026-02-27
> **Target**: Samsung SM-T377A (Galaxy Tab E 8.0), AT&T, Android 6.0.1
> **App**: com.sec.android.app.servicemodeapp (serviceModeApp_FB)
> **Severity**: HIGH — unlocks all engineering-only SysDump features on commercial builds

---

## Summary

Samsung's SysDump diagnostic tool (`*#9900#`) gates powerful features behind an "OTP Authentication" dialog on commercial/user builds. Features protected include TCP packet capture, Silent Log, CP RAM Logging, and others. We reversed the OTP algorithm from the app's ODEX and built a solver that computes valid codes in real-time.

## OTP-Protected Features (Now Accessible)

| Feature | What It Does | Security Impact |
|---------|-------------|-----------------|
| TCP DUMP START | Root-level pcap capture on any interface | Captures all device traffic including IPC |
| SILENT LOG | Persistent modem/CP logging across reboots | Logs baseband/modem activity |
| CP RAM LOGGING | Communication Processor RAM dump | Raw modem memory contents |
| 2MIC PCM DUMP | Microphone audio dump | Audio surveillance capability |

## The Algorithm

**Class**: `LibOTPSecurity.OTPSecurity`  
**Location**: Embedded DEX at offset 0x1640 inside `serviceModeApp_FB.odex`

### CheckOTP(input, key)
```java
// Tries 6 time windows (current minute and 5 minutes back)
for offset in [0..5]:
    expected = MakeHashCode(key + GetDateString(offset))
    if input == expected: return true
return false
```

### GetDateString(minute_offset)
```java
// GMT time, formatted as YYMMmmDDHH
// YY = year-2000, MM = month, mm = minute, DD = day, HH = hour
TimeZone GMT; Calendar adjusted by -offset minutes;
return String.format("%02d%02d%02d%02d%02d", YY, MM, mm, DD, HH);
```

**Note**: The field order is `YYMMmmDDHH` — minute comes BEFORE day and hour. This is unusual and easy to get wrong.

### MakeHashCode(arg)
```java
// Classic DJB2 hash variant: hash = hash * 33 + char
int hash = 0;
for each char c in arg:
    hash = (hash << 5) + hash + c;  // equivalent to hash * 33 + c
return abs(hash);  // if negative, negate
```

## Solver Script

**Location**: `work/otp_solver.py`

```
Usage: python3 work/otp_solver.py <key>

Example:
  $ python3 work/otp_solver.py z02p1
  GMT time: 2026-02-27 06:41:47
  Key: z02p1
    offset=0min: z02p12602412706 -> 1940529412  <-- USE THIS
    offset=1min: ...
```

The code at offset=0 is the answer. Valid for ~5 minutes (the app checks offsets 0-5).

## How to Use

1. Open SysDump (Calculator → `(+300120127327+` → type `*#9900#`, or via APK: `am broadcast -a com.privesc.agent.COMMAND --es command secret_code --es code 9900`)
2. Tap a protected feature (e.g., TCP DUMP START, SILENT LOG)
3. OTP dialog appears with "Key : xxxxx"
4. Run: `python3 work/otp_solver.py xxxxx`
5. Enter the offset=0 result
6. Tap OK → "OTP Authentication enabled!"

Once authenticated, the OTP session persists until the SysDump activity is closed. All OTP-protected features become accessible without re-entering codes.

## Reverse Engineering Process

1. Pulled `serviceModeApp_FB.apk` (78KB, resources only) and `.odex` (848KB, ART-compiled) from `/system/priv-app/serviceModeApp_FB/`
2. Searched ODEX binary for strings: found `CheckOTP`, `MakeHashCode`, `LLibOTPSecurity/OTPSecurity;`, `Key : `, `OTP Authentication`
3. Located DEX magic (`dex\n035\0`) at offset 0x1640 in the OAT file, size 275,460 bytes
4. Extracted DEX, fixed checksum (SHA1 + Adler32), decompiled with jadx `--show-bad-code`
5. Found `LibOTPSecurity/OTPSecurity.java` — 39 lines, completely self-contained
6. Algorithm is a simple DJB2 hash with time-based salt, no cryptographic security

## Files

| File | Description |
|------|-------------|
| `work/otp_solver.py` | Python3 OTP solver script |
| `work/sysdump_app/serviceModeApp_FB.apk` | Pulled APK (resources only) |
| `work/sysdump_app/serviceModeApp_FB.odex` | Pulled ODEX (ART-compiled code) |
| `work/sysdump_app/extracted_classes.dex` | Extracted DEX from OAT |
| `work/sysdump_app/dex_decompiled/` | Full jadx decompilation output |
| `work/sysdump_app/dex_decompiled/sources/LibOTPSecurity/OTPSecurity.java` | **The OTP algorithm source** |
| `work/sysdump_app/dex_decompiled/sources/com/sec/android/app/servicemodeapp/SysDump.java` | SysDump main activity |

## Additional Notes

- The `libtlcotp.so` library found at `/system/lib/` is a **separate** TrustZone-backed OTP system used by `otp_server` — it is NOT what SysDump uses. SysDump's OTP is purely Java, no TrustZone.
- The `/efs/sec_efs/.otp_auth` file is used by the TrustZone OTP, not the SysDump OTP.
- The DJB2 hash has no cryptographic strength — the 5-char key + 10-char date gives ~15 chars of input, producing a predictable 32-bit hash.
- This same OTP class is likely shared across Samsung service/diagnostic apps on devices of this era.
