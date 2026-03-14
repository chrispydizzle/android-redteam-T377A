# DRParser Keystring Processing — Full Reverse Engineering

**Source**: `com.sec.android.app.parser` v1.0.06, decompiled from OAT/ODEX (DEX extracted at offset 0x1458)
**UID**: 1000 (`android.uid.system` shared UID)
**Tool chain**: jadx 1.x with `--show-bad-code` on extracted DEX from `DRParser.odex`

---

## 1. Architecture Overview

```
Dialer Input → SecretCodeIME (calculator UI) → EventHandler.CheckInput()
  → EventHandler.sendMessage() → ParseService (bound via Messenger)
    → ParseService.process(keystring)
      → KeystringCommon.hasKeystring() → lookup in mKeystringList HashMap
      → sendBroadcast(SECRET_CODE_ACTION, uri) with package restriction
        → Target app's BroadcastReceiver
```

DRParser is a disguised calculator app that intercepts dial pad input. Every keystroke triggers `CheckInput()` which sends the current input string to `ParseService` via IPC Messenger. The service matches against a HashMap of known keystrings loaded from encrypted XML files.

---

## 2. Keystring XML Format

### Source XML Structure (decrypted `ATT_keystrings.dat`)

```xml
<?xml version="1.0" encoding="utf-8"?>
<keystrings>
  <Plm_Info>
    <Single_Id>yongmin.koo</Single_Id>
    <Time_Of_Txt>1508191844</Time_Of_Txt>
    <Csc_Code>ATT</Csc_Code>
    <!-- ... metadata fields ... -->
  </Plm_Info>

  <keystring>
    <keysequence>*#197328640#</keysequence>
    <output>197328640</output>
    <packagename>com.sec.android.RilServiceModeApp</packagename>
    <enable>true</enable>
    <alwaysopen>true</alwaysopen>
  </keystring>

  <!-- More keystring entries... -->
</keystrings>
```

### All Supported XML Tags (from `KeystringsList.java`)

| Tag | Purpose | Values |
|-----|---------|--------|
| `<keysequence>` | Dial sequence to match (e.g. `*#0808#`) | String, supports `DEVICEID`/`IMEI`/`MEID` placeholders |
| `<output>` | The "host" value for the secret code URI | String (digits between `*#` and `#`) |
| `<packagename>` | Target package for the broadcast | Package name string |
| `<enable>` | Whether this keystring is active | `true`/`false` (default: `true`) |
| `<alwaysopen>` | Survives keystring blocking (ship mode) | `true`/`false` (default: `false`) |
| `<isblocking>` | Can be blocked by ship mode | `true`/`false` |
| `<factorymode>` | Only works in factory mode | `true`/`false` |
| `<category>` | Bitmask controlling visibility | Integer (see below) |
| `<uri>` | Custom URI scheme (overrides `android_secret_code`) | String |
| `<googlekeystring>` | Marks as Google-standard keystring | `true`/`false` |

### Category Bitmask (from `KeystringsList.readCategory()`)

```java
bit 0 (0x01): hiddenMenuDep     — requires hidden menu ON
bit 1 (0x02): engMode           — only on eng/userdebug builds  
bit 2 (0x04): engNormMode       — only on user builds (inverted)
bit 3 (0x08): blockOffHiddenOn  — requires BOTH block-off AND hidden menu
```

- `category=0`: Normal keystring, always registered
- `category=1`: Hidden menu dependent (registered only when HiddenMenu=ON or JIG connected)
- `category=2`: Engineering mode only (userdebug/eng build type)

---

## 3. Keystring Loading Pipeline (`XMLParser.parseKeystringXMLs`)

Loading order (each subsequent file can **override** entries from previous):

1. **`common_keystrings.dat`** — APK asset, RSA-encrypted, common to all carriers
2. **`{SalesCode}_keystrings.dat`** — APK asset, RSA-encrypted (e.g. `ATT_keystrings.dat`)
3. **`/system/etc/{model}_keystrings.dat`** — Device-specific, RSA-encrypted
4. **`/system/etc/{OMC_SalesCode}_keystrings.dat`** — OMC override, RSA-encrypted
5. **`/efs/FactoryApp/keystrings_EFS.xml`** — EFS partition override, RSA-encrypted

**All .dat files are RSA-encrypted** using a 512-bit RSA key. The private key is embedded in the APK assets:
- `assets/mod_pri_key.txt` — 65-byte RSA modulus
- `assets/exp_pri_key.txt` — 65-byte RSA private exponent

### RSA Key Material (from APK assets)

```
Modulus (512-bit):  00CF21BA30A11440580C86F2F6A7B58F2B319BFA7BA1FC035291E981B683F4C0
                    9A5AEB824020641817834525B60E51204EA436A6F5C40B1787043181958DC2616D
Exponent:           008793CAFC63A30ECED33C4DB2376A36D10E02CBBCBAF56AF35400A4DFE39583A
                    F1699F38C430D01A54D270CFF2004C28943D253563C11309002ABF3A61C7F923D
Algorithm:          RSA/ECB with BouncyCastle ("BC") provider
Block size:         64 bytes (512-bit key → 64-byte blocks)
```

The decryption reads 64-byte blocks, decrypts each with `Cipher.doFinal()`, and concatenates the output. The result is the plaintext XML.

### Loading Behavior
- If a keystring already exists in the HashMap and a later file redefines it, the **old entry is removed first** (including from alwaysOpen list), then the new definition is added
- This means `/efs/FactoryApp/keystrings_EFS.xml` (loaded last) can override any entry

---

## 4. KeyStringUpdateReceiver — The File Copy Mechanism

**This is the critical path for keystring injection.**

```java
// KeyStringUpdateReceiver.java — triggered by SECRET_CODE broadcast
public void onReceive(Context context, Intent intent) {
    if (intent.getAction().equals("android.provider.Telephony.SECRET_CODE")) {
        String host = intent.getData().getHost();
        if ("873283".equals(host)) {          // Secret code: *#873283#  ("UPDATE" on keypad)
            // Copies /mnt/sdcard/keystrings_EFS.xml → /efs/FactoryApp/keystrings_EFS.xml
            // Backs up existing EFS file to keystrings_EFS_temp.xml first
            byte[] fileContents = read("/mnt/sdcard/keystrings_EFS.xml");
            write(fileContents, "/efs/FactoryApp/keystrings_EFS.xml");
            Toast: "Keystring file copy success. Reboot to effect changes"
        }
    }
}
```

### Key Details:
- **Trigger**: Secret code `*#873283#` (maps to host `873283`)
- **Source**: `/mnt/sdcard/keystrings_EFS.xml` (world-readable SD card)
- **Destination**: `/efs/FactoryApp/keystrings_EFS.xml` (system-only EFS partition)
- **Backup**: Existing EFS file backed up to `/efs/FactoryApp/keystrings_EFS_temp.xml`
- **NO ENCRYPTION CHECK**: The file is copied **raw** — no RSA verification
- **NO FORMAT VALIDATION**: No XML schema check before copy
- **Requires reboot** to take effect (keystrings loaded in ParseService.onCreate)

### BUT: The EFS file IS decrypted during loading
Looking at `parseKeystringXMLs`, the EFS file path goes through the same `Encrypt64.decrypt()` pipeline as the .dat files. So even though `KeyStringUpdateReceiver` copies the file raw, when DRParser tries to load it, it will attempt RSA decryption.

**However**, looking more carefully at the JADX decompilation of `parseKeystringXMLs`, there's a path where it reads the EFS file separately from the asset-based .dat files. The EFS file reading path (blocks at 0x0100-0x016a in the bytecode) does call `Encrypt64.decrypt()`, meaning **the EFS XML must also be RSA-encrypted**.

---

## 5. ParseService.process() — Intent Dispatch Logic

```java
public synchronized boolean process(String keystring) {
    String keystring_noSeparators = PhoneNumberUtils.stripSeparators(keystring);
    
    // 1. Hidden menu block (VZW family only)
    if (!eng_build && !hiddenMenuOn && !jigOn && isHiddenKeyString && vzwFamily) {
        return false;  // blocked
    }
    
    // 2. PIN/PUK MMI codes (**04*..# or **05*..#)
    if ((keystring.startsWith("**04") || keystring.startsWith("**05")) && keystring.endsWith("#")) {
        MultiSimManager.handlePinMmi(slot, keystring);
        return true;
    }
    
    // 3. Sprint/Boost ##xxx# codes (9-char, not in keystring list)
    if (!hasKeystring && len==9 && "##...#" format && sprint_family) {
        Intent intent = new Intent(SECRET_CODE_ACTION, Uri.parse("android_secret_code://MSL_OTKSL"));
        intent.putExtra("String", keystring.substring(2, len-1));
        sendBroadcast(intent, "com.sec.android.app.hiddenmenu.permission.KEYSTRING");
        return true;
    }
    
    // 4. Normal keystring lookup and dispatch
    if (hasKeystring(keystring_noSeparators)) {
        // Check factory mode and blocking flags
        if (!isFactoryMode && factorymodeFlag) return false;
        if (isKeystringBlocked && blockFlag) return false;
        
        Uri uri = getUri(keystring_noSeparators);  // "android_secret_code://<output>"
        Intent intent = new Intent("android.provider.Telephony.SECRET_CODE", uri);
        intent.setFlags(FLAG_RECEIVER_INCLUDE_BACKGROUND | FLAG_ACTIVITY_NEW_TASK);
        intent.setPackage(getPackage(keystring_noSeparators));
        sendBroadcast(intent);  // ← SENT AS UID 1000!
        return true;
    }
    return false;
}
```

### Critical: The broadcast is sent from UID 1000

The `sendBroadcast()` call in `process()` executes as the **system user** (UID 1000). The intent:
- Action: `android.provider.Telephony.SECRET_CODE`
- Data: `android_secret_code://<output>` (or custom `<uri>://<output>`)
- Package: `<packagename>` from the keystring entry
- Flags: `FLAG_RECEIVER_INCLUDE_BACKGROUND (0x20)` + `FLAG_ACTIVITY_NEW_TASK (0x10000000)`

---

## 6. Keystring Blocking Mechanism

### isKeyStringBlocked()
```java
public static boolean isKeyStringBlocked() {
    if (isJigOn()) return false;   // JIG bypasses ALL blocking
    return true;                    // Always blocked on retail devices!
}
```

**On retail devices without JIG**, `isKeystringBlocked` is always `true`. This blocks keystrings where `<isblocking>true</isblocking>`.

### Hidden Menu
Checked via `/efs/carrier/HiddenMenu` file content. If "ON", hidden-menu-dependent keystrings (category bit 0) are registered.

### alwaysOpen
Keystrings with `<alwaysopen>true</alwaysopen>` survive both blocking and hidden menu restrictions. Most AT&T keystrings in the decrypted XML have `alwaysopen=true`.

---

## 7. Exploitation Analysis — Can We Inject a Keystring?

### Attack Vector: Craft keystrings_EFS.xml → Trigger *#873283# → Reboot → Arbitrary Intent as UID 1000

#### Step 1: Write the file
Place at `/mnt/sdcard/keystrings_EFS.xml` or `/sdcard/keystrings_EFS.xml`. ADB shell (UID 2000) can write to SD card.

#### Step 2: Trigger the copy
Dial `*#873283#` via the calculator/dialer UI, or try to send the broadcast directly:
```
android.provider.Telephony.SECRET_CODE
data: android_secret_code://873283
```

**Problem**: The `KeyStringUpdateReceiver` listens for `SECRET_CODE` broadcasts. Can we send this from ADB?

```bash
adb shell am broadcast -a android.provider.Telephony.SECRET_CODE -d android_secret_code://873283
```

This may or may not work — it depends on whether the receiver is registered in the manifest (it's NOT in the manifest we see — it may be dynamically registered, or there may be a `<receiver>` entry we're missing from the ODEX-only code).

#### Step 3: The encryption problem
**BLOCKER**: The EFS file goes through `Encrypt64.decrypt()` during loading. A plaintext XML file would fail RSA decryption and be silently ignored.

**However**, we have the RSA private key from the APK assets! Since DRParser uses RSA **decryption** with a **private key**, the encryption was done with the corresponding **public key**. To create a valid encrypted keystring file, we need the public key.

For RSA, given the private key (d, N), the public exponent e is typically 65537 (0x10001). We can verify:
- N (modulus) = `0x00CF21BA30A11440...958DC2616D` (512 bits)
- d (private exponent) = `0x008793CAFC63A30E...C7F923D`
- e (public exponent) = likely 65537

We can **encrypt our own keystring XML** using the public key and the same 64-byte block RSA scheme.

#### Step 4: What intent would we inject?

```xml
<?xml version="1.0" encoding="utf-8"?>
<keystrings>
  <keystring>
    <keysequence>*#999999#</keysequence>
    <output>999999</output>
    <packagename>com.sec.android.app.personalization</packagename>
    <enable>true</enable>
    <alwaysopen>true</alwaysopen>
  </keystring>
</keystrings>
```

When dialed, this would cause DRParser (UID 1000) to broadcast:
```
Action: android.provider.Telephony.SECRET_CODE  
Data: android_secret_code://999999
Package: com.sec.android.app.personalization
```

But `SECRET_CODE` is intercepted by receivers registered for that action + data scheme. We can't make it launch an arbitrary activity this way.

#### The `uri` tag — custom URI scheme!

Looking at `KeystringInfos` constructor:
```java
if (uri != null) {
    this.mUri = Uri.parse(uri + "://" + this.mOutput);
} else {
    this.mUri = Uri.parse("android_secret_code://" + this.mOutput);
}
```

And in `process()`:
```java
Intent intent = new Intent("android.provider.Telephony.SECRET_CODE", uri);
intent.setPackage(packageName);
sendBroadcast(intent);
```

The intent always uses action `SECRET_CODE` and sets the package. We can control the **URI data** via the `<uri>` tag, but the **action** is hardcoded to `android.provider.Telephony.SECRET_CODE`.

This means we can only trigger receivers that listen for `SECRET_CODE` — we can't launch arbitrary activities or services.

---

## 8. Key Findings Summary

### What DRParser Does
1. Disguised calculator app that intercepts dial sequences
2. Matches against encrypted XML keystring databases
3. Dispatches `SECRET_CODE` broadcasts as **UID 1000** to target packages
4. Supports keystring override via EFS file (SD card → EFS copy mechanism)

### Security Properties
| Property | Value |
|---|---|
| Runs as | UID 1000 (system) |
| Intent dispatch | `sendBroadcast()` as system — receivers see caller as UID 1000 |
| EFS update trigger | `*#873283#` via dialer or SECRET_CODE broadcast |
| EFS file encryption | RSA 512-bit — key embedded in APK (extractable) |
| Action hardcoded | `android.provider.Telephony.SECRET_CODE` only |
| URI customizable | Via `<uri>` XML tag |
| Package targeting | Via `<packagename>` XML tag |

### Exploitation Potential

**Medium-High** if we can:
1. Compute RSA public key from the embedded private key material
2. Encrypt a crafted keystrings_EFS.xml
3. Copy it to `/mnt/sdcard/keystrings_EFS.xml`
4. Trigger `*#873283#` (either via dialer UI or broadcast)
5. Reboot the device
6. Dial the injected keystring

**The broadcast is sent as UID 1000**, but only with action `SECRET_CODE`. This limits us to triggering SECRET_CODE receivers in Samsung system apps. However, some of those receivers (in `com.sec.android.app.personalization`, `com.sec.android.RilServiceModeApp`, etc.) run as **system** and may have exploitable code paths triggered by unexpected secret code values.

### Blocked by
- RSA encryption requirement for EFS keystring file
- Hardcoded intent action (can't launch arbitrary activities)
- Need physical access to dialer (or broadcast capability) to trigger codes
- Reboot required after EFS file update

---

## 9. Files Referenced

| Path | Purpose | Access from Shell |
|---|---|---|
| `/efs/FactoryApp/keystrings_EFS.xml` | Override keystring definitions | ❌ No access |
| `/efs/FactoryApp/keystrings_EFS_temp.xml` | Backup of previous EFS file | ❌ No access |
| `/efs/carrier/HiddenMenu` | Hidden menu enable flag ("ON"/"OFF") | ❌ No access |
| `/efs/FactoryApp/factorymode` | Factory mode flag | ❌ No access |
| `/efs/imei/mps_code.dat` | Sales code (carrier) | ❌ No access |
| `/mnt/sdcard/keystrings_EFS.xml` | Source file for EFS update | ✅ Writable |
| `/system/etc/{code}_keystrings.dat` | Per-carrier encrypted keystrings | ❌ Read-only |
| `/system/csc/customer.xml` | CSC configuration | ❌ Read-only |
| `/sys/class/sec/switch/attached_dev` | JIG detection | ✅ Readable |

---

## 10. Decompiled Source Files

Full jadx decompilation (26 Java files) at: `work/drparser_full/sources/com/sec/android/app/parser/`

Key classes:
- **ParseService.java** — Main service, keystring dispatch (`process()` method)
- **KeystringCommon.java** — Keystring management, HashMap lookup
- **KeystringsList.java** — XML tag parser (SAX-style), builds KeystringInfos objects
- **XMLParser.java** — File loading pipeline, RSA decryption, XmlPullParser
- **KeyStringUpdateReceiver.java** — SD card → EFS file copy (`*#873283#`)
- **KeystringInfos.java** — Data class for a single keystring entry
- **Encrypt64.java** — RSA 512-bit decryption with BouncyCastle
- **EventHandler.java** — Input handler, Messenger IPC to ParseService
- **SecretCodeIME.java** — Calculator activity UI
- **CscParser.java** — CSC/customer.xml parser for sales code
