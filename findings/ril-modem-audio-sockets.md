# RIL/Modem Interface & Samsung Audio Socket Analysis

**Device:** Samsung SM-T377A (AT&T) — Android 6.0.1, Kernel 3.10.9  
**Baseband:** T377AUCU2AQGF (Shannon 308 modem)  
**RIL:** Samsung RIL v3.0 (`/system/lib/libsec-ril.so`, 2.4MB)  
**Date:** 2025-07-17  
**Shell context:** `u:r:shell:s0` (uid=2000, no radio group)  
**SELinux:** Enforcing

---

## Part 1: RIL/Modem Interface

### 1.1 Socket Inventory

| Socket / Device | Owner:Group | Perms | SELinux Label | Status |
|---|---|---|---|---|
| `/dev/socket/rild` | root:radio | `srw-rw----` | `u:object_r:rild_socket:s0` | LISTENING, 1 connected client |
| `/dev/socket/rild-debug` | radio:system | `srw-rw----` | `u:object_r:rild_debug_socket:s0` | LISTENING |
| `/dev/socket/rild-cas` | root:root | `srw-rw----` | `u:object_r:socket_device:s0` | Created but idle |

### 1.2 Modem Character Devices (Samsung SIPC/DPRAM)

| Device | Owner:Group | Perms | SELinux Label | Purpose |
|---|---|---|---|---|
| `/dev/umts_ipc0` | radio:radio | `crw-rw----` | `u:object_r:radio_device:s0` | Main modem IPC channel |
| `/dev/umts_boot0` | system:radio | `crw-rw----` | `u:object_r:ssipc_device:s0` | Modem boot control |
| `/dev/umts_dm0` | system:radio | `crw-rw----` | `u:object_r:ssipc_device:s0` | Diagnostic monitor |
| `/dev/umts_ramdump0` | system:radio | `crw-rw----` | `u:object_r:ssipc_device:s0` | Modem crash dump |
| `/dev/umts_rfs0` | system:radio | `crw-rw----` | `u:object_r:ssipc_device:s0` | Remote file system |
| `/dev/umts_csd` | system:loop_radio | `crw-rw----` | `u:object_r:ssipc_device:s0` | Circuit-switched data |
| `/dev/umts_router` | system:radio | `crw-rw----` | `u:object_r:ssipc_device:s0` | Modem data router |
| `/dev/ipc_loopback0` | root:root | `crw-------` | `u:object_r:device:s0` | IPC loopback (testing) |
| `/dev/smd4` | root:root | `crw-------` | — | Shared memory driver |

### 1.3 Modem Firmware / Block Devices

| Symlink/Path | Target | Purpose |
|---|---|---|
| `/dev/mbin0` | `/dev/block/mmcblk0p14` (RADIO) | Modem firmware image |
| `CDMA-RADIO` | `/dev/block/mmcblk0p13` | CDMA radio partition |
| `CPEFS` | `/dev/block/mmcblk0p4` | CP (modem) EFS data |
| `RADIO` | `/dev/block/mmcblk0p14` | Main radio firmware |

### 1.4 Running Modem Processes

| PID | UID | Process | Notes |
|---|---|---|---|
| 2194 | radio | `/system/bin/rild` | Main RIL daemon |
| 2203 | radio | `/sbin/cbd` | Samsung modem (CBD) daemon |
| 2210 | radio | `/system/bin/at_distributor` | AT command distributor |
| 3502 | radio | `com.android.phone` | Telephony app |
| 3932 | radio | `com.sec.phone` | Samsung phone app |
| 16146 | radio | `com.sec.android.RilServiceModeApp` | Service mode (active!) |

### 1.5 RIL Socket Access Assessment

**Direct socket access from shell: DENIED**
```
/dev/socket/rild       → "Permission denied" (need radio group or root)
/dev/socket/rild-debug → "Permission denied" (need system group)
```

**Modem char devices: DENIED**  
All `umts_*` devices require radio or system group membership. Shell (uid=2000) is not in the radio (1001) or system (1000) group. SELinux `shell` domain also lacks `ssipc_device` / `radio_device` access.

**Key property findings:**
- `gsm.sim.state = NETWORK_LOCKED` — SIM is carrier-locked
- `ril.modem.board = SHANNON308` — Samsung Shannon baseband
- `ril.cbd.boot_done = 1` — Modem is booted and running
- `ril.RildInit = 1` — RIL initialized
- `ril.radiostate = 10` — Radio state active
- RIL client library: `libsecril-client.so` uses `socket_local_client()` with "Multiclient" / "Multiclient2" named connections

### 1.6 Interesting RIL Attack Vectors

1. **`/dev/mobicore-user`** — `crw-rw-rw-` (world-readable/writable!) with SELinux label `u:object_r:mobicore-user_device:s0`. This is the **MobiCore/Kinibi TEE** user-space interface. If SELinux policy allows `shell` domain to access this, it could be a **direct TEE attack surface**.

2. **`/dev/mbin0`** (RADIO partition symlink) — SELinux label `u:object_r:mbin_device:s0`. Reading modem firmware from eMMC for offline analysis is possible if SELinux allows.

3. **`at_distributor`** (PID 2210) — AT command distribution daemon. If reachable via any interface (USB serial, socket), could allow AT command injection for modem control.

4. **`RilServiceModeApp`** — Samsung service mode is actively running (PID 16146). This is the engineering/diagnostic menu that exposes low-level modem controls.

---

## Part 2: Samsung TMAudio Sockets

### 2.1 Socket Discovery

The TMAudio sockets are **Unix domain sockets** used by Samsung's proprietary **TMS (Telephony Media Service)** audio path:

| Socket Path | State | In /proc/net/unix |
|---|---|---|
| `/data/TMAudioSocketServer` | LISTENING | Yes (inode 1630) |
| `/data/TMAudioSocketClient` | LISTENING | Yes (inode 6935) |

**Critical finding:** The sockets exist in `/proc/net/unix` but `ls -la /data/TMAudio*` returns nothing — they are **abstract namespace Unix sockets** bound to `/data/TMAudioSocket*` paths, meaning they are NOT filesystem entries. They exist purely in the kernel's socket namespace.

### 2.2 Owning Library: `audio.tms.default.so`

Strings analysis of `/system/lib/hw/audio.tms.default.so` (26,260 bytes) reveals:

```
AudioTmsServerInit / AudioTmsServerdeInit / AudioTmsServerIsActive
AudioTmsServerIsReady / AudioTmsServerWrite / AudioTmsServerEndStream
AudioTmsClientSetup / AudioTmsClientInit / AudioTmsClientfinish
AudioTmsClientIsActive / AudioTmsClientIsReady
AudioTmsClientGetDataCmd / AudioTmsClientRead
AudioTmsClientRestart / AudioTmsClientMicEvent / AudioTmsClientListen
```

This is a **client-server IPC for in-call audio**. The server side pushes downlink audio from the modem, the client side reads it for the speaker/earpiece. `AudioTmsClientMicEvent` suggests microphone routing control.

### 2.3 Audio-RIL Bridge

`/system/lib/libaudio-ril.so` (26,160 bytes) bridges audio HAL to the modem:
- Uses `libsecril-client.so` (`SecRilOpen`, `Connect_RILD`, `Disconnect_RILD`)
- Functions: `SecRilCheckConnection`, `SecRilDump`
- The primary audio HAL (`audio.primary.universal3475.so`) also contains:
  - `connect RILD ok` / `connect RILD fail` — direct RILD connection
  - `Send stop PCM clock IPC` — modem clock control
  - `Send wfc IPC to stop CP CLK` — WiFi Calling modem IPC
  - `ril_state_connected` — tracks RIL state

### 2.4 Audio Socket Access Assessment

**Direct access from shell: DENIED**
```
/data/TMAudioSocketServer → "Permission denied"
/data/TMAudioSocketClient → "Permission denied"
```

Since these are abstract namespace sockets, access control is purely **SELinux-based** (no filesystem DAC). The `shell` domain (`u:r:shell:s0`) is blocked by SELinux policy from connecting to these sockets.

### 2.5 Samsung Audio Effects (Potential Attack Surface)

The device loads multiple Samsung-proprietary audio effect libraries:

| Library | Effect | UUID |
|---|---|---|
| `soundalive_sec` | SoundAlive (main) | `cf65eb39-ce2f-48a8-a903-ceb818c06745` |
| `soundalive` | SoundAlive_EQ | `0c117b70-f97f-11e0-be50-0002a5d5c51b` |
| `soundalive` | SoundAlive_Virtualizer | `c747f6a0-418a-11e1-a621-0002a5d5c51b` |
| `soundalive` | SoundAlive_BassBoost | `a926a540-418a-11e1-b2f1-0002a5d5c51b` |
| `myspace` | MySpace | `3462a6e0-655a-11e4-8b67-0002a5d5c51b` |
| `mysound` | MySound | `263a88e0-50b1-11e2-bcfd-0800200c9a66` |

These run in the `audioserver` / `mediaserver` process (system-level). Malformed audio effect parameters could potentially trigger vulnerabilities in these Samsung-proprietary libraries.

---

## Summary: Attack Surface Assessment

### Accessible from Shell (uid=2000)

| Target | Access | Risk |
|---|---|---|
| `/dev/mobicore-user` | **DAC: YES (0666)**, SELinux: needs verification | **HIGH** — TEE interface, world-writable |
| `dumpsys telephony.registry` | YES | MEDIUM — SIM state, signal info leak |
| `getprop` (RIL properties) | YES | LOW-MEDIUM — modem info, serial, firmware versions |
| RIL sockets | NO (need radio/system group) | Blocked by DAC + SELinux |
| `umts_*` modem devices | NO (need radio group) | Blocked by DAC + SELinux |
| TMAudio sockets | NO (abstract namespace, SELinux) | Blocked by SELinux |

### Escalation-Dependent Targets (require radio/system/root)

1. **`/dev/umts_dm0`** — Modem diagnostic monitor. With radio group, could inject diagnostic commands to the Shannon 308 modem.
2. **`/dev/umts_ramdump0`** — Modem crash dump interface. Could trigger/read modem crashes for firmware analysis.
3. **`rild-debug` socket** — With system group access, can send debug commands to RIL daemon.
4. **TMAudio sockets** — With appropriate SELinux context, could intercept/inject in-call audio.
5. **`/dev/mbin0`** — Direct modem firmware read for offline analysis.

### New Attack Surfaces Identified

1. **MobiCore/Kinibi TEE (`/dev/mobicore-user`)** — World-writable device node. This is the **highest priority** finding. If SELinux allows shell domain access, we can communicate directly with the Trusted Execution Environment. This could expose TrustZone apps (trustlets) including Samsung Knox key storage.

2. **AT Command Distributor** — `at_distributor` daemon (PID 2210) distributes AT commands. If reachable via USB serial interface or an exposed socket, could control modem directly (change bands, unlock SIM, dump IMEI).

3. **Samsung Audio Effects in mediaserver** — Six proprietary audio effect plugins loaded into a privileged process. Effect parameter fuzzing via the AudioEffect API could trigger memory corruption in the `audioserver` process.

4. **Audio-RIL Bridge** — The `libaudio-ril.so` ↔ `libsecril-client.so` path creates a cross-domain bridge between audio and radio. A vulnerability in the audio path could potentially reach the RIL.

5. **RilServiceModeApp** — Samsung's engineering diagnostic app is actively running. This provides service-mode access to modem internals if the app can be controlled via `am start` intents.

---

## Recommended Next Steps

1. **Verify mobicore-user SELinux access**: `cat /dev/mobicore-user` from shell to test if SELinux permits the access despite DAC allowing it.
2. **Enumerate AT command interface**: Check `/dev/ttyACM*`, `/dev/ttyGS*` for USB serial AT command access.
3. **Fuzz Samsung audio effects**: Use AudioEffect API to send malformed parameters to SoundAlive/MySound/MySpace plugins.
4. **Analyze modem firmware**: If `/dev/mbin0` is readable, dump and analyze Shannon 308 firmware for vulnerabilities.
5. **Test RilServiceModeApp intents**: `am start -n com.sec.android.RilServiceModeApp/.RilServiceModeApp` to access service mode diagnostics.
