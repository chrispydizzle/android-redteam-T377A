# BlueBorne CVE-2017-0782 — L2CAP Protocol Reverse Engineering
## Samsung SM-T377A | Kernel 3.10.9 | ARM32 | NO KASLR/PXN/canaries
## Date: 2026-03-03

---

## Executive Summary

This document provides a complete protocol-level reverse engineering of the L2CAP signaling
protocol as implemented in the SM-T377A's kernel (3.10.9), with specific focus on the
CVE-2017-0782 stack buffer overflow in `l2cap_parse_conf_rsp()`. The vulnerability allows
a remote attacker within Bluetooth range (~10m) to overflow a 64-byte stack buffer in the
kernel, overwriting saved ARM32 registers including the return address (LR), achieving
arbitrary code execution in kernel context.

**Key findings:**
1. The PENDING path in `l2cap_config_rsp()` has **ZERO input length validation** on data passed to `l2cap_parse_conf_rsp()`
2. The UNACCEPT path has a length check: `len > sizeof(req) - sizeof(struct l2cap_conf_req)` = 60 bytes max
3. `l2cap_add_conf_opt()` writes `type(1) + len(1) + value(N)` bytes — EFS options write 18 bytes each
4. ARM32 with no stack canaries means saved `{r4-r11, lr}` is directly overwritable
5. All 6 existing exploit files have correctness issues identified below

---

## 1. L2CAP Signaling Protocol Specification

### 1.1 Transport Layer

| Property | Value |
|----------|-------|
| Transport | Bluetooth ACL (Asynchronous Connection-Less) |
| L2CAP CID | 0x0001 (Signaling Channel) |
| Byte order | Little-endian |
| Maximum MTU | Negotiated (default 672 bytes) |
| Encryption | Optional (not required for signaling) |
| Authentication | Not required for L2CAP signaling |

### 1.2 L2CAP Basic Header (4 bytes)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Length (16-bit LE)     |          CID (16-bit LE)      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Payload (variable)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Length**: Payload size in bytes (excluding this 4-byte header)
- **CID**: Channel Identifier. 0x0001 = BR/EDR Signaling, 0x0005 = LE Signaling

### 1.3 Signaling Command Header (4 bytes)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Code      |   Identifier  |      Data Length (16-bit LE)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Data (variable)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Code**: Command type (see table below)
- **Identifier**: Transaction ID (1-255, 0 is invalid — kernel rejects `!cmd.ident`)
- **Data Length**: Length of the Data field

### 1.4 Signaling Command Codes

| Code | Name | Direction | Description |
|------|------|-----------|-------------|
| 0x01 | COMMAND_REJ | ← | Reject unknown command |
| 0x02 | CONN_REQ | → | Request L2CAP connection |
| 0x03 | CONN_RSP | ← | Connection response |
| 0x04 | CONF_REQ | ↔ | Configuration request |
| **0x05** | **CONF_RSP** | **↔** | **Configuration response (VULNERABLE)** |
| 0x06 | DISCONN_REQ | → | Disconnect request |
| 0x07 | DISCONN_RSP | ← | Disconnect response |
| 0x08 | ECHO_REQ | → | Echo/ping request |
| 0x09 | ECHO_RSP | ← | Echo/ping response |
| 0x0A | INFO_REQ | → | Information request |
| 0x0B | INFO_RSP | ← | Information response |

### 1.5 Configuration Option TLV Format

```
 0         1         2
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Type       |    Length      |  ...Value (Length bytes)...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Type | Name | Value Length | Description |
|------|------|-------------|-------------|
| 0x01 | MTU | 2 | Maximum Transmission Unit |
| 0x02 | FLUSH_TO | 2 | Flush timeout |
| 0x03 | QOS | 22 | Quality of Service |
| 0x04 | RFC | 9 | Retransmission & Flow Control |
| 0x05 | FCS | 1 | Frame Check Sequence |
| **0x06** | **EFS** | **16** | **Extended Flow Specification** |
| 0x07 | EWS | 2 | Extended Window Size |

**Critical for exploitation**: Each option's total output size in `l2cap_add_conf_opt` is `2 + value_length`:
- MTU: 2 + 2 = **4 bytes** output
- RFC: 2 + 9 = **11 bytes** output
- EFS: 2 + 16 = **18 bytes** output

---

## 2. L2CAP Connection & Configuration State Machine

### 2.1 Normal Connection Flow

```
  ATTACKER                                      TARGET (SM-T377A kernel)
     |                                                |
     |--- ACL Connection (HCI Create Connection) ---->|
     |<-- ACL Connection Complete (handle=N) ---------|
     |                                                |
     |  [L2CAP Signaling on CID 0x0001]              |
     |                                                |
     |<-- INFO_REQ (type=0x0002, Extended Features) --|
     |--- INFO_RSP (result=success, features) ------->|
     |<-- INFO_REQ (type=0x0003, Fixed Channels) -----|
     |--- INFO_RSP (result=success, channels) ------->|
     |                                                |
     |--- CONN_REQ (PSM=0x0001, SCID=0x0040) ------->|
     |<-- CONN_RSP (DCID=0x0040, SCID=0x0040, OK) ---|
     |                                                |
     |  [Both sides now send CONF_REQ/CONF_RSP]       |
     |                                                |
     |<-- CONF_REQ (dcid, flags, options) ------------|
     |--- CONF_RSP (scid, flags, result, options) --->|  ← VULNERABLE
     |                                                |
     |--- CONF_REQ (dcid, flags, options) ----------->|
     |<-- CONF_RSP (scid, flags, result, options) ----|
     |                                                |
     |  [Channel OPEN — data can flow]                |
```

### 2.2 Configuration State Bits (from kernel source)

```c
enum {
    CONF_REQ_SENT,       // We sent a CONF_REQ
    CONF_INPUT_DONE,     // We received and accepted remote config
    CONF_OUTPUT_DONE,    // Remote accepted our config
    CONF_MTU_DONE,
    CONF_MODE_DONE,
    CONF_CONNECT_PEND,
    CONF_NO_FCS_RECV,
    CONF_STATE2_DEVICE,
    CONF_EWS_RECV,
    CONF_LOC_CONF_PEND,  // ← CRITICAL: enables PENDING path
    CONF_REM_CONF_PEND,  // ← CRITICAL: triggers PENDING code
    CONF_NOT_COMPLETE,
};
```

### 2.3 CONF_RSP Result Codes

| Result | Code | Kernel Behavior |
|--------|------|-----------------|
| SUCCESS | 0x0000 | Accept config, calls `l2cap_conf_rfc_get()` (safe) |
| UNACCEPT | 0x0001 | Calls `l2cap_parse_conf_rsp()` with **length-limited** input |
| REJECT | 0x0002 | Disconnects |
| UNKNOWN_OPT | 0x0003 | Disconnects |
| **PENDING** | **0x0004** | Calls `l2cap_parse_conf_rsp()` with **NO length limit** |
| FLOW_SPEC_REJECT | 0x0005 | Not handled |

---

## 3. Vulnerability Analysis: CVE-2017-0782

### 3.1 Vulnerable Function: `l2cap_parse_conf_rsp()`

**Source**: `net/bluetooth/l2cap_core.c` (Samsung kernel 3.10.9)

```c
static int l2cap_parse_conf_rsp(struct l2cap_chan *chan, void *rsp, int len,
                                void *data, u16 *result)
{
    struct l2cap_conf_req *req = data;  // ← data is a STACK BUFFER (buf[64] or req[64])
    void *ptr = req->data;             // ← ptr starts at data + sizeof(l2cap_conf_req) = data + 4
    int type, olen;
    unsigned long val;
    struct l2cap_conf_rfc rfc = { .mode = L2CAP_MODE_BASIC };
    struct l2cap_conf_efs efs;

    while (len >= L2CAP_CONF_OPT_SIZE) {  // ← loops over ALL input options
        len -= l2cap_get_conf_opt(&rsp, &type, &olen, &val);

        switch (type) {
        case L2CAP_CONF_MTU:
            // ...
            l2cap_add_conf_opt(&ptr, L2CAP_CONF_MTU, 2, chan->imtu);  // writes 4 bytes at *ptr
            break;
        case L2CAP_CONF_FLUSH_TO:
            l2cap_add_conf_opt(&ptr, L2CAP_CONF_FLUSH_TO, 2, ...);   // writes 4 bytes
            break;
        case L2CAP_CONF_RFC:
            l2cap_add_conf_opt(&ptr, L2CAP_CONF_RFC, sizeof(rfc), ...); // writes 11 bytes
            break;
        case L2CAP_CONF_EWS:
            l2cap_add_conf_opt(&ptr, L2CAP_CONF_EWS, 2, ...);         // writes 4 bytes
            break;
        case L2CAP_CONF_EFS:
            l2cap_add_conf_opt(&ptr, L2CAP_CONF_EFS, sizeof(efs), ...); // writes 18 bytes
            break;
        }
    }
    // ... ptr is now past buf[64] if enough options were processed
    req->dcid  = cpu_to_le16(chan->dcid);  // writes at data+0
    req->flags = 0;                         // writes at data+2
    return ptr - data;  // returns total bytes written
}
```

**The bug**: `ptr` advances with each `l2cap_add_conf_opt()` call. No bounds check exists
between `ptr` and the end of the `data` buffer. If the attacker sends enough configuration
options, `ptr` writes past `data[64]` into the stack frame.

### 3.2 Caller: `l2cap_config_rsp()` — Two Code Paths

#### Path A: UNACCEPT (result=0x0001) — LENGTH LIMITED

```c
case L2CAP_CONF_UNACCEPT:
    if (chan->num_conf_rsp <= L2CAP_CONF_MAX_CONF_RSP) {
        char req[64];  // ← 64-byte stack buffer

        if (len > sizeof(req) - sizeof(struct l2cap_conf_req)) {
            // len > 64 - 4 = 60 bytes → DISCONNECT
            l2cap_send_disconn_req(chan, ECONNRESET);
            goto done;
        }

        result = L2CAP_CONF_SUCCESS;
        len = l2cap_parse_conf_rsp(chan, rsp->data, len, req, &result);
        // ← req[64] passed as data, len ≤ 60 bytes of INPUT
        // But OUTPUT can be LARGER than input! (amplification)
    }
```

**Input limit**: 60 bytes max (enforced by `len > sizeof(req) - sizeof(struct l2cap_conf_req)`)
**Output limit**: NONE — output can exceed 64 bytes if options produce more output than input

**Amplification vectors**:
- MTU: 4 bytes in → 4 bytes out (1:1)
- RFC: 11 bytes in → 11 bytes out (1:1)
- EFS: 18 bytes in → 18 bytes out (1:1)
- **No amplification** — each option type produces equal output to input size
- **BUT**: `l2cap_get_conf_opt()` can consume 3+ bytes for types with len=0, while the switch
  statement may still call `l2cap_add_conf_opt()` for certain state-dependent options

**Practical limit**: With 60 bytes of input, maximum output = 60 bytes (fills req[4..63] exactly).
The UNACCEPT path alone **cannot overflow** through simple option repetition.

#### Path B: PENDING (result=0x0004) — NO LENGTH CHECK ✓ EXPLOITABLE

```c
case L2CAP_CONF_PENDING:
    set_bit(CONF_REM_CONF_PEND, &chan->conf_state);

    if (test_bit(CONF_LOC_CONF_PEND, &chan->conf_state)) {
        char buf[64];  // ← 64-byte stack buffer

        len = l2cap_parse_conf_rsp(chan, rsp->data, len,
                                   buf, &result);
        // ← NO length check on len!
        // len comes directly from cmd_len - sizeof(*rsp)
        // which is the full L2CAP signaling payload size
    }
```

**CRITICAL**: No `len > ...` check before calling `l2cap_parse_conf_rsp()`.
The attacker controls `len` via the L2CAP signaling command length field.

**Prerequisite**: `CONF_LOC_CONF_PEND` must be set. This happens when the **target** itself
sent a CONF_RSP with result=PENDING during the initial config exchange. This occurs when:
- The target negotiates EFS (Extended Flow Specification) and sends CONF_RSP(PENDING)
- The `l2cap_parse_conf_req()` sets `result = L2CAP_CONF_PENDING` and `CONF_LOC_CONF_PEND`

**How to trigger CONF_LOC_CONF_PEND**: During the target's processing of OUR CONF_REQ,
if we include EFS options and the target's channel has `L2CAP_SERV_NOTRAFIC` or matching
`stype`, the target sets `CONF_LOC_CONF_PEND`. This requires ERTM or Streaming mode.

### 3.3 Attack Prerequisite: Setting CONF_LOC_CONF_PEND

The PENDING path requires both flags set:
1. `CONF_REM_CONF_PEND` — set when WE send CONF_RSP(PENDING) to the target
2. `CONF_LOC_CONF_PEND` — set when the TARGET sends CONF_RSP(PENDING) to us

**Alternative approach via UNACCEPT with output amplification**:

Actually, re-examining the code more carefully, the UNACCEPT path processes options
from the attacker's CONF_RSP. Each option the attacker sends causes `l2cap_add_conf_opt()`
to write into `req[64]`. The attacker controls:
- Which option types appear (MTU, RFC, EFS, etc.)
- The values within those options
- The number of options

With 60 bytes of input and 1:1 output ratio, we fill req[4..63] = 60 bytes exactly.
No overflow via UNACCEPT without amplification.

**However**: The code also writes `req->dcid` and `req->flags` at the END of the function,
at `data[0..3]`. This doesn't help for overflow.

**Conclusion**: The PENDING path is the primary exploitable path.

---

## 4. ARM32 Stack Overflow Geometry

### 4.1 Stack Frame Layout (l2cap_config_rsp, PENDING path)

```
Higher addresses (stack grows DOWN on ARM)
┌─────────────────────────────────┐
│  Saved LR (return address)      │  ← TARGET: overwrite for PC control
├─────────────────────────────────┤
│  Saved FP (r11)                 │
├─────────────────────────────────┤
│  Saved r10                      │
├─────────────────────────────────┤
│  Saved r9                       │
├─────────────────────────────────┤
│  Saved r8                       │
├─────────────────────────────────┤
│  Saved r7                       │
├─────────────────────────────────┤
│  Saved r6                       │
├─────────────────────────────────┤
│  Saved r5                       │
├─────────────────────────────────┤
│  Saved r4                       │
├─────────────────────────────────┤ ← buf + 64 + padding
│  [Possible compiler padding]    │
├─────────────────────────────────┤ ← buf + 64
│  buf[60..63]                    │
│  buf[56..59]                    │
│  ...                            │
│  buf[4..7]   ← ptr starts here │
│  buf[0..3]   ← conf_req header │
├─────────────────────────────────┤ ← buf[0] / SP + offset
│  Other local variables          │
│  (rfc, efs, result, etc.)       │
└─────────────────────────────────┘
Lower addresses
```

### 4.2 Overflow Calculation

**Buffer**: `char buf[64]` on stack
**Write pointer**: `ptr = buf + sizeof(struct l2cap_conf_req)` = `buf + 4`
**Available before overflow**: 64 - 4 = **60 bytes** of safe writes

**Per-option output sizes**:
| Option Type | Input Size | Output Size | Options to fill 60 bytes |
|-------------|-----------|-------------|-------------------------|
| MTU (0x01) | 4 bytes | 4 bytes | 15 options |
| FLUSH_TO (0x02) | 4 bytes | 4 bytes | 15 options |
| RFC (0x04) | 11 bytes | 11 bytes | 5 options + 5 bytes |
| EFS (0x06) | 18 bytes | 18 bytes | 3 options + 6 bytes |
| EWS (0x07) | 4 bytes | 4 bytes | 15 options |

### 4.3 Overflow Strategy

**Phase 1: Fill buf[4..63]** — 60 bytes
- 15 × MTU options = 60 bytes output → fills buffer exactly

**Phase 2: Overflow into saved registers** — variable bytes
- Use EFS options for maximum controlled data per option (16 bytes of value data)
- Each EFS: 2 header + 16 value = 18 bytes, all value bytes attacker-controlled
- 8 × EFS = 144 bytes → guarantees hitting saved LR regardless of padding

**Phase 3: PC control**
- Saved LR gets overwritten with attacker-chosen address
- On function return (`pop {r4-r11, pc}`), PC = our address
- Jump to `prepare_kernel_cred(0)` → `commit_creds()` chain

### 4.4 Exact Offset Determination

The exact offset from buf[64] to saved LR depends on compiler optimization level
and register allocation. Without the exact binary disassembly, we must spray.

**Known from vmlinux analysis**:
- Function prologue: `push {r4-r11, lr}` = 36 bytes of saved registers
- Compiler may add 0-32 bytes of padding/locals between buf end and saved regs
- **Safe spray range**: 0 to 128 bytes past buf[64]

**EFS spray covers**: 8 × 18 = 144 bytes, with the target address repeated every 4 bytes
within the 16-byte EFS value. This gives 4 copies per EFS option × 8 options = 32 copies
of the target address across 144 bytes. At least one WILL hit saved LR.

---

## 5. Critical Analysis of Existing Exploit Code

### 5.1 Common Issues Across All 6 Files

| File | Primary Issue | Secondary Issues |
|------|--------------|------------------|
| `cve_2017_0782.py` | Uses pybluez (can't send raw signaling) | MTU option only writes 2 bytes of controlled data per 4-byte output |
| `bluborne_exploit.py` | Dry-run only, never sends exploit | Correct protocol knowledge but no raw socket implementation |
| `bluborne_l2cap.c` | Uses `send_l2cap()` via HCI write — needs ACL handle | Doesn't receive/parse target responses, hardcodes ident=1 |
| `bluborne_pwn.c` | Best approach (raw L2CAP + SDP) but sends CONF_RSP on **wrong** CID | SCID=OUR_SCID (0x40) should be target's SCID |
| `bluborne_hci.py` | Most complete — handles INFO_REQ, CONN_RSP, CONF_REQ | PENDING path requires CONF_LOC_CONF_PEND which it doesn't trigger |
| `bluborne_v3.py` | Kernel handles L2CAP config automatically → can't inject | Spray approach is correct but delivery mechanism is wrong |
| `bluborne_scapy.py` | BluetoothL2CAPSocket sends on data CID, not signaling | Spray across idents/SCIDs is a good fallback |

### 5.2 The SCID Problem

All exploit files send CONF_RSP with `scid = OUR_SCID (0x0040)`. But in `l2cap_config_rsp()`:

```c
scid = __le16_to_cpu(rsp->scid);
chan = l2cap_get_chan_by_scid(conn, scid);  // ← looks up by OUR LOCAL scid
```

The `scid` field in CONF_RSP must match the **target's local SCID** for the channel.
The target allocates SCIDs starting from `L2CAP_CID_DYN_START` (0x0040).
If we initiated the connection, the target's SCID for our channel is typically 0x0040.

**This is actually correct** — the target's kernel assigned SCID 0x0040 for the channel
we created via CONN_REQ. Our CONN_REQ used SCID=0x0040 as OUR SCID, and the target's
CONN_RSP contains DCID (target's allocated CID) and SCID (echoing our CID).

**The SCID in CONF_RSP should be the target's DCID from CONN_RSP** — which the target
allocated for this channel. `bluborne_hci.py` correctly captures this from CONN_RSP.

### 5.3 The PENDING Path Prerequisite

The PENDING path in `l2cap_config_rsp()` requires `CONF_LOC_CONF_PEND` to be set.
This flag is set in `l2cap_parse_conf_req()` when processing OUR CONF_REQ:

```c
if (remote_efs) {
    if (__l2cap_efs_supported(chan))
        set_bit(FLAG_EFS_ENABLE, &chan->flags);
    else
        return -ECONNREFUSED;  // ← EFS not supported → can't use PENDING path!
}
```

**Problem**: The SM-T377A's L2CAP implementation likely does NOT have `FLAG_EFS_ENABLE`
(requires High Speed Bluetooth, `enable_hs = true`). Without EFS support,
`CONF_LOC_CONF_PEND` is **never set**, making the PENDING path unreachable.

### 5.4 Revised Attack Strategy: UNACCEPT Path with Output Amplification

Since the PENDING path may be unreachable, we need to revisit the UNACCEPT path.

Re-examining `l2cap_parse_conf_rsp()` more carefully for the UNACCEPT case:

```c
case L2CAP_CONF_UNACCEPT:
    char req[64];
    if (len > sizeof(req) - sizeof(struct l2cap_conf_req)) {
        // len > 60 → disconnect
    }
    len = l2cap_parse_conf_rsp(chan, rsp->data, len, req, &result);
```

The input `len` is capped at 60 bytes. Each option produces equal or fewer output bytes.
**Direct overflow via UNACCEPT appears impossible with 1:1 output ratio.**

**But wait** — look at the `L2CAP_CONF_RFC` case in `l2cap_parse_conf_rsp()`:

```c
case L2CAP_CONF_RFC:
    if (olen == sizeof(rfc))
        memcpy(&rfc, (void *)val, olen);  // copies 9 bytes into local rfc
    // ... state checks ...
    chan->fcs = 0;
    l2cap_add_conf_opt(&ptr, L2CAP_CONF_RFC, sizeof(rfc), (unsigned long) &rfc);
    // ← ALWAYS writes 11 bytes, even if input olen != sizeof(rfc)
    break;
```

If `olen != sizeof(rfc)` (e.g., olen=1), the `memcpy` is skipped but `l2cap_add_conf_opt`
**still writes 11 bytes**. The input option consumes only `2 + olen` = 3 bytes but
produces 11 bytes of output. **This is a 3:11 amplification!**

Similarly for EFS:
```c
case L2CAP_CONF_EFS:
    if (olen == sizeof(efs))
        memcpy(&efs, (void *)val, olen);  // copies 16 bytes only if olen==16
    // ...
    l2cap_add_conf_opt(&ptr, L2CAP_CONF_EFS, sizeof(efs), (unsigned long) &efs);
    // ← ALWAYS writes 18 bytes
    break;
```

If `olen=1` (minimum), input = 3 bytes, output = 18 bytes. **3:18 amplification!**

### 5.5 Output Amplification Attack (UNACCEPT Path)

**Strategy**: Send options with `olen` values that DON'T match the expected size,
bypassing the `memcpy` but still triggering `l2cap_add_conf_opt`.

Wait — re-reading the code:

```c
case L2CAP_CONF_EFS:
    if (olen == sizeof(efs))
        memcpy(&efs, (void *)val, olen);

    if (chan->local_stype != L2CAP_SERV_NOTRAFIC &&
        efs.stype != L2CAP_SERV_NOTRAFIC &&
        efs.stype != chan->local_stype)
        return -ECONNREFUSED;

    l2cap_add_conf_opt(&ptr, L2CAP_CONF_EFS, sizeof(efs),
                       (unsigned long) &efs);
    break;
```

The `efs` variable is a stack-local `struct l2cap_conf_efs` initialized at function entry.
If `olen != sizeof(efs)`, the `memcpy` is skipped, but `l2cap_add_conf_opt` still writes
the **uninitialized** `efs` struct to the output buffer. This is:
1. An info leak (writes stack data)
2. An amplification — 3 bytes in, 18 bytes out

**Maximum amplification with 60 bytes input**:
- 20 × EFS(olen=1) = 20 × 3 = 60 bytes input ✓
- 20 × EFS output = 20 × 18 = **360 bytes output** → 296 bytes past buf[64]!

**BUT**: `l2cap_get_conf_opt` reads `opt->len` from the input. If we set `opt->len = 1`,
it reads 1 byte of value, advances the pointer by 3 bytes, and returns. The switch case
gets `type=0x06` (EFS) with `olen=1`. Since `olen != sizeof(efs) = 16`, the memcpy is
skipped, but `l2cap_add_conf_opt` writes 18 bytes. **CONFIRMED AMPLIFICATION.**

**However**, there's a subtlety: when `olen != sizeof(efs)`, `val` is set to `*((u8 *)opt->val)`
(the 1-byte case in `l2cap_get_conf_opt`). The `(void *)val` cast in the memcpy check
means the `efs` local struct retains its initial (zero or garbage) values.

The stype checks may `return -ECONNREFUSED` if `efs.stype` doesn't match. Since `efs` is
stack-local and potentially uninitialized (it's declared but not `= {0}`), this is
unpredictable. We may need to send one valid EFS option first to set `efs` safely.

### 5.6 CORRECTED Exploit Approach

**Option A: PENDING path (if EFS/HS is supported)**
1. Connect L2CAP to any PSM with ERTM mode + EFS options
2. Target sends CONF_RSP(PENDING) → sets CONF_LOC_CONF_PEND
3. We send CONF_RSP(PENDING) with unlimited overflow payload
4. No length check → direct overflow

**Option B: UNACCEPT path with amplification (more reliable)**
1. Connect L2CAP to PSM 0x0001 (SDP) — normal channel setup
2. Wait for configuration exchange to complete
3. Send CONF_RSP(UNACCEPT) with options designed for amplification:
   - First option: valid EFS (18 bytes in) to initialize the `efs` struct safely
   - Remaining: short EFS options (3 bytes each) that amplify to 18 bytes output
   - 1 × EFS(olen=16) = 18 bytes + up to 14 × EFS(olen=1) = 42 bytes = 60 bytes input
   - Output: 1 × 18 + 14 × 18 = 270 bytes → 206 bytes past buf[64]

**Option C: Repeated CONF_RSP (if channel stays in CONFIG state)**
1. After initial config exchange, send ADDITIONAL CONF_RSP(UNACCEPT) packets
2. Each triggers `l2cap_config_rsp()` if `num_conf_rsp` hasn't exceeded max
3. Chain multiple overflow attempts

---

## 6. ROP Chain Design (ARM32, No PXN)

### 6.1 No PXN Means Simpler Exploitation

Without PXN (Privileged Execute-Never), the kernel CAN execute userspace-mapped code.
This means we don't need a full ROP chain — we can jump to shellcode in user memory.

**However**, this is a KERNEL stack overflow triggered by a REMOTE Bluetooth packet.
There is no user process context to map shellcode into. We must use kernel addresses.

### 6.2 Simple Kernel Root Chain

Since there's NO KASLR and NO stack canaries:

```
commit_creds:        0xC0054328
prepare_kernel_cred: 0xC00548E0
selinux_enforcing:   0xC0B7AD18
```

**Minimal chain**:
1. Overflow saved LR with address of `prepare_kernel_cred`
2. Ensure r0 = 0 (NULL → create root credentials)
3. Return value (new cred) in r0
4. Chain to `commit_creds(r0)`
5. Return to normal execution

**Challenge**: The overflow writes `l2cap_add_conf_opt` output format, not raw addresses.
For MTU options, we get: `[type=0x01][len=0x02][val_lo][val_hi]` — only 2 bytes controlled.
For EFS options, we get: `[type=0x06][len=0x10][16 bytes of efs data]` — 16 bytes controlled
but the first 2 bytes are `0x06 0x10`.

**Solution**: Use EFS options with carefully crafted EFS struct values:
- The 16-byte EFS struct is: id(1) + stype(1) + msdu(2) + sdu_itime(4) + acc_lat(4) + flush_to(4)
- We control all 16 bytes via the initial valid EFS option
- For amplified short EFS options, the output is the PREVIOUS efs struct values

### 6.3 Gadget Requirements

We need gadgets from vmlinux at known addresses (no KASLR):
1. `mov r0, #0; bl prepare_kernel_cred` or equivalent
2. `bl commit_creds` with r0 = result of step 1
3. Return to caller / clean exit

**Alternative**: Since this is in Bluetooth kernel thread context (not syscall),
we may need to write to `selinux_enforcing` directly instead of using cred manipulation.
But TIMA monitors selinux_enforcing every 5 minutes.

---

## 7. Protocol Capture Recommendations

### 7.1 BT Snoop Log

The target has active HCI snoop logging:
```
/sdcard/Android/data/btsnoop_hci.log (363KB)
```

Pull this file for Wireshark analysis:
```bash
adb pull /sdcard/Android/data/btsnoop_hci.log
wireshark btsnoop_hci.log
```

### 7.2 Attack-Side Capture

On the Kali attack machine:
```bash
# Start btmon (BlueZ monitor)
sudo btmon -w attack_capture.btsnoop &

# Or capture with hcidump
sudo hcidump -w attack_hci.pcap

# Wireshark filters for L2CAP signaling:
# btl2cap.cid == 0x0001
# btl2cap.cmd_code == 0x05  (CONF_RSP)
# btl2cap.result == 0x0004  (PENDING)
```

### 7.3 Custom Wireshark Dissector

```lua
-- bluborne_detector.lua — highlight overflow CONF_RSP packets
local proto = Proto("bluborne", "BlueBorne Detector")

function proto.dissector(buffer, pinfo, tree)
    -- Check if this is L2CAP signaling
    if buffer:len() < 8 then return end

    local l2cap_len = buffer(0,2):le_uint()
    local l2cap_cid = buffer(2,2):le_uint()
    if l2cap_cid ~= 0x0001 then return end  -- Not signaling

    local sig_code = buffer(4,1):uint()
    if sig_code ~= 0x05 then return end  -- Not CONF_RSP

    local sig_len = buffer(6,2):le_uint()
    local result = buffer(12,2):le_uint()

    if result == 0x0004 then  -- PENDING
        pinfo.cols.info:append(" [BLUBORNE! PENDING CONF_RSP]")
    end

    if sig_len > 70 then  -- Suspiciously large
        local subtree = tree:add(proto, buffer())
        subtree:add_expert_info(PI_SECURITY, PI_WARN,
            "Possible CVE-2017-0782 overflow: " .. sig_len .. " bytes")
    end
end

-- Register as post-dissector
register_postdissector(proto)
```

---

## 8. Summary & Next Steps

### 8.1 Key Findings

1. **PENDING path** (`result=0x0004`) has NO input length validation — unlimited overflow
2. **UNACCEPT path** (`result=0x0001`) has 60-byte input limit but **output amplification**
   via EFS options with olen≠16 (3 bytes in → 18 bytes out)
3. **EFS amplification** allows up to 270 bytes of output from 60 bytes of input
4. ARM32 with NO stack canaries → direct LR overwrite → PC control
5. NO KASLR → all kernel addresses are static and known
6. NO PXN → kernel can execute at any address
7. The `CONF_LOC_CONF_PEND` flag requirement for PENDING path may be a blocker
   if the target doesn't support EFS/High Speed Bluetooth
8. All 6 existing exploit files have issues (see Section 5)

### 8.2 Recommended Attack Sequence

1. **Verify BT connectivity** via SDP query (CVE-2017-0785 info leak optional)
2. **Establish L2CAP channel** to PSM 0x0001 using raw HCI signaling
3. **Complete normal config exchange** (accept target's CONF_REQ, send our CONF_REQ)
4. **Determine if PENDING path is viable** — check if target ever sends CONF_RSP(PENDING)
5. **If PENDING available**: Send overflow CONF_RSP(PENDING) with unlimited EFS options
6. **If UNACCEPT only**: Send amplified CONF_RSP(UNACCEPT) with short EFS options
7. **Verify crash** → adjust offset → send with ROP chain

### 8.3 Required for Exploitation

- **Linux attack machine** with Bluetooth adapter (Kali recommended)
- **Root/CAP_NET_RAW** for raw HCI socket access
- **BlueZ tools**: hcitool, btmon, hcidump
- **Physical proximity**: ~10 meters Bluetooth range
- **Target BT ON**: 02:00:00:00:00:21 (controllable from ADB shell)
- **vmlinux disassembly**: Extract exact stack frame layout and ROP gadgets

### 8.4 Open Questions

1. Does the SM-T377A's L2CAP support EFS / High Speed mode (`enable_hs`)?
2. What is the exact compiler padding between buf[64] and saved registers?
3. Can we trigger repeated `l2cap_config_rsp()` calls after initial config?
4. What is the state of the `efs` local variable when amplification is used?
5. Can the BT snoop log reveal the exact L2CAP config exchange for this target?

---

## Appendix A: L2CAP CONF_RSP Packet Format (Exploit Payload)

```
L2CAP Header (4 bytes):
  [length_lo] [length_hi] [0x01] [0x00]    # CID = 0x0001 (signaling)

Signaling Header (4 bytes):
  [0x05]      [ident]     [len_lo] [len_hi] # code=CONF_RSP

CONF_RSP Payload:
  [scid_lo]   [scid_hi]                     # Source CID (target's DCID)
  [flags_lo]  [flags_hi]                    # Flags (0x0000)
  [result_lo] [result_hi]                   # Result: 0x0004=PENDING, 0x0001=UNACCEPT

Configuration Options (variable):
  [type] [len] [value...]                   # Repeated N times
  [type] [len] [value...]                   # Each l2cap_add_conf_opt writes type+len+value
  ...
```

## Appendix B: EFS Struct Layout (16 bytes)

```c
struct l2cap_conf_efs {
    __u8    id;         // offset 0:  Endpoint ID
    __u8    stype;      // offset 1:  Service Type (0x01=Best Effort, 0x02=Guaranteed)
    __le16  msdu;       // offset 2:  Max SDU size
    __le32  sdu_itime;  // offset 4:  SDU inter-arrival time
    __le32  acc_lat;    // offset 8:  Access latency
    __le32  flush_to;   // offset 12: Flush timeout
};                      // Total: 16 bytes
```

When used for ROP: place target addresses at offsets 4, 8, and 12 (32-bit aligned fields).

## Appendix C: Known Kernel Symbols

| Symbol | Address | Use |
|--------|---------|-----|
| `commit_creds` | 0xC0054328 | Apply credentials (give root) |
| `prepare_kernel_cred` | 0xC00548E0 | Create new root credentials |
| `selinux_enforcing` | 0xC0B7AD18 | SELinux enforce flag (TIMA-monitored!) |
| `selinux_enabled` | 0xC0AB00A8 | SELinux enabled flag |
| `task_struct->cred` | offset 0x164 | Current process credentials |
| `thread_info->addr_limit` | offset 8 | KERNEL_DS = 0xFFFFFFFF |
