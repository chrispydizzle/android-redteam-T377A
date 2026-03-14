#!/usr/bin/env python3
"""Samsung SysDump OTP Solver - Reversed from LibOTPSecurity.OTPSecurity"""
import datetime
import sys

def make_hash_code(arg):
    """DJB2 variant: hash = hash*33 + char, abs value"""
    h = 0
    for c in arg:
        h = ((h << 5) + h + ord(c)) & 0xFFFFFFFF
    if h >= 0x80000000:
        h = h - 0x100000000
    if h < 0:
        h = -h
    return h

def get_date_string(minute_offset=0):
    """YYMMmmDDHH in GMT"""
    now = datetime.datetime.utcnow() - datetime.timedelta(minutes=minute_offset)
    yy = now.year - 2000
    mm = now.month
    minute = now.minute
    dd = now.day
    hh = now.hour
    return "{:02d}{:02d}{:02d}{:02d}{:02d}".format(yy, mm, minute, dd, hh)

def solve_otp(key):
    now = datetime.datetime.utcnow()
    print("GMT time: {}".format(now.strftime("%Y-%m-%d %H:%M:%S")))
    print("Key: {}".format(key))
    print()
    for offset in range(6):
        ds = get_date_string(offset)
        combined = key + ds
        code = make_hash_code(combined)
        marker = " <-- USE THIS" if offset == 0 else ""
        print("  offset={}min: {} -> {}{}".format(offset, combined, code, marker))

if __name__ == "__main__":
    if len(sys.argv) > 1:
        key = sys.argv[1]
    else:
        key = input("Enter OTP key from device: ").strip()
    solve_otp(key)
