"""USB device enumeration - skip string descriptors, enumerate endpoints."""
import sys, os, struct, time

# Set libusb DLL path
os.environ['PATH'] = r'C:\InfoSec\Samsung\Heimdall Suite' + os.pathsep + os.environ.get('PATH', '')

import usb.core
import usb.util
import usb.backend.libusb1

VID = 0x04E8
PID = 0x685D

dll_path = r'C:\Program Files\qemu\libusb-1.0.dll'
print(f"Using libusb: {dll_path} (exists={os.path.exists(dll_path)})")

# Try ctypes load first to verify DLL works
import ctypes
try:
    lib = ctypes.CDLL(dll_path)
    print(f"  ctypes load OK: {lib}")
except Exception as e:
    print(f"  ctypes load failed: {e}")

be = usb.backend.libusb1.get_backend(find_library=lambda x: dll_path)
print(f"Backend: {be}")
dev = usb.core.find(idVendor=VID, idProduct=PID, backend=be)

if dev is None:
    print("Device not found")
    sys.exit(1)

print(f"Device: VID={dev.idVendor:04x} PID={dev.idProduct:04x}")
print(f"  bcdDevice: {dev.bcdDevice:04x}")
print(f"  bDeviceClass: {dev.bDeviceClass}")
print(f"  bDeviceSubClass: {dev.bDeviceSubClass}")
print(f"  bNumConfigurations: {dev.bNumConfigurations}")

try:
    print(f"  Manufacturer: {dev.manufacturer}")
except:
    print(f"  Manufacturer: (unavailable - driver permission)")
try:
    print(f"  Product: {dev.product}")
except:
    print(f"  Product: (unavailable)")
try:
    print(f"  Serial: {dev.serial_number}")
except:
    print(f"  Serial: (unavailable)")

# Enumerate all configs/interfaces/endpoints
for cfg in dev:
    print(f"\nConfiguration {cfg.bConfigurationValue} (MaxPower={cfg.bMaxPower*2}mA)")
    for intf in cfg:
        cls_names = {2: "CDC", 10: "CDC-Data", 0xFF: "Vendor", 0: "None", 8: "MassStorage", 6: "Imaging"}
        cls = cls_names.get(intf.bInterfaceClass, f"0x{intf.bInterfaceClass:02x}")
        print(f"\n  Interface {intf.bInterfaceNumber} Alt {intf.bAlternateSetting}: "
              f"Class={cls}({intf.bInterfaceClass}), SubClass={intf.bInterfaceSubClass}, "
              f"Protocol={intf.bInterfaceProtocol}")
        
        ep_types = {0: "CTRL", 1: "ISO", 2: "BULK", 3: "INT"}
        for ep in intf:
            direction = "IN" if usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_IN else "OUT"
            ep_type = ep_types.get(usb.util.endpoint_type(ep.bmAttributes), "?")
            print(f"    EP 0x{ep.bEndpointAddress:02x} {direction:3s} {ep_type:4s} MaxPkt={ep.wMaxPacketSize}")

# Try to claim each interface and do bulk I/O
print("\n--- Attempting interface access ---")
for cfg in dev:
    for intf in cfg:
        intf_num = intf.bInterfaceNumber
        
        # Find bulk endpoints
        bulk_in = None
        bulk_out = None
        for ep in intf:
            if usb.util.endpoint_type(ep.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK:
                if usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_IN:
                    bulk_in = ep
                else:
                    bulk_out = ep
        
        if not (bulk_in and bulk_out):
            continue
            
        print(f"\nInterface {intf_num}: BULK pair found (OUT=0x{bulk_out.bEndpointAddress:02x}, IN=0x{bulk_in.bEndpointAddress:02x})")
        
        # Try detach kernel driver
        try:
            if dev.is_kernel_driver_active(intf_num):
                print(f"  Kernel driver active, attempting detach...")
                dev.detach_kernel_driver(intf_num)
                print(f"  Detached!")
        except usb.core.USBError as e:
            print(f"  Cannot detach kernel driver: {e}")
        except NotImplementedError:
            print(f"  detach_kernel_driver not supported on Windows")
        
        # Try claim
        try:
            usb.util.claim_interface(dev, intf_num)
            print(f"  Interface claimed!")
            
            # Send ODIN handshake
            print(f"  Sending ODIN...")
            try:
                bulk_out.write(b'ODIN')
                time.sleep(1)
                resp = bulk_in.read(1024, timeout=5000)
                resp_bytes = bytes(resp)
                print(f"  Response: {resp_bytes!r} ({resp_bytes.hex()})")
                if resp_bytes == b'LOKE':
                    print("  *** SUCCESS: LOKE received! ***")
            except usb.core.USBError as e:
                print(f"  I/O error: {e}")
            
            usb.util.release_interface(dev, intf_num)
            
        except usb.core.USBError as e:
            print(f"  Cannot claim interface: {e}")

print("\nDone.")
