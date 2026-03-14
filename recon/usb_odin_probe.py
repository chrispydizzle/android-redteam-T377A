"""Direct USB access to Samsung download mode device using pyusb.
Also checks for libusb DLL availability and tries multiple backends.
"""
import sys
import os
import struct
import time

# Try to find libusb DLL
libusb_paths = [
    r"C:\InfoSec\Samsung\Heimdall Suite",
    r"C:\InfoSec\Samsung\Heimdall Suite\Drivers",
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
]

for p in libusb_paths:
    if os.path.isdir(p):
        for f in os.listdir(p):
            if 'libusb' in f.lower() and f.endswith('.dll'):
                print(f"Found: {os.path.join(p, f)}")

print()

# Try importing usb
try:
    import usb.core
    import usb.util
    import usb.backend.libusb1
    import usb.backend.libusb0
    print("pyusb imported successfully")
except ImportError as e:
    print(f"Import error: {e}")
    sys.exit(1)

VID = 0x04E8  # Samsung
PID = 0x685D  # Download mode

# Try to find the device
print(f"\nSearching for Samsung device (VID={VID:04x}, PID={PID:04x})...")

# Try different backends
backends = []
try:
    be1 = usb.backend.libusb1.get_backend()
    if be1:
        backends.append(("libusb1", be1))
        print("  libusb1 backend: available")
except:
    print("  libusb1 backend: not available")

try:
    be0 = usb.backend.libusb0.get_backend()
    if be0:
        backends.append(("libusb0", be0))
        print("  libusb0 backend: available")
except:
    print("  libusb0 backend: not available")

# Also try without explicit backend (uses default search)
backends.append(("default", None))

for name, backend in backends:
    print(f"\n--- Trying {name} backend ---")
    try:
        if backend:
            dev = usb.core.find(idVendor=VID, idProduct=PID, backend=backend)
        else:
            dev = usb.core.find(idVendor=VID, idProduct=PID)
        
        if dev is None:
            print(f"  Device not found with {name}")
            continue
        
        print(f"  Device found!")
        print(f"  Manufacturer: {dev.manufacturer}")
        print(f"  Product: {dev.product}")
        print(f"  Serial: {dev.serial_number}")
        print(f"  Configs: {dev.bNumConfigurations}")
        
        # List configurations and interfaces
        for cfg in dev:
            print(f"\n  Config {cfg.bConfigurationValue}:")
            for intf in cfg:
                print(f"    Interface {intf.bInterfaceNumber}, Alt {intf.bAlternateSetting}")
                print(f"      Class: {intf.bInterfaceClass}, SubClass: {intf.bInterfaceSubClass}")
                for ep in intf:
                    direction = "IN" if usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_IN else "OUT"
                    print(f"      EP 0x{ep.bEndpointAddress:02x} ({direction}), "
                          f"Type: {usb.util.endpoint_type(ep.bmAttributes)}, "
                          f"MaxPacket: {ep.wMaxPacketSize}")
        
        # Try to detach kernel driver and claim interface
        print("\n  Attempting to access bulk endpoints...")
        for intf_num in range(4):
            try:
                if dev.is_kernel_driver_active(intf_num):
                    print(f"    Interface {intf_num}: kernel driver active, detaching...")
                    dev.detach_kernel_driver(intf_num)
            except:
                pass
        
        # Try to set configuration
        try:
            dev.set_configuration()
            print("  Configuration set")
        except Exception as e:
            print(f"  set_configuration: {e}")
        
        # Find bulk endpoints
        cfg = dev.get_active_configuration()
        for intf in cfg:
            eps_in = [ep for ep in intf if usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_IN
                      and usb.util.endpoint_type(ep.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK]
            eps_out = [ep for ep in intf if usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_OUT
                       and usb.util.endpoint_type(ep.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK]
            
            if eps_in and eps_out:
                print(f"\n  Bulk pair on interface {intf.bInterfaceNumber}:")
                print(f"    OUT: 0x{eps_out[0].bEndpointAddress:02x}")
                print(f"    IN:  0x{eps_in[0].bEndpointAddress:02x}")
                
                try:
                    usb.util.claim_interface(dev, intf.bInterfaceNumber)
                    print(f"    Interface claimed!")
                    
                    # Try ODIN handshake
                    print("    Sending ODIN handshake...")
                    eps_out[0].write(b'ODIN')
                    time.sleep(1)
                    try:
                        resp = eps_in[0].read(1024, timeout=5000)
                        print(f"    Response: {bytes(resp)!r}")
                        if bytes(resp) == b'LOKE':
                            print("    *** LOKE RECEIVED! ***")
                    except Exception as e:
                        print(f"    Read error: {e}")
                    
                    usb.util.release_interface(dev, intf.bInterfaceNumber)
                except Exception as e:
                    print(f"    Claim/IO error: {e}")
        
        break
        
    except Exception as e:
        print(f"  Error: {e}")
        import traceback
        traceback.print_exc()

print("\nDone.")
