"""Extract PIT file from Samsung firmware tar.md5 files."""
import tarfile
import os
import sys

IMAGES_DIR = r'C:\InfoSec\android-redteam\images'
OUTPUT_DIR = r'C:\InfoSec\android-redteam\data'

# Samsung tar.md5 files to check (BL most likely has PIT)
tar_files = [
    os.path.join(IMAGES_DIR, 'BL_T377AUCU2AQGF_CL11788437_QB14156771_REV00_user_low_ship.tar.md5'),
    os.path.join(IMAGES_DIR, 'CP_T377AUCU2AQGF_CL11788437_QB14156771_REV00_user_low_ship.tar.md5'),
    os.path.join(IMAGES_DIR, 'CSC_ATT_T377AATT2AQGF_CL11788437_QB14156771_REV00_user_low_ship.tar.md5'),
]

for tar_path in tar_files:
    name = os.path.basename(tar_path)
    print(f"\n{'='*60}")
    print(f"Checking: {name}")
    print(f"{'='*60}")
    
    try:
        with tarfile.open(tar_path, 'r:') as tf:
            members = tf.getmembers()
            for m in members:
                suffix = ""
                if m.name.endswith('.pit'):
                    suffix = " <--- PIT FILE!"
                print(f"  {m.size:>12}  {m.name}{suffix}")
            
            # Extract PIT files
            for m in members:
                if m.name.endswith('.pit'):
                    print(f"\n  Extracting {m.name}...")
                    f = tf.extractfile(m)
                    if f:
                        data = f.read()
                        outpath = os.path.join(OUTPUT_DIR, 'sm-t377a.pit')
                        with open(outpath, 'wb') as out:
                            out.write(data)
                        print(f"  Saved to {outpath} ({len(data)} bytes)")
    except Exception as e:
        print(f"  Error: {e}")

# Also check AP tar (it's large, just list first few entries)
ap_path = os.path.join(IMAGES_DIR, 'AP_T377AUCU2AQGF_CL11788437_QB14156771_REV00_user_low_ship.tar.md5')
print(f"\n{'='*60}")
print(f"Checking AP tar (listing only, large file)...")
print(f"{'='*60}")
try:
    with tarfile.open(ap_path, 'r:') as tf:
        for m in tf.getmembers():
            suffix = ""
            if m.name.endswith('.pit'):
                suffix = " <--- PIT FILE!"
            print(f"  {m.size:>12}  {m.name}{suffix}")
            
            if m.name.endswith('.pit'):
                print(f"\n  Extracting {m.name} from AP...")
                f = tf.extractfile(m)
                if f:
                    data = f.read()
                    outpath = os.path.join(OUTPUT_DIR, 'sm-t377a-ap.pit')
                    with open(outpath, 'wb') as out:
                        out.write(data)
                    print(f"  Saved to {outpath} ({len(data)} bytes)")
except Exception as e:
    print(f"  Error: {e}")

# Check if PIT was found
pit_path = os.path.join(OUTPUT_DIR, 'sm-t377a.pit')
if os.path.exists(pit_path) and os.path.getsize(pit_path) > 0:
    print(f"\n{'='*60}")
    print(f"PIT FILE EXTRACTED: {pit_path} ({os.path.getsize(pit_path)} bytes)")
    print(f"{'='*60}")
else:
    print("\nNo PIT file found in firmware tars.")
