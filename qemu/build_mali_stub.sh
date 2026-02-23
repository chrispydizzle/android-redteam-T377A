#!/bin/bash
# build_mali_stub.sh — Builds the Mali stub kernel module
set -e

KDIR="$HOME/kernel-fuzz/linux-3.10.108"
CROSS="$HOME/kernel-fuzz/gcc-linaro-4.9.4/bin/arm-linux-gnueabi-"
MODDIR="$HOME/kernel-fuzz/mali_stub"
ROOTFS="$HOME/kernel-fuzz/rootfs"

mkdir -p "$MODDIR"
cp /mnt/c/InfoSec/android-redteam/qemu/mali_stub.c "$MODDIR/"

# Create proper Makefile with tabs
cat > "$MODDIR/Makefile" <<'MEOF'
obj-m := mali_stub.o
MEOF

echo "[*] Building mali_stub.ko..."
make -C "$KDIR" M="$MODDIR" ARCH=arm CROSS_COMPILE="$CROSS" modules 2>&1

if [ ! -f "$MODDIR/mali_stub.ko" ]; then
    echo "[-] Build failed!"
    exit 1
fi

echo "[+] mali_stub.ko built successfully"
file "$MODDIR/mali_stub.ko"

# Install into rootfs
mkdir -p "$ROOTFS/lib/modules"
cp "$MODDIR/mali_stub.ko" "$ROOTFS/lib/modules/"
echo "[+] Copied to rootfs/lib/modules/"

# Update init to load the module
cat > "$ROOTFS/init" <<'INITEOF'
#!/bin/busybox sh
/bin/busybox --install -s /bin
/bin/busybox --install -s /sbin
/bin/busybox --install -s /usr/bin
/bin/busybox --install -s /usr/sbin

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /dev/pts /dev/shm
mount -t devpts devpts /dev/pts
mount -t tmpfs tmpfs /tmp

hostname qemu-fuzz

echo "=================================="
echo " QEMU ARM Kernel Fuzzing VM"
echo " Kernel: $(uname -r)"
echo " Arch:   $(uname -m)"
echo "=================================="

# Load Mali stub module
if [ -f /lib/modules/mali_stub.ko ]; then
    echo "[*] Loading mali_stub.ko..."
    insmod /lib/modules/mali_stub.ko
    if [ $? -eq 0 ]; then
        echo "[+] Mali stub loaded — /dev/mali0 available"
    else
        echo "[-] Failed to load mali_stub.ko"
    fi
fi

# Show available device nodes
echo ""
echo "Device nodes:"
ls -la /dev/mali0 /dev/binder /dev/ashmem 2>/dev/null || echo "(some nodes missing)"

# Auto-run /bin/autorun if it exists
if [ -x /bin/autorun ]; then
    echo ""
    echo "[*] Running /bin/autorun..."
    /bin/autorun
    echo "[*] autorun finished (exit=$?)"
fi

exec /bin/sh
INITEOF
chmod +x "$ROOTFS/init"

# Repack initramfs
cd "$ROOTFS"
find . | cpio -o -H newc 2>/dev/null | gzip > "$HOME/kernel-fuzz/initramfs.cpio.gz"
echo "[+] initramfs repacked with mali_stub.ko"
