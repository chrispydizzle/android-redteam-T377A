@echo off
REM ============================================================
REM  rebuild-kernel.bat — Rebuild the 3.10.108 ARM kernel
REM
REM  Usage:  rebuild-kernel.bat              (just rebuild)
REM          rebuild-kernel.bat menuconfig    (open config menu first)
REM ============================================================

setlocal

if /i "%~1"=="menuconfig" (
    echo [*] Opening kernel menuconfig...
    wsl -d Ubuntu-22.04 -- bash -c "cd ~/kernel-fuzz/linux-3.10.108 && export ARCH=arm && export CROSS_COMPILE=$HOME/kernel-fuzz/gcc-linaro-4.9.4/bin/arm-linux-gnueabi- && make menuconfig"
)

echo [*] Building kernel...
wsl -d Ubuntu-22.04 -- bash -c "cd ~/kernel-fuzz/linux-3.10.108 && export ARCH=arm && export CROSS_COMPILE=$HOME/kernel-fuzz/gcc-linaro-4.9.4/bin/arm-linux-gnueabi- && make -j$(nproc) zImage dtbs 2>&1 | tail -5 && ls -lh arch/arm/boot/zImage"

echo [+] Done. Run with: run-qemu.bat
endlocal
