@echo off
REM ============================================================
REM  run-qemu.bat — Launch QEMU ARM kernel fuzzing VM
REM
REM  Usage:  run-qemu.bat           (interactive shell)
REM          run-qemu.bat headless   (serial output to file)
REM ============================================================

setlocal

set "KDIR=~/kernel-fuzz"
set "KERNEL=%KDIR%/linux-3.10.108/arch/arm/boot/zImage"
set "DTB=%KDIR%/linux-3.10.108/arch/arm/boot/dts/vexpress-v2p-ca9.dtb"
set "INITRD=%KDIR%/initramfs.cpio.gz"

if /i "%~1"=="headless" (
    echo [*] Starting QEMU in headless mode (output to ~/kernel-fuzz/serial.log^)
    wsl -d Ubuntu-22.04 -- qemu-system-arm -M vexpress-a9 -kernel %KERNEL% -dtb %DTB% -initrd %INITRD% -serial file:%KDIR%/serial.log -display none -append "console=ttyAMA0 root=/dev/ram rdinit=/init panic=1 slub_debug=FZPU" -m 256M -no-reboot
) else (
    echo [*] Starting QEMU (Ctrl-A X to quit^)
    wsl -d Ubuntu-22.04 -- qemu-system-arm -M vexpress-a9 -kernel %KERNEL% -dtb %DTB% -initrd %INITRD% -nographic -append "console=ttyAMA0 root=/dev/ram rdinit=/init panic=1 slub_debug=FZPU" -m 256M -no-reboot
)

endlocal
