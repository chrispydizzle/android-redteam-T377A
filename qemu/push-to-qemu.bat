@echo off
REM ============================================================
REM  push-to-qemu.bat — Compile C and inject into QEMU rootfs
REM
REM  Usage:  push-to-qemu.bat myprogram.c
REM          push-to-qemu.bat myprogram.c myprogram
REM
REM  Compiles the source, adds it to the initramfs, and tells
REM  you to restart QEMU to pick it up.
REM ============================================================

setlocal enabledelayedexpansion

if "%~1"=="" (
    echo Usage: push-to-qemu.bat source.c [output_name]
    exit /b 1
)

if "%~1"=="--no-compile" (
    set "OUT=%~2"
    echo "not compiling, just pushing %OUT% to QEMU rootfs"
    GOTO NO_COMPILE
)

set "SRC=%~1"
if "%~2"=="" ( set "OUT=%~n1" ) else ( set "OUT=%~2" )

echo [*] Compiling %SRC% -^> %OUT% (static ARM PIE^)


REM --- Convert path and compile with Linaro GCC ---
for /f "delims=" %%i in ('wsl -d Ubuntu-22.04 -- wslpath -a "%cd:\=/%/%SRC%"') do set "WSL_SRC=%%i"
wsl -d Ubuntu-22.04 -- bash -c "~/kernel-fuzz/gcc-linaro-4.9.4/bin/arm-linux-gnueabi-gcc -o /tmp/%OUT% '%WSL_SRC%' -static -march=armv7-a -O2 -Wall 2>&1"
if errorlevel 1 (
    echo [!] Compilation failed.
    exit /b 1
)

echo [+] Compiled.

:NO_COMPILE
REM --- Add to rootfs and rebuild initramfs ---
wsl -d Ubuntu-22.04 -- bash -c "cp /tmp/%OUT% ~/kernel-fuzz/rootfs/bin/%OUT% && chmod +x ~/kernel-fuzz/rootfs/bin/%OUT% && cd ~/kernel-fuzz/rootfs && find . | cpio -o -H newc 2>/dev/null | gzip > ~/kernel-fuzz/initramfs.cpio.gz"

echo [+] Added to QEMU rootfs at /bin/%OUT%
echo [*] Restart QEMU (run-qemu.bat) to use it.

endlocal
