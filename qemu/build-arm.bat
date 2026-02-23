@echo off
REM ============================================================
REM  build-arm.bat — Cross-compile C source for ARM Android 6.0.1
REM  Target: Samsung SM-T377A (ARMv7 Cortex-A7, Android 6.0.1)
REM
REM  Usage:  build-arm.bat myprogram.c
REM          build-arm.bat myprogram.c myprogram
REM
REM  Arg 1:  Source file  (required)
REM  Arg 2:  Output name  (optional, defaults to source name without .c)
REM
REM  On first run, installs gcc-arm-linux-gnueabi in WSL Ubuntu.
REM  Produces a static PIE ARM binary, pushes to device, and
REM  sets executable permissions.
REM ============================================================

setlocal enabledelayedexpansion

if "%~1"=="" (
    echo Usage: build-arm.bat source.c [output_name]
    echo.
    echo   source.c    - C source file to compile
    echo   output_name - optional binary name ^(default: source name^)
    exit /b 1
)

set "SRC=%~1"
if "%~2"=="" (
    set "OUT=%~n1"
) else (
    set "OUT=%~2"
)

echo [*] Source: %SRC%
echo [*] Output: %OUT%

REM --- Check source file exists ---
if not exist "%SRC%" (
    echo [!] Error: source file "%SRC%" not found.
    exit /b 1
)

REM --- Check WSL is available ---
wsl --list >nul 2>&1
if errorlevel 1 (
    echo [!] Error: WSL not available. Install WSL with Ubuntu.
    exit /b 1
)

REM --- Install cross-compiler if needed (one-time) ---
echo [*] Checking cross-compiler in WSL...
wsl -d Ubuntu-22.04 -- bash -c "which arm-linux-gnueabi-gcc >/dev/null 2>&1"
if errorlevel 1 (
    echo [*] Installing gcc-arm-linux-gnueabi in WSL ^(one-time^)...
    wsl -d Ubuntu-22.04 -- bash -c "sudo apt-get update -qq && sudo apt-get install -y -qq gcc-arm-linux-gnueabi"
    if errorlevel 1 (
        echo [!] Failed to install cross-compiler. Run manually:
        echo     wsl -d Ubuntu-22.04 -- sudo apt-get install gcc-arm-linux-gnueabi
        exit /b 1
    )
    echo [+] Cross-compiler installed.
) else (
    echo [+] Cross-compiler already installed.
)

REM --- Convert Windows path to WSL path ---
set "WINDIR_=%cd%"
for /f "delims=" %%i in ('wsl -d Ubuntu-22.04 -- wslpath -a "%WINDIR_%\%SRC%"') do set "WSL_SRC=%%i"
for /f "delims=" %%i in ('wsl -d Ubuntu-22.04 -- wslpath -a "%WINDIR_%"') do set "WSL_DIR=%%i"

echo [*] Compiling with arm-linux-gnueabi-gcc (static PIE)...

REM --- Compile: static, PIE, ARM32 ---
wsl -d Ubuntu-22.04 -- bash -c "arm-linux-gnueabi-gcc -o '%WSL_DIR%/%OUT%' '%WSL_SRC%' -static -pie -fPIE -march=armv7-a -mfloat-abi=soft -O2 -Wall 2>&1"
if errorlevel 1 (
    echo [!] Compilation failed. Check errors above.
    exit /b 1
)

echo [+] Compiled: %OUT%

REM --- Verify binary ---
wsl -d Ubuntu-22.04 -- bash -c "file '%WSL_DIR%/%OUT%'"

REM --- Push to device if adb is connected ---
adb get-state >nul 2>&1
if errorlevel 1 (
    echo [*] No ADB device connected. Binary at: %cd%\%OUT%
    echo     Push manually: adb push %OUT% /data/local/tmp/
) else (
    echo [*] Pushing to device...
    adb push "%OUT%" /data/local/tmp/%OUT%
    adb shell "chmod 755 /data/local/tmp/%OUT%"
    echo [+] Ready: /data/local/tmp/%OUT%
    echo     Run:   adb shell /data/local/tmp/%OUT%
)

endlocal
