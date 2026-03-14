param(
  [string]$OutDir = ".\crash_artifacts",
  [switch]$NoBugreport
)

$ErrorActionPreference = "Continue"

function Require-Adb {
  $adb = Get-Command adb -ErrorAction SilentlyContinue
  if (-not $adb) {
    Write-Host "adb not found in PATH. Install Android platform-tools or add adb to PATH." -ForegroundColor Red
    exit 1
  }
}

function Run($cmd, $outfile) {
  Write-Host ">> $cmd"
  try {
    # Use cmd.exe so pipes/redirection behave predictably
    cmd.exe /c $cmd | Out-File -FilePath $outfile -Encoding utf8
  } catch {
    "ERROR running: $cmd`n$($_.Exception.Message)" | Out-File -FilePath $outfile -Encoding utf8
  }
}

function RunRaw($cmd, $outfile) {
  Write-Host ">> $cmd"
  try {
    cmd.exe /c $cmd > $outfile 2>&1
  } catch {
    "ERROR running: $cmd`n$($_.Exception.Message)" | Out-File -FilePath $outfile -Encoding utf8
  }
}

Require-Adb

# Timestamped folder
$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$dest = Join-Path $OutDir $ts
New-Item -ItemType Directory -Force -Path $dest | Out-Null

# Basic device info
RunRaw "adb devices" (Join-Path $dest "adb_devices.txt")
RunRaw "adb shell getprop" (Join-Path $dest "getprop.txt")

# Uptime / memory stats (no-root friendly)
RunRaw "adb shell cat /proc/uptime" (Join-Path $dest "proc_uptime.txt")
RunRaw "adb shell cat /proc/meminfo" (Join-Path $dest "proc_meminfo.txt")
RunRaw "adb shell cat /proc/vmstat" (Join-Path $dest "proc_vmstat.txt")

# Logcat buffers
RunRaw "adb logcat -b all -d -v threadtime" (Join-Path $dest "logcat_all.txt")
RunRaw "adb logcat -b crash -d -v threadtime" (Join-Path $dest "logcat_crash.txt")

# Kernel buffer often blocked on user builds, but try
RunRaw "adb logcat -b kernel -d -v threadtime" (Join-Path $dest "logcat_kernel.txt")

# Dropbox: VERY high signal for watchdog/system_server crashes/reboots
RunRaw "adb shell dumpsys dropbox --print" (Join-Path $dest "dropbox_print.txt")

# Extra system state that can hint at watchdogs / restarts
RunRaw "adb shell dumpsys activity processes" (Join-Path $dest "dumpsys_activity_processes.txt")
RunRaw "adb shell dumpsys power" (Join-Path $dest "dumpsys_power.txt")

# Best-effort listings for persistent crash artifacts (often permission denied without root)
RunRaw "adb shell ls -la /sys/fs/pstore" (Join-Path $dest "ls_pstore.txt")
RunRaw "adb shell ls -la /data/tombstones" (Join-Path $dest "ls_tombstones.txt")
RunRaw "adb shell ls -la /cache/recovery" (Join-Path $dest "ls_cache_recovery.txt")

# Grab fuzzer log if you store it somewhere readable (edit paths as needed)
# Try common locations:
$fuzzPaths = @(
  "/sdcard/Download/mali_fuzz.log",
  "/sdcard/mali_fuzz.log",
  "/data/local/tmp/mali_fuzz.log"
)

$pulledAny = $false
foreach ($p in $fuzzPaths) {
  $target = Join-Path $dest ("pulled_" + ($p -replace "[/:]", "_"))
  Write-Host ">> adb pull $p $target"
  cmd.exe /c "adb pull $p $target" | Out-Null
  if (Test-Path $target) { $pulledAny = $true }
}
if (-not $pulledAny) {
  "No fuzzer log pulled from common locations. If you log elsewhere, add the path in the script." |
    Out-File -FilePath (Join-Path $dest "fuzzer_log_pull.txt") -Encoding utf8
}

# Optional: bugreport (can be large/slow)
if (-not $NoBugreport) {
  $bug = Join-Path $dest "bugreport.zip"
  Write-Host ">> adb bugreport $bug"
  try {
    cmd.exe /c "adb bugreport $bug" | Out-Null
  } catch {
    "ERROR running adb bugreport: $($_.Exception.Message)" | Out-File -FilePath (Join-Path $dest "bugreport_error.txt") -Encoding utf8
  }
} else {
  "Bugreport disabled via -NoBugreport" | Out-File -FilePath (Join-Path $dest "bugreport_skipped.txt") -Encoding utf8
}

Write-Host ""
Write-Host "Collected artifacts in: $dest" -ForegroundColor Green
Write-Host "Tip: run right after reboot (or right after you regain ADB) for best signal."