REM Launch the Repo Explorer — serves on http://127.0.0.1:8787
REM Regenerates file tree + contents + PII scan, then opens browser.

cd /d "%~dp0..\..\"

echo [*] Scanning repo + PII detection...
echo errorlevel: %errorlevel%
python docs\dashboards\_scan_repo.py &
if errorlevel 1 (
    echo [!] Scan failed. Make sure Python 3 is installed.
    pause
    exit /b 1
)

echo errorlevel: %errorlevel%
cd /d "%~dp0"
echo [*] Starting server on http://127.0.0.1:8787
echo     v1: http://127.0.0.1:8787/repo-explorer.html
echo     v2: http://127.0.0.1:8787/repo-explorer-v2.html  (treemap + PII)
echo.
start "python -m http.server 8787 --bind 127.0.0.1" http://127.0.0.1:8787/repo-explorer-v2.html

