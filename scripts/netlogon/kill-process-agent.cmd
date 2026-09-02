@echo off
:: WAZUH-KK-AR-V1
:: Wazuh Active Response - Agent-side process killer
:: Deployed by: install-wazuh.ps1 via GPO
:: Triggered by: rules 100013,100014,100015,100016,100017

setlocal enabledelayedexpansion

set LOG="%PROGRAMFILES(X86)%\ossec-agent\active-response\active-responses.log"
set TMPFILE=%TEMP%\wazuh_ar_%RANDOM%.json

:: Read stdin via PowerShell - handles long JSON without cmd line length limits
powershell -NoProfile -Command ^
  "$raw = [Console]::In.ReadToEnd(); $raw | Out-File -FilePath '%TMPFILE%' -Encoding UTF8 -NoNewline"

:: Extract fields from parameters.alert path
for /f "delims=" %%P in ('powershell -NoProfile -Command ^
  "try { $d = Get-Content '%TMPFILE%' | ConvertFrom-Json; $d.parameters.alert.data.win.eventdata.processId } catch { '' }"') do set TARGET_PID=%%P

for /f "delims=" %%I in ('powershell -NoProfile -Command ^
  "try { $d = Get-Content '%TMPFILE%' | ConvertFrom-Json; $d.parameters.alert.data.win.eventdata.image } catch { 'unknown' }"') do set PROC_IMAGE=%%I

for /f "delims=" %%R in ('powershell -NoProfile -Command ^
  "try { $d = Get-Content '%TMPFILE%' | ConvertFrom-Json; $d.parameters.alert.rule.id } catch { 'unknown' }"') do set RULE_ID=%%R

for /f "delims=" %%U in ('powershell -NoProfile -Command ^
  "try { $d = Get-Content '%TMPFILE%' | ConvertFrom-Json; $d.parameters.alert.data.win.eventdata.user } catch { 'unknown' }"') do set PROC_USER=%%U

echo [%DATE% %TIME%] ===== kill-process-agent triggered ===== >> %LOG%
echo [%DATE% %TIME%] Rule: %RULE_ID% >> %LOG%
echo [%DATE% %TIME%] Image: %PROC_IMAGE% >> %LOG%
echo [%DATE% %TIME%] User: %PROC_USER% >> %LOG%
echo [%DATE% %TIME%] PID: %TARGET_PID% >> %LOG%

if "%TARGET_PID%"=="" (
    echo [%DATE% %TIME%] WARNING: No PID extracted from alert - kill skipped >> %LOG%
    goto cleanup
)

:: Confirm process still exists before killing
tasklist /FI "PID eq %TARGET_PID%" 2>nul | find "%TARGET_PID%" >nul
if errorlevel 1 (
    echo [%DATE% %TIME%] INFO: PID %TARGET_PID% no longer running - no action needed >> %LOG%
    goto cleanup
)

:: Kill it
taskkill /PID %TARGET_PID% /F >> %LOG% 2>&1
if errorlevel 1 (
    echo [%DATE% %TIME%] ERROR: taskkill failed for PID %TARGET_PID% >> %LOG%
) else (
    echo [%DATE% %TIME%] SUCCESS: PID %TARGET_PID% terminated >> %LOG%
)

:cleanup
del /f /q %TMPFILE% 2>nul
exit 0