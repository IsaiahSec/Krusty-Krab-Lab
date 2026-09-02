# =====================================================================
# Wazuh Active Response Test Script - Full Coverage
# Run as: KRUSTYKRAB\Administrator or SpongeBob.SquarePants on KK-DC
# Triggers: 100012, 100013, 100014, 100015, 100019, 100020, 100021
# =====================================================================

$ErrorActionPreference = "SilentlyContinue"
$LogFile = "C:\Users\Public\ar-test.log"

function Write-Log {
    param([string]$Message, [string]$Color = "White")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp] $Message"
    Write-Host $line -ForegroundColor $Color
    [System.IO.File]::AppendAllText($LogFile, ($line + [System.Environment]::NewLine))
}

function Wait-AndReport {
    param([string]$RuleDesc, [int]$Seconds = 20)
    Write-Log "  >> Waiting $Seconds seconds for: $RuleDesc" "Cyan"
    Start-Sleep -Seconds $Seconds
}

function Check-Killed {
    param($proc, [string]$label)
    if ($proc -eq $null) { return }
    $stillRunning = Get-Process -Id $proc.Id -ErrorAction SilentlyContinue
    if ($stillRunning) {
        Write-Log "  RESULT: $label still running - active response did NOT kill it" "Red"
        $proc | Stop-Process -Force -ErrorAction SilentlyContinue
        Write-Log "  Manually cleaned up PID $($proc.Id)" "Yellow"
    } else {
        Write-Log "  RESULT: $label killed - active response worked!" "Green"
    }
}

# Track all artifacts for cleanup
$artifacts = [System.Collections.Generic.List[string]]::new()

Write-Log "=====================================================" "Yellow"
Write-Log "  Wazuh Active Response Test - $(Get-Date)" "Yellow"
Write-Log "  Running as: $env:USERDOMAIN\$env:USERNAME on $env:COMPUTERNAME" "Yellow"
Write-Log "=====================================================" "Yellow"

# ---------------------------------------------------------------------
# TEST 1 - Rule 100012
# Executable dropped in C:\Users\Public\ (Sysmon EID 11)
# Expected: Email to Larry
# ---------------------------------------------------------------------
Write-Log "--- TEST 1: Executable dropped in suspicious location (Rule 100012) ---" "Magenta"

$suspiciousExe = "C:\Users\Public\definitely_not_malware.exe"
Copy-Item "C:\Windows\System32\notepad.exe" $suspiciousExe -Force
$artifacts.Add($suspiciousExe)
Write-Log "  Dropped: $suspiciousExe" "Green"

Wait-AndReport "Rule 100012 - Executable dropped" 20

# ---------------------------------------------------------------------
# TEST 2 - Rule 100013
# Process launched from C:\Users\Public\ (Sysmon EID 1)
# Expected: Email to Larry + process killed
# ---------------------------------------------------------------------
Write-Log "--- TEST 2: Process launched from suspicious path (Rule 100013) ---" "Magenta"

if (-not (Test-Path $suspiciousExe)) {
    Copy-Item "C:\Windows\System32\notepad.exe" $suspiciousExe -Force
}

$proc2 = Start-Process $suspiciousExe -PassThru
Write-Log "  Process started - PID: $($proc2.Id)" "Green"
Write-Log "  notepad is long-running - Wazuh has time to kill it" "Cyan"

Wait-AndReport "Rule 100013 - Process from suspicious path" 25
Check-Killed $proc2 "notepad from Public"

# ---------------------------------------------------------------------
# TEST 3 - Rule 100014
# Fake browser spawning PowerShell (Sysmon EID 1)
# Expected: Email to Larry + PowerShell child killed
# ---------------------------------------------------------------------
Write-Log "--- TEST 3: Scripting engine spawn simulation (Rule 100014) ---" "Magenta"

$fakeBrowser = "C:\Users\Public\chrome.exe"
Copy-Item "C:\Windows\System32\cmd.exe" $fakeBrowser -Force
$artifacts.Add($fakeBrowser)

$existingPS = Get-Process powershell -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty Id

Start-Process $fakeBrowser -ArgumentList "/c start powershell.exe -NoProfile -WindowStyle Normal -Command `"Write-Host Rule100014_test_running; Start-Sleep -Seconds 60`"" -WindowStyle Hidden
Write-Log "  Fake chrome.exe launched - spawning PowerShell child" "Green"
Write-Log "  Waiting for PowerShell child to appear..." "Cyan"
Start-Sleep -Seconds 3

$newPS = Get-Process powershell -ErrorAction SilentlyContinue |
    Where-Object { $existingPS -notcontains $_.Id } |
    Sort-Object StartTime |
    Select-Object -Last 1

if ($newPS) {
    Write-Log "  Found new PowerShell child - PID: $($newPS.Id)" "Green"
    Write-Log "  If active response works, this PID should be killed" "Cyan"
} else {
    Write-Log "  WARNING: Could not identify new PowerShell child" "Yellow"
}

Wait-AndReport "Rule 100014 - Browser spawning scripting engine" 25

if ($newPS) {
    $stillRunning = Get-Process -Id $newPS.Id -ErrorAction SilentlyContinue
    if ($stillRunning) {
        $agentLog = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
        $recentKill = Get-Content $agentLog -ErrorAction SilentlyContinue |
            Select-Object -Last 20 |
            Where-Object { $_ -match "100014" -and $_ -match "SUCCESS" }
        if ($recentKill) {
            Write-Log "  RESULT: Wazuh killed a sibling PowerShell process (Rule 100014 worked)" "Green"
            $newPS | Stop-Process -Force -ErrorAction SilentlyContinue
            Write-Log "  Cleaned up remaining PowerShell PID $($newPS.Id)" "Yellow"
        } else {
            Write-Log "  RESULT: PowerShell child still running - active response did NOT kill it" "Red"
            $newPS | Stop-Process -Force -ErrorAction SilentlyContinue
            Write-Log "  Manually cleaned up PID $($newPS.Id)" "Yellow"
        }
    } else {
        Write-Log "  RESULT: PowerShell child killed - active response worked!" "Green"
    }
}

# ---------------------------------------------------------------------
# TEST 4 - Rule 100015
# PowerShell with GetAsyncKeyState in command line (Sysmon EID 1)
# Expected: Email to Larry + process killed
# ---------------------------------------------------------------------
Write-Log "--- TEST 4: PowerShell keylogger API simulation (Rule 100015) ---" "Magenta"

$keyloggerArgs = '-NoProfile -ExecutionPolicy Bypass -Command "' +
    'Write-Host GetAsyncKeyState_simulation_running; ' +
    'Start-Sleep -Seconds 60"'

$proc4 = Start-Process powershell.exe -ArgumentList $keyloggerArgs -PassThru
Write-Log "  Keylogger sim started - PID: $($proc4.Id)" "Green"

Wait-AndReport "Rule 100015 - PowerShell keylogger API" 25
Check-Killed $proc4 "keylogger sim"

# ---------------------------------------------------------------------
# TEST 5 - Rule 100019
# Registry Run key written from suspicious path (Sysmon EID 13)
# Alert only - no kill expected
# ---------------------------------------------------------------------
Write-Log "--- TEST 5: Registry persistence simulation (Rule 100019) ---" "Magenta"

$regKey  = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$regName = "KKWazuhTest"
Set-ItemProperty -Path $regKey -Name $regName -Value $suspiciousExe -Force
Write-Log "  Registry run key written: $regKey\$regName" "Green"
Write-Log "  Alert only expected - no process kill for registry rule" "Cyan"

Wait-AndReport "Rule 100019 - Registry persistence" 20

Remove-ItemProperty -Path $regKey -Name $regName -Force -ErrorAction SilentlyContinue
Write-Log "  Registry key cleaned up" "Yellow"

# ---------------------------------------------------------------------
# TEST 6 - Rule 100020
# net.exe domain enumeration (Sysmon EID 1)
# Alert only - no kill expected
# ---------------------------------------------------------------------
Write-Log "--- TEST 6: Domain enumeration via net.exe (Rule 100020) ---" "Magenta"

$proc6 = Start-Process "net.exe" -ArgumentList "user /domain" -PassThru -WindowStyle Hidden
Write-Log "  net user /domain executed - PID: $($proc6.Id)" "Green"
Write-Log "  Alert only expected - recon rule" "Cyan"

Wait-AndReport "Rule 100020 - net.exe domain enumeration" 20

# ---------------------------------------------------------------------
# TEST 7 - Rule 100021
# Network scanner detection (Sysmon EID 1)
# Alert only - no kill expected
# ---------------------------------------------------------------------
Write-Log "--- TEST 7: Network scanner detection (Rule 100021) ---" "Magenta"

$nmapPath = "C:\Program Files (x86)\Nmap\nmap.exe"
if (Test-Path $nmapPath) {
    $proc7 = Start-Process $nmapPath -ArgumentList "-sn 10.8.0.0/24" -PassThru -WindowStyle Hidden
    Write-Log "  nmap started - PID: $($proc7.Id)" "Green"
    Wait-AndReport "Rule 100021 - Network scanner" 20
} else {
    Write-Log "  nmap not found - using fake nmap.exe to trigger image name match" "Yellow"
    $fakeNmap = "C:\Users\Public\nmap.exe"
    Copy-Item "C:\Windows\System32\cmd.exe" $fakeNmap -Force
    $artifacts.Add($fakeNmap)
    $proc7 = Start-Process $fakeNmap -ArgumentList "/c echo nmap_simulation" -PassThru
    Write-Log "  Fake nmap.exe launched - PID: $($proc7.Id)" "Green"
    Wait-AndReport "Rule 100021 - Network scanner name match" 20

    # Wait for the process to finish before cleanup
    if ($proc7 -ne $null) {
        $proc7 | Wait-Process -Timeout 5 -ErrorAction SilentlyContinue
        $proc7 | Stop-Process -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------
# CLEANUP
# ---------------------------------------------------------------------
Write-Log ""
Write-Log "--- Cleaning up test artifacts ---" "Magenta"

foreach ($f in $artifacts) {
    $retries = 3
    while ($retries -gt 0) {
        try {
            if (Test-Path $f) {
                Remove-Item $f -Force -ErrorAction Stop
                Write-Log "  Removed: $f" "Yellow"
            }
            break
        } catch {
            $retries--
            if ($retries -gt 0) {
                Start-Sleep -Seconds 2
            } else {
                Write-Log "  WARNING: Could not remove $f - $($_.Exception.Message)" "Red"
            }
        }
    }
}

# ---------------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------------
Write-Log ""
Write-Log "=====================================================" "Yellow"
Write-Log "  Test complete. Expected results:" "Yellow"
Write-Log ""
Write-Log "  KILLS expected (agent active-responses.log):" "White"
Write-Log "    Rule 100013 - notepad from C:\Users\Public\" "White"
Write-Log "    Rule 100014 - PowerShell child of fake browser" "White"
Write-Log "    Rule 100015 - PowerShell with GetAsyncKeyState" "White"
Write-Log ""
Write-Log "  ALERTS ONLY expected (email to Larry):" "White"
Write-Log "    Rule 100012 - executable dropped" "White"
Write-Log "    Rule 100019 - registry run key (requires Sysmon EID 13)" "White"
Write-Log "    Rule 100020 - net.exe domain enum" "White"
Write-Log "    Rule 100021 - network scanner name" "White"
Write-Log ""
Write-Log "  CHECK:" "Yellow"
Write-Log "    Larry inbox - should have 7 emails" "White"
Write-Log "    Manager: /var/ossec/logs/active-responses.log" "White"
Write-Log "    Agent:   C:\Program Files (x86)\ossec-agent\active-response\active-responses.log" "White"
Write-Log "    Full test log: $LogFile" "White"
Write-Log "=====================================================" "Yellow"