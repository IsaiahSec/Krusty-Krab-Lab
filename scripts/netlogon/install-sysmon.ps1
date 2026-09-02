$logPath = "C:\Windows\Temp\sysmon-install.log"
Start-Transcript -Path $logPath -Append

Write-Output "===== Sysmon deployment started: $(Get-Date) ====="

# --------------------------------------------------
# WAIT FOR DOMAIN / NETWORK
# --------------------------------------------------
$share = "\\krustykrab.local\NETLOGON"
$maxAttempts = 18
$attempt = 0

Write-Output "Waiting for domain connectivity..."

while ($attempt -lt $maxAttempts) {
    if (Test-Path $share) {
        Write-Output "Domain share reachable."
        break
    }
    Start-Sleep -Seconds 10
    $attempt++
}

if ($attempt -ge $maxAttempts) {
    Write-Output "ERROR: Domain not reachable. Exiting."
    Stop-Transcript
    exit 1
}

# --------------------------------------------------
# VARIABLES
# --------------------------------------------------
$osVersion = [System.Environment]::OSVersion.Version.Version
$isWin7    = ($osVersion.Major -eq 6 -and $osVersion.Minor -eq 1)

if ($isWin7) {
    Write-Output "Windows 7 detected - using Sysmon v13"
    $sysmonSource = "\\krustykrab.local\NETLOGON\software\Sysmon64-v13.exe"
} else {
    Write-Output "Windows 10/Server detected - using Sysmon v15"
    $sysmonSource = "\\krustykrab.local\NETLOGON\software\Sysmon64.exe"
}

$configSource = "\\krustykrab.local\NETLOGON\software\sysmonconfig.xml"
$sysmonLocal = "C:\Windows\Temp\Sysmon64.exe"
$configLocal = "C:\Windows\Temp\sysmonconfig.xml"

# --------------------------------------------------
# CHECK EXISTING INSTALLATION
# --------------------------------------------------
$service = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue

if (-not $service) {
    Write-Output "Sysmon not installed. Copying files..."
    [System.IO.File]::Copy($sysmonSource, $sysmonLocal, $true)
    [System.IO.File]::Copy($configSource, $configLocal, $true)
    Write-Output "Installing Sysmon..."
    $process = Start-Process -FilePath $sysmonLocal -ArgumentList "-accepteula -i $configLocal" -Wait -PassThru
    if ($process.ExitCode -eq 0) {
        Write-Output "Sysmon installed successfully."
    } else {
        Write-Output "ERROR: Sysmon install failed with exit code $($process.ExitCode)"
    }
} else {
    Write-Output "Sysmon already installed, updating config..."
    [System.IO.File]::Copy($configSource, $configLocal, $true)
    Start-Process -FilePath "C:\Windows\Sysmon64.exe" -ArgumentList "-c $configLocal" -Wait
    Write-Output "Config updated."
}

# --------------------------------------------------
# VERIFY
# --------------------------------------------------
$verify = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
if ($verify) {
    Write-Output "SUCCESS: Sysmon service detected - Status: $($verify.Status)"
} else {
    Write-Output "ERROR: Sysmon service not found after install."
}

Write-Output "===== Sysmon deployment finished: $(Get-Date) ====="
Stop-Transcript