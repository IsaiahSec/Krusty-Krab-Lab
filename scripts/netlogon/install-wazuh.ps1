$ErrorActionPreference = "Stop"

# --------------------------------------------------
# LOGGING
# --------------------------------------------------
$logPath = "C:\Windows\Temp\wazuh-install.log"
Start-Transcript -Path $logPath -Append
Write-Output "===== Wazuh deployment started: $(Get-Date) ====="

# --------------------------------------------------
# WAIT FOR DOMAIN / NETWORK
# --------------------------------------------------
$share       = "\\krustykrab.local\NETLOGON"
$maxAttempts = 18
$attempt     = 0

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
    Write-Output "ERROR: Domain not reachable."
    Stop-Transcript
    exit 1
}

# --------------------------------------------------
# VARIABLES
# --------------------------------------------------
$msiSource   = "\\krustykrab.local\NETLOGON\software\wazuh-agent-4.14.3-1.msi"
$msiLocal    = "C:\Windows\Temp\wazuh-agent.msi"
$managerIP   = "10.8.0.8"
$agentBinDir = "C:\Program Files (x86)\ossec-agent\active-response\bin"

# --------------------------------------------------
# BLOCK 1: WAZUH AGENT INSTALL
# Logic: skip entirely if service already exists and is running.
# --------------------------------------------------
$service = Get-Service -Name "wazuh" -ErrorAction SilentlyContinue

if ($service -ne $null) {
    Write-Output "Wazuh already installed."
    if ($service.Status -ne "Running") {
        Write-Output "Starting existing service..."
        Start-Service -Name "wazuh" -ErrorAction SilentlyContinue
    }
} else {
    Write-Output "Wazuh not installed. Beginning installation."

    # Copy MSI locally
    try {
        Write-Output "Copying installer locally..."
        Copy-Item -Path $msiSource -Destination $msiLocal -Force
    } catch {
        Write-Output "ERROR copying MSI: $($_.Exception.Message)"
        Stop-Transcript
        exit 1
    }

    # Install
    try {
        Write-Output "Running silent MSI install..."
        $arguments    = "/i `"$msiLocal`" /qn WAZUH_MANAGER=$managerIP WAZUH_REGISTRATION_SERVER=$managerIP"
        $processParams = @{
            FilePath     = "msiexec.exe"
            ArgumentList = $arguments
            Wait         = $true
            PassThru     = $true
            NoNewWindow  = $true
        }
        $process = Start-Process @processParams
        if ($process.ExitCode -ne 0) {
            throw "MSI exited with code $($process.ExitCode)"
        }
        Write-Output "Installation completed successfully."
    } catch {
        Write-Output "ERROR during installation: $($_.Exception.Message)"
        Stop-Transcript
        exit 1
    }

    # Agent authentication
    $agentAuth = "C:\Program Files (x86)\ossec-agent\agent-auth.exe"
    if (Test-Path $agentAuth) {
        Write-Output "Waiting for network to stabilize after Wazuh driver install..."
        $timeout = (Get-Date).AddMinutes(3)
        $ready   = $false

        while ((Get-Date) -lt $timeout) {
            $ping = Test-Connection -ComputerName $managerIP -Count 1 -Quiet -ErrorAction SilentlyContinue
            if ($ping) {
                Write-Output "Manager reachable. Proceeding with registration."
                $ready = $true
                break
            }
            Write-Output "Manager not reachable yet - waiting 10 seconds..."
            Start-Sleep -Seconds 10
        }

        if (-not $ready) {
            Write-Output "ERROR: Manager unreachable after 3 minutes. Registration skipped."
        } else {
            Write-Output "Registering agent..."
            $authParams = @{
                FilePath     = $agentAuth
                ArgumentList = "-m $managerIP"
                Wait         = $true
                PassThru     = $true
                NoNewWindow  = $true
            }
            $authProcess = Start-Process @authParams
            if ($authProcess.ExitCode -eq 0) {
                Write-Output "Agent authentication successful."
            } else {
                Write-Output "WARNING: agent-auth exit code $($authProcess.ExitCode)"
            }
        }
    } else {
        Write-Output "ERROR: agent-auth.exe not found."
    }

    # Start service
    try {
        Write-Output "Starting Wazuh service..."
        Start-Service -Name "wazuh"
    } catch {
        Write-Output "WARNING: Failed to start service."
    }

    # Verify
    $verify = Get-Service -Name "wazuh" -ErrorAction SilentlyContinue
    if ($verify -ne $null) {
        Write-Output "SUCCESS: Wazuh agent installed."
    } else {
        Write-Output "ERROR: Service missing after install."
    }
}

# --------------------------------------------------
# BLOCK 2: KILL-PROCESS-AGENT.CMD DEPLOYMENT
# Logic: fully independent of Block 1.
# Checks if the file exists AND contains the expected
# signature string. Redeploys from NETLOGON if either
# check fails.
# --------------------------------------------------

Write-Output "--- Checking kill-process-agent.cmd deployment ---"

$cmdSource    = "\\krustykrab.local\NETLOGON\software\kill-process-agent.cmd"
$cmdDest      = "$agentBinDir\kill-process-agent.cmd"
$cmdSignature = "WAZUH-KK-AR-V1"   # Must appear somewhere in the deployed file
$needsDeploy  = $false

if (-not (Test-Path $cmdDest)) {
    Write-Output "kill-process-agent.cmd missing - will deploy."
    $needsDeploy = $true
} else {
    $content = Get-Content $cmdDest -Raw -ErrorAction SilentlyContinue
    if ($content -notmatch [regex]::Escape($cmdSignature)) {
        Write-Output "kill-process-agent.cmd signature mismatch - will redeploy."
        $needsDeploy = $true
    } else {
        Write-Output "kill-process-agent.cmd present and signature verified. No action needed."
    }
}

if ($needsDeploy) {
    if (-not (Test-Path $cmdSource)) {
        Write-Output "ERROR: kill-process-agent.cmd not found on NETLOGON share. Cannot deploy."
    } else {
        try {
            # Ensure the bin directory exists (it should, but be safe)
            if (-not (Test-Path $agentBinDir)) {
                New-Item -ItemType Directory -Path $agentBinDir -Force | Out-Null
                Write-Output "Created directory: $agentBinDir"
            }
            Copy-Item -Path $cmdSource -Destination $cmdDest -Force
            Write-Output "SUCCESS: kill-process-agent.cmd deployed to $cmdDest"

            # Verify signature in freshly deployed file
            $deployed = Get-Content $cmdDest -Raw -ErrorAction SilentlyContinue
            if ($deployed -match [regex]::Escape($cmdSignature)) {
                Write-Output "Post-deploy signature check passed."
            } else {
                Write-Output "WARNING: Post-deploy signature check failed - NETLOGON source may be outdated."
            }
        } catch {
            Write-Output "ERROR deploying kill-process-agent.cmd: $($_.Exception.Message)"
        }
    }
}

# --------------------------------------------------
Write-Output "===== Wazuh deployment finished: $(Get-Date) ====="
Stop-Transcript
exit 0