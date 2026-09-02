# =====================================================================
# Krusty Krab Phishing Simulation - Deployment Script
# GPO Computer Startup Script
# =====================================================================

$ErrorActionPreference = "SilentlyContinue"

# ---------------- LOGGING ----------------

$LogFile = "C:\Windows\Temp\phish-deploy.log"

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp] $Message"
    [System.IO.File]::AppendAllText($LogFile, ($line + [System.Environment]::NewLine), [System.Text.Encoding]::UTF8)
    Write-Host $line
}

# ---------------- CONFIG ----------------

$NetlogonBase = "\\krustykrabexample.local\NETLOGON"
$SimScript    = "$NetlogonBase\phishing_simulation_SECURE.ps1"
$LocalDir     = "C:\Scripts"
$LocalScript  = "$LocalDir\phishing_simulation_SECURE.ps1"
$TaskBaseName = "KKPhishSim"
$Domain       = "KRUSTYKRABEXAMP"
$IntervalMins = 5
$DCName       = "KK-DCEX"
$Win7Name     = "blueTeamWin7VM"
$Win10Name    = "blueTeamWin10VM"

# OS detection - Win7 is 6.1, Win8+ is 6.2+, Win10 is 10.0
$osVersion = [System.Environment]::OSVersion.Version
$isWin7    = ($osVersion.Major -eq 6 -and $osVersion.Minor -eq 1)
Write-Log "OS Version: $($osVersion.ToString())  Win7 mode: $isWin7"

# Machine field controls which computer each task is deployed on.
# Deploy script skips any user whose Machine does not match $env:COMPUTERNAME.
$DomainUsers = @(
    @{ User = "SpongeBob.SquarePant"; Password = "KrustyFryCook!";  Machine = $Win7Name  }
    @{ User = "Squidward.Tentacles";  Password = "KrustyKlarinet!"; Machine = $Win7Name  }
    @{ User = "Eugene.Krabs";         Password = "KrustyAnchor!";   Machine = $Win10Name }
    @{ User = "Sandy.Cheeks";         Password = "KrustyAcorns!";   Machine = $DCName    }
    @{ User = "Larry.Lobster";        Password = "KrustyPants!";    Machine = $DCName    }
)

Write-Log "===== Deployment started ====="
Write-Log "Running as $env:USERNAME on $env:COMPUTERNAME"

# ---------------- WAIT FOR NETLOGON ----------------

Write-Log "Waiting for NETLOGON..."
$timeout = (Get-Date).AddMinutes(5)
while (-not (Test-Path $SimScript)) {
    if ((Get-Date) -gt $timeout) {
        Write-Log "ERROR: NETLOGON unavailable after 5 minutes. Aborting."
        exit 1
    }
    Start-Sleep -Seconds 10
}
Write-Log "NETLOGON available."

# ---------------- LOCAL DIRECTORY + ACL ----------------

if (-not (Test-Path $LocalDir)) {
    New-Item -ItemType Directory -Path $LocalDir | Out-Null
    Write-Log "Created $LocalDir"
}

try {
    $acl  = Get-Acl $LocalDir
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Users", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.SetAccessRule($rule)
    Set-Acl $LocalDir $acl
    Write-Log "ACL set: Users have Modify on $LocalDir"
} catch {
    Write-Log "WARNING: Could not set ACL: $_"
}

# ---------------- COPY SIMULATION SCRIPT ----------------

try {
    Copy-Item $SimScript $LocalScript -Force -ErrorAction Stop
    Write-Log "Simulation script copied to $LocalScript"

    $bytes = [System.IO.File]::ReadAllBytes($LocalScript)
    if ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        $content   = [System.IO.File]::ReadAllText($LocalScript, [System.Text.Encoding]::UTF8)
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($LocalScript, $content, $utf8NoBom)
        Write-Log "BOM stripped from simulation script."
    }
} catch {
    Write-Log "ERROR copying simulation script: $_"
    exit 1
}

# ---------------- CREATE TASKS ----------------

foreach ($entry in $DomainUsers) {
    $user      = $entry.User
    $pass      = $entry.Password
    $runAs     = "$Domain\$user"
    $userClean = $user -replace "[^a-zA-Z0-9]", ""
    $taskName  = "$TaskBaseName$userClean"

    if ($entry.Machine -ne $env:COMPUTERNAME) {
        Write-Log "Skipping $taskName - assigned to $($entry.Machine), this machine is $env:COMPUTERNAME"
        continue
    }

    Write-Log "--- Registering task $taskName for $runAs ---"

    cmd /c "schtasks /Delete /TN $taskName /F" 2>&1 | Out-Null

    if ($isWin7) {
        # Win7: plain schtasks /Create without /RL HIGHEST (not supported on Win7)
        # No XML needed - standard command works fine for domain user tasks
        $tr        = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$LocalScript`""
        $startTime = (Get-Date).AddMinutes(2).ToString("HH:mm")
        $cmd       = "schtasks /Create /SC MINUTE /MO $IntervalMins /TN `"$taskName`" /TR `"$tr`" /RU `"$runAs`" /RP `"$pass`" /ST $startTime /F"

        $result   = cmd /c $cmd 2>&1
        $exitCode = $LASTEXITCODE

        if ($exitCode -ne 0) {
            Write-Log "WARNING: schtasks failed for $user (exit $exitCode): $result"
        } else {
            Write-Log "Task created: $taskName"
        }

    } else {
        # Win8+ / Server 2016 path: schtasks with /RL HIGHEST then patch via cmdlets
        $tr        = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File $LocalScript"
        $startTime = (Get-Date).AddMinutes(2).ToString("HH:mm")
        $cmd       = "schtasks /Create /SC MINUTE /MO $IntervalMins /TN $taskName /TR `"$tr`" /RU $runAs /RP $pass /RL HIGHEST /ST $startTime /F"

        $result   = cmd /c $cmd 2>&1
        $exitCode = $LASTEXITCODE

        if ($exitCode -ne 0) {
            Write-Log "WARNING: schtasks failed for $user (exit $exitCode): $result"
        } else {
            Write-Log "Task created: $taskName"
        }
    }
}

# ---------------- PATCH TASK SETTINGS (Win8+ only) ----------------
# On Win7 all settings are baked into the XML above - no patch needed.

if (-not $isWin7) {
    Write-Log "Patching task settings (battery restrictions, StartWhenAvailable)..."

    foreach ($entry in $DomainUsers) {
        $user      = $entry.User
        $userClean = $user -replace "[^a-zA-Z0-9]", ""
        $taskName  = "$TaskBaseName$userClean"

        if ($entry.Machine -ne $env:COMPUTERNAME) { continue }

        try {
            $t = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
            $t.Settings.DisallowStartIfOnBatteries = $false
            $t.Settings.StopIfGoingOnBatteries     = $false
            $t.Settings.StartWhenAvailable         = $true
            $t | Set-ScheduledTask -User "$Domain\$user" -Password $pass | Out-Null
            Write-Log "Settings patched: $taskName"
        } catch {
            Write-Log "WARNING: Could not patch settings for $taskName : $_"
        }
    }
} else {
    Write-Log "Win7 detected - skipping patch loop (settings baked into XML)."
}

Write-Log "===== Deployment complete ====="
exit 0