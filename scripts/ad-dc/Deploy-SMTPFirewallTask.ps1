# =====================================================================
# Deploy-SMTPFirewallTask.ps1
# Run once on KK-DC as Administrator to register the sync task.
# =====================================================================

$ScriptDest = "C:\Scripts\FirewallSync\Sync-SMTPFirewall.ps1"

# Copy script if not already there
if (-not (Test-Path $ScriptDest)) {
    Copy-Item "$PSScriptRoot\Sync-SMTPFirewall.ps1" $ScriptDest -Force
    Write-Host "Copied Sync-SMTPFirewall.ps1 to C:\Scripts"
}

$action = New-ScheduledTaskAction `
    -Execute  "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ScriptDest`""

$triggers = @(
    # Run at every system startup
    $(New-ScheduledTaskTrigger -AtStartup),
    # Also re-sync every 30 minutes in case a machine joins/leaves
    $(New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 30) `
        -Once -At (Get-Date))
)

$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 5)

Register-ScheduledTask `
    -TaskName  "KK-SyncSMTPFirewall" `
    -Action    $action `
    -Trigger   $triggers `
    -Settings  $settings `
    -RunLevel  Highest `
    -User      "SYSTEM" `
    -Force | Out-Null

Write-Host "Task registered. Running now..."
Start-ScheduledTask -TaskName "KK-SyncSMTPFirewall"
Start-Sleep -Seconds 3

# Verify
$rules = Get-NetFirewallRule -DisplayName "Allow SMTP - Domain Hosts","Block SMTP - Non-Domain" -ErrorAction SilentlyContinue
foreach ($r in $rules) {
    Write-Host "Rule: $($r.DisplayName) - $($r.Action) - $($r.Enabled)"
}

Write-Host "Done. Check C:\Scripts\logs\smtp-firewall-sync.log for details."