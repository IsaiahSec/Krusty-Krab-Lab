# =====================================================================
# Sync-SMTPFirewall.ps1
# Dynamically whitelist port 25 (SMTP) for domain-joined machines only
# Queries AD for all enabled computers, resolves their IPs, rebuilds
# the firewall whitelist. Blocks everything else including redTeamXUVM.
# Run at boot + every 30 min via scheduled task on KK-DC.
# =====================================================================

$LogFile      = "C:\Scripts\logs\smtp-firewall-sync.log"
$AllowRule    = "Allow SMTP - Domain Hosts"
$BlockRule    = "Block SMTP - Non-Domain"

function Write-Log {
    param([string]$Message)
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
    Write-Host $line
    try {
        $dir = [System.IO.Path]::GetDirectoryName($LogFile)
        if (-not [System.IO.Directory]::Exists($dir)) {
            [System.IO.Directory]::CreateDirectory($dir) | Out-Null
        }
        Add-Content -Path $LogFile -Value $line
    } catch {}
}

Write-Log "===== SMTP Firewall Sync Started ====="

# Always allow localhost
$allowedIPs = [System.Collections.Generic.List[string]]@("127.0.0.1")

# ---------------------------------------------------------------
# Query AD for all enabled domain computers except the DC itself
# ---------------------------------------------------------------
try {
    Import-Module ActiveDirectory -ErrorAction Stop

    $computers = Get-ADComputer -Filter { Enabled -eq $true } |
                 Where-Object { $_.Name -ne $env:COMPUTERNAME }

    foreach ($computer in $computers) {
        $fqdn = "$($computer.Name).krustykrab.local"
        try {
            # Try Resolve-DnsName first (respects local DNS server under SYSTEM)
            $resolved = Resolve-DnsName -Name $fqdn -Type A -ErrorAction Stop |
                        Where-Object { $_.Type -eq "A" } |
                        Select-Object -First 1
            if ($resolved) {
                $ip = $resolved.IPAddress
                if (-not $allowedIPs.Contains($ip)) {
                    $allowedIPs.Add($ip)
                    Write-Log "Whitelisted: $($computer.Name) -> $ip"
                }
            } else {
                Write-Log "WARN: No A record found for $fqdn - skipping"
            }
        } catch {
            Write-Log "WARN: DNS resolution failed for $fqdn - $_"
        }
    }
} catch {
    Write-Log "ERROR: AD query failed - $_"
    Write-Log "Falling back to localhost only - check AD module availability"
}

Write-Log "Final whitelist ($($allowedIPs.Count) IPs): $($allowedIPs -join ', ')"

# ---------------------------------------------------------------
# Static fallback - ensures certain hosts that are not domain-joined are included
# ---------------------------------------------------------------
$staticIPs = @("10.8.0.8", "10.8.0.9")  # SOCVM, IntraVM
foreach ($ip in $staticIPs) {
    if (-not $allowedIPs.Contains($ip)) {
        $allowedIPs.Add($ip)
        Write-Log "Added static fallback: $ip"
    }
}

Write-Log "Final whitelist after fallback ($($allowedIPs.Count) IPs): $($allowedIPs -join ', ')"

# ---------------------------------------------------------------
# Disable MailEnable's built-in SMTP inbound rule
# It allows port 25 from Any and overrides our whitelist
# ---------------------------------------------------------------
Disable-NetFirewallRule -DisplayName "MailEnable SMTP (Inbound)" -ErrorAction SilentlyContinue
Write-Log "Disabled MailEnable built-in SMTP inbound rule"

# ---------------------------------------------------------------
# Rebuild firewall rules cleanly
# ---------------------------------------------------------------
Remove-NetFirewallRule -DisplayName $AllowRule -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName $BlockRule  -ErrorAction SilentlyContinue

New-NetFirewallRule `
    -DisplayName $AllowRule `
    -Direction   Inbound `
    -Protocol    TCP `
    -LocalPort   25 `
    -RemoteAddress ($allowedIPs.ToArray()) `
    -Action      Allow `
    -Profile     Any | Out-Null
Write-Log "Allow rule created for $($allowedIPs.Count) IPs"

# Default inbound policy blocks everything not explicitly allowed
# No explicit block rule needed - it causes Allow rules to be overridden
Set-NetFirewallProfile -Profile Domain -DefaultInboundAction Block
Set-NetFirewallProfile -Profile Private -DefaultInboundAction Block
Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block
Write-Log "Default inbound policy set to Block on all profiles"

Write-Log "===== SMTP Firewall Sync Complete ====="