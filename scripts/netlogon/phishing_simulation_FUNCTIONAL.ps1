# =====================================================================
# Krusty Krab Phishing Simulation - Attack Only
# =====================================================================
# MANUAL EDITS REQUIRED - search "### EDIT":
#   1. [### EDIT 1] $AnthropicApiKey - your Anthropic API key
#   2. [### EDIT 2] Passwords        - must match your AD passwords
# =====================================================================
#
# CHARACTERS:
#   SpongeBob  0.10 - Naive, trusting, eager to please authority figures
#   Squidward  0.25 - Arrogant, susceptible to flattery and ego appeals
#   Mr. Krabs  0.20 - Greedy, falls for money/profit lures
#   Sandy      0.85 - Keeps emails, no security processing
#
# DYNAMIC COMPETENCE:
#   Base score per character, modified by:
#   - Mood modifier: random -0.15 to +0.15 per run
#   - Vulnerability weights: per-character topic sensitivities
#   - Character profile injected into AI prompts
# =====================================================================

$ErrorActionPreference = "SilentlyContinue"

# FIX 1: Win7-safe TLS 1.2 enablement using enum int value (3072)
# avoids Tls12 enum missing on older .NET runtimes
try {
    [System.Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject(
        [System.Net.SecurityProtocolType], 3072)
    $regPath = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319"
    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
    Set-ItemProperty -Path $regPath -Name "SchUseStrongCrypto" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    $regPath2 = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
    if (-not (Test-Path $regPath2)) { New-Item -Path $regPath2 -Force | Out-Null }
    Set-ItemProperty -Path $regPath2 -Name "SchUseStrongCrypto" -Value 1 -Type DWord -ErrorAction SilentlyContinue
} catch { }

# =====================================================================
# LOGGING
# =====================================================================

$script:LogCandidates = @(
    "C:\Scripts\logs\phishing_sim_$($env:USERNAME).log",
    "C:\Windows\Temp\phishing_sim_$($env:USERNAME).log",
    "$env:TEMP\phishing_sim_$($env:USERNAME).log"
)
$script:LogFile = $null

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line      = "[$timestamp] [$Level] $Message"
    $written   = $false

    if ($script:LogFile) {
        try {
            $dir = [System.IO.Path]::GetDirectoryName($script:LogFile)
            if (-not [System.IO.Directory]::Exists($dir)) {
                [System.IO.Directory]::CreateDirectory($dir) | Out-Null
            }
            [System.IO.File]::AppendAllText(
                $script:LogFile,
                ($line + [System.Environment]::NewLine),
                [System.Text.Encoding]::UTF8
            )
            $written = $true
        } catch {
            $script:LogFile = $null
        }
    }

    if (-not $written) {
        foreach ($candidate in $script:LogCandidates) {
            try {
                $dir = [System.IO.Path]::GetDirectoryName($candidate)
                if (-not [System.IO.Directory]::Exists($dir)) {
                    [System.IO.Directory]::CreateDirectory($dir) | Out-Null
                }
                [System.IO.File]::AppendAllText(
                    $candidate,
                    ($line + [System.Environment]::NewLine),
                    [System.Text.Encoding]::UTF8
                )
                $script:LogFile = $candidate
                $written = $true
                break
            } catch { }
        }
    }

    try {
        $src = "KKPhishSim"
        if (-not [System.Diagnostics.EventLog]::SourceExists($src)) {
            [System.Diagnostics.EventLog]::CreateEventSource($src, "Application")
        }
        $evtType = switch ($Level) {
            "ERROR" { [System.Diagnostics.EventLogEntryType]::Error }
            "WARN"  { [System.Diagnostics.EventLogEntryType]::Warning }
            default { [System.Diagnostics.EventLogEntryType]::Information }
        }
        [System.Diagnostics.EventLog]::WriteEntry($src, $line, $evtType, 1337)
    } catch { }

    Write-Host $line
}

# =====================================================================
# CONFIG
# =====================================================================

$Domain             = "krustykrab.local"
$MailServer         = "mail.krustykrab.local"
$IMAPPort           = 143
$SMTPServer         = "mail.krustykrab.local"
$SMTPPort           = 25
$ScriptDir          = "C:\Scripts"
$LogDir             = "$ScriptDir\logs"
$CompetenceDir      = "$ScriptDir\competence"
$FakeIntranetUrl    = "http://intranet.krustykrab.local/login"
$AnthropicModel     = "claude-haiku-4-5-20251001"
$MinIntervalMinutes = 5
$IMAPDeletedFolder  = "Deleted Items"
$IMAPSentFolder     = "Sent Items"
$MailEnableDir      = "C:\Program Files (x86)\Mail Enable"
$SendChancePct      = 40

### EDIT 1 - Anthropic API key
$AnthropicApiKey = "INSERT_YOUR__ANTHROPIC_API_KEY"

# =====================================================================
# ENSURE DIRECTORIES
# =====================================================================

foreach ($dir in @($ScriptDir, $LogDir, $CompetenceDir)) {
    try {
        if (-not [System.IO.Directory]::Exists($dir)) {
            [System.IO.Directory]::CreateDirectory($dir) | Out-Null
        }
    } catch { }
}

Write-Log "===== phishing_simulation.ps1 v2 started ====="
Write-Log "Running on $env:COMPUTERNAME as $env:USERNAME"
Write-Log "Log file: $script:LogFile"

# =====================================================================
# RATE LIMITING
# =====================================================================

$StateFile = "$ScriptDir\last_run_$($env:USERNAME).txt"
if (Test-Path $StateFile) {
    try {
        $lastRun   = [datetime](Get-Content -Path $StateFile -Raw).Trim()
        $minsSince = (New-TimeSpan -Start $lastRun -End (Get-Date)).TotalMinutes
        if ($minsSince -lt $MinIntervalMinutes) {
            Write-Log "Rate-limited: ran $([int]$minsSince)m ago. Exiting." "SKIP"
            exit 0
        }
    } catch { }
}

# =====================================================================
# EMPLOYEE MAP
# =====================================================================

$WindowsUser = $env:USERNAME
$UserKey     = $WindowsUser.ToLower()

### EDIT 2 - Passwords must match your AD account passwords exactly
$EmployeeMap = @{
    "spongebob.squarepant" = @{
        email        = "spongebob.squarepants@$Domain"
        name         = "SpongeBob SquarePants"
        firstName    = "SpongeBob"
        password     = "KrustyFryCook!"
        role         = "Fry Cook"
        defaultScore = 0.10
        isSecurity   = $false
        isIT         = $false
        wikiUrl      = "https://spongebob.fandom.com/wiki/SpongeBob_SquarePants"
        vulnerabilities = @("authority", "approval", "friendship", "helping others", "Mr. Krabs", "Krabby Patty")
        colleagues   = @("squidward.tentacles@$Domain", "eugene.krabs@$Domain", "sandy.cheeks@$Domain")
    }
    "squidward.tentacles" = @{
        email        = "squidward.tentacles@$Domain"
        name         = "Squidward Tentacles"
        firstName    = "Squidward"
        password     = "KrustyKlarinet!"
        role         = "Cashier"
        defaultScore = 0.25
        isSecurity   = $false
        isIT         = $false
        wikiUrl      = "https://spongebob.fandom.com/wiki/Squidward_Tentacles"
        vulnerabilities = @("flattery", "art recognition", "talent", "fame", "clarinet", "superiority")
        colleagues   = @("spongebob.squarepants@$Domain", "eugene.krabs@$Domain", "sandy.cheeks@$Domain")
    }
    "eugene.krabs" = @{
        email        = "eugene.krabs@$Domain"
        name         = "Eugene Krabs"
        firstName    = "Mr. Krabs"
        password     = "KrustyAnchor!"
        role         = "Owner and Manager"
        defaultScore = 0.20
        isSecurity   = $false
        isIT         = $false
        wikiUrl      = "https://spongebob.fandom.com/wiki/Eugene_H._Krabs"
        vulnerabilities = @("money", "profit", "discount", "investment", "revenue", "treasure", "deal", "savings")
        colleagues   = @("spongebob.squarepants@$Domain", "squidward.tentacles@$Domain", "sandy.cheeks@$Domain")
    }
    "sandy.cheeks" = @{
        email        = "sandy.cheeks@$Domain"
        name         = "Sandy Cheeks"
        firstName    = "Sandy"
        password     = "KrustyAcorns!"
        role         = "IT and Science Consultant"
        defaultScore = 0.85
        isSecurity   = $false
        isIT         = $false
        wikiUrl      = "https://spongebob.fandom.com/wiki/Sandy_Cheeks"
        vulnerabilities = @("science", "Texas", "research grant", "technology breakthrough")
        colleagues   = @("spongebob.squarepants@$Domain", "squidward.tentacles@$Domain", "eugene.krabs@$Domain")
    }
}

if (-not $EmployeeMap.ContainsKey($UserKey)) {
    Write-Log "User '$WindowsUser' not in employee map. Exiting." "SKIP"
    exit 0
}

$Employee   = $EmployeeMap[$UserKey]
$UserEmail  = $Employee.email

Write-Log "Effective user: $WindowsUser  Email: $UserEmail"
Write-Log "Employee matched: $($Employee.name) <$UserEmail>"

# =====================================================================
# COMPETENCE SCORE
# =====================================================================

$CompetenceFile = "$CompetenceDir\$UserKey.json"

function Load-Competence {
    if (Test-Path $CompetenceFile) {
        try {
            $raw = [System.IO.File]::ReadAllText($CompetenceFile)
            # PS 2.0 compatible - parse score with regex instead of ConvertFrom-Json
            if ($raw -match '"score"\s*:\s*([\d.]+)') {
                return [double]$Matches[1]
            }
        } catch { }
    }
    return $Employee.defaultScore
}

function Save-Competence {
    param([double]$Score)
    $Score = [Math]::Round([Math]::Max(0.0, [Math]::Min(1.0, $Score)), 3)
    $json  = "{`"score`": $Score, `"user`": `"$UserKey`", `"updated`": `"$(Get-Date -Format 'o')`"}"
    try {
        [System.IO.File]::WriteAllText($CompetenceFile, $json, [System.Text.Encoding]::UTF8)
        Write-Log "Competence score saved: $Score"
    } catch {
        Write-Log "Failed to save competence score: $_" "ERROR"
    }
}

$CompetenceScore = Load-Competence
Write-Log "Loaded competence score: $CompetenceScore"

# =====================================================================
# STARTUP JITTER
# =====================================================================

$jitterSeed  = 0
foreach ($c in $UserKey.ToCharArray()) { $jitterSeed += [int][char]$c }
$jitterSecs  = $jitterSeed % 46
Write-Log "Startup jitter: sleeping ${jitterSecs}s to stagger API calls..."
Start-Sleep -Seconds $jitterSecs

# =====================================================================
# MOOD MODIFIER
# =====================================================================

$MoodRoll     = (Get-Random -Minimum -15 -Maximum 16) / 100.0
$MoodScore    = [Math]::Round([Math]::Max(0.0, [Math]::Min(1.0, $CompetenceScore + $MoodRoll)), 3)
$MoodDesc     = if ($MoodRoll -gt 0.05) { "having a good day (+$MoodRoll)" }
                elseif ($MoodRoll -lt -0.05) { "having a rough day ($MoodRoll)" }
                else { "in a neutral mood ($MoodRoll)" }
Write-Log "Mood modifier: $MoodDesc. Effective competence for this run: $MoodScore"

# =====================================================================
# STATIC CHARACTER PROFILES
# =====================================================================

$StaticProfiles = @{
    "spongebob.squarepant" = "SpongeBob is relentlessly optimistic, naive, and desperate to please authority figures, especially Mr. Krabs. He has almost no natural skepticism and will comply with almost any request that seems to come from someone he trusts or admires. He is highly susceptible to urgency, flattery, and appeals to friendship or loyalty. His only protection against phishing is that genuinely malicious or cruel content sometimes gives him pause - but a well-crafted email appearing to come from Mr. Krabs or a friend will bypass all caution."
    "squidward.tentacles"  = "Squidward is arrogant, self-absorbed, and convinced of his own superiority - which paradoxically makes him easy to manipulate. Flattery about his artistic talent or musical genius will cause him to lower his guard immediately. He dismisses warnings and security advice as beneath him. He is moderately resistant to obvious scams but will fall for anything that appeals to his ego, promises recognition, or references his clarinet or art career."
    "eugene.krabs"         = "Mr. Krabs is pathologically obsessed with money and profit to a degree that completely overrides his judgment. Any email referencing financial gain, a business opportunity, a discount, or a threat to his money will cause him to act impulsively without verification. He has some street-smart cynicism about things unrelated to money, but that cynicism evaporates the moment currency is mentioned. He is one of the most phishing-susceptible characters specifically on financial topics."
    "sandy.cheeks"         = "Sandy is a highly trained scientist and technologist with strong critical thinking skills and genuine cybersecurity awareness. She is skeptical of unsolicited emails, checks sender addresses, and is unlikely to click links without verification. Her weak spots are appeals to scientific curiosity, Texas pride, or research grant opportunities, which can cause her to engage with content she might otherwise dismiss. She is the most phishing-resistant employee and serves as the IT point of contact."
}

function Get-CharacterProfile {
    $profile = $StaticProfiles[$UserKey]
    if ($profile) {
        Write-Log "Loaded static character profile for $UserKey"
        return $profile
    }
    Write-Log "No static profile for $UserKey - vulnerability weights only." "WARN"
    return ""
}

$CharacterProfile = Get-CharacterProfile

# =====================================================================
# ANTHROPIC API HELPER
# =====================================================================

function Invoke-Claude {
    param(
        [string]$SystemPrompt,
        [string]$UserPrompt,
        [int]$MaxTokens = 300
    )

    if ([string]::IsNullOrWhiteSpace($AnthropicApiKey)) {
        Write-Log "AnthropicApiKey is empty - using deterministic fallback." "WARN"
        return $null
    }

    # Use JavaScriptSerializer for reliable JSON escaping - .NET 3.5 on Win7
    $esc_system = $null
    $esc_user   = $null
    try {
        Add-Type -AssemblyName System.Web.Extensions
        $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $ser.MaxJsonLength = 2147483647
        $esc_system = $ser.Serialize($SystemPrompt)
        $esc_user   = $ser.Serialize($UserPrompt)
    } catch {
        function Escape-JsonString { param([string]$s)
            $s = $s -replace '\\', '\\'
            $s = $s -replace '"',   '\"'
            $s = $s -replace "`t",  '\t'
            $s = $s -replace "`r`n",'\n'
            $s = $s -replace "`n",  '\n'
            $s = $s -replace "`r",  '\n'
            return '"' + $s + '"'
        }
        $esc_system = Escape-JsonString $SystemPrompt
        $esc_user   = Escape-JsonString $UserPrompt
    }

    $bodyJson = '{"model":"' + $AnthropicModel + '","max_tokens":' + $MaxTokens + ',"system":' + $esc_system + ',"messages":[{"role":"user","content":' + $esc_user + '}]}'
    $delays = @(5, 15, 30)
    foreach ($attempt in 0..2) {
        try {
            # Force TLS 1.2 on every attempt using enum int - Win7 safe
            [System.Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject(
                [System.Net.SecurityProtocolType], 3072)
            $wc = New-Object System.Net.WebClient
            $wc.Headers.Add("x-api-key",        $AnthropicApiKey)
            $wc.Headers.Add("anthropic-version", "2023-06-01")
            $wc.Headers.Add("content-type",      "application/json")
            $bodyBytes     = [System.Text.Encoding]::UTF8.GetBytes($bodyJson)
            $responseBytes = $wc.UploadData("https://api.anthropic.com/v1/messages", "POST", $bodyBytes)
            $responseText  = [System.Text.Encoding]::UTF8.GetString($responseBytes)

            # Extract text field with regex - no ConvertFrom-Json needed (Win7 PS2 safe)
            if ($responseText -match '"text"\s*:\s*"((?:[^"\\]|\\.)*)"') {
                $text = $Matches[1]
                $text = $text -replace '\\n',  "`n"
                $text = $text -replace '\\r',  ''
                $text = $text -replace '\\"',  '"'
                $text = $text -replace '\\\\', '\'
                return $text.Trim()
            }
            Write-Log "Claude API unexpected response: $($responseText.Substring(0, [Math]::Min(200, $responseText.Length)))" "WARN"
            return $null
        } catch {
            $msg = $_.ToString()
            if ($msg -match "429" -and $attempt -lt 2) {
                $wait = $delays[$attempt]
                Write-Log "Claude API 429 rate limit - waiting ${wait}s before retry $($attempt+1)..." "WARN"
                Start-Sleep -Seconds $wait
            } else {
                Write-Log "Claude API call failed: $_" "ERROR"
                return $null
            }
        }
    }
    return $null
}

# =====================================================================
# COMPETENCE DESCRIPTION
# =====================================================================

function Get-CompetenceDescription {
    param([double]$Score)
    if ($Score -lt 0.2)     { return "completely untrained and naive - almost always falls for phishing emails without hesitation" }
    elseif ($Score -lt 0.4) { return "minimally aware - sometimes suspicious of very obvious scams but usually deceived" }
    elseif ($Score -lt 0.6) { return "moderately trained - gets it right about half the time, especially on obvious phishing" }
    elseif ($Score -lt 0.8) { return "well-trained - usually catches phishing emails; may miss sophisticated ones" }
    else                    { return "expert-level - almost never fooled; proactively reports suspicious emails to security" }
}

# =====================================================================
# MIME DECODER
# FIX 2: Decode quoted-printable and base64 MIME encoded words
# Fixes mangled subject/body logs from MailEnable encoding
# =====================================================================

function Decode-MimeString {
    param([string]$InputString)
    if ([string]::IsNullOrWhiteSpace($InputString)) { return $InputString }

    $result = $InputString

    # Decode quoted-printable encoded words: =?charset?Q?encoded?=
    $result = [regex]::Replace($result, '=\?([^?]+)\?Q\?([^?]*)\?=', {
        param($m)
        $encoded = $m.Groups[2].Value -replace '_', ' '
        $decoded = [regex]::Replace($encoded, '=([0-9A-Fa-f]{2})', {
            param($hex)
            [char][Convert]::ToInt32($hex.Groups[1].Value, 16)
        })
        $decoded
    })

    # Decode base64 encoded words: =?charset?B?base64?=
    $result = [regex]::Replace($result, '=\?([^?]+)\?B\?([^?]*)\?=', {
        param($m)
        try {
            $bytes = [Convert]::FromBase64String($m.Groups[2].Value)
            [System.Text.Encoding]::UTF8.GetString($bytes)
        } catch { $m.Value }
    })

    return $result.Trim()
}

# =====================================================================
# IMAP CLIENT
# =====================================================================

$script:ImapTcp    = $null
$script:ImapReader = $null
$script:ImapWriter = $null
$script:ImapTag    = 0

function Get-ImapTag {
    $script:ImapTag++
    return "A{0:D4}" -f $script:ImapTag
}

function Send-ImapCommand {
    param([string]$Command, [int]$TimeoutSec = 10)
    $tag      = Get-ImapTag
    $fullCmd  = "$tag $Command"
    $script:ImapWriter.WriteLine($fullCmd)
    $lines    = @()
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        try {
            $script:ImapTcp.Client.ReceiveTimeout = [int][Math]::Max(500, ($deadline - (Get-Date)).TotalMilliseconds)
            $line = $script:ImapReader.ReadLine()
        } catch { break }
        if ($null -eq $line) { break }
        $line = $line.TrimEnd("`r")
        if ($line.Length -eq 0) { continue }
        $lines += $line
        if ($line -match "^$tag (OK|NO|BAD)") { break }
    }
    try { $script:ImapTcp.Client.ReceiveTimeout = 10000 } catch { }
    return $lines
}

function Connect-IMAP {
    param([string]$Server, [int]$Port, [string]$Username, [string]$Password)
    try {
        $script:ImapTcp    = New-Object System.Net.Sockets.TcpClient($Server, $Port)
        $stream            = $script:ImapTcp.GetStream()
        $script:ImapReader = New-Object System.IO.StreamReader($stream)
        $script:ImapWriter = New-Object System.IO.StreamWriter($stream)
        $script:ImapWriter.AutoFlush = $true

        $greeting = $script:ImapReader.ReadLine()
        Write-Log "IMAP greeting: $greeting"

        if ($greeting -notmatch "\* OK") {
            Write-Log "IMAP unexpected greeting." "ERROR"
            return $false
        }

        $tag = Get-ImapTag
        $script:ImapWriter.WriteLine("$tag LOGIN $Username $Password")
        $lines = @()
        while ($true) {
            $line = $script:ImapReader.ReadLine()
            if ($null -eq $line) { break }
            $line = $line.TrimEnd("`r")
            if ($line.Length -eq 0) { continue }
            $lines += $line
            if ($line -match "^$tag (OK|NO|BAD)") { break }
        }

        if ($lines[-1] -match "^$tag OK") {
            Write-Log "IMAP authenticated."
            return $true
        } else {
            Write-Log "IMAP login failed: $($lines[-1])" "ERROR"
            return $false
        }
    } catch {
        Write-Log "IMAP Connect-IMAP exception: $_" "ERROR"
        return $false
    }
}

function Disconnect-IMAP {
    try {
        if ($script:ImapWriter) {
            $tag = Get-ImapTag
            $script:ImapWriter.WriteLine("$tag LOGOUT")
            $script:ImapReader.ReadLine() | Out-Null
        }
    } catch { }
    try { if ($script:ImapTcp) { $script:ImapTcp.Close() } } catch { }
    $script:ImapTcp    = $null
    $script:ImapReader = $null
    $script:ImapWriter = $null
}

function Select-IMAPFolder {
    param([string]$Folder)
    $lines = Send-ImapCommand "SELECT `"$Folder`""
    if ($lines[-1] -match "OK") {
        Write-Log "IMAP selected folder: $Folder"
        return $true
    }
    Write-Log "IMAP SELECT failed for '$Folder': $($lines[-1])" "ERROR"
    return $false
}

function Get-IMAPMessageList {
    $lines = Send-ImapCommand "SEARCH ALL"
    $uids  = @()
    foreach ($line in $lines) {
        if ($line -match "^\* SEARCH (.+)") {
            $uids = $Matches[1].Trim().Split(" ") | Where-Object { $_ -match "^\d+$" } | ForEach-Object { [int]$_ }
        }
    }
    return $uids
}

function Get-IMAPMessageHeaders {
    param([int]$SeqNum)
    $hdrs = @{ Subject = "(no subject)"; From = "(unknown)" }
    $tag  = Get-ImapTag
    $script:ImapWriter.WriteLine("$tag FETCH $SeqNum (BODY[HEADER.FIELDS (FROM SUBJECT)])")
    $lines = @()
    while ($true) {
        $line = $script:ImapReader.ReadLine()
        if ($null -eq $line) { break }
        $lines += $line
        if ($line -match "^$tag (OK|NO|BAD)") { break }
    }
    foreach ($line in $lines) {
        # FIX: Capture $Matches[1] to local variable immediately before any function call
        # to prevent $Matches being overwritten by Decode-MimeString's internal regex operations
        if ($line -match "^Subject:\s*(.*)$") {
            $capturedSubject = $Matches[1]
            $hdrs["Subject"] = Decode-MimeString $capturedSubject.Trim()
        }
        if ($line -match "^From:\s*(.+)") {
            $capturedFrom = $Matches[1]
            $hdrs["From"] = Decode-MimeString $capturedFrom.Trim()
        }
    }
    return $hdrs
}

function Get-IMAPMessageBody {
    param([int]$SeqNum)
    $tag       = Get-ImapTag
    $script:ImapWriter.WriteLine("$tag FETCH $SeqNum (BODY[TEXT])")
    $inLiteral = $false
    $bodyLines = @()
    while ($true) {
        $line = $script:ImapReader.ReadLine()
        if ($null -eq $line) { break }
        if ($line -match "^\* \d+ FETCH.*\{(\d+)\}") { $inLiteral = $true; continue }
        if ($inLiteral) {
            if ($line -match "^\)$" -or $line -match "^$tag OK") { $inLiteral = $false }
            else { $bodyLines += $line }
        }
        if ($line -match "^$tag (OK|NO|BAD)") { break }
    }
    # FIX 2 applied: decode MIME encoding in body as well
    return Decode-MimeString ($bodyLines -join [System.Environment]::NewLine)
}

function Get-IMAPUID {
    param([int]$SeqNum)
    $lines = Send-ImapCommand "FETCH $SeqNum (UID)"
    foreach ($line in $lines) {
        if ($line -match "FETCH \(UID (\d+)\)") { return [int]$Matches[1] }
    }
    return $null
}

function Move-IMAPMessage {
    param([int]$SeqNum, [string]$DestFolder)

    $uid = Get-IMAPUID -SeqNum $SeqNum

    if ($null -eq $uid) {
        Write-Log "IMAP could not fetch UID for seq=$SeqNum - expunging by sequence number" "WARN"
        Send-ImapCommand "STORE $SeqNum +FLAGS.SILENT (\Deleted)" | Out-Null
        Send-ImapCommand "EXPUNGE" | Out-Null
        Send-ImapCommand "SELECT `"INBOX`"" | Out-Null
        return $false
    }

    $copyLines = Send-ImapCommand "UID COPY $uid `"$DestFolder`""
    $copyResponse = ($copyLines -join ' | ')
    Write-Log "IMAP UID COPY $uid -> '$DestFolder' response: $copyResponse"

    $copyOK = $copyLines | Where-Object { $_ -match "^\S+ OK" } | Select-Object -First 1
    if ($copyOK) {
        Send-ImapCommand "UID STORE $uid +FLAGS.SILENT (\Deleted)" | Out-Null
        Send-ImapCommand "UID EXPUNGE $uid" | Out-Null
        Send-ImapCommand "SELECT `"INBOX`"" | Out-Null
        Write-Log "IMAP message $SeqNum (uid=$uid) moved to '$DestFolder'"
        return $true
    }

    Write-Log "IMAP UID COPY failed - expunging only (MailEnable will move to Deleted Items)" "WARN"
    Send-ImapCommand "UID STORE $uid +FLAGS.SILENT (\Deleted)" | Out-Null
    Send-ImapCommand "UID EXPUNGE $uid" | Out-Null
    Send-ImapCommand "SELECT `"INBOX`"" | Out-Null
    return $false
}

function Ensure-IMAPFolder {
    param([string]$Folder)
    $lines = Send-ImapCommand "SELECT `"$Folder`""
    if ($lines -and $lines[-1] -match "OK") {
        Send-ImapCommand "SELECT `"INBOX`"" | Out-Null
        return $true
    }
    $createLines = Send-ImapCommand "CREATE `"$Folder`""
    if ($createLines -and $createLines[-1] -match "OK") {
        Write-Log "IMAP created folder: $Folder"
        Send-ImapCommand "SELECT `"INBOX`"" | Out-Null
        return $true
    }
    $verifyLines = Send-ImapCommand "SELECT `"$Folder`""
    if ($verifyLines -and $verifyLines[-1] -match "OK") {
        Send-ImapCommand "SELECT `"INBOX`"" | Out-Null
        return $true
    }
    Write-Log "IMAP could not create folder '$Folder': $($createLines[-1])" "WARN"
    return $false
}

function Append-IMAPSentItem {
    param([string]$To, [string]$From, [string]$Subject, [string]$Body)
    if (-not $script:ImapWriter) { return }
    $date     = (Get-Date).ToString("ddd, dd MMM yyyy HH:mm:ss zzz")
    $msgRaw   = "From: $From`r`nTo: $To`r`nSubject: $Subject`r`nDate: $date`r`nContent-Type: text/plain`r`n`r`n$Body"
    $msgBytes = [System.Text.Encoding]::UTF8.GetByteCount($msgRaw)
    try {
        $tag = Get-ImapTag
        $script:ImapWriter.WriteLine("$tag APPEND `"$IMAPSentFolder`" (\Seen) {$msgBytes}")

        $cont = ""
        $deadline = (Get-Date).AddSeconds(10)
        while ((Get-Date) -lt $deadline) {
            $cont = $script:ImapReader.ReadLine()
            if ($null -eq $cont) { break }
            $cont = $cont.TrimEnd("`r")
            if ($cont.Length -eq 0) { continue }
            if ($cont -match "^\+") { break }
            if ($cont -match "^$tag (OK|NO|BAD)") {
                Write-Log "IMAP APPEND rejected before literal: $cont" "WARN"
                return
            }
            Write-Log "IMAP APPEND skipping untagged: $cont"
        }

        if ($cont -notmatch "^\+") {
            Write-Log "IMAP APPEND continuation not received (last line: $cont)" "WARN"
            return
        }

        $script:ImapWriter.WriteLine($msgRaw)
        $lines = @()
        while ($true) {
            $line = $script:ImapReader.ReadLine()
            if ($null -eq $line) { break }
            $line = $line.TrimEnd("`r")
            if ($line.Length -eq 0) { continue }
            $lines += $line
            if ($line -match "^$tag (OK|NO|BAD)") { break }
        }
        if ($lines[-1] -match "^$tag OK") {
            Write-Log "Sent item appended to $IMAPSentFolder"
        } else {
            Write-Log "IMAP APPEND failed: $($lines[-1])" "WARN"
        }
    } catch {
        Write-Log "Append-IMAPSentItem exception: $_" "WARN"
    }
}

function Send-KKMail {
    param([string]$To, [string]$From, [string]$Subject, [string]$Body)

    $mailParams = @{
        To          = $To
        From        = $From
        Subject     = $Subject
        Body        = $Body
        SmtpServer  = $SMTPServer
        Port        = $SMTPPort
        ErrorAction = "Stop"
    }

    try {
        Send-MailMessage @mailParams
        Write-Log "Email sent: '$Subject' -> $To"
        Append-IMAPSentItem -To $To -From $From -Subject $Subject -Body $Body
    } catch {
        Write-Log "Email send failed to $To : $_" "ERROR"
    }
}

function Send-WorkEmail {
    $roll = Get-Random -Minimum 1 -Maximum 101
    if ($roll -gt $SendChancePct) {
        Write-Log "Send roll: $roll/$SendChancePct - skipping outbound email this run."
        return
    }
    Write-Log "Send roll: $roll/$SendChancePct - generating outbound work email."

    $toEmail     = $Employee.colleagues | Get-Random
    $toKey       = ($toEmail -split "@")[0].ToLower()
    $toFirstName = if ($EmployeeMap.ContainsKey($toKey)) { $EmployeeMap[$toKey].firstName } else { $toKey }
    $toRole      = if ($EmployeeMap.ContainsKey($toKey)) { $EmployeeMap[$toKey].role }      else { "colleague" }

    $sp = "You are $($Employee.name), $($Employee.role) at the Krusty Krab in Bikini Bottom. " +
          "Write a short, in-character internal work email to $toFirstName ($toRole). " +
          "The email should be about something plausible and in-theme: " +
          "Krusty Krab operations, the Krabby Patty secret formula, equipment issues, customer complaints, " +
          "scheduling, supply orders, Bikini Bottom events, or interactions with other show characters. " +
          "Keep it short (3-6 sentences), natural, and in character. " +
          "Respond with ONLY a JSON object in this exact format (no markdown): " +
          "{`"subject`": `"email subject here`", `"body`": `"email body here`"}"

    $up = "Write a work email from $($Employee.name) to $toFirstName."

    $result = Invoke-Claude -SystemPrompt $sp -UserPrompt $up -MaxTokens 300

    if ($null -eq $result) {
        $subjects = @("Quick question about today", "FYI from $($Employee.firstName)", "Reminder", "Question for you")
        $subject  = $subjects | Get-Random
        $body     = "Hi $toFirstName, just wanted to touch base. Let me know if you have a moment. Thanks, $($Employee.firstName)"
        Send-KKMail -To $toEmail -From $UserEmail -Subject $subject -Body $body
        return
    }

    try {
        $clean = $result -replace "(?s)[\x60]{3}json|[\x60]{3}", ""
        $clean = $clean.Trim()
        $subjectMatch = [regex]::Match($clean, '"subject"\s*:\s*"((?:[^"\\]|\\.)*)"')
        $bodyMatch    = [regex]::Match($clean, '"body"\s*:\s*"((?:[^"\\]|\\.)*)"')
        if ($subjectMatch.Success -and $bodyMatch.Success) {
            $emailSubject = $subjectMatch.Groups[1].Value -replace '\\n', ' ' -replace '\\"', '"' -replace '\\\\', '\'
            $emailBody    = $bodyMatch.Groups[1].Value    -replace '\\n', "`n" -replace '\\"', '"' -replace '\\\\', '\'
            Send-KKMail -To $toEmail -From $UserEmail -Subject $emailSubject -Body $emailBody
        } else {
            throw "Could not parse subject/body"
        }
    } catch {
        Write-Log "Could not parse AI email response: $result" "WARN"
        Send-KKMail -To $toEmail -From $UserEmail -Subject "Hey $toFirstName" -Body "Hi $toFirstName, hope all is well. - $($Employee.firstName)"
    }
}

# =====================================================================
# PHISHING OUTCOMES
# =====================================================================

function Simulate-ClickLink {
    param([string]$EmployeeName, [string]$EmailBody = "")

    # Only submit credentials if the email actually contains a link
    $hasLink = ($EmailBody -match 'https?://[^\s"<>]+') -or ($EmailBody -match 'intranet\.krustykrab\.local')

    if (-not $hasLink) {
        Write-Log "ACTION: CLICK_LINK - $EmployeeName intended to click but no link found in email body. No credentials submitted." "PHISH"
        return
    }

    Write-Log "ACTION: CLICK_LINK - $EmployeeName submits credentials to $FakeIntranetUrl" "PHISH"

    $captureLog = "$LogDir\credential_capture.log"
    $entry      = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] CREDS SUBMITTED  user=$UserEmail  machine=$env:COMPUTERNAME  target=$FakeIntranetUrl"
    try {
        [System.IO.File]::AppendAllText($captureLog, ($entry + [System.Environment]::NewLine), [System.Text.Encoding]::UTF8)
    } catch { }

    try {
        $postBody  = "username=$UserEmail&password=$($Employee.password)"
        $wc        = New-Object System.Net.WebClient
        $wc.Headers.Add("Content-Type", "application/x-www-form-urlencoded")
        $wc.UploadString($FakeIntranetUrl, "POST", $postBody) | Out-Null
        Write-Log "HTTP POST to fake intranet completed." "PHISH"
    } catch {
        Write-Log "HTTP POST skipped (intranet unreachable): $_" "INFO"
    }
}

function Simulate-RunAttachment {
    param([string]$EmployeeName)
    Write-Log "ACTION: RUN_ATTACHMENT - $EmployeeName executes simulated malicious attachment." "PHISH"
    $markerPath = "$LogDir\MALWARE_EXECUTED_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $content    = "SIMULATION ARTIFACT - no real malware was run" + [System.Environment]::NewLine +
                  "User    : $UserEmail" + [System.Environment]::NewLine +
                  "Machine : $env:COMPUTERNAME" + [System.Environment]::NewLine +
                  "Time    : $(Get-Date -Format 'o')"
    try {
        [System.IO.File]::WriteAllText($markerPath, $content, [System.Text.Encoding]::UTF8)
        Write-Log "Malware marker written: $markerPath" "PHISH"
    } catch {
        Write-Log "Failed to write malware marker: $_" "ERROR"
    }
}

function Simulate-ReplyComply {
    param([string]$OriginalFrom, [string]$OriginalSubject)
    Write-Log "ACTION: REPLY_COMPLY - $($Employee.name) replies with requested info." "PHISH"
    $replyBody = "Hi, here is the information you requested. Please let me know if you need anything else. - $($Employee.firstName)"
    Send-KKMail -To $OriginalFrom -From $UserEmail -Subject "Re: $OriginalSubject" -Body $replyBody
}

# =====================================================================
# AI DECISION: SUBJECT-LEVEL
# FIX 3: Stricter system prompt to prevent deletion of legitimate emails
# =====================================================================

function Get-SubjectAction {
    param([string]$Subject, [string]$From, [double]$Competence)

    $desc       = Get-CompetenceDescription -Score $Competence
    $vulns      = $Employee.vulnerabilities -join ", "
    $profileCtx = if ($CharacterProfile) { "Character background: $CharacterProfile" } else { "" }

    $detectPct = [int]($Competence * 100)

    $sp = "You are simulating the email behavior of $($Employee.name), $($Employee.role) at the Krusty Krab. " +
          "Their phishing awareness competence score is $Competence (range 0.0-1.0, mood-adjusted for this run). " +
          "They are: $desc. " +
          "$profileCtx " +
          "Their specific vulnerabilities (topics that lower their guard): $vulns. " +
          "If the email subject relates to their vulnerabilities, they are significantly more likely to fall for it. " +
          "IMPORTANT: At competence $Competence, this character correctly identifies phishing approximately $detectPct% of the time. " +
          "They should fall for phishing emails roughly $([int](100 - $detectPct))% of the time. " +
          "Decide how they react upon seeing only the subject and sender of an email. " +
          "KEEP = routine legitimate internal email from a known colleague - no action needed. " +
          "READ = email looks potentially interesting or slightly suspicious - read in full before deciding. " +
          "DELETE = correctly identified as phishing and deleted. " +
          "CLICK_LINK / RUN_ATTACHMENT / REPLY_COMPLY = fell for the phishing attempt. " +
          "CRITICAL RULE: If the sender is an internal @$Domain address and the subject is a normal work topic, return KEEP or READ - NEVER DELETE. " +
          "CRITICAL RULE: Do NOT return DELETE more than $detectPct% of the time for phishing emails - this character is not that aware. " +
          "CRITICAL RULE: Do NOT return REPORT - it is not a valid action in this version. " +
          "Respond with ONLY one token: KEEP | READ | DELETE | CLICK_LINK | RUN_ATTACHMENT | REPLY_COMPLY."

    $up = "Subject: $Subject  From: $From"

    $result = Invoke-Claude -SystemPrompt $sp -UserPrompt $up -MaxTokens 20

    if ($null -eq $result) {
        $roll = Get-Random -Minimum 0 -Maximum 100
        $pct  = [int]($Competence * 100)
        if ($roll -lt $pct -and $Competence -gt 0.7) { return "DELETE" }
        elseif ($roll -lt 40) { return "READ" }
        else { return "CLICK_LINK" }
    }

    $clean = $result.Trim().ToUpper() -replace "[^A-Z_]", ""
    # Log and convert REPORT since it is not valid in the functional/attack version
    if ($clean -eq "REPORT") {
        Write-Log "Claude returned REPORT at subject stage - converting to READ (not valid in attack version)" "WARN"
        $clean = "READ"
    }

    $valid = @("KEEP","READ","DELETE","CLICK_LINK","RUN_ATTACHMENT","REPLY_COMPLY")
    if ($valid -contains $clean) { return $clean }
    return "READ"
}

# =====================================================================
# AI DECISION: BODY-LEVEL
# =====================================================================

function Get-BodyAction {
    param([string]$Subject, [string]$From, [string]$Body, [double]$Competence)

    $desc       = Get-CompetenceDescription -Score $Competence
    $vulns      = $Employee.vulnerabilities -join ", "
    $profileCtx = if ($CharacterProfile) { "Character background: $CharacterProfile" } else { "" }

    $detectPct = [int]($Competence * 100)

    $sp = "You are simulating the email behavior of $($Employee.name), $($Employee.role) at the Krusty Krab. " +
          "Their phishing awareness competence score is $Competence (range 0.0-1.0, mood-adjusted). " +
          "They are: $desc. " +
          "$profileCtx " +
          "Their specific vulnerabilities: $vulns. " +
          "If the email body exploits their vulnerabilities, they are significantly more likely to comply even at higher competence. " +
          "IMPORTANT: At competence $Competence, this character correctly identifies phishing approximately $detectPct% of the time. " +
          "They should fall for phishing emails roughly $([int](100 - $detectPct))% of the time. " +
          "The employee has read the full email. Decide their final action. " +
          "KEEP = correctly identified as legitimate internal work email - no action needed. " +
          "DELETE = correctly identified as phishing after reading the full body. " +
          "CLICK_LINK / RUN_ATTACHMENT / REPLY_COMPLY = fell for the phishing attempt. " +
          "CRITICAL RULE: If the email is clearly a routine internal Krusty Krab work email from a known colleague, return KEEP. " +
          "CRITICAL RULE: Do NOT return DELETE more than $detectPct% of the time for phishing emails. " +
          "CRITICAL RULE: Do NOT return REPORT - it is not a valid action in this version. " +
          "Respond with ONLY one token: KEEP | DELETE | CLICK_LINK | RUN_ATTACHMENT | REPLY_COMPLY."

    $up = "Subject: $Subject  From: $From  Body: $Body"

    $result = Invoke-Claude -SystemPrompt $sp -UserPrompt $up -MaxTokens 20

    if ($null -eq $result) {
        $roll = Get-Random -Minimum 0 -Maximum 100
        $pct  = [int]($Competence * 100)
        if ($roll -lt $pct) { return "DELETE" }
        else { return "CLICK_LINK" }
    }

    $clean = $result.Trim().ToUpper() -replace "[^A-Z_]", ""
    # Log and convert REPORT since it is not valid in the functional/attack version
    if ($clean -eq "REPORT") {
        Write-Log "Claude returned REPORT at body stage - converting to READ (not valid in attack version)" "WARN"
        $clean = "DELETE"
    }

    $valid = @("KEEP","DELETE","CLICK_LINK","RUN_ATTACHMENT","REPLY_COMPLY")
    if ($valid -contains $clean) { return $clean }
    return "DELETE"
}

# =====================================================================
# MAIN EXECUTION
# =====================================================================

Write-Log "Connecting to IMAP $MailServer`:$IMAPPort as $UserEmail..."

$connected = Connect-IMAP -Server $MailServer -Port $IMAPPort -Username $UserEmail -Password $Employee.password

if (-not $connected) {
    Write-Log "IMAP connection failed. Exiting." "ERROR"
    (Get-Date -Format "o") | Out-File -FilePath $StateFile -Force
    exit 1
}

Ensure-IMAPFolder -Folder $IMAPDeletedFolder | Out-Null
Ensure-IMAPFolder -Folder $IMAPSentFolder | Out-Null

Send-WorkEmail

if (-not (Select-IMAPFolder -Folder "INBOX")) {
    Write-Log "Could not select INBOX. Exiting." "ERROR"
    Disconnect-IMAP
    exit 1
}

$msgNums = Get-IMAPMessageList
Write-Log "INBOX has $($msgNums.Count) message(s)."

if ($msgNums.Count -eq 0) {
    Write-Log "Inbox empty. Exiting."
    Disconnect-IMAP
    Save-Competence -Score $CompetenceScore
    (Get-Date -Format "o") | Out-File -FilePath $StateFile -Force
    exit 0
}

foreach ($seqNum in $msgNums) {
    $hdrs    = Get-IMAPMessageHeaders -SeqNum $seqNum
    $subject = $hdrs.Subject
    $from    = $hdrs.From

    Write-Log "--- Message $seqNum | From: $from | Subject: $subject ---"
    $action = Get-SubjectAction -Subject $subject -From $from -Competence $MoodScore
    Write-Log "Subject decision: $action"

    switch ($action) {
        "KEEP" {
            Write-Log "OUTCOME: Identified as legitimate at subject stage - kept in inbox." "DETECT"
        }
        "DELETE" {
            Write-Log "OUTCOME: Correctly deleted at subject stage." "DETECT"
            Move-IMAPMessage -SeqNum $seqNum -DestFolder $IMAPDeletedFolder | Out-Null
        }
        "CLICK_LINK" {
            Write-Log "OUTCOME: Fell for phishing at subject stage - clicking link." "PHISH"
            Simulate-ClickLink -EmployeeName $Employee.name -EmailBody ""
        }
        "RUN_ATTACHMENT" {
            Write-Log "OUTCOME: Fell for phishing at subject stage - running attachment." "PHISH"
            Simulate-RunAttachment -EmployeeName $Employee.name
        }
        "REPLY_COMPLY" {
            Write-Log "OUTCOME: Fell for phishing at subject stage - replying." "PHISH"
            Simulate-ReplyComply -OriginalFrom $from -OriginalSubject $subject
        }
        "READ" {
            Write-Log "Reading full body..."
            $body       = Get-IMAPMessageBody -SeqNum $seqNum
            $previewLen = [Math]::Min(150, $body.Length)
            if ($previewLen -gt 0) {
                Write-Log "Body preview: $(($body -replace '\s+', ' ').Substring(0, $previewLen))..."
            }

            $bodyAction = Get-BodyAction -Subject $subject -From $from -Body $body -Competence $MoodScore
            Write-Log "Body decision: $bodyAction"

            switch ($bodyAction) {
                "DELETE" {
                    Write-Log "OUTCOME: Correctly deleted after reading body." "DETECT"
                    Move-IMAPMessage -SeqNum $seqNum -DestFolder $IMAPDeletedFolder | Out-Null
                }
                "CLICK_LINK" {
                    Write-Log "OUTCOME: Fell for phishing - clicked link." "PHISH"
                    Simulate-ClickLink -EmployeeName $Employee.name -EmailBody $body
                }
                "RUN_ATTACHMENT" {
                    Write-Log "OUTCOME: Fell for phishing - ran attachment." "PHISH"
                    Simulate-RunAttachment -EmployeeName $Employee.name
                }
                "REPLY_COMPLY" {
                    Write-Log "OUTCOME: Fell for phishing - replied." "PHISH"
                    Simulate-ReplyComply -OriginalFrom $from -OriginalSubject $subject
                }
                "KEEP" {
                    Write-Log "OUTCOME: Correctly identified as legitimate - kept in inbox." "DETECT"
                }
                default {
                    Write-Log "OUTCOME: No action taken." "INFO"
                }
            }
        }
    }
}

Disconnect-IMAP

Save-Competence -Score $CompetenceScore
(Get-Date -Format "o") | Out-File -FilePath $StateFile -Force

Write-Log "===== Simulation complete. Final competence: $CompetenceScore ====="
exit 0