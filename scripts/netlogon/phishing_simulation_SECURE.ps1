# =====================================================================
# Krusty Krab Phishing Simulation - SECURE VERSION
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
#   Sandy      0.80 - IT consultant, escalates phishing reports to Larry
#   Larry      0.85 - Cybersecurity officer, investigates and blocks threats
#
# SECURE VERSION FEATURES:
#   - REPORT action: non-security users can forward suspicious emails to Sandy
#   - Sandy escalates confirmed phishing to Larry for investigation and gives
#     the reporter an immediate holding reply
#   - Larry performs AI threat assessment on escalated reports (internal
#     compromised-account vs. false alarm vs. spoofed real-employee address;
#     external LOW/MEDIUM/HIGH threat), resets AD passwords only on confirmed
#     and verified compromise, and warns affected/all staff while briefing
#     Mr. Krabs
#   - Send-KKMail stamps every outbound message with X-KK-Sender (the domain
#     identity the sending scheduled task is actually running as). Larry
#     cross-checks this stamp before treating an internal report as a real
#     account compromise, so a spoofed real-employee address is no longer
#     indistinguishable from a genuinely compromised one
#   - Larry triages real Wazuh alerts from $WazuhManagerEmail, confirming
#     whether each is genuinely suspicious/malicious or benign scheduled-task
#     noise from this simulation, and tasks Sandy with checking potentially
#     compromised endpoints on confirmed-suspicious alerts
#   - Larry's and Sandy's internal investigation correspondence
#     ([PHISHING REPORT], [INVESTIGATION COMPLETE], [INVESTIGATION NEEDED])
#     is intercepted before the phishing-decision AI, so operational email
#     is never scored as a simulated phishing test
#   - Training emails delivered by Sandy improve competence scores over time
#   - $Input renamed to $InputString in Decode-MimeString (PS reserved var fix)
#   - $Matches captured to local var before function calls
#   - REPORT->DELETE conversion removed; REPORT is now a valid action
#   - Competence score tied numerically to AI prompt probability
#   - REPORT explicitly forbidden from being returned by non-security characters
#
# Larry does not block/blacklist senders in MailEnable - $MailEnableDir is
# defined for future use but no send-block function currently exists.
#
# SENDER VERIFICATION (X-KK-Sender):
#   Purpose: let Larry distinguish a simple spoofed-address report from an
#   actual account compromise, for this simulation's current attack
#   scenarios. Send-KKMail is the only path any character script legitimately
#   sends mail through, so any message that genuinely originated from a
#   character's own run of the sim carries the stamp; the sim's current
#   attack-simulation scripts (ar-test.ps1, deploy_phishing's injector) were
#   not written to set it, so their forged internal-looking addresses do not.
#   That's the distinction Larry uses.
#
#   Limitation: this is a self-reported header, not an authenticated one -
#   nothing on the MailEnable side validates or strips it. It defends against
#   the sim's current attack scripts not bothering to set it; it would NOT
#   stop an attacker who deliberately set out to forge it, since doing so
#   requires no more effort than forging From: itself. It is intentionally
#   scoped to this project's current attack scenarios (see Limitations,
#   Section 1: "the secure snapshot is only secure against the specific
#   attacks we explored"), not presented as resistant to a motivated forger.
#
#   Real-world parallel: closest is Microsoft Exchange's
#   X-MS-Exchange-Organization-AuthAs header, which similarly flags whether a
#   message came from an authenticated internal session vs. an anonymous or
#   external one. The key difference: Exchange's MTA stamps that header
#   itself, after verifying authentication server-side, so a client can't
#   simply write its own value into it. X-KK-Sender is client-stamped with no
#   server-side enforcement, which is exactly why it doesn't carry the same
#   guarantee - see SMTP AUTH note below for the step that starts closing
#   that gap.
#
#   IMPORTANT: A missing stamp is NOT neutral - it is read as "spoofed," not
#   "unverifiable." If someone signs into a character's real mailbox directly
#   (bypassing Send-KKMail entirely) and sends mail from it, that message has
#   no X-KK-Sender. If a script later flags it and it gets reported, Larry
#   will classify it as a spoofed address impersonating that employee - NOT
#   as a compromised account - even if the account genuinely is compromised.
#   No AD reset fires, the real employee isn't warned, and Sandy isn't tasked
#   to check the workstation. X-KK-Sender only proves a message passed
#   through Send-KKMail; it does not prove the account behind it is clean.
#
#   SMTP AUTH: Send-KKMail also now authenticates to MailEnable using the
#   sending character's own password (the same credential already used for
#   Connect-IMAP and the webmail login), rather than submitting anonymously.
#   This is a necessary step toward a real version of the Exchange AuthAs
#   parallel above, but is not sufficient on its own: it only has security
#   value if MailEnable's SMTP connector is configured to require
#   authentication (reject anonymous relay) for submission. If MailEnable
#   still permits unauthenticated relay from internal hosts - which is the
#   likely current configuration, since sends worked previously with no
#   credentials at all - an unauthenticated attacker can still submit mail
#   exactly as before; this change only means the sim's own legitimate
#   traffic now proves what it claims, not that forged traffic is rejected.
#   Confirming and, if needed, changing that connector setting is a MailEnable
#   admin-console task outside what this script controls.
#
# ESCALATION CHAIN (phishing reports):
#   User reports -> Sandy (IT) escalates by email to Larry and immediately
#     sends the reporter a holding reply (don't click, escalated to Larry).
#     The report carries the original message's raw From:/Subject: (fetched
#     via IMAP) plus its Verified-Sender: field (X-KK-Sender, if any) as its
#     own tagged field, unmodified, all the way to Larry.
#   Larry's next scheduled run picks up that email and investigates the
#     sender: internal (compromised account vs. false alarm vs. spoofed
#     real-employee address, via X-KK-Sender cross-check) or external
#     (LOW/MEDIUM/HIGH threat)
#   Larry warns affected/all staff directly, briefs Mr. Krabs, and emails
#     Sandy an [INVESTIGATION COMPLETE] summary
#
# WAZUH ALERT TRIAGE:
#   Wazuh -> Larry receives real notifications from $WazuhManagerEmail
#     (Wazuh.Manager@krustykrabexample.local). Subject varies by alert
#     type - leveled alerts use "Wazuh notification - ...", active-response
#     alerts have no subject at all - so detection is gated on sender
#     address alone, not subject.
#   Larry confirms whether the alert reflects this simulation's own
#     scheduled-task activity (benign, no action) or the ar-test.ps1
#     attack-simulation script (genuine, treated as a real incident)
#   On a confirmed-suspicious alert, Larry asks Sandy to check the
#     potentially compromised endpoint(s) and briefs Mr. Krabs
# =====================================================================

$ErrorActionPreference = "SilentlyContinue"

# Win7-safe TLS 1.2 enablement using enum int value (3072)
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

$Domain             = "krustykrabexample.local"
$MailServer         = "mail.krustykrabexample.local"
$IMAPPort           = 143
$SMTPServer         = "mail.krustykrabexample.local"
$SMTPPort           = 25
$ScriptDir          = "C:\Scripts"
$LogDir             = "$ScriptDir\logs"
$CompetenceDir      = "$ScriptDir\competence"
$FakeIntranetUrl    = "http://intranet.krustykrabexample.local/login"
$AnthropicModel     = "claude-haiku-4-5-20251001"
$MinIntervalMinutes = 5
$IMAPDeletedFolder  = "Deleted Items"
$IMAPSentFolder     = "Sent Items"
$MailEnableDir      = "C:\Program Files (x86)\Mail Enable"
$SendChancePct      = 40
$TrainingSubject    = "Krusty Krab Required Phishing Awareness Training"
$ITOfficer          = "sandy.cheeks@$Domain"
$CyberSecOfficer    = "larry.lobster@$Domain"
$WazuhManagerEmail  = "Wazuh.Manager@$Domain"
# Informational only - NOT used to gate detection (see the Wazuh triage
# block below). Leveled Wazuh alerts use this subject format; active-response
# alerts have no subject at all, so subject can't reliably identify Wazuh mail.
$WazuhSubjectPrefix = "Wazuh notification -"

### EDIT 1 - Anthropic API key
$AnthropicApiKey = "YOUR-API-KEY-HERE"

# =====================================================================
# ENSURE DIRECTORIES
# =====================================================================

Write-Log "===== phishing_simulation-SECURE.ps1 started ====="
Write-Log "Running on $env:COMPUTERNAME as $env:USERNAME"
Write-Log "Log file: $script:LogFile"

# =====================================================================
# ENSURE DIRECTORIES
# =====================================================================

foreach ($dir in @($ScriptDir, $LogDir, $CompetenceDir)) {
    try {
        if (-not [System.IO.Directory]::Exists($dir)) {
            [System.IO.Directory]::CreateDirectory($dir) | Out-Null
            Write-Log "Created directory: $dir"
        }
    } catch { }
}

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
        email           = "spongebob.squarepants@$Domain"
        name            = "SpongeBob SquarePants"
        firstName       = "SpongeBob"
        password        = "KrustyFryCook!"
        role            = "Fry Cook"
        defaultScore    = 0.10
        isSecurity      = $false
        isIT            = $false
        isCyberSec      = $false
        wikiUrl         = "https://spongebob.fandom.com/wiki/SpongeBob_SquarePants"
        vulnerabilities = @("authority", "approval", "friendship", "helping others", "Mr. Krabs", "Krabby Patty")
        colleagues      = @("squidward.tentacles@$Domain", "eugene.krabs@$Domain", "sandy.cheeks@$Domain")
    }
    "squidward.tentacles" = @{
        email           = "squidward.tentacles@$Domain"
        name            = "Squidward Tentacles"
        firstName       = "Squidward"
        password        = "KrustyKlarinet!"
        role            = "Cashier"
        defaultScore    = 0.25
        isSecurity      = $false
        isIT            = $false
        isCyberSec      = $false
        wikiUrl         = "https://spongebob.fandom.com/wiki/Squidward_Tentacles"
        vulnerabilities = @("flattery", "art recognition", "talent", "fame", "clarinet", "superiority")
        colleagues      = @("spongebob.squarepants@$Domain", "eugene.krabs@$Domain", "sandy.cheeks@$Domain")
    }
    "eugene.krabs" = @{
        email           = "eugene.krabs@$Domain"
        name            = "Eugene Krabs"
        firstName       = "Mr. Krabs"
        password        = "KrustyAnchor!"
        role            = "Owner and Manager"
        defaultScore    = 0.20
        isSecurity      = $false
        isIT            = $false
        isCyberSec      = $false
        wikiUrl         = "https://spongebob.fandom.com/wiki/Eugene_H._Krabs"
        vulnerabilities = @("money", "profit", "discount", "investment", "revenue", "treasure", "deal", "savings")
        colleagues      = @("spongebob.squarepants@$Domain", "squidward.tentacles@$Domain", "sandy.cheeks@$Domain")
    }
    "sandy.cheeks" = @{
        email           = "sandy.cheeks@$Domain"
        name            = "Sandy Cheeks"
        firstName       = "Sandy"
        password        = "KrustyAcorns!"
        role            = "IT and Science Consultant"
        defaultScore    = 0.80
        isSecurity      = $true
        isIT            = $true
        isCyberSec      = $false
        wikiUrl         = "https://spongebob.fandom.com/wiki/Sandy_Cheeks"
        vulnerabilities = @("science", "Texas", "research grant", "technology breakthrough")
        colleagues      = @("spongebob.squarepants@$Domain", "squidward.tentacles@$Domain", "eugene.krabs@$Domain", "larry.lobster@$Domain")
    }
    "larry.lobster" = @{
        email           = "larry.lobster@$Domain"
        name            = "Larry Lobster"
        firstName       = "Larry"
        password        = "KrustyPants!"
        role            = "Cybersecurity and Physical Security Officer"
        defaultScore    = 0.85
        isSecurity      = $true
        isIT            = $false
        isCyberSec      = $true
        wikiUrl         = "https://spongebob.fandom.com/wiki/Larry_the_Lobster"
        vulnerabilities = @("fitness", "bodybuilding", "gym", "protein", "muscles", "competition")
        colleagues      = @("sandy.cheeks@$Domain", "eugene.krabs@$Domain", "spongebob.squarepants@$Domain", "squidward.tentacles@$Domain")
    }
}

if (-not $EmployeeMap.ContainsKey($UserKey)) {
    Write-Log "User '$WindowsUser' not in employee map. Exiting." "SKIP"
    exit 0
}

$Employee   = $EmployeeMap[$UserKey]
$UserEmail  = $Employee.email
$IsSecurity = $Employee.isSecurity
$IsIT       = $Employee.isIT
$IsCyberSec = $Employee.isCyberSec

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
            if ($raw -match '"score"\s*:\s*([\d.]+)') {
                $score = [double]$Matches[1]

                # Time-based competence decay: lose 2% per week since last update
                # Skills fade without reinforcement - decay floor is the character's default score
                if ($raw -match '"updated"\s*:\s*"([^"]+)"') {
                    try {
                        $lastUpdated  = [datetime]$Matches[1]
                        $weeksSince   = ([datetime]::UtcNow - $lastUpdated.ToUniversalTime()).TotalDays / 7.0
                        $decay        = [Math]::Round($weeksSince * 0.02, 4)
                        if ($decay -gt 0) {
                            $decayedScore = [Math]::Max($Employee.defaultScore, $score - $decay)
                            Write-Log "TRAINING: Decay: $([Math]::Round($weeksSince,1)) weeks since last update, -$decay applied. $score -> $decayedScore" "TRAINING"
                            $score = $decayedScore
                        }
                    } catch { }
                }

                return $score
            }
        } catch { }
    }
    return $Employee.defaultScore
}

# Load training boost total and seen email hashes from competence file
# Returns hashtable: @{ boostTotal = 0.0; seenHashes = @() }
function Load-TrainingMeta {
    $meta = @{ boostTotal = 0.0; seenHashes = @() }
    if (Test-Path $CompetenceFile) {
        try {
            $raw = [System.IO.File]::ReadAllText($CompetenceFile)
            if ($raw -match '"boostTotal"\s*:\s*([\d.]+)') {
                $meta.boostTotal = [double]$Matches[1]
            }
            if ($raw -match '"seenHashes"\s*:\s*\[([^\]]*)\]') {
                $hashStr = $Matches[1]
                $meta.seenHashes = @($hashStr -split ',' | ForEach-Object {
                    ($_ -replace '"', '').Trim()
                } | Where-Object { $_ -ne '' })
            }
        } catch { }
    }
    return $meta
}

function Save-Competence {
    param([double]$Score, [double]$BoostTotal = 0.0, [string[]]$SeenHashes = @())
    $Score       = [Math]::Round([Math]::Max(0.0, [Math]::Min(1.0, $Score)), 3)
    $BoostTotal  = [Math]::Round([Math]::Max(0.0, $BoostTotal), 4)
    $hashesJson  = ($SeenHashes | ForEach-Object { "`"$_`"" }) -join ","
    $json        = "{`"score`": $Score, `"user`": `"$UserKey`", `"updated`": `"$(Get-Date -Format 'o')`", `"boostTotal`": $BoostTotal, `"seenHashes`": [$hashesJson]}"
    try {
        # Ensure competence directory exists - may not exist on first run for new users
        $dir = [System.IO.Path]::GetDirectoryName($CompetenceFile)
        if (-not [System.IO.Directory]::Exists($dir)) {
            [System.IO.Directory]::CreateDirectory($dir) | Out-Null
            Write-Log "Created competence directory: $dir"
        }
        [System.IO.File]::WriteAllText($CompetenceFile, $json, [System.Text.Encoding]::UTF8)
        Write-Log "Competence score saved: $Score (training boost total: $BoostTotal)"
    } catch {
        Write-Log "Failed to save competence score: $_" "ERROR"
    }
}

$CompetenceScore = Load-Competence
$TrainingMeta    = Load-TrainingMeta
Write-Log "Loaded competence score: $CompetenceScore (training boost total: $($TrainingMeta.boostTotal), seen emails: $($TrainingMeta.seenHashes.Count))"

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
    "larry.lobster"        = "Larry is confident, physically imposing, and takes his security role seriously - but his self-assurance can create blind spots. He is highly resistant to most social engineering but can be distracted by anything related to fitness, bodybuilding, gym culture, or physical competition, which he finds genuinely engaging. He approaches threats methodically and is unlikely to panic or act impulsively, making him reliable but occasionally overconfident in his own threat assessment."
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

    # Validate locally before ever sending - if our own serialization is
    # broken, PowerShell's JSON parser catches it immediately with a
    # specific parse error, instead of waiting on a round-trip to the API
    # just to get back a generic "(400) Bad Request" with no detail.
    try {
        $null = ConvertFrom-Json $bodyJson -ErrorAction Stop
    } catch {
        Write-Log "Claude API request body is malformed JSON BEFORE sending - $_ | Body preview: $($bodyJson.Substring(0, [Math]::Min(300, $bodyJson.Length)))" "ERROR"
        return $null
    }

    $delays = @(5, 15, 30)
    foreach ($attempt in 0..2) {
        try {
            [System.Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject(
                [System.Net.SecurityProtocolType], 3072)
            $wc = New-Object System.Net.WebClient
            $wc.Headers.Add("x-api-key",        $AnthropicApiKey)
            $wc.Headers.Add("anthropic-version", "2023-06-01")
            $wc.Headers.Add("content-type",      "application/json")
            $bodyBytes     = [System.Text.Encoding]::UTF8.GetBytes($bodyJson)
            $responseBytes = $wc.UploadData("https://api.anthropic.com/v1/messages", "POST", $bodyBytes)
            $responseText  = [System.Text.Encoding]::UTF8.GetString($responseBytes)

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
            # PowerShell wraps this in its own MethodInvocationException, same
            # as the SmtpClient failures - "(400) Bad Request" alone doesn't
            # say what was wrong. The actual detail Anthropic sends back
            # (e.g. which field was invalid) sits unread on the underlying
            # WebException's response stream unless we go get it.
            $apiErrorBody = ""
            $curEx = $_.Exception
            while ($null -ne $curEx) {
                if ($curEx -is [System.Net.WebException] -and $curEx.Response) {
                    try {
                        $errStream = $curEx.Response.GetResponseStream()
                        $reader    = New-Object System.IO.StreamReader($errStream)
                        $apiErrorBody = $reader.ReadToEnd()
                        $reader.Close()
                    } catch { }
                    break
                }
                $curEx = $curEx.InnerException
            }

            $msg = $_.ToString()
            if ($msg -match "429" -and $attempt -lt 2) {
                $wait = $delays[$attempt]
                Write-Log "Claude API 429 rate limit - waiting ${wait}s before retry $($attempt+1)..." "WARN"
                Start-Sleep -Seconds $wait
            } else {
                $detail = if ($apiErrorBody) { " | API response: $apiErrorBody" } else { "" }
                Write-Log "Claude API call failed: $_$detail" "ERROR"
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
# FIX: Parameter renamed from $Input to $InputString
# $Input is a PowerShell reserved automatic variable (pipeline enumerator)
# Using it as a parameter name causes it to receive System.Collections.IEnumerator
# instead of the string, making IsNullOrWhiteSpace always return true
# =====================================================================

function Decode-MimeString {
    param([string]$InputString)
    if ([string]::IsNullOrWhiteSpace($InputString)) { return $InputString }

    $result = $InputString

    # Decode quoted-printable encoded words in headers: =?charset?Q?encoded?=
    $result = [regex]::Replace($result, '=\?([^?]+)\?Q\?([^?]*)\?=', {
        param($m)
        $encoded = $m.Groups[2].Value -replace '_', ' '
        $decoded = [regex]::Replace($encoded, '=([0-9A-Fa-f]{2})', {
            param($hex)
            [char][Convert]::ToInt32($hex.Groups[1].Value, 16)
        })
        $decoded
    })

    # Decode base64 encoded words in headers: =?charset?B?base64?=
    $result = [regex]::Replace($result, '=\?([^?]+)\?B\?([^?]*)\?=', {
        param($m)
        try {
            $bytes = [Convert]::FromBase64String($m.Groups[2].Value)
            [System.Text.Encoding]::UTF8.GetString($bytes)
        } catch { $m.Value }
    })

    # Decode raw quoted-printable body encoding (=0D=0A style from MailEnable)
    # First join soft line breaks: trailing = means the line continues on the next
    $result = $result -replace '=\r?\n', ''
    # Then decode remaining =XX hex sequences
    $result = [regex]::Replace($result, '=([0-9A-Fa-f]{2})', {
        param($m)
        try {
            [char][Convert]::ToInt32($m.Groups[1].Value, 16)
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
            $captured = $Matches[1]
            $uids = $captured.Trim().Split(" ") | Where-Object { $_ -match "^\d+$" } | ForEach-Object { [int]$_ }
        }
    }
    return $uids
}

function Get-IMAPMessageHeaders {
    param([int]$SeqNum)
    $hdrs = @{ Subject = "(no subject)"; From = "(unknown)"; XKKSender = "" }
    $tag  = Get-ImapTag
    $script:ImapWriter.WriteLine("$tag FETCH $SeqNum (BODY[HEADER.FIELDS (FROM SUBJECT X-KK-SENDER)])")
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
        # X-KK-Sender is absent on any message that didn't come through
        # Send-KKMail (e.g. a spoofed or injected message) - that absence
        # is itself the signal, not a parsing failure to work around.
        if ($line -match "^X-KK-Sender:\s*(.+)") {
            $capturedXKK = $Matches[1]
            $hdrs["XKKSender"] = $capturedXKK.Trim()
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

    $copyLines    = Send-ImapCommand "UID COPY $uid `"$DestFolder`""
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

        $cont     = ""
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

# =====================================================================
# IMAP PROBE - check if a mailbox exists (used by Larry to verify senders)
# =====================================================================

function Test-MailboxExists {
    param([string]$Email)
    try {
        $probeTcp    = New-Object System.Net.Sockets.TcpClient($MailServer, $IMAPPort)
        $probeStream = $probeTcp.GetStream()
        $probeReader = New-Object System.IO.StreamReader($probeStream)
        $probeWriter = New-Object System.IO.StreamWriter($probeStream)
        $probeWriter.AutoFlush = $true

        $probeReader.ReadLine() | Out-Null  # greeting

        $probeWriter.WriteLine("Z001 LOGIN $Email INVALIDPASSWORD_PROBE")
        $lines    = @()
        $deadline = (Get-Date).AddSeconds(5)
        while ((Get-Date) -lt $deadline) {
            if ($probeReader.Peek() -ge 0) {
                $line = $probeReader.ReadLine()
                $lines += $line
                if ($line -match "^Z001 (OK|NO|BAD)") { break }
            } else {
                Start-Sleep -Milliseconds 100
            }
        }
        $probeWriter.WriteLine("Z002 LOGOUT")
        $probeTcp.Close()

        $response = $lines -join " "
        if ($response -match "Invalid credentials|authentication failed|password|incorrect") {
            return $true
        } elseif ($response -match "user.*not.*found|no.*such.*user|unknown.*user|doesn.t exist") {
            return $false
        } else {
            return $true
        }
    } catch {
        Write-Log "Test-MailboxExists probe exception: $_" "WARN"
        return $true
    }
}

# =====================================================================
# EMAIL HELPER
# =====================================================================

function Send-KKMail {
    param([string]$To, [string]$From, [string]$Subject, [string]$Body)

    # X-KK-Sender: self-reported by the sending script, stamped with the
    # domain identity the current task is running as. It does NOT resist a
    # deliberate forger - it's a plain header, and nothing on the MailEnable
    # side validates or strips it, so an attacker who specifically sets out to
    # defeat it trivially can. It is not a security control and isn't meant
    # to be read as one; see the SENDER VERIFICATION note above for its
    # actual intended purpose, limitation, and real-world parallel.
    $authenticatedSender = "$($env:USERNAME)@$Domain"

    try {
        $mailMessage = New-Object System.Net.Mail.MailMessage
        $mailMessage.To.Add($To)
        $mailMessage.From = New-Object System.Net.Mail.MailAddress($From)
        $mailMessage.Subject = $Subject
        $mailMessage.Body = $Body
        $mailMessage.Headers.Add("X-KK-Sender", $authenticatedSender)

        $smtpClient = New-Object System.Net.Mail.SmtpClient($SMTPServer, $SMTPPort)
        # SMTP AUTH: reuse the character's own MailEnable password (the same
        # credential already proven against this server via Connect-IMAP and
        # the webmail login). Every Send-KKMail call in this script sends
        # -From $UserEmail (the running character's own address), so
        # authenticating as $Employee/$UserEmail here is always correct - this
        # function is never used to send as anyone other than the account the
        # task is actually running as.
        $smtpClient.Credentials = New-Object System.Net.NetworkCredential($UserEmail, $Employee.password)
        $smtpClient.Send($mailMessage)
        $mailMessage.Dispose()

        Write-Log "Email sent: '$Subject' -> $To"
        Append-IMAPSentItem -To $To -From $From -Subject $Subject -Body $Body
    } catch {
        # PowerShell wraps .NET method-call exceptions in its own
        # MethodInvocationException, and SmtpException's own .Message is
        # almost always just the generic "Failure sending mail." - the real
        # cause is typically one level deeper still. Walk the full chain
        # rather than assuming a fixed depth.
        $exChain = @()
        $curEx = $_.Exception
        while ($null -ne $curEx) {
            $exChain += $curEx.Message
            $curEx = $curEx.InnerException
        }
        Write-Log "Email send failed to $To : $($exChain -join ' | ')" "ERROR"
    }
}

# =====================================================================
# LARRY: INVESTIGATE AND RESPOND TO PHISHING REPORT
# External sender: warn all staff, notify Mr. Krabs
# Internal compromised account: warn affected user, reset AD password,
#   ask Sandy to investigate machine, notify Mr. Krabs
# =====================================================================

function Invoke-LarryInvestigation {
    param(
        [string]$SenderAddress,
        [string]$OriginalSubject,
        [string]$OriginalBody,
        [string]$VictimEmail,
        [string]$VictimName,
        [string]$VerifiedSender = ""
    )

    $SenderAddress = ($SenderAddress -replace "=0[Dd]=0[Aa]|=0[Aa]|=0[Dd]|[\r\n]", "").Trim()
    # Extract bare email from display-name format e.g. "Plankton" <plankton@evil.com>
    if ($SenderAddress -match '<([^>]+@[^>]+)>') { $SenderAddress = $Matches[1].Trim() }
    $SenderAddress = $SenderAddress -replace '[<>]', '' -replace '^\s+|\s+$', ''

    if ($SenderAddress -notmatch "@" -or $SenderAddress.Length -lt 5) {
        Write-Log "LARRY: Invalid sender address '$SenderAddress' - skipping investigation." "WARN"
        return
    }

    Write-Log "LARRY: Beginning investigation of sender $SenderAddress" "SECURITY"

    $senderDomain = ($SenderAddress -split "@")[-1]
    $isInternal   = ($senderDomain -eq $Domain)
    $reasoning    = ""

    # Build list of non-security staff to notify
    $staffEmails = $EmployeeMap.Keys | Where-Object {
        -not $EmployeeMap[$_].isSecurity -and -not $EmployeeMap[$_].isCyberSec
    } | ForEach-Object { $EmployeeMap[$_].email }

    if ($isInternal) {
        # ----------------------------------------------------------------
        # INTERNAL SENDER - check if real employee account or fabricated
        # ----------------------------------------------------------------
        Write-Log "LARRY: Sender appears internal. Running mailbox probe..." "SECURITY"
        $mailboxExists  = Test-MailboxExists -Email $SenderAddress
        $senderLocalKey = ($SenderAddress -split "@")[0].ToLower()
        $isKnownEmployee = $EmployeeMap.ContainsKey($senderLocalKey)

        # A real mailbox/employee only tells us the address is genuine, not
        # that the message actually came from that account. Cross-check the
        # X-KK-Sender stamp (see Send-KKMail) - present and matching means
        # this really did originate from that user's own authenticated
        # sending context; missing or mismatched means the address was
        # spoofed by something outside the sim's legitimate mail path.
        $verifiedMatch = $false
        if ($mailboxExists -and $isKnownEmployee -and $VerifiedSender) {
            $verifiedMatch = ($VerifiedSender.Trim().ToLower() -eq $SenderAddress.ToLower())
        }

        if ($mailboxExists -and $isKnownEmployee -and -not $verifiedMatch) {
            # ------------------------------------------------------------
            # SPOOFED REAL-EMPLOYEE ADDRESS - the address belongs to an
            # actual employee, but this message did not carry a matching
            # X-KK-Sender stamp, so it did not originate from that
            # account's own Send-KKMail calls. This is spoofing, not
            # compromise: do NOT reset AD credentials or accuse the real
            # employee. Respond the same way as a fabricated address.
            # ------------------------------------------------------------
            $gotStamp = if ($VerifiedSender) { $VerifiedSender } else { "(none)" }
            Write-Log "LARRY: $SenderAddress is a real employee, but sender verification failed (X-KK-Sender: $gotStamp) - treating as SPOOFED, not compromised." "SECURITY"

            $spoofWarningSp = "You are Larry Lobster, Cybersecurity Officer at the Krusty Krab. " +
                               "Write a brief all-staff security warning about a phishing email that spoofed a real " +
                               "colleague's email address ($SenderAddress) without actually being sent from their account. " +
                               "Tell staff: do not click any links or reply, verify anything unusual with the sender through " +
                               "another channel, and report anything unusual to you or Sandy immediately. " +
                               "In-character as Larry, confident and direct. 3-4 sentences. Plain text only."
            $spoofWarningUp  = "Spoofed sender address: $SenderAddress. Subject of phishing email: $OriginalSubject."
            $spoofWarningMsg = Invoke-Claude -SystemPrompt $spoofWarningSp -UserPrompt $spoofWarningUp -MaxTokens 200

            if ($null -eq $spoofWarningMsg) {
                $spoofWarningMsg = "Attention team - we've identified a phishing email that spoofed '$SenderAddress' to look like it came from a real colleague, but it did not actually come from their account. Do not click any links or reply, and verify anything unusual with them directly through another channel before acting on it. Report anything odd to me or Sandy. Stay sharp out there. - Larry Lobster, Security"
            }

            foreach ($staffEmail in $staffEmails) {
                Send-KKMail -To $staffEmail -From $UserEmail -Subject "[SECURITY ALERT] Phishing Email - Spoofed Colleague Address" -Body $spoofWarningMsg
            }

            $krabsSpoofMsg = "Mr. Krabs, I want to let you know that someone sent a phishing email spoofing $SenderAddress, a real employee's address, to trick our staff. Their account itself was not used and is not compromised - I've confirmed this via our sender verification. I've warned the team and Sandy is aware. - Larry"
            Send-KKMail -To "eugene.krabs@$Domain" -From $UserEmail -Subject "[SECURITY NOTICE] Phishing Spoofed a Real Employee Address" -Body $krabsSpoofMsg

            Write-Log "LARRY: Staff warned about spoofed employee address. Mr. Krabs notified. No AD action taken." "SECURITY"

        } elseif ($mailboxExists -and $isKnownEmployee) {
            # Real employee account, verified genuine - run AI to determine if compromised or false alarm
            $sp = "You are Larry Lobster, Cybersecurity Officer at the Krusty Krab. " +
                  "An internal email address ($SenderAddress) sent a suspicious email that was reported as phishing. " +
                  "The mailbox EXISTS and belongs to a real employee. Analyze the email content: " +
                  "is this a COMPROMISED account sending phishing, or a FALSE_ALARM (legitimate email misidentified)? " +
                  "Respond with ONLY valid JSON: {`"verdict`": `"COMPROMISED`" or `"FALSE_ALARM`", `"reasoning`": `"two sentences`"}"

            $up     = "Subject: $OriginalSubject`nBody: $OriginalBody"
            $result = Invoke-Claude -SystemPrompt $sp -UserPrompt $up -MaxTokens 200

            $verdict = "COMPROMISED"
            if ($null -ne $result) {
                try {
                    $clean    = $result -replace "(?s)[\x60]{3}json|[\x60]{3}", ""
                    $verdictM = [regex]::Match($clean.Trim(), '"verdict"\s*:\s*"([^"]+)"')
                    $reasonM  = [regex]::Match($clean.Trim(), '"reasoning"\s*:\s*"([^"]+)"')
                    if ($verdictM.Success) { $verdict   = $verdictM.Groups[1].Value }
                    if ($reasonM.Success)  { $reasoning = $reasonM.Groups[1].Value }
                } catch {
                    $reasoning = "Analysis inconclusive - treating as compromised out of caution."
                }
            } else {
                $reasoning = "AI analysis unavailable - treating as compromised out of caution."
            }

            Write-Log "LARRY: Internal verdict: $verdict | $reasoning" "SECURITY"

            if ($verdict -eq "COMPROMISED") {
                # --------------------------------------------------------
                # COMPROMISED ACCOUNT RESPONSE
                # --------------------------------------------------------
                Write-Log "LARRY: Account $SenderAddress assessed as COMPROMISED. Initiating response." "SECURITY"

                # 1. Reset the compromised user's AD password
                $newPassword = "KrustyReset$((Get-Random -Minimum 1000 -Maximum 9999))!"
                try {
                    $securePass = ConvertTo-SecureString $newPassword -AsPlainText -Force
                    Set-ADAccountPassword -Identity $senderLocalKey -NewPassword $securePass -Reset -ErrorAction Stop
                    # Must clear PasswordNeverExpires before ChangePasswordAtLogon will take effect
                    Set-ADUser -Identity $senderLocalKey -PasswordNeverExpires $false -ErrorAction SilentlyContinue
                    Set-ADUser -Identity $senderLocalKey -ChangePasswordAtLogon $true -ErrorAction Stop
                    Write-Log "LARRY: AD password reset for $senderLocalKey. User must change on next login." "SECURITY"
                } catch {
                    Write-Log "LARRY: Failed to reset AD password for $senderLocalKey : $_" "ERROR"
                    $newPassword = "[password reset failed - manual reset required]"
                }

                # 2. Email the compromised user directly
                $compromisedUserEntry = $EmployeeMap[$senderLocalKey]
                $compromisedUserEmail = $compromisedUserEntry.email
                $compromisedFirstName = $compromisedUserEntry.firstName

                $userNoticeSp = "You are Larry Lobster, Cybersecurity and Physical Security Officer at the Krusty Krab. " +
                                "Write a direct, urgent but calm in-character message to $compromisedFirstName telling them: " +
                                "1) We believe their email account may have been compromised and used to send phishing emails. " +
                                "2) Their password has been reset and they must change it on next login. " +
                                "3) They should NOT click any suspicious links or open attachments until further notice. " +
                                "4) They should contact you (Larry) immediately if they notice anything unusual. " +
                                "Keep it professional, in-character as Larry, 4-6 sentences. Plain text only."
                $userNoticeUp  = "Compromised account: $SenderAddress. Victim who reported it: $VictimName."
                $userNoticeMsg = Invoke-Claude -SystemPrompt $userNoticeSp -UserPrompt $userNoticeUp -MaxTokens 200

                if ($null -eq $userNoticeMsg) {
                    $userNoticeMsg = "Hey $compromisedFirstName, heads up - it looks like your email account may have been compromised and used to send phishing emails to your colleagues. I've already reset your password so you'll need to change it the next time you log in. Please don't click any suspicious links or open any unexpected attachments until we get this sorted out, and come find me right away if you notice anything else unusual. - Larry"
                }
                Send-KKMail -To $compromisedUserEmail -From $UserEmail -Subject "[URGENT] Your Account May Be Compromised" -Body $userNoticeMsg

                # 3. Email Sandy to investigate the machine
                $sandyInvestigateSp = "You are Larry Lobster, Cybersecurity Officer at the Krusty Krab. " +
                                      "Write a message to Sandy Cheeks (IT consultant) asking her to urgently investigate " +
                                      "$($compromisedUserEntry.name)'s workstation for signs of malware or unauthorized access. " +
                                      "Mention that their account was used to send phishing emails and their password has been reset. " +
                                      "Ask Sandy to check for keyloggers, suspicious processes, and unauthorized remote access tools. " +
                                      "In-character as Larry, 3-4 sentences. Plain text only."
                $sandyInvestigateUp  = "Compromised user: $($compromisedUserEntry.name). Machine assignment: check EmployeeMap for their workstation."
                $sandyInvestigateMsg = Invoke-Claude -SystemPrompt $sandyInvestigateSp -UserPrompt $sandyInvestigateUp -MaxTokens 200

                if ($null -eq $sandyInvestigateMsg) {
                    $sandyInvestigateMsg = "Sandy, I need you to take a look at $($compromisedUserEntry.name)'s workstation ASAP - their account was used to send phishing emails to the team and I've had to reset their password. Check for keyloggers, suspicious background processes, and any unauthorized remote access tools. Let me know what you find as soon as you're done. - Larry"
                }
                Send-KKMail -To $ITOfficer -From $UserEmail -Subject "[INVESTIGATION NEEDED] Compromised Workstation - $($compromisedUserEntry.name)" -Body $sandyInvestigateMsg

                # 4. Notify Mr. Krabs
                $krabsCompromisedSp = "You are Larry Lobster, Cybersecurity Officer at the Krusty Krab. " +
                                      "Write a brief, professional message to Mr. Krabs notifying him that an internal employee account " +
                                      "($($compromisedUserEntry.name)) has been compromised and used to send phishing emails to staff. " +
                                      "Mention that you have reset the password, asked Sandy to investigate the machine, and notified the affected employee. " +
                                      "Frame it around business risk and reassure him the situation is being handled. " +
                                      "In-character as Larry, 3-4 sentences. Plain text only."
                $krabsCompromisedUp  = "Compromised employee: $($compromisedUserEntry.name). Actions taken: password reset, Sandy investigating, user notified."
                $krabsCompromisedMsg = Invoke-Claude -SystemPrompt $krabsCompromisedSp -UserPrompt $krabsCompromisedUp -MaxTokens 200

                if ($null -eq $krabsCompromisedMsg) {
                    $krabsCompromisedMsg = "Mr. Krabs, I need to let you know that $($compromisedUserEntry.name)'s email account appears to have been compromised and used to send phishing emails to your staff. I've already reset their password, asked Sandy to check their workstation for malware, and notified the employee directly. The situation is under control but I'll keep you posted as Sandy's investigation progresses. - Larry"
                }
                Send-KKMail -To "eugene.krabs@$Domain" -From $UserEmail -Subject "[SECURITY INCIDENT] Internal Account Compromised" -Body $krabsCompromisedMsg

                Write-Log "LARRY: Compromised account response complete - user notified, Sandy tasked, Mr. Krabs briefed." "SECURITY"

            } else {
                # FALSE ALARM - just notify Sandy
                $falseAlarmMsg = "Sandy," + [System.Environment]::NewLine + [System.Environment]::NewLine +
                    "Quick update on the reported phishing email from $SenderAddress." + [System.Environment]::NewLine + [System.Environment]::NewLine +
                    "VERDICT: FALSE ALARM" + [System.Environment]::NewLine +
                    "REASONING: $reasoning" + [System.Environment]::NewLine + [System.Environment]::NewLine +
                    "No action required. The email appears to be legitimate and was misidentified as phishing." + [System.Environment]::NewLine +
                    "Reported by: $VictimName ($VictimEmail)" + [System.Environment]::NewLine + [System.Environment]::NewLine +
                    "- Larry Lobster, Security"
                Send-KKMail -To $ITOfficer -From $UserEmail -Subject "[INVESTIGATION COMPLETE] $OriginalSubject" -Body $falseAlarmMsg

                # Also notify Mr. Krabs for awareness
                $krabsFalseAlarmMsg = "Mr. Krabs," + [System.Environment]::NewLine + [System.Environment]::NewLine +
                    "Just a quick heads up - one of the staff flagged a suspicious email from an internal address ($SenderAddress) but after investigation it turned out to be a false alarm. No action needed, everything checks out. I'll keep my eye on things. - Larry"
                Send-KKMail -To "eugene.krabs@$Domain" -From $UserEmail -Subject "[SECURITY UPDATE] Phishing Report - False Alarm" -Body $krabsFalseAlarmMsg
            }

        } else {
            # Fabricated internal address - not a real employee
            $reasoning = "Address $SenderAddress does not match any known employee and does not exist on the mail server. This is a fabricated internal address used to spoof legitimacy."
            Write-Log "LARRY: Fabricated internal address detected - $SenderAddress is not a real employee." "SECURITY"

            # Warn all non-security staff
            $warningSp = "You are Larry Lobster, Cybersecurity Officer at the Krusty Krab. " +
                         "Write a brief all-staff security warning about a phishing email that used a fake internal address ($SenderAddress) to appear legitimate. " +
                         "Tell staff: do not click any links or reply to any suspicious emails, and to report anything unusual to you or Sandy immediately. " +
                         "In-character as Larry, confident and direct. 3-4 sentences. Plain text only."
            $warningUp  = "Fake sender: $SenderAddress. Subject of phishing email: $OriginalSubject."
            $warningMsg = Invoke-Claude -SystemPrompt $warningSp -UserPrompt $warningUp -MaxTokens 200

            if ($null -eq $warningMsg) {
                $warningMsg = "Attention team - we have identified a phishing email circulating that used a fake internal address to look legitimate. Do not click any links or reply to any suspicious emails, and delete anything that looks off. If you received an email from '$SenderAddress' please delete it immediately and let me or Sandy know. Stay sharp out there. - Larry Lobster, Security"
            }

            foreach ($staffEmail in $staffEmails) {
                Send-KKMail -To $staffEmail -From $UserEmail -Subject "[SECURITY ALERT] Phishing Email - Fake Internal Address" -Body $warningMsg
            }

            # Notify Mr. Krabs
            $krabsMsg = "Mr. Krabs, I want to let you know that someone is sending phishing emails using a fake Krusty Krab email address ($SenderAddress) to trick our staff into thinking it's internal. I've sent a warning to the team and Sandy is aware. No accounts have been compromised as far as I can tell, but I'm keeping a close eye on things. - Larry"
            Send-KKMail -To "eugene.krabs@$Domain" -From $UserEmail -Subject "[SECURITY NOTICE] Phishing Using Fake Internal Address" -Body $krabsMsg

            Write-Log "LARRY: Staff warned about fabricated internal address. Mr. Krabs notified." "SECURITY"
        }

    } else {
        # ----------------------------------------------------------------
        # EXTERNAL SENDER - threat assessment and staff warning
        # ----------------------------------------------------------------
        Write-Log "LARRY: Sender is external ($senderDomain). Running AI threat assessment..." "SECURITY"

        $sp = "You are Larry Lobster, Cybersecurity Officer at the Krusty Krab. " +
              "An external email ($SenderAddress) was reported as phishing by a staff member. " +
              "Analyze the email and provide a threat assessment. Consider: urgency tactics, credential requests, " +
              "suspicious links, impersonation attempts, grammar/spelling issues, unexpected requests. " +
              "Respond with ONLY valid JSON: {`"threat_level`": `"LOW`" or `"MEDIUM`" or `"HIGH`", `"reasoning`": `"two to three sentences`"}"

        $up     = "From: $SenderAddress`nSubject: $OriginalSubject`nBody: $OriginalBody"
        $result = Invoke-Claude -SystemPrompt $sp -UserPrompt $up -MaxTokens 200

        $threatLevel = "MEDIUM"
        if ($null -ne $result) {
            try {
                $clean    = $result -replace "(?s)[\x60]{3}json|[\x60]{3}", ""
                $threatM  = [regex]::Match($clean.Trim(), '"threat_level"\s*:\s*"([^"]+)"')
                $reasonM  = [regex]::Match($clean.Trim(), '"reasoning"\s*:\s*"([^"]+)"')
                if ($threatM.Success) { $threatLevel = $threatM.Groups[1].Value }
                if ($reasonM.Success) { $reasoning   = $reasonM.Groups[1].Value }
                Write-Log "LARRY: External threat level: $threatLevel | $reasoning" "SECURITY"
            } catch {
                $reasoning   = "External sender analysis inconclusive."
                $threatLevel = "MEDIUM"
            }
        } else {
            $reasoning   = "AI analysis unavailable."
            $threatLevel = "MEDIUM"
        }

        # Warn all non-security staff
        $warningSp = "You are Larry Lobster, Cybersecurity Officer at the Krusty Krab. " +
                     "Write a $threatLevel-threat all-staff security warning about an external phishing email from $SenderAddress. " +
                     "Tell staff: this email is a phishing attempt, do not click any links or reply, delete it immediately, report if they received it. " +
                     "In-character as Larry, appropriately urgent for a $threatLevel threat. 3-5 sentences. Plain text only."
        $warningUp  = "External phisher: $SenderAddress. Subject: $OriginalSubject. Assessment: $reasoning"
        $warningMsg = Invoke-Claude -SystemPrompt $warningSp -UserPrompt $warningUp -MaxTokens 250

        if ($null -eq $warningMsg) {
            $warningMsg = "Attention team - we have identified a $threatLevel-threat phishing email from an external sender ($SenderAddress) targeting Krusty Krab staff. Do not click any links, open any attachments, or reply to this email under any circumstances. If you received it, delete it immediately and let me or Sandy know right away. Stay vigilant. - Larry Lobster, Security"
        }

        foreach ($staffEmail in $staffEmails) {
            Send-KKMail -To $staffEmail -From $UserEmail -Subject "[$threatLevel THREAT] Phishing Alert - External Sender" -Body $warningMsg
        }

        # Notify Mr. Krabs
        $krabsSp = "You are Larry Lobster, Cybersecurity Officer at the Krusty Krab. " +
                   "Write a brief message to Mr. Krabs about a $threatLevel-threat external phishing campaign targeting staff. " +
                   "Mention you have warned the team and the situation is being monitored. Frame it around business risk. " +
                   "In-character as Larry, 3-4 sentences. Plain text only."
        $krabsUp  = "External phisher: $SenderAddress. Threat level: $threatLevel. Assessment: $reasoning. Staff warned."
        $krabsMsg = Invoke-Claude -SystemPrompt $krabsSp -UserPrompt $krabsUp -MaxTokens 200

        if ($null -eq $krabsMsg) {
            $krabsMsg = "Mr. Krabs, I need to let you know we have a $threatLevel-threat phishing campaign coming from an external address ($SenderAddress) targeting our staff. I've already sent a warning to the whole team and Sandy is aware of the situation. No accounts have been compromised at this time and I'm keeping a close watch on things. - Larry"
        }
        Send-KKMail -To "eugene.krabs@$Domain" -From $UserEmail -Subject "[SECURITY NOTICE] External Phishing Campaign - $threatLevel Threat" -Body $krabsMsg

        # Notify Sandy for awareness
        $sandyMsg = "Sandy," + [System.Environment]::NewLine + [System.Environment]::NewLine +
            "Investigation complete on the reported phishing email." + [System.Environment]::NewLine + [System.Environment]::NewLine +
            "SENDER: $SenderAddress (EXTERNAL)" + [System.Environment]::NewLine +
            "THREAT LEVEL: $threatLevel" + [System.Environment]::NewLine +
            "ASSESSMENT: $reasoning" + [System.Environment]::NewLine + [System.Environment]::NewLine +
            "I've warned all staff and notified Mr. Krabs. No further action needed from you at this time." + [System.Environment]::NewLine +
            "Reported by: $VictimName ($VictimEmail)" + [System.Environment]::NewLine + [System.Environment]::NewLine +
            "- Larry Lobster, Security"
        Send-KKMail -To $ITOfficer -From $UserEmail -Subject "[INVESTIGATION COMPLETE] $OriginalSubject" -Body $sandyMsg

        Write-Log "LARRY: External phishing response complete - staff warned, Sandy updated, Mr. Krabs briefed." "SECURITY"

        # Optional in-character follow-up chatter to Sandy
        $chatRoll = Get-Random -Minimum 1 -Maximum 101
        if ($chatRoll -le 40) {
            $chatSp = "You are Larry Lobster, Cybersecurity and Physical Security Officer at the Krusty Krab. " +
                      "Write a short casual follow-up message to Sandy Cheeks about the phishing investigation you just wrapped up. " +
                      "In-character as a muscular lobster who takes security seriously. 2-3 sentences. Plain text only."
            $chatUp  = "Just finished investigating: $OriginalSubject from $SenderAddress. Threat level: $threatLevel."
            $chatMsg = Invoke-Claude -SystemPrompt $chatSp -UserPrompt $chatUp -MaxTokens 100
            if ($null -ne $chatMsg) {
                Send-KKMail -To $ITOfficer -From $UserEmail -Subject "Re: [INVESTIGATION COMPLETE] $OriginalSubject" -Body $chatMsg
            }
        }
    }
}

# =====================================================================
# LARRY: TRIAGE WAZUH ALERTS
# Larry's inbox receives real Wazuh notifications from $WazuhManagerEmail.
# Two sources trigger these on this network:
#   1. This phishing simulation's own scheduled tasks (PowerShell/IMAP/mail
#      activity) - frequent, expected, and BENIGN.
#   2. ar-test.ps1, an attack-simulation script that intentionally mimics
#      malicious behavior to test detections - these alerts are genuine and
#      should be triaged like a real incident: Larry asks Sandy to check the
#      potentially compromised endpoint(s).
# Larry does not act on every Wazuh email - most are the simulation's own
# scheduled-task noise. He confirms whether an alert is genuinely
# suspicious/malicious or benign before doing anything with it.
# =====================================================================

function Invoke-LarryWazuhTriage {
    param(
        [string]$AlertSubject,
        [string]$AlertBody,
        [string]$AlertFrom
    )

    Write-Log "LARRY: Received Wazuh notification. Triaging alert." "SECURITY"

    # Known-benign fast path: alerts that are clearly about this simulation's
    # own scheduled tasks and make no mention of the ar-test attack-simulation
    # script are routine noise - skip the AI call and move on.
    $simTaskPattern = "(?i)(phishing_simulation|phishing-simulation|phishing sim(ulation)?|KKPhishSim|scheduled task)"
    $arTestPattern  = "(?i)ar-test"

    if (($AlertSubject -match $simTaskPattern -or $AlertBody -match $simTaskPattern) -and
        ($AlertSubject -notmatch $arTestPattern -and $AlertBody -notmatch $arTestPattern)) {
        Write-Log "LARRY: Wazuh alert matches known phishing-sim scheduled task activity - benign, no action." "SECURITY"
        return
    }

    # Everything else (including anything mentioning ar-test.ps1) goes through
    # an AI assessment, exactly as Larry would triage a real Wazuh alert.
    $sp = "You are Larry Lobster, Cybersecurity Officer at the Krusty Krab, reviewing a Wazuh endpoint " +
          "detection alert. Two kinds of activity generate these alerts on this network: (1) this phishing-" +
          "awareness simulation's own scheduled tasks running PowerShell/IMAP/mail activity - expected and " +
          "BENIGN, and (2) an attack-simulation script (ar-test.ps1) that intentionally mimics real malicious " +
          "behavior (credential access, encoded/obfuscated commands, LOLBins, persistence, discovery, etc.) to " +
          "test detections - treat any alert referencing or resembling this as a GENUINE, SUSPICIOUS alert " +
          "requiring triage, exactly as you would a real intrusion. Read the alert and decide which it is. " +
          "Respond with ONLY valid JSON: {`"verdict`": `"BENIGN`" or `"SUSPICIOUS`", `"reasoning`": `"two sentences`"}"
    $up     = "Subject: $AlertSubject`nFrom: $AlertFrom`nBody: $AlertBody"
    $result = Invoke-Claude -SystemPrompt $sp -UserPrompt $up -MaxTokens 200

    $verdict   = "SUSPICIOUS"
    $reasoning = "AI analysis unavailable - treating as suspicious out of caution."
    if ($null -ne $result) {
        try {
            $clean    = $result -replace "(?s)[\x60]{3}json|[\x60]{3}", ""
            $verdictM = [regex]::Match($clean.Trim(), '"verdict"\s*:\s*"([^"]+)"')
            $reasonM  = [regex]::Match($clean.Trim(), '"reasoning"\s*:\s*"([^"]+)"')
            if ($verdictM.Success) { $verdict   = $verdictM.Groups[1].Value }
            if ($reasonM.Success)  { $reasoning = $reasonM.Groups[1].Value }
        } catch {
            $reasoning = "Analysis inconclusive - treating as suspicious out of caution."
        }
    }

    Write-Log "LARRY: Wazuh alert verdict: $verdict | $reasoning" "SECURITY"

    if ($verdict -ne "SUSPICIOUS") {
        Write-Log "LARRY: Wazuh alert assessed as benign. No further action." "SECURITY"
        return
    }

    # SUSPICIOUS - ask Sandy to check potentially compromised endpoints
    $sandyTriageSp = "You are Larry Lobster, Cybersecurity Officer at the Krusty Krab. Write a message to " +
                      "Sandy Cheeks (IT consultant) asking her to check potentially compromised endpoint(s), " +
                      "based on a Wazuh alert that looks genuinely suspicious. Ask her to check for malware, " +
                      "unauthorized access, and persistence mechanisms on the affected workstation(s). " +
                      "In-character as Larry, 3-4 sentences. Plain text only."
    $sandyTriageUp  = "Wazuh alert subject: $AlertSubject. Assessment: $reasoning"
    $sandyTriageMsg = Invoke-Claude -SystemPrompt $sandyTriageSp -UserPrompt $sandyTriageUp -MaxTokens 200

    if ($null -eq $sandyTriageMsg) {
        $sandyTriageMsg = "Sandy, I just got a Wazuh alert that looks genuinely suspicious ($AlertSubject) - can you check the affected endpoint(s) for signs of malware, unauthorized access, or anything else out of place? Let me know what you find. - Larry"
    }
    Send-KKMail -To $ITOfficer -From $UserEmail -Subject "[INVESTIGATION NEEDED] Wazuh Alert - $AlertSubject" -Body $sandyTriageMsg

    # Brief Mr. Krabs on the confirmed-suspicious finding
    $krabsWazuhMsg = "Mr. Krabs, I want to flag that our monitoring system (Wazuh) picked up a genuinely suspicious alert ($AlertSubject) on one of our endpoints. I've asked Sandy to check the affected machine and I'm tracking it closely. I'll update you as soon as we know more. - Larry"
    Send-KKMail -To "eugene.krabs@$Domain" -From $UserEmail -Subject "[SECURITY NOTICE] Wazuh Alert Under Investigation" -Body $krabsWazuhMsg

    Write-Log "LARRY: Wazuh alert triage complete - Sandy tasked, Mr. Krabs briefed." "SECURITY"
}

# =====================================================================
# SANDY: HANDLE PHISHING REPORT - escalate to Larry, advise user, deliver training
# =====================================================================

function Invoke-SandyEscalation {
    param(
        [string]$ReportFrom,
        [string]$ReportSubject,
        [string]$ReportBody
    )

    Write-Log "SANDY: Received phishing report from $ReportFrom. Escalating to Larry." "SECURITY"

    # Parse original sender, subject, and verified-sender from the report body
    # NOTE: use [ \t]* rather than \s* after the field name - \s matches
    # newlines too, so a greedy \s* on a blank field (Verified-Sender is
    # routinely blank for external senders) will skip straight past the
    # blank-line paragraph separator and capture text from the NEXT line
    # instead of an empty value. [ \t]* stays confined to the current line.
    $originalFrom     = ""
    $originalSubject  = ""
    $originalVerified = ""

    if ($ReportBody -match "(?m)^From:[ \t]*(.+)$") {
        $originalFrom = $Matches[1].Trim()
    }
    if ($ReportBody -match "(?m)^Subject:[ \t]*(.+)$") {
        $originalSubject = $Matches[1].Trim()
    }
    if ($ReportBody -match "(?m)^Verified-Sender:[ \t]*(.*)$") {
        $originalVerified = $Matches[1].Trim()
    }
    if (-not $originalFrom) { $originalFrom = $ReportFrom }
    if (-not $originalSubject) { $originalSubject = $ReportSubject }

    # Look up reporter name
    $reporterKey  = ($ReportFrom -split "@")[0].ToLower()
    $reporterName = if ($EmployeeMap.ContainsKey($reporterKey)) { $EmployeeMap[$reporterKey].name } else { $ReportFrom }

    # Forward to Larry for investigation
    $larryReport = "Larry," + [System.Environment]::NewLine + [System.Environment]::NewLine +
        "$reporterName has reported a suspicious email. Details below:" + [System.Environment]::NewLine + [System.Environment]::NewLine +
        "Reporter: $reporterName ($ReportFrom)" + [System.Environment]::NewLine +
        "Reported From: $originalFrom" + [System.Environment]::NewLine +
        "Reported Subject: $originalSubject" + [System.Environment]::NewLine +
        "Reported Verified-Sender: $originalVerified" + [System.Environment]::NewLine + [System.Environment]::NewLine +
        "Original report:" + [System.Environment]::NewLine +
        $ReportBody + [System.Environment]::NewLine + [System.Environment]::NewLine +
        "Please investigate and advise. I will follow up with the reporter once I hear from you." + [System.Environment]::NewLine + [System.Environment]::NewLine +
        "- Sandy Cheeks, IT"

    Send-KKMail -To $CyberSecOfficer -From $UserEmail -Subject "[PHISHING REPORT] $originalSubject" -Body $larryReport

    # Sandy advises the user
    $sandySp = "You are Sandy Cheeks, IT and Science Consultant at the Krusty Krab. " +
               "A staff member just reported a suspicious email to you. Write a brief, professional, " +
               "in-character response acknowledging the report, thanking them for their vigilance, and " +
               "advising them not to click any links or reply to the suspicious email. " +
               "Mention that you have escalated to Larry for investigation. " +
               "Keep it 3-5 sentences. Plain text only. In-character as Sandy from SpongeBob."
    $sandyUp  = "Staff member $reporterName reported a suspicious email from $originalFrom with subject: $originalSubject"
    $sandyMsg = Invoke-Claude -SystemPrompt $sandySp -UserPrompt $sandyUp -MaxTokens 200

    if ($null -eq $sandyMsg) {
        $sandyMsg = "Hi $reporterName, thanks for reporting that suspicious email. Good job staying vigilant! " +
                    "I've flagged it for Larry to investigate. In the meantime, please don't click any links or reply to it. " +
                    "I'll follow up once Larry has had a chance to look into it. - Sandy"
    }

    Send-KKMail -To $ReportFrom -From $UserEmail -Subject "Re: [PHISHING REPORT] $originalSubject" -Body $sandyMsg
}

# =====================================================================
# TRAINING EMAIL HANDLER
# Sandy sends training emails; receiving one may improve competence
# =====================================================================

function Process-TrainingEmail {
    param([string]$Subject, [string]$Body, [double]$CurrentScore)

    # ----------------------------------------------------------------
    # DEDUPLICATION: hash the email body to detect resends
    # A resend of the same training email provides no additional benefit
    # ----------------------------------------------------------------
    $bodyBytes  = [System.Text.Encoding]::UTF8.GetBytes($Body.Trim())
    $sha        = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes  = $sha.ComputeHash($bodyBytes)
    $emailHash  = [BitConverter]::ToString($hashBytes) -replace '-', ''
    $sha.Dispose()

    $meta = Load-TrainingMeta
    if ($meta.seenHashes -contains $emailHash) {
        Write-Log "TRAINING: Duplicate training email detected (hash=$($emailHash.Substring(0,8))...). No competence boost applied." "TRAINING"
        return $CurrentScore
    }

    Write-Log "TRAINING: New training email (hash=$($emailHash.Substring(0,8))...). Evaluating quality." "TRAINING"

    # ----------------------------------------------------------------
    # CAP CHECK: training boosts are capped at +40% above default score
    # Each additional email has diminishing returns as the cap approaches
    # ----------------------------------------------------------------
    $maxBoost      = 0.40
    $remainingCap  = [Math]::Max(0.0, $maxBoost - $meta.boostTotal)

    if ($remainingCap -le 0.001) {
        Write-Log "TRAINING: Training boost cap reached (boostTotal=$($meta.boostTotal), max=$maxBoost). Recording email but no boost applied." "TRAINING"
        # Still record the hash so resends are tracked
        $newHashes = @($meta.seenHashes) + @($emailHash)
        Save-Competence -Score $CurrentScore -BoostTotal $meta.boostTotal -SeenHashes $newHashes
        return $CurrentScore
    }

    # ----------------------------------------------------------------
    # AI QUALITY EVALUATION
    # ----------------------------------------------------------------
    $sp = "You are evaluating the quality of a phishing awareness training email sent to a Krusty Krab employee. " +
          "Rate the training email's effectiveness on a scale from 0.0 to 1.0, where: " +
          "0.0-0.3 = poor quality, confusing, or unlikely to improve awareness; " +
          "0.3-0.7 = moderate quality, covers basics but not memorable; " +
          "0.7-1.0 = excellent quality, clear examples, memorable, likely to improve phishing detection. " +
          "Respond with ONLY a JSON object: {`"quality`": 0.0-1.0, `"reasoning`": `"one sentence`"}"

    $up     = "Subject: $Subject`nBody: $Body"
    $result = Invoke-Claude -SystemPrompt $sp -UserPrompt $up -MaxTokens 150

    $qualityScore = 0.5
    if ($null -ne $result) {
        try {
            $clean    = $result -replace "(?s)[\x60]{3}json|[\x60]{3}", ""
            $qualityM = [regex]::Match($clean.Trim(), '"quality"\s*:\s*([\d.]+)')
            if ($qualityM.Success) { $qualityScore = [double]$qualityM.Groups[1].Value }
        } catch { }
    }

    # ----------------------------------------------------------------
    # DIMINISHING RETURNS: each training email is worth less as the
    # boost total grows. The base boost scales down proportionally to
    # how close we are to the cap.
    # Formula: boost = quality * 0.05 * (1 - boostTotal/maxBoost)
    # This means the first email gives full boost, later ones give less
    # ----------------------------------------------------------------
    $diminishingFactor = 1.0 - ($meta.boostTotal / $maxBoost)
    $rawImprovement    = $qualityScore * 0.05 * $diminishingFactor
    $improvement       = [Math]::Round([Math]::Min($rawImprovement, $remainingCap), 4)
    $newScore          = [Math]::Round([Math]::Min(1.0, $CurrentScore + $improvement), 3)
    $newBoostTotal     = [Math]::Round($meta.boostTotal + $improvement, 4)
    $newHashes         = @($meta.seenHashes) + @($emailHash)

    Write-Log "TRAINING: Quality=$qualityScore DiminishFactor=$([Math]::Round($diminishingFactor,3)) Improvement=+$improvement BoostTotal=$newBoostTotal/$maxBoost New competence=$newScore" "TRAINING"

    Save-Competence -Score $newScore -BoostTotal $newBoostTotal -SeenHashes $newHashes
    return $newScore
}

# =====================================================================
# WORK EMAIL SENDER
# =====================================================================

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
        $clean        = $result -replace "(?s)[\x60]{3}json|[\x60]{3}", ""
        $clean        = $clean.Trim()
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

function Simulate-ReportPhishing {
    param([string]$OriginalFrom, [string]$OriginalSubject, [string]$OriginalBody, [string]$OriginalVerifiedSender = "")
    Write-Log "ACTION: REPORT - $($Employee.name) reports phishing email to Sandy." "DETECT"
    # Verified-Sender is carried as its own tagged field (mirroring From:/Subject:)
    # rather than folded into the freeform body, so it survives the regex
    # re-parse at each hop of the escalation chain intact. It is sourced
    # directly from the original message's raw X-KK-Sender header (fetched
    # via IMAP in the main loop), never retyped or inferred - it is blank
    # whenever the original message carried no such header at all.
    $reportBody = "Hi Sandy," + [System.Environment]::NewLine + [System.Environment]::NewLine +
                  "I received a suspicious email and wanted to report it." + [System.Environment]::NewLine + [System.Environment]::NewLine +
                  "From: $OriginalFrom" + [System.Environment]::NewLine +
                  "Subject: $OriginalSubject" + [System.Environment]::NewLine +
                  "Verified-Sender: $OriginalVerifiedSender" + [System.Environment]::NewLine + [System.Environment]::NewLine +
                  "Body:" + [System.Environment]::NewLine +
                  $OriginalBody + [System.Environment]::NewLine + [System.Environment]::NewLine +
                  "It seemed suspicious to me. Thought you should know." + [System.Environment]::NewLine + [System.Environment]::NewLine +
                  "- $($Employee.firstName)"
    Send-KKMail -To $ITOfficer -From $UserEmail -Subject "[PHISHING REPORT] $OriginalSubject" -Body $reportBody
}

# =====================================================================
# AI DECISION: SUBJECT-LEVEL
# =====================================================================

function Get-SubjectAction {
    param([string]$Subject, [string]$From, [double]$Competence, [string]$VerifiedSender = "")

    $desc       = Get-CompetenceDescription -Score $Competence
    $vulns      = $Employee.vulnerabilities -join ", "
    $profileCtx = if ($CharacterProfile) { "Character background: $CharacterProfile" } else { "" }
    $detectPct  = [int]($Competence * 100)

    # Extract a bare address from From (which may carry a display name, e.g.
    # '"Mr. Krabs" <eugene.krabs@chum-bucket.com>') to compare against
    # VerifiedSender (always a bare address from X-KK-Sender).
    $fromAddr      = if ($From -match "<(.+@.+)>") { $Matches[1].Trim() } else { $From.Trim() }
    $isInternalAddr = $fromAddr -match "@$([regex]::Escape($Domain))$"
    $senderVerified = $isInternalAddr -and $VerifiedSender -and ($VerifiedSender.Trim().ToLower() -eq $fromAddr.ToLower())
    $verifyFact = if (-not $isInternalAddr) { "" }
                  elseif ($senderVerified) { "Sender verification: this internal address IS verified as genuine (X-KK-Sender confirms it)." }
                  else { "Sender verification: this address LOOKS internal, but is NOT verified - no confirmed match. Treat this the same as any unverified/suspicious sender, even if the subject sounds like a normal work topic; an internal-looking but unverified sender is a red flag consistent with address spoofing, not a reason for automatic trust." }

    # Security characters get different prompt - they process reports not just phishing
    if ($IsSecurity -or $IsCyberSec) {
        $sp = "You are simulating the email behavior of $($Employee.name), $($Employee.role) at the Krusty Krab. " +
              "As a security professional, you handle both regular email and incoming phishing reports from staff. " +
              "As IT/cybersecurity staff, you know how to check whether a sender's identity is actually verified rather than just trusting an internal-looking address at face value. " +
              "$profileCtx " +
              "Decide what to do with this email based on its subject and sender. " +
              "KEEP = routine legitimate internal email from a colleague - keep in inbox. " +
              "READ = needs to be read in full before deciding. " +
              "DELETE = obvious spam with no security significance. " +
              "CRITICAL RULE: If the subject contains '[PHISHING REPORT]' you MUST return READ to process the report. " +
              "CRITICAL RULE: If the sender's identity is verified (see sender verification note) and the subject is a normal work topic, return KEEP or READ. If the sender is internal-looking but NOT verified, do not automatically trust it - evaluate it with real scrutiny, likely READ rather than KEEP. " +
              "CRITICAL RULE: Do NOT return REPORT - security staff handle reports, they do not forward them. " +
              "Respond with ONLY one token: KEEP | READ | DELETE."
    } else {
        $sp = "You are simulating the email behavior of $($Employee.name), $($Employee.role) at the Krusty Krab. " +
              "Their phishing awareness competence score is $Competence (range 0.0-1.0, mood-adjusted for this run). " +
              "They are: $desc. " +
              "$profileCtx " +
              "Their specific vulnerabilities (topics that lower their guard): $vulns. " +
              "If the email subject relates to their vulnerabilities, they are significantly more likely to fall for it. " +
              "IMPORTANT: At competence $Competence, this character correctly identifies phishing approximately $detectPct% of the time. " +
              "For phishing emails they should fall for it roughly $([int](100 - $detectPct))% of the time. " +
              "Decide how they react upon seeing only the subject and sender. " +
              "KEEP = routine legitimate internal email from a known colleague - no action needed. " +
              "READ = email looks potentially interesting or slightly suspicious - read in full before deciding. " +
              "DELETE = correctly identified as phishing at subject stage and deleted. " +
              "REPORT = recognized as suspicious and forwarded to Sandy (IT) for review. " +
              "CLICK_LINK / RUN_ATTACHMENT / REPLY_COMPLY = fell for the phishing attempt. " +
              "CRITICAL RULE: If the sender is an internal @$Domain address and the subject is a normal work topic, this character - unlike IT/security staff - has no way to verify sender identity and generally leans toward KEEP or READ. But this leaning should scale with competence like everything else: a well-trained character can still feel a flicker of doubt about an internal-looking sender if something about the message is off, and should occasionally return DELETE or REPORT even for an internal-looking address at higher competence. A low-competence character should give internal-looking senders an almost automatic pass. " +
              "CRITICAL RULE: Do NOT return DELETE or REPORT more than $detectPct% of the time for phishing emails - this character is not that aware. " +
              "CRITICAL RULE: When you do catch it, also weigh DELETE vs REPORT by competence, not just detection. Security staff (IT, cybersecurity) run around 0.80-0.85, so for a regular employee a competence of 0.5-0.6 is already comparatively high. At low-to-moderate competence, correctly catching a phishing email should mostly mean DELETE without thinking to escalate; REPORT should become more likely only as competence approaches or exceeds that 0.5-0.6 range, and be common only near security-staff levels. " +
              "Respond with ONLY one token: KEEP | READ | DELETE | REPORT | CLICK_LINK | RUN_ATTACHMENT | REPLY_COMPLY."
    }

    $up = "Subject: $Subject  From: $From" + $(if ($verifyFact) { "  $verifyFact" } else { "" })

    $result = Invoke-Claude -SystemPrompt $sp -UserPrompt $up -MaxTokens 20

    if ($null -eq $result) {
        $roll = Get-Random -Minimum 0 -Maximum 100
        if ($IsSecurity -or $IsCyberSec) { return "READ" }
        if ($roll -lt $detectPct -and $Competence -gt 0.7) { return "DELETE" }
        elseif ($roll -lt 40) { return "READ" }
        else { return "CLICK_LINK" }
    }

    $clean = $result.Trim().ToUpper() -replace "[^A-Z_]", ""

    if ($IsSecurity -or $IsCyberSec) {
        $valid = @("KEEP","READ","DELETE")
        if ($valid -contains $clean) { return $clean }
        return "READ"
    } else {
        $valid = @("KEEP","READ","DELETE","REPORT","CLICK_LINK","RUN_ATTACHMENT","REPLY_COMPLY")
        if ($valid -contains $clean) { return $clean }
        return "READ"
    }
}

# =====================================================================
# AI DECISION: BODY-LEVEL
# =====================================================================

function Get-BodyAction {
    param([string]$Subject, [string]$From, [string]$Body, [double]$Competence, [string]$VerifiedSender = "")

    $desc       = Get-CompetenceDescription -Score $Competence
    $vulns      = $Employee.vulnerabilities -join ", "
    $profileCtx = if ($CharacterProfile) { "Character background: $CharacterProfile" } else { "" }
    $detectPct  = [int]($Competence * 100)

    # Same verification check as Get-SubjectAction - see notes there. This is
    # the stage that actually mattered in the confirmed incident: the
    # spoofed-Larry-to-Sandy attack was let through at BODY stage (subject
    # stage returned READ, body stage returned KEEP), so this prompt is at
    # least as important to fix as the subject-stage one.
    $fromAddr      = if ($From -match "<(.+@.+)>") { $Matches[1].Trim() } else { $From.Trim() }
    $isInternalAddr = $fromAddr -match "@$([regex]::Escape($Domain))$"
    $senderVerified = $isInternalAddr -and $VerifiedSender -and ($VerifiedSender.Trim().ToLower() -eq $fromAddr.ToLower())
    $verifyFact = if (-not $isInternalAddr) { "" }
                  elseif ($senderVerified) { "Sender verification: this internal address IS verified as genuine (X-KK-Sender confirms it)." }
                  else { "Sender verification: this address LOOKS internal, but is NOT verified - no confirmed match. This is a red flag consistent with address spoofing regardless of how plausible the sender name or subject looks; do not treat it as automatically trustworthy just because it appears to come from a colleague." }

    if ($IsCyberSec) {
        # Larry is the cybersecurity officer - he NEVER reports to Sandy, he investigates himself
        # He only KEEPs legitimate emails or DELETEs obvious spam
        # [PHISHING REPORT] emails are intercepted before this function is ever called
        $sp = "You are simulating the email behavior of $($Employee.name), $($Employee.role) at the Krusty Krab. " +
              "You are the head of cybersecurity. You NEVER forward emails to anyone for review - you ARE the reviewer. " +
              "As cybersecurity staff, you know how to check whether a sender's identity is actually verified rather than just trusting an internal-looking address at face value - factor the sender verification note below into your decision. " +
              "$profileCtx " +
              "Decide the final action after reading the full email. " +
              "KEEP = legitimate internal work email - keep it. " +
              "DELETE = spam, obvious phishing, or irrelevant email - delete it. " +
              "CRITICAL RULE: An internal-looking sender that is NOT verified (see sender verification note) should be treated with real scrutiny, not automatically KEPT, even if the subject and body look like plausible internal business. " +
              "CRITICAL RULE: Do NOT return REPORT under any circumstances. Larry does not report to Sandy. " +
              "CRITICAL RULE: Do NOT return CLICK_LINK, RUN_ATTACHMENT, or REPLY_COMPLY unless the email " +
              "specifically exploits Larry's vulnerabilities (fitness, bodybuilding, gym, protein, muscles, competition). " +
              "Respond with ONLY one token: KEEP | DELETE | CLICK_LINK | RUN_ATTACHMENT | REPLY_COMPLY."
    } elseif ($IsSecurity) {
        # Sandy is IT - she can forward suspicious emails to Larry via REPORT
        $sp = "You are simulating the email behavior of $($Employee.name), $($Employee.role) at the Krusty Krab. " +
              "As the IT consultant you handle incoming phishing reports from staff and forward them to Larry. " +
              "As IT staff, you know how to check whether a sender's identity is actually verified rather than just trusting an internal-looking address at face value - factor the sender verification note below into your decision. " +
              "$profileCtx " +
              "Decide the final action after reading the full email. " +
              "KEEP = legitimate internal work email - no action needed. " +
              "DELETE = spam with no security significance. " +
              "REPORT = suspicious email that should be forwarded to Larry Lobster (cybersecurity) for investigation. " +
              "CLICK_LINK / RUN_ATTACHMENT / REPLY_COMPLY = fell for the phishing (rare for Sandy). " +
              "CRITICAL RULE: An internal-looking sender that is NOT verified (see sender verification note) should be treated with real scrutiny, not automatically KEPT, even if it claims to be from a colleague or fellow security staff and the subject sounds like normal business - lean toward REPORT rather than KEEP in that case. " +
              "CRITICAL RULE: If the subject contains '[PHISHING REPORT]' return REPORT so Larry investigates. " +
              "CRITICAL RULE: Do NOT return REPORT unless this is genuinely suspicious or a staff phishing report. " +
              "Respond with ONLY one token: KEEP | DELETE | REPORT | CLICK_LINK | RUN_ATTACHMENT | REPLY_COMPLY."
    } else {
        $sp = "You are simulating the email behavior of $($Employee.name), $($Employee.role) at the Krusty Krab. " +
              "Their phishing awareness competence score is $Competence (range 0.0-1.0, mood-adjusted). " +
              "They are: $desc. " +
              "$profileCtx " +
              "Their specific vulnerabilities: $vulns. " +
              "If the email body exploits their vulnerabilities, they are significantly more likely to comply even at higher competence. " +
              "IMPORTANT: At competence $Competence, this character correctly identifies phishing approximately $detectPct% of the time. " +
              "The employee has read the full email. Decide their final action. " +
              "KEEP = correctly identified as legitimate internal work email - no action needed. " +
              "DELETE = correctly identified as phishing after reading body. " +
              "REPORT = recognized as suspicious and forwarded to Sandy (IT) for review. " +
              "CLICK_LINK / RUN_ATTACHMENT / REPLY_COMPLY = fell for the phishing attempt. " +
              "CRITICAL RULE: If the email is clearly a routine internal Krusty Krab work email from a known colleague, return KEEP. " +
              "CRITICAL RULE: Do NOT return DELETE or REPORT more than $detectPct% of the time for phishing emails. " +
              "CRITICAL RULE: When you do catch it, also weigh DELETE vs REPORT by competence, not just detection. Security staff (IT, cybersecurity) run around 0.80-0.85, so for a regular employee a competence of 0.5-0.6 is already comparatively high. At low-to-moderate competence, correctly catching a phishing email should mostly mean DELETE without thinking to escalate; REPORT should become more likely only as competence approaches or exceeds that 0.5-0.6 range, and be common only near security-staff levels. " +
              "Respond with ONLY one token: KEEP | DELETE | REPORT | CLICK_LINK | RUN_ATTACHMENT | REPLY_COMPLY."
    }

    $up = "Subject: $Subject  From: $From  Body: $Body" + $(if ($verifyFact) { "  $verifyFact" } else { "" })

    $result = Invoke-Claude -SystemPrompt $sp -UserPrompt $up -MaxTokens 20

    if ($null -eq $result) {
        if ($IsCyberSec) { return "KEEP" }
        if ($IsSecurity) { return "KEEP" }
        $roll = Get-Random -Minimum 0 -Maximum 100
        if ($roll -lt $detectPct) { return "DELETE" }
        else { return "CLICK_LINK" }
    }

    $clean = $result.Trim().ToUpper() -replace "[^A-Z_]", ""

    if ($IsCyberSec) {
        # Larry NEVER reports - if AI somehow returns REPORT, convert to KEEP
        if ($clean -eq "REPORT") {
            Write-Log "Larry returned REPORT at body stage - converting to KEEP. Larry does not report to Sandy." "WARN"
            return "KEEP"
        }
        $valid = @("KEEP","DELETE","CLICK_LINK","RUN_ATTACHMENT","REPLY_COMPLY")
        if ($valid -contains $clean) { return $clean }
        return "KEEP"
    } elseif ($IsSecurity) {
        $valid = @("KEEP","DELETE","REPORT","CLICK_LINK","RUN_ATTACHMENT","REPLY_COMPLY")
        if ($valid -contains $clean) { return $clean }
        return "KEEP"
    } else {
        $valid = @("KEEP","DELETE","REPORT","CLICK_LINK","RUN_ATTACHMENT","REPLY_COMPLY")
        if ($valid -contains $clean) { return $clean }
        return "DELETE"
    }
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

# Non-security characters send work emails; security characters focus on inbox
if (-not $IsSecurity -and -not $IsCyberSec) {
    Send-WorkEmail
}

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
    $finalMeta = Load-TrainingMeta
    Save-Competence -Score $CompetenceScore -BoostTotal $finalMeta.boostTotal -SeenHashes $finalMeta.seenHashes
    (Get-Date -Format "o") | Out-File -FilePath $StateFile -Force
    exit 0
}

$updatedCompetence = $CompetenceScore

foreach ($seqNum in $msgNums) {
    $hdrs      = Get-IMAPMessageHeaders -SeqNum $seqNum
    $subject   = $hdrs.Subject
    $from      = $hdrs.From
    $xkkSender = $hdrs.XKKSender

    Write-Log "--- Message $seqNum | From: $from | Subject: $subject ---"

    # Sandy: handle incoming phishing reports directly
    if ($IsIT -and $subject -match "\[PHISHING REPORT\]") {
        Write-Log "SANDY: Detected incoming phishing report. Processing escalation chain." "SECURITY"
        $body = Get-IMAPMessageBody -SeqNum $seqNum
        Invoke-SandyEscalation -ReportFrom $from -ReportSubject $subject -ReportBody $body
        Move-IMAPMessage -SeqNum $seqNum -DestFolder $IMAPDeletedFolder | Out-Null
        continue
    }

    # Sandy: Larry's internal investigation correspondence is operational
    # traffic, not a simulated phishing email - keep for records without
    # running it through the phishing-decision AI.
    if ($IsIT -and $subject -match "\[INVESTIGATION (COMPLETE|NEEDED)\]") {
        Write-Log "SANDY: Received Larry's investigation correspondence. Keeping for records." "SECURITY"
        continue
    }

    # Larry: real Wazuh alert - confirm whether it's genuinely
    # suspicious/malicious or benign scheduled-task noise, BEFORE AI
    # decision logic (a raw Wazuh alert subject would otherwise be scored
    # like any other simulated phishing email)
    #
    # Gated on sender address alone, NOT subject: real Wazuh mail arrives in
    # two different subject formats depending on alert type - leveled alerts
    # use "Wazuh notification - ...", while active-response alerts carry no
    # subject at all. Sender address is the only field both types reliably
    # share, so it's the only field this gate can safely require.
    if ($IsCyberSec -and $from -match [regex]::Escape($WazuhManagerEmail)) {
        Write-Log "LARRY: Detected Wazuh notification. Triaging." "SECURITY"
        $body = Get-IMAPMessageBody -SeqNum $seqNum
        Invoke-LarryWazuhTriage -AlertSubject $subject -AlertBody $body -AlertFrom $from
        Move-IMAPMessage -SeqNum $seqNum -DestFolder $IMAPDeletedFolder | Out-Null
        continue
    }

    # All characters: check for training emails
    if ($subject -match [regex]::Escape($TrainingSubject)) {
        Write-Log "TRAINING: Detected training email from Sandy." "TRAINING"
        $body              = Get-IMAPMessageBody -SeqNum $seqNum
        $updatedCompetence = Process-TrainingEmail -Subject $subject -Body $body -CurrentScore $updatedCompetence
        Move-IMAPMessage -SeqNum $seqNum -DestFolder $IMAPDeletedFolder | Out-Null
        continue
    }

    # Larry: intercept [PHISHING REPORT] emails from Sandy BEFORE AI decision logic
    # Without this, Larry's AI sees a suspicious-looking subject and treats Sandy's
    # escalation email as a potential threat, sending Sandy an alert about her own email
    if ($IsCyberSec -and $subject -match "\[PHISHING REPORT\]") {
        Write-Log "LARRY: Detected phishing report from Sandy. Triggering investigation." "SECURITY"
        $body = Get-IMAPMessageBody -SeqNum $seqNum
        # Parse original sender and subject from Sandy's report body
        # Use flexible matching to handle CRLF, MIME artifacts, and whitespace variations
        # NOTE: [ \t]* (not \s*) after each field name - \s matches newlines
        # too, so a greedy \s* on a blank field (Verified-Sender is routinely
        # blank for external senders) skips past the blank-line paragraph
        # separator and captures text from the NEXT line instead of an empty
        # value. This is what produced a garbage "X-KK-Sender: Original
        # report:" reading during testing - confirmed via test harness run.
        $bodyClean       = $body -replace '\r', ''
        $originalFrom    = if ($bodyClean -match "(?m)^Reported From:[ \t]*(.+)$")    { $Matches[1].Trim() -replace '=0D$', '' } else { $null }
        $originalSubject = if ($bodyClean -match "(?m)^Reported Subject:[ \t]*(.+)$") { $Matches[1].Trim() -replace '=0D$', '' } else { $null }
        $reporterEmail   = if ($bodyClean -match "(?m)^Reporter:.*\((.+@.+)\)")    { $Matches[1].Trim() } else { $ITOfficer }
        $reporterName    = if ($bodyClean -match "(?m)^Reporter:[ \t]*([^(\r\n]+)")   { $Matches[1].Trim() } else { "Sandy Cheeks" }
        $verifiedSender  = if ($bodyClean -match "(?m)^Reported Verified-Sender:[ \t]*(.*)$") { $Matches[1].Trim() -replace '=0D$', '' } else { "" }

        # Safety check - if we couldn't parse the original sender, log and skip
        # rather than investigating Sandy herself as the phishing sender
        if ([string]::IsNullOrWhiteSpace($originalFrom)) {
            Write-Log "LARRY: Could not parse original sender from Sandy's report body - skipping investigation to avoid false positive against Sandy." "WARN"
            Move-IMAPMessage -SeqNum $seqNum -DestFolder $IMAPDeletedFolder | Out-Null
            continue
        }

        Invoke-LarryInvestigation -SenderAddress $originalFrom -OriginalSubject $originalSubject -OriginalBody $body -VictimEmail $reporterEmail -VictimName $reporterName -VerifiedSender $verifiedSender
        Move-IMAPMessage -SeqNum $seqNum -DestFolder $IMAPDeletedFolder | Out-Null
        continue
    }

    # Larry: keep completed investigation reports for records without AI processing
    if ($IsCyberSec -and $subject -match "\[INVESTIGATION COMPLETE\]") {
        Write-Log "LARRY: Received investigation complete report. Keeping for records." "SECURITY"
        continue
    }

    $action = Get-SubjectAction -Subject $subject -From $from -Competence $MoodScore -VerifiedSender $xkkSender
    Write-Log "Subject decision: $action"

    switch ($action) {
        "KEEP" {
            Write-Log "OUTCOME: Decision - kept in inbox at subject stage." "DETECT"
        }
        "DELETE" {
            Write-Log "OUTCOME: Decision - deleted at subject stage." "DETECT"
            Move-IMAPMessage -SeqNum $seqNum -DestFolder $IMAPDeletedFolder | Out-Null
        }
        "REPORT" {
            Write-Log "OUTCOME: Reported to Sandy at subject stage." "DETECT"
            $body = Get-IMAPMessageBody -SeqNum $seqNum
            Simulate-ReportPhishing -OriginalFrom $from -OriginalSubject $subject -OriginalBody $body -OriginalVerifiedSender $xkkSender
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

            # Sandy: check again for phishing report after reading body
            if ($IsIT -and $subject -match "\[PHISHING REPORT\]") {
                Write-Log "SANDY: Processing phishing report after body read." "SECURITY"
                Invoke-SandyEscalation -ReportFrom $from -ReportSubject $subject -ReportBody $body
                Move-IMAPMessage -SeqNum $seqNum -DestFolder $IMAPDeletedFolder | Out-Null
                continue
            }

            $bodyAction = Get-BodyAction -Subject $subject -From $from -Body $body -Competence $MoodScore -VerifiedSender $xkkSender
            Write-Log "Body decision: $bodyAction"

            switch ($bodyAction) {
                "DELETE" {
                    Write-Log "OUTCOME: Decision - deleted after reading body." "DETECT"
                    Move-IMAPMessage -SeqNum $seqNum -DestFolder $IMAPDeletedFolder | Out-Null
                }
                "REPORT" {
                    # No $IsIT branching here, matching the subject-stage
                    # REPORT case above: by this point in the loop, a
                    # genuinely tagged [PHISHING REPORT] forward has already
                    # been handled and continue'd out at the check above
                    # ("Sandy: check again for phishing report after reading
                    # body"). Reaching this case means Sandy/Larry, like
                    # anyone else, is looking at a RAW original email and
                    # deciding to report it - not relaying someone else's
                    # report. Routing that through Invoke-SandyEscalation
                    # (which parses "Reported From:"/"Reported Subject:" out
                    # of an already-tagged body) mislabeled the phishing
                    # sender as the "Reporter" and could send an
                    # acknowledgment reply straight back to the attacker's
                    # address. Send a properly-tagged report instead, same as
                    # any employee; it will be correctly picked up and
                    # escalated to Larry on the next run via the tagged-
                    # subject check above.
                    Write-Log "OUTCOME: Reported to Sandy after reading body." "DETECT"
                    Simulate-ReportPhishing -OriginalFrom $from -OriginalSubject $subject -OriginalBody $body -OriginalVerifiedSender $xkkSender
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
                    Write-Log "OUTCOME: Decision - kept in inbox after reading body." "DETECT"
                }
                default {
                    Write-Log "OUTCOME: No action taken." "INFO"
                }
            }
        }
    }
}

Disconnect-IMAP

# Reload training meta in case Process-TrainingEmail already saved an update this run
# Only save here if no training emails were processed (Process-TrainingEmail saves its own)
$finalMeta = Load-TrainingMeta
Save-Competence -Score $updatedCompetence -BoostTotal $finalMeta.boostTotal -SeenHashes $finalMeta.seenHashes
(Get-Date -Format "o") | Out-File -FilePath $StateFile -Force

Write-Log "===== Simulation complete. Final competence: $updatedCompetence ====="
exit 0
