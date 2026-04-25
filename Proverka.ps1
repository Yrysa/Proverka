[CmdletBinding()]
param(
    [switch]$SelfTest,
    [switch]$Fast,
    [switch]$Deep,
    [switch]$FullSystem,
    [switch]$AllDrives,
    [switch]$OnlyMinecraft,
    [switch]$Forensic,
    [switch]$NoDeletedTraces,
    [switch]$NoPrompt,
    [switch]$OpenReport,
    [switch]$ShowIgnored,
    [switch]$Drivers,
    [switch]$VMCheck,
    [switch]$HuntSystem32,
    [switch]$StrictEvidence,
    [switch]$Amsi,
    [switch]$Yara,
    [string]$YaraExe = "yara64.exe",
    [string]$YaraRules = "",
    [switch]$VirusTotal,
    [string]$VirusTotalApiKey = "",
    [int]$VirusTotalMax = 20,
    [string]$Cheat = "",
    [int]$MaxMinutes = 25,
    [int]$MaxCandidates = 4500,
    [int]$MaxDeepBytes = 524288,
    [int]$Top = 80,
    [int]$MinScore = 20,
    [int]$TraceMinScore = 35,
    [switch]$EvidenceUI,
    [switch]$TraceTimeline,
    [switch]$EntropyScan,
    [switch]$NoHeavyForensics,
    [switch]$NoUSNJournal,
    [switch]$NoDNSCache,
    [switch]$NoNamedPipes,
    [switch]$NoBehaviorChains,
    [int]$USNMaxLines = 1600,
    [int]$ExternalTimeoutSec = 7,
    [switch]$HWIDForensics,
    [switch]$USBForensics,
    [switch]$WMIForensics,
    [switch]$BrowserForensics,
    [switch]$DiscordForensics,
    [switch]$InputMacroScan,
    [switch]$NoHWIDSpoofing,
    [switch]$NoUSBForensics,
    [switch]$NoWMIForensics,
    [switch]$NoBrowserForensics,
    [switch]$NoDiscordForensics,
    [switch]$NoInputMacroScan,
    [switch]$NoKDMapperTrace,
    [switch]$CompactUI,
    [switch]$NoColor,
    [switch]$NoProgress,
    [int]$UiWidth = 100
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Continue"
$script:Version = "15.0.0"
$script:StartTime = Get-Date
$script:Deadline = $script:StartTime.AddMinutes([Math]::Max(2,$MaxMinutes))
$script:TempRoot = Join-Path $env:TEMP ("YRYS_CHECKER_" + ([Guid]::NewGuid().ToString("N")))
$script:UiWidth = [Math]::Max(78, [Math]::Min(130, $UiWidth))
$script:UiNoColor = [bool]$NoColor
$script:UiCompact = [bool]$CompactUI
$script:UiNoProgress = [bool]$NoProgress
$script:UiPhaseIndex = 0
$script:UiPhaseTotal = 18
$script:UiPhaseStarted = Get-Date
$script:UiLastStatus = "init"
$script:IsElevated = $false
$script:AdminMethod = "not_checked"
$script:AdminChecks = ""
$script:Findings = New-Object System.Collections.Generic.List[object]
$script:Ignored = New-Object System.Collections.Generic.List[object]
$script:CandidatesSeen = 0
$script:FilesAnalyzed = 0
$script:DeletedTraceCount = 0
$script:TrustedIgnoredCount = 0
$script:BlockedErrors = 0
$script:SystemAnomaliesChecked = 0
$script:ScheduledTaskCount = 0
$script:DynamicRootsCount = 0
$script:WeakSuppressedCount = 0
$script:BelowThresholdSuppressedCount = 0
$script:TraceTimelineCount = 0
$script:USNTraceCount = 0
$script:DNSCacheCount = 0
$script:BitsJobCount = 0
$script:FirewallRuleCount = 0
$script:NamedPipeCount = 0
$script:JavaAttachCount = 0
$script:LwjglCheckedCount = 0
$script:CompatTraceCount = 0
$script:BehaviorChainCount = 0
$script:EntropyCheckedCount = 0
$script:TimestompCheckedCount = 0
$script:ExternalToolTimeouts = 0
$script:HWIDAnomalyCount = 0
$script:USBTraceCount = 0
$script:WMIPersistenceCount = 0
$script:BrowserTraceCount = 0
$script:DiscordTraceCount = 0
$script:MacroProfileCount = 0
$script:KDMapperTraceCount = 0
$script:V13BehaviorChainCount = 0
$script:HashCache = @{}
$script:SignatureCache = @{}
$script:TokenRegexCache = @{}
$script:UserCheatTokens = @()
$script:CriticalCheatTokens = @()
$script:TrustedVendorTokens = @(
    "microsoft", "windows", "nvidia", "amd", "intel", "oracle", "adoptium", "eclipse adoptium", "mojang", "minecraft", "lunar client", "badlion", "feather", "modrinth", "curseforge", "overwolf", "steam", "discord", "google", "mozilla", "valve", "epic games", "java", "openjdk", "jetbrains", "github", "visual studio", "vmware", "virtualbox", "logitech", "razer", "steelseries", "corsair", "asus", "lenovo", "hp", "dell", "realtek", "apple", "adobe"
)
$script:TrustedPathFragments = @(
    "\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\winsxs\\", "\\windows\\servicing\\", "\\program files\\nvidia corporation\\", "\\program files (x86)\\nvidia corporation\\", "\\program files\\amd\\", "\\program files\\intel\\", "\\program files\\java\\", "\\program files\\eclipse adoptium\\", "\\program files\\microsoft\\", "\\program files (x86)\\microsoft\\", "\\program files\\windowsapps\\", "\\programdata\\nvidia corporation\\", "\\programdata\\microsoft\\windows defender\\"
)
$script:UserWritableFragments = @(
    "\\appdata\\", "\\temp\\", "\\downloads\\", "\\desktop\\", "\\documents\\", "\\programdata\\", "\\users\\public\\", "\\startup\\", "\\recent\\", "\\.minecraft\\", "\\.tlauncher\\", "\\prismlauncher\\", "\\polymc\\", "\\multimc\\", "\\gdlauncher\\", "\\atlauncher\\", "\\modrinthapp\\", "\\curseforge\\", "\\overwolf\\", "\\lunarclient\\", "\\feather\\", "\\badlion client\\"
)
$script:NeverStrongAlone = @(
    "client", "loader", "module", "mod", "api", "gui", "service", "update", "helper", "driver", "host", "render", "graphics", "overlay", "moon", "dream", "winter", "summer", "impact", "velocity", "thread", "packet", "mixin", "event"
)
$script:StrongEvidenceTokens = @(
    "javaagent", "agentmain", "premain", "attachapi", "virtualmachine.attach", "xbootclasspath", "bootclasspath", "system.class.loader", "noverify", "manualmap", "createremotethread", "writeprocessmemory", "virtualallocex", "dllinject", "appinit_dlls", "image file execution options", "debugger", "killaura", "aimassist", "triggerbot", "autoclicker", "reach", "scaffold", "xray", "cheststealer", "crystalaura", "clickgui", "modulemanager", "anticheatbypass", "disabler", "classfiletransformer", "launchwrapper", "mixintransformer", "baritone", "rotationutils", "silentaim", "timerange", "reachdisplay"
)
$script:BenignVendorProcessTokens = @(
    "nvidia", "nvcontainer", "nvdisplay", "geforce", "amd", "radeon", "intel", "igfx", "microsoft", "defender", "onedrive", "teams", "edge", "chrome", "firefox", "discord", "steam", "epic", "java", "openjdk", "oracle", "adoptium"
)

function Test-Deadline {
    try { return ((Get-Date) -gt $script:Deadline) } catch { return $false }
}


function Repeat-Text {
    param([string]$Text, [int]$Count)
    if ($Count -le 0) { return "" }
    return ([string]$Text) * $Count
}

function Truncate-UiText {
    param([string]$Text, [int]$Max = 100)
    if ($null -eq $Text) { return "" }
    $s = [string]$Text
    $s = $s -replace "`r|`n|`t", " "
    if ($s.Length -le $Max) { return $s }
    if ($Max -le 3) { return $s.Substring(0,$Max) }
    return ($s.Substring(0, $Max-3) + "...")
}

function Write-YLine {
    param([string]$Text = "", [string]$Color = "Gray", [switch]$NoNewline)
    try {
        if ($script:UiNoColor) { $Color = "Gray" }
        if ($NoNewline) { Write-Host $Text -ForegroundColor $Color -NoNewline }
        else { Write-Host $Text -ForegroundColor $Color }
    } catch { Write-Host $Text }
}

function Get-UiColorForSeverity {
    param([string]$Severity)
    switch ($Severity) {
        "CRITICAL" { return "Red" }
        "HIGH" { return "Yellow" }
        "MEDIUM" { return "Cyan" }
        "LOW" { return "DarkGray" }
        default { return "Gray" }
    }
}

function Get-UiIconForSeverity {
    param([string]$Severity, [bool]$Trace)
    if ($Trace) { return "TRACE" }
    switch ($Severity) {
        "CRITICAL" { return "!!!" }
        "HIGH" { return "!!" }
        "MEDIUM" { return "!" }
        "LOW" { return "i" }
        default { return "." }
    }
}

function Write-UiRule {
    param([string]$Title = "", [string]$Color = "DarkMagGray")
    if ($Color -eq "DarkMagGray") { $Color = "DarkMagenta" }
    $w = $script:UiWidth
    $spark = ".*..*..*..*..*..*..*..*..*..*..*..*..*..*..*..*..*..*..*..*..*..*..*..*..*..*..*..*..*..*..*..*."
    if ([string]::IsNullOrWhiteSpace($Title)) {
        Write-YLine (Truncate-UiText $spark $w) $Color
        return
    }
    $label = "[ " + $Title + " ]"
    $left = [Math]::Max(3, [int](($w - $label.Length) / 2))
    $right = [Math]::Max(3, $w - $left - $label.Length)
    Write-YLine ((Repeat-Text "=" $left) + $label + (Repeat-Text "=" $right)) $Color
}

function Write-UiBoxLine {
    param([string]$Text = "", [string]$Color = "Gray")
    $w = $script:UiWidth
    $inner = $w - 4
    $body = Truncate-UiText $Text $inner
    $pad = [Math]::Max(0, $inner - $body.Length)
    Write-YLine ("| " + $body + (Repeat-Text " " $pad) + " |") $Color
}

function Write-UiBox {
    param([string]$Title, [string[]]$Lines, [string]$Color = "White")
    $w = $script:UiWidth
    Write-YLine ("+" + (Repeat-Text "=" ($w-2)) + "+") $Color
    if ($Title) { Write-UiBoxLine (":: " + $Title + " ::") $Color }
    Write-YLine ("+" + (Repeat-Text "-" ($w-2)) + "+") $Color
    foreach ($line in @($Lines)) { Write-UiBoxLine $line "Gray" }
    Write-YLine ("+" + (Repeat-Text "=" ($w-2)) + "+") $Color
}

function Write-UiKV {
    param([string]$Key, [string]$Value, [string]$Color = "Gray")
    $label = ($Key + ":").PadRight(22)
    Write-YLine ("  " + $label + " " + $Value) $Color
}

function Get-UiBar {
    param([int]$Value, [int]$Max, [int]$Width = 28)
    if ($Max -le 0) { $Max = 1 }
    $filled = [Math]::Min($Width, [Math]::Max(0, [int][Math]::Round(($Value / [double]$Max) * $Width)))
    return "[" + (Repeat-Text "#" $filled) + (Repeat-Text "-" ($Width - $filled)) + "]"
}

function Write-UiBarLine {
    param([string]$Name, [int]$Value, [int]$Max, [string]$Color = "Gray")
    Write-YLine ("  " + $Name.PadRight(12) + " " + (Get-UiBar -Value $Value -Max $Max -Width 28) + " " + $Value) $Color
}

function Write-CosmicStatus {
    param([string]$Name, [string]$Value, [string]$Color = "Gray")
    $line = "  <" + $Name.PadRight(14) + "> " + $Value
    Write-YLine $line $Color
}

function Start-UiPhase {
    param([string]$Name, [string]$Details = "")
    $script:UiPhaseIndex++
    $script:UiLastStatus = $Name
    $phase = "PHASE " + $script:UiPhaseIndex + "/" + $script:UiPhaseTotal
    if ($script:UiCompact) {
        Write-YLine ("  [" + $script:UiPhaseIndex + "/" + $script:UiPhaseTotal + "] " + $Name + $(if($Details){" - " + $Details}else{""})) "DarkCyan"
    } else {
        Write-UiRule ($phase + "  ::  " + $Name) "DarkMagenta"
        if ($Details) { Write-YLine ("  orbit: " + $Details) "DarkCyan" }
    }
    if (-not $script:UiNoProgress) {
        try {
            $pct = [Math]::Min(100, [Math]::Max(0, [int](($script:UiPhaseIndex / [double]$script:UiPhaseTotal) * 100)))
            Write-Progress -Activity "YRYS CHECKER COSMIC" -Status $Name -PercentComplete $pct
        } catch {}
    }
}

function Show-Banner {
    Clear-Host
    $script:UiPhaseStarted = Get-Date
    $adminState = if ($script:IsElevated) { "YES / " + $script:AdminMethod } else { "NO / " + $script:AdminMethod }
    Write-YLine "" "DarkGray"
    Write-YLine "                 .        *        .       .        *        ." "DarkMagenta"
    Write-YLine "          *         Y R Y S   C H E C K E R   C O S M I C         *" "Magenta"
    Write-YLine "     .__________________________________________________________________." "DarkMagenta"
    Write-YLine "     |  YYYYY  RRRRR   YYYYY   SSSS      CCCC  H   H  EEEEE  CCCC  K  K |" "Red"
    Write-YLine "     |    Y    R   R     Y    S         C      H   H  E     C      K K  |" "Red"
    Write-YLine "     |    Y    RRRR      Y     SSS      C      HHHHH  EEEE  C      KK   |" "Red"
    Write-YLine "     |    Y    R  R      Y        S     C      H   H  E     C      K K  |" "Red"
    Write-YLine "     |    Y    R   R     Y    SSSS       CCCC  H   H  EEEEE  CCCC  K  K |" "Red"
    Write-YLine "     |__________________________________________________________________|" "DarkMagenta"
    Write-YLine "                    FORENSIC AI v15.0  ::  COSMIC UI" "Cyan"
    Write-YLine "" "DarkGray"
    Write-UiBox "MISSION CONTROL" @(
        "Scan mode: autonomous local forensic scan",
        "Admin: " + $adminState,
        "Workspace: " + $script:TempRoot,
        "Privacy: no permanent reports; temp workspace removed on exit",
        "Engines: files, processes, java, registry, USB, HWID, WMI, browser, Discord, macros, USN, DNS, BITS",
        "Output: dashboard, triage, evidence cards, confidence and risk bars"
    ) "Magenta"
    if (-not $script:IsElevated) {
        Write-UiBox "ELEVATION" @(
            "Admin token was not detected by token/fltmc/fsutil checks.",
            "Some protected areas may be partial: Prefetch, BAM/DAM, services, drivers, USN, process modules.",
            "If your terminal is already elevated, Windows/UAC policy may still block specific providers. The scanner will use fallbacks."
        ) "Yellow"
    }
    Write-YLine "" "DarkGray"
}

function Test-SelfSyntax {
    $p = $MyInvocation.ScriptName
    if (-not $p) { $p = $PSCommandPath }
    if (-not $p) { Write-YLine "SelfTest: cannot find script path." "Yellow"; return }
    $errors = $null
    [void][System.Management.Automation.PSParser]::Tokenize((Get-Content -Path $p -Raw), [ref]$errors)
    if ($errors -and $errors.Count -gt 0) {
        Write-YLine "SelfTest: parser errors found." "Red"
        $errors | Format-List | Out-Host
        exit 2
    }
    Write-YLine "SelfTest: OK, parser found no syntax errors." "Green"
    Write-YLine ("SelfTest: file = " + $p) "DarkGray"
    exit 0
}

function Initialize-Workspace {
    try { New-Item -ItemType Directory -Path $script:TempRoot -Force | Out-Null } catch {}
}

function Remove-Workspace {
    try {
        if (Test-Path $script:TempRoot) { Remove-Item -Path $script:TempRoot -Recurse -Force -ErrorAction SilentlyContinue }
    } catch {}
}

function Normalize-Token {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return "" }
    return ($Value.ToLowerInvariant().Trim())
}

function Split-InputTokens {
    param([string]$Value)
    $result = New-Object System.Collections.Generic.List[string]
    if (-not [string]::IsNullOrWhiteSpace($Value)) {
        foreach ($x in ($Value -split "[,;]")) {
            $t = Normalize-Token $x
            if ($t.Length -ge 3 -and -not $result.Contains($t)) { [void]$result.Add($t) }
        }
    }
    return @($result)
}

function Escape-RegexSafe {
    param([string]$Value)
    return [Regex]::Escape($Value)
}

function Test-AnyTokenInText {
    param([string]$Text, [string[]]$Tokens)
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    $lower = $Text.ToLowerInvariant()
    $hits = New-Object System.Collections.Generic.List[string]
    foreach ($t in $Tokens) {
        if ([string]::IsNullOrWhiteSpace($t)) { continue }
        if ($lower.Contains($t.ToLowerInvariant())) { if (-not $hits.Contains($t)) { [void]$hits.Add($t) } }
    }
    return @($hits)
}

function Get-FileSha256Safe {
    param([string]$Path)
    if ($script:HashCache.ContainsKey($Path)) { return $script:HashCache[$Path] }
    try {
        $h = (Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToUpperInvariant()
        $script:HashCache[$Path] = $h
        return $h
    } catch {
        $script:HashCache[$Path] = ""
        return ""
    }
}

function Get-AuthenticodeInfoSafe {
    param([string]$Path)
    if ($script:SignatureCache.ContainsKey($Path)) { return $script:SignatureCache[$Path] }
    $o = [pscustomobject]@{ Status="Unknown"; Subject=""; Issuer=""; Trusted=$false }
    try {
        $s = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
        $sub = ""
        $iss = ""
        if ($s.SignerCertificate) { $sub = [string]$s.SignerCertificate.Subject; $iss = [string]$s.SignerCertificate.Issuer }
        $o = [pscustomobject]@{ Status=([string]$s.Status); Subject=$sub; Issuer=$iss; Trusted=($s.Status -eq "Valid") }
    } catch {}
    $script:SignatureCache[$Path] = $o
    return $o
}

function Test-TrustedVendorText {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    $lower = $Text.ToLowerInvariant()
    foreach ($v in $script:TrustedVendorTokens) { if ($lower.Contains($v)) { return $true } }
    return $false
}

function Test-TrustedPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $p = $Path.ToLowerInvariant()
    foreach ($frag in $script:TrustedPathFragments) { if ($p.Contains($frag)) { return $true } }
    return $false
}

function Test-UserWritablePath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $p = $Path.ToLowerInvariant()
    foreach ($frag in $script:UserWritableFragments) { if ($p.Contains($frag)) { return $true } }
    return $false
}

function Test-MinecraftPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $p = $Path.ToLowerInvariant()
    foreach ($frag in @(".minecraft", ".tlauncher", "prismlauncher", "polymc", "multimc", "gdlauncher", "atlauncher", "modrinthapp", "curseforge", "lunarclient", "badlion", "feather", "minecraft")) {
        if ($p.Contains($frag)) { return $true }
    }
    return $false
}

function Get-FileVersionTextSafe {
    param([string]$Path)
    try {
        $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
        return (($vi.CompanyName + " " + $vi.ProductName + " " + $vi.FileDescription + " " + $vi.OriginalFilename) -replace "\s+", " ")
    } catch { return "" }
}

function Read-TextWindowSafe {
    param([string]$Path, [int]$MaxBytes = 524288)
    try {
        $fi = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($fi.Length -le 0) { return "" }
        $take = [Math]::Min([int64]$MaxBytes, [int64]$fi.Length)
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $buf = New-Object byte[] $take
            $read = $fs.Read($buf, 0, [int]$take)
            if ($read -le 0) { return "" }
            if ($read -lt $buf.Length) {
                $tmp = New-Object byte[] $read
                [Array]::Copy($buf, $tmp, $read)
                $buf = $tmp
            }
            $ascii = [System.Text.Encoding]::ASCII.GetString($buf)
            $utf8 = ""
            try { $utf8 = [System.Text.Encoding]::UTF8.GetString($buf) } catch {}
            $u16 = ""
            try { $u16 = [System.Text.Encoding]::Unicode.GetString($buf) } catch {}
            return (($ascii + " `n" + $utf8 + " `n" + $u16) -replace "[^\x09\x0A\x0D\x20-\x7E]", " ")
        } finally { $fs.Dispose() }
    } catch { return "" }
}

function Test-BenignWeakText {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    $l = $Text.ToLowerInvariant()
    foreach ($t in $script:BenignVendorProcessTokens) { if ($l.Contains($t)) { return $true } }
    return $false
}

function Get-ExpandedCommandText {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return "" }
    $out = $Text
    try { $out = [Environment]::ExpandEnvironmentVariables($out) } catch {}
    return $out
}

function Test-StrongEvidenceList {
    param([string[]]$Evidence)
    $joined = ((@($Evidence)) -join " ").ToLowerInvariant()
    foreach ($t in $script:StrongEvidenceTokens) { if ($joined.Contains($t)) { return $true } }
    if ($joined.Contains("java agent") -or $joined.Contains("currently running") -or $joined.Contains("autorun") -or $joined.Contains("yara") -or $joined.Contains("virustotal")) { return $true }
    return $false
}

function Get-FileAgeBucket {
    param([string]$Path)
    try {
        $f = Get-Item -LiteralPath $Path -ErrorAction Stop
        $days = [int]((Get-Date) - $f.LastWriteTime).TotalDays
        if ($days -le 2) { return "new_0_2d" }
        if ($days -le 14) { return "recent_3_14d" }
        if ($days -le 60) { return "month_15_60d" }
        return "old_60d_plus"
    } catch { return "unknown_age" }
}

function Get-EvidenceProfile {
    param(
        [string[]]$Evidence,
        [int]$Score,
        [string]$Class = "",
        [string]$ObjectType = "",
        [string]$Object = "",
        [switch]$DeletedTrace
    )
    $positive = New-Object System.Collections.Generic.List[string]
    $mitigation = New-Object System.Collections.Generic.List[string]
    $context = New-Object System.Collections.Generic.List[string]
    $strong = 0
    $weak = 0
    foreach ($raw in @($Evidence)) {
        $e = [string]$raw
        $l = $e.ToLowerInvariant()
        if ($l.Contains("trusted") -or $l.Contains("signed by trusted") -or $l.Contains("valid signature") -or $l.Contains("vendor") -or $l.Contains("benign") -or $l.Contains("ignored")) {
            [void]$mitigation.Add($e)
            continue
        }
        if ($l.Contains("weak ") -or $l.Contains("weak-") -or $l.Contains("weak filename") -or $l.Contains("weak path")) {
            $weak++
            [void]$context.Add($e)
            continue
        }
        if ($l.Contains("javaagent") -or $l.Contains("agentpath") -or $l.Contains("agentlib") -or $l.Contains("xbootclasspath") -or $l.Contains("noverify") -or $l.Contains("inject") -or $l.Contains("manualmap") -or $l.Contains("createremotethread") -or $l.Contains("writeprocessmemory") -or $l.Contains("yara") -or $l.Contains("virustotal") -or $l.Contains("amsi") -or $l.Contains("unsigned") -or $l.Contains("system32 anomaly") -or $l.Contains("appinit_dlls") -or $l.Contains("debugger") -or $l.Contains("prefetch") -or $l.Contains("bam/dam") -or $l.Contains("userassist") -or $l.Contains("recycle bin") -or $l.Contains("usn journal") -or $l.Contains("dns cache") -or $l.Contains("bits job") -or $l.Contains("firewall rule") -or $l.Contains("named pipe") -or $l.Contains("java attach") -or $l.Contains("high entropy") -or $l.Contains("timestomp") -or $l.Contains("behavior chain") -or $l.Contains("lwjgl") -or $l.Contains("mixin") -or $l.Contains("killaura") -or $l.Contains("aimassist") -or $l.Contains("reach") -or $l.Contains("autoclicker")) {
            $strong++
            [void]$positive.Add($e)
            continue
        }
        if ($DeletedTrace -or $ObjectType -match "TRACE") {
            [void]$context.Add($e)
        } else {
            [void]$positive.Add($e)
        }
    }
    $confidence = "LOW"
    if ($Score -ge 120 -and $strong -ge 1) { $confidence = "VERY_HIGH" }
    elseif ($Score -ge 80 -and ($strong -ge 1 -or $positive.Count -ge 2)) { $confidence = "HIGH" }
    elseif ($Score -ge 45 -and ($positive.Count -ge 1 -or $context.Count -ge 2)) { $confidence = "MEDIUM" }
    elseif ($mitigation.Count -gt 0 -and $strong -eq 0) { $confidence = "LOW_TRUSTED_CONTEXT" }
    return [pscustomobject]@{
        Positive = @($positive)
        Mitigation = @($mitigation)
        Context = @($context)
        StrongCount = $strong
        WeakCount = $weak
        Confidence = $confidence
    }
}

function Get-FindingRecommendation {
    param([string]$Severity, [string]$Class, [string]$ObjectType, [switch]$DeletedTrace)
    if ($DeletedTrace -or $ObjectType -match "TRACE") { return "past-use trace: compare dates and ask for manual review, not proof of current install" }
    if ($Severity -eq "CRITICAL") { return "isolate evidence, verify signature/hash, review process/autorun, then decide" }
    if ($Severity -eq "HIGH") { return "manual review recommended: check path, signature, hash, and related launcher logs" }
    if ($Severity -eq "MEDIUM") { return "weak suspicion: verify with logs and user context before accusing" }
    return "informational: keep only if it supports stronger evidence" }

function New-FindingObject {
    param(
        [string]$Object,
        [string]$ObjectType,
        [int]$Score,
        [string]$Severity,
        [string]$Class,
        [string[]]$Evidence,
        [string]$Sha256,
        [bool]$DeletedTrace
    )
    $profile = Get-EvidenceProfile -Evidence $Evidence -Score $Score -Class $Class -ObjectType $ObjectType -Object $Object -DeletedTrace:([bool]$DeletedTrace)
    $recommend = Get-FindingRecommendation -Severity $Severity -Class $Class -ObjectType $ObjectType -DeletedTrace:([bool]$DeletedTrace)
    return [pscustomobject]@{
        Object = $Object
        ObjectType = $ObjectType
        Score = $Score
        Severity = $Severity
        Class = $Class
        Evidence = @($Evidence)
        EvidenceProfile = $profile
        Confidence = $profile.Confidence
        Recommendation = $recommend
        Sha256 = $Sha256
        DeletedTrace = [bool]$DeletedTrace
        Time = (Get-Date)
    }
}

function Add-Finding {
    param(
        [string]$Object,
        [string]$ObjectType,
        [int]$Score,
        [string]$Severity,
        [string]$Class,
        [string[]]$Evidence,
        [string]$Sha256 = "",
        [switch]$DeletedTrace,
        [switch]$Ignored
    )
    if (-not $Evidence) { $Evidence = @("no evidence text") }
    $item = New-FindingObject -Object $Object -ObjectType $ObjectType -Score $Score -Severity $Severity -Class $Class -Evidence $Evidence -Sha256 $Sha256 -DeletedTrace:([bool]$DeletedTrace)
    if ($Ignored) { [void]$script:Ignored.Add($item); return }

    $effectiveMin = $MinScore
    if ($DeletedTrace) { $effectiveMin = $TraceMinScore }
    if ($Score -lt $effectiveMin) {
        $script:BelowThresholdSuppressedCount++
        if ($ShowIgnored) {
            $item.Class = "suppressed_below_threshold"
            [void]$script:Ignored.Add($item)
        }
        return
    }
    if ($StrictEvidence -and -not $DeletedTrace -and $item.EvidenceProfile.StrongCount -lt 1 -and $Score -lt 80) {
        $script:WeakSuppressedCount++
        if ($ShowIgnored) {
            $item.Class = "suppressed_weak_evidence"
            [void]$script:Ignored.Add($item)
        }
        return
    }
    [void]$script:Findings.Add($item)
}

function Convert-ScoreToSeverity {
    param([int]$Score)
    if ($Score -ge 120) { return "CRITICAL" }
    if ($Score -ge 80) { return "HIGH" }
    if ($Score -ge 45) { return "MEDIUM" }
    if ($Score -ge 20) { return "LOW" }
    return "INFO"
}

function Get-ObjectKindFromPath {
    param([string]$Path)
    $ext = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
    if ($ext -eq ".jar") { return "JAR" }
    if ($ext -eq ".dll") { return "DLL" }
    if ($ext -eq ".exe") { return "EXE" }
    if ($ext -eq ".lnk") { return "LNK" }
    if ($ext -eq ".pf") { return "PREFETCH" }
    if ($ext -eq ".log") { return "LOG" }
    return "FILE"
}

function Get-BasicRiskContext {
    param([string]$Path)
    $kind = Get-ObjectKindFromPath $Path
    $p = $Path.ToLowerInvariant()
    $evidence = New-Object System.Collections.Generic.List[string]
    $score = 0
    $class = "unknown_file"
    $sig = $null
    $versionText = ""
    if (Test-MinecraftPath $Path) { $score += 18; [void]$evidence.Add("path is related to Minecraft/launcher") ; $class = "minecraft_or_launcher_area" }
    if (Test-UserWritablePath $Path) { $score += 12; [void]$evidence.Add("file is in user-writable area") }
    if (Test-TrustedPath $Path) { $score -= 18; [void]$evidence.Add("trusted/system path context") }
    $nameHits = Test-AnyTokenInText -Text ([System.IO.Path]::GetFileNameWithoutExtension($Path)) -Tokens $script:CriticalCheatTokens
    if ($nameHits.Count -gt 0) {
        foreach ($h in $nameHits) {
            if ($script:NeverStrongAlone -contains $h) { $score += 3; [void]$evidence.Add("weak filename token: " + $h) }
            else { $score += 45; [void]$evidence.Add("filename token: " + $h) }
        }
        $class = "name_based_candidate"
    }
    $pathHits = Test-AnyTokenInText -Text $p -Tokens $script:CriticalCheatTokens
    if ($pathHits.Count -gt 0) {
        foreach ($h in $pathHits | Select-Object -First 8) {
            if ($script:NeverStrongAlone -contains $h) { $score += 2; [void]$evidence.Add("weak path token: " + $h) }
            else { $score += 25; [void]$evidence.Add("path token: " + $h) }
        }
        if ($class -eq "unknown_file") { $class = "path_based_candidate" }
    }
    if ($kind -in @("EXE","DLL")) {
        $sig = Get-AuthenticodeInfoSafe $Path
        $versionText = Get-FileVersionTextSafe $Path
        if ($sig.Trusted -and (Test-TrustedVendorText ($sig.Subject + " " + $versionText))) {
            $score -= 45
            [void]$evidence.Add("valid trusted vendor signature/version info")
            if ($class -eq "unknown_file") { $class = "trusted_system_or_vendor_software" }
        } elseif ($sig.Status -eq "NotSigned" -or $sig.Status -eq "UnknownError" -or -not $sig.Trusted) {
            $score += 14
            [void]$evidence.Add("not signed or signature not trusted: " + $sig.Status)
            if ($class -eq "unknown_file") { $class = "unsigned_binary_candidate" }
        }
        $verHits = Test-AnyTokenInText -Text $versionText -Tokens $script:CriticalCheatTokens
        if ($verHits.Count -gt 0) {
            foreach ($h in $verHits | Select-Object -First 8) { $score += 25; [void]$evidence.Add("version info token: " + $h) }
            $class = "binary_metadata_candidate"
        }
    }
    try {
        $fi = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($fi.LastWriteTime -gt (Get-Date).AddDays(-14)) { $score += 5; [void]$evidence.Add("recent file write time") }
        if ($fi.Length -gt 0 -and $fi.Length -lt 15360 -and $kind -in @("EXE","DLL")) { $score += 5; [void]$evidence.Add("very small binary") }
    } catch {}
    return [pscustomobject]@{ Kind=$kind; Score=$score; Class=$class; Evidence=@($evidence); Signature=$sig; VersionText=$versionText }
}

function Analyze-JarFile {
    param([string]$Path, [object]$Base)
    $score = [int]$Base.Score
    $class = [string]$Base.Class
    $evidence = New-Object System.Collections.Generic.List[string]
    foreach ($x in @($Base.Evidence)) { [void]$evidence.Add($x) }
    try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue } catch {}
    try {
        $zip = [System.IO.Compression.ZipFile]::OpenRead($Path)
        try {
            $entryNames = New-Object System.Collections.Generic.List[string]
            $smallText = New-Object System.Text.StringBuilder
            foreach ($entry in $zip.Entries) {
                if ($entry.FullName) { [void]$entryNames.Add($entry.FullName.ToLowerInvariant()) }
                if ($entry.FullName -match "(?i)(manifest.mf|fabric.mod.json|mods.toml|plugin.yml|mixin|accesswidener|\.json$|\.properties$|\.txt$)") {
                    if ($entry.Length -gt 0 -and $entry.Length -lt 262144) {
                        try {
                            $stream = $null
                            $reader = $null
                            $stream = $entry.Open()
                            try {
                                $reader = New-Object System.IO.StreamReader($stream)
                                $txt = $reader.ReadToEnd()
                                [void]$smallText.AppendLine($txt)
                            } finally { if ($reader -ne $null) { $reader.Dispose() }; if ($stream -ne $null) { $stream.Dispose() } }
                        } catch {}
                    }
                }
                if ($entry.FullName -match "(?i)(killaura|aimassist|triggerbot|autoclicker|clickgui|module|combat|movement|render|exploit|mixin|baritone|xray|scaffold|reach|velocity)") {
                    $score += 10
                    [void]$evidence.Add("suspicious jar entry: " + $entry.FullName)
                    $class = "minecraft_jar_static_candidate"
                }
            }
            $namesText = (($entryNames | Select-Object -First 2200) -join " ")
            $allText = ($namesText + " " + $smallText.ToString()).ToLowerInvariant()
            $kbHits = Test-AnyTokenInText -Text $allText -Tokens $script:CriticalCheatTokens
            foreach ($h in ($kbHits | Select-Object -First 20)) {
                if ($script:NeverStrongAlone -contains $h) { $score += 2; [void]$evidence.Add("weak jar token: " + $h) }
                elseif ($script:StrongEvidenceTokens -contains $h) { $score += 28; [void]$evidence.Add("strong jar token: " + $h) }
                else { $score += 18; [void]$evidence.Add("jar token: " + $h) }
                $class = "minecraft_jar_static_candidate"
            }
            if ($allText.Contains("premain-class") -or $allText.Contains("agent-class")) {
                $score += 65; [void]$evidence.Add("jar declares Java agent manifest class"); $class = "jvm_agent_candidate"
            }
        } finally { $zip.Dispose() }
    } catch {
        [void]$evidence.Add("jar could not be opened as zip")
        $score += 2
    }
    return [pscustomobject]@{ Score=$score; Class=$class; Evidence=@($evidence) }
}

function Analyze-BinaryLight {
    param([string]$Path, [object]$Base)
    $score = [int]$Base.Score
    $class = [string]$Base.Class
    $evidence = New-Object System.Collections.Generic.List[string]
    foreach ($x in @($Base.Evidence)) { [void]$evidence.Add($x) }
    $mustDeep = $false
    if ($score -ge 25) { $mustDeep = $true }
    if (Test-UserWritablePath $Path) { $mustDeep = $true }
    if (-not (Test-TrustedPath $Path)) { $mustDeep = $true }
    if ($mustDeep) {
        $txt = Read-TextWindowSafe -Path $Path -MaxBytes $MaxDeepBytes
        if ($txt) {
            $low = $txt.ToLowerInvariant()
            $hits = Test-AnyTokenInText -Text $low -Tokens $script:StrongEvidenceTokens
            foreach ($h in ($hits | Select-Object -First 12)) {
                $score += 35
                [void]$evidence.Add("binary contains strong static token: " + $h)
                $class = "binary_static_candidate"
            }
            $hits2 = Test-AnyTokenInText -Text $low -Tokens $script:CriticalCheatTokens
            foreach ($h in ($hits2 | Select-Object -First 15)) {
                if ($script:NeverStrongAlone -contains $h) { continue }
                $score += 10
                [void]$evidence.Add("binary contains token: " + $h)
                if ($class -eq "unknown_file" -or $class -eq "trusted_system_or_vendor_software") { $class = "binary_static_candidate" }
            }
        }
    }
    return [pscustomobject]@{ Score=$score; Class=$class; Evidence=@($evidence) }
}

function Test-FalsePositiveGate {
    param([string]$Path, [object]$Base, [object]$Analyzed)
    $score = [int]$Analyzed.Score
    $ev = @($Analyzed.Evidence)
    $kind = Get-ObjectKindFromPath $Path
    $sig = $Base.Signature
    $versionText = [string]$Base.VersionText
    $trustedVendor = $false
    if ($sig -and $sig.Trusted -and (Test-TrustedVendorText ($sig.Subject + " " + $versionText))) { $trustedVendor = $true }
    $hasStrong = Test-StrongEvidenceList @($ev)
    if ($trustedVendor -and (Test-TrustedPath $Path) -and $score -lt 110 -and -not $hasStrong) {
        return [pscustomobject]@{ Ignore=$true; Reason="trusted signed vendor in trusted path with no strong evidence" }
    }
    if ((Test-BenignWeakText ($Path + " " + $versionText)) -and $score -lt 95 -and -not $hasStrong) {
        return [pscustomobject]@{ Ignore=$true; Reason="benign vendor/process context with weak token only" }
    }
    if ($kind -in @("EXE","DLL") -and (Test-TrustedPath $Path) -and $score -lt 70 -and -not $hasStrong) {
        return [pscustomobject]@{ Ignore=$true; Reason="system path weak signal only" }
    }
    if ($StrictEvidence -and $score -lt 45 -and -not $hasStrong) {
        return [pscustomobject]@{ Ignore=$true; Reason="strict evidence mode suppressed weak single-signal object" }
    }
    return [pscustomobject]@{ Ignore=$false; Reason="" }
}

function Analyze-FileCandidate {
    param([string]$Path, [string]$Source = "filesystem")
    if ((Get-Date) -gt $script:Deadline) { return }
    $script:FilesAnalyzed++
    $base = Get-BasicRiskContext $Path
    $kind = $base.Kind
    $an = $null
    if ($kind -eq "JAR") { $an = Analyze-JarFile -Path $Path -Base $base }
    elseif ($kind -in @("EXE","DLL")) { $an = Analyze-BinaryLight -Path $Path -Base $base }
    else { $an = [pscustomobject]@{ Score=$base.Score; Class=$base.Class; Evidence=@($base.Evidence) } }
    $score = [int]$an.Score
    if ($source -eq "process") { $score += 25; $an.Evidence += "object is currently running or loaded" }
    if ($source -eq "autorun") { $score += 30; $an.Evidence += "object is referenced by autorun/persistence" }
    if ($source -eq "javaagent") { $score += 75; $an.Evidence += "object is used as Java agent" }
    if ($source -eq "system_anomaly") { $score += 35; $an.Evidence += "system-folder anomaly: unsigned/untrusted object in Windows system area" }
    if ($source -eq "suspicious_stream") { $score += 25; $an.Evidence += "file has suspicious alternate data stream metadata" }
    if ($source -eq "firewall") { $score += 25; $an.Evidence += "object is referenced by firewall rule" }
    if ($source -eq "bits") { $score += 35; $an.Evidence += "object is referenced by BITS transfer job" }
    if ($source -eq "compat_trace") { $score += 30; $an.Evidence += "object appears in Windows compatibility execution traces" }
    if ($source -eq "lwjgl") { $score += 30; $an.Evidence += "object is LWJGL/native library candidate used by Minecraft" }
    $adv = Get-AdvancedFileSignalsV12 -Path $Path -Kind $kind
    if ($adv.Score -ne 0) { $score += [int]$adv.Score; $an.Evidence += @($adv.Evidence) }
    $gate = Test-FalsePositiveGate -Path $Path -Base $base -Analyzed ([pscustomobject]@{Score=$score; Evidence=@($an.Evidence)})
    $sha = ""
    if ($score -ge 45) { $sha = Get-FileSha256Safe $Path }
    $sev = Convert-ScoreToSeverity $score
    if ($gate.Ignore) {
        $script:TrustedIgnoredCount++
        if ($ShowIgnored) { Add-Finding -Object $Path -ObjectType $kind -Score $score -Severity $sev -Class "ignored_trusted" -Evidence (@($an.Evidence) + @("ignored: " + $gate.Reason)) -Sha256 $sha -Ignored }
        return
    }
    if ($score -ge 20) {
        Add-Finding -Object $Path -ObjectType $kind -Score $score -Severity $sev -Class $an.Class -Evidence @($an.Evidence) -Sha256 $sha
    }
}


function Get-DynamicLauncherRoots {
    $list = New-Object System.Collections.Generic.List[string]
    $add = {
        param([string]$p)
        try {
            if ([string]::IsNullOrWhiteSpace($p)) { return }
            $expanded = Get-ExpandedCommandText $p
            if (-not [System.IO.Path]::IsPathRooted($expanded)) { return }
            if ((Test-Path -LiteralPath $expanded) -and -not $list.Contains($expanded)) { [void]$list.Add($expanded) }
        } catch {}
    }
    try {
        $lp = Join-Path $env:APPDATA ".minecraft\launcher_profiles.json"
        if (Test-Path -LiteralPath $lp) {
            $json = Get-Content -LiteralPath $lp -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($json -and $json.profiles) {
                foreach ($prop in $json.profiles.PSObject.Properties) {
                    try {
                        $gd = [string]$prop.Value.gameDir
                        if ($gd) { & $add $gd }
                    } catch {}
                }
            }
        }
    } catch {}
    $instanceRoots = @(
        (Join-Path $env:APPDATA "PrismLauncher\instances"),
        (Join-Path $env:APPDATA "PolyMC\instances"),
        (Join-Path $env:APPDATA "MultiMC\instances"),
        (Join-Path $env:APPDATA "GDLauncher\instances"),
        (Join-Path $env:APPDATA "GDLauncher_next\instances"),
        (Join-Path $env:APPDATA "ATLauncher\instances"),
        (Join-Path $env:APPDATA "ModrinthApp\profiles"),
        (Join-Path $env:APPDATA "CurseForge\minecraft\Instances"),
        (Join-Path $env:LOCALAPPDATA "Packages"),
        (Join-Path $env:LOCALAPPDATA "Programs"),
        (Join-Path $env:USERPROFILE "Games"),
        (Join-Path $env:USERPROFILE "Minecraft"),
        (Join-Path $env:USERPROFILE "Desktop"),
        (Join-Path $env:USERPROFILE "Downloads")
    )
    foreach ($root in $instanceRoots) {
        try {
            if (-not (Test-Path -LiteralPath $root)) { continue }
            & $add $root
            foreach ($d in Get-ChildItem -LiteralPath $root -Directory -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match "(?i)(minecraft|mods|instances|profiles|launcher|client|java|libraries|versions)" } | Select-Object -First 600) {
                & $add $d.FullName
                $mc = Join-Path $d.FullName ".minecraft"
                if (Test-Path -LiteralPath $mc) { & $add $mc }
                $mods = Join-Path $d.FullName "mods"
                if (Test-Path -LiteralPath $mods) { & $add $mods }
            }
        } catch { $script:BlockedErrors++ }
    }
    $script:DynamicRootsCount = $list.Count
    return @($list)
}

function Get-RootSet {
    $roots = New-Object System.Collections.Generic.List[string]
    $add = { param($p) if ($p -and (Test-Path $p) -and -not $roots.Contains($p)) { [void]$roots.Add($p) } }
    & $add (Join-Path $env:APPDATA ".minecraft")
    & $add (Join-Path $env:APPDATA ".tlauncher")
    & $add (Join-Path $env:LOCALAPPDATA "Packages")
    & $add (Join-Path $env:LOCALAPPDATA "Programs")
    & $add (Join-Path $env:LOCALAPPDATA "PrismLauncher")
    & $add (Join-Path $env:APPDATA "PrismLauncher")
    & $add (Join-Path $env:APPDATA "PolyMC")
    & $add (Join-Path $env:APPDATA "MultiMC")
    & $add (Join-Path $env:APPDATA "GDLauncher")
    & $add (Join-Path $env:APPDATA "ATLauncher")
    & $add (Join-Path $env:APPDATA "ModrinthApp")
    & $add (Join-Path $env:APPDATA "CurseForge")
    & $add (Join-Path $env:PROGRAMDATA "Microsoft\Windows\Start Menu\Programs\Startup")
    & $add (Join-Path $env:USERPROFILE "Downloads")
    & $add (Join-Path $env:USERPROFILE "Desktop")
    & $add (Join-Path $env:USERPROFILE "Documents")
    foreach ($dyn in Get-DynamicLauncherRoots) { & $add $dyn }
    if ($OnlyMinecraft) { return @($roots) }
    if ($Deep -or $FullSystem) {
        & $add $env:PROGRAMDATA
        & $add $env:TEMP
        & $add $env:WINDIR
        & $add (Join-Path $env:WINDIR "System32")
        & $add (Join-Path $env:WINDIR "SysWOW64")
        & $add $env:ProgramFiles
        & $add ${env:ProgramFiles(x86)}
    }
    if ($AllDrives -or $FullSystem) {
        try {
            foreach ($d in Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue) {
                if ($d.DeviceID) { & $add ($d.DeviceID + "\") }
            }
        } catch {}
    }
    return @($roots)
}

function Should-PreCandidate {
    param([System.IO.FileInfo]$File)
    $p = $File.FullName.ToLowerInvariant()
    $ext = $File.Extension.ToLowerInvariant()
    if ($ext -eq ".jar") { return $true }
    if ($p.Contains(".minecraft") -or $p.Contains("launcher") -or $p.Contains("tlauncher") -or $p.Contains("prismlauncher") -or $p.Contains("polymc") -or $p.Contains("multimc") -or $p.Contains("gdlauncher") -or $p.Contains("atlauncher") -or $p.Contains("modrinth") -or $p.Contains("curseforge")) { return $true }
    if (Test-UserWritablePath $File.FullName) { return $true }
    $hits = Test-AnyTokenInText -Text ($File.Name + " " + $File.DirectoryName) -Tokens $script:CriticalCheatTokens
    if ($hits.Count -gt 0) { return $true }
    if (($Deep -or $FullSystem -or $AllDrives) -and $ext -in @(".exe", ".dll")) {
        if (Test-TrustedPath $File.FullName) {
            if ($File.LastWriteTime -gt (Get-Date).AddDays(-45)) { return $true }
            return $false
        }
        return $true
    }
    return $false
}

function Search-FileSystemCandidates {
    Write-YLine "  > Finding EXE/DLL/JAR candidates across selected roots..." "Cyan"
    $roots = Get-RootSet
    foreach ($r in $roots) { Write-YLine ("    root: " + $r) "DarkGray" }
    $exts = @("*.jar", "*.exe", "*.dll")
    foreach ($root in $roots) {
        if ((Get-Date) -gt $script:Deadline) { break }
        try {
            foreach ($file in Get-ChildItem -LiteralPath $root -Include $exts -Recurse -Force -File -ErrorAction SilentlyContinue) {
                if ((Get-Date) -gt $script:Deadline) { break }
                if ($script:CandidatesSeen -ge $MaxCandidates) { break }
                try {
                    if (Should-PreCandidate -File $file) {
                        $script:CandidatesSeen++
                        Analyze-FileCandidate -Path $file.FullName -Source "filesystem"
                    }
                } catch { $script:BlockedErrors++ }
            }
        } catch { $script:BlockedErrors++ }
        if ($script:CandidatesSeen -ge $MaxCandidates) { break }
    }
}

function Get-CommandLinePaths {
    param([string]$CommandLine)
    $paths = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return @() }
    $expanded = Get-ExpandedCommandText $CommandLine
    $patterns = @(
        '"([A-Za-z]:\\[^"<>|]+?\.(jar|exe|dll))"|([A-Za-z]:\\[^\s"<>|]+?\.(jar|exe|dll))',
        '"(%[^%]+%\\[^"<>|]+?\.(jar|exe|dll))"|(%[^%]+%\\[^\s"<>|]+?\.(jar|exe|dll))'
    )
    foreach ($text in @($CommandLine, $expanded)) {
        foreach ($pat in $patterns) {
            foreach ($m in [Regex]::Matches($text, $pat, 'IgnoreCase')) {
                $v = ""
                if ($m.Groups[1].Success) { $v = $m.Groups[1].Value }
                elseif ($m.Groups[3].Success) { $v = $m.Groups[3].Value }
                if ($v) {
                    $v = Get-ExpandedCommandText $v
                    $v = $v.Trim('"')
                    if ((Test-Path -LiteralPath $v) -and -not $paths.Contains($v)) { [void]$paths.Add($v) }
                }
            }
        }
    }
    return @($paths)
}
function Analyze-RunningProcesses {
    Write-YLine "  > Checking running processes, command lines, and JVM agent flags..." "Cyan"
    $procs = @()
    $source = "none"
    try {
        $procs = @(Get-CimInstance Win32_Process -ErrorAction Stop)
        $source = "CIM"
    } catch {
        try {
            $procs = @(Get-WmiObject Win32_Process -ErrorAction Stop)
            $source = "WMI"
        } catch {
            try {
                $gp = @(Get-Process -ErrorAction SilentlyContinue)
                foreach ($x in $gp) {
                    $procs += [pscustomobject]@{ Name = ($x.ProcessName + ".exe"); ProcessId = $x.Id; CommandLine = ""; ParentProcessId = 0 }
                }
                $source = "GetProcessFallback"
            } catch {
                $script:BlockedErrors++
                if ($script:IsElevated) { Write-YLine "  ! Process providers blocked even with admin token. Continuing with other modules." "Yellow" }
                else { Write-YLine "  ! Process providers blocked and admin token not detected. Continuing with other modules." "Yellow" }
                return
            }
        }
    }
    Write-YLine ("  + Process provider: " + $source + " | count=" + $procs.Count) "DarkCyan"
    foreach ($p in $procs) {
        if ((Get-Date) -gt $script:Deadline) { break }
        try {
            $line = [string]$p.CommandLine
            $name = [string]$p.Name
            $text = ($name + " " + $line)
            $hits = Test-AnyTokenInText -Text $text -Tokens $script:CriticalCheatTokens
            $javaAgent = $false
            if ($line -match "(?i)-javaagent|-agentpath|-Xbootclasspath|-Djava\.system\.class\.loader|-noverify") { $javaAgent = $true }
            if ($hits.Count -gt 0 -or $javaAgent) {
                $ev = New-Object System.Collections.Generic.List[string]
                if ($hits.Count -gt 0) { [void]$ev.Add("process command/name token: " + (($hits | Select-Object -First 8) -join ", ")) }
                if ($javaAgent) { [void]$ev.Add("JVM injection-like argument detected") }
                if ($source -eq "GetProcessFallback") { [void]$ev.Add("command line unavailable because CIM/WMI was blocked") }
                $score = 35 + ([Math]::Min(80, $hits.Count * 15))
                if ($javaAgent) { $score += 60 }
                Add-Finding -Object ("PID " + $p.ProcessId + " " + $name) -ObjectType "PROCESS" -Score $score -Severity (Convert-ScoreToSeverity $score) -Class "running_process_candidate" -Evidence @($ev)
            }
            if (-not [string]::IsNullOrWhiteSpace($line)) {
                foreach ($path in Get-CommandLinePaths $line) {
                    if ($javaAgent -and $path.ToLowerInvariant().EndsWith(".jar")) { Analyze-FileCandidate -Path $path -Source "javaagent" }
                    else { Analyze-FileCandidate -Path $path -Source "process" }
                }
            }
        } catch { $script:BlockedErrors++ }
    }
}

function Analyze-ProcessModules {
    Write-YLine "  > Checking loaded DLL modules in Java/Minecraft/suspicious processes..." "Cyan"
    try {
        $procList = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match "(?i)java|javaw|minecraft|launcher|lunar|badlion|feather|tlauncher|prism|polymc|multimc|gdlauncher" }
        foreach ($p in $procList) {
            if ((Get-Date) -gt $script:Deadline) { break }
            try {
                foreach ($m in $p.Modules) {
                    $path = $m.FileName
                    if (-not $path) { continue }
                    $lower = $path.ToLowerInvariant()
                    $hits = Test-AnyTokenInText -Text ($path + " " + $m.ModuleName) -Tokens $script:CriticalCheatTokens
                    if (($hits.Count -gt 0) -or ((Test-UserWritablePath $path) -and -not (Test-TrustedPath $path))) {
                        Analyze-FileCandidate -Path $path -Source "process"
                    }
                }
            } catch { $script:BlockedErrors++ }
        }
    } catch { $script:BlockedErrors++ }
}

function Analyze-AutorunsRegistry {
    Write-YLine "  > Checking registry autoruns, services, AppInit_DLLs, IFEO, Uninstall..." "Cyan"
    $keys = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows",
        "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    )
    foreach ($k in $keys) {
        try {
            if (-not (Test-Path $k)) { continue }
            $items = @()
            if ($k.EndsWith("Image File Execution Options")) { $items = Get-ChildItem $k -ErrorAction SilentlyContinue }
            else { $items = @(Get-ItemProperty $k -ErrorAction SilentlyContinue) }
            foreach ($it in $items) {
                $text = ($it | Out-String)
                $hits = Test-AnyTokenInText -Text $text -Tokens ($script:CriticalCheatTokens + $script:StrongEvidenceTokens)
                if ($hits.Count -gt 0) {
                    $score = 45 + [Math]::Min(80, $hits.Count * 10)
                    Add-Finding -Object $k -ObjectType "REGISTRY" -Score $score -Severity (Convert-ScoreToSeverity $score) -Class "registry_autorun_or_hijack_candidate" -Evidence @("registry text tokens: " + (($hits | Select-Object -First 12) -join ", "))
                }
                foreach ($path in Get-CommandLinePaths $text) { Analyze-FileCandidate -Path $path -Source "autorun" }
            }
        } catch { $script:BlockedErrors++ }
    }
    try {
        foreach ($svc in Get-CimInstance Win32_Service -ErrorAction SilentlyContinue) {
            $txt = ([string]$svc.Name + " " + [string]$svc.DisplayName + " " + [string]$svc.PathName)
            $hits = Test-AnyTokenInText -Text $txt -Tokens $script:CriticalCheatTokens
            if ($hits.Count -gt 0) {
                $score = 65 + [Math]::Min(60, $hits.Count * 12)
                Add-Finding -Object ("Service: " + $svc.Name) -ObjectType "SERVICE" -Score $score -Severity (Convert-ScoreToSeverity $score) -Class "service_candidate" -Evidence @("service tokens: " + (($hits | Select-Object -First 10) -join ", "), "path: " + [string]$svc.PathName)
            }
            foreach ($path in Get-CommandLinePaths ([string]$svc.PathName)) { Analyze-FileCandidate -Path $path -Source "autorun" }
        }
    } catch { $script:BlockedErrors++ }
    try {
        $uninst = @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")
        foreach ($uk in $uninst) {
            if (-not (Test-Path $uk)) { continue }
            foreach ($sub in Get-ChildItem $uk -ErrorAction SilentlyContinue) {
                $prop = Get-ItemProperty $sub.PSPath -ErrorAction SilentlyContinue
                $txt = ([string]$prop.DisplayName + " " + [string]$prop.Publisher + " " + [string]$prop.InstallLocation + " " + [string]$prop.UninstallString)
                $hits = Test-AnyTokenInText -Text $txt -Tokens $script:CriticalCheatTokens
                if ($hits.Count -gt 0) {
                    $score = 35 + [Math]::Min(60, $hits.Count * 10)
                    Add-Finding -Object ([string]$prop.DisplayName) -ObjectType "INSTALLED_APP" -Score $score -Severity (Convert-ScoreToSeverity $score) -Class "installed_software_candidate" -Evidence @("uninstall registry tokens: " + (($hits | Select-Object -First 10) -join ", "))
                }
            }
        }
    } catch { $script:BlockedErrors++ }
}


function Analyze-ScheduledTasksDeep {
    Write-YLine "  > Checking scheduled tasks deeply..." "Cyan"
    try {
        $taskObjs = @()
        try { $taskObjs = Get-ScheduledTask -ErrorAction SilentlyContinue } catch { $taskObjs = @() }
        foreach ($task in $taskObjs) {
            if ((Get-Date) -gt $script:Deadline) { break }
            try {
                $script:ScheduledTaskCount++
                $actionText = ($task.Actions | Out-String)
                $triggerText = ($task.Triggers | Out-String)
                $text = ([string]$task.TaskName + " " + [string]$task.TaskPath + " " + $actionText + " " + $triggerText)
                $hits = Test-AnyTokenInText -Text $text -Tokens ($script:CriticalCheatTokens + $script:StrongEvidenceTokens)
                $riskPath = ($text.ToLowerInvariant().Contains("\appdata\") -or $text.ToLowerInvariant().Contains("\temp\") -or $text.ToLowerInvariant().Contains("\downloads\") -or $text.ToLowerInvariant().Contains("\desktop\"))
                $logonTrigger = ($triggerText -match "(?i)logon|startup|unlock|session")
                if ($hits.Count -gt 0 -or ($riskPath -and $logonTrigger)) {
                    $score = 38
                    $ev = New-Object System.Collections.Generic.List[string]
                    if ($hits.Count -gt 0) { $score += [Math]::Min(90, $hits.Count * 12); [void]$ev.Add("scheduled task token(s): " + (($hits | Select-Object -First 12) -join ", ")) }
                    if ($riskPath) { $score += 18; [void]$ev.Add("task action points to user-writable path") }
                    if ($logonTrigger) { $score += 12; [void]$ev.Add("task trigger is logon/startup/unlock related") }
                    Add-Finding -Object ($task.TaskPath + $task.TaskName) -ObjectType "SCHEDULED_TASK" -Score $score -Severity (Convert-ScoreToSeverity $score) -Class "scheduled_task_persistence_candidate" -Evidence @($ev)
                }
                foreach ($path in Get-CommandLinePaths $actionText) { Analyze-FileCandidate -Path $path -Source "scheduled_task" }
            } catch { $script:BlockedErrors++ }
        }
    } catch { $script:BlockedErrors++ }
    try {
        $raw = schtasks.exe /query /fo LIST /v 2>$null
        $textBlocks = ($raw -join "`n") -split "`r?`n`r?`n"
        foreach ($b in $textBlocks | Select-Object -First 2500) {
            if ((Get-Date) -gt $script:Deadline) { break }
            $hits = Test-AnyTokenInText -Text $b -Tokens ($script:CriticalCheatTokens + $script:StrongEvidenceTokens)
            $riskPath = ($b.ToLowerInvariant().Contains("\appdata\") -or $b.ToLowerInvariant().Contains("\temp\") -or $b.ToLowerInvariant().Contains("\downloads\"))
            if ($hits.Count -gt 0 -or $riskPath) {
                $score = 32 + [Math]::Min(80, $hits.Count * 12)
                if ($riskPath) { $score += 10 }
                Add-Finding -Object (($b -split "`r?`n" | Select-Object -First 1) -join "") -ObjectType "SCHEDULED_TASK_RAW" -Score $score -Severity (Convert-ScoreToSeverity $score) -Class "scheduled_task_raw_candidate" -Evidence @("schtasks text token(s): " + (($hits | Select-Object -First 10) -join ", "), "raw task contains user-writable execution path")
            }
        }
    } catch {}
}

function Decode-Rot13 {
    param([string]$s)
    $chars = $s.ToCharArray()
    for ($i=0; $i -lt $chars.Length; $i++) {
        $c = [int][char]$chars[$i]
        if ($c -ge 65 -and $c -le 90) { $chars[$i] = [char](((($c - 65 + 13) % 26) + 65)) }
        elseif ($c -ge 97 -and $c -le 122) { $chars[$i] = [char](((($c - 97 + 13) % 26) + 97)) }
    }
    return -join $chars
}

function Analyze-DeletedAndExecutionTraces {
    if ($NoDeletedTraces) { return }
    Write-YLine "  > Checking deleted/execution traces: Recycle Bin, Recent, JumpLists, UserAssist, BAM/DAM, Prefetch, Minecraft logs..." "Cyan"
    $traceTokens = $script:CriticalCheatTokens + $script:StrongEvidenceTokens
    try {
        foreach ($drive in Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue) {
            $rb = Join-Path $drive.Root "`$Recycle.Bin"
            if (-not (Test-Path $rb)) { continue }
            foreach ($f in Get-ChildItem -LiteralPath $rb -Recurse -Force -ErrorAction SilentlyContinue | Select-Object -First 2500) {
                $txt = $f.FullName
                if ($f.Name -like "`$I*") { $txt += " " + (Read-TextWindowSafe -Path $f.FullName -MaxBytes 4096) }
                $hits = Test-AnyTokenInText -Text $txt -Tokens $traceTokens
                if ($hits.Count -gt 0) {
                    $script:DeletedTraceCount++
                    $score = 50 + [Math]::Min(80, $hits.Count * 12)
                    Add-Finding -Object $f.FullName -ObjectType "DELETED_TRACE" -Score $score -Severity (Convert-ScoreToSeverity $score) -Class "deleted_or_recycle_bin_trace" -Evidence @("recycle bin token(s): " + (($hits | Select-Object -First 10) -join ", ")) -DeletedTrace
                }
            }
        }
    } catch { $script:BlockedErrors++ }
    $traceRoots = @(
        (Join-Path $env:APPDATA "Microsoft\Windows\Recent"),
        (Join-Path $env:APPDATA "Microsoft\Windows\Recent\AutomaticDestinations"),
        (Join-Path $env:APPDATA "Microsoft\Windows\Recent\CustomDestinations")
    )
    foreach ($tr in $traceRoots) {
        try {
            if (-not (Test-Path $tr)) { continue }
            foreach ($f in Get-ChildItem -LiteralPath $tr -Recurse -Force -ErrorAction SilentlyContinue | Select-Object -First 3000) {
                $txt = $f.FullName + " " + (Read-TextWindowSafe -Path $f.FullName -MaxBytes 65536)
                $hits = Test-AnyTokenInText -Text $txt -Tokens $traceTokens
                if ($hits.Count -gt 0) {
                    $script:DeletedTraceCount++
                    $score = 45 + [Math]::Min(80, $hits.Count * 10)
                    Add-Finding -Object $f.FullName -ObjectType "EXECUTION_TRACE" -Score $score -Severity (Convert-ScoreToSeverity $score) -Class "recent_or_jumplist_trace" -Evidence @("recent/jumplist token(s): " + (($hits | Select-Object -First 10) -join ", ")) -DeletedTrace
                }
            }
        } catch { $script:BlockedErrors++ }
    }
    try {
        $pfroot = Join-Path $env:WINDIR "Prefetch"
        if (Test-Path $pfroot) {
            foreach ($f in Get-ChildItem -LiteralPath $pfroot -Filter "*.pf" -Force -ErrorAction SilentlyContinue | Select-Object -First 5000) {
                $txt = $f.Name + " " + (Read-TextWindowSafe -Path $f.FullName -MaxBytes 131072)
                $hits = Test-AnyTokenInText -Text $txt -Tokens $traceTokens
                if ($hits.Count -gt 0) {
                    $script:DeletedTraceCount++
                    $score = 55 + [Math]::Min(90, $hits.Count * 12)
                    Add-Finding -Object $f.FullName -ObjectType "PREFETCH_TRACE" -Score $score -Severity (Convert-ScoreToSeverity $score) -Class "prefetch_execution_trace" -Evidence @("prefetch token(s): " + (($hits | Select-Object -First 10) -join ", ")) -DeletedTrace
                }
            }
        }
    } catch { $script:BlockedErrors++ }
    try {
        $uaBase = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
        if (Test-Path $uaBase) {
            foreach ($sub in Get-ChildItem $uaBase -ErrorAction SilentlyContinue) {
                $count = Join-Path $sub.PSPath "Count"
                if (-not (Test-Path $count)) { continue }
                $props = Get-ItemProperty $count -ErrorAction SilentlyContinue
                foreach ($pn in $props.PSObject.Properties.Name) {
                    if ($pn -like "PS*") { continue }
                    $decoded = Decode-Rot13 $pn
                    $hits = Test-AnyTokenInText -Text $decoded -Tokens $traceTokens
                    if ($hits.Count -gt 0) {
                        $script:DeletedTraceCount++
                        $score = 50 + [Math]::Min(70, $hits.Count * 10)
                        Add-Finding -Object $decoded -ObjectType "USERASSIST_TRACE" -Score $score -Severity (Convert-ScoreToSeverity $score) -Class "userassist_execution_trace" -Evidence @("UserAssist token(s): " + (($hits | Select-Object -First 10) -join ", ")) -DeletedTrace
                    }
                }
            }
        }
    } catch { $script:BlockedErrors++ }
    try {
        $bamRoots = @("HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings", "HKLM:\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings")
        foreach ($br in $bamRoots) {
            if (-not (Test-Path $br)) { continue }
            foreach ($sid in Get-ChildItem $br -ErrorAction SilentlyContinue) {
                $props = Get-ItemProperty $sid.PSPath -ErrorAction SilentlyContinue
                foreach ($pn in $props.PSObject.Properties.Name) {
                    if ($pn -like "PS*") { continue }
                    $hits = Test-AnyTokenInText -Text $pn -Tokens $traceTokens
                    if ($hits.Count -gt 0) {
                        $script:DeletedTraceCount++
                        $score = 60 + [Math]::Min(90, $hits.Count * 12)
                        Add-Finding -Object $pn -ObjectType "BAM_DAM_TRACE" -Score $score -Severity (Convert-ScoreToSeverity $score) -Class "bam_dam_execution_trace" -Evidence @("BAM/DAM token(s): " + (($hits | Select-Object -First 10) -join ", ")) -DeletedTrace
                    }
                }
            }
        }
    } catch { $script:BlockedErrors++ }
    $logRoots = @(
        (Join-Path $env:APPDATA ".minecraft\logs"),
        (Join-Path $env:APPDATA ".tlauncher"),
        (Join-Path $env:APPDATA "PrismLauncher"),
        (Join-Path $env:APPDATA "PolyMC"),
        (Join-Path $env:APPDATA "MultiMC"),
        (Join-Path $env:APPDATA "GDLauncher"),
        (Join-Path $env:APPDATA "ATLauncher"),
        (Join-Path $env:APPDATA "ModrinthApp"),
        (Join-Path $env:APPDATA "CurseForge")
    )
    foreach ($lr in $logRoots) {
        try {
            if (-not (Test-Path $lr)) { continue }
            foreach ($log in Get-ChildItem -LiteralPath $lr -Recurse -Force -Include "*.log","*.txt" -ErrorAction SilentlyContinue | Select-Object -First 2500) {
                $txt = $log.FullName + " " + (Read-TextWindowSafe -Path $log.FullName -MaxBytes 262144)
                $hits = Test-AnyTokenInText -Text $txt -Tokens $traceTokens
                if ($hits.Count -gt 0) {
                    $script:DeletedTraceCount++
                    $score = 45 + [Math]::Min(85, $hits.Count * 10)
                    Add-Finding -Object $log.FullName -ObjectType "MINECRAFT_LOG_TRACE" -Score $score -Severity (Convert-ScoreToSeverity $score) -Class "minecraft_or_launcher_log_trace" -Evidence @("log token(s): " + (($hits | Select-Object -First 12) -join ", ")) -DeletedTrace
                }
            }
        } catch { $script:BlockedErrors++ }
    }
}


function Analyze-SystemFolderAnomalies {
    if (-not ($FullSystem -or $AllDrives -or $HuntSystem32)) { return }
    Write-YLine "  > Hunting System32/SysWOW64 anomalies: unsigned/untrusted EXE/DLL only..." "Cyan"
    $roots = @((Join-Path $env:WINDIR "System32"), (Join-Path $env:WINDIR "SysWOW64")) | Where-Object { $_ -and (Test-Path $_) }
    $limit = [Math]::Min([Math]::Max(200, [int]($MaxCandidates / 4)), 1200)
    foreach ($root in $roots) {
        if ((Get-Date) -gt $script:Deadline) { break }
        try {
            foreach ($f in Get-ChildItem -LiteralPath $root -Include "*.exe","*.dll" -Recurse -Force -File -ErrorAction SilentlyContinue) {
                if ((Get-Date) -gt $script:Deadline) { break }
                if ($script:SystemAnomaliesChecked -ge $limit) { break }
                try {
                    $nameHits = Test-AnyTokenInText -Text ($f.Name + " " + $f.FullName) -Tokens $script:CriticalCheatTokens
                    $recent = ($f.LastWriteTime -gt (Get-Date).AddDays(-120))
                    $sig = Get-AuthenticodeInfoSafe $f.FullName
                    $ver = Get-FileVersionTextSafe $f.FullName
                    $trustedVendor = ($sig.Trusted -and (Test-TrustedVendorText ($sig.Subject + " " + $ver)))
                    if ($trustedVendor -and $nameHits.Count -eq 0 -and -not $recent) { continue }
                    if (-not $trustedVendor -or $nameHits.Count -gt 0 -or $recent) {
                        $script:SystemAnomaliesChecked++
                        Analyze-FileCandidate -Path $f.FullName -Source "system_anomaly"
                    }
                } catch { $script:BlockedErrors++ }
            }
        } catch { $script:BlockedErrors++ }
    }
}

function Analyze-AlternateDataStreamsForCandidates {
    Write-YLine "  > Checking alternate data streams on suspicious file candidates..." "Cyan"
    $targets = @($script:Findings | Where-Object { $_.ObjectType -in @("JAR","EXE","DLL") } | Sort-Object Score -Descending | Select-Object -First 120)
    foreach ($t in $targets) {
        if ((Get-Date) -gt $script:Deadline) { break }
        try {
            if (-not (Test-Path -LiteralPath $t.Object)) { continue }
            $streams = @(Get-Item -LiteralPath $t.Object -Stream * -ErrorAction SilentlyContinue)
            foreach ($st in $streams) {
                if (-not $st.Stream -or $st.Stream -eq ':$DATA') { continue }
                $sname = [string]$st.Stream
                if ($sname -match '(?i)zone.identifier|payload|inject|loader|vape|raven|drip|entropy|whiteout|slinky') {
                    Add-Finding -Object $t.Object -ObjectType "ADS_TRACE" -Score 60 -Severity "MEDIUM" -Class "alternate_data_stream_trace" -Evidence @("alternate data stream: " + $sname)
                }
            }
        } catch {}
    }
}

function Analyze-IFEODeep {
    Write-YLine "  > Deep IFEO debugger hijack check..." "Cyan"
    $base = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    try {
        if (-not (Test-Path $base)) { return }
        foreach ($sub in Get-ChildItem -Path $base -ErrorAction SilentlyContinue) {
            try {
                $prop = Get-ItemProperty -Path $sub.PSPath -ErrorAction SilentlyContinue
                $dbg = [string]$prop.Debugger
                $gflags = [string]$prop.GlobalFlag
                $txt = ([string]$sub.PSChildName + " " + $dbg + " " + $gflags)
                if ([string]::IsNullOrWhiteSpace($txt)) { continue }
                $hits = Test-AnyTokenInText -Text $txt -Tokens ($script:CriticalCheatTokens + $script:StrongEvidenceTokens)
                if ($dbg -or $hits.Count -gt 0) {
                    $score = 65
                    $ev = New-Object System.Collections.Generic.List[string]
                    if ($dbg) { $score += 25; [void]$ev.Add("IFEO Debugger value: " + $dbg) }
                    if ($hits.Count -gt 0) { $score += [Math]::Min(60, $hits.Count * 12); [void]$ev.Add("IFEO token(s): " + (($hits | Select-Object -First 10) -join ", ")) }
                    Add-Finding -Object ("IFEO: " + [string]$sub.PSChildName) -ObjectType "IFEO" -Score $score -Severity (Convert-ScoreToSeverity $score) -Class "ifeo_debugger_hijack_candidate" -Evidence @($ev)
                    foreach ($path in Get-CommandLinePaths $dbg) { Analyze-FileCandidate -Path $path -Source "autorun" }
                }
            } catch { $script:BlockedErrors++ }
        }
    } catch { $script:BlockedErrors++ }
}

function Analyze-HostsNetworkAndDrivers {
    Write-YLine "  > Checking hosts, active network process names, and optional drivers..." "Cyan"
    try {
        $hosts = Join-Path $env:WINDIR "System32\drivers\etc\hosts"
        if (Test-Path $hosts) {
            $txt = Get-Content -LiteralPath $hosts -Raw -ErrorAction SilentlyContinue
            if ($txt -match "(?i)minecraft|mojang|microsoft|xboxlive|launcher|sessionserver|authserver") {
                $bad = $false
                foreach ($line in ($txt -split "`n")) {
                    $l = $line.Trim()
                    if ($l.StartsWith("#") -or $l.Length -lt 5) { continue }
                    if ($l -match "(?i)(minecraft|mojang|sessionserver|authserver|launcher|xboxlive)" -and $l -match "(?i)(127\.0\.0\.1|0\.0\.0\.0|::1)") { $bad = $true }
                }
                if ($bad) { Add-Finding -Object $hosts -ObjectType "HOSTS" -Score 85 -Severity "HIGH" -Class "hosts_redirect_candidate" -Evidence @("hosts redirects game/auth domains to local/null address") }
            }
        }
    } catch { $script:BlockedErrors++ }
    try {
        $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        foreach ($c in $conns) {
            try {
                $p = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
                if (-not $p) { continue }
                $txt = $p.ProcessName + " " + $c.RemoteAddress + ":" + $c.RemotePort
                $hits = Test-AnyTokenInText -Text $txt -Tokens $script:CriticalCheatTokens
                if ($hits.Count -gt 0) {
                    $score = 55 + [Math]::Min(70, $hits.Count * 10)
                    Add-Finding -Object $txt -ObjectType "NETWORK" -Score $score -Severity (Convert-ScoreToSeverity $score) -Class "network_process_candidate" -Evidence @("network owner process token(s): " + (($hits | Select-Object -First 8) -join ", "))
                }
            } catch {}
        }
    } catch { }
    if ($Drivers) {
        try {
            foreach ($drv in Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue) {
                $txt = ([string]$drv.Name + " " + [string]$drv.DisplayName + " " + [string]$drv.PathName + " " + [string]$drv.Description)
                $hits = Test-AnyTokenInText -Text $txt -Tokens ($script:CriticalCheatTokens + $script:StrongEvidenceTokens)
                if ($hits.Count -gt 0) {
                    $score = 65 + [Math]::Min(90, $hits.Count * 12)
                    Add-Finding -Object ("Driver: " + $drv.Name) -ObjectType "DRIVER" -Score $score -Severity (Convert-ScoreToSeverity $score) -Class "driver_candidate" -Evidence @("driver token(s): " + (($hits | Select-Object -First 10) -join ", "), "path: " + [string]$drv.PathName)
                }
            }
        } catch { $script:BlockedErrors++ }
    }
}

function Analyze-VMIndicators {
    if (-not $VMCheck) { return }
    Write-YLine "  > Checking VM/sandbox indicators (informational only)..." "Cyan"
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
        $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
        $txt = ([string]$cs.Manufacturer + " " + [string]$cs.Model + " " + [string]$bios.SerialNumber + " " + [string]$bios.SMBIOSBIOSVersion)
        if ($txt -match "(?i)virtualbox|vmware|qemu|kvm|hyper-v|parallels|xen|sandbox") {
            Add-Finding -Object "System" -ObjectType "VM_INFO" -Score 10 -Severity "INFO" -Class "vm_or_sandbox_indicator" -Evidence @("VM/sandbox indicators: " + $txt)
        }
    } catch {}
}

function Invoke-AmsiOptional {
    if (-not $Amsi) { return }
    Write-YLine "  > AMSI option enabled. PowerShell AMSI direct file scanning is limited; checking suspicious text windows only." "Cyan"
    foreach ($f in @($script:Findings | Where-Object { $_.ObjectType -in @("JAR","EXE","DLL") } | Select-Object -First 80)) {
        try {
            $txt = Read-TextWindowSafe -Path $f.Object -MaxBytes 262144
            if ($txt -match "(?i)(malware|trojan|stealer|keylogger|injector|shellcode)") {
                Add-Finding -Object $f.Object -ObjectType "AMSI_STATIC_HINT" -Score 75 -Severity "HIGH" -Class "amsi_static_text_hint" -Evidence @("static AMSI-like suspicious text hint in file window")
            }
        } catch {}
    }
}

function Invoke-YaraOptional {
    if (-not $Yara) { return }
    Write-YLine "  > YARA option enabled..." "Cyan"
    $exe = $YaraExe
    $rules = $YaraRules
    if (-not $rules -or -not (Test-Path $rules)) {
        $rules = Join-Path $script:TempRoot "yrys_default_rules.yar"
        $ruleText = @(
            "rule YRYS_Minecraft_Cheat_Static_Tokens {",
            "  strings:",
            '    $a1 = "KillAura" nocase',
            '    $a2 = "AimAssist" nocase',
            '    $a3 = "TriggerBot" nocase',
            '    $a4 = "ClickGUI" nocase',
            '    $a5 = "javaagent" nocase',
            '    $a6 = "ClassFileTransformer" nocase',
            '    $a7 = "manualmap" nocase',
            "  condition:",
            "    2 of them",
            "}"
        )
        try { Set-Content -LiteralPath $rules -Value $ruleText -Encoding ASCII -Force } catch {}
    }
    try {
        $targets = @($script:Findings | Where-Object { $_.ObjectType -in @("JAR","EXE","DLL") } | Sort-Object Score -Descending | Select-Object -First 120)
        foreach ($t in $targets) {
            if (-not (Test-Path $t.Object)) { continue }
            try {
                $out = & $exe $rules $t.Object 2>$null
                if ($LASTEXITCODE -eq 0 -and $out) {
                    Add-Finding -Object $t.Object -ObjectType "YARA_MATCH" -Score 115 -Severity "HIGH" -Class "yara_static_match" -Evidence @("YARA matched: " + (($out | Select-Object -First 3) -join " | "))
                }
            } catch {}
        }
    } catch { Write-YLine "  ! YARA failed or yara.exe was not found." "Yellow" }
}

function Invoke-VirusTotalOptional {
    if (-not $VirusTotal) { return }
    if ([string]::IsNullOrWhiteSpace($VirusTotalApiKey)) { Write-YLine "  ! VirusTotal enabled but API key missing. Skipped." "Yellow"; return }
    Write-YLine "  > VirusTotal option enabled: sending SHA256 hashes only, never file contents..." "Cyan"
    $sent = 0
    foreach ($f in @($script:Findings | Where-Object { $_.Sha256 -and $_.ObjectType -in @("JAR","EXE","DLL") } | Sort-Object Score -Descending)) {
        if ($sent -ge $VirusTotalMax) { break }
        try {
            $uri = "https://www.virustotal.com/api/v3/files/" + $f.Sha256
            $r = Invoke-RestMethod -Method Get -Uri $uri -Headers @{ "x-apikey" = $VirusTotalApiKey } -ErrorAction Stop
            $mal = 0; $susp = 0
            try { $mal = [int]$r.data.attributes.last_analysis_stats.malicious; $susp = [int]$r.data.attributes.last_analysis_stats.suspicious } catch {}
            if (($mal + $susp) -gt 0) {
                $score = 95 + [Math]::Min(80, ($mal + $susp) * 5)
                Add-Finding -Object $f.Object -ObjectType "VT_HASH" -Score $score -Severity (Convert-ScoreToSeverity $score) -Class "virustotal_hash_detection" -Evidence @("VirusTotal hash report: malicious=" + $mal + ", suspicious=" + $susp) -Sha256 $f.Sha256
            }
            $sent++
            Start-Sleep -Milliseconds 300
        } catch {
            $sent++
            Start-Sleep -Milliseconds 300
        }
    }
}


function Test-IsAdministratorV15 {
    $checks = New-Object System.Collections.Generic.List[string]
    $ok = $false
    $method = "none"
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object Security.Principal.WindowsPrincipal($id)
        $role = New-Object Security.Principal.SecurityIdentifier("S-1-5-32-544")
        if ($p.IsInRole($role) -or $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            $ok = $true
            $method = "token_role"
            [void]$checks.Add("token_role=ok")
        } else {
            [void]$checks.Add("token_role=no")
        }
    } catch { [void]$checks.Add("token_role=error") }
    try {
        $fltmc = Join-Path $env:WINDIR "System32\fltmc.exe"
        if (Test-Path -LiteralPath $fltmc) {
            $pinfo = New-Object System.Diagnostics.ProcessStartInfo
            $pinfo.FileName = $fltmc
            $pinfo.Arguments = "filters"
            $pinfo.UseShellExecute = $false
            $pinfo.RedirectStandardOutput = $true
            $pinfo.RedirectStandardError = $true
            $pinfo.CreateNoWindow = $true
            $proc = New-Object System.Diagnostics.Process
            $proc.StartInfo = $pinfo
            [void]$proc.Start()
            [void]$proc.WaitForExit(2500)
            if ($proc.ExitCode -eq 0) {
                if (-not $ok) { $method = "fltmc" }
                $ok = $true
                [void]$checks.Add("fltmc=ok")
            } else { [void]$checks.Add("fltmc=exit" + $proc.ExitCode) }
        }
    } catch { [void]$checks.Add("fltmc=error") }
    try {
        $fsutil = Join-Path $env:WINDIR "System32\fsutil.exe"
        if (Test-Path -LiteralPath $fsutil) {
            $pinfo = New-Object System.Diagnostics.ProcessStartInfo
            $pinfo.FileName = $fsutil
            $pinfo.Arguments = "dirty query " + $env:SystemDrive
            $pinfo.UseShellExecute = $false
            $pinfo.RedirectStandardOutput = $true
            $pinfo.RedirectStandardError = $true
            $pinfo.CreateNoWindow = $true
            $proc = New-Object System.Diagnostics.Process
            $proc.StartInfo = $pinfo
            [void]$proc.Start()
            [void]$proc.WaitForExit(2500)
            if ($proc.ExitCode -eq 0) {
                if (-not $ok) { $method = "fsutil" }
                $ok = $true
                [void]$checks.Add("fsutil=ok")
            } else { [void]$checks.Add("fsutil=exit" + $proc.ExitCode) }
        }
    } catch { [void]$checks.Add("fsutil=error") }
    try {
        $testPath = Join-Path $env:WINDIR ("Temp\yrys_admin_" + [Guid]::NewGuid().ToString("N") + ".tmp")
        Set-Content -LiteralPath $testPath -Value "x" -Encoding ASCII -ErrorAction Stop
        Remove-Item -LiteralPath $testPath -Force -ErrorAction SilentlyContinue
        if (-not $ok) { $method = "windows_temp_write" }
        $ok = $true
        [void]$checks.Add("windows_temp_write=ok")
    } catch { [void]$checks.Add("windows_temp_write=no") }
    if (-not $ok) { $method = "not_elevated_or_uac_restricted" }
    return [pscustomobject]@{ IsAdmin = [bool]$ok; Method = $method; Checks = ($checks -join "; ") }
}

function Invoke-ExternalTextLimitedV12 {
    param(
        [string]$FilePath,
        [string]$Arguments,
        [int]$TimeoutSeconds = 7,
        [int]$MaxLines = 1000
    )
    $lines = New-Object System.Collections.Generic.List[string]
    try {
        if ([string]::IsNullOrWhiteSpace($FilePath)) { return @() }
        $tmp = Join-Path $script:TempRoot ("tool_" + [Guid]::NewGuid().ToString("N") + ".txt")
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $FilePath
        $psi.Arguments = $Arguments
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true
        $p = New-Object System.Diagnostics.Process
        $p.StartInfo = $psi
        [void]$p.Start()
        $deadline = (Get-Date).AddSeconds([Math]::Max(2,$TimeoutSeconds))
        while (-not $p.HasExited -and (Get-Date) -lt $deadline -and $lines.Count -lt $MaxLines) {
            try {
                while (-not $p.StandardOutput.EndOfStream -and $lines.Count -lt $MaxLines) {
                    $line = $p.StandardOutput.ReadLine()
                    if ($null -ne $line) { [void]$lines.Add($line) }
                    if ((Get-Date) -gt $deadline) { break }
                }
            } catch { break }
            Start-Sleep -Milliseconds 60
        }
        if (-not $p.HasExited) {
            $script:ExternalToolTimeouts++
            try { $p.Kill() } catch {}
        }
        try {
            while (-not $p.StandardOutput.EndOfStream -and $lines.Count -lt $MaxLines) {
                $line = $p.StandardOutput.ReadLine()
                if ($null -ne $line) { [void]$lines.Add($line) }
            }
        } catch {}
    } catch { $script:BlockedErrors++ }
    return @($lines)
}

function Get-ShannonEntropyV12 {
    param([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Length -le 0) { return 0.0 }
    $counts = New-Object 'int[]' 256
    foreach ($b in $Bytes) { $counts[[int]$b]++ }
    $entropy = 0.0
    $len = [double]$Bytes.Length
    for ($i=0; $i -lt 256; $i++) {
        if ($counts[$i] -gt 0) {
            $p = [double]$counts[$i] / $len
            $entropy -= $p * ([Math]::Log($p,2))
        }
    }
    return [Math]::Round($entropy,3)
}

function Get-FileEntropySampleV12 {
    param([string]$Path, [int]$MaxBytes = 262144)
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return 0.0 }
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $n = [Math]::Min([int64]$MaxBytes, $fs.Length)
            if ($n -le 0) { return 0.0 }
            $buf = New-Object byte[] ([int]$n)
            [void]$fs.Read($buf,0,[int]$n)
            return (Get-ShannonEntropyV12 -Bytes $buf)
        } finally { $fs.Dispose() }
    } catch { return 0.0 }
}

function Get-AdvancedFileSignalsV12 {
    param([string]$Path, [string]$Kind)
    $score = 0
    $ev = New-Object System.Collections.Generic.List[string]
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return [pscustomobject]@{Score=0; Evidence=@()} }
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        if (-not $item) { return [pscustomobject]@{Score=0; Evidence=@()} }
        $p = $Path.ToLowerInvariant()
        if (($Kind -eq "EXE" -or $Kind -eq "DLL") -and ($Deep -or $FullSystem -or $EntropyScan -or $HuntSystem32)) {
            $script:EntropyCheckedCount++
            $entropy = Get-FileEntropySampleV12 -Path $Path -MaxBytes ([Math]::Min($MaxDeepBytes, 524288))
            if ($entropy -ge 7.55 -and $item.Length -gt 32768) {
                $score += 24
                [void]$ev.Add("high entropy binary sample: " + $entropy + " (packed/obfuscated indicator)")
            } elseif ($entropy -ge 7.25 -and (Test-UserWritablePath $Path)) {
                $score += 12
                [void]$ev.Add("elevated entropy in user-writable binary: " + $entropy)
            }
        }
        if ($Deep -or $FullSystem -or $Forensic) {
            $script:TimestompCheckedCount++
            $created = $item.CreationTimeUtc
            $written = $item.LastWriteTimeUtc
            $access = $item.LastAccessTimeUtc
            if ($created.Year -lt 2016 -and $written -gt (Get-Date).ToUniversalTime().AddDays(-90) -and (Test-UserWritablePath $Path)) {
                $score += 18
                [void]$ev.Add("possible timestomp: very old creation time but recent write time")
            }
            if ([Math]::Abs(($created - $written).TotalDays) -gt 1500 -and (Test-UserWritablePath $Path)) {
                $score += 14
                [void]$ev.Add("large creation/write timestamp gap: possible timestomp or restored file")
            }
            if ($p.Contains("\windows\system32\") -or $p.Contains("\windows\syswow64\")) {
                if ($written -gt (Get-Date).ToUniversalTime().AddDays(-30) -and ($Kind -eq "EXE" -or $Kind -eq "DLL")) {
                    $score += 10
                    [void]$ev.Add("recently modified Windows system-area binary")
                }
            }
        }
    } catch {}
    return [pscustomobject]@{Score=$score; Evidence=@($ev)}
}

function Analyze-USNJournalLiteV12 {
    if ($NoUSNJournal -or $NoHeavyForensics -or $OnlyMinecraft) { return }
    if (-not ($Forensic -or $Deep -or $FullSystem)) { return }
    Write-YLine "  > Reading limited NTFS USN Journal traces..." "Cyan"
    try {
        $drives = @()
        foreach ($d in Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue) { if ($d.DeviceID) { $drives += $d.DeviceID } }
        foreach ($drive in $drives) {
            if ((Get-Date) -gt $script:Deadline) { break }
            $args = "usn readjournal " + $drive + " csv"
            $lines = Invoke-ExternalTextLimitedV12 -FilePath "fsutil.exe" -Arguments $args -TimeoutSeconds $ExternalTimeoutSec -MaxLines $USNMaxLines
            foreach ($line in $lines) {
                $l = [string]$line
                if ($l.Length -lt 4) { continue }
                $hits = Test-AnyTokenInText -Text $l -Tokens $script:CriticalCheatTokens
                $extHit = ($l -match "(?i)\.(exe|dll|jar)(,|$|\s)")
                $deleteHit = ($l -match "(?i)(delete|file_delete|close|rename)")
                if ($hits.Count -gt 0 -and $extHit) {
                    $script:USNTraceCount++
                    $score = 55
                    if ($deleteHit) { $score += 15 }
                    Add-Finding -Object ("USN Journal " + $drive + ": " + ($l.Substring(0,[Math]::Min(220,$l.Length)))) -ObjectType "USN_TRACE" -Score $score -Severity (Convert-ScoreToSeverity $score) -Class "deleted_or_renamed_file_trace" -Evidence (@("USN Journal entry contains cheat token(s): " + ($hits -join ", "), "trace may survive deletion/rename", "source is local NTFS journal")) -DeletedTrace
                }
            }
        }
    } catch { $script:BlockedErrors++ }
}

function Analyze-DNSCacheV12 {
    if ($NoDNSCache) { return }
    if (-not ($Forensic -or $Deep -or $FullSystem)) { return }
    Write-YLine "  > Checking DNS cache for cheat service domains..." "Cyan"
    $extraDomains = @("vape.gg","intent.store","riseclient.com","entropy.club","whiteout.lol","slinky.gg","drip.gg","meteorclient.com","liquidbounce.net","wurstclient.net")
    $domainTokens = @($script:CriticalCheatTokens + $extraDomains) | Select-Object -Unique
    try {
        $lines = Invoke-ExternalTextLimitedV12 -FilePath "ipconfig.exe" -Arguments "/displaydns" -TimeoutSeconds $ExternalTimeoutSec -MaxLines 3000
        foreach ($line in $lines) {
            $l = [string]$line
            $hits = Test-AnyTokenInText -Text $l -Tokens $domainTokens
            if ($hits.Count -gt 0) {
                $script:DNSCacheCount++
                $score = 50
                foreach ($h in $hits) { if ($h -match "\.") { $score += 15 } }
                Add-Finding -Object ("DNS cache: " + $l.Trim()) -ObjectType "DNS_TRACE" -Score $score -Severity (Convert-ScoreToSeverity $score) -Class "network_past_contact_trace" -Evidence (@("DNS cache contains cheat/domain token(s): " + ($hits -join ", "), "indicates recent name resolution, not proof of current install")) -DeletedTrace
            }
        }
    } catch { $script:BlockedErrors++ }
}

function Analyze-BitsJobsV12 {
    if (-not ($Forensic -or $Deep -or $FullSystem)) { return }
    Write-YLine "  > Checking BITS jobs for loader/payload traces..." "Cyan"
    try {
        $lines = Invoke-ExternalTextLimitedV12 -FilePath "bitsadmin.exe" -Arguments "/list /allusers /verbose" -TimeoutSeconds $ExternalTimeoutSec -MaxLines 3500
        $buffer = New-Object System.Collections.Generic.List[string]
        foreach ($line in $lines) {
            $l = [string]$line
            if ($l -match "(?i)^(GUID:|DISPLAY:|TYPE:|STATE:|OWNER:)") {
                if ($buffer.Count -gt 0) { $buffer.Clear() }
            }
            [void]$buffer.Add($l)
            $joined = ($buffer -join " ")
            $hits = Test-AnyTokenInText -Text $joined -Tokens $script:CriticalCheatTokens
            if ($hits.Count -gt 0 -or $joined -match "(?i)(appdata|temp|downloads).*(exe|dll|jar)") {
                $script:BitsJobCount++
                $score = 62
                if ($hits.Count -gt 0) { $score += 20 }
                Add-Finding -Object ("BITS job: " + ($joined.Substring(0,[Math]::Min(260,$joined.Length)))) -ObjectType "BITS_JOB" -Score $score -Severity (Convert-ScoreToSeverity $score) -Class "background_download_or_payload_trace" -Evidence (@("BITS job contains suspicious path or cheat token(s): " + ($hits -join ", "), "BITS can be used by loaders to download payloads")) -DeletedTrace
                $buffer.Clear()
            }
        }
    } catch { $script:BlockedErrors++ }
}

function Analyze-FirewallRulesV12 {
    if (-not ($Deep -or $FullSystem -or $Forensic)) { return }
    Write-YLine "  > Checking Windows Firewall application rules..." "Cyan"
    try {
        if (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue) {
            $rules = Get-NetFirewallRule -ErrorAction SilentlyContinue | Select-Object -First 2500
            foreach ($rule in $rules) {
                if ((Get-Date) -gt $script:Deadline) { break }
                try {
                    $apps = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
                    foreach ($app in @($apps)) {
                        $path = [string]$app.Program
                        if ([string]::IsNullOrWhiteSpace($path) -or $path -eq "Any") { continue }
                        $expanded = Get-ExpandedCommandText $path
                        $text = ($rule.DisplayName + " " + $rule.Direction + " " + $rule.Action + " " + $expanded)
                        $hits = Test-AnyTokenInText -Text $text -Tokens $script:CriticalCheatTokens
                        if ($hits.Count -gt 0 -or ($expanded -match "(?i)\\(appdata|temp|downloads)\\.*\.(exe|dll|jar)$")) {
                            $script:FirewallRuleCount++
                            $score = 48
                            if ($hits.Count -gt 0) { $score += 25 }
                            Add-Finding -Object ("Firewall rule: " + $rule.DisplayName + " -> " + $expanded) -ObjectType "FIREWALL_RULE" -Score $score -Severity (Convert-ScoreToSeverity $score) -Class "network_persistence_or_allow_rule" -Evidence (@("firewall rule references suspicious program/path", "token(s): " + ($hits -join ", "))) -DeletedTrace
                            if (Test-Path -LiteralPath $expanded) { Analyze-FileCandidate -Path $expanded -Source "firewall" }
                        }
                    }
                } catch {}
            }
        }
    } catch { $script:BlockedErrors++ }
}

function Analyze-AppCompatAndPcaTracesV12 {
    if (-not ($Forensic -or $Deep -or $FullSystem)) { return }
    Write-YLine "  > Checking AppCompat/PCA execution stores..." "Cyan"
    $keys = @(
        "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
        "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted",
        "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
        "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted"
    )
    foreach ($key in $keys) {
        try {
            if (-not (Test-Path $key)) { continue }
            $props = (Get-ItemProperty -Path $key -ErrorAction SilentlyContinue).PSObject.Properties
            foreach ($prop in $props) {
                $name = [string]$prop.Name
                if ($name.StartsWith("PS")) { continue }
                $hits = Test-AnyTokenInText -Text $name -Tokens $script:CriticalCheatTokens
                if ($hits.Count -gt 0 -or $name -match "(?i)\\(appdata|temp|downloads)\\.*\.(exe|jar|dll)$") {
                    $script:CompatTraceCount++
                    $score = 58
                    if ($hits.Count -gt 0) { $score += 18 }
                    Add-Finding -Object ("AppCompat/PCA: " + $name) -ObjectType "APPCOMPAT_TRACE" -Score $score -Severity (Convert-ScoreToSeverity $score) -Class "execution_history_trace" -Evidence (@("Windows compatibility/PCA store contains suspicious execution path", "token(s): " + ($hits -join ", "))) -DeletedTrace
                    if (Test-Path -LiteralPath $name) { Analyze-FileCandidate -Path $name -Source "compat_trace" }
                }
            }
        } catch { $script:BlockedErrors++ }
    }
}

function Analyze-ShadowCopyHintsV12 {
    if (-not ($FullSystem -or $Forensic) -or $NoHeavyForensics) { return }
    Write-YLine "  > Checking Volume Shadow Copy availability (metadata only)..." "Cyan"
    try {
        $lines = Invoke-ExternalTextLimitedV12 -FilePath "vssadmin.exe" -Arguments "list shadows" -TimeoutSeconds $ExternalTimeoutSec -MaxLines 1200
        $count = @($lines | Where-Object { $_ -match "(?i)Shadow Copy ID|Shadow Copy Volume" }).Count
        if ($count -gt 0) {
            Add-Finding -Object "Volume Shadow Copies available" -ObjectType "VSS_CONTEXT" -Score 20 -Severity "LOW" -Class "forensic_context" -Evidence @("shadow copies exist; deleted Downloads/AppData artifacts may be recoverable manually", "scanner does not mount or copy shadow data to preserve privacy") -DeletedTrace
        }
    } catch { }
}

function Analyze-NamedPipesV12 {
    if ($NoNamedPipes) { return }
    if (-not ($Deep -or $FullSystem -or $Forensic)) { return }
    Write-YLine "  > Checking named pipes for loader/IPC traces..." "Cyan"
    try {
        $pipes = @()
        try { $pipes = [System.IO.Directory]::GetFiles("\\.\pipe\") } catch { $pipes = @() }
        foreach ($pipe in $pipes) {
            $name = [System.IO.Path]::GetFileName($pipe)
            $hits = Test-AnyTokenInText -Text $name -Tokens $script:CriticalCheatTokens
            if ($hits.Count -gt 0 -or $name -match "(?i)(inject|loader|client|java|minecraft|ipc|bridge|clicker|aim|reach)") {
                $script:NamedPipeCount++
                $score = 42
                if ($hits.Count -gt 0) { $score += 30 }
                Add-Finding -Object ("Named pipe: " + $name) -ObjectType "NAMED_PIPE" -Score $score -Severity (Convert-ScoreToSeverity $score) -Class "runtime_ipc_indicator" -Evidence (@("named pipe may indicate loader/client IPC", "token(s): " + ($hits -join ", "))) 
            }
        }
    } catch { $script:BlockedErrors++ }
}

function Analyze-JavaAttachArtifactsV12 {
    if (-not ($Deep -or $FullSystem -or $Forensic -or $OnlyMinecraft)) { return }
    Write-YLine "  > Checking Java Attach API artifacts and jcmd visibility..." "Cyan"
    try {
        $hsRoots = @()
        $hsRoots += Join-Path $env:TEMP ("hsperfdata_" + $env:USERNAME)
        $hsRoots += Join-Path $env:LOCALAPPDATA "Temp"
        foreach ($root in $hsRoots | Select-Object -Unique) {
            if (-not (Test-Path -LiteralPath $root)) { continue }
            foreach ($f in Get-ChildItem -LiteralPath $root -Force -ErrorAction SilentlyContinue | Select-Object -First 300) {
                $text = $f.FullName
                $hits = Test-AnyTokenInText -Text $text -Tokens $script:CriticalCheatTokens
                if ($hits.Count -gt 0 -or $f.Name -match "^(java_pid|hsperfdata|attach_pid)") {
                    $script:JavaAttachCount++
                    $score = 32
                    if ($hits.Count -gt 0) { $score += 35 }
                    Add-Finding -Object ("Java attach/perf artifact: " + $f.FullName) -ObjectType "JAVA_ATTACH_TRACE" -Score $score -Severity (Convert-ScoreToSeverity $score) -Class "java_attach_or_perfdata_trace" -Evidence (@("Java Attach/perfdata artifact found", "token(s): " + ($hits -join ", "))) -DeletedTrace
                }
            }
        }
        $jcmd = Get-Command jcmd.exe -ErrorAction SilentlyContinue
        if ($jcmd) {
            $lines = Invoke-ExternalTextLimitedV12 -FilePath $jcmd.Source -Arguments "-l" -TimeoutSeconds $ExternalTimeoutSec -MaxLines 600
            foreach ($line in $lines) {
                $hits = Test-AnyTokenInText -Text $line -Tokens $script:CriticalCheatTokens
                if ($hits.Count -gt 0 -or $line -match "(?i)(minecraft|fabric|forge|quilt|lwjgl)") {
                    $script:JavaAttachCount++
                    $score = 45
                    if ($hits.Count -gt 0) { $score += 30 }
                    Add-Finding -Object ("jcmd JVM: " + $line.Trim()) -ObjectType "JAVA_JCMD" -Score $score -Severity (Convert-ScoreToSeverity $score) -Class "live_jvm_context" -Evidence (@("jcmd sees live JVM matching Minecraft or cheat token", "token(s): " + ($hits -join ", "))) 
                }
            }
        }
    } catch { $script:BlockedErrors++ }
}

function Analyze-LwjglIntegrityV12 {
    if (-not ($Deep -or $FullSystem -or $OnlyMinecraft)) { return }
    Write-YLine "  > Checking LWJGL/native Minecraft libraries for anomalies..." "Cyan"
    try {
        $roots = Get-RootSet | Select-Object -Unique
        foreach ($root in $roots) {
            if ((Get-Date) -gt $script:Deadline) { break }
            if (-not (Test-Path -LiteralPath $root)) { continue }
            foreach ($f in Get-ChildItem -LiteralPath $root -Recurse -Force -File -Include "lwjgl*.dll","glfw*.dll","OpenAL*.dll" -ErrorAction SilentlyContinue | Select-Object -First 700) {
                $script:LwjglCheckedCount++
                $p = $f.FullName.ToLowerInvariant()
                $score = 0
                $ev = New-Object System.Collections.Generic.List[string]
                [void]$ev.Add("LWJGL/native library candidate used by Minecraft")
                if (Test-UserWritablePath $f.FullName) { $score += 16; [void]$ev.Add("native library located in user-writable area") }
                if ($f.LastWriteTime -gt (Get-Date).AddDays(-45)) { $score += 10; [void]$ev.Add("native library modified recently") }
                $sig = Get-AuthenticodeInfoSafe $f.FullName
                if ($sig.Status -ne "Valid") { $score += 15; [void]$ev.Add("native library is unsigned or invalid signature") }
                $sample = Read-TextWindowSafe -Path $f.FullName -MaxBytes ([Math]::Min($MaxDeepBytes, 262144))
                $hits = Test-AnyTokenInText -Text ($p + " " + $sample) -Tokens $script:CriticalCheatTokens
                if ($hits.Count -gt 0) { $score += 45; [void]$ev.Add("LWJGL/native library contains cheat token(s): " + ($hits -join ", ")) }
                $entropy = Get-FileEntropySampleV12 -Path $f.FullName -MaxBytes 262144
                if ($entropy -ge 7.55) { $score += 18; [void]$ev.Add("high entropy native library: " + $entropy) }
                if ($score -ge 28) {
                    Analyze-FileCandidate -Path $f.FullName -Source "lwjgl"
                    Add-Finding -Object $f.FullName -ObjectType "LWJGL_NATIVE" -Score $score -Severity (Convert-ScoreToSeverity $score) -Class "minecraft_native_library_anomaly" -Evidence @($ev)
                }
            }
        }
    } catch { $script:BlockedErrors++ }
}

function Analyze-ProcessParentAndAntiEvasionV12 {
    if (-not ($Deep -or $FullSystem -or $Forensic)) { return }
    Write-YLine "  > Checking process parent logic and anti-evasion context..." "Cyan"
    try {
        $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
        $byPid = @{}
        foreach ($p in $procs) { $byPid[[int]$p.ProcessId] = $p }
        foreach ($p in $procs) {
            $name = [string]$p.Name
            $cmd = [string]$p.CommandLine
            $parent = $null
            if ($byPid.ContainsKey([int]$p.ParentProcessId)) { $parent = $byPid[[int]$p.ParentProcessId] }
            $parentName = ""
            if ($parent) { $parentName = [string]$parent.Name }
            $text = ($name + " " + $cmd + " parent=" + $parentName)
            $hits = Test-AnyTokenInText -Text $text -Tokens $script:CriticalCheatTokens
            if (($name -match "(?i)^(java|javaw|minecraft|launcher)" -and $parentName -match "(?i)(powershell|wscript|cscript|rundll32|regsvr32|mshta)") -or $hits.Count -gt 0) {
                $score = 50
                if ($hits.Count -gt 0) { $score += 30 }
                $cmdShort = ""
                if ($cmd) { $cmdShort = $cmd.Substring(0,[Math]::Min(220,$cmd.Length)) }
                $evp = @("process parent chain is unusual for game/JVM or contains cheat token", "token(s): " + ($hits -join ", "), "cmd: " + $cmdShort)
                Add-Finding -Object ("Process parent: " + $name + " PID=" + $p.ProcessId + " Parent=" + $parentName) -ObjectType "PROCESS_PARENT" -Score $score -Severity (Convert-ScoreToSeverity $score) -Class "process_parent_or_ppid_anomaly" -Evidence $evp
            }
        }
        $self = Get-Process -Id $PID -ErrorAction SilentlyContinue
        if ($self) {
            $mods = @($self.Modules | Select-Object -ExpandProperty ModuleName -ErrorAction SilentlyContinue)
            if ($Amsi -and -not ($mods -contains "amsi.dll")) {
                Add-Finding -Object "Current PowerShell session" -ObjectType "ANTI_EVASION_CONTEXT" -Score 35 -Severity "LOW" -Class "amsi_context_warning" -Evidence @("AMSI option requested but amsi.dll module was not visible in current process", "not proof of patching; run as administrator and verify")
            }
        }
    } catch { $script:BlockedErrors++ }
}

function Analyze-RdpBitmapCacheHintsV12 {
    if (-not ($Forensic -or $FullSystem) -or $NoHeavyForensics) { return }
    try {
        $paths = @(
            (Join-Path $env:LOCALAPPDATA "Microsoft\Terminal Server Client\Cache"),
            (Join-Path $env:LOCALAPPDATA "Microsoft\Terminal Server Client\Cache\"),
            (Join-Path $env:APPDATA "AnyDesk"),
            (Join-Path $env:PROGRAMDATA "AnyDesk")
        ) | Select-Object -Unique
        foreach ($p in $paths) {
            if (Test-Path -LiteralPath $p) {
                $files = @(Get-ChildItem -LiteralPath $p -Force -File -ErrorAction SilentlyContinue | Select-Object -First 80)
                if ($files.Count -gt 0) {
                    Add-Finding -Object ("Remote/bitmap cache location: " + $p) -ObjectType "REMOTE_CACHE_CONTEXT" -Score 20 -Severity "LOW" -Class "forensic_context" -Evidence @("remote desktop/AnyDesk cache exists", "this is context only; visual cache is not parsed or saved") -DeletedTrace
                }
            }
        }
    } catch {}
}

function Analyze-BehavioralChainsV12 {
    if ($NoBehaviorChains) { return }
    Write-YLine "  > Building behavior chains from evidence..." "Cyan"
    try {
        $tokens = @($script:UserCheatTokens + $script:CriticalCheatTokens) | Where-Object { $_ -and $_.Length -ge 4 -and -not ($script:NeverStrongAlone -contains $_) } | Select-Object -Unique | Select-Object -First 180
        foreach ($tok in $tokens) {
            $matches = @($script:Findings | Where-Object { (($_.Object + " " + ($_.Evidence -join " ")).ToLowerInvariant()).Contains($tok.ToLowerInvariant()) })
            if ($matches.Count -lt 2) { continue }
            $classes = @($matches | Select-Object -ExpandProperty Class -Unique)
            $types = @($matches | Select-Object -ExpandProperty ObjectType -Unique)
            $hasTrace = @($matches | Where-Object { $_.DeletedTrace }).Count -gt 0
            $hasRuntime = @($matches | Where-Object { $_.ObjectType -match "PROCESS|JAVA|PIPE|MODULE|JVM" }).Count -gt 0
            $hasFile = @($matches | Where-Object { $_.ObjectType -match "EXE|DLL|JAR|LWJGL" }).Count -gt 0
            $hasPersistence = @($matches | Where-Object { $_.Class -match "autorun|firewall|bits|persistence|scheduled|debugger|appinit" }).Count -gt 0
            $score = 55 + ([Math]::Min(5,$classes.Count) * 10) + ([Math]::Min(5,$types.Count) * 6)
            if ($hasTrace) { $score += 10 }
            if ($hasRuntime) { $score += 25 }
            if ($hasFile) { $score += 20 }
            if ($hasPersistence) { $score += 25 }
            if ($score -ge 85) {
                $script:BehaviorChainCount++
                Add-Finding -Object ("Behavior chain for token: " + $tok) -ObjectType "BEHAVIOR_CHAIN" -Score $score -Severity (Convert-ScoreToSeverity $score) -Class "behavioral_chain_ai_v2" -Evidence (@("behavior chain connects multiple evidence sources for token: " + $tok, "classes: " + ($classes -join ", "), "object types: " + ($types -join ", "), "runtime=" + $hasRuntime + " file=" + $hasFile + " trace=" + $hasTrace + " persistence=" + $hasPersistence))
            }
        }
    } catch { $script:BlockedErrors++ }
}


function Get-V13SuspiciousTextHits {
    param([string]$Text, [string[]]$ExtraTokens = @())
    $hits = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    $tokens = New-Object System.Collections.Generic.List[string]
    foreach ($t in @($script:CriticalCheatTokens + $ExtraTokens)) {
        $n = Normalize-Token $t
        if ($n.Length -ge 3 -and -not $tokens.Contains($n)) { [void]$tokens.Add($n) }
    }
    foreach ($t in $tokens) {
        if ($Text.ToLowerInvariant().Contains($t.ToLowerInvariant())) { [void]$hits.Add($t) }
    }
    return @($hits | Select-Object -Unique)
}

function Test-V13LikelyDefaultSerial {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $true }
    $v = $Value.Trim().ToLowerInvariant()
    $bad = @('default string','to be filled by o.e.m.','to be filled by oem','system serial number','none','null','unknown','not specified','not available','00000000','11111111','123456789','abcdef','o.e.m.','oem','base board serial number','serial number')
    foreach ($b in $bad) { if ($v -eq $b -or $v.Contains($b)) { return $true } }
    if ($v.Length -lt 4) { return $true }
    if ($v -match '^[0]+$') { return $true }
    if ($v -match '^[f]+$') { return $true }
    if ($v -match '^[x]{5,}$') { return $true }
    return $false
}

function Get-V13RegistryTextSafe {
    param([string]$Path)
    $out = New-Object System.Collections.Generic.List[string]
    try {
        $item = Get-ItemProperty -Path $Path -ErrorAction Stop
        foreach ($p in $item.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            if ($null -ne $p.Value) { [void]$out.Add(($p.Name + '=' + [string]$p.Value)) }
        }
    } catch {}
    return (@($out) -join ' ; ')
}

function Add-V13EvidenceFinding {
    param(
        [string]$Object,
        [string]$Type,
        [int]$Score,
        [string]$Class,
        [string[]]$Evidence,
        [switch]$Trace
    )
    $sev = Convert-ScoreToSeverity $Score
    Add-Finding -Object $Object -ObjectType $Type -Score $Score -Severity $sev -Class $Class -Evidence $Evidence -DeletedTrace:([bool]$Trace)
}

function Analyze-HWIDSpoofingV13 {
    if ($NoHWIDSpoofing) { return }
    if (-not ($FullSystem -or $Forensic -or $HWIDForensics)) { return }
    Write-YLine '  > v13: HWID/Spoofer artifacts...' 'White'
    try {
        $serialEvidence = New-Object System.Collections.Generic.List[string]
        $items = @()
        try { $items += Get-CimInstance Win32_BIOS -ErrorAction Stop | Select-Object @{n='Area';e={'BIOS'}},SerialNumber,Manufacturer,SMBIOSBIOSVersion } catch {}
        try { $items += Get-CimInstance Win32_BaseBoard -ErrorAction Stop | Select-Object @{n='Area';e={'BaseBoard'}},SerialNumber,Manufacturer,Product } catch {}
        try { $items += Get-CimInstance Win32_ComputerSystemProduct -ErrorAction Stop | Select-Object @{n='Area';e={'ComputerSystemProduct'}},IdentifyingNumber,Vendor,Name,UUID } catch {}
        try { $items += Get-CimInstance Win32_DiskDrive -ErrorAction Stop | Select-Object @{n='Area';e={'DiskDrive'}},SerialNumber,Model,InterfaceType,PNPDeviceID } catch {}
        foreach ($it in $items) {
            foreach ($prop in @('SerialNumber','IdentifyingNumber','UUID')) {
                if ($it.PSObject.Properties.Name -contains $prop) {
                    $val = [string]$it.$prop
                    if (Test-V13LikelyDefaultSerial $val) { [void]$serialEvidence.Add(($it.Area + ' has weak/default ' + $prop + ': ' + $val)) }
                }
            }
        }
        $biosReg = Get-V13RegistryTextSafe 'HKLM:\HARDWARE\DESCRIPTION\System\BIOS'
        if ($biosReg) {
            foreach ($needle in @('BaseBoardSerialNumber','SystemSerialNumber','BIOSVendor','SystemManufacturer')) {
                if ($biosReg.ToLowerInvariant().Contains($needle.ToLowerInvariant())) { }
            }
        }
        if ($serialEvidence.Count -gt 0) {
            $script:HWIDAnomalyCount++
            Add-V13EvidenceFinding -Object 'SMBIOS/WMI hardware identifiers' -Type 'HWID' -Score ([Math]::Min(95, 35 + ($serialEvidence.Count * 12))) -Class 'hwid_spoofing_suspicion' -Evidence @($serialEvidence | Select-Object -First 8)
        }
    } catch { $script:BlockedErrors++ }
}

function Analyze-KDMapperAndVulnerableDriverTracesV13 {
    if ($NoKDMapperTrace) { return }
    if (-not ($FullSystem -or $Forensic -or $Drivers)) { return }
    Write-YLine '  > v13: kdmapper/drvmap/vulnerable-driver traces...' 'White'
    $tokens = @('kdmapper','drvmap','iqvw64e','iqvw64e.sys','capcom.sys','gdrv.sys','dbutil_2_3.sys','rtcore64.sys','aswarpot.sys','ksdumper','physmem','mapdriver','kernelmapper','vulndriver')
    $roots = New-Object System.Collections.Generic.List[string]
    foreach ($r in @((Join-Path $env:WINDIR 'System32\drivers'), $env:TEMP, (Join-Path $env:USERPROFILE 'Downloads'), (Join-Path $env:APPDATA ''), (Join-Path $env:LOCALAPPDATA 'Temp'))) {
        if ($r -and (Test-Path $r) -and -not $roots.Contains($r)) { [void]$roots.Add($r) }
    }
    foreach ($root in $roots) {
        try {
            Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue -File | Where-Object { $_.Extension -match '^\.(sys|exe|dll|pf|log|txt)$' } | Select-Object -First 900 | ForEach-Object {
                if (Test-Deadline) { return }
                $name = $_.Name.ToLowerInvariant()
                $matched = @($tokens | Where-Object { $name.Contains($_) })
                if ($matched.Count -gt 0) {
                    $script:KDMapperTraceCount++
                    Add-V13EvidenceFinding -Object $_.FullName -Type (Get-ObjectKindFromPath $_.FullName) -Score 120 -Class 'kernel_mapper_or_vulnerable_driver_trace' -Evidence @('filename matches kernel mapper/vulnerable driver token: ' + (($matched | Select-Object -First 4) -join ', '),'common HWID spoofer/private cheat loader driver artifact') -Trace
                }
            }
        } catch { $script:BlockedErrors++ }
    }
    try {
        Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | ForEach-Object {
            $txt = (([string]$_.Name) + ' ' + ([string]$_.DisplayName) + ' ' + ([string]$_.PathName)).ToLowerInvariant()
            $hit = @($tokens | Where-Object { $txt.Contains($_) })
            if ($hit.Count -gt 0) {
                $script:KDMapperTraceCount++
                Add-V13EvidenceFinding -Object ('driver: ' + $_.Name + ' ' + $_.PathName) -Type 'DRIVER' -Score 130 -Class 'loaded_or_registered_vulnerable_driver' -Evidence @('driver/service text matches kernel mapper token: ' + (($hit | Select-Object -First 4) -join ', '),'registered driver can be used by spoofers/loaders')
            }
        }
    } catch { $script:BlockedErrors++ }
}

function Get-V13RecentLnkTarget {
    param([string]$Path)
    try {
        $shell = New-Object -ComObject WScript.Shell
        $sc = $shell.CreateShortcut($Path)
        return [string]$sc.TargetPath
    } catch { return '' }
}

function Analyze-USBForensicsV13 {
    if ($NoUSBForensics) { return }
    if (-not ($FullSystem -or $Forensic -or $USBForensics)) { return }
    Write-YLine '  > v13: USB/PnP removable traces...' 'White'
    try {
        $usbRoot = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'
        if (Test-Path $usbRoot) {
            Get-ChildItem -Path $usbRoot -ErrorAction SilentlyContinue | ForEach-Object {
                $devName = $_.PSChildName
                Get-ChildItem -Path $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
                    $text = Get-V13RegistryTextSafe $_.PSPath
                    $score = 30
                    $ev = @('USBSTOR history entry: ' + $devName, 'device instance: ' + $_.PSChildName)
                    $hits = Get-V13SuspiciousTextHits -Text ($devName + ' ' + $_.PSChildName + ' ' + $text)
                    if ($hits.Count -gt 0) { $score += 50; $ev += ('USB metadata contains cheat token: ' + (($hits | Select-Object -First 5) -join ', ')) }
                    $script:USBTraceCount++
                    if ($score -ge 55 -or $ShowIgnored) { Add-V13EvidenceFinding -Object ('USBSTOR\' + $devName + '\' + $_.PSChildName) -Type 'USB_TRACE' -Score $score -Class 'usb_storage_trace' -Evidence $ev -Trace }
                }
            }
        }
    } catch { $script:BlockedErrors++ }
    try {
        $recent = Join-Path $env:APPDATA 'Microsoft\Windows\Recent'
        if (Test-Path $recent) {
            Get-ChildItem -LiteralPath $recent -Filter '*.lnk' -Force -ErrorAction SilentlyContinue | Select-Object -First 1200 | ForEach-Object {
                $target = Get-V13RecentLnkTarget $_.FullName
                if ($target -match '^[D-Z]:\\') {
                    $exists = Test-Path ([System.IO.Path]::GetPathRoot($target))
                    $hits = Get-V13SuspiciousTextHits -Text ($target + ' ' + $_.Name)
                    if ((-not $exists) -or $hits.Count -gt 0) {
                        $script:USBTraceCount++
                        $score = 45
                        $ev = @('Recent shortcut points to removable/non-system drive: ' + $target)
                        if (-not $exists) { $score += 20; $ev += 'drive root is not currently present' }
                        if ($hits.Count -gt 0) { $score += 45; $ev += ('shortcut/target contains cheat token: ' + (($hits | Select-Object -First 5) -join ', ')) }
                        Add-V13EvidenceFinding -Object $_.FullName -Type 'LNK' -Score $score -Class 'usb_lnk_execution_trace' -Evidence $ev -Trace
                    }
                }
            }
        }
    } catch { $script:BlockedErrors++ }
    try {
        $providers = @('Microsoft-Windows-DriverFrameworks-UserMode/Operational','System')
        foreach ($log in $providers) {
            Get-WinEvent -LogName $log -MaxEvents 300 -ErrorAction SilentlyContinue | ForEach-Object {
                $msg = [string]$_.Message
                if ($msg -match '(USBSTOR|USB Mass Storage|Disk&Ven|removable)' ) {
                    $hits = Get-V13SuspiciousTextHits -Text $msg
                    if ($hits.Count -gt 0) {
                        $script:USBTraceCount++
                        Add-V13EvidenceFinding -Object ('EventLog ' + $log + ' id=' + $_.Id + ' time=' + $_.TimeCreated) -Type 'EVENTLOG' -Score 90 -Class 'usb_event_with_cheat_context' -Evidence @('USB/PnP event contains cheat token: ' + (($hits | Select-Object -First 5) -join ', ')) -Trace
                    }
                }
            }
        }
    } catch { $script:BlockedErrors++ }
}

function Analyze-WMIAndIFEOPersistenceV13 {
    if ($NoWMIForensics) { return }
    if (-not ($FullSystem -or $Forensic -or $WMIForensics)) { return }
    Write-YLine '  > v13: WMI fileless persistence and IFEO SilentProcessExit...' 'White'
    try {
        foreach ($cls in @('__EventFilter','CommandLineEventConsumer','ActiveScriptEventConsumer','__FilterToConsumerBinding')) {
            Get-CimInstance -Namespace 'root\subscription' -ClassName $cls -ErrorAction SilentlyContinue | ForEach-Object {
                $txt = ($_ | Out-String)
                $hits = Get-V13SuspiciousTextHits -Text $txt -ExtraTokens @('powershell','encodedcommand','javaw.exe','minecraft','appdata','temp','http','download','bitsadmin','mshta','rundll32','regsvr32')
                if ($hits.Count -gt 0) {
                    $script:WMIPersistenceCount++
                    $score = 75
                    if (($hits -contains 'encodedcommand') -or ($hits -contains 'powershell') -or ($hits -contains 'javaw.exe')) { $score += 30 }
                    Add-V13EvidenceFinding -Object ('WMI root\subscription ' + $cls) -Type 'WMI' -Score $score -Class 'wmi_event_subscription_persistence' -Evidence @('WMI subscription text contains suspicious tokens: ' + (($hits | Select-Object -First 8) -join ', '),'fileless persistence can execute without visible exe on disk')
                }
            }
        }
    } catch { $script:BlockedErrors++ }
    try {
        $paths = @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\SilentProcessExit')
        foreach ($p in $paths) {
            if (-not (Test-Path $p)) { continue }
            Get-ChildItem -Path $p -ErrorAction SilentlyContinue | ForEach-Object {
                $text = Get-V13RegistryTextSafe $_.PSPath
                $hits = Get-V13SuspiciousTextHits -Text ($_.PSChildName + ' ' + $text) -ExtraTokens @('monitorprocess','reportingmode','javaw.exe','minecraft','powershell','cmd.exe','rundll32','appdata','temp')
                if ($hits.Count -gt 0) {
                    $script:WMIPersistenceCount++
                    Add-V13EvidenceFinding -Object ('IFEO SilentProcessExit: ' + $_.PSChildName) -Type 'REGISTRY' -Score 95 -Class 'ifeo_silentprocessexit_persistence' -Evidence @('SilentProcessExit key contains suspicious tokens: ' + (($hits | Select-Object -First 8) -join ', '), $text)
                }
            }
        }
    } catch { $script:BlockedErrors++ }
}

function Get-V13BrowserArtifactPaths {
    $paths = New-Object System.Collections.Generic.List[string]
    $candidates = @(
        (Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data'),
        (Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data'),
        (Join-Path $env:LOCALAPPDATA 'BraveSoftware\Brave-Browser\User Data'),
        (Join-Path $env:APPDATA 'Mozilla\Firefox\Profiles')
    )
    foreach ($root in $candidates) {
        if (-not (Test-Path $root)) { continue }
        try {
            Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue -File | Where-Object { $_.Name -in @('History','Web Data','places.sqlite','downloads.sqlite') } | Select-Object -First 80 | ForEach-Object { [void]$paths.Add($_.FullName) }
        } catch {}
    }
    return @($paths | Select-Object -Unique)
}

function Analyze-BrowserDownloadTracesV13 {
    if ($NoBrowserForensics) { return }
    if (-not ($FullSystem -or $Forensic -or $BrowserForensics)) { return }
    Write-YLine '  > v13: browser download/history artifacts (local token scan only)...' 'White'
    $extra = @('intent.store','vape.gg','whiteout.lol','entropy.club','slinky.gg','riseclient.com','spezz.exchange','drip.gg','neverlack','loader','injector','clicker','autoclicker','download')
    foreach ($p in Get-V13BrowserArtifactPaths) {
        try {
            $txt = Read-TextWindowSafe -Path $p -MaxBytes ([Math]::Max($MaxDeepBytes, 2097152))
            $hits = Get-V13SuspiciousTextHits -Text $txt -ExtraTokens $extra
            if ($hits.Count -gt 0) {
                $script:BrowserTraceCount++
                $score = 65
                if (@($hits | Where-Object { $_ -match 'vape|intent|whiteout|entropy|slinky|rise|drip' }).Count -gt 0) { $score += 35 }
                Add-V13EvidenceFinding -Object $p -Type 'BROWSER_DB' -Score $score -Class 'browser_download_or_history_trace' -Evidence @('browser artifact contains suspicious download/domain token: ' + (($hits | Select-Object -First 10) -join ', '),'only local artifact bytes were scanned; no browser database was copied permanently') -Trace
            }
        } catch { $script:BlockedErrors++ }
    }
}

function Analyze-DiscordCacheV13 {
    if ($NoDiscordForensics) { return }
    if (-not ($FullSystem -or $Forensic -or $DiscordForensics)) { return }
    Write-YLine '  > v13: Discord cache/LevelDB artifacts (local token scan only)...' 'White'
    $roots = @(
        (Join-Path $env:APPDATA 'discord'),
        (Join-Path $env:APPDATA 'discordcanary'),
        (Join-Path $env:APPDATA 'discordptb'),
        (Join-Path $env:LOCALAPPDATA 'Discord')
    )
    $extra = @('cdn.discordapp.com','media.discordapp.net','attachments','vape','raven','rise','drip','entropy','whiteout','slinky','loader','injector','clicker','jar')
    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        try {
            Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue -File | Where-Object { $_.Extension -match '^\.(ldb|log|sqlite|cache|tmp)$' -or $_.DirectoryName -match '(Cache|Code Cache|leveldb)' } | Select-Object -First 900 | ForEach-Object {
                if (Test-Deadline) { return }
                $txt = Read-TextWindowSafe -Path $_.FullName -MaxBytes ([Math]::Min([Math]::Max($MaxDeepBytes, 1048576), 3145728))
                $hits = Get-V13SuspiciousTextHits -Text $txt -ExtraTokens $extra
                if ($hits.Count -gt 0) {
                    $script:DiscordTraceCount++
                    $score = 55
                    if (@($hits | Where-Object { $_ -match 'vape|raven|rise|drip|entropy|whiteout|slinky' }).Count -gt 0) { $score += 45 }
                    Add-V13EvidenceFinding -Object $_.FullName -Type 'DISCORD_CACHE' -Score $score -Class 'discord_cache_cheat_delivery_trace' -Evidence @('Discord cache/LevelDB contains suspicious token: ' + (($hits | Select-Object -First 10) -join ', '),'possible delivery/download trace; not proof of active installed cheat') -Trace
                }
            }
        } catch { $script:BlockedErrors++ }
    }
}

function Analyze-PeripheralMacroProfilesV13 {
    if ($NoInputMacroScan) { return }
    if (-not ($FullSystem -or $Forensic -or $InputMacroScan)) { return }
    Write-YLine '  > v13: peripheral macro profiles...' 'White'
    $roots = @(
        (Join-Path $env:LOCALAPPDATA 'LGHUB'),
        (Join-Path $env:APPDATA 'LGHUB'),
        (Join-Path $env:LOCALAPPDATA 'Razer'),
        (Join-Path $env:APPDATA 'Razer'),
        (Join-Path $env:PROGRAMDATA 'Razer'),
        (Join-Path $env:PROGRAMDATA 'SteelSeries'),
        (Join-Path $env:APPDATA 'SteelSeries'),
        (Join-Path $env:APPDATA 'Corsair'),
        (Join-Path $env:LOCALAPPDATA 'Corsair'),
        (Join-Path $env:PROGRAMDATA 'Bloody7'),
        (Join-Path $env:APPDATA 'Bloody7')
    )
    $macroTokens = @('lua','macro','autoclick','auto click','click_delay','delay_ms','sleep(15','sleep(10','sleep 15','mouse_event','sendinput','norecoil','no recoil','rapidfire','rapid fire','leftbutton','button1','cps')
    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        try {
            Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue -File | Where-Object { $_.Extension -match '^\.(json|xml|lua|cfg|ini|db|sqlite|txt)$' } | Select-Object -First 900 | ForEach-Object {
                if (Test-Deadline) { return }
                $txt = Read-TextWindowSafe -Path $_.FullName -MaxBytes ([Math]::Min($MaxDeepBytes, 1048576))
                $hits = Get-V13SuspiciousTextHits -Text $txt -ExtraTokens $macroTokens
                if ($hits.Count -gt 0) {
                    $script:MacroProfileCount++
                    $score = 45
                    if (@($hits | Where-Object { $_ -match 'autoclick|click|cps|rapid|norecoil|mouse_event|sendinput' }).Count -gt 0) { $score += 35 }
                    Add-V13EvidenceFinding -Object $_.FullName -Type 'MACRO_PROFILE' -Score $score -Class 'peripheral_macro_profile_suspicion' -Evidence @('peripheral profile contains macro/input token: ' + (($hits | Select-Object -First 10) -join ', '),'review manually: gaming peripheral macros can be legitimate or cheating depending on server rules')
                }
            }
        } catch { $script:BlockedErrors++ }
    }
}

function Analyze-BehavioralChainsV13 {
    if ($NoBehaviorChains) { return }
    Write-YLine '  > v13: advanced behavior-chain correlation...' 'White'
    try {
        $classes = @($script:Findings | ForEach-Object { $_.Class })
        $hasUSB = @($classes | Where-Object { $_ -match 'usb' }).Count -gt 0
        $hasBrowser = @($classes | Where-Object { $_ -match 'browser|discord' }).Count -gt 0
        $hasMapper = @($classes | Where-Object { $_ -match 'mapper|vulnerable_driver|kernel' }).Count -gt 0
        $hasWMI = @($classes | Where-Object { $_ -match 'wmi|ifeo' }).Count -gt 0
        $hasJava = @($classes | Where-Object { $_ -match 'java|jvm|minecraft|jar|attach|lwjgl' }).Count -gt 0
        $hasDeleted = @($script:Findings | Where-Object { $_.DeletedTrace }).Count -gt 0
        if ($hasUSB -and $hasJava) {
            $script:V13BehaviorChainCount++
            Add-V13EvidenceFinding -Object 'USB-to-Minecraft execution pattern' -Type 'BEHAVIOR_CHAIN' -Score 115 -Class 'behavior_chain_usb_java_minecraft' -Evidence @('USB/removable trace exists','Java/Minecraft/JAR evidence exists','common pattern: run loader from removable device then launch game') -Trace
        }
        if ($hasBrowser -and $hasDeleted) {
            $script:V13BehaviorChainCount++
            Add-V13EvidenceFinding -Object 'Download-to-deleted-trace pattern' -Type 'BEHAVIOR_CHAIN' -Score 110 -Class 'behavior_chain_browser_deleted_loader' -Evidence @('browser/Discord delivery trace exists','deleted/execution trace exists','common pattern: download loader, execute, delete') -Trace
        }
        if ($hasMapper -and $hasJava) {
            $script:V13BehaviorChainCount++
            Add-V13EvidenceFinding -Object 'Kernel mapper plus Minecraft pattern' -Type 'BEHAVIOR_CHAIN' -Score 135 -Class 'behavior_chain_kernel_mapper_minecraft' -Evidence @('kernel mapper/vulnerable driver trace exists','Java/Minecraft evidence exists','strong pattern for HWID spoofers or private cheat loaders')
        }
        if ($hasWMI -and $hasJava) {
            $script:V13BehaviorChainCount++
            Add-V13EvidenceFinding -Object 'Fileless persistence plus Minecraft pattern' -Type 'BEHAVIOR_CHAIN' -Score 125 -Class 'behavior_chain_wmi_ifeo_java' -Evidence @('WMI/IFEO persistence indicator exists','Java/Minecraft evidence exists','possible fileless loader trigger around game launch')
        }
    } catch { $script:BlockedErrors++ }
}

function Invoke-AutonomousForensicsV13 {
    Write-YLine '  > v13 autonomous modules: HWID/USB/WMI/Browser/Discord/Macros/kdmapper/chains' 'White'
    Analyze-HWIDSpoofingV13
    Analyze-KDMapperAndVulnerableDriverTracesV13
    Analyze-USBForensicsV13
    Analyze-WMIAndIFEOPersistenceV13
    Analyze-BrowserDownloadTracesV13
    Analyze-DiscordCacheV13
    Analyze-PeripheralMacroProfilesV13
}

function Invoke-AutonomousForensicsV12 {
    Write-YLine "  > v12 autonomous modules: USN/DNS/BITS/Firewall/AppCompat/Pipes/JavaAttach/LWJGL/AntiEvasion" "White"
    Analyze-DNSCacheV12
    Analyze-BitsJobsV12
    Analyze-FirewallRulesV12
    Analyze-AppCompatAndPcaTracesV12
    Analyze-NamedPipesV12
    Analyze-JavaAttachArtifactsV12
    Analyze-LwjglIntegrityV12
    Analyze-ProcessParentAndAntiEvasionV12
    Analyze-ShadowCopyHintsV12
    Analyze-RdpBitmapCacheHintsV12
    Analyze-USNJournalLiteV12
}

function Initialize-BrainTokens {
    $tokens = New-Object System.Collections.Generic.List[string]
    foreach ($r in $script:YrysKbRules) {
        if ($r.Weight -ge 35) {
            $t = Normalize-Token $r.Token
            if ($t.Length -ge 3 -and -not $tokens.Contains($t)) { [void]$tokens.Add($t) }
        }
    }
    foreach ($t in Split-InputTokens $Cheat) { if (-not $tokens.Contains($t)) { [void]$tokens.Add($t) } }
    if (-not $NoPrompt -and [string]::IsNullOrWhiteSpace($Cheat)) {
        Write-YLine "Enter possible cheat names/keywords separated by comma." "White"
        Write-YLine "Example: vape, raven, rise, drip, entropy, whiteout, slinky" "DarkGray"
        $typed = Read-Host "Cheats"
        foreach ($t in Split-InputTokens $typed) { if (-not $tokens.Contains($t)) { [void]$tokens.Add($t) } }
    }
    $script:CriticalCheatTokens = @($tokens | Where-Object { $_ -and $_.Length -ge 3 } | Select-Object -Unique)
    Write-YLine ("  + Brain tokens loaded: " + $script:CriticalCheatTokens.Count) "Green"
}


function Print-FindingBlock {
    param([object]$F, [int]$Index)
    $color = Get-UiColorForSeverity $F.Severity
    $icon = Get-UiIconForSeverity -Severity $F.Severity -Trace:([bool]$F.DeletedTrace)
    $scoreBar = Get-UiBar -Value ([int]$F.Score) -Max 160 -Width 18
    $title = ("#" + $Index + " " + $icon + " " + $F.Severity + " | score " + $F.Score + " " + $scoreBar + " | confidence " + $F.Confidence)
    if ($script:UiCompact) {
        Write-YLine ("[" + $Index + "] " + $F.Severity + " score=" + $F.Score + " type=" + $F.ObjectType + " class=" + $F.Class) $color
        Write-YLine ("    " + (Truncate-UiText $F.Object 115)) "White"
        return
    }
    $w = $script:UiWidth
    Write-YLine ("+" + (Repeat-Text "-" ($w-2)) + "+") $color
    Write-UiBoxLine $title $color
    Write-UiBoxLine ("type=" + $F.ObjectType + " | class=" + $F.Class + " | trace=" + [bool]$F.DeletedTrace) "Gray"
    Write-UiBoxLine ("object: " + $F.Object) "White"
    if ($F.Sha256) { Write-UiBoxLine ("sha256: " + $F.Sha256) "DarkGray" }
    try {
        $profile = $F.EvidenceProfile
        if ($profile.Positive.Count -gt 0) {
            Write-UiBoxLine "evidence:" "Gray"
            foreach ($e in ($profile.Positive | Select-Object -First 7)) { Write-UiBoxLine ("  + " + $e) "DarkGray" }
        }
        if ($profile.Context.Count -gt 0) {
            Write-UiBoxLine "context:" "Gray"
            foreach ($e in ($profile.Context | Select-Object -First 4)) { Write-UiBoxLine ("  ~ " + $e) "DarkGray" }
        }
        if ($profile.Mitigation.Count -gt 0) {
            Write-UiBoxLine "lowers risk:" "Gray"
            foreach ($e in ($profile.Mitigation | Select-Object -First 4)) { Write-UiBoxLine ("  - " + $e) "DarkGray" }
        }
    } catch {
        foreach ($e in (@($F.Evidence) | Select-Object -First 7)) { Write-UiBoxLine ("  + " + $e) "DarkGray" }
    }
    if ($F.Recommendation) { Write-UiBoxLine ("next: " + $F.Recommendation) "Gray" }
    Write-YLine ("+" + (Repeat-Text "-" ($w-2)) + "+") $color
}

function Show-UiQuickTriage {
    param([object[]]$Sorted)
    $criticalItems = @($Sorted | Where-Object { $_.Severity -eq "CRITICAL" } | Select-Object -First 3)
    $highItems = @($Sorted | Where-Object { $_.Severity -eq "HIGH" } | Select-Object -First 3)
    if ($criticalItems.Count -eq 0 -and $highItems.Count -eq 0) { return }
    Write-UiRule "QUICK TRIAGE" "Red"
    $n = 1
    foreach ($x in @($criticalItems + $highItems)) {
        $c = Get-UiColorForSeverity $x.Severity
        Write-YLine ("  " + $n + ". " + $x.Severity.PadRight(8) + " score=" + ([string]$x.Score).PadRight(4) + " " + (Truncate-UiText $x.Object 85)) $c
        $n++
    }
}

function Show-FinalVerdict {
    if (-not $script:UiNoProgress) { try { Write-Progress -Activity "YRYS CHECKER" -Completed } catch {} }
    $elapsed = [int]((Get-Date) - $script:StartTime).TotalSeconds
    $sorted = @($script:Findings | Sort-Object Score -Descending)
    $critical = @($sorted | Where-Object { $_.Severity -eq "CRITICAL" }).Count
    $high = @($sorted | Where-Object { $_.Severity -eq "HIGH" }).Count
    $medium = @($sorted | Where-Object { $_.Severity -eq "MEDIUM" }).Count
    $low = @($sorted | Where-Object { $_.Severity -eq "LOW" }).Count
    $sevMaxObj = @($critical,$high,$medium,$low) | Measure-Object -Maximum
    $maxSev = [Math]::Max(1, [int]$sevMaxObj.Maximum)
    $verdict = "CLEAN"
    $vcolor = "Green"
    $riskText = "No strong cheat indicators were found by the local evidence engine."
    if ($critical -gt 0) { $verdict = "CHEAT LIKELY / CRITICAL EVIDENCE"; $vcolor = "Red"; $riskText = "Critical evidence exists. Review the top cards first." }
    elseif ($high -gt 0) { $verdict = "SUSPICIOUS / NEED MANUAL REVIEW"; $vcolor = "Yellow"; $riskText = "High-risk evidence exists but needs manual review." }
    elseif ($medium -gt 0) { $verdict = "WEAK SUSPICION / REVIEW ONLY"; $vcolor = "Cyan"; $riskText = "Only medium/weak evidence was found." }
    Write-YLine "" "DarkGray"
    Write-UiRule "FINAL DASHBOARD" $vcolor
    Write-UiBox "VERDICT" @(
        ("Result: " + $verdict),
        ("Meaning: " + $riskText),
        ("Runtime: " + $elapsed + " sec | Last phase: " + $script:UiLastStatus),
        "Privacy: no permanent report files created; temp workspace is removed on exit"
    ) $vcolor
    Write-UiRule "RISK COUNTERS" "White"
    Write-UiBarLine "CRITICAL" $critical $maxSev "Red"
    Write-UiBarLine "HIGH" $high $maxSev "Yellow"
    Write-UiBarLine "MEDIUM" $medium $maxSev "Cyan"
    Write-UiBarLine "LOW" $low $maxSev "DarkGray"
    Write-YLine "" "DarkGray"
    Write-UiRule "SCAN STATS" "White"
    Write-UiKV "Candidates" ([string]$script:CandidatesSeen) "Gray"
    Write-UiKV "Files analyzed" ([string]$script:FilesAnalyzed) "Gray"
    Write-UiKV "Trusted ignored" ([string]$script:TrustedIgnoredCount) "Gray"
    Write-UiKV "Weak suppressed" ([string]$script:WeakSuppressedCount) "Gray"
    Write-UiKV "Below threshold" ([string]$script:BelowThresholdSuppressedCount) "Gray"
    Write-UiKV "Blocked errors" ([string]$script:BlockedErrors) "Gray"
    Write-UiKV "Dynamic roots" ([string]$script:DynamicRootsCount) "Gray"
    Write-UiRule "FORENSIC MODULES" "White"
    $moduleLine1 = "USN=" + $script:USNTraceCount + " DNS=" + $script:DNSCacheCount + " BITS=" + $script:BitsJobCount + " Firewall=" + $script:FirewallRuleCount + " Pipes=" + $script:NamedPipeCount + " JavaAttach=" + $script:JavaAttachCount
    $moduleLine2 = "HWID=" + $script:HWIDAnomalyCount + " USB=" + $script:USBTraceCount + " WMI=" + $script:WMIPersistenceCount + " Browser=" + $script:BrowserTraceCount + " Discord=" + $script:DiscordTraceCount + " Macros=" + $script:MacroProfileCount + " KDMapper=" + $script:KDMapperTraceCount
    Write-YLine ("  " + $moduleLine1) "DarkGray"
    Write-YLine ("  " + $moduleLine2) "DarkGray"
    Show-UiQuickTriage -Sorted $sorted
    if ($sorted.Count -gt 0) {
        Write-UiRule "TOP CLASSES" "White"
        foreach ($g in ($sorted | Group-Object Class | Sort-Object Count -Descending | Select-Object -First 8)) {
            Write-YLine ("  " + $g.Name.PadRight(38) + " " + $g.Count) "DarkGray"
        }
        Write-YLine "" "DarkGray"
    }
    Write-UiRule "EVIDENCE CARDS" "White"
    $i = 1
    foreach ($f in ($sorted | Select-Object -First $Top)) {
        Print-FindingBlock -F $f -Index $i
        $i++
    }
    if ($sorted.Count -eq 0) { Write-YLine "No strong cheat indicators were found by the local evidence engine." "Green" }
    if ($ShowIgnored -and $script:Ignored.Count -gt 0) {
        Write-UiRule "IGNORED / SUPPRESSED" "DarkGray"
        $j=1
        foreach ($x in ($script:Ignored | Sort-Object Score -Descending | Select-Object -First 30)) { Print-FindingBlock -F $x -Index $j; $j++ }
    }
    Write-YLine "" "DarkGray"
    $adminNote = if ($script:IsElevated) { "Admin: detected via " + $script:AdminMethod + ". Protected modules will use elevated access where Windows allows." } else { "Admin: not detected. Protected modules may be partial." }
    Write-UiBox "NOTES" @(
        "Deleted/execution traces mean possible past use, not necessarily current installation.",
        $adminNote,
        "Use -CompactUI for short output, -ShowIgnored to audit filtered trusted/weak objects."
    ) "DarkGray"
}

function Main {
    if ($SelfTest) { Test-SelfSyntax }
    Initialize-Workspace
    $adminProbe = Test-IsAdministratorV15
    $script:IsElevated = [bool]$adminProbe.IsAdmin
    $script:AdminMethod = [string]$adminProbe.Method
    $script:AdminChecks = [string]$adminProbe.Checks
    Show-Banner
    if ($OpenReport) { Write-YLine "  ! OpenReport accepted for compatibility, but permanent reports are disabled." "Yellow" }
    if ($FullSystem) {
        Set-Variable -Name AllDrives -Scope Script -Value $true
        Set-Variable -Name Deep -Scope Script -Value $true
        Set-Variable -Name Forensic -Scope Script -Value $true
        Set-Variable -Name HuntSystem32 -Scope Script -Value $true
    }
    if ($Fast) {
        Set-Variable -Name MaxCandidates -Scope Script -Value ([Math]::Min($MaxCandidates, 900))
        Set-Variable -Name MaxMinutes -Scope Script -Value ([Math]::Min($MaxMinutes, 8))
    }
    $script:Deadline = (Get-Date).AddMinutes([Math]::Max(2,$MaxMinutes))
    Start-UiPhase "Brain / keyword model" "loading cheat tokens, trusted vendors and false-positive rules"
    Initialize-BrainTokens
    Write-YLine ("  > Mode: Fast=" + [bool]$Fast + " Deep=" + [bool]$Deep + " FullSystem=" + [bool]$FullSystem + " AllDrives=" + [bool]$AllDrives + " OnlyMinecraft=" + [bool]$OnlyMinecraft + " HuntSystem32=" + [bool]$HuntSystem32 + " HeavyForensics=" + (-not [bool]$NoHeavyForensics)) "White"
    Write-YLine ("  > Limit: MaxMinutes=" + $MaxMinutes + " MaxCandidates=" + $MaxCandidates + " MinScore=" + $MinScore + " TraceMinScore=" + $TraceMinScore) "DarkGray"
    Start-UiPhase "Processes" "process names, command lines, parents and windows"
    Analyze-RunningProcesses
    Start-UiPhase "Process modules" "java/minecraft DLL modules and native libraries"
    Analyze-ProcessModules
    Start-UiPhase "Registry autoruns" "Run/RunOnce/services/uninstall/persistence keys"
    Analyze-AutorunsRegistry
    Start-UiPhase "Scheduled tasks" "logon/unlock/startup tasks and suspicious actions"
    Analyze-ScheduledTasksDeep
    Start-UiPhase "IFEO / hijacks" "Debugger and SilentProcessExit persistence"
    Analyze-IFEODeep
    Start-UiPhase "Network / hosts / drivers" "hosts, TCP connections, driver traces"
    Analyze-HostsNetworkAndDrivers
    Start-UiPhase "VM / sandbox context" "virtualization and remote-control context"
    Analyze-VMIndicators
    Start-UiPhase "Deep forensics v12" "USN, DNS, BITS, Firewall, Pipes, JavaAttach, entropy"
    Invoke-AutonomousForensicsV12
    Start-UiPhase "Extended forensics v13" "HWID, USB, WMI, Browser, Discord, Macros, kdmapper"
    Invoke-AutonomousForensicsV13
    if ($Forensic -or $Deep -or $FullSystem) {
        Start-UiPhase "Deleted/execution traces" "Prefetch, Recent, JumpLists, UserAssist, BAM/DAM, logs"
        Analyze-DeletedAndExecutionTraces
    }
    Start-UiPhase "System32 anomaly hunt" "unsigned, recent or suspicious files in system folders"
    Analyze-SystemFolderAnomalies
    Start-UiPhase "File-system hunt" "EXE/DLL/JAR candidate discovery across selected roots"
    Search-FileSystemCandidates
    Start-UiPhase "Alternate Data Streams" "ADS check on suspicious candidates"
    Analyze-AlternateDataStreamsForCandidates
    Start-UiPhase "Optional engines" "YARA / AMSI / VirusTotal hash checks if enabled"
    Invoke-YaraOptional
    Invoke-AmsiOptional
    Invoke-VirusTotalOptional
    Start-UiPhase "Behavior chains" "correlating USB/browser/deleted traces/java/network/system anomalies"
    Analyze-BehavioralChainsV12
    Start-UiPhase "Final dashboard" "building verdict and evidence cards"
    Show-FinalVerdict
}

$script:YrysKbRules = @(
    [pscustomobject]@{ Id='KB0001'; Token='vapeloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0002'; Token='vapecrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0003'; Token='vapelite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0004'; Token='vapeclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0005'; Token='vape'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0006'; Token='vapeinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0007'; Token='vapev4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0008'; Token='ravencrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0009'; Token='ravenclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0010'; Token='ravenv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0011'; Token='raven'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0012'; Token='ravenloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0013'; Token='ravenlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0014'; Token='raveninjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0015'; Token='riseinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0016'; Token='risev4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0017'; Token='riseloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0018'; Token='riselite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0019'; Token='rise'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0020'; Token='riseclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0021'; Token='risecrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0022'; Token='driploader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0023'; Token='dripclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0024'; Token='dripv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0025'; Token='driplite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0026'; Token='dripinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0027'; Token='dripcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0028'; Token='drip'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0029'; Token='entropycrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0030'; Token='entropyclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0031'; Token='entropyloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0032'; Token='entropyv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0033'; Token='entropyinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0034'; Token='entropy'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0035'; Token='entropylite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0036'; Token='whiteoutinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0037'; Token='whiteout'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0038'; Token='whiteoutcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0039'; Token='whiteoutloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0040'; Token='whiteoutclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0041'; Token='whiteoutv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0042'; Token='whiteoutlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0043'; Token='slinkyclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0044'; Token='slinkyinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0045'; Token='slinkyloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0046'; Token='slinky'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0047'; Token='slinkycrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0048'; Token='slinkyv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0049'; Token='slinkylite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0050'; Token='dreamcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0051'; Token='dreamv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0052'; Token='dreaminjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0053'; Token='dream'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0054'; Token='dreamlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0055'; Token='dreamclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0056'; Token='dreamloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0057'; Token='liquidbounce'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0058'; Token='liquidbounceinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0059'; Token='liquidbounceclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0060'; Token='liquidbouncev4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0061'; Token='liquidbouncecrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0062'; Token='liquidbouncelite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0063'; Token='liquidbounceloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0064'; Token='wurstloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0065'; Token='wurstv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0066'; Token='wurstclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0067'; Token='wurst'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0068'; Token='wurstlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0069'; Token='wurstcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0070'; Token='wurstinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0071'; Token='meteorinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0072'; Token='meteor'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0073'; Token='meteorlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0074'; Token='meteorv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0075'; Token='meteorclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0076'; Token='meteorcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0077'; Token='meteorloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0078'; Token='aristoisinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0079'; Token='aristoislite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0080'; Token='aristoisclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0081'; Token='aristoisv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0082'; Token='aristoiscrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0083'; Token='aristoisloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0084'; Token='aristois'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0085'; Token='impactloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0086'; Token='impact'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0087'; Token='impactcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0088'; Token='impactinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0089'; Token='impactlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0090'; Token='impactv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0091'; Token='impactclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0092'; Token='futureclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0093'; Token='futureinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0094'; Token='future'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0095'; Token='futureloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0096'; Token='futurev4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0097'; Token='futurecrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0098'; Token='futurelite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0099'; Token='rusherhackinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0100'; Token='rusherhackv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0101'; Token='rusherhack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0102'; Token='rusherhackloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0103'; Token='rusherhackcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0104'; Token='rusherhackclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0105'; Token='rusherhacklite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0106'; Token='lambdav4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0107'; Token='lambdaclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0108'; Token='lambda'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0109'; Token='lambdalite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0110'; Token='lambdaloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0111'; Token='lambdainjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0112'; Token='lambdacrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0113'; Token='kamilite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0114'; Token='kamiinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0115'; Token='kamiclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0116'; Token='kamicrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0117'; Token='kamiv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0118'; Token='kami'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0119'; Token='kamiloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0120'; Token='kamiblueinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0121'; Token='kamiblue'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0122'; Token='kamibluelite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0123'; Token='kamibluev4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0124'; Token='kamiblueloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0125'; Token='kamibluecrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0126'; Token='kamiblueclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0127'; Token='salhackloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0128'; Token='salhack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0129'; Token='salhackcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0130'; Token='salhackinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0131'; Token='salhackclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0132'; Token='salhackv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0133'; Token='salhacklite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0134'; Token='phobosinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0135'; Token='phobosv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0136'; Token='phobosloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0137'; Token='phoboslite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0138'; Token='phoboscrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0139'; Token='phobos'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0140'; Token='phobosclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0141'; Token='konasv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0142'; Token='konasinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0143'; Token='konascrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0144'; Token='konaslite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0145'; Token='konasloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0146'; Token='konasclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0147'; Token='konas'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0148'; Token='pyrocrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0149'; Token='pyrov4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0150'; Token='pyroclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0151'; Token='pyrolite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0152'; Token='pyroloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0153'; Token='pyroinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0154'; Token='pyro'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0155'; Token='gamesenseclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0156'; Token='gamesensev4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0157'; Token='gamesenseloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0158'; Token='gamesenselite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0159'; Token='gamesense'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0160'; Token='gamesensecrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0161'; Token='gamesenseinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0162'; Token='oyveyloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0163'; Token='oyveyinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0164'; Token='oyveyv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0165'; Token='oyveycrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0166'; Token='oyvey'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0167'; Token='oyveyclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0168'; Token='oyveylite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0169'; Token='3arthh4cklite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0170'; Token='3arthh4ckinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0171'; Token='3arthh4ckloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0172'; Token='3arthh4ckclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0173'; Token='3arthh4ck'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0174'; Token='3arthh4ckcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0175'; Token='3arthh4ckv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0176'; Token='earthhackinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0177'; Token='earthhacklite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0178'; Token='earthhackclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0179'; Token='earthhackcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0180'; Token='earthhack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0181'; Token='earthhackloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0182'; Token='earthhackv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0183'; Token='seppukucrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0184'; Token='seppukuloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0185'; Token='seppuku'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0186'; Token='seppukuclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0187'; Token='seppukulite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0188'; Token='seppukuinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0189'; Token='seppukuv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0190'; Token='catalystlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0191'; Token='catalyst'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0192'; Token='catalystinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0193'; Token='catalystv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0194'; Token='catalystcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0195'; Token='catalystclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0196'; Token='catalystloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0197'; Token='abyssclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0198'; Token='abyssinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0199'; Token='abysscrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0200'; Token='abyssloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0201'; Token='abyssv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0202'; Token='abysslite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0203'; Token='abyss'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0204'; Token='xuluinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0205'; Token='xuluclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0206'; Token='xululoader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0207'; Token='xulucrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0208'; Token='xululite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0209'; Token='xulu'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0210'; Token='xuluv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0211'; Token='cosmosv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0212'; Token='cosmosclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0213'; Token='cosmos'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0214'; Token='cosmosinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0215'; Token='cosmoslite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0216'; Token='cosmoscrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0217'; Token='cosmosloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0218'; Token='trollhackv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0219'; Token='trollhackclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0220'; Token='trollhackinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0221'; Token='trollhack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0222'; Token='trollhacklite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0223'; Token='trollhackloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0224'; Token='trollhackcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0225'; Token='nullpointloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0226'; Token='nullpointclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0227'; Token='nullpointinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0228'; Token='nullpointv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0229'; Token='nullpoint'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0230'; Token='nullpointcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0231'; Token='nullpointlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0232'; Token='shorelinecrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0233'; Token='shorelineclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0234'; Token='shorelineloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0235'; Token='shorelinelite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0236'; Token='shoreline'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0237'; Token='shorelineinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0238'; Token='shorelinev4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0239'; Token='bozeinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0240'; Token='bozeclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0241'; Token='bozecrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0242'; Token='bozev4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0243'; Token='bozelite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0244'; Token='bozeloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0245'; Token='boze'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0246'; Token='mioinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0247'; Token='miov4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0248'; Token='miolite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0249'; Token='mioclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0250'; Token='mioloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0251'; Token='miocrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0252'; Token='mio'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0253'; Token='prestigelite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0254'; Token='prestige'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0255'; Token='prestigeinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0256'; Token='prestigecrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0257'; Token='prestigev4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0258'; Token='prestigeclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0259'; Token='prestigeloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0260'; Token='alien'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0261'; Token='alienloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0262'; Token='alienlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0263'; Token='aliencrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0264'; Token='alieninjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0265'; Token='alienv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0266'; Token='alienclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0267'; Token='thunderhacklite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0268'; Token='thunderhackcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0269'; Token='thunderhackv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0270'; Token='thunderhackclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0271'; Token='thunderhackinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0272'; Token='thunderhack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0273'; Token='thunderhackloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0274'; Token='bleachhackinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0275'; Token='bleachhackloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0276'; Token='bleachhackcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0277'; Token='bleachhackclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0278'; Token='bleachhacklite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0279'; Token='bleachhack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0280'; Token='bleachhackv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0281'; Token='forgehaxclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0282'; Token='forgehaxcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0283'; Token='forgehax'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0284'; Token='forgehaxloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0285'; Token='forgehaxinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0286'; Token='forgehaxv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0287'; Token='forgehaxlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0288'; Token='inertialite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0289'; Token='inertiacrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0290'; Token='inertialoader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0291'; Token='inertiav4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0292'; Token='inertia'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0293'; Token='inertiainjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0294'; Token='inertiaclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0295'; Token='sigmaclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0296'; Token='sigmaloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0297'; Token='sigmainjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0298'; Token='sigma'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0299'; Token='sigmav4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0300'; Token='sigmalite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0301'; Token='sigmacrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0302'; Token='fluxlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0303'; Token='fluxinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0304'; Token='fluxv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0305'; Token='fluxcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0306'; Token='fluxloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0307'; Token='flux'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0308'; Token='fluxclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0309'; Token='tenacityclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0310'; Token='tenacityloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0311'; Token='tenacity'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0312'; Token='tenacityv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0313'; Token='tenacitylite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0314'; Token='tenacityinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0315'; Token='tenacitycrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0316'; Token='zerodayloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0317'; Token='zeroday'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0318'; Token='zerodaycrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0319'; Token='zerodayclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0320'; Token='zerodayinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0321'; Token='zerodayv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0322'; Token='zerodaylite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0323'; Token='exhibition'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0324'; Token='exhibitionlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0325'; Token='exhibitionloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0326'; Token='exhibitionv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0327'; Token='exhibitioncrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0328'; Token='exhibitioninjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0329'; Token='exhibitionclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0330'; Token='astolfoloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0331'; Token='astolfoinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0332'; Token='astolfo'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0333'; Token='astolfolite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0334'; Token='astolfoclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0335'; Token='astolfov4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0336'; Token='astolfocrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0337'; Token='novolineloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0338'; Token='novolineinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0339'; Token='novolinev4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0340'; Token='novolineclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0341'; Token='novoline'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0342'; Token='novolinecrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0343'; Token='novolinelite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0344'; Token='novoinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0345'; Token='novolite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0346'; Token='novo'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0347'; Token='novocrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0348'; Token='novoloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0349'; Token='novoclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0350'; Token='novov4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0351'; Token='remixcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0352'; Token='remixinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0353'; Token='remixloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0354'; Token='remixclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0355'; Token='remix'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0356'; Token='remixv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0357'; Token='remixlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0358'; Token='huzuniloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0359'; Token='huzuniinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0360'; Token='huzunicrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0361'; Token='huzuni'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0362'; Token='huzuniclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0363'; Token='huzuniv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0364'; Token='huzunilite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0365'; Token='wolfram'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0366'; Token='wolframlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0367'; Token='wolframclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0368'; Token='wolframcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0369'; Token='wolframloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0370'; Token='wolframv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0371'; Token='wolframinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0372'; Token='nodusloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0373'; Token='nodus'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0374'; Token='noduslite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0375'; Token='noduscrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0376'; Token='nodusclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0377'; Token='nodusv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0378'; Token='nodusinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0379'; Token='weepcraftclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0380'; Token='weepcraftcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0381'; Token='weepcraftinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0382'; Token='weepcraftv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0383'; Token='weepcraftlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0384'; Token='weepcraftloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0385'; Token='weepcraft'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0386'; Token='jigsawlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0387'; Token='jigsaw'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0388'; Token='jigsawinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0389'; Token='jigsawv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0390'; Token='jigsawclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0391'; Token='jigsawcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0392'; Token='jigsawloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0393'; Token='skillclientv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0394'; Token='skill'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0395'; Token='skillclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0396'; Token='skillclientlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0397'; Token='skillclientclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0398'; Token='skillclientloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0399'; Token='skillclientinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0400'; Token='skillclientcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0401'; Token='akriencrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0402'; Token='akrienlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0403'; Token='akrieninjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0404'; Token='akrienclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0405'; Token='akrienloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0406'; Token='akrienv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0407'; Token='akrien'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0408'; Token='fdpv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0409'; Token='fdplite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0410'; Token='fdploader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0411'; Token='fdp'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0412'; Token='fdpcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0413'; Token='fdpinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0414'; Token='fdpclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0415'; Token='fdpclientloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0416'; Token='fdpclientcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0417'; Token='fdpclientv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0418'; Token='fdpclientlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0419'; Token='fdpclientinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0420'; Token='fdpclientclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0421'; Token='itamilite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0422'; Token='itamiinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0423'; Token='itamicrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0424'; Token='itamiloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0425'; Token='itamiclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0426'; Token='itamiv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0427'; Token='itami'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0428'; Token='dope'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0429'; Token='dopev4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0430'; Token='dopeloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0431'; Token='dopeclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0432'; Token='dopelite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0433'; Token='dopecrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0434'; Token='dopeinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0435'; Token='koidloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0436'; Token='koidclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0437'; Token='koidv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0438'; Token='koid'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0439'; Token='koidlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0440'; Token='koidinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0441'; Token='koidcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0442'; Token='iridiuminjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0443'; Token='iridiumv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0444'; Token='iridiumlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0445'; Token='iridiumloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0446'; Token='iridiumcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0447'; Token='iridium'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0448'; Token='iridiumclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0449'; Token='mergeloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0450'; Token='mergecrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0451'; Token='mergeinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0452'; Token='merge'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0453'; Token='mergelite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0454'; Token='mergev4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0455'; Token='mergeclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0456'; Token='cryptloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0457'; Token='cryptlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0458'; Token='cryptv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0459'; Token='crypt'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0460'; Token='cryptinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0461'; Token='cryptcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0462'; Token='cryptclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0463'; Token='incognitoloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0464'; Token='incognitov4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0465'; Token='incognitolite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0466'; Token='incognito'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0467'; Token='incognitocrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0468'; Token='incognitoclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0469'; Token='incognitoinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0470'; Token='antic'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0471'; Token='anticcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0472'; Token='anticv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0473'; Token='anticloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0474'; Token='anticinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0475'; Token='anticclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0476'; Token='anticlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0477'; Token='explicitloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0478'; Token='explicitlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0479'; Token='explicitcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0480'; Token='explicit'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0481'; Token='explicitclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0482'; Token='explicitinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0483'; Token='explicitv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0484'; Token='akira'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0485'; Token='akirainjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0486'; Token='akirav4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0487'; Token='akiralite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0488'; Token='akiraloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0489'; Token='akiracrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0490'; Token='akiraclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0491'; Token='sparkloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0492'; Token='spark'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0493'; Token='sparklite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0494'; Token='sparkv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0495'; Token='sparkclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0496'; Token='sparkinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0497'; Token='sparkcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0498'; Token='skilledcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0499'; Token='skilledlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0500'; Token='skilled'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0501'; Token='skilledloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0502'; Token='skilledv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0503'; Token='skilledinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0504'; Token='skilledclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0505'; Token='karmainjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0506'; Token='karmalite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0507'; Token='karmaloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0508'; Token='karmacrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0509'; Token='karma'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0510'; Token='karmav4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0511'; Token='karmaclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0512'; Token='doomsdaylite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0513'; Token='doomsdayv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0514'; Token='doomsdayinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0515'; Token='doomsdayloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0516'; Token='doomsdaycrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0517'; Token='doomsdayclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0518'; Token='doomsday'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0519'; Token='horionv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0520'; Token='horioninjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0521'; Token='horionloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0522'; Token='horion'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0523'; Token='horioncrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0524'; Token='horionclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0525'; Token='horionlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0526'; Token='zephyrv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0527'; Token='zephyrlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0528'; Token='zephyr'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0529'; Token='zephyrcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0530'; Token='zephyrclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0531'; Token='zephyrinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0532'; Token='zephyrloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0533'; Token='toolboxinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0534'; Token='toolboxloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0535'; Token='toolboxcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0536'; Token='toolboxlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0537'; Token='toolboxv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0538'; Token='toolboxclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0539'; Token='toolbox'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0540'; Token='praxinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0541'; Token='praxcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0542'; Token='praxloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0543'; Token='praxv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0544'; Token='praxclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0545'; Token='prax'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0546'; Token='praxlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0547'; Token='ambrosial'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0548'; Token='ambrosialinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0549'; Token='ambrosialloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0550'; Token='ambrosialcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0551'; Token='ambrosialv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0552'; Token='ambrosiallite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0553'; Token='ambrosialclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0554'; Token='badmanclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0555'; Token='badmanlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0556'; Token='badmancrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0557'; Token='badmanv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0558'; Token='badmanloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0559'; Token='badman'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0560'; Token='badmaninjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0561'; Token='fatecrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0562'; Token='fate'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0563'; Token='fatelite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0564'; Token='fateclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0565'; Token='fateloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0566'; Token='fateinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0567'; Token='fatev4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0568'; Token='borioninjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0569'; Token='borioncrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0570'; Token='borionlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0571'; Token='borionv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0572'; Token='borion'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0573'; Token='borionloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0574'; Token='borionclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0575'; Token='latitelite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0576'; Token='latiteloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0577'; Token='latiteinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0578'; Token='latite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0579'; Token='latitecrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0580'; Token='latiteclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0581'; Token='latitev4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0582'; Token='onix'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0583'; Token='onixv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0584'; Token='onixclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0585'; Token='onixcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0586'; Token='onixloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0587'; Token='onixlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0588'; Token='onixinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0589'; Token='solsticeloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0590'; Token='solsticeclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0591'; Token='solsticelite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0592'; Token='solsticeinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0593'; Token='solstice'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0594'; Token='solsticev4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0595'; Token='solsticecrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0596'; Token='nitr0loader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0597'; Token='nitr0client'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0598'; Token='nitr0v4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0599'; Token='nitr0lite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0600'; Token='nitr0'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0601'; Token='nitr0crack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0602'; Token='nitr0injector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0603'; Token='surgeclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0604'; Token='surgelite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0605'; Token='surge'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0606'; Token='surgev4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0607'; Token='surgeloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0608'; Token='surgecrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0609'; Token='surgeinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0610'; Token='flarev4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0611'; Token='flareclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0612'; Token='flarelite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0613'; Token='flare'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0614'; Token='flareinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0615'; Token='flareloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0616'; Token='flarecrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0617'; Token='pandorav4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0618'; Token='pandoraclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0619'; Token='pandoralite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0620'; Token='pandoraloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0621'; Token='pandorainjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0622'; Token='pandora'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0623'; Token='pandoracrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0624'; Token='resiliencev4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0625'; Token='resilienceloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0626'; Token='resilience'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0627'; Token='resilienceclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0628'; Token='resiliencelite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0629'; Token='resilienceinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0630'; Token='resiliencecrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0631'; Token='saintv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0632'; Token='saint'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0633'; Token='saintinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0634'; Token='saintlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0635'; Token='saintloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0636'; Token='saintcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0637'; Token='saintclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0638'; Token='serenityinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0639'; Token='serenityloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0640'; Token='serenityclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0641'; Token='serenityv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0642'; Token='serenitycrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0643'; Token='serenity'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0644'; Token='serenitylite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0645'; Token='cyanidev4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0646'; Token='cyanidecrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0647'; Token='cyanideinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0648'; Token='cyanideclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0649'; Token='cyanide'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0650'; Token='cyanideloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0651'; Token='cyanidelite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0652'; Token='reflexclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0653'; Token='reflexlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0654'; Token='reflexv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0655'; Token='reflex'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0656'; Token='reflexloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0657'; Token='reflexcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0658'; Token='reflexinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0659'; Token='metrolite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0660'; Token='metroloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0661'; Token='metrov4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0662'; Token='metroclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0663'; Token='metrocrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0664'; Token='metroinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0665'; Token='metro'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0666'; Token='spicyloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0667'; Token='spicyv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0668'; Token='spicyclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0669'; Token='spicycrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0670'; Token='spicyinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0671'; Token='spicylite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0672'; Token='spicy'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0673'; Token='tomatocrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0674'; Token='tomatoloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0675'; Token='tomatoinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0676'; Token='tomatov4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0677'; Token='tomatolite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0678'; Token='tomato'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0679'; Token='tomatoclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0680'; Token='apollov4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0681'; Token='apollo'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0682'; Token='apolloloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0683'; Token='apollocrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0684'; Token='apollolite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0685'; Token='apolloclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0686'; Token='apolloinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0687'; Token='fusionxclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0688'; Token='fusionxcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0689'; Token='fusionxinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0690'; Token='fusionxlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0691'; Token='fusionxv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0692'; Token='fusionx'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0693'; Token='fusionxloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0694'; Token='envycrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0695'; Token='envyclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0696'; Token='envylite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0697'; Token='envy'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0698'; Token='envyinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0699'; Token='envyloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0700'; Token='envyv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0701'; Token='sensation'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0702'; Token='sensationcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0703'; Token='sensationv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0704'; Token='sensationclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0705'; Token='sensationloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0706'; Token='sensationlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0707'; Token='sensationinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0708'; Token='daemoncrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0709'; Token='daemonlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0710'; Token='daemonclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0711'; Token='daemonv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0712'; Token='daemon'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0713'; Token='daemoninjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0714'; Token='daemonloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0715'; Token='violenceloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0716'; Token='violencev4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0717'; Token='violenceinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0718'; Token='violence'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0719'; Token='violencecrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0720'; Token='violenceclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0721'; Token='violencelite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0722'; Token='omikroncrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0723'; Token='omikroninjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0724'; Token='omikronv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0725'; Token='omikron'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0726'; Token='omikronlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0727'; Token='omikronclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0728'; Token='omikronloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0729'; Token='icariusloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0730'; Token='icariusv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0731'; Token='icariusinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0732'; Token='icariuscrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0733'; Token='icariusclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0734'; Token='icarius'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0735'; Token='icariuslite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0736'; Token='zeuslite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0737'; Token='zeus'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0738'; Token='zeusinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0739'; Token='zeuscrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0740'; Token='zeusloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0741'; Token='zeusv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0742'; Token='zeusclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0743'; Token='darklightloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0744'; Token='darklight'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0745'; Token='darklightcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0746'; Token='darklightinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0747'; Token='darklightv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0748'; Token='darklightlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0749'; Token='darklightclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0750'; Token='reliance'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0751'; Token='reliancelite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0752'; Token='reliancecrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0753'; Token='relianceclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0754'; Token='reliancev4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0755'; Token='relianceinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0756'; Token='relianceloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0757'; Token='cyaniteclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0758'; Token='cyanite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0759'; Token='cyaniteinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0760'; Token='cyanitelite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0761'; Token='cyanitecrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0762'; Token='cyanitev4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0763'; Token='cyaniteloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0764'; Token='nightx'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0765'; Token='nightxcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0766'; Token='nightxclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0767'; Token='nightxinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0768'; Token='nightxloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0769'; Token='nightxv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0770'; Token='nightxlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0771'; Token='limelite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0772'; Token='limeclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0773'; Token='limeloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0774'; Token='limev4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0775'; Token='lime'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0776'; Token='limeinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0777'; Token='limecrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0778'; Token='pandainjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0779'; Token='panda'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0780'; Token='pandaloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0781'; Token='pandav4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0782'; Token='pandaclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0783'; Token='pandalite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0784'; Token='pandacrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0785'; Token='augustusloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0786'; Token='augustusclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0787'; Token='augustusv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0788'; Token='augustusinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0789'; Token='augustus'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0790'; Token='augustuslite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0791'; Token='augustuscrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0792'; Token='winterwarelite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0793'; Token='winterware'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0794'; Token='winterwarev4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0795'; Token='winterwareinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0796'; Token='winterwareloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0797'; Token='winterwarecrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0798'; Token='winterwareclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0799'; Token='thunderclientclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0800'; Token='thunder'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0801'; Token='thunderclientlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0802'; Token='thunderclientinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0803'; Token='thunderclientcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0804'; Token='thunderclientv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0805'; Token='thunderclientloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0806'; Token='thunderclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0807'; Token='base'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0808'; Token='clientbaseloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0809'; Token='clientbasecrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0810'; Token='clientbaselite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0811'; Token='clientbaseclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0812'; Token='clientbasev4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0813'; Token='clientbaseinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0814'; Token='clientbase'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0815'; Token='neverloseloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0816'; Token='neverlose'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0817'; Token='neverloselite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0818'; Token='neverlosev4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0819'; Token='neverloseclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0820'; Token='neverloseinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0821'; Token='neverlosecrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0822'; Token='moon'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0823'; Token='moonlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0824'; Token='moonloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0825'; Token='mooninjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0826'; Token='moonclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0827'; Token='moonv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0828'; Token='mooncrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0829'; Token='moonxlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0830'; Token='moonxinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0831'; Token='moonxcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0832'; Token='moonxloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0833'; Token='moonxv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0834'; Token='moonxclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0835'; Token='moonx'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0836'; Token='venusinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0837'; Token='venuscrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0838'; Token='venusclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0839'; Token='venuslite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0840'; Token='venus'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0841'; Token='venusv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0842'; Token='venusloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0843'; Token='celestialloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0844'; Token='celestialcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0845'; Token='celestialinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0846'; Token='celestiallite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0847'; Token='celestialv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0848'; Token='celestial'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0849'; Token='celestialclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0850'; Token='wildloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0851'; Token='wildv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0852'; Token='wild'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0853'; Token='wildclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0854'; Token='wildinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0855'; Token='wildlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0856'; Token='wildcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0857'; Token='excellentloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0858'; Token='excellentcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0859'; Token='excellentv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0860'; Token='excellentinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0861'; Token='excellent'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0862'; Token='excellentclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0863'; Token='excellentlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0864'; Token='expensiveloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0865'; Token='expensive'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0866'; Token='expensiveinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0867'; Token='expensivev4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0868'; Token='expensiveclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0869'; Token='expensivelite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0870'; Token='expensivecrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0871'; Token='nursultanv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0872'; Token='nursultanlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0873'; Token='nursultancrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0874'; Token='nursultaninjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0875'; Token='nursultan'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0876'; Token='nursultanclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0877'; Token='nursultanloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0878'; Token='mincedlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0879'; Token='mincedcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0880'; Token='mincedloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0881'; Token='mincedinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0882'; Token='mincedclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0883'; Token='minced'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0884'; Token='mincedv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0885'; Token='celkalite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0886'; Token='celkav4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0887'; Token='celkainjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0888'; Token='celka'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0889'; Token='celkaclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0890'; Token='celkaloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0891'; Token='celkacrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0892'; Token='hachwareclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0893'; Token='hachwarev4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0894'; Token='hachwareloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0895'; Token='hachwarecrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0896'; Token='hachware'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0897'; Token='hachwareinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0898'; Token='hachwarelite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0899'; Token='rex'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0900'; Token='rexinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0901'; Token='rexloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0902'; Token='rexclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0903'; Token='rexv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0904'; Token='rexlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0905'; Token='rexcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0906'; Token='celestialclientinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0907'; Token='celestialclientloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0908'; Token='celestialclientlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0909'; Token='celestialclientcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0910'; Token='celestialclientclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0911'; Token='celestialclientv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0912'; Token='baritonelite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0913'; Token='baritonev4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0914'; Token='baritoneclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0915'; Token='baritonecrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0916'; Token='baritone'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0917'; Token='baritoneinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0918'; Token='baritoneloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0919'; Token='fabritoneclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0920'; Token='fabritonev4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0921'; Token='fabritonecrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0922'; Token='fabritone'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0923'; Token='fabritonelite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0924'; Token='fabritoneinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0925'; Token='fabritoneloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0926'; Token='impactclientloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0927'; Token='impactclientinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0928'; Token='impactclientclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0929'; Token='impactclientcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0930'; Token='impactclientv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0931'; Token='impactclientlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0932'; Token='sigma5lite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0933'; Token='sigma5v4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0934'; Token='sigma5loader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0935'; Token='sigma5injector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0936'; Token='sigma5'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0937'; Token='sigma5crack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0938'; Token='sigma5client'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0939'; Token='sigmajello'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0940'; Token='sigmajelloinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0941'; Token='sigmajelloclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0942'; Token='sigmajellocrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0943'; Token='sigmajelloloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0944'; Token='sigmajellov4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0945'; Token='sigmajellolite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0946'; Token='vapev4crack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0947'; Token='vapev4client'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0948'; Token='vapev4v4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0949'; Token='vapev4lite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0950'; Token='vapev4injector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0951'; Token='vapev4loader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0952'; Token='vapeliteinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0953'; Token='vapelitecrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0954'; Token='vapelitelite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0955'; Token='vapeliteclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0956'; Token='vapelitev4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0957'; Token='vapeliteloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0958'; Token='vapecrackv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0959'; Token='vapecrackinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0960'; Token='vapecrackclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0961'; Token='vapecrackcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0962'; Token='vapecrackloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0963'; Token='vapecracklite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0964'; Token='vapeinjectorlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0965'; Token='vapeinjectorcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0966'; Token='vapeinjectorclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0967'; Token='vapeinjectorinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0968'; Token='vapeinjectorloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0969'; Token='vapeinjectorv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0970'; Token='ravenbpluslite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0971'; Token='ravenbplusinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0972'; Token='ravenbpluscrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0973'; Token='ravenbplus'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0974'; Token='ravenbplusclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0975'; Token='ravenbplusloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0976'; Token='ravenbplusv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0977'; Token='ravenbplusplusloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0978'; Token='ravenbplusplusclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0979'; Token='ravenbplusplusinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0980'; Token='ravenbpluspluslite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0981'; Token='ravenbplusplus'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0982'; Token='ravenbpluspluscrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0983'; Token='ravenbplusplusv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0984'; Token='ravenxdcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0985'; Token='ravenxdclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0986'; Token='ravenxdv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0987'; Token='ravenxdinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0988'; Token='ravenxdlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0989'; Token='ravenxd'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0990'; Token='ravenxdloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0991'; Token='ravennplusclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0992'; Token='ravennplusv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0993'; Token='ravennplusloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0994'; Token='ravennplus'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0995'; Token='ravennpluslite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0996'; Token='ravennplusinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0997'; Token='ravennpluscrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0998'; Token='ravenweaveloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB0999'; Token='ravenweaveclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1000'; Token='ravenweavev4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1001'; Token='ravenweavelite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1002'; Token='ravenweave'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1003'; Token='ravenweavecrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1004'; Token='ravenweaveinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1005'; Token='ravenb3v4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1006'; Token='ravenb3client'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1007'; Token='ravenb3loader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1008'; Token='ravenb3crack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1009'; Token='ravenb3lite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1010'; Token='ravenb3'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1011'; Token='ravenb3injector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1012'; Token='dreamadvancedclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1013'; Token='dreamadvancedinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1014'; Token='dreamadvancedcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1015'; Token='dreamadvancedlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1016'; Token='dreamadvancedloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1017'; Token='dreamadvanced'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1018'; Token='dreamadvancedv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1019'; Token='slinkyclientcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1020'; Token='slinkyclientinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1021'; Token='slinkyclientclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1022'; Token='slinkyclientv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1023'; Token='slinkyclientloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1024'; Token='slinkyclientlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1025'; Token='whiteoutclientlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1026'; Token='whiteoutclientinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1027'; Token='whiteoutclientv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1028'; Token='whiteoutclientcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1029'; Token='whiteoutclientclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1030'; Token='whiteoutclientloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1031'; Token='dripclientlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1032'; Token='dripclientv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1033'; Token='dripclientinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1034'; Token='dripclientcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1035'; Token='dripclientclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1036'; Token='dripclientloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1037'; Token='entropyclientloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1038'; Token='entropyclientlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1039'; Token='entropyclientclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1040'; Token='entropyclientinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1041'; Token='entropyclientcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1042'; Token='entropyclientv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1043'; Token='riseclientv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1044'; Token='riseclientcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1045'; Token='riseclientinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1046'; Token='riseclientlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1047'; Token='riseclientloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1048'; Token='riseclientclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1049'; Token='liquidbounceplusinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1050'; Token='liquidbounceplusloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1051'; Token='liquidbounceplusclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1052'; Token='liquidbouncepluscrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1053'; Token='liquidbounceplus'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1054'; Token='liquidbounceplusv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1055'; Token='liquidbouncepluslite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1056'; Token='liquidbounceplusplusclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1057'; Token='liquidbouncepluspluslite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1058'; Token='liquidbounceplusplusinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1059'; Token='liquidbounceplusplusv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1060'; Token='liquidbounceplusplusloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1061'; Token='liquidbounceplusplus'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1062'; Token='liquidbouncepluspluscrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1063'; Token='wurstplusloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1064'; Token='wurstplusv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1065'; Token='wurstpluscrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1066'; Token='wurstplusclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1067'; Token='wurstplusinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1068'; Token='wurstpluslite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1069'; Token='wurstplus'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1070'; Token='wurstplus2loader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1071'; Token='wurstplus2v4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1072'; Token='wurstplus2lite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1073'; Token='wurstplus2crack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1074'; Token='wurstplus2injector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1075'; Token='wurstplus2client'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1076'; Token='wurstplus2'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1077'; Token='wurstplus3client'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1078'; Token='wurstplus3v4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1079'; Token='wurstplus3lite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1080'; Token='wurstplus3injector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1081'; Token='wurstplus3'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1082'; Token='wurstplus3loader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1083'; Token='wurstplus3crack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1084'; Token='kami-blueloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1085'; Token='kami-bluev4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1086'; Token='kami-blueclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1087'; Token='kami-blue'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1088'; Token='kami-bluelite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1089'; Token='kami-blueinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1090'; Token='kami-bluecrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1091'; Token='aresloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1092'; Token='aresv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1093'; Token='aresinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1094'; Token='areslite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1095'; Token='ares'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1096'; Token='arescrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1097'; Token='aresclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1098'; Token='aresclientloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1099'; Token='aresclientlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1100'; Token='aresclientinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1101'; Token='aresclientclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1102'; Token='aresclientv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1103'; Token='aresclientcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1104'; Token='arespremiuminjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1105'; Token='arespremiumlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1106'; Token='arespremiumcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1107'; Token='arespremiumloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1108'; Token='arespremiumclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1109'; Token='arespremium'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1110'; Token='arespremiumv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1111'; Token='futureclientinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1112'; Token='futureclientv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1113'; Token='futureclientlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1114'; Token='futureclientloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1115'; Token='futureclientclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1116'; Token='futureclientcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1117'; Token='rusherhackplusv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1118'; Token='rusherhackplus'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1119'; Token='rusherhackpluslite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1120'; Token='rusherhackpluscrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1121'; Token='rusherhackplusinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1122'; Token='rusherhackplusclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1123'; Token='rusherhackplusloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1124'; Token='konasclientloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1125'; Token='konasclientclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1126'; Token='konasclientlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1127'; Token='konasclientcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1128'; Token='konasclientv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1129'; Token='konasclientinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1130'; Token='pyroclientinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1131'; Token='pyroclientclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1132'; Token='pyroclientcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1133'; Token='pyroclientlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1134'; Token='pyroclientv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1135'; Token='pyroclientloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1136'; Token='gamesenseclientinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1137'; Token='gamesenseclientcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1138'; Token='gamesenseclientlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1139'; Token='gamesenseclientclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1140'; Token='gamesenseclientv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1141'; Token='gamesenseclientloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1142'; Token='phobosclientclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1143'; Token='phobosclientcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1144'; Token='phobosclientinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1145'; Token='phobosclientv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1146'; Token='phobosclientloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1147'; Token='phobosclientlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1148'; Token='salhackclientcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1149'; Token='salhackclientloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1150'; Token='salhackclientinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1151'; Token='salhackclientclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1152'; Token='salhackclientv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1153'; Token='salhackclientlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1154'; Token='lambda-clientloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1155'; Token='lambda-clientlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1156'; Token='lambda-client'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1157'; Token='lambda-clientv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1158'; Token='lambda-clientcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1159'; Token='lambda-clientclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1160'; Token='lambda-clientinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1161'; Token='inertiaclientloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1162'; Token='inertiaclientcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1163'; Token='inertiaclientclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1164'; Token='inertiaclientv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1165'; Token='inertiaclientlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1166'; Token='inertiaclientinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1167'; Token='aristoisclientlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1168'; Token='aristoisclientv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1169'; Token='aristoisclientclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1170'; Token='aristoisclientinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1171'; Token='aristoisclientloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1172'; Token='aristoisclientcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1173'; Token='bleachhackclientloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1174'; Token='bleachhackclientclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1175'; Token='bleachhackclientv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1176'; Token='bleachhackclientinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1177'; Token='bleachhackclientlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1178'; Token='bleachhackclientcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1179'; Token='meteorclientinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1180'; Token='meteorclientcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1181'; Token='meteorclientloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1182'; Token='meteorclientv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1183'; Token='meteorclientclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1184'; Token='meteorclientlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1185'; Token='meteorplus'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1186'; Token='meteorpluslite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1187'; Token='meteorplusinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1188'; Token='meteorplusclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1189'; Token='meteorplusv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1190'; Token='meteorplusloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1191'; Token='meteorpluscrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1192'; Token='meteoraddonv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1193'; Token='meteoraddoninjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1194'; Token='meteoraddonclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1195'; Token='meteoraddoncrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1196'; Token='meteoraddonlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1197'; Token='meteoraddon'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1198'; Token='meteoraddonloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1199'; Token='thunderhackrecodeclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1200'; Token='thunderhackrecodelite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1201'; Token='thunderhackrecodev4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1202'; Token='thunderhackrecodeloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1203'; Token='thunderhackrecodecrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1204'; Token='thunderhackrecodeinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1205'; Token='thunderhackrecode'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1206'; Token='shorelineclientloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1207'; Token='shorelineclientlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1208'; Token='shorelineclientcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1209'; Token='shorelineclientv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1210'; Token='shorelineclientclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1211'; Token='shorelineclientinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1212'; Token='bozeclientlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1213'; Token='bozeclientloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1214'; Token='bozeclientcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1215'; Token='bozeclientclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1216'; Token='bozeclientv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1217'; Token='bozeclientinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1218'; Token='prestigeclientclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1219'; Token='prestigeclientinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1220'; Token='prestigeclientv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1221'; Token='prestigeclientloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1222'; Token='prestigeclientcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1223'; Token='prestigeclientlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1224'; Token='alienclientlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1225'; Token='alienclientv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1226'; Token='alienclientclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1227'; Token='alienclientcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1228'; Token='alienclientloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1229'; Token='alienclientinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1230'; Token='nullpointclientinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1231'; Token='nullpointclientlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1232'; Token='nullpointclientclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1233'; Token='nullpointclientloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1234'; Token='nullpointclientcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1235'; Token='nullpointclientv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1236'; Token='xuluclientloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1237'; Token='xuluclientclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1238'; Token='xuluclientcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1239'; Token='xuluclientinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1240'; Token='xuluclientv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1241'; Token='xuluclientlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1242'; Token='xulupvpcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1243'; Token='xulupvp'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1244'; Token='xulupvplite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1245'; Token='xulupvpclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1246'; Token='xulupvploader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1247'; Token='xulupvpv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1248'; Token='xulupvpinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1249'; Token='cosmosclientlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1250'; Token='cosmosclientclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1251'; Token='cosmosclientloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1252'; Token='cosmosclientcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1253'; Token='cosmosclientinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1254'; Token='cosmosclientv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1255'; Token='trollhackclientv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1256'; Token='trollhackclientlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1257'; Token='trollhackclientcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1258'; Token='trollhackclientinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1259'; Token='trollhackclientclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1260'; Token='trollhackclientloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1261'; Token='oyveyclientv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1262'; Token='oyveyclientclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1263'; Token='oyveyclientcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1264'; Token='oyveyclientlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1265'; Token='oyveyclientinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1266'; Token='oyveyclientloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1267'; Token='earthhackclientv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1268'; Token='earthhackclientclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1269'; Token='earthhackclientcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1270'; Token='earthhackclientloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1271'; Token='earthhackclientlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1272'; Token='earthhackclientinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1273'; Token='seppukuhackloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1274'; Token='seppukuhackclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1275'; Token='seppukuhackcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1276'; Token='seppukuhackinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1277'; Token='seppukuhackv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1278'; Token='seppukuhacklite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1279'; Token='seppukuhack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1280'; Token='forgehaxclientclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1281'; Token='forgehaxclientlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1282'; Token='forgehaxclientinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1283'; Token='forgehaxclientloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1284'; Token='forgehaxclientcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1285'; Token='forgehaxclientv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1286'; Token='kami-clientlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1287'; Token='kami-client'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1288'; Token='kami-clientv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1289'; Token='kami-clientcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1290'; Token='kami-clientinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1291'; Token='kami-clientloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1292'; Token='kami-clientclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1293'; Token='kamiblueclientv4'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1294'; Token='kamiblueclientinjector'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1295'; Token='kamiblueclientloader'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1296'; Token='kamiblueclientlite'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1297'; Token='kamiblueclientcrack'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1298'; Token='kamiblueclientclient'; Category='cheat_name'; Weight=80; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1299'; Token='killaura'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1300'; Token='module/killaura'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1301'; Token='modules/killaura'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1302'; Token='features/killaura'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1303'; Token='aimassist'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1304'; Token='module/aimassist'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1305'; Token='modules/aimassist'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1306'; Token='features/aimassist'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1307'; Token='triggerbot'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1308'; Token='module/triggerbot'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1309'; Token='modules/triggerbot'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1310'; Token='features/triggerbot'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1311'; Token='autoclicker'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1312'; Token='module/autoclicker'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1313'; Token='modules/autoclicker'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1314'; Token='features/autoclicker'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1315'; Token='clicker'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1316'; Token='module/clicker'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1317'; Token='modules/clicker'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1318'; Token='features/clicker'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1319'; Token='reach'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1320'; Token='velocity'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1321'; Token='module/velocity'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1322'; Token='modules/velocity'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1323'; Token='features/velocity'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1324'; Token='antikb'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1325'; Token='module/antikb'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1326'; Token='modules/antikb'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1327'; Token='features/antikb'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1328'; Token='bhop'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1329'; Token='speedhack'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1330'; Token='module/speedhack'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1331'; Token='modules/speedhack'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1332'; Token='features/speedhack'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1333'; Token='flyhack'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1334'; Token='module/flyhack'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1335'; Token='modules/flyhack'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1336'; Token='features/flyhack'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1337'; Token='nofall'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1338'; Token='module/nofall'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1339'; Token='modules/nofall'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1340'; Token='features/nofall'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1341'; Token='jesus'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1342'; Token='scaffold'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1343'; Token='module/scaffold'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1344'; Token='modules/scaffold'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1345'; Token='features/scaffold'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1346'; Token='tower'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1347'; Token='eagle'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1348'; Token='xray'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1349'; Token='esp'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1350'; Token='tracers'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1351'; Token='module/tracers'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1352'; Token='modules/tracers'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1353'; Token='features/tracers'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1354'; Token='nametags'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1355'; Token='module/nametags'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1356'; Token='modules/nametags'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1357'; Token='features/nametags'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1358'; Token='freecam'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1359'; Token='module/freecam'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1360'; Token='modules/freecam'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1361'; Token='features/freecam'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1362'; Token='chams'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1363'; Token='wallhack'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1364'; Token='module/wallhack'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1365'; Token='modules/wallhack'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1366'; Token='features/wallhack'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1367'; Token='cheststealer'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1368'; Token='module/cheststealer'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1369'; Token='modules/cheststealer'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1370'; Token='features/cheststealer'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1371'; Token='inventorycleaner'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1372'; Token='module/inventorycleaner'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1373'; Token='modules/inventorycleaner'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1374'; Token='features/inventorycleaner'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1375'; Token='autopot'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1376'; Token='module/autopot'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1377'; Token='modules/autopot'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1378'; Token='features/autopot'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1379'; Token='autosoup'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1380'; Token='module/autosoup'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1381'; Token='modules/autosoup'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1382'; Token='features/autosoup'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1383'; Token='autoarmor'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1384'; Token='module/autoarmor'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1385'; Token='modules/autoarmor'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1386'; Token='features/autoarmor'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1387'; Token='fastplace'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1388'; Token='module/fastplace'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1389'; Token='modules/fastplace'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1390'; Token='features/fastplace'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1391'; Token='fastbreak'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1392'; Token='module/fastbreak'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1393'; Token='modules/fastbreak'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1394'; Token='features/fastbreak'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1395'; Token='nuker'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1396'; Token='blink'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1397'; Token='timer'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1398'; Token='criticals'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1399'; Token='module/criticals'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1400'; Token='modules/criticals'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1401'; Token='features/criticals'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1402'; Token='packetfly'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1403'; Token='module/packetfly'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1404'; Token='modules/packetfly'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1405'; Token='features/packetfly'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1406'; Token='elytrafly'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1407'; Token='module/elytrafly'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1408'; Token='modules/elytrafly'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1409'; Token='features/elytrafly'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1410'; Token='phase'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1411'; Token='nofog'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1412'; Token='fullbright'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1413'; Token='module/fullbright'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1414'; Token='modules/fullbright'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1415'; Token='features/fullbright'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1416'; Token='fakeplayer'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1417'; Token='module/fakeplayer'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1418'; Token='modules/fakeplayer'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1419'; Token='features/fakeplayer'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1420'; Token='dupe'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1421'; Token='baritone'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1422'; Token='module/baritone'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1423'; Token='modules/baritone'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1424'; Token='features/baritone'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1425'; Token='automine'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1426'; Token='module/automine'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1427'; Token='modules/automine'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1428'; Token='features/automine'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1429'; Token='autototem'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1430'; Token='module/autototem'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1431'; Token='modules/autototem'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1432'; Token='features/autototem'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1433'; Token='crystalaura'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1434'; Token='module/crystalaura'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1435'; Token='modules/crystalaura'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1436'; Token='features/crystalaura'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1437'; Token='anchoraura'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1438'; Token='module/anchoraura'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1439'; Token='modules/anchoraura'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1440'; Token='features/anchoraura'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1441'; Token='bedaura'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1442'; Token='module/bedaura'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1443'; Token='modules/bedaura'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1444'; Token='features/bedaura'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1445'; Token='surround'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1446'; Token='module/surround'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1447'; Token='modules/surround'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1448'; Token='features/surround'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1449'; Token='selftrap'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1450'; Token='module/selftrap'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1451'; Token='modules/selftrap'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1452'; Token='features/selftrap'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1453'; Token='burrow'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1454'; Token='module/burrow'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1455'; Token='modules/burrow'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1456'; Token='features/burrow'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1457'; Token='holeesp'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1458'; Token='module/holeesp'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1459'; Token='modules/holeesp'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1460'; Token='features/holeesp'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1461'; Token='cityboss'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1462'; Token='module/cityboss'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1463'; Token='modules/cityboss'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1464'; Token='features/cityboss'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1465'; Token='autocrystal'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1466'; Token='module/autocrystal'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1467'; Token='modules/autocrystal'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1468'; Token='features/autocrystal'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1469'; Token='targetstrafe'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1470'; Token='module/targetstrafe'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1471'; Token='modules/targetstrafe'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1472'; Token='features/targetstrafe'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1473'; Token='rotation'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1474'; Token='module/rotation'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1475'; Token='modules/rotation'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1476'; Token='features/rotation'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1477'; Token='silentaim'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1478'; Token='module/silentaim'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1479'; Token='modules/silentaim'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1480'; Token='features/silentaim'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1481'; Token='backtrack'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1482'; Token='module/backtrack'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1483'; Token='modules/backtrack'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1484'; Token='features/backtrack'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1485'; Token='lagback'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1486'; Token='module/lagback'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1487'; Token='modules/lagback'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1488'; Token='features/lagback'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1489'; Token='disabler'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1490'; Token='module/disabler'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1491'; Token='modules/disabler'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1492'; Token='features/disabler'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1493'; Token='anticheatbypass'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1494'; Token='module/anticheatbypass'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1495'; Token='modules/anticheatbypass'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1496'; Token='features/anticheatbypass'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1497'; Token='spoof'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1498'; Token='mixin'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1499'; Token='eventbus'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1500'; Token='module/eventbus'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1501'; Token='modules/eventbus'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1502'; Token='features/eventbus'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1503'; Token='modulemanager'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1504'; Token='module/modulemanager'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1505'; Token='modules/modulemanager'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1506'; Token='features/modulemanager'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1507'; Token='clickgui'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1508'; Token='module/clickgui'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1509'; Token='modules/clickgui'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1510'; Token='features/clickgui'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1511'; Token='hudeditor'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1512'; Token='module/hudeditor'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1513'; Token='modules/hudeditor'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1514'; Token='features/hudeditor'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1515'; Token='arraylist'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1516'; Token='module/arraylist'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1517'; Token='modules/arraylist'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1518'; Token='features/arraylist'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1519'; Token='combatmodule'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1520'; Token='module/combatmodule'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1521'; Token='modules/combatmodule'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1522'; Token='features/combatmodule'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1523'; Token='movementmodule'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1524'; Token='module/movementmodule'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1525'; Token='modules/movementmodule'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1526'; Token='features/movementmodule'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1527'; Token='rendermodule'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1528'; Token='module/rendermodule'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1529'; Token='modules/rendermodule'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1530'; Token='features/rendermodule'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1531'; Token='exploitmodule'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1532'; Token='module/exploitmodule'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1533'; Token='modules/exploitmodule'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1534'; Token='features/exploitmodule'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1535'; Token='clientcommand'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1536'; Token='module/clientcommand'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1537'; Token='modules/clientcommand'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1538'; Token='features/clientcommand'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1539'; Token='hackmodule'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1540'; Token='module/hackmodule'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1541'; Token='modules/hackmodule'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1542'; Token='features/hackmodule'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1543'; Token='cheatmodule'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1544'; Token='module/cheatmodule'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1545'; Token='modules/cheatmodule'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1546'; Token='features/cheatmodule'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1547'; Token='injector'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1548'; Token='module/injector'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1549'; Token='modules/injector'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1550'; Token='features/injector'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1551'; Token='loader'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1552'; Token='module/loader'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1553'; Token='modules/loader'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1554'; Token='features/loader'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1555'; Token='mapper'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1556'; Token='module/mapper'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1557'; Token='modules/mapper'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1558'; Token='features/mapper'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1559'; Token='manualmap'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1560'; Token='module/manualmap'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1561'; Token='modules/manualmap'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1562'; Token='features/manualmap'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1563'; Token='dllinject'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1564'; Token='module/dllinject'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1565'; Token='modules/dllinject'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1566'; Token='features/dllinject'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1567'; Token='javaagent'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1568'; Token='module/javaagent'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1569'; Token='modules/javaagent'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1570'; Token='features/javaagent'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1571'; Token='agentmain'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1572'; Token='module/agentmain'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1573'; Token='modules/agentmain'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1574'; Token='features/agentmain'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1575'; Token='premain'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1576'; Token='module/premain'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1577'; Token='modules/premain'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1578'; Token='features/premain'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1579'; Token='attachapi'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1580'; Token='module/attachapi'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1581'; Token='modules/attachapi'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1582'; Token='features/attachapi'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1583'; Token='virtualmachine.attach'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1584'; Token='module/virtualmachine.attach'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1585'; Token='modules/virtualmachine.attach'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1586'; Token='features/virtualmachine.attach'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1587'; Token='instrumentation'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1588'; Token='module/instrumentation'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1589'; Token='modules/instrumentation'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1590'; Token='features/instrumentation'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1591'; Token='transformer'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1592'; Token='module/transformer'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1593'; Token='modules/transformer'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1594'; Token='features/transformer'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1595'; Token='classloader'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1596'; Token='module/classloader'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1597'; Token='modules/classloader'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1598'; Token='features/classloader'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1599'; Token='bootclasspath'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1600'; Token='module/bootclasspath'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1601'; Token='modules/bootclasspath'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1602'; Token='features/bootclasspath'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1603'; Token='noverify'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1604'; Token='module/noverify'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1605'; Token='modules/noverify'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1606'; Token='features/noverify'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1607'; Token='systemclassloader'; Category='cheat_feature'; Weight=35; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1608'; Token='module/systemclassloader'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1609'; Token='modules/systemclassloader'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1610'; Token='features/systemclassloader'; Category='java_class_fragment'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1611'; Token='inject'; Category='injection_or_loader'; Weight=60; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1612'; Token='injector'; Category='injection_or_loader'; Weight=60; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1613'; Token='loader'; Category='injection_or_loader'; Weight=60; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1614'; Token='mapper'; Category='injection_or_loader'; Weight=60; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1615'; Token='manualmap'; Category='injection_or_loader'; Weight=60; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1616'; Token='shellcode'; Category='injection_or_loader'; Weight=60; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1617'; Token='reflective'; Category='injection_or_loader'; Weight=60; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1618'; Token='dllmain'; Category='injection_or_loader'; Weight=60; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1619'; Token='createremotethread'; Category='injection_or_loader'; Weight=60; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1620'; Token='writeprocessmemory'; Category='injection_or_loader'; Weight=60; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1621'; Token='virtualallocex'; Category='injection_or_loader'; Weight=60; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1622'; Token='openprocess'; Category='injection_or_loader'; Weight=60; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1623'; Token='ntqueryinformationprocess'; Category='injection_or_loader'; Weight=60; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1624'; Token='setwindowshookex'; Category='injection_or_loader'; Weight=60; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1625'; Token='appinit_dlls'; Category='injection_or_loader'; Weight=60; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1626'; Token='image file execution options'; Category='injection_or_loader'; Weight=60; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1627'; Token='debugger'; Category='injection_or_loader'; Weight=60; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1628'; Token='javaagent'; Category='injection_or_loader'; Weight=60; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1629'; Token='agentpath'; Category='injection_or_loader'; Weight=60; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1630'; Token='xbootclasspath'; Category='injection_or_loader'; Weight=60; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1631'; Token='bootclasspath'; Category='injection_or_loader'; Weight=60; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1632'; Token='system.class.loader'; Category='injection_or_loader'; Weight=60; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1633'; Token='jvmti'; Category='injection_or_loader'; Weight=60; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1634'; Token='attachapi'; Category='injection_or_loader'; Weight=60; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1635'; Token='agentmain'; Category='injection_or_loader'; Weight=60; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1636'; Token='premain'; Category='injection_or_loader'; Weight=60; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1637'; Token='classfiletransformer'; Category='injection_or_loader'; Weight=60; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1638'; Token='asm.tree'; Category='injection_or_loader'; Weight=60; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1639'; Token='mixintransformer'; Category='injection_or_loader'; Weight=60; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1640'; Token='accesswidener'; Category='injection_or_loader'; Weight=60; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1641'; Token='launchwrapper'; Category='injection_or_loader'; Weight=60; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1642'; Token='modlauncher'; Category='injection_or_loader'; Weight=60; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1643'; Token='fabricloader'; Category='injection_or_loader'; Weight=60; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1644'; Token='liteloader'; Category='injection_or_loader'; Weight=60; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1645'; Token='forgegradle'; Category='injection_or_loader'; Weight=60; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1646'; Token='weave'; Category='injection_or_loader'; Weight=60; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1647'; Token='weave-loader'; Category='injection_or_loader'; Weight=60; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1648'; Token='loaded mod'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1649'; Token='loading mod'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1650'; Token='fabric mod'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1651'; Token='forge mod'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1652'; Token='mixin config'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1653'; Token='access widener'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1654'; Token='javaagent'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1655'; Token='jvm arguments'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1656'; Token='launchwrapper'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1657'; Token='modlauncher'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1658'; Token='liteloader'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1659'; Token='tlauncher'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1660'; Token='prism launcher'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1661'; Token='polymc'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1662'; Token='multimc'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1663'; Token='gdlauncher'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1664'; Token='atlauncher'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1665'; Token='lunar client'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1666'; Token='badlion client'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1667'; Token='feather client'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1668'; Token='meteor client'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1669'; Token='liquidbounce'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1670'; Token='raven b+'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1671'; Token='vape v4'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1672'; Token='rise client'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1673'; Token='drip lite'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1674'; Token='entropy client'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1675'; Token='whiteout'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1676'; Token='slinky'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1677'; Token='kill aura'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1678'; Token='killaura'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1679'; Token='aim assist'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1680'; Token='trigger bot'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1681'; Token='auto clicker'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1682'; Token='reach'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1683'; Token='velocity'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1684'; Token='scaffold'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1685'; Token='xray'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1686'; Token='esp'; Category='log_phrase'; Weight=42; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1687'; Token='vape.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1688'; Token='vape/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1689'; Token='vape.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1690'; Token='vape/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1691'; Token='vape.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1692'; Token='vape/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1693'; Token='vape.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1694'; Token='vape/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1695'; Token='vape.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1696'; Token='vape/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1697'; Token='vape.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1698'; Token='vape/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1699'; Token='vape.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1700'; Token='vape/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1701'; Token='vape.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1702'; Token='vape/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1703'; Token='vape.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1704'; Token='vape/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1705'; Token='vape.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1706'; Token='vape/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1707'; Token='vape.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1708'; Token='vape/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1709'; Token='vape.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1710'; Token='vape/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1711'; Token='vape.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1712'; Token='vape/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1713'; Token='vape.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1714'; Token='vape/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1715'; Token='vape.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1716'; Token='vape/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1717'; Token='vape.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1718'; Token='vape/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1719'; Token='vape.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1720'; Token='vape/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1721'; Token='vape.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1722'; Token='vape/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1723'; Token='raven.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1724'; Token='raven/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1725'; Token='raven.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1726'; Token='raven/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1727'; Token='raven.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1728'; Token='raven/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1729'; Token='raven.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1730'; Token='raven/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1731'; Token='raven.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1732'; Token='raven/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1733'; Token='raven.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1734'; Token='raven/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1735'; Token='raven.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1736'; Token='raven/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1737'; Token='raven.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1738'; Token='raven/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1739'; Token='raven.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1740'; Token='raven/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1741'; Token='raven.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1742'; Token='raven/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1743'; Token='raven.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1744'; Token='raven/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1745'; Token='raven.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1746'; Token='raven/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1747'; Token='raven.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1748'; Token='raven/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1749'; Token='raven.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1750'; Token='raven/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1751'; Token='raven.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1752'; Token='raven/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1753'; Token='raven.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1754'; Token='raven/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1755'; Token='raven.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1756'; Token='raven/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1757'; Token='raven.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1758'; Token='raven/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1759'; Token='rise.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1760'; Token='rise/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1761'; Token='rise.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1762'; Token='rise/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1763'; Token='rise.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1764'; Token='rise/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1765'; Token='rise.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1766'; Token='rise/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1767'; Token='rise.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1768'; Token='rise/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1769'; Token='rise.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1770'; Token='rise/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1771'; Token='rise.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1772'; Token='rise/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1773'; Token='rise.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1774'; Token='rise/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1775'; Token='rise.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1776'; Token='rise/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1777'; Token='rise.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1778'; Token='rise/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1779'; Token='rise.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1780'; Token='rise/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1781'; Token='rise.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1782'; Token='rise/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1783'; Token='rise.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1784'; Token='rise/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1785'; Token='rise.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1786'; Token='rise/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1787'; Token='rise.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1788'; Token='rise/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1789'; Token='rise.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1790'; Token='rise/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1791'; Token='rise.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1792'; Token='rise/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1793'; Token='rise.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1794'; Token='rise/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1795'; Token='drip.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1796'; Token='drip/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1797'; Token='drip.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1798'; Token='drip/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1799'; Token='drip.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1800'; Token='drip/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1801'; Token='drip.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1802'; Token='drip/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1803'; Token='drip.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1804'; Token='drip/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1805'; Token='drip.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1806'; Token='drip/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1807'; Token='drip.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1808'; Token='drip/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1809'; Token='drip.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1810'; Token='drip/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1811'; Token='drip.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1812'; Token='drip/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1813'; Token='drip.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1814'; Token='drip/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1815'; Token='drip.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1816'; Token='drip/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1817'; Token='drip.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1818'; Token='drip/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1819'; Token='drip.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1820'; Token='drip/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1821'; Token='drip.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1822'; Token='drip/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1823'; Token='drip.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1824'; Token='drip/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1825'; Token='drip.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1826'; Token='drip/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1827'; Token='drip.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1828'; Token='drip/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1829'; Token='drip.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1830'; Token='drip/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1831'; Token='entropy.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1832'; Token='entropy/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1833'; Token='entropy.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1834'; Token='entropy/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1835'; Token='entropy.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1836'; Token='entropy/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1837'; Token='entropy.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1838'; Token='entropy/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1839'; Token='entropy.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1840'; Token='entropy/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1841'; Token='entropy.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1842'; Token='entropy/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1843'; Token='entropy.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1844'; Token='entropy/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1845'; Token='entropy.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1846'; Token='entropy/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1847'; Token='entropy.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1848'; Token='entropy/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1849'; Token='entropy.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1850'; Token='entropy/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1851'; Token='entropy.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1852'; Token='entropy/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1853'; Token='entropy.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1854'; Token='entropy/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1855'; Token='entropy.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1856'; Token='entropy/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1857'; Token='entropy.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1858'; Token='entropy/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1859'; Token='entropy.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1860'; Token='entropy/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1861'; Token='entropy.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1862'; Token='entropy/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1863'; Token='entropy.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1864'; Token='entropy/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1865'; Token='entropy.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1866'; Token='entropy/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1867'; Token='whiteout.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1868'; Token='whiteout/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1869'; Token='whiteout.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1870'; Token='whiteout/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1871'; Token='whiteout.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1872'; Token='whiteout/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1873'; Token='whiteout.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1874'; Token='whiteout/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1875'; Token='whiteout.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1876'; Token='whiteout/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1877'; Token='whiteout.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1878'; Token='whiteout/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1879'; Token='whiteout.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1880'; Token='whiteout/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1881'; Token='whiteout.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1882'; Token='whiteout/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1883'; Token='whiteout.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1884'; Token='whiteout/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1885'; Token='whiteout.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1886'; Token='whiteout/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1887'; Token='whiteout.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1888'; Token='whiteout/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1889'; Token='whiteout.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1890'; Token='whiteout/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1891'; Token='whiteout.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1892'; Token='whiteout/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1893'; Token='whiteout.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1894'; Token='whiteout/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1895'; Token='whiteout.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1896'; Token='whiteout/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1897'; Token='whiteout.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1898'; Token='whiteout/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1899'; Token='whiteout.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1900'; Token='whiteout/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1901'; Token='whiteout.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1902'; Token='whiteout/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1903'; Token='slinky.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1904'; Token='slinky/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1905'; Token='slinky.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1906'; Token='slinky/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1907'; Token='slinky.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1908'; Token='slinky/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1909'; Token='slinky.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1910'; Token='slinky/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1911'; Token='slinky.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1912'; Token='slinky/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1913'; Token='slinky.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1914'; Token='slinky/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1915'; Token='slinky.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1916'; Token='slinky/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1917'; Token='slinky.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1918'; Token='slinky/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1919'; Token='slinky.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1920'; Token='slinky/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1921'; Token='slinky.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1922'; Token='slinky/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1923'; Token='slinky.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1924'; Token='slinky/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1925'; Token='slinky.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1926'; Token='slinky/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1927'; Token='slinky.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1928'; Token='slinky/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1929'; Token='slinky.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1930'; Token='slinky/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1931'; Token='slinky.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1932'; Token='slinky/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1933'; Token='slinky.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1934'; Token='slinky/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1935'; Token='slinky.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1936'; Token='slinky/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1937'; Token='slinky.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1938'; Token='slinky/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1939'; Token='dream.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1940'; Token='dream/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1941'; Token='dream.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1942'; Token='dream/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1943'; Token='dream.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1944'; Token='dream/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1945'; Token='dream.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1946'; Token='dream/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1947'; Token='dream.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1948'; Token='dream/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1949'; Token='dream.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1950'; Token='dream/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1951'; Token='dream.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1952'; Token='dream/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1953'; Token='dream.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1954'; Token='dream/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1955'; Token='dream.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1956'; Token='dream/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1957'; Token='dream.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1958'; Token='dream/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1959'; Token='dream.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1960'; Token='dream/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1961'; Token='dream.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1962'; Token='dream/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1963'; Token='dream.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1964'; Token='dream/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1965'; Token='dream.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1966'; Token='dream/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1967'; Token='dream.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1968'; Token='dream/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1969'; Token='dream.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1970'; Token='dream/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1971'; Token='dream.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1972'; Token='dream/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1973'; Token='dream.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1974'; Token='dream/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1975'; Token='liquidbounce.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1976'; Token='liquidbounce/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1977'; Token='liquidbounce.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1978'; Token='liquidbounce/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1979'; Token='liquidbounce.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1980'; Token='liquidbounce/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1981'; Token='liquidbounce.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1982'; Token='liquidbounce/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1983'; Token='liquidbounce.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1984'; Token='liquidbounce/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1985'; Token='liquidbounce.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1986'; Token='liquidbounce/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1987'; Token='liquidbounce.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1988'; Token='liquidbounce/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1989'; Token='liquidbounce.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1990'; Token='liquidbounce/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1991'; Token='liquidbounce.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1992'; Token='liquidbounce/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1993'; Token='liquidbounce.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1994'; Token='liquidbounce/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1995'; Token='liquidbounce.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1996'; Token='liquidbounce/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1997'; Token='liquidbounce.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1998'; Token='liquidbounce/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB1999'; Token='liquidbounce.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2000'; Token='liquidbounce/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2001'; Token='liquidbounce.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2002'; Token='liquidbounce/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2003'; Token='liquidbounce.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2004'; Token='liquidbounce/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2005'; Token='liquidbounce.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2006'; Token='liquidbounce/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2007'; Token='liquidbounce.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2008'; Token='liquidbounce/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2009'; Token='liquidbounce.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2010'; Token='liquidbounce/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2011'; Token='wurst.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2012'; Token='wurst/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2013'; Token='wurst.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2014'; Token='wurst/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2015'; Token='wurst.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2016'; Token='wurst/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2017'; Token='wurst.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2018'; Token='wurst/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2019'; Token='wurst.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2020'; Token='wurst/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2021'; Token='wurst.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2022'; Token='wurst/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2023'; Token='wurst.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2024'; Token='wurst/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2025'; Token='wurst.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2026'; Token='wurst/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2027'; Token='wurst.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2028'; Token='wurst/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2029'; Token='wurst.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2030'; Token='wurst/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2031'; Token='wurst.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2032'; Token='wurst/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2033'; Token='wurst.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2034'; Token='wurst/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2035'; Token='wurst.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2036'; Token='wurst/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2037'; Token='wurst.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2038'; Token='wurst/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2039'; Token='wurst.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2040'; Token='wurst/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2041'; Token='wurst.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2042'; Token='wurst/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2043'; Token='wurst.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2044'; Token='wurst/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2045'; Token='wurst.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2046'; Token='wurst/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2047'; Token='meteor.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2048'; Token='meteor/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2049'; Token='meteor.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2050'; Token='meteor/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2051'; Token='meteor.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2052'; Token='meteor/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2053'; Token='meteor.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2054'; Token='meteor/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2055'; Token='meteor.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2056'; Token='meteor/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2057'; Token='meteor.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2058'; Token='meteor/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2059'; Token='meteor.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2060'; Token='meteor/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2061'; Token='meteor.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2062'; Token='meteor/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2063'; Token='meteor.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2064'; Token='meteor/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2065'; Token='meteor.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2066'; Token='meteor/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2067'; Token='meteor.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2068'; Token='meteor/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2069'; Token='meteor.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2070'; Token='meteor/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2071'; Token='meteor.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2072'; Token='meteor/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2073'; Token='meteor.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2074'; Token='meteor/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2075'; Token='meteor.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2076'; Token='meteor/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2077'; Token='meteor.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2078'; Token='meteor/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2079'; Token='meteor.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2080'; Token='meteor/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2081'; Token='meteor.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2082'; Token='meteor/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2083'; Token='aristois.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2084'; Token='aristois/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2085'; Token='aristois.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2086'; Token='aristois/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2087'; Token='aristois.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2088'; Token='aristois/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2089'; Token='aristois.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2090'; Token='aristois/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2091'; Token='aristois.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2092'; Token='aristois/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2093'; Token='aristois.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2094'; Token='aristois/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2095'; Token='aristois.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2096'; Token='aristois/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2097'; Token='aristois.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2098'; Token='aristois/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2099'; Token='aristois.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2100'; Token='aristois/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2101'; Token='aristois.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2102'; Token='aristois/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2103'; Token='aristois.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2104'; Token='aristois/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2105'; Token='aristois.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2106'; Token='aristois/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2107'; Token='aristois.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2108'; Token='aristois/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2109'; Token='aristois.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2110'; Token='aristois/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2111'; Token='aristois.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2112'; Token='aristois/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2113'; Token='aristois.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2114'; Token='aristois/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2115'; Token='aristois.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2116'; Token='aristois/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2117'; Token='aristois.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2118'; Token='aristois/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2119'; Token='impact.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2120'; Token='impact/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2121'; Token='impact.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2122'; Token='impact/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2123'; Token='impact.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2124'; Token='impact/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2125'; Token='impact.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2126'; Token='impact/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2127'; Token='impact.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2128'; Token='impact/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2129'; Token='impact.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2130'; Token='impact/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2131'; Token='impact.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2132'; Token='impact/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2133'; Token='impact.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2134'; Token='impact/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2135'; Token='impact.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2136'; Token='impact/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2137'; Token='impact.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2138'; Token='impact/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2139'; Token='impact.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2140'; Token='impact/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2141'; Token='impact.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2142'; Token='impact/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2143'; Token='impact.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2144'; Token='impact/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2145'; Token='impact.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2146'; Token='impact/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2147'; Token='impact.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2148'; Token='impact/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2149'; Token='impact.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2150'; Token='impact/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2151'; Token='impact.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2152'; Token='impact/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2153'; Token='impact.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2154'; Token='impact/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2155'; Token='future.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2156'; Token='future/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2157'; Token='future.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2158'; Token='future/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2159'; Token='future.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2160'; Token='future/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2161'; Token='future.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2162'; Token='future/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2163'; Token='future.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2164'; Token='future/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2165'; Token='future.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2166'; Token='future/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2167'; Token='future.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2168'; Token='future/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2169'; Token='future.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2170'; Token='future/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2171'; Token='future.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2172'; Token='future/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2173'; Token='future.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2174'; Token='future/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2175'; Token='future.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2176'; Token='future/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2177'; Token='future.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2178'; Token='future/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2179'; Token='future.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2180'; Token='future/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2181'; Token='future.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2182'; Token='future/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2183'; Token='future.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2184'; Token='future/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2185'; Token='future.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2186'; Token='future/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2187'; Token='future.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2188'; Token='future/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2189'; Token='future.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2190'; Token='future/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2191'; Token='rusherhack.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2192'; Token='rusherhack/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2193'; Token='rusherhack.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2194'; Token='rusherhack/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2195'; Token='rusherhack.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2196'; Token='rusherhack/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2197'; Token='rusherhack.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2198'; Token='rusherhack/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2199'; Token='rusherhack.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2200'; Token='rusherhack/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2201'; Token='rusherhack.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2202'; Token='rusherhack/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2203'; Token='rusherhack.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2204'; Token='rusherhack/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2205'; Token='rusherhack.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2206'; Token='rusherhack/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2207'; Token='rusherhack.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2208'; Token='rusherhack/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2209'; Token='rusherhack.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2210'; Token='rusherhack/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2211'; Token='rusherhack.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2212'; Token='rusherhack/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2213'; Token='rusherhack.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2214'; Token='rusherhack/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2215'; Token='rusherhack.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2216'; Token='rusherhack/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2217'; Token='rusherhack.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2218'; Token='rusherhack/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2219'; Token='rusherhack.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2220'; Token='rusherhack/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2221'; Token='rusherhack.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2222'; Token='rusherhack/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2223'; Token='rusherhack.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2224'; Token='rusherhack/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2225'; Token='rusherhack.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2226'; Token='rusherhack/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2227'; Token='lambda.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2228'; Token='lambda/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2229'; Token='lambda.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2230'; Token='lambda/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2231'; Token='lambda.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2232'; Token='lambda/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2233'; Token='lambda.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2234'; Token='lambda/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2235'; Token='lambda.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2236'; Token='lambda/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2237'; Token='lambda.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2238'; Token='lambda/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2239'; Token='lambda.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2240'; Token='lambda/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2241'; Token='lambda.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2242'; Token='lambda/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2243'; Token='lambda.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2244'; Token='lambda/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2245'; Token='lambda.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2246'; Token='lambda/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2247'; Token='lambda.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2248'; Token='lambda/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2249'; Token='lambda.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2250'; Token='lambda/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2251'; Token='lambda.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2252'; Token='lambda/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2253'; Token='lambda.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2254'; Token='lambda/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2255'; Token='lambda.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2256'; Token='lambda/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2257'; Token='lambda.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2258'; Token='lambda/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2259'; Token='lambda.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2260'; Token='lambda/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2261'; Token='lambda.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2262'; Token='lambda/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2263'; Token='kami.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2264'; Token='kami/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2265'; Token='kami.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2266'; Token='kami/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2267'; Token='kami.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2268'; Token='kami/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2269'; Token='kami.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2270'; Token='kami/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2271'; Token='kami.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2272'; Token='kami/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2273'; Token='kami.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2274'; Token='kami/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2275'; Token='kami.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2276'; Token='kami/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2277'; Token='kami.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2278'; Token='kami/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2279'; Token='kami.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2280'; Token='kami/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2281'; Token='kami.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2282'; Token='kami/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2283'; Token='kami.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2284'; Token='kami/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2285'; Token='kami.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2286'; Token='kami/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2287'; Token='kami.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2288'; Token='kami/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2289'; Token='kami.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2290'; Token='kami/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2291'; Token='kami.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2292'; Token='kami/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2293'; Token='kami.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2294'; Token='kami/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2295'; Token='kami.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2296'; Token='kami/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2297'; Token='kami.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2298'; Token='kami/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2299'; Token='kamiblue.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2300'; Token='kamiblue/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2301'; Token='kamiblue.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2302'; Token='kamiblue/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2303'; Token='kamiblue.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2304'; Token='kamiblue/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2305'; Token='kamiblue.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2306'; Token='kamiblue/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2307'; Token='kamiblue.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2308'; Token='kamiblue/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2309'; Token='kamiblue.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2310'; Token='kamiblue/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2311'; Token='kamiblue.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2312'; Token='kamiblue/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2313'; Token='kamiblue.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2314'; Token='kamiblue/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2315'; Token='kamiblue.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2316'; Token='kamiblue/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2317'; Token='kamiblue.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2318'; Token='kamiblue/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2319'; Token='kamiblue.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2320'; Token='kamiblue/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2321'; Token='kamiblue.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2322'; Token='kamiblue/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2323'; Token='kamiblue.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2324'; Token='kamiblue/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2325'; Token='kamiblue.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2326'; Token='kamiblue/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2327'; Token='kamiblue.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2328'; Token='kamiblue/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2329'; Token='kamiblue.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2330'; Token='kamiblue/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2331'; Token='kamiblue.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2332'; Token='kamiblue/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2333'; Token='kamiblue.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2334'; Token='kamiblue/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2335'; Token='salhack.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2336'; Token='salhack/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2337'; Token='salhack.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2338'; Token='salhack/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2339'; Token='salhack.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2340'; Token='salhack/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2341'; Token='salhack.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2342'; Token='salhack/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2343'; Token='salhack.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2344'; Token='salhack/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2345'; Token='salhack.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2346'; Token='salhack/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2347'; Token='salhack.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2348'; Token='salhack/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2349'; Token='salhack.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2350'; Token='salhack/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2351'; Token='salhack.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2352'; Token='salhack/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2353'; Token='salhack.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2354'; Token='salhack/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2355'; Token='salhack.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2356'; Token='salhack/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2357'; Token='salhack.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2358'; Token='salhack/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2359'; Token='salhack.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2360'; Token='salhack/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2361'; Token='salhack.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2362'; Token='salhack/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2363'; Token='salhack.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2364'; Token='salhack/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2365'; Token='salhack.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2366'; Token='salhack/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2367'; Token='salhack.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2368'; Token='salhack/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2369'; Token='salhack.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2370'; Token='salhack/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2371'; Token='phobos.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2372'; Token='phobos/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2373'; Token='phobos.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2374'; Token='phobos/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2375'; Token='phobos.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2376'; Token='phobos/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2377'; Token='phobos.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2378'; Token='phobos/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2379'; Token='phobos.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2380'; Token='phobos/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2381'; Token='phobos.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2382'; Token='phobos/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2383'; Token='phobos.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2384'; Token='phobos/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2385'; Token='phobos.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2386'; Token='phobos/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2387'; Token='phobos.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2388'; Token='phobos/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2389'; Token='phobos.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2390'; Token='phobos/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2391'; Token='phobos.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2392'; Token='phobos/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2393'; Token='phobos.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2394'; Token='phobos/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2395'; Token='phobos.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2396'; Token='phobos/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2397'; Token='phobos.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2398'; Token='phobos/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2399'; Token='phobos.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2400'; Token='phobos/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2401'; Token='phobos.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2402'; Token='phobos/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2403'; Token='phobos.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2404'; Token='phobos/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2405'; Token='phobos.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2406'; Token='phobos/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2407'; Token='konas.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2408'; Token='konas/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2409'; Token='konas.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2410'; Token='konas/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2411'; Token='konas.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2412'; Token='konas/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2413'; Token='konas.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2414'; Token='konas/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2415'; Token='konas.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2416'; Token='konas/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2417'; Token='konas.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2418'; Token='konas/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2419'; Token='konas.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2420'; Token='konas/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2421'; Token='konas.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2422'; Token='konas/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2423'; Token='konas.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2424'; Token='konas/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2425'; Token='konas.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2426'; Token='konas/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2427'; Token='konas.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2428'; Token='konas/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2429'; Token='konas.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2430'; Token='konas/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2431'; Token='konas.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2432'; Token='konas/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2433'; Token='konas.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2434'; Token='konas/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2435'; Token='konas.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2436'; Token='konas/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2437'; Token='konas.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2438'; Token='konas/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2439'; Token='konas.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2440'; Token='konas/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2441'; Token='konas.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2442'; Token='konas/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2443'; Token='pyro.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2444'; Token='pyro/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2445'; Token='pyro.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2446'; Token='pyro/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2447'; Token='pyro.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2448'; Token='pyro/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2449'; Token='pyro.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2450'; Token='pyro/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2451'; Token='pyro.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2452'; Token='pyro/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2453'; Token='pyro.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2454'; Token='pyro/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2455'; Token='pyro.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2456'; Token='pyro/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2457'; Token='pyro.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2458'; Token='pyro/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2459'; Token='pyro.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2460'; Token='pyro/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2461'; Token='pyro.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2462'; Token='pyro/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2463'; Token='pyro.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2464'; Token='pyro/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2465'; Token='pyro.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2466'; Token='pyro/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2467'; Token='pyro.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2468'; Token='pyro/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2469'; Token='pyro.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2470'; Token='pyro/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2471'; Token='pyro.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2472'; Token='pyro/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2473'; Token='pyro.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2474'; Token='pyro/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2475'; Token='pyro.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2476'; Token='pyro/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2477'; Token='pyro.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2478'; Token='pyro/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2479'; Token='gamesense.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2480'; Token='gamesense/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2481'; Token='gamesense.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2482'; Token='gamesense/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2483'; Token='gamesense.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2484'; Token='gamesense/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2485'; Token='gamesense.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2486'; Token='gamesense/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2487'; Token='gamesense.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2488'; Token='gamesense/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2489'; Token='gamesense.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2490'; Token='gamesense/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2491'; Token='gamesense.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2492'; Token='gamesense/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2493'; Token='gamesense.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2494'; Token='gamesense/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2495'; Token='gamesense.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2496'; Token='gamesense/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2497'; Token='gamesense.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2498'; Token='gamesense/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2499'; Token='gamesense.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2500'; Token='gamesense/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2501'; Token='gamesense.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2502'; Token='gamesense/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2503'; Token='gamesense.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2504'; Token='gamesense/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2505'; Token='gamesense.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2506'; Token='gamesense/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2507'; Token='gamesense.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2508'; Token='gamesense/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2509'; Token='gamesense.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2510'; Token='gamesense/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2511'; Token='gamesense.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2512'; Token='gamesense/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2513'; Token='gamesense.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2514'; Token='gamesense/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2515'; Token='oyvey.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2516'; Token='oyvey/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2517'; Token='oyvey.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2518'; Token='oyvey/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2519'; Token='oyvey.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2520'; Token='oyvey/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2521'; Token='oyvey.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2522'; Token='oyvey/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2523'; Token='oyvey.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2524'; Token='oyvey/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2525'; Token='oyvey.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2526'; Token='oyvey/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2527'; Token='oyvey.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2528'; Token='oyvey/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2529'; Token='oyvey.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2530'; Token='oyvey/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2531'; Token='oyvey.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2532'; Token='oyvey/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2533'; Token='oyvey.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2534'; Token='oyvey/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2535'; Token='oyvey.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2536'; Token='oyvey/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2537'; Token='oyvey.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2538'; Token='oyvey/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2539'; Token='oyvey.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2540'; Token='oyvey/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2541'; Token='oyvey.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2542'; Token='oyvey/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2543'; Token='oyvey.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2544'; Token='oyvey/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2545'; Token='oyvey.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2546'; Token='oyvey/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2547'; Token='oyvey.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2548'; Token='oyvey/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2549'; Token='oyvey.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2550'; Token='oyvey/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2551'; Token='3arthh4ck.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2552'; Token='3arthh4ck/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2553'; Token='3arthh4ck.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2554'; Token='3arthh4ck/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2555'; Token='3arthh4ck.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2556'; Token='3arthh4ck/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2557'; Token='3arthh4ck.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2558'; Token='3arthh4ck/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2559'; Token='3arthh4ck.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2560'; Token='3arthh4ck/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2561'; Token='3arthh4ck.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2562'; Token='3arthh4ck/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2563'; Token='3arthh4ck.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2564'; Token='3arthh4ck/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2565'; Token='3arthh4ck.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2566'; Token='3arthh4ck/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2567'; Token='3arthh4ck.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2568'; Token='3arthh4ck/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2569'; Token='3arthh4ck.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2570'; Token='3arthh4ck/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2571'; Token='3arthh4ck.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2572'; Token='3arthh4ck/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2573'; Token='3arthh4ck.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2574'; Token='3arthh4ck/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2575'; Token='3arthh4ck.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2576'; Token='3arthh4ck/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2577'; Token='3arthh4ck.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2578'; Token='3arthh4ck/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2579'; Token='3arthh4ck.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2580'; Token='3arthh4ck/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2581'; Token='3arthh4ck.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2582'; Token='3arthh4ck/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2583'; Token='3arthh4ck.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2584'; Token='3arthh4ck/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2585'; Token='3arthh4ck.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2586'; Token='3arthh4ck/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2587'; Token='earthhack.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2588'; Token='earthhack/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2589'; Token='earthhack.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2590'; Token='earthhack/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2591'; Token='earthhack.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2592'; Token='earthhack/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2593'; Token='earthhack.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2594'; Token='earthhack/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2595'; Token='earthhack.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2596'; Token='earthhack/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2597'; Token='earthhack.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2598'; Token='earthhack/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2599'; Token='earthhack.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2600'; Token='earthhack/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2601'; Token='earthhack.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2602'; Token='earthhack/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2603'; Token='earthhack.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2604'; Token='earthhack/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2605'; Token='earthhack.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2606'; Token='earthhack/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2607'; Token='earthhack.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2608'; Token='earthhack/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2609'; Token='earthhack.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2610'; Token='earthhack/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2611'; Token='earthhack.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2612'; Token='earthhack/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2613'; Token='earthhack.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2614'; Token='earthhack/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2615'; Token='earthhack.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2616'; Token='earthhack/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2617'; Token='earthhack.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2618'; Token='earthhack/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2619'; Token='earthhack.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2620'; Token='earthhack/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2621'; Token='earthhack.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2622'; Token='earthhack/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2623'; Token='seppuku.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2624'; Token='seppuku/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2625'; Token='seppuku.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2626'; Token='seppuku/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2627'; Token='seppuku.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2628'; Token='seppuku/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2629'; Token='seppuku.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2630'; Token='seppuku/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2631'; Token='seppuku.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2632'; Token='seppuku/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2633'; Token='seppuku.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2634'; Token='seppuku/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2635'; Token='seppuku.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2636'; Token='seppuku/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2637'; Token='seppuku.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2638'; Token='seppuku/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2639'; Token='seppuku.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2640'; Token='seppuku/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2641'; Token='seppuku.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2642'; Token='seppuku/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2643'; Token='seppuku.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2644'; Token='seppuku/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2645'; Token='seppuku.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2646'; Token='seppuku/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2647'; Token='seppuku.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2648'; Token='seppuku/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2649'; Token='seppuku.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2650'; Token='seppuku/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2651'; Token='seppuku.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2652'; Token='seppuku/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2653'; Token='seppuku.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2654'; Token='seppuku/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2655'; Token='seppuku.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2656'; Token='seppuku/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2657'; Token='seppuku.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2658'; Token='seppuku/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2659'; Token='catalyst.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2660'; Token='catalyst/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2661'; Token='catalyst.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2662'; Token='catalyst/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2663'; Token='catalyst.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2664'; Token='catalyst/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2665'; Token='catalyst.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2666'; Token='catalyst/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2667'; Token='catalyst.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2668'; Token='catalyst/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2669'; Token='catalyst.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2670'; Token='catalyst/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2671'; Token='catalyst.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2672'; Token='catalyst/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2673'; Token='catalyst.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2674'; Token='catalyst/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2675'; Token='catalyst.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2676'; Token='catalyst/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2677'; Token='catalyst.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2678'; Token='catalyst/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2679'; Token='catalyst.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2680'; Token='catalyst/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2681'; Token='catalyst.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2682'; Token='catalyst/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2683'; Token='catalyst.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2684'; Token='catalyst/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2685'; Token='catalyst.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2686'; Token='catalyst/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2687'; Token='catalyst.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2688'; Token='catalyst/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2689'; Token='catalyst.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2690'; Token='catalyst/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2691'; Token='catalyst.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2692'; Token='catalyst/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2693'; Token='catalyst.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2694'; Token='catalyst/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2695'; Token='abyss.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2696'; Token='abyss/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2697'; Token='abyss.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2698'; Token='abyss/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2699'; Token='abyss.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2700'; Token='abyss/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2701'; Token='abyss.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2702'; Token='abyss/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2703'; Token='abyss.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2704'; Token='abyss/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2705'; Token='abyss.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2706'; Token='abyss/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2707'; Token='abyss.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2708'; Token='abyss/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2709'; Token='abyss.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2710'; Token='abyss/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2711'; Token='abyss.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2712'; Token='abyss/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2713'; Token='abyss.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2714'; Token='abyss/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2715'; Token='abyss.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2716'; Token='abyss/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2717'; Token='abyss.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2718'; Token='abyss/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2719'; Token='abyss.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2720'; Token='abyss/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2721'; Token='abyss.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2722'; Token='abyss/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2723'; Token='abyss.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2724'; Token='abyss/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2725'; Token='abyss.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2726'; Token='abyss/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2727'; Token='abyss.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2728'; Token='abyss/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2729'; Token='abyss.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2730'; Token='abyss/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2731'; Token='xulu.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2732'; Token='xulu/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2733'; Token='xulu.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2734'; Token='xulu/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2735'; Token='xulu.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2736'; Token='xulu/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2737'; Token='xulu.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2738'; Token='xulu/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2739'; Token='xulu.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2740'; Token='xulu/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2741'; Token='xulu.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2742'; Token='xulu/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2743'; Token='xulu.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2744'; Token='xulu/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2745'; Token='xulu.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2746'; Token='xulu/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2747'; Token='xulu.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2748'; Token='xulu/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2749'; Token='xulu.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2750'; Token='xulu/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2751'; Token='xulu.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2752'; Token='xulu/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2753'; Token='xulu.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2754'; Token='xulu/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2755'; Token='xulu.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2756'; Token='xulu/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2757'; Token='xulu.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2758'; Token='xulu/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2759'; Token='xulu.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2760'; Token='xulu/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2761'; Token='xulu.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2762'; Token='xulu/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2763'; Token='xulu.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2764'; Token='xulu/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2765'; Token='xulu.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2766'; Token='xulu/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2767'; Token='cosmos.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2768'; Token='cosmos/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2769'; Token='cosmos.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2770'; Token='cosmos/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2771'; Token='cosmos.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2772'; Token='cosmos/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2773'; Token='cosmos.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2774'; Token='cosmos/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2775'; Token='cosmos.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2776'; Token='cosmos/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2777'; Token='cosmos.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2778'; Token='cosmos/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2779'; Token='cosmos.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2780'; Token='cosmos/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2781'; Token='cosmos.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2782'; Token='cosmos/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2783'; Token='cosmos.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2784'; Token='cosmos/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2785'; Token='cosmos.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2786'; Token='cosmos/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2787'; Token='cosmos.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2788'; Token='cosmos/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2789'; Token='cosmos.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2790'; Token='cosmos/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2791'; Token='cosmos.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2792'; Token='cosmos/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2793'; Token='cosmos.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2794'; Token='cosmos/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2795'; Token='cosmos.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2796'; Token='cosmos/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2797'; Token='cosmos.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2798'; Token='cosmos/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2799'; Token='cosmos.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2800'; Token='cosmos/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2801'; Token='cosmos.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2802'; Token='cosmos/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2803'; Token='trollhack.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2804'; Token='trollhack/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2805'; Token='trollhack.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2806'; Token='trollhack/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2807'; Token='trollhack.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2808'; Token='trollhack/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2809'; Token='trollhack.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2810'; Token='trollhack/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2811'; Token='trollhack.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2812'; Token='trollhack/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2813'; Token='trollhack.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2814'; Token='trollhack/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2815'; Token='trollhack.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2816'; Token='trollhack/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2817'; Token='trollhack.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2818'; Token='trollhack/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2819'; Token='trollhack.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2820'; Token='trollhack/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2821'; Token='trollhack.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2822'; Token='trollhack/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2823'; Token='trollhack.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2824'; Token='trollhack/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2825'; Token='trollhack.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2826'; Token='trollhack/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2827'; Token='trollhack.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2828'; Token='trollhack/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2829'; Token='trollhack.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2830'; Token='trollhack/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2831'; Token='trollhack.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2832'; Token='trollhack/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2833'; Token='trollhack.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2834'; Token='trollhack/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2835'; Token='trollhack.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2836'; Token='trollhack/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2837'; Token='trollhack.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2838'; Token='trollhack/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2839'; Token='nullpoint.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2840'; Token='nullpoint/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2841'; Token='nullpoint.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2842'; Token='nullpoint/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2843'; Token='nullpoint.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2844'; Token='nullpoint/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2845'; Token='nullpoint.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2846'; Token='nullpoint/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2847'; Token='nullpoint.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2848'; Token='nullpoint/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2849'; Token='nullpoint.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2850'; Token='nullpoint/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2851'; Token='nullpoint.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2852'; Token='nullpoint/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2853'; Token='nullpoint.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2854'; Token='nullpoint/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2855'; Token='nullpoint.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2856'; Token='nullpoint/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2857'; Token='nullpoint.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2858'; Token='nullpoint/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2859'; Token='nullpoint.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2860'; Token='nullpoint/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2861'; Token='nullpoint.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2862'; Token='nullpoint/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2863'; Token='nullpoint.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2864'; Token='nullpoint/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2865'; Token='nullpoint.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2866'; Token='nullpoint/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2867'; Token='nullpoint.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2868'; Token='nullpoint/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2869'; Token='nullpoint.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2870'; Token='nullpoint/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2871'; Token='nullpoint.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2872'; Token='nullpoint/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2873'; Token='nullpoint.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2874'; Token='nullpoint/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2875'; Token='shoreline.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2876'; Token='shoreline/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2877'; Token='shoreline.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2878'; Token='shoreline/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2879'; Token='shoreline.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2880'; Token='shoreline/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2881'; Token='shoreline.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2882'; Token='shoreline/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2883'; Token='shoreline.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2884'; Token='shoreline/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2885'; Token='shoreline.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2886'; Token='shoreline/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2887'; Token='shoreline.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2888'; Token='shoreline/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2889'; Token='shoreline.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2890'; Token='shoreline/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2891'; Token='shoreline.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2892'; Token='shoreline/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2893'; Token='shoreline.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2894'; Token='shoreline/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2895'; Token='shoreline.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2896'; Token='shoreline/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2897'; Token='shoreline.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2898'; Token='shoreline/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2899'; Token='shoreline.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2900'; Token='shoreline/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2901'; Token='shoreline.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2902'; Token='shoreline/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2903'; Token='shoreline.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2904'; Token='shoreline/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2905'; Token='shoreline.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2906'; Token='shoreline/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2907'; Token='shoreline.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2908'; Token='shoreline/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2909'; Token='shoreline.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2910'; Token='shoreline/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2911'; Token='boze.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2912'; Token='boze/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2913'; Token='boze.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2914'; Token='boze/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2915'; Token='boze.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2916'; Token='boze/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2917'; Token='boze.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2918'; Token='boze/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2919'; Token='boze.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2920'; Token='boze/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2921'; Token='boze.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2922'; Token='boze/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2923'; Token='boze.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2924'; Token='boze/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2925'; Token='boze.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2926'; Token='boze/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2927'; Token='boze.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2928'; Token='boze/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2929'; Token='boze.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2930'; Token='boze/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2931'; Token='boze.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2932'; Token='boze/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2933'; Token='boze.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2934'; Token='boze/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2935'; Token='boze.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2936'; Token='boze/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2937'; Token='boze.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2938'; Token='boze/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2939'; Token='boze.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2940'; Token='boze/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2941'; Token='boze.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2942'; Token='boze/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2943'; Token='boze.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2944'; Token='boze/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2945'; Token='boze.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2946'; Token='boze/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2947'; Token='mio.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2948'; Token='mio/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2949'; Token='mio.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2950'; Token='mio/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2951'; Token='mio.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2952'; Token='mio/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2953'; Token='mio.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2954'; Token='mio/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2955'; Token='mio.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2956'; Token='mio/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2957'; Token='mio.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2958'; Token='mio/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2959'; Token='mio.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2960'; Token='mio/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2961'; Token='mio.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2962'; Token='mio/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2963'; Token='mio.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2964'; Token='mio/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2965'; Token='mio.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2966'; Token='mio/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2967'; Token='mio.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2968'; Token='mio/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2969'; Token='mio.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2970'; Token='mio/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2971'; Token='mio.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2972'; Token='mio/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2973'; Token='mio.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2974'; Token='mio/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2975'; Token='mio.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2976'; Token='mio/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2977'; Token='mio.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2978'; Token='mio/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2979'; Token='mio.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2980'; Token='mio/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2981'; Token='mio.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2982'; Token='mio/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2983'; Token='prestige.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2984'; Token='prestige/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2985'; Token='prestige.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2986'; Token='prestige/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2987'; Token='prestige.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2988'; Token='prestige/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2989'; Token='prestige.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2990'; Token='prestige/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2991'; Token='prestige.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2992'; Token='prestige/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2993'; Token='prestige.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2994'; Token='prestige/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2995'; Token='prestige.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2996'; Token='prestige/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2997'; Token='prestige.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2998'; Token='prestige/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB2999'; Token='prestige.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3000'; Token='prestige/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3001'; Token='prestige.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3002'; Token='prestige/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3003'; Token='prestige.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3004'; Token='prestige/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3005'; Token='prestige.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3006'; Token='prestige/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3007'; Token='prestige.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3008'; Token='prestige/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3009'; Token='prestige.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3010'; Token='prestige/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3011'; Token='prestige.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3012'; Token='prestige/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3013'; Token='prestige.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3014'; Token='prestige/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3015'; Token='prestige.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3016'; Token='prestige/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3017'; Token='prestige.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3018'; Token='prestige/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3019'; Token='alien.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3020'; Token='alien/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3021'; Token='alien.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3022'; Token='alien/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3023'; Token='alien.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3024'; Token='alien/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3025'; Token='alien.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3026'; Token='alien/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3027'; Token='alien.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3028'; Token='alien/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3029'; Token='alien.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3030'; Token='alien/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3031'; Token='alien.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3032'; Token='alien/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3033'; Token='alien.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3034'; Token='alien/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3035'; Token='alien.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3036'; Token='alien/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3037'; Token='alien.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3038'; Token='alien/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3039'; Token='alien.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3040'; Token='alien/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3041'; Token='alien.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3042'; Token='alien/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3043'; Token='alien.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3044'; Token='alien/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3045'; Token='alien.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3046'; Token='alien/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3047'; Token='alien.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3048'; Token='alien/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3049'; Token='alien.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3050'; Token='alien/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3051'; Token='alien.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3052'; Token='alien/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3053'; Token='alien.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3054'; Token='alien/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3055'; Token='thunderhack.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3056'; Token='thunderhack/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3057'; Token='thunderhack.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3058'; Token='thunderhack/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3059'; Token='thunderhack.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3060'; Token='thunderhack/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3061'; Token='thunderhack.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3062'; Token='thunderhack/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3063'; Token='thunderhack.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3064'; Token='thunderhack/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3065'; Token='thunderhack.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3066'; Token='thunderhack/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3067'; Token='thunderhack.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3068'; Token='thunderhack/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3069'; Token='thunderhack.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3070'; Token='thunderhack/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3071'; Token='thunderhack.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3072'; Token='thunderhack/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3073'; Token='thunderhack.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3074'; Token='thunderhack/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3075'; Token='thunderhack.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3076'; Token='thunderhack/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3077'; Token='thunderhack.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3078'; Token='thunderhack/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3079'; Token='thunderhack.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3080'; Token='thunderhack/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3081'; Token='thunderhack.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3082'; Token='thunderhack/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3083'; Token='thunderhack.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3084'; Token='thunderhack/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3085'; Token='thunderhack.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3086'; Token='thunderhack/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3087'; Token='thunderhack.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3088'; Token='thunderhack/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3089'; Token='thunderhack.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3090'; Token='thunderhack/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3091'; Token='bleachhack.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3092'; Token='bleachhack/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3093'; Token='bleachhack.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3094'; Token='bleachhack/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3095'; Token='bleachhack.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3096'; Token='bleachhack/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3097'; Token='bleachhack.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3098'; Token='bleachhack/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3099'; Token='bleachhack.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3100'; Token='bleachhack/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3101'; Token='bleachhack.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3102'; Token='bleachhack/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3103'; Token='bleachhack.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3104'; Token='bleachhack/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3105'; Token='bleachhack.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3106'; Token='bleachhack/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3107'; Token='bleachhack.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3108'; Token='bleachhack/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3109'; Token='bleachhack.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3110'; Token='bleachhack/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3111'; Token='bleachhack.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3112'; Token='bleachhack/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3113'; Token='bleachhack.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3114'; Token='bleachhack/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3115'; Token='bleachhack.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3116'; Token='bleachhack/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3117'; Token='bleachhack.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3118'; Token='bleachhack/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3119'; Token='bleachhack.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3120'; Token='bleachhack/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3121'; Token='bleachhack.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3122'; Token='bleachhack/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3123'; Token='bleachhack.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3124'; Token='bleachhack/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3125'; Token='bleachhack.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3126'; Token='bleachhack/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3127'; Token='forgehax.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3128'; Token='forgehax/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3129'; Token='forgehax.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3130'; Token='forgehax/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3131'; Token='forgehax.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3132'; Token='forgehax/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3133'; Token='forgehax.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3134'; Token='forgehax/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3135'; Token='forgehax.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3136'; Token='forgehax/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3137'; Token='forgehax.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3138'; Token='forgehax/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3139'; Token='forgehax.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3140'; Token='forgehax/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3141'; Token='forgehax.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3142'; Token='forgehax/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3143'; Token='forgehax.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3144'; Token='forgehax/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3145'; Token='forgehax.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3146'; Token='forgehax/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3147'; Token='forgehax.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3148'; Token='forgehax/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3149'; Token='forgehax.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3150'; Token='forgehax/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3151'; Token='forgehax.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3152'; Token='forgehax/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3153'; Token='forgehax.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3154'; Token='forgehax/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3155'; Token='forgehax.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3156'; Token='forgehax/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3157'; Token='forgehax.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3158'; Token='forgehax/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3159'; Token='forgehax.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3160'; Token='forgehax/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3161'; Token='forgehax.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3162'; Token='forgehax/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3163'; Token='inertia.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3164'; Token='inertia/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3165'; Token='inertia.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3166'; Token='inertia/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3167'; Token='inertia.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3168'; Token='inertia/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3169'; Token='inertia.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3170'; Token='inertia/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3171'; Token='inertia.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3172'; Token='inertia/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3173'; Token='inertia.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3174'; Token='inertia/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3175'; Token='inertia.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3176'; Token='inertia/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3177'; Token='inertia.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3178'; Token='inertia/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3179'; Token='inertia.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3180'; Token='inertia/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3181'; Token='inertia.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3182'; Token='inertia/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3183'; Token='inertia.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3184'; Token='inertia/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3185'; Token='inertia.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3186'; Token='inertia/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3187'; Token='inertia.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3188'; Token='inertia/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3189'; Token='inertia.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3190'; Token='inertia/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3191'; Token='inertia.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3192'; Token='inertia/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3193'; Token='inertia.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3194'; Token='inertia/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3195'; Token='inertia.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3196'; Token='inertia/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3197'; Token='inertia.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3198'; Token='inertia/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3199'; Token='sigma.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3200'; Token='sigma/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3201'; Token='sigma.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3202'; Token='sigma/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3203'; Token='sigma.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3204'; Token='sigma/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3205'; Token='sigma.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3206'; Token='sigma/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3207'; Token='sigma.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3208'; Token='sigma/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3209'; Token='sigma.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3210'; Token='sigma/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3211'; Token='sigma.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3212'; Token='sigma/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3213'; Token='sigma.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3214'; Token='sigma/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3215'; Token='sigma.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3216'; Token='sigma/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3217'; Token='sigma.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3218'; Token='sigma/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3219'; Token='sigma.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3220'; Token='sigma/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3221'; Token='sigma.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3222'; Token='sigma/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3223'; Token='sigma.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3224'; Token='sigma/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3225'; Token='sigma.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3226'; Token='sigma/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3227'; Token='sigma.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3228'; Token='sigma/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3229'; Token='sigma.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3230'; Token='sigma/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3231'; Token='sigma.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3232'; Token='sigma/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3233'; Token='sigma.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3234'; Token='sigma/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3235'; Token='flux.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3236'; Token='flux/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3237'; Token='flux.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3238'; Token='flux/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3239'; Token='flux.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3240'; Token='flux/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3241'; Token='flux.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3242'; Token='flux/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3243'; Token='flux.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3244'; Token='flux/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3245'; Token='flux.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3246'; Token='flux/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3247'; Token='flux.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3248'; Token='flux/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3249'; Token='flux.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3250'; Token='flux/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3251'; Token='flux.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3252'; Token='flux/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3253'; Token='flux.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3254'; Token='flux/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3255'; Token='flux.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3256'; Token='flux/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3257'; Token='flux.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3258'; Token='flux/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3259'; Token='flux.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3260'; Token='flux/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3261'; Token='flux.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3262'; Token='flux/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3263'; Token='flux.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3264'; Token='flux/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3265'; Token='flux.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3266'; Token='flux/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3267'; Token='flux.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3268'; Token='flux/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3269'; Token='flux.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3270'; Token='flux/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3271'; Token='tenacity.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3272'; Token='tenacity/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3273'; Token='tenacity.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3274'; Token='tenacity/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3275'; Token='tenacity.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3276'; Token='tenacity/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3277'; Token='tenacity.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3278'; Token='tenacity/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3279'; Token='tenacity.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3280'; Token='tenacity/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3281'; Token='tenacity.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3282'; Token='tenacity/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3283'; Token='tenacity.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3284'; Token='tenacity/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3285'; Token='tenacity.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3286'; Token='tenacity/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3287'; Token='tenacity.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3288'; Token='tenacity/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3289'; Token='tenacity.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3290'; Token='tenacity/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3291'; Token='tenacity.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3292'; Token='tenacity/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3293'; Token='tenacity.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3294'; Token='tenacity/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3295'; Token='tenacity.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3296'; Token='tenacity/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3297'; Token='tenacity.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3298'; Token='tenacity/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3299'; Token='tenacity.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3300'; Token='tenacity/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3301'; Token='tenacity.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3302'; Token='tenacity/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3303'; Token='tenacity.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3304'; Token='tenacity/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3305'; Token='tenacity.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3306'; Token='tenacity/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3307'; Token='zeroday.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3308'; Token='zeroday/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3309'; Token='zeroday.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3310'; Token='zeroday/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3311'; Token='zeroday.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3312'; Token='zeroday/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3313'; Token='zeroday.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3314'; Token='zeroday/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3315'; Token='zeroday.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3316'; Token='zeroday/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3317'; Token='zeroday.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3318'; Token='zeroday/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3319'; Token='zeroday.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3320'; Token='zeroday/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3321'; Token='zeroday.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3322'; Token='zeroday/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3323'; Token='zeroday.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3324'; Token='zeroday/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3325'; Token='zeroday.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3326'; Token='zeroday/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3327'; Token='zeroday.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3328'; Token='zeroday/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3329'; Token='zeroday.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3330'; Token='zeroday/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3331'; Token='zeroday.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3332'; Token='zeroday/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3333'; Token='zeroday.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3334'; Token='zeroday/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3335'; Token='zeroday.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3336'; Token='zeroday/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3337'; Token='zeroday.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3338'; Token='zeroday/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3339'; Token='zeroday.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3340'; Token='zeroday/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3341'; Token='zeroday.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3342'; Token='zeroday/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3343'; Token='exhibition.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3344'; Token='exhibition/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3345'; Token='exhibition.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3346'; Token='exhibition/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3347'; Token='exhibition.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3348'; Token='exhibition/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3349'; Token='exhibition.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3350'; Token='exhibition/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3351'; Token='exhibition.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3352'; Token='exhibition/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3353'; Token='exhibition.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3354'; Token='exhibition/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3355'; Token='exhibition.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3356'; Token='exhibition/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3357'; Token='exhibition.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3358'; Token='exhibition/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3359'; Token='exhibition.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3360'; Token='exhibition/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3361'; Token='exhibition.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3362'; Token='exhibition/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3363'; Token='exhibition.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3364'; Token='exhibition/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3365'; Token='exhibition.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3366'; Token='exhibition/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3367'; Token='exhibition.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3368'; Token='exhibition/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3369'; Token='exhibition.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3370'; Token='exhibition/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3371'; Token='exhibition.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3372'; Token='exhibition/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3373'; Token='exhibition.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3374'; Token='exhibition/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3375'; Token='exhibition.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3376'; Token='exhibition/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3377'; Token='exhibition.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3378'; Token='exhibition/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3379'; Token='astolfo.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3380'; Token='astolfo/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3381'; Token='astolfo.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3382'; Token='astolfo/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3383'; Token='astolfo.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3384'; Token='astolfo/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3385'; Token='astolfo.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3386'; Token='astolfo/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3387'; Token='astolfo.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3388'; Token='astolfo/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3389'; Token='astolfo.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3390'; Token='astolfo/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3391'; Token='astolfo.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3392'; Token='astolfo/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3393'; Token='astolfo.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3394'; Token='astolfo/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3395'; Token='astolfo.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3396'; Token='astolfo/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3397'; Token='astolfo.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3398'; Token='astolfo/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3399'; Token='astolfo.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3400'; Token='astolfo/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3401'; Token='astolfo.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3402'; Token='astolfo/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3403'; Token='astolfo.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3404'; Token='astolfo/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3405'; Token='astolfo.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3406'; Token='astolfo/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3407'; Token='astolfo.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3408'; Token='astolfo/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3409'; Token='astolfo.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3410'; Token='astolfo/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3411'; Token='astolfo.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3412'; Token='astolfo/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3413'; Token='astolfo.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3414'; Token='astolfo/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3415'; Token='novoline.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3416'; Token='novoline/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3417'; Token='novoline.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3418'; Token='novoline/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3419'; Token='novoline.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3420'; Token='novoline/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3421'; Token='novoline.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3422'; Token='novoline/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3423'; Token='novoline.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3424'; Token='novoline/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3425'; Token='novoline.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3426'; Token='novoline/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3427'; Token='novoline.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3428'; Token='novoline/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3429'; Token='novoline.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3430'; Token='novoline/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3431'; Token='novoline.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3432'; Token='novoline/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3433'; Token='novoline.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3434'; Token='novoline/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3435'; Token='novoline.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3436'; Token='novoline/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3437'; Token='novoline.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3438'; Token='novoline/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3439'; Token='novoline.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3440'; Token='novoline/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3441'; Token='novoline.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3442'; Token='novoline/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3443'; Token='novoline.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3444'; Token='novoline/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3445'; Token='novoline.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3446'; Token='novoline/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3447'; Token='novoline.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3448'; Token='novoline/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3449'; Token='novoline.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3450'; Token='novoline/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3451'; Token='novo.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3452'; Token='novo/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3453'; Token='novo.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3454'; Token='novo/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3455'; Token='novo.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3456'; Token='novo/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3457'; Token='novo.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3458'; Token='novo/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3459'; Token='novo.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3460'; Token='novo/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3461'; Token='novo.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3462'; Token='novo/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3463'; Token='novo.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3464'; Token='novo/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3465'; Token='novo.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3466'; Token='novo/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3467'; Token='novo.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3468'; Token='novo/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3469'; Token='novo.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3470'; Token='novo/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3471'; Token='novo.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3472'; Token='novo/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3473'; Token='novo.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3474'; Token='novo/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3475'; Token='novo.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3476'; Token='novo/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3477'; Token='novo.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3478'; Token='novo/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3479'; Token='novo.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3480'; Token='novo/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3481'; Token='novo.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3482'; Token='novo/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3483'; Token='novo.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3484'; Token='novo/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3485'; Token='novo.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3486'; Token='novo/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3487'; Token='remix.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3488'; Token='remix/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3489'; Token='remix.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3490'; Token='remix/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3491'; Token='remix.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3492'; Token='remix/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3493'; Token='remix.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3494'; Token='remix/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3495'; Token='remix.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3496'; Token='remix/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3497'; Token='remix.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3498'; Token='remix/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3499'; Token='remix.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3500'; Token='remix/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3501'; Token='remix.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3502'; Token='remix/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3503'; Token='remix.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3504'; Token='remix/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3505'; Token='remix.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3506'; Token='remix/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3507'; Token='remix.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3508'; Token='remix/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3509'; Token='remix.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3510'; Token='remix/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3511'; Token='remix.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3512'; Token='remix/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3513'; Token='remix.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3514'; Token='remix/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3515'; Token='remix.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3516'; Token='remix/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3517'; Token='remix.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3518'; Token='remix/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3519'; Token='remix.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3520'; Token='remix/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3521'; Token='remix.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3522'; Token='remix/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3523'; Token='huzuni.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3524'; Token='huzuni/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3525'; Token='huzuni.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3526'; Token='huzuni/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3527'; Token='huzuni.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3528'; Token='huzuni/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3529'; Token='huzuni.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3530'; Token='huzuni/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3531'; Token='huzuni.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3532'; Token='huzuni/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3533'; Token='huzuni.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3534'; Token='huzuni/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3535'; Token='huzuni.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3536'; Token='huzuni/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3537'; Token='huzuni.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3538'; Token='huzuni/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3539'; Token='huzuni.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3540'; Token='huzuni/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3541'; Token='huzuni.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3542'; Token='huzuni/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3543'; Token='huzuni.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3544'; Token='huzuni/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3545'; Token='huzuni.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3546'; Token='huzuni/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3547'; Token='huzuni.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3548'; Token='huzuni/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3549'; Token='huzuni.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3550'; Token='huzuni/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3551'; Token='huzuni.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3552'; Token='huzuni/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3553'; Token='huzuni.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3554'; Token='huzuni/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3555'; Token='huzuni.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3556'; Token='huzuni/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3557'; Token='huzuni.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3558'; Token='huzuni/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3559'; Token='wolfram.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3560'; Token='wolfram/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3561'; Token='wolfram.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3562'; Token='wolfram/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3563'; Token='wolfram.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3564'; Token='wolfram/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3565'; Token='wolfram.loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3566'; Token='wolfram/loader'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3567'; Token='wolfram.injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3568'; Token='wolfram/injector'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3569'; Token='wolfram.api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3570'; Token='wolfram/api'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3571'; Token='wolfram.gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3572'; Token='wolfram/gui'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3573'; Token='wolfram.combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3574'; Token='wolfram/combat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3575'; Token='wolfram.movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3576'; Token='wolfram/movement'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3577'; Token='wolfram.render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3578'; Token='wolfram/render'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3579'; Token='wolfram.exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3580'; Token='wolfram/exploit'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3581'; Token='wolfram.event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3582'; Token='wolfram/event'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3583'; Token='wolfram.mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3584'; Token='wolfram/mixin'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3585'; Token='wolfram.manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3586'; Token='wolfram/manager'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3587'; Token='wolfram.impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3588'; Token='wolfram/impl'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3589'; Token='wolfram.features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3590'; Token='wolfram/features'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3591'; Token='wolfram.hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3592'; Token='wolfram/hack'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3593'; Token='wolfram.cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3594'; Token='wolfram/cheat'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3595'; Token='nodus.client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3596'; Token='nodus/client'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3597'; Token='nodus.module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3598'; Token='nodus/module'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3599'; Token='nodus.mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
    [pscustomobject]@{ Id='KB3600'; Token='nodus/mod'; Category='package_fragment'; Weight=45; Applies='path,file,jar,log,trace' }
)

try {
    Main
} finally {
    Remove-Workspace
}
