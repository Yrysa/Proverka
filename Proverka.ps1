#Requires -Version 5.1
<#
YRYS CHECKER - autonomous local anti-cheat risk scanner for Windows / Minecraft.
No permanent reports. Temporary working files are deleted on normal exit and by a cleanup watcher after the console closes.

Design goals:
- Fast candidate discovery across the system.
- Strict scoring instead of noisy red spam.
- Checks EXE / DLL / JAR linked to cheat software.
- Local "AI-like" expert risk engine. No internet, no cloud, no upload.
#>

[CmdletBinding()]
param(
    [string[]]$Cheat,
    [switch]$Deep,
    [switch]$Fast,
    [switch]$NoPrompt,
    [int]$MaxMinutes = 10,
    [int]$MaxFileSizeMB = 120,
    [int]$MaxStringScanMB = 24,
    [int]$Top = 40
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "SilentlyContinue"

$script:Version = "6.0.0"
$script:StartedAt = Get-Date
$script:Deadline = $script:StartedAt.AddMinutes([Math]::Max(1, $MaxMinutes))
$script:RunId = [Guid]::NewGuid().ToString("N")
$script:TempRoot = Join-Path $env:TEMP ("YRYS_CHECKER_" + $script:RunId)
$script:CacheFile = Join-Path $script:TempRoot "runtime.cache"
$script:Findings = New-Object System.Collections.ArrayList
$script:Candidates = @{}
$script:SeenFinding = @{}
$script:Stats = [pscustomobject]@{
    Processes = 0
    Modules = 0
    FilesSeen = 0
    Candidates = 0
    FilesAnalyzed = 0
    JarScanned = 0
    PeScanned = 0
    Errors = 0
    TimedOut = $false
}

New-Item -ItemType Directory -Path $script:TempRoot -Force | Out-Null

function Start-TempCleanupWatcher {
    param([string]$Target, [int]$ParentPid)
    try {
        $cleanup = Join-Path $Target "cleanup.ps1"
        $lines = @()
        $lines += "param([int]`$ParentPid,[string]`$Target)"
        $lines += "`$ErrorActionPreference = 'SilentlyContinue'"
        $lines += "while (`$true) {"
        $lines += "    `$p = Get-Process -Id `$ParentPid -ErrorAction SilentlyContinue"
        $lines += "    if (-not `$p) { break }"
        $lines += "    Start-Sleep -Seconds 2"
        $lines += "}"
        $lines += "Start-Sleep -Seconds 1"
        $lines += "Remove-Item -LiteralPath `$Target -Recurse -Force -ErrorAction SilentlyContinue"
        Set-Content -Path $cleanup -Value $lines -Encoding UTF8
        $args = "-NoProfile -ExecutionPolicy Bypass -File `"$cleanup`" -ParentPid $ParentPid -Target `"$Target`""
        Start-Process -FilePath "powershell.exe" -ArgumentList $args -WindowStyle Hidden | Out-Null
    } catch {}
}

function Remove-TempNow {
    try {
        Remove-Item -LiteralPath $script:TempRoot -Recurse -Force -ErrorAction SilentlyContinue
    } catch {}
}

Start-TempCleanupWatcher -Target $script:TempRoot -ParentPid $PID
Register-EngineEvent PowerShell.Exiting -Action {
    try {
        Remove-Item -LiteralPath $event.MessageData -Recurse -Force -ErrorAction SilentlyContinue
    } catch {}
} -MessageData $script:TempRoot | Out-Null

function Test-TimeLeft {
    if ((Get-Date) -gt $script:Deadline) {
        $script:Stats.TimedOut = $true
        return $false
    }
    return $true
}

function Write-Centered {
    param([string]$Text, [ConsoleColor]$Color = "White")
    try {
        $w = [Console]::WindowWidth
        if ($w -lt 20) { $w = 100 }
        $pad = [Math]::Max(0, [int](($w - $Text.Length) / 2))
        Write-Host ((" " * $pad) + $Text) -ForegroundColor $Color
    } catch {
        Write-Host $Text -ForegroundColor $Color
    }
}

function Show-Banner {
    Clear-Host
    try { [Console]::Title = "YRYS CHECKER v$script:Version - local risk scanner" } catch {}
    $banner = @(
"YYYY   YYYY RRRRRR   YYYY   YYYY  SSSSS        CCCCC  HH   HH EEEEEEE  CCCCC  KK  KK EEEEEEE RRRRRR ",
" YYYY YYYY  RR   RR   YYYY YYYY  SS   SS      CC    C HH   HH EE      CC    C KK KK  EE      RR   RR",
"   YYYYY    RRRRRR      YYYYY     SSSSS       CC      HHHHHHH EEEEE   CC      KKK    EEEEE   RRRRRR ",
"    YYY     RR  RR       YYY         SS       CC    C HH   HH EE      CC    C KK KK  EE      RR  RR ",
"    YYY     RR   RR      YYY     SSSSS         CCCCC  HH   HH EEEEEEE  CCCCC  KK  KK EEEEEEE RR   RR"
    )
    Write-Host ""
    foreach ($l in $banner) { Write-Centered $l Red }
    Write-Centered ("v" + $script:Version + " | STRICT LOCAL SCAN | NO PERMANENT REPORTS") DarkRed
    Write-Host ""
}

function Write-Step {
    param([string]$Text)
    Write-Host ("  > " + $Text) -ForegroundColor Cyan
}

function Write-Soft {
    param([string]$Text)
    Write-Host ("    " + $Text) -ForegroundColor DarkGray
}

function Write-Status {
    param([string]$Label, [string]$Value, [ConsoleColor]$Color = "White")
    Write-Host ("  {0,-18} " -f $Label) -NoNewline -ForegroundColor DarkGray
    Write-Host $Value -ForegroundColor $Color
}

function Normalize-Token {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return "" }
    return ($Text.Trim().ToLowerInvariant() -replace '[^a-z0-9_\-\. ]','')
}

function Split-UserCheats {
    param([string[]]$InputItems)
    $out = New-Object System.Collections.ArrayList
    foreach ($item in @($InputItems)) {
        if ([string]::IsNullOrWhiteSpace($item)) { continue }
        foreach ($x in ($item -split '[,;|]+')) {
            $n = Normalize-Token $x
            if ($n.Length -ge 2) { [void]$out.Add($n) }
        }
    }
    return @($out | Select-Object -Unique)
}

function Read-CheatInput {
    param([string[]]$Current)
    $given = Split-UserCheats $Current
    if ($given.Count -gt 0 -or $NoPrompt) { return $given }

    Write-Host "Enter possible cheat names separated by comma. Press Enter to use built-in database only." -ForegroundColor Yellow
    Write-Host "Example: vape, raven, rise, drip, entropy, autoclicker" -ForegroundColor DarkGray
    $line = Read-Host "Possible cheats"
    return (Split-UserCheats @($line))
}

$script:UserCheats = Read-CheatInput -Current $Cheat

$script:BuiltInCheats = @(
    "vape","vape v4","raven","raven b","raven b+","rise","rise client","liquidbounce","wurst","aristois",
    "sigma","sigma5","zeroday","breez","breeze","ares","impact","inertia","phobos","rusherhack","future",
    "astolfo","novoline","moon","tenacity","zeroday","bleachhack","meteor","kami","salhack","kami blue",
    "coffee","drip","drip lite","entropy","whiteout","ape","ape v4","dream","dope","koid","skilled",
    "tap","echo","slapp","karma","prestige","slinky","exire","karma.rip","autoclicker","auto clicker",
    "ghost client","ghostclient","external client","injector","minecraft cheat","reach display"
)

$script:StrongTerms = @(
    "killaura","kill aura","aimassist","aim assist","triggerbot","trigger bot","autoclicker","auto clicker",
    "reach","velocity","scaffold","xray","x-ray","esp","tracers","nofall","no fall","flyhack","speedhack",
    "timerhack","bhop","blink","cheststealer","invcleaner","clickgui","click gui","modulemanager",
    "combatmodule","renderhack","packetfly","crasher","dupe","javaagent","mixintransformer"
)

$script:WeakTerms = @(
    "fly","speed","timer","blink","velocity","module","client","hack","cheat","inject","injection",
    "loader","bypass","mapper","clicker","aim","assist","legit","silent","arraylist"
)

$script:LegitVendors = @(
    "microsoft","microsoft corporation","oracle","oracle america","eclipse adoptium","adoptium","mojang",
    "nvidia","intel","amd","advanced micro devices","google","valve","discord","spotify","badlion",
    "lunar client","feather","labymod","curseforge","overwolf","modrinth","prismlauncher","multimc"
)

$script:LegitFileHints = @(
    "\windows\system32\","\windows\syswow64\","\windows\servicing\","\windows\winsxs\",
    "\program files\java\","\program files\eclipse adoptium\","\program files\microsoft\",
    "\program files (x86)\microsoft\","\lunar client\","\badlion client\","\curseforge\",
    "\prismlauncher\","\multimc\","\modrinth\"
)

$allKeywords = @()
$allKeywords += $script:BuiltInCheats
$allKeywords += $script:StrongTerms
$allKeywords += $script:UserCheats
$allKeywords = @($allKeywords | Where-Object { $_ -and $_.Trim().Length -ge 2 } | Select-Object -Unique)

function New-WordRegex {
    param([string[]]$Words)
    $escaped = New-Object System.Collections.ArrayList
    foreach ($w in @($Words)) {
        $n = Normalize-Token $w
        if ($n.Length -lt 2) { continue }
        [void]$escaped.Add([Regex]::Escape($n))
    }
    if ($escaped.Count -eq 0) {
        return New-Object Regex "a^", ([System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    }
    $pat = ($escaped | Sort-Object Length -Descending) -join "|"
    return New-Object Regex $pat, ([System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
}

$script:KeywordRegex = New-WordRegex -Words $allKeywords
$script:StrongRegex = New-WordRegex -Words $script:StrongTerms
$script:WeakRegex = New-WordRegex -Words $script:WeakTerms
$script:UserRegex = New-WordRegex -Words $script:UserCheats

function Get-TextMatches {
    param(
        [string]$Text,
        [string[]]$Terms,
        [int]$Limit = 12
    )
    $res = New-Object System.Collections.ArrayList
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    $t = $Text.ToLowerInvariant()
    foreach ($term in @($Terms)) {
        if ([string]::IsNullOrWhiteSpace($term)) { continue }
        $n = Normalize-Token $term
        if ($n.Length -lt 2) { continue }
        if ($t.Contains($n)) {
            [void]$res.Add($n)
            if ($res.Count -ge $Limit) { break }
        }
    }
    return @($res | Select-Object -Unique)
}

function Test-LegitPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $p = $Path.ToLowerInvariant()
    foreach ($hint in $script:LegitFileHints) {
        if ($p.Contains($hint)) { return $true }
    }
    return $false
}

function Test-ExcludedDirectory {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $true }
    $p = $Path.ToLowerInvariant().TrimEnd('\')
    $bad = @(
        "\windows\winsxs",
        "\windows\servicing",
        "\windows\softwaredistribution",
        "\windows\installer",
        "\windows\assembly",
        "\windows\system32\driverstore",
        "\system volume information",
        "\$recycle.bin",
        "\recovery",
        "\program files\windowsapps",
        "\programdata\microsoft\windows defender",
        "\programdata\microsoft\windows\wer"
    )
    foreach ($b in $bad) {
        if ($p.Contains($b)) { return $true }
    }
    return $false
}

function Add-Candidate {
    param(
        [string]$Path,
        [string]$Source,
        [int]$Boost = 0
    )
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    try {
        $full = [System.IO.Path]::GetFullPath($Path)
    } catch {
        $full = $Path
    }
    $key = $full.ToLowerInvariant()
    if (-not $script:Candidates.ContainsKey($key)) {
        $script:Candidates[$key] = [ordered]@{
            Path = $full
            Sources = New-Object System.Collections.ArrayList
            Boost = 0
        }
    }
    if ($Source) {
        if (-not ($script:Candidates[$key].Sources -contains $Source)) {
            [void]$script:Candidates[$key].Sources.Add($Source)
        }
    }
    $script:Candidates[$key].Boost += $Boost
}

function Add-Finding {
    param(
        [string]$Kind,
        [string]$Target,
        [int]$Score,
        [string[]]$Evidence,
        [string]$Source = ""
    )
    if ([string]::IsNullOrWhiteSpace($Target)) { return }
    $e = @($Evidence | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
    if ($Score -lt 45) { return }

    $sev = "WATCH"
    if ($Score -ge 90) { $sev = "CRITICAL" }
    elseif ($Score -ge 75) { $sev = "HIGH" }
    elseif ($Score -ge 60) { $sev = "MEDIUM" }

    $hashKey = ($Kind + "|" + $Target + "|" + ($e -join ";")).ToLowerInvariant()
    if ($script:SeenFinding.ContainsKey($hashKey)) { return }
    $script:SeenFinding[$hashKey] = $true

    $obj = [pscustomobject]@{
        Severity = $sev
        Score = [Math]::Min(99, [Math]::Max(0, $Score))
        Kind = $Kind
        Target = $Target
        Evidence = ($e -join " | ")
        Source = $Source
    }
    [void]$script:Findings.Add($obj)
}

function Get-AuthenticodeInfo {
    param([string]$Path)
    $info = [ordered]@{
        Status = "Unknown"
        Signer = ""
        Trusted = $false
    }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction SilentlyContinue
        if ($sig) {
            $info.Status = [string]$sig.Status
            if ($sig.SignerCertificate) {
                $info.Signer = [string]$sig.SignerCertificate.Subject
                $s = $info.Signer.ToLowerInvariant()
                foreach ($v in $script:LegitVendors) {
                    if ($s.Contains($v)) { $info.Trusted = $true; break }
                }
            }
        }
    } catch {}
    return $info
}

function Read-FileTextSample {
    param([string]$Path, [int]$MaxMB)
    try {
        $fi = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($fi.Length -le 0) { return "" }
        $limit = [Math]::Min([int64]($MaxMB * 1MB), [int64]$fi.Length)
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $buf = New-Object byte[] $limit
            $read = $fs.Read($buf, 0, $buf.Length)
            if ($read -le 0) { return "" }
            $ascii = [System.Text.Encoding]::ASCII.GetString($buf, 0, $read)
            return $ascii
        } finally {
            $fs.Close()
        }
    } catch {
        $script:Stats.Errors++
        return ""
    }
}

function Scan-JarLight {
    param([string]$Path)
    $result = [ordered]@{
        Strong = @()
        Weak = @()
        Entries = 0
        Error = $false
    }
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        $zip = [System.IO.Compression.ZipFile]::OpenRead($Path)
        try {
            $maxEntries = 520
            foreach ($entry in $zip.Entries) {
                if (-not (Test-TimeLeft)) { break }
                $result.Entries++
                if ($result.Entries -gt $maxEntries) { break }
                if ($entry.Length -gt ([int64]$MaxStringScanMB * 1MB)) { continue }
                $name = $entry.FullName.ToLowerInvariant()

                $nameStrong = Get-TextMatches -Text $name -Terms $script:StrongTerms -Limit 8
                $nameWeak = Get-TextMatches -Text $name -Terms $script:WeakTerms -Limit 8
                if ($nameStrong.Count -gt 0) { $result.Strong += $nameStrong }
                if ($nameWeak.Count -gt 0) { $result.Weak += $nameWeak }

                if ($entry.Length -le 0) { continue }
                if ($entry.Length -gt 1048576) { continue }
                if ($name -notmatch '\.(class|json|txt|cfg|properties|mf|yml|yaml|xml)$' -and -not $name.Contains("meta-inf")) { continue }

                try {
                    $stream = $entry.Open()
                    try {
                        $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::ASCII, $true, 8192)
                        $content = $reader.ReadToEnd()
                        $reader.Close()
                    } finally {
                        $stream.Close()
                    }
                    $strong = Get-TextMatches -Text $content -Terms $script:StrongTerms -Limit 20
                    $weak = Get-TextMatches -Text $content -Terms $script:WeakTerms -Limit 20
                    if ($strong.Count -gt 0) { $result.Strong += $strong }
                    if ($weak.Count -gt 0) { $result.Weak += $weak }
                } catch {}
            }
        } finally {
            $zip.Dispose()
        }
    } catch {
        $result.Error = $true
        $script:Stats.Errors++
    }
    $result.Strong = @($result.Strong | Select-Object -Unique)
    $result.Weak = @($result.Weak | Select-Object -Unique)
    return $result
}

function Invoke-YrysAiRisk {
    param(
        [string]$Path,
        [string]$Kind,
        [string[]]$Sources,
        [int]$Boost = 0
    )

    $evidence = New-Object System.Collections.ArrayList
    $score = 0
    $lower = $Path.ToLowerInvariant()
    $fileName = ""
    try { $fileName = [System.IO.Path]::GetFileName($Path).ToLowerInvariant() } catch {}

    if ($Boost -gt 0) {
        $score += $Boost
        [void]$evidence.Add("context boost +" + $Boost)
    }

    if ($Sources -contains "running-process") {
        $score += 25
        [void]$evidence.Add("currently running")
    }
    if ($Sources -contains "java-commandline") {
        $score += 25
        [void]$evidence.Add("linked from Java/Minecraft command line")
    }
    if ($Sources -contains "loaded-module") {
        $score += 18
        [void]$evidence.Add("loaded module in process")
    }
    if ($Sources -contains "startup") {
        $score += 20
        [void]$evidence.Add("startup persistence")
    }
    if ($Sources -contains "scheduled-task") {
        $score += 20
        [void]$evidence.Add("scheduled task persistence")
    }

    $userMatches = Get-TextMatches -Text $lower -Terms $script:UserCheats -Limit 10
    if ($userMatches.Count -gt 0) {
        $score += 55
        [void]$evidence.Add("matches user cheat input: " + ($userMatches -join ","))
    }

    $builtMatches = Get-TextMatches -Text $lower -Terms $script:BuiltInCheats -Limit 10
    if ($builtMatches.Count -gt 0) {
        $score += 45
        [void]$evidence.Add("known cheat name in path/name: " + ($builtMatches -join ","))
    }

    $strongName = Get-TextMatches -Text $fileName -Terms $script:StrongTerms -Limit 10
    if ($strongName.Count -gt 0) {
        $score += 25
        [void]$evidence.Add("strong cheat words in file name: " + ($strongName -join ","))
    }

    if ($lower.Contains("\.minecraft\") -or $lower.Contains("\minecraft\") -or $lower.Contains("\tlauncher\") -or $lower.Contains("\lunarclient\")) {
        $score += 8
        [void]$evidence.Add("minecraft-related path")
    }

    $ext = ""
    try { $ext = [System.IO.Path]::GetExtension($Path).ToLowerInvariant() } catch {}

    if ($ext -eq ".jar") {
        $script:Stats.JarScanned++
        $jar = Scan-JarLight -Path $Path
        if ($jar.Strong.Count -ge 5) {
            $score += 55
            [void]$evidence.Add("many strong JAR cheat strings: " + (($jar.Strong | Select-Object -First 10) -join ","))
        } elseif ($jar.Strong.Count -ge 2) {
            $score += 35
            [void]$evidence.Add("strong JAR cheat strings: " + (($jar.Strong | Select-Object -First 8) -join ","))
        } elseif ($jar.Strong.Count -eq 1) {
            $score += 18
            [void]$evidence.Add("one strong JAR string: " + ($jar.Strong[0]))
        }

        if ($jar.Weak.Count -ge 6) {
            $score += 15
            [void]$evidence.Add("weak JAR indicators: " + (($jar.Weak | Select-Object -First 8) -join ","))
        }

        if ($jar.Error) {
            [void]$evidence.Add("JAR could not be parsed")
        }
    } elseif ($ext -eq ".exe" -or $ext -eq ".dll") {
        $script:Stats.PeScanned++
        $sig = Get-AuthenticodeInfo -Path $Path
        if ($sig.Trusted -and (Test-LegitPath -Path $Path) -and $score -lt 80) {
            $score -= 30
            [void]$evidence.Add("trusted vendor signature: " + $sig.Signer)
        } elseif ($sig.Status -ne "Valid") {
            if ($score -ge 30) {
                $score += 15
                [void]$evidence.Add("not valid signed: " + $sig.Status)
            } else {
                [void]$evidence.Add("signature: " + $sig.Status)
            }
        } else {
            [void]$evidence.Add("signature valid but not whitelisted")
        }

        if ($score -ge 30 -or $Sources -contains "running-process" -or $Sources -contains "loaded-module") {
            $sample = Read-FileTextSample -Path $Path -MaxMB $MaxStringScanMB
            $strong = Get-TextMatches -Text $sample -Terms $script:StrongTerms -Limit 15
            $built = Get-TextMatches -Text $sample -Terms $script:BuiltInCheats -Limit 12
            $user = Get-TextMatches -Text $sample -Terms $script:UserCheats -Limit 12

            if ($user.Count -gt 0) {
                $score += 35
                [void]$evidence.Add("user cheat strings inside binary: " + ($user -join ","))
            }
            if ($built.Count -gt 0) {
                $score += 28
                [void]$evidence.Add("known cheat strings inside binary: " + (($built | Select-Object -First 8) -join ","))
            }
            if ($strong.Count -ge 3) {
                $score += 25
                [void]$evidence.Add("strong cheat strings inside binary: " + (($strong | Select-Object -First 8) -join ","))
            } elseif ($strong.Count -gt 0) {
                $score += 12
                [void]$evidence.Add("some strong binary strings: " + (($strong | Select-Object -First 5) -join ","))
            }
        }
    }

    if ($lower.Contains("\temp\") -or $lower.Contains("\appdata\local\temp\") -or $lower.Contains("\downloads\")) {
        if ($score -ge 35) {
            $score += 8
            [void]$evidence.Add("risky user/temp/download path")
        }
    }

    if ((Test-LegitPath -Path $Path) -and $score -lt 75) {
        $score -= 20
        [void]$evidence.Add("legit path damping")
    }

    if ($score -lt 0) { $score = 0 }
    return [pscustomobject]@{
        Score = [int][Math]::Min(99, $score)
        Evidence = @($evidence | Select-Object -Unique)
    }
}

function Scan-Processes {
    Write-Step "Scanning running processes and command lines..."
    $procs = @()
    try {
        $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
    } catch {
        $procs = @()
        $script:Stats.Errors++
    }

    foreach ($p in @($procs)) {
        if (-not (Test-TimeLeft)) { break }
        $script:Stats.Processes++
        $text = (($p.Name + " " + $p.ExecutablePath + " " + $p.CommandLine) -as [string])
        if ([string]::IsNullOrWhiteSpace($text)) { continue }

        $matched = $script:KeywordRegex.IsMatch($text)
        $javaLike = ($p.Name -match 'java|javaw|minecraft|launcher') -or ($text -match 'minecraft|\.jar|forge|fabric|quilt|optifine|lunar|badlion|tlauncher')

        if ($matched) {
            $target = $p.ExecutablePath
            if ([string]::IsNullOrWhiteSpace($target)) { $target = $p.Name }
            Add-Candidate -Path $target -Source "running-process" -Boost 20
            $risk = Invoke-YrysAiRisk -Path $target -Kind "PROCESS" -Sources @("running-process") -Boost 20
            Add-Finding -Kind "PROCESS" -Target ($p.Name + " PID=" + $p.ProcessId + " PATH=" + $target) -Score $risk.Score -Evidence $risk.Evidence -Source "process"
        }

        if ($javaLike) {
            $jarMatches = [regex]::Matches($text, '([A-Za-z]:\\[^" ]+?\.jar|(?:"[^"]+?\.jar")|[^"\s]+?\.jar)')
            foreach ($m in $jarMatches) {
                $jp = $m.Value.Trim('"')
                if (Test-Path -LiteralPath $jp) {
                    Add-Candidate -Path $jp -Source "java-commandline" -Boost 25
                }
            }

            $agentMatches = [regex]::Matches($text, '-javaagent:([^" ]+\.jar)|-agentpath:([^" ]+)|-agentlib:([^" ]+)')
            foreach ($m in $agentMatches) {
                $agent = ($m.Value -replace '^-javaagent:','' -replace '^-agentpath:','' -replace '^-agentlib:','').Trim('"')
                if ($agent) {
                    Add-Finding -Kind "JAVA_AGENT" -Target ("PID=" + $p.ProcessId + " " + $agent) -Score 85 -Evidence @("Java agent used by Minecraft/Java process", "agents are common for injection or instrumentation") -Source "java-commandline"
                    if (Test-Path -LiteralPath $agent) { Add-Candidate -Path $agent -Source "java-commandline" -Boost 40 }
                }
            }
        }
    }
}

function Scan-LoadedModules {
    Write-Step "Checking loaded DLL modules in Java/Minecraft processes..."
    $gps = @()
    try { $gps = Get-Process -ErrorAction SilentlyContinue } catch { $gps = @() }

    foreach ($p in @($gps)) {
        if (-not (Test-TimeLeft)) { break }
        $name = $p.ProcessName.ToLowerInvariant()
        if ($name -notmatch 'java|javaw|minecraft|launcher|badlion|lunar|tlauncher') { continue }
        $mods = @()
        try { $mods = $p.Modules } catch { continue }
        foreach ($m in @($mods)) {
            if (-not (Test-TimeLeft)) { break }
            $script:Stats.Modules++
            $mp = $m.FileName
            if ([string]::IsNullOrWhiteSpace($mp)) { continue }
            $text = ($m.ModuleName + " " + $mp)
            if ($script:KeywordRegex.IsMatch($text) -or ($mp.ToLowerInvariant().Contains("\temp\"))) {
                Add-Candidate -Path $mp -Source "loaded-module" -Boost 20
            }
        }
    }
}

function Get-StartupLocations {
    $items = New-Object System.Collections.ArrayList
    $startupDirs = @(
        [Environment]::GetFolderPath("Startup"),
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
    )
    foreach ($d in $startupDirs) {
        if (Test-Path -LiteralPath $d) {
            try {
                Get-ChildItem -LiteralPath $d -File -ErrorAction SilentlyContinue | ForEach-Object {
                    [void]$items.Add($_.FullName)
                }
            } catch {}
        }
    }

    $regPaths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    )
    foreach ($rp in $regPaths) {
        try {
            $props = Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue
            if ($props) {
                foreach ($pr in $props.PSObject.Properties) {
                    if ($pr.Name -match '^PS') { continue }
                    $val = [string]$pr.Value
                    if ([string]::IsNullOrWhiteSpace($val)) { continue }
                    [void]$items.Add($val)
                }
            }
        } catch {}
    }
    return @($items)
}

function Extract-PathsFromText {
    param([string]$Text)
    $out = New-Object System.Collections.ArrayList
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    $matches = [regex]::Matches($Text, '([A-Za-z]:\\[^"<>|]+?\.(exe|dll|jar))')
    foreach ($m in $matches) {
        $p = $m.Value.Trim('"')
        [void]$out.Add($p)
    }
    return @($out | Select-Object -Unique)
}

function Scan-Persistence {
    Write-Step "Scanning startup and scheduled tasks..."
    foreach ($it in Get-StartupLocations) {
        if (-not (Test-TimeLeft)) { break }
        $text = [string]$it
        if ($script:KeywordRegex.IsMatch($text)) {
            Add-Finding -Kind "STARTUP" -Target $text -Score 80 -Evidence @("startup entry matches cheat keyword") -Source "startup"
        }
        foreach ($p in Extract-PathsFromText $text) {
            if (Test-Path -LiteralPath $p) {
                Add-Candidate -Path $p -Source "startup" -Boost 20
            }
        }
    }

    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
        foreach ($t in @($tasks)) {
            if (-not (Test-TimeLeft)) { break }
            $txt = (($t.TaskName + " " + $t.TaskPath + " " + (($t.Actions | Out-String))) -as [string])
            if ($script:KeywordRegex.IsMatch($txt)) {
                Add-Finding -Kind "SCHEDULED_TASK" -Target ($t.TaskPath + $t.TaskName) -Score 78 -Evidence @("scheduled task matches cheat keyword") -Source "scheduled-task"
                foreach ($p in Extract-PathsFromText $txt) {
                    if (Test-Path -LiteralPath $p) { Add-Candidate -Path $p -Source "scheduled-task" -Boost 20 }
                }
            }
        }
    } catch {}
}

function Get-SmartRoots {
    $roots = New-Object System.Collections.ArrayList

    if ($Fast) {
        $base = @(
            $env:USERPROFILE,
            $env:APPDATA,
            $env:LOCALAPPDATA,
            $env:TEMP,
            "$env:APPDATA\.minecraft",
            "$env:APPDATA\.tlauncher",
            "$env:APPDATA\.lunarclient",
            "$env:APPDATA\.feather",
            "$env:ProgramData"
        )
        foreach ($b in $base) {
            if ($b -and (Test-Path -LiteralPath $b)) { [void]$roots.Add((Resolve-Path -LiteralPath $b).Path) }
        }
    } else {
        try {
            [System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq "Fixed" -and $_.IsReady } | ForEach-Object {
                [void]$roots.Add($_.RootDirectory.FullName)
            }
        } catch {
            if ($env:SystemDrive) { [void]$roots.Add(($env:SystemDrive + "\")) }
        }
    }

    return @($roots | Select-Object -Unique)
}

function Test-InterestingPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $p = $Path.ToLowerInvariant()
    if ($script:KeywordRegex.IsMatch($p)) { return $true }
    if ($p.Contains("\.minecraft\") -or $p.Contains("\minecraft\") -or $p.Contains("\tlauncher\") -or $p.Contains("\lunarclient\") -or $p.Contains("\feather\")) { return $true }
    if ($p.Contains("\mods\") -or $p.Contains("\versions\") -or $p.Contains("\libraries\")) { return $true }
    if ($p.Contains("\downloads\") -or $p.Contains("\desktop\") -or $p.Contains("\appdata\") -or $p.Contains("\temp\")) {
        return $true
    }
    return $false
}

function Scan-FileSystemCandidates {
    Write-Step "Indexing EXE / DLL / JAR candidates across system..."
    $roots = Get-SmartRoots
    if ($Fast) {
        Write-Soft "Mode: FAST smart locations."
    } else {
        Write-Soft "Mode: SMART-FULL fixed drives with system-noise pruning."
    }

    $allowed = @{
        ".exe" = $true
        ".dll" = $true
        ".jar" = $true
    }

    $stack = New-Object System.Collections.Stack
    foreach ($r in $roots) { if ($r) { $stack.Push($r) } }

    while ($stack.Count -gt 0) {
        if (-not (Test-TimeLeft)) { break }
        $dir = [string]$stack.Pop()
        if (Test-ExcludedDirectory -Path $dir) { continue }

        $files = $null
        try {
            $files = [System.IO.Directory]::EnumerateFiles($dir)
        } catch {
            continue
        }

        foreach ($f in $files) {
            if (-not (Test-TimeLeft)) { break }
            $script:Stats.FilesSeen++
            $ext = ""
            try { $ext = [System.IO.Path]::GetExtension($f).ToLowerInvariant() } catch { continue }
            if (-not $allowed.ContainsKey($ext)) { continue }

            $candidate = $false
            $boost = 0
            $src = "filesystem"

            if ($script:KeywordRegex.IsMatch($f)) {
                $candidate = $true
                $boost += 30
            }

            if ($ext -eq ".jar" -and (Test-InterestingPath -Path $f)) {
                $candidate = $true
                $boost += 8
            }

            if ($Deep -and (Test-InterestingPath -Path $f)) {
                $candidate = $true
                $boost += 5
            }

            if ($candidate) {
                try {
                    $fi = Get-Item -LiteralPath $f -ErrorAction SilentlyContinue
                    if ($fi -and $fi.Length -gt ([int64]$MaxFileSizeMB * 1MB)) {
                        if (-not $script:KeywordRegex.IsMatch($f)) { continue }
                    }
                } catch {}
                Add-Candidate -Path $f -Source $src -Boost $boost
            }
        }

        $dirs = $null
        try {
            $dirs = [System.IO.Directory]::EnumerateDirectories($dir)
        } catch {
            $dirs = $null
        }
        foreach ($sd in @($dirs)) {
            if (-not (Test-TimeLeft)) { break }
            if (Test-ExcludedDirectory -Path $sd) { continue }
            $stack.Push($sd)
        }

        if (($script:Stats.FilesSeen % 15000) -eq 0 -and $script:Stats.FilesSeen -gt 0) {
            Write-Host ("    indexed files: {0} | candidates: {1}" -f $script:Stats.FilesSeen, $script:Candidates.Count) -ForegroundColor DarkGray
        }
    }
}

function Scan-PrefetchLight {
    Write-Step "Checking Prefetch hints..."
    $pf = Join-Path $env:SystemRoot "Prefetch"
    if (-not (Test-Path -LiteralPath $pf)) { return }
    try {
        Get-ChildItem -LiteralPath $pf -Filter "*.pf" -ErrorAction SilentlyContinue | ForEach-Object {
            if (-not (Test-TimeLeft)) { return }
            $n = $_.Name.ToLowerInvariant()
            if ($script:KeywordRegex.IsMatch($n)) {
                Add-Finding -Kind "PREFETCH" -Target $_.FullName -Score 65 -Evidence @("Windows Prefetch name matches cheat keyword", "program likely executed before") -Source "prefetch"
            }
        }
    } catch {}
}

function Analyze-Candidates {
    Write-Step "Running local AI risk engine on candidates..."
    $script:Stats.Candidates = $script:Candidates.Count
    $i = 0
    foreach ($kv in $script:Candidates.GetEnumerator()) {
        if (-not (Test-TimeLeft)) { break }
        $i++
        $data = $kv.Value
        $path = [string]$data.Path
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $script:Stats.FilesAnalyzed++

        $sources = @($data.Sources)
        $risk = Invoke-YrysAiRisk -Path $path -Kind "FILE" -Sources $sources -Boost ([int]$data.Boost)
        Add-Finding -Kind "FILE" -Target $path -Score $risk.Score -Evidence $risk.Evidence -Source (($sources | Select-Object -Unique) -join ",")

        if (($i % 150) -eq 0) {
            Write-Host ("    analyzed candidates: {0}/{1}" -f $i, $script:Candidates.Count) -ForegroundColor DarkGray
        }
    }
}

function Scan-NetworkLight {
    Write-Step "Checking active TCP connections for cheat domains/IP hints..."
    $known = @(
        "vape.gg","riseclient.com","intent.store","entropy.club","whiteout.lol","drip.gg","slinky.gg",
        "dreamclient.xyz","ravenclient.com","liquidbounce.net"
    )
    $ips = New-Object System.Collections.ArrayList
    foreach ($d in $known) {
        try {
            [System.Net.Dns]::GetHostAddresses($d) | ForEach-Object {
                [void]$ips.Add($_.IPAddressToString)
            }
        } catch {}
    }
    $ips = @($ips | Select-Object -Unique)
    if ($ips.Count -eq 0) { return }

    try {
        $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        foreach ($c in @($conns)) {
            if (-not (Test-TimeLeft)) { break }
            if ($ips -contains $c.RemoteAddress) {
                Add-Finding -Kind "NETWORK" -Target ($c.RemoteAddress + ":" + $c.RemotePort + " PID=" + $c.OwningProcess) -Score 82 -Evidence @("active connection to known cheat-related host IP") -Source "network"
            }
        }
    } catch {}
}

function Show-Summary {
    $items = @($script:Findings | Sort-Object -Property @{Expression="Score";Descending=$true}, Severity)
    $critical = @($items | Where-Object { $_.Severity -eq "CRITICAL" }).Count
    $high = @($items | Where-Object { $_.Severity -eq "HIGH" }).Count
    $medium = @($items | Where-Object { $_.Severity -eq "MEDIUM" }).Count
    $watch = @($items | Where-Object { $_.Severity -eq "WATCH" }).Count

    Write-Host ""
    Write-Host "=============================================================================="
    Write-Centered "YRYS CHECKER RESULT" Red
    Write-Host "=============================================================================="
    Write-Status "Processes" ([string]$script:Stats.Processes) Cyan
    Write-Status "Files indexed" ([string]$script:Stats.FilesSeen) Cyan
    Write-Status "Candidates" ([string]$script:Stats.Candidates) Cyan
    Write-Status "Analyzed" ([string]$script:Stats.FilesAnalyzed) Cyan
    Write-Status "JAR scanned" ([string]$script:Stats.JarScanned) Cyan
    Write-Status "EXE/DLL scanned" ([string]$script:Stats.PeScanned) Cyan
    Write-Status "Temp cleanup" "enabled; no permanent report" Green

    if ($script:Stats.TimedOut) {
        Write-Status "Time limit" "reached; use -MaxMinutes 20 for deeper scan" Yellow
    }

    Write-Host ""
    Write-Status "CRITICAL" ([string]$critical) Red
    Write-Status "HIGH" ([string]$high) Red
    Write-Status "MEDIUM" ([string]$medium) Yellow
    Write-Status "WATCH" ([string]$watch) DarkYellow
    Write-Host ""

    if ($items.Count -eq 0) {
        Write-Host "  CLEAN: no strong cheat-linked artifacts found by local risk engine." -ForegroundColor Green
        Write-Host "  Tip: run as Administrator and add -Deep for stronger module/JAR inspection." -ForegroundColor DarkGray
        return
    }

    $max = [Math]::Min($Top, $items.Count)
    Write-Host ("  Top {0} risk findings:" -f $max) -ForegroundColor White
    Write-Host ""

    $idx = 0
    foreach ($it in ($items | Select-Object -First $max)) {
        $idx++
        $color = "DarkYellow"
        if ($it.Severity -eq "CRITICAL") { $color = "Red" }
        elseif ($it.Severity -eq "HIGH") { $color = "Red" }
        elseif ($it.Severity -eq "MEDIUM") { $color = "Yellow" }

        Write-Host ("[{0}] {1} | SCORE {2} | {3}" -f $idx, $it.Severity, $it.Score, $it.Kind) -ForegroundColor $color
        Write-Host ("    " + $it.Target) -ForegroundColor White
        Write-Host ("    evidence: " + $it.Evidence) -ForegroundColor DarkGray
        if ($it.Source) { Write-Host ("    source: " + $it.Source) -ForegroundColor DarkGray }
        Write-Host ""
    }

    if ($items.Count -gt $max) {
        Write-Host ("  Hidden lower findings: {0}. Increase -Top to show more." -f ($items.Count - $max)) -ForegroundColor DarkGray
    }

    if ($critical -gt 0 -or $high -gt 0) {
        Write-Host "  VERDICT: CHEAT-LIKELY artifacts found. Review CRITICAL/HIGH paths above." -ForegroundColor Red
    } elseif ($medium -gt 0) {
        Write-Host "  VERDICT: SUSPICIOUS. Needs manual review; not enough for a final ban alone." -ForegroundColor Yellow
    } else {
        Write-Host "  VERDICT: WATCH ONLY. Weak indicators, likely not enough alone." -ForegroundColor DarkYellow
    }
}

function Main {
    Show-Banner
    if ($script:UserCheats.Count -gt 0) {
        Write-Status "User targets" ($script:UserCheats -join ", ") Yellow
    } else {
        Write-Status "User targets" "none; built-in DB only" DarkGray
    }
    Write-Status "Scan mode" ($(if ($Fast) { "FAST" } else { "SMART-FULL" }) + $(if ($Deep) { " + DEEP" } else { "" })) Cyan
    Write-Status "Time limit" ($MaxMinutes.ToString() + " min") Cyan
    Write-Status "Reports" "disabled; temp data auto-deletes" Green
    Write-Host ""

    Scan-Processes
    Scan-LoadedModules
    Scan-Persistence
    Scan-FileSystemCandidates
    Scan-PrefetchLight
    Scan-NetworkLight
    Analyze-Candidates
    Show-Summary
}

try {
    Main
} finally {
    Write-Host ""
    Write-Host "Press Enter to close and delete temporary files..." -ForegroundColor DarkGray
    try { [void][Console]::ReadLine() } catch {}
    Remove-TempNow
}
