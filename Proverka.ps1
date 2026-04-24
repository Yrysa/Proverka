#Requires -Version 5.1
<#
YRYS CHECKER Advanced - autonomous Minecraft / Java cheat checker.
PowerShell 5.1 safe build: ASCII-only source, no fragile HTML here-strings.
This script is detection/reporting only. It does not delete, kill, or modify user files.
#>

[CmdletBinding()]
param(
    [switch]$OnlyMinecraft,
    [switch]$Deep,
    [switch]$OpenReport,
    [switch]$NoHtml,
    [int]$MaxFileMB = 120,
    [int]$MaxEntryKB = 1024,
    [string]$ReportRoot = (Join-Path $env:TEMP 'YrysChecker'),
    [string]$DbPath = ''
)

$script:ScriptVersion = '5.1.2-fixed'
$script:RunId = Get-Date -Format 'yyyyMMdd_HHmmss'
$script:RunDir = Join-Path $ReportRoot ('Run_' + $script:RunId)
$script:TxtReport = Join-Path $script:RunDir 'YRYS_CHECKER_report.txt'
$script:HtmlReport = Join-Path $script:RunDir 'YRYS_CHECKER_report.html'
$script:JsonReport = Join-Path $script:RunDir 'YRYS_CHECKER_findings.json'
$script:Findings = New-Object System.Collections.ArrayList
$script:LogLines = New-Object System.Collections.ArrayList
$script:ScannedFiles = 0
$script:ScannedJars = 0
$script:ReadErrors = 0
$script:IsAdmin = $false

$script:CheatDB = [ordered]@{
    Hashes = @()
    ProcessNames = @(
        'vape','raven','rise','liquidbounce','wurst','aristois','sigma','zeroday','bleachhack',
        'ares','impact','inertia','phobos','rusherhack','astolfo','meteor','future','kami',
        'xray','autoclicker','clicker','ghostclient','drip','entropy','doomsday','whiteout',
        'ape','dream','slapp','breez','skilled','slinky','prestige','karma','moon','novoline'
    )
    WindowTitleKeywords = @(
        'vape v4','vape lite','raven b+','liquidbounce','wurst client','aristois client',
        'sigma client','rise client','meteor client','impact client','inertia client','phobos',
        'rusherhack','future client','bleachhack','breez','autoclicker','auto clicker','ghost client'
    )
    FileNameTokens = @(
        'vape','raven','rise','liquidbounce','wurst','aristois','sigma','zeroday','bleachhack',
        'meteor','impact','inertia','phobos','rusherhack','astolfo','future','kami','xray',
        'killaura','aimassist','reach','autoclicker','clicker','ghost','injector','loader','crack',
        'bypass','velocity','triggerbot','cheststealer','scaffold','client','cheat','hack'
    )
    SuspiciousStrings = @(
        'KillAura','killaura','AutoClicker','auto clicker','TriggerBot','triggerbot','AimAssist',
        'aimassist','Reach','Velocity','NoFall','Scaffold','ChestStealer','ESP','XRay','xray',
        'Blink','Bhop','Timer','Flight','FlyHack','Criticals','AntiBot','NoSlow','SpeedHack',
        'clickgui','ClickGUI','modmenu','hackclient','ghostclient','MixinTransformer','javaagent',
        'org.spongepowered.asm.mixin','net.weavemc.loader','lunar client agent','badlion bypass',
        'packet spoof','rotation spoof','silent aim','legit aura','reachdisplaymod spoof'
    )
    DllModules = @(
        'vape.dll','vapelite.dll','echo.dll','raven.dll','rise.dll','sigma.dll','injector.dll',
        'whiteout.dll','entropy.dll','drip.dll','doomsday.dll','ape.dll','breez.dll','slinky.dll'
    )
    CheatServers = @(
        'vape.gg','riseclient.com','intent.store','liquidbounce.net','meteorclient.com','wurstclient.net'
    )
}

function Initialize-Yrys {
    if (-not (Test-Path -LiteralPath $script:RunDir)) {
        New-Item -ItemType Directory -Path $script:RunDir -Force | Out-Null
    }
    $script:IsAdmin = Test-IsAdministrator
    Load-ExternalDatabase
}

function Test-IsAdministrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Load-ExternalDatabase {
    $candidate = $DbPath
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        $local = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'cheat_signatures.json'
        if (Test-Path -LiteralPath $local) { $candidate = $local }
    }
    if ([string]::IsNullOrWhiteSpace($candidate)) { return }
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { return }
    try {
        $db = Get-Content -LiteralPath $candidate -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        foreach ($key in @('Hashes','ProcessNames','WindowTitleKeywords','FileNameTokens','SuspiciousStrings','DllModules','CheatServers')) {
            if ($null -ne $db.$key) {
                $script:CheatDB[$key] = @($script:CheatDB[$key] + @($db.$key)) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique
            }
        }
        Write-Log 'OK' ('External DB loaded: ' + $candidate)
    } catch {
        Write-Log 'WARN' ('External DB load failed: ' + $_.Exception.Message)
    }
}

function Show-Banner {
    Clear-Host
    $lines = @(
        '',
        'YYYYY   RRRRR   Y   Y  SSSSS      CCCCC  H   H  EEEEE  CCCCC  K   K  EEEEE  RRRRR',
        '  Y     R   R    Y Y   S          C       H   H  E      C       K  K   E      R   R',
        '  Y     RRRRR     Y    SSSS       C       HHHHH  EEEE   C       KKK    EEEE   RRRRR',
        '  Y     R  R      Y       S       C       H   H  E      C       K  K   E      R  R',
        '  Y     R   R     Y   SSSSS        CCCCC  H   H  EEEEE  CCCCC  K   K  EEEEE  R   R',
        '',
        ('Advanced autonomous checker v' + $script:ScriptVersion),
        'Minecraft / Java / mods / processes / network / startup',
        'Detection only. No deleting. No killing. Full report is saved.',
        ''
    )
    foreach ($l in $lines) { Write-Host $l -ForegroundColor Red }
}

function Write-Log {
    param(
        [ValidateSet('INFO','OK','WARN','ERROR','DETECT')][string]$Level,
        [string]$Message
    )
    $time = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = '[' + $time + '] [' + $Level + '] ' + $Message
    [void]$script:LogLines.Add($line)
    try { Add-Content -LiteralPath $script:TxtReport -Value $line -Encoding UTF8 } catch { }
    switch ($Level) {
        'OK'     { Write-Host ('[+] ' + $Message) -ForegroundColor Green }
        'WARN'   { Write-Host ('[!] ' + $Message) -ForegroundColor Yellow }
        'ERROR'  { Write-Host ('[-] ' + $Message) -ForegroundColor Red }
        'DETECT' { Write-Host ('[!!!] ' + $Message) -ForegroundColor Red -BackgroundColor DarkGray }
        default  { Write-Host ('[*] ' + $Message) -ForegroundColor Cyan }
    }
}

function Add-Finding {
    param(
        [ValidateSet('Critical','High','Medium','Low','Info')][string]$Severity,
        [int]$Score,
        [string]$Category,
        [string]$Title,
        [string]$Path = '',
        [string]$Evidence = '',
        [string]$Recommendation = 'Review manually before taking action.'
    )
    $obj = [pscustomobject]@{
        Time = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Severity = $Severity
        Score = $Score
        Category = $Category
        Title = $Title
        Path = $Path
        Evidence = $Evidence
        Recommendation = $Recommendation
    }
    [void]$script:Findings.Add($obj)
    Write-Log 'DETECT' ($Severity + ' | ' + $Category + ' | ' + $Title + ' | ' + $Path + ' | ' + $Evidence)
}

function Get-LowerList {
    param([object[]]$InputList)
    return @($InputList | ForEach-Object { ([string]$_).ToLowerInvariant() })
}

function Has-AnyToken {
    param(
        [string]$Text,
        [object[]]$Tokens
    )
    $hits = New-Object System.Collections.ArrayList
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    $lower = $Text.ToLowerInvariant()
    foreach ($t in $Tokens) {
        $token = ([string]$t).ToLowerInvariant()
        if ($token.Length -gt 0 -and $lower.Contains($token)) { [void]$hits.Add($t) }
    }
    return @($hits | Select-Object -Unique)
}

function Get-SafeChildItems {
    param(
        [string]$Path,
        [switch]$Recurse,
        [string[]]$Include
    )
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    try {
        if ($Include -and $Include.Count -gt 0) {
            return @(Get-ChildItem -LiteralPath $Path -File -Include $Include -Recurse:$Recurse -ErrorAction SilentlyContinue)
        }
        return @(Get-ChildItem -LiteralPath $Path -File -Recurse:$Recurse -ErrorAction SilentlyContinue)
    } catch {
        $script:ReadErrors++
        Write-Log 'WARN' ('Cannot enumerate: ' + $Path + ' | ' + $_.Exception.Message)
        return @()
    }
}

function Get-FileHashSafe {
    param([string]$Path)
    try {
        return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToUpperInvariant()
    } catch {
        $script:ReadErrors++
        return ''
    }
}

function HtmlEncode {
    param([object]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Start-YrysScan {
    Initialize-Yrys
    Show-Banner

    $header = @(
        '============================================================',
        ('YRYS CHECKER v' + $script:ScriptVersion),
        ('RunId: ' + $script:RunId),
        ('Computer: ' + $env:COMPUTERNAME),
        ('User: ' + $env:USERNAME),
        ('Admin: ' + $script:IsAdmin),
        ('PowerShell: ' + $PSVersionTable.PSVersion),
        ('OnlyMinecraft: ' + $OnlyMinecraft),
        ('Deep: ' + $Deep),
        '============================================================'
    )
    foreach ($h in $header) { Add-Content -LiteralPath $script:TxtReport -Value $h -Encoding UTF8 }

    Write-Log 'INFO' 'Full autonomous scan started.'
    if (-not $script:IsAdmin) {
        Write-Log 'WARN' 'Not running as Administrator. DLL/module, Prefetch, and some network checks may be limited.'
    }

    Scan-RunningProcesses
    Scan-JavaMinecraftProcesses
    Scan-MinecraftFolders
    Scan-NetworkConnections

    if (-not $OnlyMinecraft) {
        Scan-StartupLocations
        Scan-HostsFile
        Scan-Prefetch
    }

    if ($Deep) {
        Scan-DeepUserLocations
    }

    Save-AllReports
    Show-FinalVerdict

    if ($OpenReport) {
        if ((-not $NoHtml) -and (Test-Path -LiteralPath $script:HtmlReport)) { Start-Process $script:HtmlReport }
        elseif (Test-Path -LiteralPath $script:TxtReport) { Start-Process notepad.exe $script:TxtReport }
    }
}

function Scan-RunningProcesses {
    Write-Log 'INFO' 'Scanning running processes and window titles...'
    $procTokens = Get-LowerList $script:CheatDB.ProcessNames
    $windowTokens = Get-LowerList $script:CheatDB.WindowTitleKeywords

    try {
        $processes = @(Get-Process -ErrorAction Stop)
    } catch {
        Write-Log 'WARN' ('Get-Process failed: ' + $_.Exception.Message)
        return
    }

    foreach ($p in $processes) {
        $pname = ([string]$p.ProcessName).ToLowerInvariant()
        $title = [string]$p.MainWindowTitle
        if ($procTokens -contains $pname) {
            Add-Finding -Severity 'High' -Score 70 -Category 'ProcessName' -Title ('Known suspicious process name: ' + $p.ProcessName) -Path $p.Path -Evidence ('PID=' + $p.Id)
        }
        $titleHits = Has-AnyToken -Text $title -Tokens $windowTokens
        if ($titleHits.Count -gt 0) {
            Add-Finding -Severity 'High' -Score 65 -Category 'WindowTitle' -Title ('Suspicious window title: ' + $title) -Path $p.Path -Evidence ('PID=' + $p.Id + '; Hits=' + (($titleHits) -join ', '))
        }
    }
    Write-Log 'OK' 'Process/window scan finished.'
}

function Scan-JavaMinecraftProcesses {
    Write-Log 'INFO' 'Scanning Java/Minecraft processes, command lines, javaagents, and loaded modules...'
    try {
        $processes = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
            $_.Name -match '(?i)java|javaw|minecraft|launcher' -or ([string]$_.CommandLine) -match '(?i)minecraft|\.jar|forge|fabric|quilt|optifine|lunar|badlion|tlauncher|feather'
        })
    } catch {
        Write-Log 'WARN' ('Win32_Process read failed: ' + $_.Exception.Message)
        return
    }

    if ($processes.Count -eq 0) {
        Write-Log 'WARN' 'No active Java/Minecraft processes found. Disk folders will still be scanned.'
        return
    }

    foreach ($proc in $processes) {
        $cmd = [string]$proc.CommandLine
        Write-Log 'OK' ('Process: ' + $proc.Name + ' PID=' + $proc.ProcessId)
        if (-not [string]::IsNullOrWhiteSpace($cmd)) { Write-Log 'INFO' ('CommandLine: ' + $cmd) }

        $agentHits = Has-AnyToken -Text $cmd -Tokens @('javaagent','inject','mixin','weave','loader','vape','raven','rise','liquidbounce','meteor','wurst')
        if ($cmd -match '(?i)-javaagent:' -or $agentHits.Count -gt 0) {
            Add-Finding -Severity 'High' -Score 75 -Category 'JavaAgentOrCmd' -Title 'Suspicious Java command line or javaagent flag' -Path '' -Evidence ('PID=' + $proc.ProcessId + '; Hits=' + (($agentHits) -join ', '))
        }

        $jarPaths = Get-JarPathsFromText -Text $cmd
        foreach ($jar in $jarPaths) {
            if (Test-Path -LiteralPath $jar -PathType Leaf) {
                Scan-CandidateFile -Path $jar -Source ('CommandLine PID=' + $proc.ProcessId)
            } else {
                Add-Finding -Severity 'Low' -Score 5 -Category 'JarPath' -Title 'JAR path in command line but file not found' -Path $jar -Evidence ('PID=' + $proc.ProcessId)
            }
        }
        Scan-ProcessModules -ProcessId ([int]$proc.ProcessId) -ProcessName ([string]$proc.Name)
    }
}

function Get-JarPathsFromText {
    param([string]$Text)
    $out = New-Object System.Collections.ArrayList
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    $patterns = @(
        '"([^"]+?\.jar)"',
        "'([^']+?\.jar)'",
        '([A-Za-z]:\\[^\s"<>|]+?\.jar)'
    )
    foreach ($pat in $patterns) {
        $matches = [regex]::Matches($Text, $pat, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        foreach ($m in $matches) {
            $v = $m.Groups[1].Value
            if (-not [string]::IsNullOrWhiteSpace($v)) {
                $expanded = [Environment]::ExpandEnvironmentVariables($v.Trim())
                [void]$out.Add($expanded)
            }
        }
    }
    return @($out | Select-Object -Unique)
}

function Scan-ProcessModules {
    param(
        [int]$ProcessId,
        [string]$ProcessName
    )
    try {
        $p = Get-Process -Id $ProcessId -ErrorAction Stop
        $modules = @($p.Modules)
    } catch {
        $script:ReadErrors++
        Write-Log 'WARN' ('Cannot read modules for PID ' + $ProcessId + ': ' + $_.Exception.Message)
        return
    }

    $knownDlls = Get-LowerList $script:CheatDB.DllModules
    foreach ($m in $modules) {
        $moduleName = ([string]$m.ModuleName).ToLowerInvariant()
        $filePath = [string]$m.FileName
        if ($knownDlls -contains $moduleName) {
            Add-Finding -Severity 'Critical' -Score 100 -Category 'InjectedDLL' -Title ('Known suspicious DLL loaded: ' + $m.ModuleName) -Path $filePath -Evidence ('PID=' + $ProcessId + '; Process=' + $ProcessName)
        }
        $moduleHits = Has-AnyToken -Text ($moduleName + ' ' + $filePath) -Tokens @('vape','raven','rise','inject','hook','ghost','clicker','entropy','whiteout','drip')
        if ($moduleHits.Count -gt 0 -and $moduleName -notmatch '(?i)java|jvm|windows|system32|nvidia|amd|intel|discord|overlay') {
            Add-Finding -Severity 'Medium' -Score 30 -Category 'SuspiciousModule' -Title ('Suspicious module name/path in Java process: ' + $m.ModuleName) -Path $filePath -Evidence ('PID=' + $ProcessId + '; Hits=' + (($moduleHits) -join ', '))
        }
    }
}

function Scan-MinecraftFolders {
    Write-Log 'INFO' 'Scanning Minecraft folders...'
    $roots = New-Object System.Collections.ArrayList
    $candidates = @(
        (Join-Path $env:APPDATA '.minecraft'),
        (Join-Path $env:APPDATA '.tlauncher'),
        (Join-Path $env:APPDATA '.feather'),
        (Join-Path $env:APPDATA '.lunarclient'),
        (Join-Path $env:APPDATA 'Badlion Client'),
        (Join-Path $env:LOCALAPPDATA 'Packages'),
        (Join-Path $env:USERPROFILE 'curseforge'),
        (Join-Path $env:USERPROFILE 'Twitch'),
        (Join-Path $env:USERPROFILE 'AppData\Roaming\.minecraft')
    )
    foreach ($c in $candidates) {
        if (-not [string]::IsNullOrWhiteSpace($c) -and (Test-Path -LiteralPath $c)) { [void]$roots.Add($c) }
    }
    if ($roots.Count -eq 0) {
        Write-Log 'WARN' 'No Minecraft-related folders found.'
        return
    }
    foreach ($root in ($roots | Select-Object -Unique)) {
        Write-Log 'INFO' ('Folder: ' + $root)
        $files = Get-SafeChildItems -Path $root -Recurse -Include @('*.jar','*.dll','*.exe','*.json','*.cfg','*.toml','*.properties','*.txt')
        foreach ($file in $files) { Scan-CandidateFile -Path $file.FullName -Source ('MinecraftFolder=' + $root) }
    }
    Write-Log 'OK' 'Minecraft folder scan finished.'
}

function Scan-DeepUserLocations {
    Write-Log 'INFO' 'Deep mode: scanning Downloads/Desktop/Documents/Temp/AppData local user locations...'
    $roots = @(
        (Join-Path $env:USERPROFILE 'Downloads'),
        (Join-Path $env:USERPROFILE 'Desktop'),
        (Join-Path $env:USERPROFILE 'Documents'),
        $env:TEMP,
        $env:LOCALAPPDATA,
        $env:APPDATA
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path -LiteralPath $_) } | Select-Object -Unique

    foreach ($root in $roots) {
        Write-Log 'INFO' ('Deep folder: ' + $root)
        $files = Get-SafeChildItems -Path $root -Recurse -Include @('*.jar','*.dll','*.exe','*.json','*.cfg','*.toml','*.properties','*.txt')
        foreach ($file in $files) {
            $hit = Has-AnyToken -Text ($file.Name + ' ' + $file.FullName) -Tokens $script:CheatDB.FileNameTokens
            if ($hit.Count -gt 0 -or $file.Extension -match '(?i)\.jar') {
                Scan-CandidateFile -Path $file.FullName -Source ('DeepFolder=' + $root)
            }
        }
    }
}

function Scan-CandidateFile {
    param(
        [string]$Path,
        [string]$Source = ''
    )
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }

    $item = $null
    try { $item = Get-Item -LiteralPath $Path -ErrorAction Stop } catch { $script:ReadErrors++; return }
    if ($null -eq $item) { return }

    $script:ScannedFiles++
    if ($item.Length -gt ($MaxFileMB * 1MB)) {
        Write-Log 'WARN' ('Skip large file: ' + $Path + ' SizeMB=' + [math]::Round($item.Length / 1MB, 2))
        return
    }

    $ext = ([string]$item.Extension).ToLowerInvariant()
    $nameHits = Has-AnyToken -Text ($item.Name + ' ' + $item.FullName) -Tokens $script:CheatDB.FileNameTokens
    if ($nameHits.Count -gt 0) {
        $sev = 'Medium'
        $score = 35
        if ($ext -eq '.jar' -or $ext -eq '.dll' -or $ext -eq '.exe') { $sev = 'High'; $score = 55 }
        Add-Finding -Severity $sev -Score $score -Category 'FileName' -Title 'Suspicious file name/path token' -Path $item.FullName -Evidence ('Hits=' + (($nameHits) -join ', ') + '; Source=' + $Source)
    }

    if ($ext -in @('.jar','.dll','.exe')) {
        $hash = Get-FileHashSafe -Path $item.FullName
        if (-not [string]::IsNullOrWhiteSpace($hash)) {
            $knownHashes = Get-LowerList $script:CheatDB.Hashes
            if ($knownHashes -contains $hash.ToLowerInvariant()) {
                Add-Finding -Severity 'Critical' -Score 100 -Category 'HashSignature' -Title 'SHA256 matches known suspicious signature' -Path $item.FullName -Evidence ('SHA256=' + $hash)
            }
        }
    }

    if ($ext -eq '.jar') {
        $script:ScannedJars++
        Scan-ArchiveForIndicators -ArchivePath $item.FullName
    } elseif ($ext -in @('.json','.cfg','.toml','.properties','.txt')) {
        Scan-TextFileForIndicators -Path $item.FullName
    } elseif ($ext -in @('.dll','.exe')) {
        if ($nameHits.Count -gt 0) { Scan-Authenticode -Path $item.FullName }
    }
}

function Scan-Authenticode {
    param([string]$Path)
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        if ($sig.Status -ne 'Valid') {
            Add-Finding -Severity 'Medium' -Score 25 -Category 'Signature' -Title 'Suspicious EXE/DLL is not validly signed' -Path $Path -Evidence ('Authenticode=' + $sig.Status)
        }
    } catch {
        $script:ReadErrors++
    }
}

function Scan-TextFileForIndicators {
    param([string]$Path)
    try {
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($item.Length -gt (2MB)) { return }
        $text = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        $hits = Has-AnyToken -Text $text -Tokens $script:CheatDB.SuspiciousStrings
        if ($hits.Count -gt 0) {
            Add-Finding -Severity 'Low' -Score 10 -Category 'ConfigText' -Title 'Suspicious words in text/config file' -Path $Path -Evidence ('Hits=' + (($hits | Select-Object -First 12) -join ', '))
        }
    } catch {
        $script:ReadErrors++
    }
}

function Scan-ArchiveForIndicators {
    param([string]$ArchivePath)
    $zip = $null
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
        $zip = [System.IO.Compression.ZipFile]::OpenRead($ArchivePath)
        $entryNameHits = New-Object System.Collections.ArrayList
        $contentHits = New-Object System.Collections.ArrayList
        $maxBytes = $MaxEntryKB * 1024

        foreach ($entry in $zip.Entries) {
            $full = [string]$entry.FullName
            $nameHit = Has-AnyToken -Text $full -Tokens $script:CheatDB.FileNameTokens
            foreach ($h in $nameHit) { [void]$entryNameHits.Add($h) }

            if ($entry.Length -le 0 -or $entry.Length -gt $maxBytes) { continue }
            if ($full -notmatch '(?i)\.(class|txt|json|cfg|toml|properties|mf|xml|yml|yaml)$' -and $full -notmatch '(?i)META-INF') { continue }

            $stream = $null
            $reader = $null
            try {
                $stream = $entry.Open()
                $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8, $true)
                $content = $reader.ReadToEnd()
                $hits = Has-AnyToken -Text $content -Tokens $script:CheatDB.SuspiciousStrings
                foreach ($h in $hits) { [void]$contentHits.Add($h) }
            } catch {
                $script:ReadErrors++
            } finally {
                if ($null -ne $reader) { $reader.Close() }
                elseif ($null -ne $stream) { $stream.Close() }
            }
        }

        $entryHitsUnique = @($entryNameHits | Select-Object -Unique)
        $contentHitsUnique = @($contentHits | Select-Object -Unique)
        if ($entryHitsUnique.Count -gt 0) {
            Add-Finding -Severity 'Medium' -Score 30 -Category 'JarEntryName' -Title 'Suspicious entry name inside JAR' -Path $ArchivePath -Evidence ('Hits=' + (($entryHitsUnique | Select-Object -First 16) -join ', '))
        }
        if ($contentHitsUnique.Count -gt 0) {
            $severity = 'Medium'
            $score = 35
            if ($contentHitsUnique.Count -ge 5) { $severity = 'High'; $score = 60 }
            Add-Finding -Severity $severity -Score $score -Category 'JarContent' -Title 'Suspicious strings inside JAR/class/config content' -Path $ArchivePath -Evidence ('Hits=' + (($contentHitsUnique | Select-Object -First 18) -join ', '))
        }
    } catch {
        $script:ReadErrors++
        Write-Log 'WARN' ('Cannot scan archive: ' + $ArchivePath + ' | ' + $_.Exception.Message)
    } finally {
        if ($null -ne $zip) { $zip.Dispose() }
    }
}

function Scan-NetworkConnections {
    Write-Log 'INFO' 'Scanning established network connections against known suspicious hosts...'
    $known = New-Object System.Collections.ArrayList
    foreach ($hostItem in $script:CheatDB.CheatServers) {
        $h = [string]$hostItem
        if ([string]::IsNullOrWhiteSpace($h)) { continue }
        $parsed = $null
        if ([System.Net.IPAddress]::TryParse($h, [ref]$parsed)) {
            [void]$known.Add($h)
        } else {
            try {
                $ips = [System.Net.Dns]::GetHostAddresses($h)
                foreach ($ip in $ips) { [void]$known.Add($ip.IPAddressToString) }
            } catch { }
        }
    }
    $known = @($known | Select-Object -Unique)
    if ($known.Count -eq 0) {
        Write-Log 'WARN' 'No known IPs resolved for network check.'
        return
    }

    if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
        try {
            $conns = @(Get-NetTCPConnection -State Established -ErrorAction Stop)
            foreach ($c in $conns) {
                if ($known -contains $c.RemoteAddress) {
                    Add-Finding -Severity 'High' -Score 70 -Category 'Network' -Title 'Established connection to suspicious host/IP' -Path '' -Evidence ('Remote=' + $c.RemoteAddress + ':' + $c.RemotePort + '; PID=' + $c.OwningProcess)
                }
            }
        } catch {
            Write-Log 'WARN' ('Get-NetTCPConnection failed: ' + $_.Exception.Message)
        }
    } else {
        Write-Log 'WARN' 'Get-NetTCPConnection is not available on this system.'
    }
}

function Scan-StartupLocations {
    Write-Log 'INFO' 'Scanning startup registry, startup folders, and scheduled tasks...'
    $runKeys = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    )
    foreach ($rk in $runKeys) {
        try {
            if (Test-Path $rk) {
                $props = Get-ItemProperty -Path $rk -ErrorAction Stop
                foreach ($p in $props.PSObject.Properties) {
                    if ($p.Name -like 'PS*') { continue }
                    $value = [string]$p.Value
                    $hits = Has-AnyToken -Text ($p.Name + ' ' + $value) -Tokens $script:CheatDB.FileNameTokens
                    if ($hits.Count -gt 0) {
                        Add-Finding -Severity 'Medium' -Score 35 -Category 'StartupRegistry' -Title 'Suspicious token in startup registry' -Path $rk -Evidence ($p.Name + '=' + $value + '; Hits=' + (($hits) -join ', '))
                    }
                }
            }
        } catch { $script:ReadErrors++ }
    }

    $startupFolders = @(
        [Environment]::GetFolderPath('Startup'),
        (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp')
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path -LiteralPath $_) }
    foreach ($sf in $startupFolders) {
        $files = Get-SafeChildItems -Path $sf -Recurse
        foreach ($f in $files) {
            $hits = Has-AnyToken -Text ($f.Name + ' ' + $f.FullName) -Tokens $script:CheatDB.FileNameTokens
            if ($hits.Count -gt 0) {
                Add-Finding -Severity 'Medium' -Score 30 -Category 'StartupFolder' -Title 'Suspicious startup folder item' -Path $f.FullName -Evidence ('Hits=' + (($hits) -join ', '))
            }
        }
    }

    if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
        try {
            $tasks = @(Get-ScheduledTask -ErrorAction Stop)
            foreach ($t in $tasks) {
                $text = ($t.TaskName + ' ' + $t.TaskPath + ' ' + (($t.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join ' '))
                $hits = Has-AnyToken -Text $text -Tokens $script:CheatDB.FileNameTokens
                if ($hits.Count -gt 0) {
                    Add-Finding -Severity 'Medium' -Score 35 -Category 'ScheduledTask' -Title 'Suspicious token in scheduled task' -Path ($t.TaskPath + $t.TaskName) -Evidence ('Hits=' + (($hits) -join ', '))
                }
            }
        } catch {
            Write-Log 'WARN' ('Scheduled task scan failed: ' + $_.Exception.Message)
        }
    }
}

function Scan-HostsFile {
    Write-Log 'INFO' 'Scanning hosts file...'
    $hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    if (-not (Test-Path -LiteralPath $hosts)) { return }
    try {
        $content = Get-Content -LiteralPath $hosts -Raw -ErrorAction Stop
        $hits = Has-AnyToken -Text $content -Tokens $script:CheatDB.CheatServers
        if ($hits.Count -gt 0) {
            Add-Finding -Severity 'Medium' -Score 25 -Category 'HostsFile' -Title 'Known suspicious domains are mentioned in hosts file' -Path $hosts -Evidence ('Hits=' + (($hits) -join ', '))
        }
    } catch { $script:ReadErrors++ }
}

function Scan-Prefetch {
    Write-Log 'INFO' 'Scanning Prefetch file names...'
    $prefetch = Join-Path $env:SystemRoot 'Prefetch'
    if (-not (Test-Path -LiteralPath $prefetch)) { return }
    try {
        $files = @(Get-ChildItem -LiteralPath $prefetch -File -ErrorAction SilentlyContinue)
        foreach ($f in $files) {
            $hits = Has-AnyToken -Text $f.Name -Tokens $script:CheatDB.FileNameTokens
            if ($hits.Count -gt 0) {
                Add-Finding -Severity 'Low' -Score 15 -Category 'Prefetch' -Title 'Suspicious token in Windows Prefetch file name' -Path $f.FullName -Evidence ('Hits=' + (($hits) -join ', '))
            }
        }
    } catch { $script:ReadErrors++ }
}

function Get-TotalScore {
    $sum = 0
    foreach ($f in $script:Findings) { $sum += [int]$f.Score }
    return $sum
}

function Get-VerdictObject {
    $score = Get-TotalScore
    $critical = @($script:Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $high = @($script:Findings | Where-Object { $_.Severity -eq 'High' }).Count
    $medium = @($script:Findings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $low = @($script:Findings | Where-Object { $_.Severity -eq 'Low' }).Count

    $status = 'CLEAN'
    $title = 'No critical cheat indicators found'
    $recommendation = 'Save the report. If you still suspect cheating, rerun as Administrator with -Deep.'

    if ($critical -gt 0 -or $score -ge 100) {
        $status = 'CHEAT_LIKELY'
        $title = 'High probability of cheat/injector indicators'
        $recommendation = 'Review found files/processes manually. Do not delete anything until verified. Reboot and scan again after cleanup.'
    } elseif ($high -gt 0 -or $score -ge 55) {
        $status = 'SUSPICIOUS_HIGH'
        $title = 'Strong suspicious indicators found'
        $recommendation = 'Review the JAR/DLL/process findings. Some legitimate mods may contain similar words, so verify manually.'
    } elseif ($medium -gt 0 -or $score -ge 20) {
        $status = 'SUSPICIOUS'
        $title = 'Suspicious indicators found'
        $recommendation = 'Check findings carefully. Low/medium string hits alone are not final proof.'
    }

    return [pscustomobject]@{
        Status = $status
        Title = $title
        Score = $score
        Critical = $critical
        High = $high
        Medium = $medium
        Low = $low
        Recommendation = $recommendation
    }
}

function Save-AllReports {
    Write-Log 'INFO' 'Saving TXT, JSON, and HTML reports...'
    $verdict = Get-VerdictObject

    Add-Content -LiteralPath $script:TxtReport -Value '' -Encoding UTF8
    Add-Content -LiteralPath $script:TxtReport -Value '================ FINAL VERDICT ================' -Encoding UTF8
    Add-Content -LiteralPath $script:TxtReport -Value ('Status: ' + $verdict.Status) -Encoding UTF8
    Add-Content -LiteralPath $script:TxtReport -Value ('Title: ' + $verdict.Title) -Encoding UTF8
    Add-Content -LiteralPath $script:TxtReport -Value ('Score: ' + $verdict.Score) -Encoding UTF8
    Add-Content -LiteralPath $script:TxtReport -Value ('Critical/High/Medium/Low: ' + $verdict.Critical + '/' + $verdict.High + '/' + $verdict.Medium + '/' + $verdict.Low) -Encoding UTF8
    Add-Content -LiteralPath $script:TxtReport -Value ('ScannedFiles/ScannedJars: ' + $script:ScannedFiles + '/' + $script:ScannedJars) -Encoding UTF8
    Add-Content -LiteralPath $script:TxtReport -Value ('Recommendation: ' + $verdict.Recommendation) -Encoding UTF8
    Add-Content -LiteralPath $script:TxtReport -Value ('HTML: ' + $script:HtmlReport) -Encoding UTF8
    Add-Content -LiteralPath $script:TxtReport -Value ('JSON: ' + $script:JsonReport) -Encoding UTF8

    $jsonObj = [pscustomobject]@{
        Meta = [pscustomobject]@{
            Tool = 'YRYS CHECKER'
            Version = $script:ScriptVersion
            RunId = $script:RunId
            Computer = $env:COMPUTERNAME
            User = $env:USERNAME
            IsAdmin = $script:IsAdmin
            PowerShell = [string]$PSVersionTable.PSVersion
            OnlyMinecraft = [bool]$OnlyMinecraft
            Deep = [bool]$Deep
            ScannedFiles = $script:ScannedFiles
            ScannedJars = $script:ScannedJars
            ReadErrors = $script:ReadErrors
        }
        Verdict = $verdict
        Findings = @($script:Findings)
    }
    try {
        $jsonObj | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $script:JsonReport -Encoding UTF8
    } catch {
        Write-Log 'WARN' ('JSON save failed: ' + $_.Exception.Message)
    }

    Save-HtmlReport
    Write-Log 'OK' ('Reports saved to: ' + $script:RunDir)
}

function Save-HtmlReport {
    if ($NoHtml) { return }
    $verdict = Get-VerdictObject
    $rows = New-Object System.Text.StringBuilder
    $sorted = @($script:Findings | Sort-Object @{Expression='Score';Descending=$true}, Severity, Category)
    foreach ($f in $sorted) {
        $sevClass = (HtmlEncode $f.Severity).ToLowerInvariant()
        $line = "<tr class='$sevClass'><td>" + (HtmlEncode $f.Severity) + '</td><td>' + (HtmlEncode $f.Score) + '</td><td>' + (HtmlEncode $f.Category) + '</td><td>' + (HtmlEncode $f.Title) + '</td><td class="path">' + (HtmlEncode $f.Path) + '</td><td>' + (HtmlEncode $f.Evidence) + '</td><td>' + (HtmlEncode $f.Recommendation) + '</td></tr>'
        [void]$rows.AppendLine($line)
    }
    if ($script:Findings.Count -eq 0) {
        [void]$rows.AppendLine('<tr><td colspan="7" class="clean">No findings</td></tr>')
    }

    $html = New-Object System.Text.StringBuilder
    [void]$html.AppendLine('<!doctype html>')
    [void]$html.AppendLine('<html lang="en">')
    [void]$html.AppendLine('<head>')
    [void]$html.AppendLine('<meta charset="utf-8">')
    [void]$html.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$html.AppendLine('<title>YRYS CHECKER Report</title>')
    [void]$html.AppendLine('<style>')
    [void]$html.AppendLine(':root{--bg:#0b0506;--panel:#16080a;--panel2:#210b0f;--red:#ff1f3d;--red2:#b00020;--text:#fff3f3;--muted:#d9a2aa;--line:#3a1118;--ok:#35d07f;--warn:#ffcc66;}')
    [void]$html.AppendLine('*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top,#3b0610 0,#120406 35%,#050203 100%);color:var(--text);font-family:Segoe UI,Arial,sans-serif;}')
    [void]$html.AppendLine('.hero{padding:42px 28px;border-bottom:1px solid var(--line);background:linear-gradient(135deg,#30040a,#090203 70%);box-shadow:0 24px 80px rgba(255,0,40,.18)}')
    [void]$html.AppendLine('.logo{font-size:54px;line-height:.95;font-weight:900;letter-spacing:2px;color:var(--red);text-shadow:0 0 22px rgba(255,31,61,.75),0 0 4px #fff;text-transform:uppercase;}')
    [void]$html.AppendLine('.sub{margin-top:12px;color:var(--muted);font-size:17px}.wrap{padding:26px;max-width:1400px;margin:0 auto}.cards{display:grid;grid-template-columns:repeat(5,minmax(160px,1fr));gap:14px;margin-top:-34px}.card{background:linear-gradient(180deg,var(--panel2),var(--panel));border:1px solid var(--line);border-radius:18px;padding:18px;box-shadow:0 12px 40px rgba(0,0,0,.35)}')
    [void]$html.AppendLine('.k{color:var(--muted);font-size:13px;text-transform:uppercase;letter-spacing:.08em}.v{font-size:28px;font-weight:800;margin-top:6px}.status{color:var(--red);text-shadow:0 0 14px rgba(255,31,61,.5)}')
    [void]$html.AppendLine('.section{margin-top:22px;background:rgba(22,8,10,.78);border:1px solid var(--line);border-radius:20px;overflow:hidden}.section h2{margin:0;padding:18px 20px;background:#1b070b;border-bottom:1px solid var(--line);color:#fff}.section .body{padding:18px 20px;color:#ffdce1}')
    [void]$html.AppendLine('table{width:100%;border-collapse:collapse;font-size:13px}th,td{border-bottom:1px solid var(--line);padding:10px;vertical-align:top}th{position:sticky;top:0;background:#260a10;color:#fff;text-align:left}tr.critical td{background:rgba(255,0,40,.18)}tr.high td{background:rgba(255,80,80,.13)}tr.medium td{background:rgba(255,170,0,.10)}tr.low td{background:rgba(255,255,255,.04)}.path{font-family:Consolas,monospace;font-size:12px;word-break:break-all;color:#ffc7cf}.clean{color:var(--ok);font-size:20px;text-align:center;padding:24px}.footer{padding:24px;color:var(--muted);font-size:12px}.pill{display:inline-block;border:1px solid var(--red2);background:rgba(255,31,61,.14);padding:6px 10px;border-radius:999px;color:#ffd7dc}')
    [void]$html.AppendLine('@media(max-width:900px){.cards{grid-template-columns:1fr 1fr}.logo{font-size:38px}table{font-size:12px}}')
    [void]$html.AppendLine('</style>')
    [void]$html.AppendLine('</head>')
    [void]$html.AppendLine('<body>')
    [void]$html.AppendLine('<div class="hero">')
    [void]$html.AppendLine('<div class="logo">YRYS<br>CHECKER</div>')
    [void]$html.AppendLine('<div class="sub">Advanced v' + (HtmlEncode $script:ScriptVersion) + ' - strict Minecraft/Java report - Run ' + (HtmlEncode $script:RunId) + '</div>')
    [void]$html.AppendLine('</div>')
    [void]$html.AppendLine('<div class="wrap">')
    [void]$html.AppendLine('<div class="cards">')
    [void]$html.AppendLine('<div class="card"><div class="k">Verdict</div><div class="v status">' + (HtmlEncode $verdict.Status) + '</div></div>')
    [void]$html.AppendLine('<div class="card"><div class="k">Score</div><div class="v">' + (HtmlEncode $verdict.Score) + '</div></div>')
    [void]$html.AppendLine('<div class="card"><div class="k">Critical</div><div class="v">' + (HtmlEncode $verdict.Critical) + '</div></div>')
    [void]$html.AppendLine('<div class="card"><div class="k">High/Medium</div><div class="v">' + (HtmlEncode ([string]$verdict.High + '/' + [string]$verdict.Medium)) + '</div></div>')
    [void]$html.AppendLine('<div class="card"><div class="k">Files/JARs</div><div class="v">' + (HtmlEncode ([string]$script:ScannedFiles + '/' + [string]$script:ScannedJars)) + '</div></div>')
    [void]$html.AppendLine('</div>')
    [void]$html.AppendLine('<div class="section"><h2>Summary</h2><div class="body">')
    [void]$html.AppendLine('<p><span class="pill">' + (HtmlEncode $verdict.Title) + '</span></p>')
    [void]$html.AppendLine('<p>' + (HtmlEncode $verdict.Recommendation) + '</p>')
    [void]$html.AppendLine('<p>Computer: <b>' + (HtmlEncode $env:COMPUTERNAME) + '</b> - User: <b>' + (HtmlEncode $env:USERNAME) + '</b> - Admin: <b>' + (HtmlEncode $script:IsAdmin) + '</b> - Read errors: <b>' + (HtmlEncode $script:ReadErrors) + '</b></p>')
    [void]$html.AppendLine('</div></div>')
    [void]$html.AppendLine('<div class="section"><h2>Findings</h2><div style="overflow:auto;max-height:70vh">')
    [void]$html.AppendLine('<table><thead><tr><th>Severity</th><th>Score</th><th>Category</th><th>Finding</th><th>Path</th><th>Evidence</th><th>Recommendation</th></tr></thead><tbody>')
    [void]$html.AppendLine([string]$rows)
    [void]$html.AppendLine('</tbody></table>')
    [void]$html.AppendLine('</div></div>')
    [void]$html.AppendLine('<div class="footer">YRYS CHECKER is a detection/reporting tool. It does not prove guilt by itself. Verify findings manually.</div>')
    [void]$html.AppendLine('</div>')
    [void]$html.AppendLine('</body></html>')

    try {
        Set-Content -LiteralPath $script:HtmlReport -Value ([string]$html) -Encoding UTF8
    } catch {
        Write-Log 'WARN' ('HTML save failed: ' + $_.Exception.Message)
    }
}

function Show-FinalVerdict {
    $verdict = Get-VerdictObject
    Write-Host ''
    Write-Host '================ YRYS CHECKER VERDICT ================' -ForegroundColor Red
    Write-Host ('STATUS: ' + $verdict.Status) -ForegroundColor Red
    Write-Host ('SCORE: ' + $verdict.Score) -ForegroundColor Yellow
    Write-Host ('CRITICAL/HIGH/MEDIUM/LOW: ' + $verdict.Critical + '/' + $verdict.High + '/' + $verdict.Medium + '/' + $verdict.Low) -ForegroundColor Yellow
    Write-Host ('SCANNED FILES/JARS: ' + $script:ScannedFiles + '/' + $script:ScannedJars) -ForegroundColor Cyan
    Write-Host ('REPORT TXT:  ' + $script:TxtReport) -ForegroundColor Green
    if (-not $NoHtml) { Write-Host ('REPORT HTML: ' + $script:HtmlReport) -ForegroundColor Green }
    Write-Host ('REPORT JSON: ' + $script:JsonReport) -ForegroundColor Green
    Write-Host '======================================================' -ForegroundColor Red
}

Start-YrysScan
