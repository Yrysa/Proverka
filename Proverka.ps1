#Requires -Version 5.1
<#
 YRYS CHECKER POWER v6.1
 Smart local cheat checker for Windows / Minecraft.
 No permanent report files. Temp files are removed on exit.
 Compatible with old flags: -OnlyMinecraft and -OpenReport.
#>

[CmdletBinding()]
param(
    [string]$Cheat = "",
    [switch]$NoPrompt,
    [switch]$Fast,
    [switch]$Deep,
    [switch]$OnlyMinecraft,
    [switch]$OpenReport,
    [int]$MaxMinutes = 12,
    [int]$MaxCandidates = 650,
    [switch]$KeepTemp
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'SilentlyContinue'
$script:Version = '6.1.0'
$script:StartedAt = Get-Date
$script:Deadline = (Get-Date).AddMinutes([Math]::Max(2, $MaxMinutes))
$script:TempRoot = Join-Path $env:TEMP ("YRYS_CHECKER_" + ([guid]::NewGuid().ToString('N')))
$script:Findings = New-Object System.Collections.ArrayList
$script:Seen = @{}
$script:InputTokens = @()
$script:AllTokens = @()

function New-WorkDir {
    if (-not (Test-Path $script:TempRoot)) {
        New-Item -ItemType Directory -Path $script:TempRoot -Force | Out-Null
    }
}

function Remove-WorkDir {
    if ($KeepTemp) { return }
    try {
        if (Test-Path $script:TempRoot) {
            Remove-Item -LiteralPath $script:TempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    } catch { }
}

function Test-Admin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    } catch { return $false }
}

function Write-Line {
    param(
        [string]$Text = '',
        [ConsoleColor]$Color = [ConsoleColor]::Gray,
        [ConsoleColor]$Back = [ConsoleColor]::Black
    )
    try {
        if ($Back -eq [ConsoleColor]::Black) {
            Write-Host $Text -ForegroundColor $Color
        } else {
            Write-Host $Text -ForegroundColor $Color -BackgroundColor $Back
        }
    } catch {
        Write-Host $Text
    }
}

function Write-Status {
    param([string]$Kind, [string]$Text)
    switch ($Kind.ToUpperInvariant()) {
        'STEP' { Write-Line ("  > " + $Text) Cyan }
        'OK'   { Write-Line ("  + " + $Text) Green }
        'WARN' { Write-Line ("  ! " + $Text) Yellow }
        'BAD'  { Write-Line ("  X " + $Text) Red }
        'HIT'  { Write-Line ("  !!! " + $Text) Red DarkGray }
        default { Write-Line ("    " + $Text) Gray }
    }
}

function Show-Banner {
    Clear-Host
    Write-Line '' DarkRed
    Write-Line ' __   __ ____  __   __ ____     ____ _   _ _____ ____ _  _______ ____  ' Red
    Write-Line ' \ \ / /|  _ \ \ \ / / ___|   / ___| | | | ____/ ___| |/ / ____|  _ \ ' Red
    Write-Line '  \ V / | |_) | \ V /\___ \  | |   | |_| |  _|| |   | '' /|  _| | |_) |' Red
    Write-Line '   | |  |  _ <   | |  ___) | | |___|  _  | |__| |___| . \| |___|  _ < ' Red
    Write-Line '   |_|  |_| \_\  |_| |____/   \____|_| |_|_____\____|_|\_\_____|_| \_\' Red
    Write-Line '' DarkRed
    Write-Line ('  POWER v' + $script:Version + ' | smart local scan | no permanent reports') DarkRed
    Write-Line ('  Temp workspace: ' + $script:TempRoot) DarkGray
    Write-Line '' DarkRed
}

function Split-Tokens {
    param([string]$Text)
    $items = New-Object System.Collections.ArrayList
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    foreach ($raw in ($Text -split '[,;\s]+')) {
        $t = $raw.Trim().ToLowerInvariant()
        if ($t.Length -ge 3 -and -not $items.Contains($t)) { [void]$items.Add($t) }
    }
    return $items.ToArray()
}

function Initialize-Tokens {
    $default = @(
        'vape','raven','rise','drip','entropy','karma','akira','breeze','dream','doomsday',
        'augustus','novoline','zeroday','tenacity','astolfo','sigma','wurst','liquidbounce',
        'meteor','impact','aristois','inertia','future','rusherhack','phobos','pyro','abyss',
        'bleachhack','huzuni','wolfram','jigsaw','ares','reach','velocity','killaura','aimassist',
        'autoclicker','clicker','triggerbot','scaffold','xray','esp','nofall','bhop','blink','timer',
        'injector','loader','crack','bypass','ghostclient','clientmod','selfdestruct','clickgui'
    )

    if (-not $NoPrompt -and [string]::IsNullOrWhiteSpace($Cheat)) {
        Write-Line 'Enter possible cheat names/keywords separated by comma.' Yellow
        Write-Line 'Example: vape, raven, rise, drip, entropy' DarkGray
        $Cheat = Read-Host 'Cheats'
    }

    $script:InputTokens = Split-Tokens $Cheat
    $merged = New-Object System.Collections.ArrayList
    foreach ($t in @($script:InputTokens + $default)) {
        $v = [string]$t
        if ($v.Length -ge 3 -and -not $merged.Contains($v)) { [void]$merged.Add($v) }
    }
    $script:AllTokens = @($merged)

    if ($script:InputTokens.Count -gt 0) {
        Write-Status 'OK' ('Priority keywords: ' + ($script:InputTokens -join ', '))
    } else {
        Write-Status 'WARN' 'No custom keywords entered. Built-in cheat dictionary will be used.'
    }
}

function Test-Expired {
    return ((Get-Date) -gt $script:Deadline)
}

function Add-Finding {
    param(
        [string]$Kind,
        [string]$Path,
        [int]$Score,
        [string[]]$Reasons,
        [string]$Extra = ''
    )
    if ([string]::IsNullOrWhiteSpace($Path)) { $Path = '<unknown>' }
    $key = ($Kind + '|' + $Path).ToLowerInvariant()
    if ($script:Seen.ContainsKey($key)) {
        $old = $script:Seen[$key]
        if ($Score -gt $old.Score) { $old.Score = $Score }
        foreach ($r in $Reasons) { if ($old.Reasons -notcontains $r) { $old.Reasons += $r } }
        return
    }
    $sev = 'LOW'
    if ($Score -ge 85) { $sev = 'CRITICAL' }
    elseif ($Score -ge 65) { $sev = 'HIGH' }
    elseif ($Score -ge 42) { $sev = 'MEDIUM' }
    $obj = [pscustomobject]@{
        Kind = $Kind
        Path = $Path
        Score = $Score
        Severity = $sev
        Reasons = @($Reasons)
        Extra = $Extra
    }
    [void]$script:Findings.Add($obj)
    $script:Seen[$key] = $obj
}

function Normalize-PathSafe {
    param([string]$Path)
    try { return [System.IO.Path]::GetFullPath($Path) } catch { return $Path }
}

function Test-TextHasToken {
    param([string]$Text, [string[]]$Tokens)
    if ([string]::IsNullOrEmpty($Text)) { return @() }
    $lower = $Text.ToLowerInvariant()
    $hits = New-Object System.Collections.ArrayList
    foreach ($t in $Tokens) {
        if ($t.Length -ge 3 -and $lower.Contains($t)) { [void]$hits.Add($t) }
    }
    return @($hits | Select-Object -Unique)
}

function Get-MinecraftRoots {
    $roots = New-Object System.Collections.ArrayList
    $candidates = @(
        (Join-Path $env:APPDATA '.minecraft'),
        (Join-Path $env:APPDATA '.tlauncher'),
        (Join-Path $env:APPDATA '.feather'),
        (Join-Path $env:APPDATA '.lunarclient'),
        (Join-Path $env:LOCALAPPDATA 'Packages'),
        (Join-Path $env:LOCALAPPDATA 'Programs'),
        (Join-Path $env:USERPROFILE 'Downloads'),
        (Join-Path $env:USERPROFILE 'Desktop')
    )
    foreach ($r in $candidates) {
        if ($r -and (Test-Path $r) -and -not $roots.Contains($r)) { [void]$roots.Add($r) }
    }
    return $roots.ToArray()
}

function Get-SmartRoots {
    $roots = New-Object System.Collections.ArrayList
    foreach ($r in (Get-MinecraftRoots)) { if (-not $roots.Contains($r)) { [void]$roots.Add($r) } }
    $more = @(
        $env:TEMP,
        $env:APPDATA,
        $env:LOCALAPPDATA,
        (Join-Path $env:USERPROFILE 'Downloads'),
        (Join-Path $env:USERPROFILE 'Desktop'),
        (Join-Path $env:USERPROFILE 'Documents'),
        ${env:ProgramFiles},
        ${env:ProgramFiles(x86)},
        (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs')
    )
    foreach ($r in $more) {
        if ($r -and (Test-Path $r) -and -not $roots.Contains($r)) { [void]$roots.Add($r) }
    }
    if ($Deep -and -not $Fast -and -not $OnlyMinecraft) {
        try {
            foreach ($d in (Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3")) {
                $root = $d.DeviceID + '\'
                if ((Test-Path $root) -and -not $roots.Contains($root)) { [void]$roots.Add($root) }
            }
        } catch { }
    }
    return $roots.ToArray()
}

function Test-SkipDir {
    param([string]$Dir)
    if ([string]::IsNullOrWhiteSpace($Dir)) { return $true }
    $l = $Dir.ToLowerInvariant()
    $badNames = @('\$recycle.bin', '\system volume information', '\windows\winsxs', '\windows\installer', '\windows\servicing', '\windows\softwaredistribution', '\programdata\microsoft\windows defender', '\appdata\local\google\chrome\user data\default\cache', '\appdata\local\microsoft\edge\user data\default\cache', '\node_modules', '\.git', '\cache', '\caches')
    foreach ($b in $badNames) { if ($l.Contains($b)) { return $true } }
    return $false
}

function Test-InterestingPath {
    param([string]$Path)
    $l = $Path.ToLowerInvariant()
    if ($l.Contains('\.minecraft\') -or $l.Contains('\mods\') -or $l.Contains('\versions\') -or $l.Contains('\libraries\')) { return $true }
    if ($l.Contains('\appdata\') -or $l.Contains('\temp\') -or $l.Contains('\downloads\') -or $l.Contains('\desktop\')) { return $true }
    return $false
}

function Find-CandidateFiles {
    param([string[]]$Roots)
    $exts = @('.jar','.exe','.dll')
    $out = New-Object System.Collections.ArrayList
    $stack = New-Object System.Collections.Stack

    foreach ($r in $Roots) {
        if ($r -and (Test-Path $r)) { $stack.Push((Normalize-PathSafe $r)) }
    }

    while ($stack.Count -gt 0) {
        if (Test-Expired) { break }
        if ($out.Count -ge $MaxCandidates) { break }
        $dir = [string]$stack.Pop()
        if (Test-SkipDir $dir) { continue }

        try {
            $files = [System.IO.Directory]::EnumerateFiles($dir)
            foreach ($f in $files) {
                if (Test-Expired) { break }
                $ext = [System.IO.Path]::GetExtension($f).ToLowerInvariant()
                if ($exts -notcontains $ext) { continue }

                $hits = Test-TextHasToken $f $script:AllTokens
                $interesting = Test-InterestingPath $f
                if ($OnlyMinecraft) {
                    if (-not ($interesting -or $ext -eq '.jar')) { continue }
                }

                if ($hits.Count -gt 0 -or $interesting -or $ext -eq '.jar') {
                    [void]$out.Add($f)
                    if ($out.Count -ge $MaxCandidates) { break }
                }
            }
        } catch { }

        if (-not (Test-Expired)) {
            try {
                $dirs = [System.IO.Directory]::EnumerateDirectories($dir)
                foreach ($d in $dirs) {
                    if (-not (Test-SkipDir $d)) { $stack.Push($d) }
                }
            } catch { }
        }
    }
    return @($out.ToArray() | Select-Object -Unique)
}

function Read-HeadText {
    param([string]$Path, [int]$MaxBytes = 2097152)
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $n = [Math]::Min($MaxBytes, [int]$fs.Length)
            if ($n -le 0) { return '' }
            $buf = New-Object byte[] $n
            [void]$fs.Read($buf, 0, $n)
            return [System.Text.Encoding]::ASCII.GetString($buf)
        } finally { $fs.Close() }
    } catch { return '' }
}

function Scan-JarLight {
    param([string]$Path, [string[]]$Tokens)
    $hits = New-Object System.Collections.ArrayList
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        $zip = [System.IO.Compression.ZipFile]::OpenRead($Path)
        try {
            $checked = 0
            foreach ($e in $zip.Entries) {
                if ($checked -ge 80) { break }
                if (Test-Expired) { break }
                $nameHits = Test-TextHasToken $e.FullName $Tokens
                foreach ($h in $nameHits) { if (-not $hits.Contains($h)) { [void]$hits.Add($h) } }
                if ($e.Length -gt 0 -and $e.Length -le 262144 -and ($e.FullName -match '\.(txt|json|cfg|properties|mf|yml|yaml|class)$' -or $e.FullName.ToLowerInvariant().Contains('meta-inf'))) {
                    try {
                        $stream = $e.Open()
                        try {
                            $n = [Math]::Min(262144, [int]$e.Length)
                            $buf = New-Object byte[] $n
                            [void]$stream.Read($buf, 0, $n)
                            $text = [System.Text.Encoding]::ASCII.GetString($buf)
                            $contentHits = Test-TextHasToken $text $Tokens
                            foreach ($h in $contentHits) { if (-not $hits.Contains($h)) { [void]$hits.Add($h) } }
                        } finally { $stream.Close() }
                    } catch { }
                    $checked++
                }
            }
        } finally { $zip.Dispose() }
    } catch { }
    return $hits.ToArray()
}

function Get-SignatureSignal {
    param([string]$Path)
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction SilentlyContinue
        if ($null -eq $sig) { return 'NoSignatureInfo' }
        if ($sig.Status -eq 'Valid') { return 'SignedValid' }
        return ('UnsignedOrInvalid:' + $sig.Status)
    } catch { return 'NoSignatureInfo' }
}

function Analyze-File {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $score = 0
    $reasons = New-Object System.Collections.ArrayList
    $p = Normalize-PathSafe $Path
    $name = [System.IO.Path]::GetFileName($p)
    $ext = [System.IO.Path]::GetExtension($p).ToLowerInvariant()
    $lower = $p.ToLowerInvariant()

    $inputHits = Test-TextHasToken $p $script:InputTokens
    $allHits = Test-TextHasToken $p $script:AllTokens
    if ($inputHits.Count -gt 0) {
        $score += 55 + ([Math]::Min(20, $inputHits.Count * 5))
        [void]$reasons.Add(('Matches your keywords: ' + ($inputHits -join ', ')))
    } elseif ($allHits.Count -gt 0) {
        $score += 35 + ([Math]::Min(15, $allHits.Count * 4))
        [void]$reasons.Add(('Matches cheat dictionary: ' + ($allHits -join ', ')))
    }

    if ($ext -eq '.jar') { $score += 8; [void]$reasons.Add('JAR file') }
    if ($ext -eq '.dll') { $score += 6; [void]$reasons.Add('DLL file') }
    if ($ext -eq '.exe') { $score += 6; [void]$reasons.Add('EXE file') }
    if ($lower.Contains('\.minecraft\') -or $lower.Contains('\mods\') -or $lower.Contains('\versions\')) { $score += 18; [void]$reasons.Add('Minecraft-related path') }
    if ($lower.Contains('\appdata\') -or $lower.Contains('\temp\') -or $lower.Contains('\downloads\')) { $score += 12; [void]$reasons.Add('User/temp/downloads location') }
    if ($lower.Contains('loader') -or $lower.Contains('inject') -or $lower.Contains('bypass') -or $lower.Contains('selfdestruct')) { $score += 18; [void]$reasons.Add('Loader/injector/bypass naming') }

    try {
        $fi = Get-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
        if ($fi) {
            if (($fi.Attributes -band [IO.FileAttributes]::Hidden) -ne 0) { $score += 8; [void]$reasons.Add('Hidden file') }
            if ($fi.LastWriteTime -gt (Get-Date).AddDays(-14)) { $score += 4; [void]$reasons.Add('Recently modified') }
            if ($fi.Length -lt 2048 -and $ext -in @('.exe','.dll','.jar')) { $score += 6; [void]$reasons.Add('Very small executable/container') }
        }
    } catch { }

    if ($ext -eq '.jar') {
        $jarHits = Scan-JarLight $p $script:AllTokens
        if ($jarHits.Count -gt 0) {
            $score += 35 + [Math]::Min(20, $jarHits.Count * 5)
            [void]$reasons.Add(('JAR internal hits: ' + (($jarHits | Select-Object -First 8) -join ', ')))
        }
    } elseif ($ext -in @('.exe','.dll')) {
        if ($score -ge 25 -or (Test-InterestingPath $p)) {
            $head = Read-HeadText $p 1572864
            $headHits = Test-TextHasToken $head $script:AllTokens
            if ($headHits.Count -gt 0) {
                $score += 28 + [Math]::Min(20, $headHits.Count * 4)
                [void]$reasons.Add(('Binary string hits: ' + (($headHits | Select-Object -First 8) -join ', ')))
            }
            $sig = Get-SignatureSignal $p
            if ($sig -like 'UnsignedOrInvalid*' -or $sig -eq 'NoSignatureInfo') {
                $score += 8
                [void]$reasons.Add($sig)
            }
        }
    }

    if ($score -ge 38) {
        Add-Finding 'FILE' $p ([Math]::Min(100, $score)) @($reasons)
    }
}

function Scan-Processes {
    Write-Status 'STEP' 'Checking running processes and command lines...'
    try {
        $procs = Get-CimInstance Win32_Process
        foreach ($pr in $procs) {
            if (Test-Expired) { break }
            $text = (($pr.Name + ' ' + $pr.ExecutablePath + ' ' + $pr.CommandLine) -as [string])
            if ([string]::IsNullOrWhiteSpace($text)) { continue }
            $hitsInput = Test-TextHasToken $text $script:InputTokens
            $hitsAll = Test-TextHasToken $text $script:AllTokens
            $isMc = ($text.ToLowerInvariant().Contains('minecraft') -or $text.ToLowerInvariant().Contains('java') -or $text.ToLowerInvariant().Contains('.jar') -or $text.ToLowerInvariant().Contains('forge') -or $text.ToLowerInvariant().Contains('fabric'))
            if ($OnlyMinecraft -and -not $isMc) { continue }
            $score = 0
            $reasons = New-Object System.Collections.ArrayList
            if ($hitsInput.Count -gt 0) { $score += 70; [void]$reasons.Add(('Process matches your keywords: ' + ($hitsInput -join ', '))) }
            elseif ($hitsAll.Count -gt 0) { $score += 45; [void]$reasons.Add(('Process matches cheat dictionary: ' + ($hitsAll -join ', '))) }
            if ($isMc) { $score += 12; [void]$reasons.Add('Minecraft/Java related process') }
            if (($text.ToLowerInvariant()).Contains('-javaagent') -or ($text.ToLowerInvariant()).Contains('inject')) { $score += 28; [void]$reasons.Add('Java agent/injector indicator') }
            if ($score -ge 42) {
                $path = $pr.ExecutablePath
                if ([string]::IsNullOrWhiteSpace($path)) { $path = $pr.Name }
                Add-Finding 'PROCESS' $path ([Math]::Min(100, $score)) @($reasons) ('PID=' + $pr.ProcessId)
            }
        }
    } catch { Write-Status 'WARN' 'Process scan failed or blocked.' }
}

function Scan-LoadedModules {
    Write-Status 'STEP' 'Checking DLL modules in Java/Minecraft/suspicious processes...'
    try {
        $targets = Get-Process | Where-Object { $_.ProcessName -match 'java|javaw|minecraft|lunar|badlion|feather|tlauncher' }
        foreach ($p in $targets) {
            if (Test-Expired) { break }
            try {
                foreach ($m in $p.Modules) {
                    $mp = $m.FileName
                    if ([string]::IsNullOrWhiteSpace($mp)) { continue }
                    $hits = Test-TextHasToken $mp $script:AllTokens
                    $score = 0
                    $reasons = New-Object System.Collections.ArrayList
                    if ($hits.Count -gt 0) { $score += 70; [void]$reasons.Add(('Loaded DLL matches cheat keyword: ' + ($hits -join ', '))) }
                    if (($mp.ToLowerInvariant()).Contains('\appdata\') -or ($mp.ToLowerInvariant()).Contains('\temp\')) { $score += 15; [void]$reasons.Add('DLL loaded from user/temp location') }
                    if ($score -ge 45) { Add-Finding 'LOADED_DLL' $mp ([Math]::Min(100, $score)) @($reasons) ('PID=' + $p.Id + '; Process=' + $p.ProcessName) }
                }
            } catch { }
        }
    } catch { Write-Status 'WARN' 'Module scan needs administrator rights on some systems.' }
}

function Scan-Startup {
    Write-Status 'STEP' 'Checking autoruns and scheduled tasks...'
    $runKeys = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    )
    foreach ($rk in $runKeys) {
        try {
            if (-not (Test-Path $rk)) { continue }
            $props = Get-ItemProperty -Path $rk
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -like 'PS*') { continue }
                $val = [string]$p.Value
                $hits = Test-TextHasToken ($p.Name + ' ' + $val) $script:AllTokens
                if ($hits.Count -gt 0) {
                    Add-Finding 'AUTORUN' ($rk + '\' + $p.Name) 78 @('Autorun matches cheat keywords: ' + ($hits -join ', ')) $val
                }
            }
        } catch { }
    }

    try {
        $startupFolders = @(
            [Environment]::GetFolderPath('Startup'),
            (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup')
        )
        foreach ($sf in $startupFolders) {
            if (Test-Path $sf) {
                Get-ChildItem -Path $sf -Force -ErrorAction SilentlyContinue | ForEach-Object {
                    $hits = Test-TextHasToken $_.FullName $script:AllTokens
                    if ($hits.Count -gt 0) { Add-Finding 'STARTUP_FOLDER' $_.FullName 76 @('Startup item matches cheat keywords: ' + ($hits -join ', ')) }
                }
            }
        }
    } catch { }

    if (-not $Fast) {
        try {
            $tasks = Get-ScheduledTask
            foreach ($t in $tasks) {
                if (Test-Expired) { break }
                $text = ($t.TaskName + ' ' + $t.TaskPath + ' ' + (($t.Actions | Out-String) -as [string]))
                $hits = Test-TextHasToken $text $script:AllTokens
                if ($hits.Count -gt 0) { Add-Finding 'SCHEDULED_TASK' ($t.TaskPath + $t.TaskName) 80 @('Scheduled task matches cheat keywords: ' + ($hits -join ', ')) }
            }
        } catch { }
    }
}

function Scan-Prefetch {
    if ($Fast) { return }
    Write-Status 'STEP' 'Checking Prefetch names...'
    $pf = Join-Path $env:SystemRoot 'Prefetch'
    if (-not (Test-Path $pf)) { return }
    try {
        Get-ChildItem -Path $pf -Filter '*.pf' -Force -ErrorAction SilentlyContinue | ForEach-Object {
            $hits = Test-TextHasToken $_.Name $script:AllTokens
            if ($hits.Count -gt 0) { Add-Finding 'PREFETCH' $_.FullName 58 @('Executed program name matches cheat keyword: ' + ($hits -join ', ')) }
        }
    } catch { }
}

function Scan-Network {
    if ($Fast) { return }
    Write-Status 'STEP' 'Checking established network connections by process name...'
    try {
        $pidMap = @{}
        Get-CimInstance Win32_Process | ForEach-Object { $pidMap[[int]$_.ProcessId] = $_ }
        $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        foreach ($c in $conns) {
            if (Test-Expired) { break }
            $pid = [int]$c.OwningProcess
            if (-not $pidMap.ContainsKey($pid)) { continue }
            $p = $pidMap[$pid]
            $text = (($p.Name + ' ' + $p.ExecutablePath + ' ' + $p.CommandLine) -as [string])
            $hits = Test-TextHasToken $text $script:AllTokens
            if ($hits.Count -gt 0) {
                Add-Finding 'NETWORK' ($c.RemoteAddress + ':' + $c.RemotePort) 72 @('Network owner process matches cheat keyword: ' + ($hits -join ', ')) ('PID=' + $pid + '; Process=' + $p.Name)
            }
        }
    } catch { }
}

function Scan-Files {
    $roots = if ($OnlyMinecraft) { Get-MinecraftRoots } else { Get-SmartRoots }
    Write-Status 'STEP' ('Scan mode: ' + ($(if ($OnlyMinecraft) { 'MINECRAFT ONLY' } elseif ($Deep) { 'SMART-FULL / DEEP' } elseif ($Fast) { 'FAST' } else { 'SMART' })))
    Write-Status 'STEP' ('Roots: ' + (($roots | Select-Object -First 8) -join '; ') + $(if ($roots.Count -gt 8) { ' ...' } else { '' }))
    $files = Find-CandidateFiles $roots
    Write-Status 'OK' ('Candidate files found: ' + $files.Count)
    $i = 0
    foreach ($f in $files) {
        if (Test-Expired) { Write-Status 'WARN' 'Time limit reached. Showing best results found so far.'; break }
        $i++
        if (($i % 80) -eq 0) { Write-Status 'STEP' ('Analyzed ' + $i + ' / ' + $files.Count + ' candidates...') }
        Analyze-File $f
    }
}

function Show-Results {
    Write-Line '' Gray
    Write-Line '==================== AI-LIKE LOCAL VERDICT ====================' Red
    $all = @($script:Findings | Sort-Object -Property Score -Descending)
    $crit = @($all | Where-Object { $_.Score -ge 85 })
    $high = @($all | Where-Object { $_.Score -ge 65 -and $_.Score -lt 85 })
    $med = @($all | Where-Object { $_.Score -ge 42 -and $_.Score -lt 65 })

    $status = 'CLEAN'
    $color = [ConsoleColor]::Green
    if ($crit.Count -gt 0) { $status = 'CHEAT LIKELY'; $color = [ConsoleColor]::Red }
    elseif ($high.Count -gt 0) { $status = 'SUSPICIOUS'; $color = [ConsoleColor]::Yellow }
    elseif ($med.Count -gt 0) { $status = 'LOW/MEDIUM SIGNALS'; $color = [ConsoleColor]::Cyan }

    Write-Line ('  RESULT: ' + $status) $color
    Write-Line ('  Critical: ' + $crit.Count + ' | High: ' + $high.Count + ' | Medium: ' + $med.Count + ' | Total shown: ' + $all.Count) Gray
    Write-Line ('  Runtime: ' + ([int]((Get-Date) - $script:StartedAt).TotalSeconds) + ' sec') DarkGray
    Write-Line '' Gray

    if ($all.Count -eq 0) {
        Write-Line '  No strong cheat-related signals found.' Green
        Write-Line '  Note: no checker can prove that the system is 100% clean.' DarkGray
        return
    }

    $n = 0
    foreach ($x in ($all | Select-Object -First 35)) {
        $n++
        $c = [ConsoleColor]::Cyan
        if ($x.Score -ge 85) { $c = [ConsoleColor]::Red }
        elseif ($x.Score -ge 65) { $c = [ConsoleColor]::Yellow }
        Write-Line (('[' + $n + '] ' + $x.Severity + '  score=' + $x.Score + '  type=' + $x.Kind)) $c
        Write-Line ('    ' + $x.Path) Gray
        if (-not [string]::IsNullOrWhiteSpace($x.Extra)) { Write-Line ('    ' + $x.Extra) DarkGray }
        foreach ($r in ($x.Reasons | Select-Object -First 4)) { Write-Line ('    - ' + $r) DarkGray }
        Write-Line '' Gray
    }

    if ($OpenReport) {
        Write-Line '  -OpenReport is accepted for compatibility, but permanent reports are disabled.' Yellow
        Write-Line '  Results are displayed only in this console and temp files are removed on exit.' DarkGray
    }
}

function Main {
    New-WorkDir
    Show-Banner
    if ($OpenReport) { Write-Status 'WARN' 'OpenReport flag accepted, but report creation is disabled by request.' }
    if (-not (Test-Admin)) { Write-Status 'WARN' 'Run as Administrator for stronger DLL/module/prefetch checks.' }
    Initialize-Tokens
    Write-Status 'STEP' ('Time limit: ' + $MaxMinutes + ' min | Max candidates: ' + $MaxCandidates)
    Scan-Processes
    Scan-LoadedModules
    Scan-Startup
    Scan-Prefetch
    Scan-Network
    Scan-Files
    Show-Results
}

try {
    Main
} finally {
    Remove-WorkDir
}
