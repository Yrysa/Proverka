#Requires -Version 5.1
<#
 YRYS CHECKER POWER v7.0 STEALTH-HUNTER
 Smart local Windows/Minecraft cheat checker.
 - No permanent reports
 - Temp workspace deleted on exit
 - Compatible: -OnlyMinecraft, -OpenReport
 - Optional VirusTotal hash lookup, YARA, AMSI
 - Registry, Java agents, Minecraft logs, hosts, drivers, VM signals
 - Final verdict is always printed
#>

[CmdletBinding()]
param(
    [string]$Cheat = '',
    [switch]$NoPrompt,
    [switch]$Fast,
    [switch]$Deep,
    [switch]$OnlyMinecraft,
    [switch]$OpenReport,
    [switch]$SelfTest,
    [switch]$KeepTemp,
    [switch]$AllDrives,
    [switch]$VirusTotal,
    [string]$VirusTotalApiKey = '',
    [int]$VirusTotalMax = 25,
    [switch]$Yara,
    [string]$YaraExe = '',
    [string]$YaraRules = '',
    [switch]$Amsi,
    [switch]$Jcmd,
    [switch]$Drivers,
    [switch]$VMCheck,
    [int]$MaxMinutes = 12,
    [int]$MaxCandidates = 1200,
    [int]$MaxDepth = 18
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$script:Version = '7.0.0-STEALTH-HUNTER'
$script:StartedAt = Get-Date
$script:Deadline = (Get-Date).AddMinutes([Math]::Max(2, $MaxMinutes))
$script:TempRoot = Join-Path $env:TEMP ('YRYS_CHECKER_' + ([guid]::NewGuid().ToString('N')))
$script:Findings = New-Object System.Collections.ArrayList
$script:Seen = @{}
$script:Warnings = New-Object System.Collections.ArrayList
$script:InputTokens = @()
$script:AllTokens = @()
$script:WeakTokens = @('client','classic','summer','winter','dream','moon','tap','merge','empty','explicit','packet','new','old','test','beta','alpha','free','pro','lite','premium','launcher','loader')
$script:VTChecked = 0
$script:YaraReady = $false
$script:YaraRuleFile = ''
$script:AmsiReady = $false
$script:AmsiContext = [IntPtr]::Zero
$script:StrongJavaArgs = @('-javaagent','-agentpath','-xbootclasspath','-xbootclasspath/a','-djava.system.class.loader','-noverify')
$script:TrustedPublishers = @('Microsoft','Mojang','Oracle','Eclipse Adoptium','Adoptium','OpenJDK','Amazon','Azul','JetBrains','NVIDIA','AMD','Intel','Badlion','Lunar','Overwolf','Modrinth')
$script:CheatDomains = @('vape.gg','riseclient.com','intent.store','entropy.club','whiteout.lol','slinky.gg','drip.gg','ravenclient.com','liquidbounce.net','wurstclient.net','meteorclient.com','impactclient.net')
$script:SensitiveHosts = @('minecraft.net','mojang.com','sessionserver.mojang.com','authserver.mojang.com','api.mojang.com','microsoft.com','xboxlive.com','hypixel.net','lunarclient.com','badlion.net','optifine.net','curseforge.com','modrinth.com')
$script:InternalHashDB = @{}


function Write-Line {
    param(
        [string]$Text = '',
        [ConsoleColor]$Color = [ConsoleColor]::Gray,
        [ConsoleColor]$Back = [ConsoleColor]::Black
    )
    try {
        if ($Back -eq [ConsoleColor]::Black) { Write-Host $Text -ForegroundColor $Color }
        else { Write-Host $Text -ForegroundColor $Color -BackgroundColor $Back }
    } catch { Write-Host $Text }
}

function Write-Status {
    param([string]$Kind, [string]$Text)
    $k = $Kind.ToUpperInvariant()
    if ($k -eq 'STEP') { Write-Line ('  > ' + $Text) Cyan }
    elseif ($k -eq 'OK') { Write-Line ('  + ' + $Text) Green }
    elseif ($k -eq 'WARN') { Write-Line ('  ! ' + $Text) Yellow }
    elseif ($k -eq 'BAD') { Write-Line ('  X ' + $Text) Red }
    elseif ($k -eq 'HIT') { Write-Line ('  !!! ' + $Text) Red DarkGray }
    else { Write-Line ('    ' + $Text) Gray }
}

function Add-Warn {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return }
    [void]$script:Warnings.Add($Text)
    Write-Status 'WARN' $Text
}

function Invoke-Safe {
    param([string]$Name, [scriptblock]$Code)
    try { & $Code }
    catch {
        $msg = $_.Exception.Message
        if ([string]::IsNullOrWhiteSpace($msg)) { $msg = 'unknown error' }
        Add-Warn ($Name + ' skipped: ' + $msg)
    }
}

function New-WorkDir {
    try {
        if (-not (Test-Path -LiteralPath $script:TempRoot)) {
            New-Item -ItemType Directory -Path $script:TempRoot -Force | Out-Null
        }
    } catch { }
}

function Remove-WorkDir {
    if ($KeepTemp) { return }
    try {
        if (Test-Path -LiteralPath $script:TempRoot) {
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

function Test-Expired {
    try { return ((Get-Date) -gt $script:Deadline) } catch { return $false }
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
    Write-Line ('  POWER v' + $script:Version + ' | smart AI scan | VT/YARA/AMSI optional | temp only') DarkRed
    Write-Line ('  Temp workspace: ' + $script:TempRoot) DarkGray
    Write-Line '' DarkRed
}

function Run-SelfTest {
    try {
        if (-not $PSCommandPath) { Write-Line 'SelfTest: PSCommandPath is empty.' Yellow; return }
        $errs = $null
        [void][System.Management.Automation.PSParser]::Tokenize((Get-Content -LiteralPath $PSCommandPath -Raw), [ref]$errs)
        if ($errs -and $errs.Count -gt 0) {
            Write-Line 'SelfTest: parser errors found:' Red
            $errs | ForEach-Object { Write-Line ('  ' + $_.Message) Red }
        } else { Write-Line 'SelfTest: OK, parser found no syntax errors.' Green }
    } catch { Write-Line ('SelfTest failed: ' + $_.Exception.Message) Yellow }
}

function Split-Tokens {
    param([string]$Text)
    $items = New-Object System.Collections.ArrayList
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    $parts = $Text -split '[,;\r\n\t]+'
    foreach ($rawGroup in $parts) {
        foreach ($raw in ($rawGroup -split '\s+')) {
            $t = $raw.Trim().ToLowerInvariant()
            $t = $t.Trim('"', "'", ' ', '.', ':', '/', '\\', '[', ']', '(', ')')
            if ($t.Length -lt 3) { continue }
            if ($script:WeakTokens -contains $t) { continue }
            if (-not $items.Contains($t)) { [void]$items.Add($t) }
        }
    }
    return @($items.ToArray())
}

function Initialize-Tokens {
    $default = @(
        'vape','raven','rise','drip','entropy','whiteout','slinky','breeze','dream','liquidbounce','wurst','meteor','aristois','impact','future','rusherhack','lambda','kami','kamiblue','salhack','phobos','konas','pyro','gamesense','oyvey','3arthh4ck','earthhack','wurst+2','wurst+3','seppuku','catalyst','abyss','xulu','cosmos','trollhack','nullpoint','shoreline','boze','mio','prestige','alien','thunderhack','bleachhack','forgehax','inertia','sigma','flux','tenacity','moon','zeroday','exhibition','astolfo','novo','novoline','remix','huzuni','wolfram','nodus','weepcraft','jigsaw','skillclient','akrien','fdp','fdpclient','itami','dope','koid','iridium','crypt','incognito','antic','plow','akira','spark','skilled','karma','doomsday','horion','zephyr','toolbox','prax','ambrosial','badman','fate','borion','latite','onix','solstice','nitr0','surge','flare','pandora','resilience','saint','serenity','cyanide','reflex','metro','spicy','tomato','apollo','fusionx','envy','sensation','daemon','omikron','icarius','zeus','darklight','reliance','cyanite','nightx','lime','panda','augustus','winterware','thunderclient','clientbase',
        'killaura','aimassist','autoclicker','triggerbot','reach','velocity','scaffold','xray','esp','nofall','bhop','blink','timer','criticals','speedmine','speedhack','flyhack','antikb','fastplace','fastbreak','autopot','cheststealer','nametags','tracers','wallhack','aimbot',
        'injector','bypass','ghostclient','selfdestruct','clickgui','modmenu','javaagent','agentpath','classloader','mixin','accesswidener'
    )

    if (-not $NoPrompt -and [string]::IsNullOrWhiteSpace($Cheat)) {
        Write-Line 'Enter possible cheat names/keywords separated by comma.' Yellow
        Write-Line 'Example: vape, raven, rise, drip, entropy, whiteout, slinky' DarkGray
        $script:UserCheatInput = Read-Host 'Cheats'
    } else { $script:UserCheatInput = $Cheat }

    $script:InputTokens = Split-Tokens $script:UserCheatInput
    $merged = New-Object System.Collections.ArrayList
    foreach ($t in @($script:InputTokens + $default)) {
        $v = ([string]$t).ToLowerInvariant()
        if ($v.Length -ge 3 -and -not ($script:WeakTokens -contains $v) -and -not $merged.Contains($v)) {
            [void]$merged.Add($v)
        }
    }
    $script:AllTokens = @($merged.ToArray())
    if ($script:InputTokens.Count -gt 0) {
        $shown = @($script:InputTokens | Select-Object -First 28)
        $suffix = ''
        if ($script:InputTokens.Count -gt 28) { $suffix = ' ...' }
        Write-Status 'OK' ('Priority keywords loaded: ' + ($shown -join ', ') + $suffix)
    } else { Write-Status 'WARN' 'No custom keywords entered. Built-in dictionary will be used.' }
}

function Normalize-PathSafe {
    param([string]$Path)
    try { return [System.IO.Path]::GetFullPath($Path) } catch { return $Path }
}

function Test-TextHasToken {
    param([string]$Text, [string[]]$Tokens)
    $hits = New-Object System.Collections.ArrayList
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    if (-not $Tokens -or $Tokens.Count -eq 0) { return @() }
    $lower = $Text.ToLowerInvariant()
    foreach ($t in $Tokens) {
        if ([string]::IsNullOrWhiteSpace($t)) { continue }
        if ($lower.Contains($t.ToLowerInvariant())) { if (-not $hits.Contains($t)) { [void]$hits.Add($t) } }
    }
    return @($hits.ToArray())
}


function Get-FileSha256Safe {
    param([string]$Path)
    try { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToUpperInvariant() } catch { return '' }
}

function Resolve-ToolPath {
    param([string]$NameOrPath)
    if ([string]::IsNullOrWhiteSpace($NameOrPath)) { return '' }
    if (Test-Path -LiteralPath $NameOrPath) { return (Normalize-PathSafe $NameOrPath) }
    try {
        $cmd = Get-Command $NameOrPath -ErrorAction SilentlyContinue
        if ($cmd -and $cmd.Source) { return $cmd.Source }
    } catch { }
    return ''
}

function Get-SignatureDetails {
    param([string]$Path)
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction SilentlyContinue
        if ($null -eq $sig) { return [pscustomobject]@{ Status='NoSignatureInfo'; Subject=''; Trusted=$false } }
        $subject = ''
        try { $subject = [string]$sig.SignerCertificate.Subject } catch { $subject = '' }
        $trusted = $false
        if ($sig.Status -eq 'Valid') {
            foreach ($p in $script:TrustedPublishers) { if ($subject -like ('*' + $p + '*')) { $trusted = $true; break } }
        }
        return [pscustomobject]@{ Status=([string]$sig.Status); Subject=$subject; Trusted=$trusted }
    } catch { return [pscustomobject]@{ Status='NoSignatureInfo'; Subject=''; Trusted=$false } }
}

function Initialize-YaraEngine {
    if (-not $Yara) { return }
    $exe = Resolve-ToolPath $YaraExe
    if ([string]::IsNullOrWhiteSpace($exe)) { $exe = Resolve-ToolPath 'yara64.exe' }
    if ([string]::IsNullOrWhiteSpace($exe)) { $exe = Resolve-ToolPath 'yara.exe' }
    if ([string]::IsNullOrWhiteSpace($exe)) { Add-Warn 'YARA requested but yara.exe/yara64.exe was not found. Use -YaraExe C:\path\yara64.exe'; return }
    $script:YaraExeResolved = $exe
    if (-not [string]::IsNullOrWhiteSpace($YaraRules) -and (Test-Path -LiteralPath $YaraRules)) {
        $script:YaraRuleFile = Normalize-PathSafe $YaraRules
    } else {
        $script:YaraRuleFile = Join-Path $script:TempRoot 'yrys_cheat_rules.yar'
        $rule = @'
rule YRYS_Minecraft_Cheat_Static_Strings
{
    meta:
        description = "YRYS local Minecraft cheat strings"
    strings:
        $a1 = "KillAura" nocase
        $a2 = "AimAssist" nocase
        $a3 = "AutoClicker" nocase
        $a4 = "TriggerBot" nocase
        $a5 = "Reach" nocase
        $a6 = "Velocity" nocase
        $a7 = "Scaffold" nocase
        $a8 = "ChestStealer" nocase
        $a9 = "ClickGUI" nocase
        $a10 = "SelfDestruct" nocase
        $b1 = "vape" nocase
        $b2 = "raven" nocase
        $b3 = "rise" nocase
        $b4 = "liquidbounce" nocase
        $b5 = "wurst" nocase
        $b6 = "meteor" nocase
    condition:
        3 of ($a*) or 2 of ($b*) or (1 of ($b*) and 1 of ($a*))
}
'@
        Set-Content -LiteralPath $script:YaraRuleFile -Value $rule -Encoding ASCII -Force
    }
    $script:YaraReady = $true
    Write-Status 'OK' ('YARA enabled: ' + $script:YaraExeResolved)
}

function Invoke-YaraScanSafe {
    param([string]$Path)
    if (-not $script:YaraReady) { return @() }
    try {
        $out = & $script:YaraExeResolved $script:YaraRuleFile $Path 2>$null
        if ($LASTEXITCODE -eq 0 -and $out) { return @($out) }
    } catch { }
    return @()
}

function Initialize-AmsiEngine {
    if (-not $Amsi) { return }
    try {
        if (-not ('YrysAmsi' -as [type])) {
            $src = @"
using System;
using System.Runtime.InteropServices;
public static class YrysAmsi {
    [DllImport("amsi.dll", CharSet=CharSet.Unicode)] public static extern int AmsiInitialize(string appName, out IntPtr amsiContext);
    [DllImport("amsi.dll")] public static extern void AmsiUninitialize(IntPtr amsiContext);
    [DllImport("amsi.dll", CharSet=CharSet.Unicode)] public static extern int AmsiScanBuffer(IntPtr amsiContext, byte[] buffer, uint length, string contentName, IntPtr session, out int result);
}
"@
            Add-Type -TypeDefinition $src -ErrorAction Stop | Out-Null
        }
        $ctx = [IntPtr]::Zero
        $hr = [YrysAmsi]::AmsiInitialize('YRYS_CHECKER', [ref]$ctx)
        if ($hr -eq 0 -and $ctx -ne [IntPtr]::Zero) {
            $script:AmsiContext = $ctx
            $script:AmsiReady = $true
            Write-Status 'OK' 'AMSI enabled for local content scanning.'
        } else { Add-Warn ('AMSI init failed: HRESULT=' + $hr) }
    } catch { Add-Warn ('AMSI requested but initialization failed: ' + $_.Exception.Message) }
}

function Invoke-AmsiFileSafe {
    param([string]$Path, [int]$MaxBytes = 2097152)
    if (-not $script:AmsiReady) { return 'NOT_USED' }
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $n = [int][Math]::Min([int64]$MaxBytes, [int64]$fs.Length)
            if ($n -le 0) { return 'EMPTY' }
            $buf = New-Object byte[] $n
            [void]$fs.Read($buf, 0, $n)
            $result = 0
            [void][YrysAmsi]::AmsiScanBuffer($script:AmsiContext, $buf, [uint32]$n, $Path, [IntPtr]::Zero, [ref]$result)
            if ($result -ge 32768) { return 'DETECTED' }
            if ($result -ge 16384) { return 'SUSPICIOUS' }
            return 'CLEAN'
        } finally { $fs.Close() }
    } catch { return 'ERROR' }
}

function Invoke-VirusTotalHashLookup {
    param([string]$Hash, [string]$Path)
    if (-not $VirusTotal) { return $null }
    if ([string]::IsNullOrWhiteSpace($VirusTotalApiKey)) { return $null }
    if ([string]::IsNullOrWhiteSpace($Hash)) { return $null }
    if ($script:VTChecked -ge $VirusTotalMax) { return $null }
    try {
        $script:VTChecked++
        $uri = 'https://www.virustotal.com/api/v3/files/' + $Hash
        $headers = @{ 'x-apikey' = $VirusTotalApiKey; 'accept' = 'application/json' }
        $r = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -UseBasicParsing -TimeoutSec 20 -ErrorAction Stop
        $stats = $r.data.attributes.last_analysis_stats
        $mal = 0; $sus = 0
        try { $mal = [int]$stats.malicious } catch { $mal = 0 }
        try { $sus = [int]$stats.suspicious } catch { $sus = 0 }
        return [pscustomobject]@{ Malicious=$mal; Suspicious=$sus; Hash=$Hash }
    } catch {
        if ($_.Exception.Message -notmatch '404') { Add-Warn ('VirusTotal lookup skipped/failed for one hash: ' + $_.Exception.Message) }
        return $null
    }
}

function Extract-StringsLite {
    param([string]$Path, [int]$MaxBytes = 2097152)
    try {
        $text = Read-HeadText $Path $MaxBytes
        $u = ''
        try {
            $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            try {
                $n = [int][Math]::Min([int64]$MaxBytes, [int64]$fs.Length)
                $buf = New-Object byte[] $n
                [void]$fs.Read($buf, 0, $n)
                $u = [System.Text.Encoding]::Unicode.GetString($buf)
            } finally { $fs.Close() }
        } catch { }
        return ($text + "`n" + $u)
    } catch { return '' }
}

function New-FindingObject {
    param([string]$Kind, [string]$Path, [int]$Score, [string[]]$Reasons, [string]$Extra)
    if ([string]::IsNullOrWhiteSpace($Path)) { $Path = '<unknown>' }
    if ($Score -lt 1) { $Score = 1 }
    if ($Score -gt 100) { $Score = 100 }
    $sev = 'LOW'
    if ($Score -ge 85) { $sev = 'CRITICAL' }
    elseif ($Score -ge 65) { $sev = 'HIGH' }
    elseif ($Score -ge 42) { $sev = 'MEDIUM' }
    return [pscustomobject]@{ Kind=$Kind; Path=$Path; Score=$Score; Severity=$sev; Reasons=@($Reasons); Extra=$Extra }
}

function Add-Finding {
    param([string]$Kind, [string]$Path, [int]$Score, [string[]]$Reasons, [string]$Extra = '')
    if ($Score -lt 38) { return }
    if ([string]::IsNullOrWhiteSpace($Path)) { $Path = '<unknown>' }
    $key = ($Kind + '|' + $Path).ToLowerInvariant()
    if ($script:Seen.ContainsKey($key)) {
        $old = $script:Seen[$key]
        if ($Score -gt $old.Score) {
            $old.Score = [Math]::Min(100, $Score)
            if ($old.Score -ge 85) { $old.Severity = 'CRITICAL' }
            elseif ($old.Score -ge 65) { $old.Severity = 'HIGH' }
            elseif ($old.Score -ge 42) { $old.Severity = 'MEDIUM' }
        }
        foreach ($r in $Reasons) { if ($old.Reasons -notcontains $r) { $old.Reasons += $r } }
        if ($Extra -and $old.Extra -notlike ('*' + $Extra + '*')) { $old.Extra = ($old.Extra + ' ' + $Extra).Trim() }
        return
    }
    $obj = New-FindingObject $Kind $Path $Score $Reasons $Extra
    [void]$script:Findings.Add($obj)
    $script:Seen[$key] = $obj
}

function Add-RootIfExists {
    param([System.Collections.ArrayList]$List, [string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    try {
        if ((Test-Path -LiteralPath $Path) -and -not $List.Contains((Normalize-PathSafe $Path))) { [void]$List.Add((Normalize-PathSafe $Path)) }
    } catch { }
}

function Get-MinecraftRootsOnly {
    $roots = New-Object System.Collections.ArrayList
    $candidates = @(
        (Join-Path $env:APPDATA '.minecraft'),
        (Join-Path $env:APPDATA '.tlauncher'),
        (Join-Path $env:APPDATA '.feather'),
        (Join-Path $env:APPDATA '.lunarclient'),
        (Join-Path $env:APPDATA '.badlion'),
        (Join-Path $env:APPDATA 'PrismLauncher'),
        (Join-Path $env:APPDATA 'PolyMC'),
        (Join-Path $env:APPDATA 'MultiMC'),
        (Join-Path $env:APPDATA 'GDLauncher'),
        (Join-Path $env:APPDATA 'ATLauncher'),
        (Join-Path $env:APPDATA 'ModrinthApp'),
        (Join-Path $env:LOCALAPPDATA 'Packages'),
        (Join-Path $env:LOCALAPPDATA 'Programs'),
        (Join-Path $env:LOCALAPPDATA 'Overwolf'),
        (Join-Path $env:USERPROFILE 'Downloads'),
        (Join-Path $env:USERPROFILE 'Desktop'),
        (Join-Path $env:USERPROFILE 'Documents')
    )
    foreach ($r in $candidates) { Add-RootIfExists $roots $r }
    return @($roots.ToArray())
}

function Get-CommonRoots {
    $roots = New-Object System.Collections.ArrayList
    foreach ($r in (Get-MinecraftRootsOnly)) { Add-RootIfExists $roots $r }
    $candidates = @($env:TEMP, $env:APPDATA, $env:LOCALAPPDATA, $env:ProgramData)
    foreach ($r in $candidates) { Add-RootIfExists $roots $r }
    return @($roots.ToArray())
}

function Get-DeepRoots {
    $roots = New-Object System.Collections.ArrayList
    foreach ($r in (Get-CommonRoots)) { Add-RootIfExists $roots $r }
    $more = @(${env:ProgramFiles}, ${env:ProgramFiles(x86)}, (Join-Path $env:USERPROFILE 'AppData'))
    foreach ($r in $more) { Add-RootIfExists $roots $r }
    if ($AllDrives -or $Deep) {
        try {
            $drives = Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3'
            if (-not $drives) { $drives = Get-WmiObject Win32_LogicalDisk -Filter 'DriveType=3' }
            foreach ($d in $drives) { Add-RootIfExists $roots ($d.DeviceID + '\') }
        } catch { }
    }
    return @($roots.ToArray())
}

function Test-SkipDir {
    param([string]$Dir, [int]$Depth)
    if ([string]::IsNullOrWhiteSpace($Dir)) { return $true }
    if ($Depth -gt $MaxDepth -and -not $Deep) { return $true }
    $l = $Dir.ToLowerInvariant()
    $bad = @(
        '\$recycle.bin','\system volume information','\windows\winsxs','\windows\installer',
        '\windows\servicing','\windows\softwaredistribution','\programdata\microsoft\windows defender',
        '\appdata\local\google\chrome\user data','\appdata\local\microsoft\edge\user data',
        '\appdata\local\packages\microsoft.microsoftedge','\node_modules','\.git','\cache','\caches'
    )
    foreach ($b in $bad) { if ($l.Contains($b)) { return $true } }
    return $false
}

function Test-InterestingPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $l = $Path.ToLowerInvariant()
    if ($l.Contains('\.minecraft\') -or $l.Contains('\mods\') -or $l.Contains('\versions\') -or $l.Contains('\libraries\')) { return $true }
    if ($l.Contains('\.tlauncher\') -or $l.Contains('\.feather\') -or $l.Contains('\.lunarclient\') -or $l.Contains('\.badlion\') -or $l.Contains('\prismlauncher\') -or $l.Contains('\polymc\') -or $l.Contains('\multimc\') -or $l.Contains('\gdlauncher\') -or $l.Contains('\atlauncher\') -or $l.Contains('\modrinthapp\') -or $l.Contains('\overwolf\')) { return $true }
    if ($l.Contains('\appdata\') -or $l.Contains('\temp\') -or $l.Contains('\downloads\') -or $l.Contains('\desktop\')) { return $true }
    return $false
}

function Find-CandidateFiles {
    param([string[]]$Roots)
    $exts = @('.jar','.exe','.dll')
    $out = New-Object System.Collections.ArrayList
    $stack = New-Object System.Collections.Stack
    foreach ($r in $Roots) { if ($r -and (Test-Path -LiteralPath $r)) { $stack.Push([pscustomobject]@{Path=(Normalize-PathSafe $r); Depth=0}) } }

    $dirsVisited = 0
    while ($stack.Count -gt 0) {
        if (Test-Expired) { Add-Warn 'Time limit reached during directory walk.'; break }
        if ($out.Count -ge $MaxCandidates) { Add-Warn ('Candidate limit reached: ' + $MaxCandidates); break }
        $node = $stack.Pop()
        $dir = [string]$node.Path
        $depth = [int]$node.Depth
        if (Test-SkipDir $dir $depth) { continue }
        $dirsVisited++
        if (($dirsVisited % 700) -eq 0) { Write-Status 'STEP' ('Walking folders: ' + $dirsVisited + ' | candidates: ' + $out.Count) }

        $files = @()
        try { $files = [System.IO.Directory]::GetFiles($dir) } catch { $files = @() }
        foreach ($f in $files) {
            if (Test-Expired) { break }
            if ($out.Count -ge $MaxCandidates) { break }
            $ext = ''
            try { $ext = [System.IO.Path]::GetExtension($f).ToLowerInvariant() } catch { continue }
            if ($exts -notcontains $ext) { continue }
            $pathHits = Test-TextHasToken $f $script:AllTokens
            $interesting = Test-InterestingPath $f
            if ($OnlyMinecraft) {
                if (-not ($interesting -or $ext -eq '.jar')) { continue }
            }
            if ($pathHits.Count -gt 0 -or $interesting -or ($Deep -and ($ext -eq '.jar')) -or ($Deep -and $pathHits.Count -gt 0)) {
                [void]$out.Add($f)
            }
        }

        if (-not (Test-Expired) -and $out.Count -lt $MaxCandidates) {
            $dirs = @()
            try { $dirs = [System.IO.Directory]::GetDirectories($dir) } catch { $dirs = @() }
            foreach ($d in $dirs) { if (-not (Test-SkipDir $d ($depth + 1))) { $stack.Push([pscustomobject]@{Path=$d; Depth=($depth + 1)}) } }
        }
    }
    $unique = @($out.ToArray() | Select-Object -Unique)
    Write-Status 'OK' ('Folders walked: ' + $dirsVisited)
    return $unique
}

function Read-HeadText {
    param([string]$Path, [int]$MaxBytes = 1048576)
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $n64 = [Math]::Min([int64]$MaxBytes, [int64]$fs.Length)
            $n = [int]$n64
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
                if ($checked -ge 90) { break }
                if (Test-Expired) { break }
                $nameHits = Test-TextHasToken $e.FullName $Tokens
                foreach ($h in $nameHits) { if (-not $hits.Contains($h)) { [void]$hits.Add($h) } }
                $en = $e.FullName.ToLowerInvariant()
                $okFile = ($en.EndsWith('.txt') -or $en.EndsWith('.json') -or $en.EndsWith('.cfg') -or $en.EndsWith('.properties') -or $en.EndsWith('.mf') -or $en.EndsWith('.yml') -or $en.EndsWith('.yaml') -or $en.EndsWith('.class') -or $en.Contains('meta-inf'))
                if ($okFile -and $e.Length -gt 0 -and $e.Length -le 262144) {
                    try {
                        $stream = $e.Open()
                        try {
                            $n = [int][Math]::Min([int64]262144, [int64]$e.Length)
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
    return @($hits.ToArray())
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
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return }
        $score = 0
        $reasons = New-Object System.Collections.ArrayList
        $p = Normalize-PathSafe $Path
        $ext = [System.IO.Path]::GetExtension($p).ToLowerInvariant()
        $lower = $p.ToLowerInvariant()

        $inputHits = Test-TextHasToken $p $script:InputTokens
        $allHits = Test-TextHasToken $p $script:AllTokens
        if ($inputHits.Count -gt 0) { $score += 55 + [Math]::Min(20, $inputHits.Count * 5); [void]$reasons.Add('Matches your keywords: ' + ($inputHits -join ', ')) }
        elseif ($allHits.Count -gt 0) { $score += 32 + [Math]::Min(15, $allHits.Count * 4); [void]$reasons.Add('Matches cheat dictionary: ' + ($allHits -join ', ')) }

        if ($ext -eq '.jar') { $score += 8; [void]$reasons.Add('JAR file') }
        elseif ($ext -eq '.dll') { $score += 6; [void]$reasons.Add('DLL file') }
        elseif ($ext -eq '.exe') { $score += 6; [void]$reasons.Add('EXE file') }

        if ($lower.Contains('\.minecraft\') -or $lower.Contains('\mods\') -or $lower.Contains('\versions\') -or $lower.Contains('\libraries\')) { $score += 18; [void]$reasons.Add('Minecraft-related path') }
        if ($lower.Contains('\appdata\') -or $lower.Contains('\temp\') -or $lower.Contains('\downloads\') -or $lower.Contains('\desktop\')) { $score += 10; [void]$reasons.Add('User/temp/downloads location') }
        if ($lower.Contains('inject') -or $lower.Contains('bypass') -or $lower.Contains('selfdestruct') -or $lower.Contains('ghost') -or $lower.Contains('clicker')) { $score += 22; [void]$reasons.Add('Injector/bypass/ghost/clicker naming') }

        try {
            $fi = Get-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
            if ($fi) {
                if (($fi.Attributes -band [IO.FileAttributes]::Hidden) -ne 0) { $score += 7; [void]$reasons.Add('Hidden file') }
                if ($fi.LastWriteTime -gt (Get-Date).AddDays(-14)) { $score += 4; [void]$reasons.Add('Recently modified') }
                if ($fi.Length -lt 4096 -and ($ext -eq '.exe' -or $ext -eq '.dll' -or $ext -eq '.jar')) { $score += 5; [void]$reasons.Add('Very small executable/container') }
            }
        } catch { }

        if ($ext -eq '.jar') {
            $jarHits = Scan-JarLight $p $script:AllTokens
            if ($jarHits.Count -gt 0) { $score += 34 + [Math]::Min(20, $jarHits.Count * 4); [void]$reasons.Add('JAR internal hits: ' + (($jarHits | Select-Object -First 8) -join ', ')) }
        } elseif ($ext -eq '.exe' -or $ext -eq '.dll') {
            if ($score -ge 22 -or (Test-InterestingPath $p)) {
                $head = Extract-StringsLite $p 1048576
                $headHits = Test-TextHasToken $head $script:AllTokens
                if ($headHits.Count -gt 0) { $score += 24 + [Math]::Min(18, $headHits.Count * 4); [void]$reasons.Add('Binary string hits: ' + (($headHits | Select-Object -First 8) -join ', ')) }
                $sig = Get-SignatureDetails $p
                if ($sig.Trusted) { $score -= 18; [void]$reasons.Add('Trusted signature: ' + $sig.Subject) }
                elseif ($sig.Status -ne 'Valid') { $score += 11; [void]$reasons.Add('Signature: ' + $sig.Status) }
                else { $score += 3; [void]$reasons.Add('Signed but publisher not in trusted baseline') }
            }
        }

        if ($script:YaraReady -and ($score -ge 22 -or (Test-InterestingPath $p))) {
            $ym = Invoke-YaraScanSafe $p
            if ($ym.Count -gt 0) { $score += 55; [void]$reasons.Add('YARA match: ' + (($ym | Select-Object -First 3) -join ' | ')) }
        }

        if ($script:AmsiReady -and ($score -ge 30 -or $ext -eq '.jar')) {
            $amsiResult = Invoke-AmsiFileSafe $p 2097152
            if ($amsiResult -eq 'DETECTED') { $score += 80; [void]$reasons.Add('AMSI detected malware-like content') }
            elseif ($amsiResult -eq 'SUSPICIOUS') { $score += 35; [void]$reasons.Add('AMSI suspicious result') }
        }

        $hash = ''
        if ($score -ge 38 -or $script:YaraReady -or $VirusTotal) { $hash = Get-FileSha256Safe $p }
        if ($hash -and $script:InternalHashDB.ContainsKey($hash)) { $score += 90; [void]$reasons.Add('Internal known hash DB match') }
        if ($VirusTotal -and $VirusTotalApiKey -and $score -ge 38) {
            $vt = Invoke-VirusTotalHashLookup $hash $p
            if ($vt) {
                if ($vt.Malicious -gt 0 -or $vt.Suspicious -gt 0) {
                    $score += [Math]::Min(60, ($vt.Malicious * 12) + ($vt.Suspicious * 6))
                    [void]$reasons.Add('VirusTotal hash result: malicious=' + $vt.Malicious + ', suspicious=' + $vt.Suspicious)
                } else { [void]$reasons.Add('VirusTotal hash result: 0 detections') }
            }
        }

        Add-Finding 'FILE' $p ([Math]::Max(1, [Math]::Min(100, $score))) @($reasons) $(if ($hash) { 'SHA256=' + $hash } else { '' })
    } catch { }
}

function Get-ProcessListSafe {
    $list = @()
    try { $list = Get-CimInstance Win32_Process }
    catch { try { $list = Get-WmiObject Win32_Process } catch { $list = @() } }
    return @($list)
}

function Scan-Processes {
    Write-Status 'STEP' 'Checking running processes and command lines...'
    $procs = Get-ProcessListSafe
    if (-not $procs -or $procs.Count -eq 0) { Add-Warn 'Process WMI/CIM scan failed or blocked.'; return }
    foreach ($pr in $procs) {
        if (Test-Expired) { break }
        try {
            $text = (($pr.Name + ' ' + $pr.ExecutablePath + ' ' + $pr.CommandLine) -as [string])
            if ([string]::IsNullOrWhiteSpace($text)) { continue }
            $lower = $text.ToLowerInvariant()
            $isMc = ($lower.Contains('minecraft') -or $lower.Contains('java') -or $lower.Contains('.jar') -or $lower.Contains('forge') -or $lower.Contains('fabric') -or $lower.Contains('lunar') -or $lower.Contains('badlion') -or $lower.Contains('feather'))
            if ($OnlyMinecraft -and -not $isMc) { continue }
            $hitsInput = Test-TextHasToken $text $script:InputTokens
            $hitsAll = Test-TextHasToken $text $script:AllTokens
            $score = 0
            $reasons = New-Object System.Collections.ArrayList
            if ($hitsInput.Count -gt 0) { $score += 70; [void]$reasons.Add('Process matches your keywords: ' + ($hitsInput -join ', ')) }
            elseif ($hitsAll.Count -gt 0) { $score += 45; [void]$reasons.Add('Process matches cheat dictionary: ' + ($hitsAll -join ', ')) }
            if ($isMc) { $score += 12; [void]$reasons.Add('Minecraft/Java related process') }
            foreach ($arg in $script:StrongJavaArgs) { if ($lower.Contains($arg)) { $score += 26; [void]$reasons.Add('Suspicious Java/JVM arg: ' + $arg) } }
            if ($lower.Contains('inject')) { $score += 22; [void]$reasons.Add('Injector indicator') }
            $path = $pr.ExecutablePath
            if ([string]::IsNullOrWhiteSpace($path)) { $path = $pr.Name }
            Add-Finding 'PROCESS' $path ([Math]::Min(100, $score)) @($reasons) ('PID=' + $pr.ProcessId)
        } catch { }
    }
}

function Scan-LoadedModules {
    Write-Status 'STEP' 'Checking loaded DLL modules in Java/Minecraft/suspicious processes...'
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
                    if ($hits.Count -gt 0) { $score += 75; [void]$reasons.Add('Loaded DLL matches cheat keyword: ' + ($hits -join ', ')) }
                    if ($mp.ToLowerInvariant().Contains('\appdata\') -or $mp.ToLowerInvariant().Contains('\temp\')) { $score += 18; [void]$reasons.Add('DLL loaded from user/temp location') }
                    Add-Finding 'LOADED_DLL' $mp ([Math]::Min(100, $score)) @($reasons) ('PID=' + $p.Id + '; Process=' + $p.ProcessName)
                }
            } catch { }
        }
    } catch { Add-Warn 'Module scan needs administrator rights on some systems.' }
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
                if ($hits.Count -gt 0) { Add-Finding 'AUTORUN' ($rk + '\' + $p.Name) 78 @('Autorun matches cheat keywords: ' + ($hits -join ', ')) $val }
            }
        } catch { }
    }
    if (-not $Fast) {
        try {
            $tasks = Get-ScheduledTask
            foreach ($t in $tasks) {
                if (Test-Expired) { break }
                $text = ($t.TaskName + ' ' + $t.TaskPath + ' ' + (($t.Actions | Out-String) -as [string]))
                $hits = Test-TextHasToken $text $script:AllTokens
                if ($hits.Count -gt 0) { Add-Finding 'SCHEDULED_TASK' ($t.TaskPath + $t.TaskName) 80 @('Scheduled task matches cheat keywords: ' + ($hits -join ', ')) '' }
            }
        } catch { }
    }
}

function Scan-Prefetch {
    if ($Fast) { return }
    Write-Status 'STEP' 'Checking Prefetch names and embedded strings...'
    $pf = Join-Path $env:SystemRoot 'Prefetch'
    if (-not (Test-Path -LiteralPath $pf)) { return }
    try {
        Get-ChildItem -Path $pf -Filter '*.pf' -Force -ErrorAction SilentlyContinue | ForEach-Object {
            if (Test-Expired) { return }
            $score = 0
            $reasons = New-Object System.Collections.ArrayList
            $hits = Test-TextHasToken $_.Name $script:AllTokens
            if ($hits.Count -gt 0) { $score += 58; [void]$reasons.Add('Executed program name matches cheat keyword: ' + ($hits -join ', ')) }
            if (-not $Fast) {
                $strings = Extract-StringsLite $_.FullName 262144
                $innerHits = Test-TextHasToken $strings $script:AllTokens
                if ($innerHits.Count -gt 0) { $score += 18; [void]$reasons.Add('Prefetch embedded path/string hits: ' + (($innerHits | Select-Object -First 6) -join ', ')) }
            }
            Add-Finding 'PREFETCH' $_.FullName $score @($reasons) ''
        }
    } catch { }
}

function Scan-Network {
    if ($Fast) { return }
    Write-Status 'STEP' 'Checking established network connections by process name...'
    try {
        $pidMap = @{}
        foreach ($p in (Get-ProcessListSafe)) { try { $pidMap[[int]$p.ProcessId] = $p } catch { } }
        $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        foreach ($c in $conns) {
            if (Test-Expired) { break }
            $pid = [int]$c.OwningProcess
            if (-not $pidMap.ContainsKey($pid)) { continue }
            $p = $pidMap[$pid]
            $text = (($p.Name + ' ' + $p.ExecutablePath + ' ' + $p.CommandLine) -as [string])
            $hits = Test-TextHasToken $text $script:AllTokens
            if ($hits.Count -gt 0) { Add-Finding 'NETWORK' ($c.RemoteAddress + ':' + $c.RemotePort) 72 @('Network owner process matches cheat keyword: ' + ($hits -join ', ')) ('PID=' + $pid + '; Process=' + $p.Name) }
        }
    } catch { }
}


function Scan-RegistryDeep {
    if ($Fast) { return }
    Write-Status 'STEP' 'Checking deep registry persistence and injection keys...'
    $keys = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows',
        'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
        'HKCU:\Software\Classes\ms-settings\Shell\Open\command',
        'HKCU:\Software\Classes\exefile\shell\open\command'
    )
    foreach ($rk in $keys) {
        if (Test-Expired) { break }
        try {
            if (-not (Test-Path $rk)) { continue }
            $items = @()
            if ($rk -like '*Image File Execution Options') { $items = Get-ChildItem -Path $rk -ErrorAction SilentlyContinue } else { $items = @(Get-Item -Path $rk -ErrorAction SilentlyContinue) }
            foreach ($it in $items) {
                $props = Get-ItemProperty -Path $it.PSPath -ErrorAction SilentlyContinue
                foreach ($p in $props.PSObject.Properties) {
                    if ($p.Name -like 'PS*') { continue }
                    $val = [string]$p.Value
                    $text = $it.PSPath + ' ' + $p.Name + ' ' + $val
                    $hits = Test-TextHasToken $text $script:AllTokens
                    $score = 0
                    $reasons = New-Object System.Collections.ArrayList
                    if ($hits.Count -gt 0) { $score += 78; [void]$reasons.Add('Registry value matches cheat keywords: ' + ($hits -join ', ')) }
                    if ($p.Name -match 'AppInit_DLLs|Debugger|LoadAppInit_DLLs|Shell|Userinit' -and -not [string]::IsNullOrWhiteSpace($val)) { $score += 32; [void]$reasons.Add('Sensitive persistence/injection value: ' + $p.Name) }
                    if ($val.ToLowerInvariant().Contains('\appdata\') -or $val.ToLowerInvariant().Contains('\temp\')) { $score += 12; [void]$reasons.Add('Registry path points to user/temp location') }
                    Add-Finding 'REGISTRY' ($it.PSPath + '\' + $p.Name) $score @($reasons) $val
                }
            }
        } catch { }
    }
}

function Scan-UninstallPrograms {
    if ($Fast) { return }
    Write-Status 'STEP' 'Checking installed programs for clickers/injectors/cheat tools...'
    $keys = @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
    foreach ($k in $keys) {
        try {
            Get-ItemProperty $k -ErrorAction SilentlyContinue | ForEach-Object {
                $text = ([string]$_.DisplayName + ' ' + [string]$_.Publisher + ' ' + [string]$_.InstallLocation + ' ' + [string]$_.DisplayIcon)
                $hits = Test-TextHasToken $text $script:AllTokens
                if ($hits.Count -gt 0) { Add-Finding 'INSTALLED_APP' ([string]$_.DisplayName) 62 @('Installed app matches cheat/clicker keyword: ' + ($hits -join ', ')) $text }
            }
        } catch { }
    }
}

function Scan-HostsFile {
    if ($Fast) { return }
    Write-Status 'STEP' 'Checking hosts file redirects...'
    $hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    if (-not (Test-Path -LiteralPath $hosts)) { return }
    try {
        $lines = Get-Content -LiteralPath $hosts -ErrorAction SilentlyContinue
        $i = 0
        foreach ($line in $lines) {
            $i++
            $t = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($t) -or $t.StartsWith('#')) { continue }
            $score = 0
            $reasons = New-Object System.Collections.ArrayList
            foreach ($d in $script:SensitiveHosts) { if ($t.ToLowerInvariant().Contains($d)) { $score += 62; [void]$reasons.Add('Redirects sensitive Minecraft/auth domain: ' + $d) } }
            $hits = Test-TextHasToken $t $script:AllTokens
            if ($hits.Count -gt 0) { $score += 45; [void]$reasons.Add('Hosts line matches cheat keyword: ' + ($hits -join ', ')) }
            if ($t -match '^\s*(127\.0\.0\.1|0\.0\.0\.0|::1)\s+') { $score += 8; [void]$reasons.Add('Localhost/null redirect') }
            Add-Finding 'HOSTS' ($hosts + ':line ' + $i) $score @($reasons) $t
        }
    } catch { }
}

function Scan-MinecraftLogs {
    if ($Fast) { return }
    Write-Status 'STEP' 'Checking Minecraft logs for loaded cheat/mod indicators...'
    $roots = Get-MinecraftRootsOnly
    foreach ($r in $roots) {
        if (Test-Expired) { break }
        try {
            $logs = Get-ChildItem -LiteralPath $r -Recurse -File -Include 'latest.log','*.log','*.log.gz' -ErrorAction SilentlyContinue | Select-Object -First 80
            foreach ($log in $logs) {
                if (Test-Expired) { break }
                $text = ''
                try { $text = Get-Content -LiteralPath $log.FullName -Raw -ErrorAction SilentlyContinue } catch { $text = '' }
                if ([string]::IsNullOrWhiteSpace($text)) { continue }
                if ($text.Length -gt 1200000) { $text = $text.Substring([Math]::Max(0, $text.Length - 1200000)) }
                $hits = Test-TextHasToken $text $script:AllTokens
                $score = 0
                $reasons = New-Object System.Collections.ArrayList
                if ($hits.Count -gt 0) { $score += 56 + [Math]::Min(20, $hits.Count * 3); [void]$reasons.Add('Minecraft log contains cheat/mod indicators: ' + (($hits | Select-Object -First 10) -join ', ')) }
                if ($text.ToLowerInvariant().Contains('-javaagent') -or $text.ToLowerInvariant().Contains('mixin') -and $hits.Count -gt 0) { $score += 12; [void]$reasons.Add('Log contains Java-agent/mixin context') }
                Add-Finding 'MINECRAFT_LOG' $log.FullName $score @($reasons) ''
            }
        } catch { }
    }
}

function Get-JavaAgentPathsFromCommandLine {
    param([string]$CommandLine)
    $paths = New-Object System.Collections.ArrayList
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return @() }
    try {
        $matches = [regex]::Matches($CommandLine, '-javaagent:("[^"]+"|[^\s]+)')
        foreach ($m in $matches) {
            $v = $m.Groups[1].Value.Trim('"')
            if ($v.Contains('=')) { $v = $v.Split('=')[0] }
            if (-not $paths.Contains($v)) { [void]$paths.Add($v) }
        }
    } catch { }
    return @($paths.ToArray())
}

function Scan-JavaAgents {
    Write-Status 'STEP' 'Checking Java agents and suspicious JVM parameters...'
    $procs = Get-ProcessListSafe
    foreach ($p in $procs) {
        if (Test-Expired) { break }
        $cmd = [string]$p.CommandLine
        if ([string]::IsNullOrWhiteSpace($cmd)) { continue }
        $l = $cmd.ToLowerInvariant()
        $score = 0
        $reasons = New-Object System.Collections.ArrayList
        foreach ($arg in $script:StrongJavaArgs) { if ($l.Contains($arg)) { $score += 26; [void]$reasons.Add('Suspicious JVM arg: ' + $arg) } }
        $paths = Get-JavaAgentPathsFromCommandLine $cmd
        foreach ($ap in $paths) {
            $ap2 = $ap
            if (-not [System.IO.Path]::IsPathRooted($ap2)) {
                try { if ($p.ExecutablePath) { $ap2 = Join-Path (Split-Path -Parent $p.ExecutablePath) $ap2 } } catch { }
            }
            $hits = Test-TextHasToken $ap2 $script:AllTokens
            if ($hits.Count -gt 0) { $score += 55; [void]$reasons.Add('Java agent path matches keywords: ' + ($hits -join ', ')) }
            if (Test-Path -LiteralPath $ap2) {
                $jh = Scan-JarLight $ap2 $script:AllTokens
                if ($jh.Count -gt 0) { $score += 45; [void]$reasons.Add('Java agent JAR internal hits: ' + (($jh | Select-Object -First 8) -join ', ')) }
                Analyze-File $ap2
            }
        }
        if ($score -gt 0) { Add-Finding 'JAVA_AGENT' ([string]$p.Name) ([Math]::Min(100, $score)) @($reasons) ('PID=' + $p.ProcessId) }
    }
}

function Scan-JcmdJava {
    if (-not $Jcmd) { return }
    Write-Status 'STEP' 'Checking Java processes using jcmd/jps when available...'
    $jcmdPath = Resolve-ToolPath 'jcmd.exe'
    if ([string]::IsNullOrWhiteSpace($jcmdPath)) { $jcmdPath = Resolve-ToolPath 'jcmd' }
    if ([string]::IsNullOrWhiteSpace($jcmdPath)) { Add-Warn 'jcmd requested but not found in PATH/JDK.'; return }
    try {
        $list = & $jcmdPath 2>$null
        foreach ($line in $list) {
            $hits = Test-TextHasToken $line $script:AllTokens
            if ($hits.Count -gt 0) { Add-Finding 'JCMD' $line 62 @('jcmd process listing matches keywords: ' + ($hits -join ', ')) '' }
        }
    } catch { Add-Warn ('jcmd failed: ' + $_.Exception.Message) }
}

function Scan-DriversAndVM {
    if (-not ($Drivers -or $VMCheck -or $Deep)) { return }
    Write-Status 'STEP' 'Checking drivers and VM/sandbox/emulator signals...'
    if ($Drivers -or $Deep) {
        try {
            $drivers = Get-CimInstance Win32_SystemDriver
            foreach ($d in $drivers) {
                if (Test-Expired) { break }
                $text = ([string]$d.Name + ' ' + [string]$d.DisplayName + ' ' + [string]$d.PathName)
                $hits = Test-TextHasToken $text $script:AllTokens
                if ($hits.Count -gt 0) { Add-Finding 'DRIVER' ([string]$d.PathName) 72 @('Driver/service matches cheat keyword: ' + ($hits -join ', ')) ([string]$d.State) }
            }
        } catch { }
    }
    if ($VMCheck -or $Deep) {
        try {
            $bios = Get-CimInstance Win32_BIOS
            $cs = Get-CimInstance Win32_ComputerSystem
            $text = ([string]$bios.Manufacturer + ' ' + [string]$bios.SerialNumber + ' ' + [string]$cs.Manufacturer + ' ' + [string]$cs.Model)
            $vmTerms = @('vmware','virtualbox','qemu','kvm','hyper-v','hyperv','xen','parallels','sandbox','emulator','bluestacks','nox','ldplayer')
            $hits = Test-TextHasToken $text $vmTerms
            if ($hits.Count -gt 0) { Add-Finding 'VM_SANDBOX' 'System firmware/model' 44 @('VM/sandbox/emulator signal: ' + ($hits -join ', ')) $text }
        } catch { }
    }
}

function Scan-CheatDomainsNetwork {
    if ($Fast) { return }
    Write-Status 'STEP' 'Checking known cheat domains/IPs against active connections...'
    $ips = New-Object System.Collections.ArrayList
    foreach ($d in $script:CheatDomains) {
        try { [System.Net.Dns]::GetHostAddresses($d) | ForEach-Object { if (-not $ips.Contains($_.IPAddressToString)) { [void]$ips.Add($_.IPAddressToString) } } } catch { }
    }
    if ($ips.Count -eq 0) { return }
    try {
        $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        foreach ($c in $conns) {
            if ($ips.Contains([string]$c.RemoteAddress)) { Add-Finding 'NETWORK_DOMAIN' ($c.RemoteAddress + ':' + $c.RemotePort) 84 @('Connection to known cheat-service resolved IP') ('PID=' + $c.OwningProcess) }
        }
    } catch { }
}

function Scan-Files {
    $roots = @()
    if ($OnlyMinecraft) { $roots = Get-MinecraftRootsOnly }
    elseif ($Deep) { $roots = Get-DeepRoots }
    else { $roots = Get-CommonRoots }
    if (-not $roots -or $roots.Count -eq 0) { Add-Warn 'No scan roots found.'; return }
    $mode = 'SMART'
    if ($OnlyMinecraft) { $mode = 'MINECRAFT ONLY' }
    elseif ($Deep) { $mode = 'FULL SYSTEM / DEEP' }
    elseif ($Fast) { $mode = 'FAST' }
    Write-Status 'STEP' ('Scan mode: ' + $mode)
    $rootShown = @($roots | Select-Object -First 10)
    $suffix = ''
    if ($roots.Count -gt 10) { $suffix = ' ...' }
    Write-Status 'STEP' ('Roots: ' + ($rootShown -join '; ') + $suffix)
    $files = @()
    try { $files = Find-CandidateFiles $roots } catch { Add-Warn ('File candidate search failed: ' + $_.Exception.Message); $files = @() }
    Write-Status 'OK' ('Candidate files found: ' + $files.Count)
    $i = 0
    foreach ($f in $files) {
        if (Test-Expired) { Add-Warn 'Time limit reached while analyzing files.'; break }
        $i++
        if (($i % 100) -eq 0) { Write-Status 'STEP' ('Analyzed ' + $i + ' / ' + $files.Count + ' candidates...') }
        Analyze-File $f
    }
}

function Show-Results {
    Write-Line '' Gray
    Write-Line '==================== YRYS LOCAL AI VERDICT ====================' Red
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
    Write-Line ('  Critical: ' + $crit.Count + ' | High: ' + $high.Count + ' | Medium: ' + $med.Count + ' | Total: ' + $all.Count) Gray
    Write-Line ('  Runtime: ' + ([int]((Get-Date) - $script:StartedAt).TotalSeconds) + ' sec') DarkGray
    Write-Line ('  Modules: YARA=' + $script:YaraReady + ' | AMSI=' + $script:AmsiReady + ' | VT checked=' + $script:VTChecked) DarkGray
    if ($script:Warnings.Count -gt 0) { Write-Line ('  Warnings: ' + $script:Warnings.Count + ' (some protected areas may be skipped)') Yellow }
    Write-Line '' Gray
    if ($all.Count -eq 0) {
        Write-Line '  No strong cheat-related signals found.' Green
        Write-Line '  Note: this is a local heuristic checker; it cannot prove 100% clean system.' DarkGray
    } else {
        $n = 0
        foreach ($x in ($all | Select-Object -First 40)) {
            $n++
            $c = [ConsoleColor]::Cyan
            if ($x.Score -ge 85) { $c = [ConsoleColor]::Red }
            elseif ($x.Score -ge 65) { $c = [ConsoleColor]::Yellow }
            Write-Line (('[' + $n + '] ' + $x.Severity + '  score=' + $x.Score + '  type=' + $x.Kind)) $c
            Write-Line ('    ' + $x.Path) Gray
            if (-not [string]::IsNullOrWhiteSpace($x.Extra)) { Write-Line ('    ' + $x.Extra) DarkGray }
            foreach ($r in ($x.Reasons | Select-Object -First 5)) { Write-Line ('    - ' + $r) DarkGray }
            Write-Line '' Gray
        }
        if ($all.Count -gt 40) { Write-Line ('  Showing top 40 of ' + $all.Count + ' findings.') DarkGray }
    }
    if ($OpenReport) {
        Write-Line '  -OpenReport accepted for compatibility. Permanent report creation is disabled.' Yellow
        Write-Line '  Results are displayed only in console; temp files are removed on exit.' DarkGray
    }
}

function Main {
    New-WorkDir
    Show-Banner
    if ($SelfTest) { Run-SelfTest; return }
    if ($OpenReport) { Write-Status 'WARN' 'OpenReport flag accepted, but report creation is disabled by request.' }
    if (-not (Test-Admin)) { Write-Status 'WARN' 'Run as Administrator for stronger process/DLL/prefetch checks.' }
    if ($VirusTotal -and [string]::IsNullOrWhiteSpace($VirusTotalApiKey)) { Write-Status 'WARN' 'VirusTotal requested but -VirusTotalApiKey is empty. VT lookup disabled.' }
    Initialize-Tokens
    Initialize-YaraEngine
    Initialize-AmsiEngine
    Write-Status 'STEP' ('Time limit: ' + $MaxMinutes + ' min | Max candidates: ' + $MaxCandidates + ' | Max depth: ' + $MaxDepth)
    Invoke-Safe 'Process scan' { Scan-Processes }
    Invoke-Safe 'Loaded module scan' { Scan-LoadedModules }
    Invoke-Safe 'Startup scan' { Scan-Startup }
    Invoke-Safe 'Deep registry scan' { Scan-RegistryDeep }
    Invoke-Safe 'Uninstall scan' { Scan-UninstallPrograms }
    Invoke-Safe 'Hosts scan' { Scan-HostsFile }
    Invoke-Safe 'Java agent scan' { Scan-JavaAgents }
    Invoke-Safe 'jcmd scan' { Scan-JcmdJava }
    Invoke-Safe 'Prefetch scan' { Scan-Prefetch }
    Invoke-Safe 'Network scan' { Scan-Network }
    Invoke-Safe 'Cheat domain network scan' { Scan-CheatDomainsNetwork }
    Invoke-Safe 'Minecraft log scan' { Scan-MinecraftLogs }
    Invoke-Safe 'Driver/VM scan' { Scan-DriversAndVM }
    Invoke-Safe 'File scan' { Scan-Files }
}

try { Main }
catch { Add-Warn ('Fatal recovered: ' + $_.Exception.Message) }
finally {
    try { Show-Results } catch { Write-Line ('Result output failed: ' + $_.Exception.Message) Red }
    try { if ($script:AmsiReady -and $script:AmsiContext -ne [IntPtr]::Zero) { [YrysAmsi]::AmsiUninitialize($script:AmsiContext) } } catch { }
    Remove-WorkDir
}
