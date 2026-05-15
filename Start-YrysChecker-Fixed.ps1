[CmdletBinding()]
param(
    [switch]$Fast,
    [switch]$Deep,
    [switch]$OpenReport = $true,
    [switch]$NoCleanup,
    [switch]$Manual,
    [switch]$OnlyMinecraft
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$runnerVersion = '1.20.77-fixed2'
$tempDir = Join-Path $env:TEMP ('YRYS_FIXED_' + [Guid]::NewGuid().ToString('N'))
$scannerPath = Join-Path $tempDir 'Proverka.runtime.ps1'
$scannerUrl = 'https://raw.githubusercontent.com/Yrysa/Proverka/main/Proverka.ps1'
$dbUrl = 'https://raw.githubusercontent.com/Yrysa/Proverka/main/cheat_signatures.json'

function Step([string]$Text, [ConsoleColor]$Color = [ConsoleColor]::Cyan) {
    Write-Host ('[YRYS-FIX] ' + $Text) -ForegroundColor $Color
}

function Show-Banner {
    Write-Host ''
    Write-Host '+================================================================+' -ForegroundColor DarkRed
    Write-Host '|                 YRYS CHECKER FIXED LAUNCHER                   |' -ForegroundColor Red
    Write-Host ('|                 build ' + $runnerVersion.PadRight(41) + '|') -ForegroundColor White
    Write-Host '|       deps -> download -> patch broken blocks -> syntax check   |' -ForegroundColor White
    Write-Host '+================================================================+' -ForegroundColor DarkRed
    Write-Host ''
}

function Prepare-Dependencies {
    Step 'Preparing dependencies'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    if (-not (Test-Path $tempDir)) { New-Item -ItemType Directory -Path $tempDir -Force | Out-Null }
    foreach ($m in @('CimCmdlets','NetTCPIP','ScheduledTasks','Microsoft.PowerShell.Management','Microsoft.PowerShell.Utility','Microsoft.PowerShell.Security','Microsoft.PowerShell.Archive')) {
        try { Import-Module $m -ErrorAction SilentlyContinue; Step "Module ready: $m" DarkGray } catch { Step "Module skipped: $m" Yellow }
    }
    try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue } catch {}
    try { Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue } catch {}
}

function Prepare-Db {
    $dbPath = Join-Path $env:TEMP 'YrysCheck\cheat_signatures.json'
    $dbDir = Split-Path $dbPath -Parent
    if (-not (Test-Path $dbDir)) { New-Item -ItemType Directory -Path $dbDir -Force | Out-Null }
    if (Test-Path $dbPath) { Step 'Signature database already exists' DarkGray; return }
    try {
        Step 'Downloading optional signature database'
        Invoke-WebRequest -Uri ($dbUrl + '?nocache=' + [Guid]::NewGuid().ToString('N')) -OutFile $dbPath -UseBasicParsing -TimeoutSec 8
    } catch {
        Step 'Creating empty local signature database' Yellow
        '{ "Hashes": [], "ProcessNames": [], "WindowTitleKeywords": [], "SuspiciousStrings": [], "JarNameKeywords": [], "DllModules": [], "DllPathKeywords": [], "CheatServers": [] }' | Set-Content -LiteralPath $dbPath -Encoding UTF8
    }
}

function Download-Scanner {
    Step 'Downloading Proverka.ps1 fresh copy'
    Invoke-WebRequest -Uri ($scannerUrl + '?nocache=' + [Guid]::NewGuid().ToString('N')) -OutFile $scannerPath -UseBasicParsing
    if (-not (Test-Path $scannerPath)) { throw 'Scanner download failed' }
}

function Replace-FunctionBlock {
    param(
        [Parameter(Mandatory=$true)][System.Collections.Generic.List[string]]$Lines,
        [Parameter(Mandatory=$true)][string]$FunctionName,
        [Parameter(Mandatory=$true)][string]$NextFunctionName,
        [Parameter(Mandatory=$true)][string[]]$Replacement
    )
    $start = -1
    $next = -1
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i] -match ('^\s*function\s+' + [regex]::Escape($FunctionName) + '\s*\{')) { $start = $i; break }
    }
    if ($start -ge 0) {
        for ($j = $start + 1; $j -lt $Lines.Count; $j++) {
            if ($Lines[$j] -match ('^\s*function\s+' + [regex]::Escape($NextFunctionName) + '\s*\{')) { $next = $j; break }
        }
    }
    if ($start -lt 0 -or $next -lt 0) { throw "Cannot find block $FunctionName -> $NextFunctionName. start=$start next=$next" }
    $out = New-Object System.Collections.Generic.List[string]
    for ($a = 0; $a -lt $start; $a++) { [void]$out.Add($Lines[$a]) }
    foreach ($r in $Replacement) { [void]$out.Add($r) }
    for ($b = $next; $b -lt $Lines.Count; $b++) { [void]$out.Add($Lines[$b]) }
    Step "Patched $FunctionName lines $start..$($next - 1)" Green
    return $out
}

function Patch-Scanner {
    Step 'Patching broken PowerShell blocks in runtime copy'
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($line in (Get-Content -LiteralPath $scannerPath)) { [void]$lines.Add([string]$line) }

    $banner = @(
        'function Show-Banner {',
        '    if (-not $Quiet) { Clear-Host }',
        '    $width = 100',
        '    Write-UiRule DarkRed $width',
        '    Write-UiText " __   __ ____  __   __ ____      ____ _   _ _____ ____ _  _______ ____" Red',
        '    Write-UiText " \ \ / /|  _ \ \ \ / // ___|    / ___| | | | ____/ ___| |/ / ____|  _ \" Red',
        '    Write-UiText "  \ V / | |_) | \ V / \___ \   | |   | |_| |  _|| |   |   /|  _| | |_) |" Red',
        '    Write-UiText "   | |  |  _ <   | |   ___) |  | |___|  _  | |__| |___| . \| |___|  _ <" Red',
        '    Write-UiText "   |_|  |_| \_\  |_|  |____/    \____|_| |_|_____\____|_|\_\_____|_| \_\" Red',
        '    Write-UiText ""',
        '    Write-UiText ("  Advanced v{0} | Minecraft / Java forensic scanner" -f $script:ScriptVersion) White',
        '    Write-UiText "  Premium console UI | progress stages | TXT / JSON / HTML report" DarkGray',
        '    Write-UiRule DarkRed $width',
        '    Write-UiText ""',
        '}',
        ''
    )
    $lines = Replace-FunctionBlock -Lines $lines -FunctionName 'Show-Banner' -NextFunctionName 'Show-StageProgress' -Replacement $banner

    $jarFunc = @(
        'function Get-JarPathsFromText {',
        '    param([string]$Text)',
        '    $results = @()',
        '    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }',
        '    $patterns = @(',
        '        ''"([^" ]+?\.jar)"'',',
        '        ''([A-Za-z]:\\[^\s";]+?\.jar)'',',
        '        ''([^\s";]+?\.jar)''',
        '    )',
        '    foreach ($pattern in $patterns) {',
        '        try {',
        '            $matches = [regex]::Matches($Text, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)',
        '            foreach ($m in $matches) {',
        '                $value = $m.Groups[1].Value.Trim().Trim(''"'')',
        '                $value = [Environment]::ExpandEnvironmentVariables($value)',
        '                if (-not [string]::IsNullOrWhiteSpace($value) -and $results -notcontains $value) { $results += $value }',
        '            }',
        '        } catch { }',
        '    }',
        '    return @($results | Select-Object -Unique)',
        '}',
        ''
    )
    $lines = Replace-FunctionBlock -Lines $lines -FunctionName 'Get-JarPathsFromText' -NextFunctionName 'Get-ExistingUniquePaths' -Replacement $jarFunc

    Set-Content -LiteralPath $scannerPath -Value $lines -Encoding UTF8
}

function Test-Syntax {
    Step 'Checking syntax after patches'
    $tokens = $null
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($scannerPath, [ref]$tokens, [ref]$errors) | Out-Null
    if ($errors -and $errors.Count -gt 0) {
        foreach ($e in ($errors | Select-Object -First 10)) { Step ('Syntax error line ' + $e.Extent.StartLineNumber + ': ' + $e.Message) Red }
        throw 'Syntax check failed'
    }
    Step 'Syntax OK' Green
}

function Start-Scanner {
    Step 'Starting scanner'
    $argsList = @()
    if ($Fast) { $argsList += '-Fast' }
    if ($Deep) { $argsList += '-Deep' }
    if ($Manual) { $argsList += '-Manual' }
    if ($OnlyMinecraft) { $argsList += '-OnlyMinecraft' }
    if ($OpenReport) { $argsList += '-OpenReport' }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $scannerPath @argsList
}

function Cleanup {
    if ($NoCleanup) { Step "Cleanup disabled: $tempDir" Yellow; return }
    Step 'Cleaning temp files' DarkGray
    try { if (Test-Path $tempDir) { Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue } } catch {}
}

Show-Banner
try {
    Prepare-Dependencies
    Prepare-Db
    Download-Scanner
    Patch-Scanner
    Test-Syntax
    Start-Scanner
} finally {
    Cleanup
}
