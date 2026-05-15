[CmdletBinding()]
param(
    [switch]$Fast,
    [switch]$Deep,
    [switch]$OpenReport = $true,
    [switch]$NoCleanup,
    [switch]$Manual,
    [switch]$OnlyMinecraft,
    [string]$Cheat = ""
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Continue"

$runnerVersion = "1.20.77-final"
$tempDir = Join-Path $env:TEMP ("YRYS_CHECKER_RUN_" + [Guid]::NewGuid().ToString("N"))
$scannerPath = Join-Path $tempDir "Proverka.runtime.ps1"
$scannerUrl = "https://raw.githubusercontent.com/Yrysa/Proverka/main/Proverka.ps1"
$signatureDbUrl = "https://raw.githubusercontent.com/Yrysa/Proverka/main/cheat_signatures.json"

function Step([string]$Text, [ConsoleColor]$Color = [ConsoleColor]::Cyan) {
    try { Write-Host ("[YRYS] " + $Text) -ForegroundColor $Color } catch { Write-Host ("[YRYS] " + $Text) }
}

function Banner {
    Write-Host ""
    Write-Host "+================================================================+" -ForegroundColor DarkRed
    Write-Host "|                    YRYS CHECKER LAUNCHER                      |" -ForegroundColor Red
    Write-Host ("|                    build " + $runnerVersion.PadRight(43) + "|") -ForegroundColor White
    Write-Host "|      dependencies first -> runtime patch -> premium UI          |" -ForegroundColor White
    Write-Host "+================================================================+" -ForegroundColor DarkRed
    Write-Host ""
}

function Prepare-Dependencies {
    Step "Preparing dependencies"
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
    if (-not (Test-Path $tempDir)) { New-Item -ItemType Directory -Path $tempDir -Force | Out-Null }

    $modules = @(
        "CimCmdlets",
        "NetTCPIP",
        "ScheduledTasks",
        "Microsoft.PowerShell.Management",
        "Microsoft.PowerShell.Utility",
        "Microsoft.PowerShell.Security",
        "Microsoft.PowerShell.Archive"
    )
    foreach ($m in $modules) {
        try { Import-Module $m -ErrorAction SilentlyContinue; Step "Module ready: $m" DarkGray } catch { Step "Module skipped: $m" Yellow }
    }
    try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue } catch {}
    try { Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue } catch {}
}

function Prepare-SignatureDb {
    $dbPath = Join-Path $env:TEMP "YrysCheck\cheat_signatures.json"
    $dbDir = Split-Path $dbPath -Parent
    if (-not (Test-Path $dbDir)) { New-Item -ItemType Directory -Path $dbDir -Force | Out-Null }

    if (Test-Path $dbPath) {
        Step "Signature database already exists" DarkGray
        return
    }

    try {
        Step "Downloading optional signature database"
        Invoke-WebRequest -Uri ($signatureDbUrl + "?nocache=" + [guid]::NewGuid().ToString("N")) -OutFile $dbPath -UseBasicParsing -TimeoutSec 8 -ErrorAction Stop
    } catch {
        Step "Optional signature database not found, creating local empty database" Yellow
        '{ "Hashes": [], "ProcessNames": [], "WindowTitleKeywords": [], "SuspiciousStrings": [], "JarNameKeywords": [], "DllModules": [], "DllPathKeywords": [], "CheatServers": [] }' | Set-Content -LiteralPath $dbPath -Encoding UTF8
    }
}

function Download-Scanner {
    Step "Downloading Proverka.ps1"
    Invoke-WebRequest -Uri ($scannerUrl + "?nocache=" + [guid]::NewGuid().ToString("N")) -OutFile $scannerPath -UseBasicParsing -ErrorAction Stop
    if (-not (Test-Path $scannerPath)) { throw "Scanner was not downloaded." }
}

function Patch-ScannerBanner {
    Step "Patching banner in runtime copy"
    $lines = @(Get-Content -LiteralPath $scannerPath -ErrorAction Stop)

    $start = -1
    $next = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^\s*function\s+Show-Banner\s*\{') { $start = $i; break }
    }
    if ($start -ge 0) {
        for ($j = $start + 1; $j -lt $lines.Count; $j++) {
            if ($lines[$j] -match '^\s*function\s+Show-StageProgress\s*\{') { $next = $j; break }
        }
    }

    if ($start -lt 0 -or $next -lt 0) {
        throw "Could not find Show-Banner block. start=$start next=$next"
    }

    $safeBanner = @(
        'function Show-Banner {',
        '    if (-not $Quiet) { Clear-Host }',
        '    $width = 100',
        '    Write-UiRule DarkRed $width',
        '    $bannerLines = @(',
        '        " __   __ ____  __   __ ____      ____ _   _ _____ ____ _  _______ ____"',
        '        " \ \ / /|  _ \ \ \ / // ___|    / ___| | | | ____/ ___| |/ / ____|  _ \"',
        '        "  \ V / | |_) | \ V / \___ \   | |   | |_| |  _|| |   |   /|  _| | |_) |"',
        '        "   | |  |  _ <   | |   ___) |  | |___|  _  | |__| |___| . \| |___|  _ <"',
        '        "   |_|  |_| \_\  |_|  |____/    \____|_| |_|_____\____|_|\_\_____|_| \_\"',
        '    )',
        '    foreach ($line in $bannerLines) { Write-UiText $line Red }',
        '    Write-UiText ""',
        '    Write-UiText ("  Advanced v{0} | Minecraft / Java forensic scanner" -f $script:ScriptVersion) White',
        '    Write-UiText "  Premium console UI | progress stages | TXT / JSON / HTML report" DarkGray',
        '    Write-UiRule DarkRed $width',
        '    Write-UiText ""',
        '}',
        ''
    )

    $out = New-Object System.Collections.Generic.List[string]
    for ($a = 0; $a -lt $start; $a++) { [void]$out.Add([string]$lines[$a]) }
    foreach ($s in $safeBanner) { [void]$out.Add($s) }
    for ($b = $next; $b -lt $lines.Count; $b++) { [void]$out.Add([string]$lines[$b]) }

    Set-Content -LiteralPath $scannerPath -Value $out -Encoding UTF8
    Step "Banner patched successfully: lines $start..$($next - 1)" Green
}

function Test-ScannerSyntax {
    Step "Checking scanner syntax"
    $tokens = $null
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($scannerPath, [ref]$tokens, [ref]$errors) | Out-Null
    if ($errors -and $errors.Count -gt 0) {
        foreach ($e in $errors | Select-Object -First 8) {
            Step ("Syntax error line " + $e.Extent.StartLineNumber + ": " + $e.Message) Red
        }
        throw "Scanner syntax check failed."
    }
    Step "Syntax OK" Green
}

function Start-Scanner {
    Step "Starting scanner"
    $argsList = @()
    if ($Fast) { $argsList += "-Fast" }
    if ($Deep) { $argsList += "-Deep" }
    if ($Manual) { $argsList += "-Manual" }
    if ($OnlyMinecraft) { $argsList += "-OnlyMinecraft" }
    if ($OpenReport) { $argsList += "-OpenReport" }
    if ($Cheat.Trim().Length -gt 0) { $argsList += @("-Cheat", $Cheat) }
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $scannerPath @argsList
}

function Cleanup {
    if ($NoCleanup) { Step "Cleanup disabled: $tempDir" Yellow; return }
    Step "Cleaning runner temp files" DarkGray
    try { if (Test-Path $tempDir) { Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue } } catch {}
}

Banner
try {
    Prepare-Dependencies
    Prepare-SignatureDb
    Download-Scanner
    Patch-ScannerBanner
    Test-ScannerSyntax
    Start-Scanner
} finally {
    Cleanup
}
