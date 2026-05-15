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

$runnerVersion = "1.20.77"
$tempDir = Join-Path $env:TEMP ("PROVERKA_RUN_" + [Guid]::NewGuid().ToString("N"))
$scannerPath = Join-Path $tempDir "Proverka.ps1"
$scannerUrl = "https://raw.githubusercontent.com/Yrysa/Proverka/main/Proverka.ps1"
$signatureDbUrl = "https://raw.githubusercontent.com/Yrysa/Proverka/main/cheat_signatures.json"

function Write-Step([string]$Text, [ConsoleColor]$Color = [ConsoleColor]::Cyan) {
    try { Write-Host ("[PROVERKA] " + $Text) -ForegroundColor $Color } catch { Write-Host ("[PROVERKA] " + $Text) }
}

function Show-RunnerBanner {
    Write-Host ""
    Write-Host "+============================================================+" -ForegroundColor DarkRed
    Write-Host "|                  YRYS CHECKER RUNNER                      |" -ForegroundColor Red
    Write-Host "|        dependency bootstrap + premium UI launcher          |" -ForegroundColor White
    Write-Host "|        scanner UI is preserved, not simplified             |" -ForegroundColor DarkGray
    Write-Host "+============================================================+" -ForegroundColor DarkRed
    Write-Host ""
}

function Prepare-Environment {
    Write-Step "Preparing dependencies"
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

    if (-not (Test-Path $tempDir)) {
        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    }

    foreach ($module in @(
        "CimCmdlets",
        "NetTCPIP",
        "ScheduledTasks",
        "Microsoft.PowerShell.Management",
        "Microsoft.PowerShell.Utility",
        "Microsoft.PowerShell.Security",
        "Microsoft.PowerShell.Archive"
    )) {
        try {
            Import-Module $module -ErrorAction SilentlyContinue
            Write-Step "Module ready: $module" DarkGray
        } catch {
            Write-Step "Module skipped: $module" Yellow
        }
    }

    try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue } catch {}
    try { Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue } catch {}
}

function Download-Scanner {
    Write-Step "Downloading scanner from GitHub"
    Invoke-WebRequest -Uri $scannerUrl -OutFile $scannerPath -UseBasicParsing
    if (-not (Test-Path $scannerPath)) { throw "Scanner was not downloaded." }
}

function Download-OptionalDatabase {
    $dbPath = Join-Path $env:TEMP "YrysCheck\cheat_signatures.json"
    $dbDir = Split-Path $dbPath -Parent
    if (-not (Test-Path $dbDir)) { New-Item -ItemType Directory -Path $dbDir -Force | Out-Null }

    if (Test-Path $dbPath) {
        Write-Step "Signature database already exists" DarkGray
        return
    }

    try {
        Write-Step "Downloading optional signature database"
        Invoke-WebRequest -Uri $signatureDbUrl -OutFile $dbPath -UseBasicParsing -TimeoutSec 8 -ErrorAction Stop
    } catch {
        Write-Step "Optional signature database not found online, creating local empty database" Yellow
        '{ "Hashes": [], "ProcessNames": [], "WindowTitleKeywords": [], "SuspiciousStrings": [], "JarNameKeywords": [], "DllModules": [], "DllPathKeywords": [], "CheatServers": [] }' | Set-Content -LiteralPath $dbPath -Encoding UTF8
    }
}

function Repair-ScannerRuntimeCopy {
    Write-Step "Preparing runtime copy without changing scanner UI"
    $text = Get-Content -LiteralPath $scannerPath -Raw -ErrorAction Stop

    $old = @'
function Show-Banner {
    if (-not $Quiet) { Clear-Host }
    $width = 100
    Write-UiRule DarkRed $width
    Write-UiText "  __   ______  __   __  ____     ____ _   _ _____ ____ _  _______ ____  " Red
    Write-UiText "  \ \ / /  _ \ \ \ / / / ___|   / ___| | | | ____/ ___| |/ / ____|  _ \ " Red
    Write-UiText "   \ V /| |_) | \ V /  \___ \  | |   | |_| |  _|| |   | ' /|  _| | |_) |" Red
    Write-UiText "    | | |  _ <   | |    ___) | | |___|  _  | |__| |___| . \| |___|  _ < " Red
    Write-UiText "    |_| |_| \_\  |_|   |____/   \____|_| |_|_____\____|_|\_\_____|_| \_\" Red
    Write-UiText ""
    Write-UiText ("  Advanced v{0} | Minecraft / Java forensic scanner" -f $script:ScriptVersion) White
    Write-UiText "  Premium console UI | progress stages | TXT / JSON / HTML report" DarkGray
    Write-UiRule DarkRed $width
    Write-UiText ""
}
'@

    $new = @'
function Show-Banner {
    if (-not $Quiet) { Clear-Host }
    $width = 100
    Write-UiRule DarkRed $width
    Write-UiText '  __   ______  __   __  ____     ____ _   _ _____ ____ _  _______ ____  ' Red
    Write-UiText '  \ \ / /  _ \ \ \ / / / ___|   / ___| | | | ____/ ___| |/ / ____|  _ \ ' Red
    Write-UiText '   \ V /| |_) | \ V /  \___ \  | |   | |_| |  _|| |   | '' /|  _| | |_) |' Red
    Write-UiText '    | | |  _ <   | |    ___) | | |___|  _  | |__| |___| . \| |___|  _ < ' Red
    Write-UiText '    |_| |_| \_\  |_|   |____/   \____|_| |_|_____\____|_|\_\_____|_| \_\' Red
    Write-UiText ''
    Write-UiText ("  Advanced v{0} | Minecraft / Java forensic scanner" -f $script:ScriptVersion) White
    Write-UiText '  Premium console UI | progress stages | TXT / JSON / HTML report' DarkGray
    Write-UiRule DarkRed $width
    Write-UiText ''
}
'@

    if ($text.Contains($old)) {
        $text = $text.Replace($old, $new)
        Set-Content -LiteralPath $scannerPath -Value $text -Encoding UTF8
    }
}

function Start-Scanner {
    Write-Step "Starting scanner"
    $argsList = @()
    if ($Fast) { $argsList += "-Fast" }
    if ($Deep) { $argsList += "-Deep" }
    if ($Manual) { $argsList += "-Manual" }
    if ($OnlyMinecraft) { $argsList += "-OnlyMinecraft" }
    if ($OpenReport) { $argsList += "-OpenReport" }
    if ($Cheat.Trim().Length -gt 0) { $argsList += @("-Cheat", $Cheat) }

    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $scannerPath @argsList
}

function Cleanup-RunnerFiles {
    if ($NoCleanup) {
        Write-Step "Cleanup disabled. Temp folder: $tempDir" Yellow
        return
    }
    Write-Step "Cleaning temporary runner files" DarkGray
    try {
        if (Test-Path $scannerPath) { Remove-Item -LiteralPath $scannerPath -Force -ErrorAction SilentlyContinue }
        if (Test-Path $tempDir) { Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
    } catch {}
}

Show-RunnerBanner
try {
    Prepare-Environment
    Download-OptionalDatabase
    Download-Scanner
    Repair-ScannerRuntimeCopy
    Start-Scanner
} finally {
    Cleanup-RunnerFiles
}
