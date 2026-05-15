[CmdletBinding()]
param(
    [switch]$Fast,
    [switch]$Deep,
    [switch]$FullSystem = $true,
    [switch]$Forensic = $true,
    [switch]$Drivers = $true,
    [switch]$VMCheck = $true,
    [switch]$USBForensics = $true,
    [switch]$WMIForensics = $true,
    [switch]$BrowserForensics = $true,
    [switch]$DiscordForensics = $true,
    [switch]$ShowIgnored = $true,
    [switch]$OpenReport = $true,
    [switch]$NoCleanup,
    [int]$MaxMinutes = 30,
    [int]$MaxCandidates = 20000,
    [int]$UiWidth = 124,
    [string]$Cheat = ""
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Continue"

$runnerVersion = "1.20.77"
$tempDir = Join-Path $env:TEMP ("PROVERKA_RUN_" + [Guid]::NewGuid().ToString("N"))
$scannerPath = Join-Path $tempDir "Proverka.ps1"
$scannerUrl = "https://raw.githubusercontent.com/Yrysa/Proverka/main/Proverka.ps1"

function Write-Step([string]$Text) {
    Write-Host ("> " + $Text) -ForegroundColor Cyan
}

function Prepare-Environment {
    Write-Step "Preparing environment..."
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
    foreach ($module in @("CimCmdlets", "ScheduledTasks", "Microsoft.PowerShell.Management", "Microsoft.PowerShell.Utility")) {
        try { Import-Module $module -ErrorAction SilentlyContinue } catch {}
    }
    if (-not (Test-Path $tempDir)) {
        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    }
}

function Download-Scanner {
    Write-Step "Downloading Proverka scanner from GitHub..."
    Invoke-WebRequest -Uri $scannerUrl -OutFile $scannerPath -UseBasicParsing
    if (-not (Test-Path $scannerPath)) {
        throw "Scanner was not downloaded."
    }
}

function Start-Scanner {
    Write-Step "Starting Proverka scanner..."
    $argsList = @()
    if ($Fast) { $argsList += "-Fast" }
    if ($Deep) { $argsList += "-Deep" }
    if ($FullSystem) { $argsList += "-FullSystem" }
    if ($Forensic) { $argsList += "-Forensic" }
    if ($Drivers) { $argsList += "-Drivers" }
    if ($VMCheck) { $argsList += "-VMCheck" }
    if ($USBForensics) { $argsList += "-USBForensics" }
    if ($WMIForensics) { $argsList += "-WMIForensics" }
    if ($BrowserForensics) { $argsList += "-BrowserForensics" }
    if ($DiscordForensics) { $argsList += "-DiscordForensics" }
    if ($ShowIgnored) { $argsList += "-ShowIgnored" }
    if ($OpenReport) { $argsList += "-OpenReport" }
    if ($Cheat.Trim().Length -gt 0) { $argsList += @("-Cheat", $Cheat) }
    $argsList += @("-MaxMinutes", $MaxMinutes)
    $argsList += @("-MaxCandidates", $MaxCandidates)
    $argsList += @("-UiWidth", $UiWidth)

    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $scannerPath @argsList
}

function Cleanup-RunnerFiles {
    if ($NoCleanup) {
        Write-Step "Cleanup disabled. Temp folder: $tempDir"
        return
    }
    Write-Step "Cleaning temporary files created by runner..."
    try {
        if (Test-Path $scannerPath) { Remove-Item -LiteralPath $scannerPath -Force -ErrorAction SilentlyContinue }
        if (Test-Path $tempDir) { Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
    } catch {}
}

Write-Host "============================================================" -ForegroundColor Magenta
Write-Host " PROVERKA RUNNER $runnerVersion" -ForegroundColor Cyan
Write-Host " Auto bootstrap + safe temp cleanup" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Magenta

try {
    Prepare-Environment
    Download-Scanner
    Start-Scanner
} finally {
    Cleanup-RunnerFiles
}
