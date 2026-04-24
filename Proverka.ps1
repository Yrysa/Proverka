#Requires -Version 5.1
<#
.SYNOPSIS
    YRYS CHECKER Advanced — автономная строгая проверка Minecraft/Java на чит-клиенты и подозрительные следы.

.DESCRIPTION
    Скрипт полностью автономный: запускает полный анализ без меню, собирает доказательства,
    считает риск-скор, сохраняет TXT/JSON/HTML отчёты и по желанию открывает HTML-отчёт.

    Что проверяет:
    - процессы, окна и командные строки;
    - Java/Minecraft процессы, javaagent/tweakClass и JAR из аргументов запуска;
    - папки .minecraft/mods/versions/libraries и популярные лаунчеры;
    - SHA256-сигнатуры из встроенной/внешней БД;
    - строки и имена файлов внутри JAR/ZIP;
    - DLL/модули, загруженные в Java-процессы;
    - сетевые подключения к известным адресам/доменам;
    - автозагрузку, задачи планировщика, hosts и Prefetch;
    - дополнительные пути через -ExtraScanPath.

.NOTES
    Скрипт ничего не удаляет, не отправляет в интернет и не блокирует программы.
    Он только читает локальные данные и формирует отчёт.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\YRYS_CHECKER_Advanced.ps1 -OpenReport

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\YRYS_CHECKER_Advanced.ps1 -Deep -OpenReport
#>

[CmdletBinding()]
param(
    [switch]$Manual,
    [switch]$OpenReport,
    [switch]$Deep,
    [switch]$OnlyMinecraft,
    [switch]$NoHtml,
    [switch]$Quiet,
    [int]$MaxJarMB = 250,
    [int]$MaxEntryMB = 4,
    [string]$OutputRoot = (Join-Path $env:TEMP "YrysCheck"),
    [string[]]$ExtraScanPath = @()
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

$script:ScriptVersion = '5.0.0'
$script:RunId = Get-Date -Format 'yyyyMMdd_HHmmss'
$script:TempRoot = $OutputRoot
$script:LogFile = Join-Path $script:TempRoot "session_$script:RunId.log"
$script:ReportFile = Join-Path $script:TempRoot "minecraft_jar_report_$script:RunId.txt"
$script:JsonReport = Join-Path $script:TempRoot "yrys_checker_report_$script:RunId.json"
$script:HtmlReport = Join-Path $script:TempRoot "YRYS_CHECKER_REPORT_$script:RunId.html"
$script:CheatDbFile = Join-Path $script:TempRoot 'cheat_signatures.json'
$script:Findings = @()
$script:ScannedFiles = 0
$script:ScannedJars = 0
$script:ReadErrors = 0
$script:IsAdmin = $false

# =========================
# БАЗА ИНДИКАТОРОВ
# =========================
$script:DefaultCheatDB = [ordered]@{
    Hashes = @(
        # Добавляй реальные SHA256 в $env:TEMP\YrysCheck\cheat_signatures.json
        # Формат: { "Hashes": ["ABCD..."], "ProcessNames": ["..."] }
    )
    ProcessNames = @(
        'vape','vapev4','raven','ravenb','rise','liquidbounce','wurst','aristois',
        'sigma','sigma5','zeroday','bleachhack','breez','ares','impact','inertia',
        'phobos','rusherhack','astolfo','meteor','kami','future','salhack','konas',
        'clicker','autoclicker','ghostclient','dream','whiteout','entropy','drip',
        'ape','koid','doomsday','skid','moon','novoline','tenacity','exhibition'
    )
    WindowTitleKeywords = @(
        'Vape V4','Raven B+','Raven B','LiquidBounce','Wurst Client','Aristois Client',
        'Sigma Client','Rise Client','Breez','Ares Client','Phobos','Meteor Client',
        'Ghost Client','AutoClicker','Clicker','Whiteout','Entropy','Drip Lite','Dream Client'
    )
    SuspiciousStrings = @(
        'KillAura','Killaura','AutoClicker','Auto Clicker','AimAssist','Aim Assist',
        'TriggerBot','Trigger Bot','Reach','Velocity','AntiKnockback','NoSlow','NoFall',
        'Scaffold','SafeWalk','ChestStealer','InventoryMove','InvMove','Blink','Timer',
        'Criticals','AutoTotem','CrystalAura','AutoCrystal','ESP','Tracers','XRay','X-Ray',
        'Fullbright','ClickGUI','Click Gui','modmenu','hackclient','ghostclient','cheat',
        'Vape','Raven','LiquidBounce','Wurst','Aristois','Sigma','Rise','MeteorClient',
        'MixinTransformer','tweakClass','javaagent','Baritone','NoRender','Freecam','Bhop',
        'SpeedHack','FlyHack','Jesus','FastPlace','FastBreak','AutoArmor','AutoSoup'
    )
    JarNameKeywords = @(
        'vape','raven','rise','liquidbounce','wurst','aristois','sigma','zeroday',
        'bleach','breez','ares','impact','inertia','phobos','rusherhack','astolfo',
        'meteor','future','kami','salhack','konas','novoline','tenacity','exhibition',
        'autoclicker','clicker','ghost','xray','killaura','aimassist','triggerbot'
    )
    DllModules = @(
        'vape.dll','echo.dll','raven.dll','rise.dll','sigma.dll','clicker.dll',
        'ghost.dll','entropy.dll','whiteout.dll','drip.dll','dream.dll','ape.dll'
    )
    DllPathKeywords = @(
        'vape','raven','rise','sigma','ghost','clicker','autoclicker','entropy','whiteout',
        'drip','dream','cheat','hack','inject','loader'
    )
    CheatServers = @(
        'vape.gg','riseclient.com','intent.store','novoline.lol','liquidbounce.net',
        'wurstclient.net','meteorclient.com','aristois.net'
    )
}

$script:CheatDB = $null

# =========================
# УТИЛИТЫ
# =========================
function Ensure-Directory {
    param([Parameter(Mandatory=$true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function ConvertTo-StringArray {
    param($Value)
    $out = @()
    if ($null -eq $Value) { return @() }
    if ($Value -is [System.Array]) {
        foreach ($v in $Value) {
            if ($null -ne $v -and -not [string]::IsNullOrWhiteSpace([string]$v)) { $out += [string]$v }
        }
    } else {
        if (-not [string]::IsNullOrWhiteSpace([string]$Value)) { $out += [string]$Value }
    }
    return @($out | Select-Object -Unique)
}

function Initialize-CheatDB {
    $db = [ordered]@{}
    foreach ($key in $script:DefaultCheatDB.Keys) {
        $db[$key] = ConvertTo-StringArray $script:DefaultCheatDB[$key]
    }

    if (Test-Path -LiteralPath $script:CheatDbFile) {
        try {
            $external = Get-Content -LiteralPath $script:CheatDbFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            foreach ($key in $script:DefaultCheatDB.Keys) {
                if ($external.PSObject.Properties.Name -contains $key) {
                    $merged = @()
                    $merged += ConvertTo-StringArray $db[$key]
                    $merged += ConvertTo-StringArray $external.$key
                    $db[$key] = @($merged | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
                }
            }
        } catch {
            Write-Log 'WARN' "Не удалось загрузить внешнюю БД $script:CheatDbFile. Использую встроенную. Ошибка: $($_.Exception.Message)"
        }
    }

    $db['Hashes'] = @($db['Hashes'] | ForEach-Object { ([string]$_).Trim().ToUpperInvariant() } | Where-Object { $_ -match '^[A-F0-9]{64}$' } | Select-Object -Unique)
    $script:CheatDB = $db
}

function Test-Administrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Write-Console {
    param(
        [string]$Text,
        [ConsoleColor]$Foreground = [ConsoleColor]::White,
        [ConsoleColor]$Background = [ConsoleColor]::Black
    )
    if ($Quiet) { return }
    try { Write-Host $Text -ForegroundColor $Foreground -BackgroundColor $Background } catch { Write-Host $Text }
}

function Write-Log {
    param(
        [ValidateSet('INFO','OK','WARN','ERROR','HIT','CRITICAL')]
        [string]$Level,
        [string]$Message
    )

    $time = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$time] [$Level] $Message"
    try {
        Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8
        Add-Content -LiteralPath $script:ReportFile -Value $line -Encoding UTF8
    } catch {
        # Последний шанс — не ломаем проверку из-за логов.
    }

    switch ($Level) {
        'INFO'     { Write-Console "[*] $Message" Cyan }
        'OK'       { Write-Console "[+] $Message" Green }
        'WARN'     { Write-Console "[!] $Message" Yellow }
        'ERROR'    { Write-Console "[-] $Message" Red }
        'HIT'      { Write-Console "[!] $Message" Red }
        'CRITICAL' { Write-Console "[!!!] $Message" White DarkRed }
    }
}

function Add-Finding {
    param(
        [ValidateSet('Critical','High','Medium','Low','Info')]
        [string]$Severity,
        [int]$Score,
        [string]$Category,
        [string]$Title,
        [string]$Path = '',
        [string]$Evidence = '',
        [string]$Recommendation = ''
    )

    $finding = [pscustomobject]@{
        Time = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Severity = $Severity
        Score = $Score
        Category = $Category
        Title = $Title
        Path = $Path
        Evidence = $Evidence
        Recommendation = $Recommendation
    }
    $script:Findings += $finding

    $msg = "[$Severity][$Category] $Title"
    if (-not [string]::IsNullOrWhiteSpace($Path)) { $msg += " | $Path" }
    if (-not [string]::IsNullOrWhiteSpace($Evidence)) { $msg += " | $Evidence" }

    if ($Severity -eq 'Critical') { Write-Log 'CRITICAL' $msg }
    elseif ($Severity -in @('High','Medium')) { Write-Log 'HIT' $msg }
    else { Write-Log 'WARN' $msg }
}

function Show-Banner {
    $banner = @'

██╗   ██╗██████╗ ██╗   ██╗███████╗     ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗███████╗██████╗ 
╚██╗ ██╔╝██╔══██╗╚██╗ ██╔╝██╔════╝    ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝██╔════╝██╔══██╗
 ╚████╔╝ ██████╔╝ ╚████╔╝ ███████╗    ██║     ███████║█████╗  ██║     █████╔╝ █████╗  ██████╔╝
  ╚██╔╝  ██╔══██╗  ╚██╔╝  ╚════██║    ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ ██╔══╝  ██╔══██╗
   ██║   ██║  ██║   ██║   ███████║    ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗███████╗██║  ██║
   ╚═╝   ╚═╝  ╚═╝   ╚═╝   ╚══════╝     ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
'@
    Write-Console $banner Red Black
    Write-Console "                      Advanced v$script:ScriptVersion | автономная строгая проверка" White DarkRed
    Write-Console ""
}

function Get-LowerList {
    param([string[]]$Items)
    return @($Items | ForEach-Object { ([string]$_).ToLowerInvariant() } | Select-Object -Unique)
}

function Find-IndicatorsInText {
    param(
        [string]$Text,
        [string[]]$Indicators
    )
    $matches = @()
    if ([string]::IsNullOrEmpty($Text)) { return @() }
    foreach ($indicator in $Indicators) {
        if ([string]::IsNullOrWhiteSpace($indicator)) { continue }
        if ($Text.IndexOf($indicator, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            $matches += $indicator
        }
    }
    return @($matches | Select-Object -Unique)
}

function Get-FileHashSafe {
    param([string]$Path)
    try {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToUpperInvariant()
        }
    } catch {
        $script:ReadErrors++
        Write-Log 'WARN' "Не удалось посчитать SHA256: $Path | $($_.Exception.Message)"
    }
    return ''
}

function Get-AuthenticodeInfoSafe {
    param([string]$Path)
    try {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            return Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        }
    } catch { }
    return $null
}

function Get-JarPathsFromText {
    param([string]$Text)
    $results = @()
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }

    $patterns = @(
        '"([^"]+?\.jar)"',
        '([A-Za-z]:\\[^\s";]+?\.jar)',
        '([^\s";]+?\.jar)'
    )

    foreach ($pattern in $patterns) {
        try {
            $matches = [regex]::Matches($Text, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            foreach ($m in $matches) {
                $value = $m.Groups[1].Value.Trim().Trim('"')
                $value = [Environment]::ExpandEnvironmentVariables($value)
                if (-not [string]::IsNullOrWhiteSpace($value) -and $results -notcontains $value) {
                    $results += $value
                }
            }
        } catch { }
    }
    return @($results | Select-Object -Unique)
}

function Get-ExistingUniquePaths {
    param([string[]]$Paths)
    $out = @()
    foreach ($p in $Paths) {
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        $expanded = [Environment]::ExpandEnvironmentVariables($p)
        try {
            if (Test-Path -LiteralPath $expanded) {
                $resolved = (Resolve-Path -LiteralPath $expanded -ErrorAction Stop).Path
                if ($out -notcontains $resolved) { $out += $resolved }
            }
        } catch { }
    }
    return @($out)
}

# =========================
# ПРОВЕРКИ
# =========================
function Invoke-SystemSummary {
    Write-Log 'INFO' 'Сбор информации о системе...'
    $script:IsAdmin = Test-Administrator

    $osCaption = 'Unknown OS'
    $osBuild = ''
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $osCaption = $os.Caption
        $osBuild = $os.BuildNumber
    } catch { }

    Write-Log 'OK' "YRYS CHECKER v$script:ScriptVersion"
    Write-Log 'OK' "Компьютер: $env:COMPUTERNAME | Пользователь: $env:USERNAME"
    Write-Log 'OK' "ОС: $osCaption build $osBuild | PowerShell: $($PSVersionTable.PSVersion)"
    if ($script:IsAdmin) {
        Write-Log 'OK' 'Запущено с правами администратора: доступ к модулям/сетям максимальный.'
    } else {
        Add-Finding -Severity 'Low' -Score 2 -Category 'Environment' -Title 'Скрипт запущен без администратора' -Evidence 'Некоторые DLL/сетевые/Prefetch проверки могут быть неполными.' -Recommendation 'Для самой жёсткой проверки запусти PowerShell от имени администратора.'
    }
}

function Invoke-ProcessAndWindowCheck {
    Write-Log 'INFO' 'Жёсткая проверка процессов, окон и командных строк...'
    $procKeywords = Get-LowerList $script:CheatDB.ProcessNames
    $windowKeywords = $script:CheatDB.WindowTitleKeywords
    $textIndicators = $script:CheatDB.SuspiciousStrings

    $processes = @()
    try {
        $processes = Get-Process -ErrorAction Stop
    } catch {
        Write-Log 'ERROR' "Не удалось получить процессы: $($_.Exception.Message)"
        return
    }

    foreach ($p in $processes) {
        $nameLower = ([string]$p.ProcessName).ToLowerInvariant()
        if ($procKeywords -contains $nameLower) {
            Add-Finding -Severity 'High' -Score 45 -Category 'Process' -Title "Процесс похож на известный чит/кликер: $($p.ProcessName)" -Evidence "PID=$($p.Id)"
        }

        foreach ($kw in $procKeywords) {
            if ($kw.Length -ge 4 -and $nameLower -like "*$kw*") {
                Add-Finding -Severity 'Medium' -Score 18 -Category 'Process' -Title "Подозрительное имя процесса содержит '$kw': $($p.ProcessName)" -Evidence "PID=$($p.Id)"
                break
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($p.MainWindowTitle)) {
            $hits = Find-IndicatorsInText -Text $p.MainWindowTitle -Indicators $windowKeywords
            if ($hits.Count -gt 0) {
                Add-Finding -Severity 'High' -Score 45 -Category 'Window' -Title "Окно похоже на чит-клиент: $($p.MainWindowTitle)" -Evidence "Процесс=$($p.ProcessName), PID=$($p.Id), Индикаторы=$($hits -join ', ')"
            }
        }
    }

    try {
        $cim = Get-CimInstance Win32_Process -ErrorAction Stop
        foreach ($cp in $cim) {
            $cmd = [string]$cp.CommandLine
            if ([string]::IsNullOrWhiteSpace($cmd)) { continue }

            $hits = Find-IndicatorsInText -Text $cmd -Indicators $textIndicators
            if ($hits.Count -gt 0 -and $cp.Name -match 'java|javaw|minecraft|launcher') {
                Add-Finding -Severity 'Medium' -Score 22 -Category 'CommandLine' -Title "Java/Minecraft командная строка содержит подозрительные индикаторы" -Path $cp.ExecutablePath -Evidence "PID=$($cp.ProcessId), Индикаторы=$($hits -join ', ')"
            }

            if ($cmd.IndexOf('-javaagent', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                Add-Finding -Severity 'High' -Score 50 -Category 'JavaAgent' -Title 'Обнаружен -javaagent в Java-процессе' -Path $cp.ExecutablePath -Evidence "PID=$($cp.ProcessId). JavaAgent часто используется для инжекта/модификации клиента."
            }
        }
    } catch {
        Write-Log 'WARN' "Не удалось получить командные строки процессов: $($_.Exception.Message)"
    }

    Write-Log 'OK' 'Проверка процессов и окон завершена.'
}

function Invoke-MinecraftProcessCheck {
    Write-Log 'INFO' 'Поиск Java/Minecraft процессов, JAR и модулей...'
    $processes = @()
    try {
        $processes = Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
            $_.Name -match '^(java|javaw|minecraft|Minecraft|launcher)' -or
            ([string]$_.CommandLine) -match 'minecraft|\.jar|forge|fabric|quilt|optifine|lunar|badlion|tlauncher|feather'
        }
    } catch {
        Write-Log 'WARN' "Не удалось прочитать Win32_Process: $($_.Exception.Message)"
        return
    }

    if (-not $processes -or $processes.Count -eq 0) {
        Write-Log 'WARN' 'Активные Java/Minecraft процессы не найдены. Будут проверены файлы на диске.'
        return
    }

    foreach ($proc in $processes) {
        Write-Log 'OK' "Процесс: $($proc.Name) | PID=$($proc.ProcessId)"
        if (-not [string]::IsNullOrWhiteSpace([string]$proc.CommandLine)) {
            Write-Log 'INFO' "Команда: $($proc.CommandLine)"
        }

        $jarPaths = Get-JarPathsFromText -Text ([string]$proc.CommandLine)
        foreach ($jarPath in $jarPaths) {
            if (Test-Path -LiteralPath $jarPath -PathType Leaf) {
                Scan-CandidateFile -Path $jarPath -Source "CommandLine PID=$($proc.ProcessId)"
            } else {
                Add-Finding -Severity 'Low' -Score 5 -Category 'JarPath' -Title 'JAR указан в командной строке, но файл не найден' -Path $jarPath -Evidence "PID=$($proc.ProcessId)"
            }
        }

        Invoke-JavaModuleCheck -ProcessId ([int]$proc.ProcessId) -ProcessName ([string]$proc.Name)
    }
}

function Invoke-JavaModuleCheck {
    param(
        [int]$ProcessId,
        [string]$ProcessName
    )

    try {
        $p = Get-Process -Id $ProcessId -ErrorAction Stop
        $modules = @($p.Modules)
        $knownDllLower = Get-LowerList $script:CheatDB.DllModules
        foreach ($mod in $modules) {
            $moduleName = ([string]$mod.ModuleName).ToLowerInvariant()
            $filePath = [string]$mod.FileName
            if ($knownDllLower -contains $moduleName) {
                Add-Finding -Severity 'Critical' -Score 100 -Category 'InjectedDLL' -Title "В Java/Minecraft процессе загружена известная подозрительная DLL: $($mod.ModuleName)" -Path $filePath -Evidence "PID=$ProcessId, Process=$ProcessName"
                continue
            }

            $pathHits = Find-IndicatorsInText -Text $filePath -Indicators $script:CheatDB.DllPathKeywords
            if ($pathHits.Count -gt 0 -and $moduleName -match '\.dll$') {
                Add-Finding -Severity 'Medium' -Score 25 -Category 'InjectedDLL' -Title "DLL в Java-процессе имеет подозрительный путь/имя" -Path $filePath -Evidence "PID=$ProcessId, Индикаторы=$($pathHits -join ', ')"
            }
        }
    } catch {
        Write-Log 'WARN' "Не удалось проверить DLL модулей PID=$ProcessId. Часто нужны права администратора. Ошибка: $($_.Exception.Message)"
    }
}

function Get-MinecraftScanFolders {
    $paths = @(
        "$env:APPDATA\.minecraft\mods",
        "$env:APPDATA\.minecraft\versions",
        "$env:APPDATA\.minecraft\libraries",
        "$env:APPDATA\.minecraft\config",
        "$env:APPDATA\.minecraft\shaderpacks",
        "$env:APPDATA\.minecraft\resourcepacks",
        "$env:APPDATA\.tlauncher\legacy\Minecraft\game\mods",
        "$env:APPDATA\.tlauncher\legacy\Minecraft\game\versions",
        "$env:APPDATA\.feather\mods",
        "$env:APPDATA\.feather\accounts",
        "$env:APPDATA\.lunarclient\offline\multiver\mods",
        "$env:APPDATA\.lunarclient\offline\files",
        "$env:APPDATA\.badlionclient",
        "$env:LOCALAPPDATA\Packages\Microsoft.MinecraftUWP_8wekyb3d8bbwe"
    )

    if ($ExtraScanPath.Count -gt 0) { $paths += $ExtraScanPath }
    return Get-ExistingUniquePaths -Paths $paths
}

function Invoke-MinecraftFolderCheck {
    Write-Log 'INFO' 'Сканирование папок Minecraft, лаунчеров, модов и библиотек...'
    $folders = Get-MinecraftScanFolders
    if (-not $folders -or $folders.Count -eq 0) {
        Write-Log 'WARN' 'Стандартные папки Minecraft/лаунчеров не найдены.'
        return
    }

    $extensions = @('*.jar','*.zip','*.dll','*.exe','*.json','*.cfg','*.toml','*.properties','*.txt')
    foreach ($folder in $folders) {
        Write-Log 'OK' "Папка для сканирования: $folder"
        foreach ($ext in $extensions) {
            try {
                $files = Get-ChildItem -LiteralPath $folder -Filter $ext -Recurse -File -ErrorAction SilentlyContinue
                foreach ($file in $files) {
                    Scan-CandidateFile -Path $file.FullName -Source $folder
                }
            } catch {
                $script:ReadErrors++
                Write-Log 'WARN' "Ошибка сканирования $folder ($ext): $($_.Exception.Message)"
            }
        }
    }

    Write-Log 'OK' "Сканирование Minecraft-папок завершено. Проверено файлов: $script:ScannedFiles, JAR/ZIP: $script:ScannedJars"
}

function Scan-CandidateFile {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [string]$Source = ''
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    $script:ScannedFiles++

    $item = $null
    try { $item = Get-Item -LiteralPath $Path -ErrorAction Stop } catch { return }

    $ext = ([string]$item.Extension).ToLowerInvariant()
    $name = [string]$item.Name
    $full = [string]$item.FullName
    $sizeMB = [math]::Round(($item.Length / 1MB), 2)

    if ($ext -in @('.jar','.zip') -and $item.Length -gt ($MaxJarMB * 1MB)) {
        Add-Finding -Severity 'Low' -Score 3 -Category 'FileSize' -Title "JAR/ZIP слишком большой, контент-скан пропущен" -Path $full -Evidence "Размер=$sizeMB MB, лимит=$MaxJarMB MB"
        return
    }

    $nameHits = Find-IndicatorsInText -Text $name -Indicators $script:CheatDB.JarNameKeywords
    if ($nameHits.Count -gt 0) {
        Add-Finding -Severity 'High' -Score 40 -Category 'FileName' -Title "Имя файла похоже на чит/кликер" -Path $full -Evidence "Индикаторы=$($nameHits -join ', '), Размер=$sizeMB MB, Source=$Source"
    }

    if ($ext -in @('.jar','.zip','.dll','.exe')) {
        $hash = Get-FileHashSafe -Path $full
        if (-not [string]::IsNullOrWhiteSpace($hash)) {
            Write-Log 'INFO' "SHA256 $hash | $full"
            if ($script:CheatDB.Hashes -contains $hash) {
                Add-Finding -Severity 'Critical' -Score 100 -Category 'HashSignature' -Title 'Файл совпал с SHA256-сигнатурой чита' -Path $full -Evidence "SHA256=$hash"
            }
        }
    }

    if ($ext -in @('.jar','.zip')) {
        $script:ScannedJars++
        Scan-ArchiveForIndicators -ArchivePath $full
    }
    elseif ($ext -in @('.dll','.exe')) {
        if ($nameHits.Count -gt 0) {
            $sig = Get-AuthenticodeInfoSafe -Path $full
            if ($null -ne $sig -and $sig.Status -ne 'Valid') {
                Add-Finding -Severity 'Medium' -Score 25 -Category 'Signature' -Title 'Подозрительный EXE/DLL не имеет валидной подписи' -Path $full -Evidence "Authenticode=$($sig.Status)"
            }
        }
    }
    elseif ($ext -in @('.json','.cfg','.toml','.properties','.txt')) {
        Scan-TextFileForIndicators -Path $full
    }
}

function Scan-TextFileForIndicators {
    param([string]$Path)
    try {
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($item.Length -gt (2MB)) { return }
        $text = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        $hits = Find-IndicatorsInText -Text $text -Indicators $script:CheatDB.SuspiciousStrings
        if ($hits.Count -gt 0) {
            Add-Finding -Severity 'Low' -Score 8 -Category 'ConfigText' -Title 'Конфиг/текстовый файл содержит подозрительные слова' -Path $Path -Evidence "Индикаторы=$($hits -join ', ')"
        }
    } catch {
        $script:ReadErrors++
    }
}

function Scan-ArchiveForIndicators {
    param([string]$ArchivePath)

    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    } catch {
        Write-Log 'WARN' 'Не удалось загрузить System.IO.Compression.FileSystem для чтения JAR/ZIP.'
        return
    }

    $zip = $null
    $archiveHits = @()
    $entryNameHits = @()
    $manifestHints = @()

    try {
        $zip = [System.IO.Compression.ZipFile]::OpenRead($ArchivePath)
        foreach ($entry in $zip.Entries) {
            if ($null -eq $entry) { continue }
            $entryFullName = [string]$entry.FullName

            $entryHits = Find-IndicatorsInText -Text $entryFullName -Indicators $script:CheatDB.SuspiciousStrings
            if ($entryHits.Count -gt 0) { $entryNameHits += $entryHits }

            $shouldRead = $false
            if ($entry.Length -le ($MaxEntryMB * 1MB)) {
                if ($entryFullName -match '\.(class|txt|cfg|json|properties|mf|toml|xml|yml|yaml)$') { $shouldRead = $true }
                if ($entryFullName -match 'META-INF|fabric\.mod\.json|mods\.toml|mcmod\.info|mixins.*\.json') { $shouldRead = $true }
            }

            if (-not $shouldRead) { continue }

            $stream = $null
            $reader = $null
            try {
                $stream = $entry.Open()
                $reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::UTF8, $true)
                $content = $reader.ReadToEnd()
                $hits = Find-IndicatorsInText -Text $content -Indicators $script:CheatDB.SuspiciousStrings
                if ($hits.Count -gt 0) { $archiveHits += $hits }

                if ($entryFullName -match 'META-INF/MANIFEST.MF|fabric\.mod\.json|mods\.toml|mcmod\.info') {
                    $metaHits = Find-IndicatorsInText -Text $content -Indicators $script:CheatDB.JarNameKeywords
                    if ($metaHits.Count -gt 0) { $manifestHints += $metaHits }
                }
            } catch {
                # Некоторые class-файлы читаются криво — это не критично.
            } finally {
                if ($reader) { $reader.Close() }
                if ($stream) { $stream.Close() }
            }
        }
    } catch {
        $script:ReadErrors++
        Write-Log 'WARN' "Не удалось открыть архив $ArchivePath: $($_.Exception.Message)"
    } finally {
        if ($zip) { $zip.Dispose() }
    }

    $archiveHits = @($archiveHits | Select-Object -Unique)
    $entryNameHits = @($entryNameHits | Select-Object -Unique)
    $manifestHints = @($manifestHints | Select-Object -Unique)

    if ($manifestHints.Count -gt 0) {
        Add-Finding -Severity 'High' -Score 42 -Category 'JarMetadata' -Title 'Метаданные JAR похожи на чит-клиент' -Path $ArchivePath -Evidence "Индикаторы=$($manifestHints -join ', ')"
    }

    if ($entryNameHits.Count -gt 0) {
        Add-Finding -Severity 'Medium' -Score 25 -Category 'JarEntries' -Title 'Имена файлов внутри JAR/ZIP содержат подозрительные индикаторы' -Path $ArchivePath -Evidence "Индикаторы=$($entryNameHits -join ', ')"
    }

    if ($archiveHits.Count -gt 0) {
        $score = 20
        $severity = 'Medium'
        if ($archiveHits.Count -ge 5) { $score = 40; $severity = 'High' }
        Add-Finding -Severity $severity -Score $score -Category 'JarContent' -Title 'Контент JAR/ZIP содержит подозрительные строки' -Path $ArchivePath -Evidence "Индикаторы=$($archiveHits -join ', ')"
    }
}

function Invoke-NetworkCheck {
    Write-Log 'INFO' 'Проверка сетевых подключений к известным адресам чит-клиентов...'
    $domains = @()
    $knownIps = @()
    foreach ($server in $script:CheatDB.CheatServers) {
        $ip = $null
        if ([System.Net.IPAddress]::TryParse([string]$server, [ref]$ip)) { $knownIps += [string]$server }
        else { $domains += [string]$server }
    }

    foreach ($domain in $domains) {
        try {
            $resolved = [System.Net.Dns]::GetHostAddresses($domain) | ForEach-Object { $_.IPAddressToString }
            $knownIps += $resolved
        } catch {
            Write-Log 'WARN' "DNS resolve не удался: $domain"
        }
    }
    $knownIps = @($knownIps | Select-Object -Unique)

    $connections = @()
    try {
        $connections = Get-NetTCPConnection -State Established -ErrorAction Stop
    } catch {
        Write-Log 'WARN' "Get-NetTCPConnection недоступен или нет прав. Ошибка: $($_.Exception.Message)"
        return
    }

    foreach ($conn in $connections) {
        if ($knownIps -contains [string]$conn.RemoteAddress) {
            $pname = ''
            try { $pname = (Get-Process -Id $conn.OwningProcess -ErrorAction Stop).ProcessName } catch { }
            Add-Finding -Severity 'High' -Score 45 -Category 'Network' -Title 'Соединение с известным доменом/адресом чит-клиента' -Evidence "Remote=$($conn.RemoteAddress):$($conn.RemotePort), PID=$($conn.OwningProcess), Process=$pname"
        }
    }

    Write-Log 'OK' 'Проверка сети завершена.'
}

function Invoke-StartupAndTaskCheck {
    Write-Log 'INFO' 'Проверка автозагрузки и задач планировщика...'
    $allIndicators = @()
    $allIndicators += $script:CheatDB.ProcessNames
    $allIndicators += $script:CheatDB.JarNameKeywords
    $allIndicators += $script:CheatDB.DllPathKeywords
    $allIndicators = @($allIndicators | Select-Object -Unique)

    $startupPaths = Get-ExistingUniquePaths -Paths @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )

    foreach ($folder in $startupPaths) {
        try {
            $items = Get-ChildItem -LiteralPath $folder -Recurse -File -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                $hits = Find-IndicatorsInText -Text ($item.FullName) -Indicators $allIndicators
                if ($hits.Count -gt 0) {
                    Add-Finding -Severity 'Medium' -Score 22 -Category 'Startup' -Title 'Подозрительный файл в автозагрузке' -Path $item.FullName -Evidence "Индикаторы=$($hits -join ', ')"
                }
            }
        } catch { }
    }

    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop
        foreach ($task in $tasks) {
            $blob = "$($task.TaskName) $($task.TaskPath) "
            try { $blob += (($task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ') } catch { }
            $hits = Find-IndicatorsInText -Text $blob -Indicators $allIndicators
            if ($hits.Count -gt 0) {
                Add-Finding -Severity 'Medium' -Score 24 -Category 'ScheduledTask' -Title 'Задача планировщика содержит подозрительные индикаторы' -Evidence "Task=$($task.TaskPath)$($task.TaskName), Индикаторы=$($hits -join ', ')"
            }
        }
    } catch {
        Write-Log 'WARN' "Не удалось прочитать задачи планировщика: $($_.Exception.Message)"
    }
}

function Invoke-HostsAndPrefetchCheck {
    Write-Log 'INFO' 'Проверка hosts и Prefetch на следы запусков...'
    $domains = @($script:CheatDB.CheatServers | Where-Object { $_ -notmatch '^\d{1,3}(\.\d{1,3}){3}$' })
    $hostsPath = Join-Path $env:WINDIR 'System32\drivers\etc\hosts'
    if (Test-Path -LiteralPath $hostsPath) {
        try {
            $hosts = Get-Content -LiteralPath $hostsPath -Raw -ErrorAction Stop
            $hits = Find-IndicatorsInText -Text $hosts -Indicators $domains
            if ($hits.Count -gt 0) {
                Add-Finding -Severity 'Low' -Score 10 -Category 'Hosts' -Title 'В hosts найдены домены, связанные с чит-клиентами' -Path $hostsPath -Evidence "Домены=$($hits -join ', ')"
            }
        } catch { }
    }

    $prefetch = Join-Path $env:WINDIR 'Prefetch'
    if (Test-Path -LiteralPath $prefetch) {
        try {
            $items = Get-ChildItem -LiteralPath $prefetch -Filter '*.pf' -ErrorAction SilentlyContinue
            foreach ($pf in $items) {
                $hits = Find-IndicatorsInText -Text $pf.Name -Indicators $script:CheatDB.ProcessNames
                if ($hits.Count -gt 0) {
                    Add-Finding -Severity 'Medium' -Score 28 -Category 'Prefetch' -Title 'Prefetch указывает на запуск подозрительной программы' -Path $pf.FullName -Evidence "Индикаторы=$($hits -join ', '), LastWrite=$($pf.LastWriteTime)"
                }
            }
        } catch {
            Write-Log 'WARN' "Не удалось проверить Prefetch: $($_.Exception.Message)"
        }
    }
}

function Invoke-DeepSweep {
    if (-not $Deep) { return }
    Write-Log 'INFO' 'DEEP режим: дополнительная проверка свежих подозрительных файлов в профиле пользователя...'

    $roots = Get-ExistingUniquePaths -Paths @(
        $env:USERPROFILE,
        $env:TEMP,
        $env:LOCALAPPDATA,
        $env:APPDATA
    )

    $indicators = @()
    $indicators += $script:CheatDB.JarNameKeywords
    $indicators += $script:CheatDB.ProcessNames
    $indicators += $script:CheatDB.DllPathKeywords
    $indicators = @($indicators | Select-Object -Unique)

    $cutoff = (Get-Date).AddDays(-30)
    foreach ($root in $roots) {
        try {
            $files = Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -ge $cutoff -and $_.Extension -match '^\.(jar|zip|dll|exe)$' }
            foreach ($file in $files) {
                $hits = Find-IndicatorsInText -Text ($file.FullName) -Indicators $indicators
                if ($hits.Count -gt 0) {
                    Add-Finding -Severity 'Medium' -Score 24 -Category 'DeepSweep' -Title 'Свежий подозрительный файл в профиле пользователя' -Path $file.FullName -Evidence "Индикаторы=$($hits -join ', '), LastWrite=$($file.LastWriteTime)"
                    Scan-CandidateFile -Path $file.FullName -Source 'DeepSweep'
                }
            }
        } catch {
            $script:ReadErrors++
        }
    }
}

# =========================
# ОТЧЁТЫ
# =========================
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

    $status = 'CLEAN'
    $title = 'Критичных признаков читов не найдено'
    $recommendation = 'Можно сохранить отчёт. Если есть сомнения, запусти повторно от администратора и с -Deep.'

    if ($critical -gt 0 -or $score -ge 100) {
        $status = 'CHEAT_LIKELY'
        $title = 'Высокая вероятность чита/инжекта'
        $recommendation = 'Проверь найденные файлы вручную, удали подозрительное ПО только после проверки, перезапусти систему и сделай повторный скан.'
    } elseif ($high -gt 0 -or $score -ge 55) {
        $status = 'SUSPICIOUS_HIGH'
        $title = 'Найдены серьёзные подозрительные признаки'
        $recommendation = 'Проверь найденные JAR/DLL/процессы. Возможны как читы, так и моды с похожими строками.'
    } elseif ($medium -gt 0 -or $score -ge 20) {
        $status = 'SUSPICIOUS_MEDIUM'
        $title = 'Есть средние подозрительные признаки'
        $recommendation = 'Проверь список находок. Эвристика может давать ложные срабатывания на обычные моды.'
    } elseif ($score -gt 0) {
        $status = 'LOW_SIGNALS'
        $title = 'Есть слабые сигналы, критики нет'
        $recommendation = 'Скорее всего это не доказательство чита, но стоит проверить вручную.'
    }

    return [pscustomobject]@{
        Status = $status
        Title = $title
        Score = $score
        Critical = $critical
        High = $high
        Medium = $medium
        Low = @($script:Findings | Where-Object { $_.Severity -eq 'Low' }).Count
        Recommendation = $recommendation
    }
}

function Write-FinalVerdict {
    $verdict = Get-VerdictObject
    Write-Log 'INFO' '========================================'
    if ($verdict.Status -eq 'CHEAT_LIKELY') {
        Write-Log 'CRITICAL' "ВЕРДИКТ: $($verdict.Title) | SCORE=$($verdict.Score)"
    } elseif ($verdict.Status -like 'SUSPICIOUS*') {
        Write-Log 'HIT' "ВЕРДИКТ: $($verdict.Title) | SCORE=$($verdict.Score)"
    } else {
        Write-Log 'OK' "ВЕРДИКТ: $($verdict.Title) | SCORE=$($verdict.Score)"
    }
    Write-Log 'INFO' "Critical=$($verdict.Critical), High=$($verdict.High), Medium=$($verdict.Medium), Low=$($verdict.Low)"
    Write-Log 'INFO' "Рекомендация: $($verdict.Recommendation)"
    Write-Log 'INFO' "TXT отчёт: $script:ReportFile"
    Write-Log 'INFO' "JSON отчёт: $script:JsonReport"
    if (-not $NoHtml) { Write-Log 'INFO' "HTML отчёт: $script:HtmlReport" }
    Write-Log 'INFO' '========================================'
}

function Save-JsonReport {
    $verdict = Get-VerdictObject
    $payload = [pscustomobject]@{
        Tool = 'YRYS CHECKER Advanced'
        Version = $script:ScriptVersion
        RunId = $script:RunId
        StartedAt = $script:RunId
        Computer = $env:COMPUTERNAME
        User = $env:USERNAME
        IsAdmin = $script:IsAdmin
        ScannedFiles = $script:ScannedFiles
        ScannedJars = $script:ScannedJars
        ReadErrors = $script:ReadErrors
        Verdict = $verdict
        Findings = $script:Findings
    }
    try {
        $payload | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $script:JsonReport -Encoding UTF8
    } catch {
        Write-Log 'ERROR' "Не удалось сохранить JSON: $($_.Exception.Message)"
    }
}

function HtmlEncode {
    param($Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Save-HtmlReport {
    if ($NoHtml) { return }
    $verdict = Get-VerdictObject
    $rows = New-Object System.Text.StringBuilder
    foreach ($f in ($script:Findings | Sort-Object @{Expression='Score';Descending=$true}, Severity)) {
        $sevClass = (HtmlEncode $f.Severity).ToLowerInvariant()
        [void]$rows.AppendLine("<tr class='$sevClass'><td>$(HtmlEncode $f.Severity)</td><td>$(HtmlEncode $f.Score)</td><td>$(HtmlEncode $f.Category)</td><td>$(HtmlEncode $f.Title)</td><td class='path'>$(HtmlEncode $f.Path)</td><td>$(HtmlEncode $f.Evidence)</td><td>$(HtmlEncode $f.Recommendation)</td></tr>")
    }

    if ($script:Findings.Count -eq 0) {
        [void]$rows.AppendLine("<tr><td colspan='7' class='clean'>Находок нет</td></tr>")
    }

    $html = @"
<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>YRYS CHECKER Report</title>
<style>
:root{--bg:#0b0506;--panel:#16080a;--panel2:#210b0f;--red:#ff1f3d;--red2:#b00020;--text:#fff3f3;--muted:#d9a2aa;--line:#3a1118;--ok:#35d07f;--warn:#ffcc66;}
*{box-sizing:border-box} body{margin:0;background:radial-gradient(circle at top,#3b0610 0,#120406 35%,#050203 100%);color:var(--text);font-family:Segoe UI,Arial,sans-serif;}
.hero{padding:42px 28px;border-bottom:1px solid var(--line);background:linear-gradient(135deg,#30040a,#090203 70%);box-shadow:0 24px 80px rgba(255,0,40,.18)}
.logo{font-size:54px;line-height:.95;font-weight:900;letter-spacing:2px;color:var(--red);text-shadow:0 0 22px rgba(255,31,61,.75),0 0 4px #fff;text-transform:uppercase;}
.sub{margin-top:12px;color:var(--muted);font-size:17px}.wrap{padding:26px;max-width:1400px;margin:0 auto}.cards{display:grid;grid-template-columns:repeat(5,minmax(160px,1fr));gap:14px;margin-top:-34px}.card{background:linear-gradient(180deg,var(--panel2),var(--panel));border:1px solid var(--line);border-radius:18px;padding:18px;box-shadow:0 12px 40px rgba(0,0,0,.35)}
.k{color:var(--muted);font-size:13px;text-transform:uppercase;letter-spacing:.08em}.v{font-size:28px;font-weight:800;margin-top:6px}.status{color:var(--red);text-shadow:0 0 14px rgba(255,31,61,.5)}
.section{margin-top:22px;background:rgba(22,8,10,.78);border:1px solid var(--line);border-radius:20px;overflow:hidden}.section h2{margin:0;padding:18px 20px;background:#1b070b;border-bottom:1px solid var(--line);color:#fff}.section .body{padding:18px 20px;color:#ffdce1}
table{width:100%;border-collapse:collapse;font-size:13px} th,td{border-bottom:1px solid var(--line);padding:10px;vertical-align:top} th{position:sticky;top:0;background:#260a10;color:#fff;text-align:left} tr.critical td{background:rgba(255,0,40,.18)} tr.high td{background:rgba(255,80,80,.13)} tr.medium td{background:rgba(255,170,0,.10)} tr.low td{background:rgba(255,255,255,.04)} .path{font-family:Consolas,monospace;font-size:12px;word-break:break-all;color:#ffc7cf}.clean{color:var(--ok);font-size:20px;text-align:center;padding:24px}.footer{padding:24px;color:var(--muted);font-size:12px}.pill{display:inline-block;border:1px solid var(--red2);background:rgba(255,31,61,.14);padding:6px 10px;border-radius:999px;color:#ffd7dc}
@media(max-width:900px){.cards{grid-template-columns:1fr 1fr}.logo{font-size:38px}table{font-size:12px}}
</style>
</head>
<body>
<div class="hero">
  <div class="logo">YRYS<br>CHECKER</div>
  <div class="sub">Advanced v$(HtmlEncode $script:ScriptVersion) · Красный строгий отчёт Minecraft/Java проверки · Run $(HtmlEncode $script:RunId)</div>
</div>
<div class="wrap">
  <div class="cards">
    <div class="card"><div class="k">Вердикт</div><div class="v status">$(HtmlEncode $verdict.Status)</div></div>
    <div class="card"><div class="k">Score</div><div class="v">$(HtmlEncode $verdict.Score)</div></div>
    <div class="card"><div class="k">Critical</div><div class="v">$(HtmlEncode $verdict.Critical)</div></div>
    <div class="card"><div class="k">High/Medium</div><div class="v">$(HtmlEncode "$($verdict.High)/$($verdict.Medium)")</div></div>
    <div class="card"><div class="k">Files/JARs</div><div class="v">$(HtmlEncode "$script:ScannedFiles/$script:ScannedJars")</div></div>
  </div>

  <div class="section"><h2>Итог</h2><div class="body">
    <p><span class="pill">$(HtmlEncode $verdict.Title)</span></p>
    <p>$(HtmlEncode $verdict.Recommendation)</p>
    <p>Компьютер: <b>$(HtmlEncode $env:COMPUTERNAME)</b> · Пользователь: <b>$(HtmlEncode $env:USERNAME)</b> · Админ: <b>$(HtmlEncode $script:IsAdmin)</b> · Ошибки чтения: <b>$(HtmlEncode $script:ReadErrors)</b></p>
  </div></div>

  <div class="section"><h2>Находки</h2><div style="overflow:auto;max-height:70vh">
    <table><thead><tr><th>Severity</th><th>Score</th><th>Категория</th><th>Находка</th><th>Путь</th><th>Доказательство</th><th>Рекомендация</th></tr></thead><tbody>
    $rows
    </tbody></table>
  </div></div>

  <div class="footer">YRYS CHECKER ничего не удаляет и не отправляет данные наружу. Эвристика может давать ложные срабатывания: финальное решение всегда проверяй вручную.</div>
</div>
</body>
</html>
"@
    try {
        $html | Set-Content -LiteralPath $script:HtmlReport -Encoding UTF8
    } catch {
        Write-Log 'ERROR' "Не удалось сохранить HTML: $($_.Exception.Message)"
    }
}

# =========================
# МЕНЮ И ЗАПУСК
# =========================
function Start-FullAnalysis {
    Ensure-Directory -Path $script:TempRoot
    "" | Set-Content -LiteralPath $script:LogFile -Encoding UTF8
    "" | Set-Content -LiteralPath $script:ReportFile -Encoding UTF8
    $script:Findings = @()
    $script:ScannedFiles = 0
    $script:ScannedJars = 0
    $script:ReadErrors = 0

    Show-Banner
    Write-Log 'INFO' 'Запуск полного автономного анализа YRYS CHECKER...'
    Initialize-CheatDB
    Invoke-SystemSummary

    if (-not $OnlyMinecraft) {
        Invoke-ProcessAndWindowCheck
        Invoke-StartupAndTaskCheck
        Invoke-HostsAndPrefetchCheck
    } else {
        Write-Log 'INFO' 'Включен -OnlyMinecraft: системная автозагрузка/hosts/prefetch частично пропущены.'
        Invoke-ProcessAndWindowCheck
    }

    Invoke-MinecraftProcessCheck
    Invoke-MinecraftFolderCheck
    Invoke-NetworkCheck
    Invoke-DeepSweep

    Save-JsonReport
    Save-HtmlReport
    Write-FinalVerdict

    if ($OpenReport) {
        if (-not $NoHtml -and (Test-Path -LiteralPath $script:HtmlReport)) {
            Start-Process -FilePath $script:HtmlReport | Out-Null
        } elseif (Test-Path -LiteralPath $script:ReportFile) {
            notepad.exe $script:ReportFile
        }
    }
}

function Show-Menu {
    Ensure-Directory -Path $script:TempRoot
    Initialize-CheatDB
    do {
        Show-Banner
        Write-Console '[1] Полный автономный анализ' Red Black
        Write-Console '[2] Процессы/окна/командные строки' White Black
        Write-Console '[3] Java/Minecraft процессы и JAR' White Black
        Write-Console '[4] Папки Minecraft/моды/библиотеки' White Black
        Write-Console '[5] Сеть' White Black
        Write-Console '[6] Автозагрузка/tasks/hosts/prefetch' White Black
        Write-Console '[O] Открыть последний HTML/TXT отчёт' White Black
        Write-Console '[Q] Выход' Gray Black
        $choice = Read-Host 'Выбери действие'
        switch ($choice.ToUpperInvariant()) {
            '1' { Start-FullAnalysis; Pause }
            '2' { Invoke-ProcessAndWindowCheck; Pause }
            '3' { Invoke-MinecraftProcessCheck; Pause }
            '4' { Invoke-MinecraftFolderCheck; Pause }
            '5' { Invoke-NetworkCheck; Pause }
            '6' { Invoke-StartupAndTaskCheck; Invoke-HostsAndPrefetchCheck; Pause }
            'O' {
                if (-not $NoHtml -and (Test-Path -LiteralPath $script:HtmlReport)) { Start-Process -FilePath $script:HtmlReport }
                elseif (Test-Path -LiteralPath $script:ReportFile) { notepad.exe $script:ReportFile }
                else { Write-Console 'Отчёт ещё не создан.' Yellow Black; Pause }
            }
            'Q' { return }
            default { Write-Console 'Неизвестная команда.' Yellow Black; Start-Sleep -Seconds 1 }
        }
    } while ($true)
}

# Точка входа
try {
    Ensure-Directory -Path $script:TempRoot
    if ($Manual) { Show-Menu } else { Start-FullAnalysis }
} catch {
    try {
        Write-Log 'ERROR' "Критическая ошибка: $($_.Exception.Message)"
        Write-Log 'ERROR' "StackTrace: $($_.ScriptStackTrace)"
    } catch {
        Write-Host "Критическая ошибка: $($_.Exception.Message)" -ForegroundColor Red
    }
    exit 1
}
