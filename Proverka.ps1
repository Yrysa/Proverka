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
    [int]$MaxMinutes = 10,
    [int]$MaxCandidates = 8000,
    [int]$MaxDeepBytes = 524288,
    [int]$Top = 100,
    [int]$MinScore = 18,
    [int]$TraceMinScore = 28,
    [switch]$EvidenceUI,
    [switch]$TraceTimeline,
    [switch]$EntropyScan,
    [switch]$NoHeavyForensics,
    [switch]$NoUSNJournal,
    [switch]$NoDNSCache,
    [switch]$NoNamedPipes,
    [switch]$NoBehaviorChains,
    [int]$USNMaxLines = 1500,
    [int]$ExternalTimeoutSec = 6,
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
    [switch]$ScreenPrivacyGuard,
    [switch]$NoScreenPrivacyGuard,
    [ValidateSet("Warn","Pause","Exit","Block")]
    [string]$ScreenGuardMode = "Warn",
    [int]$ScreenGuardPauseSeconds = 15,
    [int]$ScreenGuardCountdownSeconds = 5,
    [int]$UiWidth = 124
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Continue"

$App = [ordered]@{
    Name = "PROVERKA"
    Version = "1.20.77"
    Started = Get-Date
    Deadline = (Get-Date).AddMinutes([Math]::Max(2, [Math]::Min(120, $MaxMinutes)))
    Width = [Math]::Max(96, [Math]::Min(160, $UiWidth))
    Report = Join-Path (Get-Location) ("PROVERKA_REPORT_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".json")
}

$State = [ordered]@{
    Findings = New-Object 'System.Collections.Generic.List[object]'
    Ignored = New-Object 'System.Collections.Generic.List[object]'
    Events = New-Object 'System.Collections.Generic.List[object]'
    Counters = [ordered]@{ Roots=0; Files=0; Processes=0; Java=0; Modules=0; Minecraft=0; Prefetch=0; Recent=0; Services=0; Tasks=0; Registry=0; Drivers=0; Network=0; Usb=0; Wmi=0; Traces=0; Errors=0 }
}

$Ansi = [ordered]@{ Reset="`e[0m"; Red="`e[38;5;203m"; Green="`e[38;5;83m"; Yellow="`e[38;5;221m"; Purple="`e[38;5;141m"; Cyan="`e[38;5;81m"; Pink="`e[38;5;213m"; Gray="`e[38;5;245m"; White="`e[38;5;255m" }
if ($NoColor -or $Host.Name -match "ISE") { foreach ($k in @($Ansi.Keys)) { $Ansi[$k] = "" } }

function C([string]$Text,[string]$Color){ "$($Ansi[$Color])$Text$($Ansi.Reset)" }
function Fit([string]$Text,[int]$Size){ if($null -eq $Text){$Text=""}; $x=$Text -replace "`r|`n"," "; if($x.Length -gt $Size){$x.Substring(0,[Math]::Max(0,$Size-1))+"…"}else{$x.PadRight($Size)} }
function Line([string]$Char="─",[string]$Color="Purple"){ Write-Host (C ($Char * $App.Width) $Color) }

function Panel([string]$Title,[string[]]$Rows,[string]$Color="Cyan"){
    $w=$App.Width
    Write-Host (C ("╭"+("─"*($w-2))+"╮") $Color)
    Write-Host (C "│" $Color) -NoNewline; Write-Host (C (Fit ("  "+$Title) ($w-2)) "White") -NoNewline; Write-Host (C "│" $Color)
    Write-Host (C ("├"+("─"*($w-2))+"┤") $Color)
    foreach($row in $Rows){ Write-Host (C "│" $Color) -NoNewline; Write-Host (Fit ("  "+$row) ($w-2)) -NoNewline; Write-Host (C "│" $Color) }
    Write-Host (C ("╰"+("─"*($w-2))+"╯") $Color)
}

function Banner{
    Clear-Host
    $logo=@(
        "██████╗ ██████╗  ██████╗ ██╗   ██╗███████╗██████╗ ██╗  ██╗ █████╗ ",
        "██╔══██╗██╔══██╗██╔═══██╗██║   ██║██╔════╝██╔══██╗██║ ██╔╝██╔══██╗",
        "██████╔╝██████╔╝██║   ██║██║   ██║█████╗  ██████╔╝█████╔╝ ███████║",
        "██╔═══╝ ██╔══██╗██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗██╔═██╗ ██╔══██║",
        "██║     ██║  ██║╚██████╔╝ ╚████╔╝ ███████╗██║  ██║██║  ██╗██║  ██║",
        "╚═╝     ╚═╝  ╚═╝ ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝")
    Line "═" "Purple"
    foreach($x in $logo){ Write-Host (C ("  "+$x) "Cyan") }
    Write-Host (C ("  Security scanner build "+$App.Version+"  •  advanced Minecraft forensic UI") "White")
    Line "═" "Purple"
}

function Status([string]$Stage,[string]$Text,[int]$Percent=-1){
    if($NoProgress){return}
    $msg=Fit "$Stage $Text" ([Math]::Max(20,$App.Width-22))
    if($Percent -ge 0){
        $barSize=14; $done=[Math]::Min($barSize,[Math]::Max(0,[int]([double]$Percent/100*$barSize)))
        Write-Host "$(C "▶" "Pink") $(C (("█"*$done)+("░"*($barSize-$done))) "Cyan") $msg $(C (($Percent.ToString().PadLeft(3))+"%") "Yellow")"
    } else { Write-Host "$(C "▶" "Pink") $msg" }
}

function SafeRun([scriptblock]$Body,[string]$Where){ try{ & $Body } catch { $State.Counters.Errors++; Add-Event "error" $Where $_.Exception.Message } }
function Add-Event([string]$Type,[string]$Name,[string]$Value){ $State.Events.Add([pscustomobject]@{time=(Get-Date).ToString("s");type=$Type;name=$Name;value=$Value}) | Out-Null }

function Add-Finding([string]$Type,[string]$Name,[string]$Path,[int]$Score,[string[]]$Reasons,[string]$Meta=""){
    $row=[pscustomobject]@{type=$Type;name=$Name;path=$Path;score=[Math]::Min(100,[Math]::Max(0,$Score));reasons=$Reasons;meta=$Meta}
    if($row.score -lt $MinScore -and -not $ShowIgnored){ $State.Ignored.Add($row) | Out-Null } else { $State.Findings.Add($row) | Out-Null }
}

function Tokens{
    $base=@(
        "vape","raven","rise","drip","entropy","whiteout","slinky","liquidbounce","wurst","meteor","impact","future","rusherhack","phobos","konas","pyro","boze","prestige","thunderhack","bleachhack","forgehax","inertia","sigma","flux","tenacity","zeroday","astolfo","fdp","dope","koid","iridium","autoclicker","clicker","injector","loader","kdmapper","drvmap","spoofer","ghostclient","reach","velocity","aimassist","xray","baritone","killaura","antikb","antiknockback","timer","hitbox","esp","tracers","wallhack","triggerbot","macro","jvmtia","jvmti","agent","nativehook","rawinput","interception","mapper","unsigned","mixin","fabricloader","forgeclient","ghost","silent","selfdestruct","destruct","cleaner","bypass","dll","dlc","client"
    )
    $extra=@(); if($Cheat.Trim().Length -gt 0){ $extra=$Cheat -split "," | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ } }
    @($base+$extra | Sort-Object -Unique)
}

function Score-Item([string]$Name,[string]$Path,[string[]]$Words){
    $score=0; $reasons=New-Object 'System.Collections.Generic.List[string]'; $hay=(($Name+" "+$Path).ToLowerInvariant())
    foreach($t in $Words){ if($t.Length -ge 3 -and $hay.Contains($t)){ $score+=32; $reasons.Add("token:$t") | Out-Null } }
    if($Path -match "\\AppData\\|\\Temp\\|\\Downloads\\|\\Desktop\\|\\.minecraft\\|\\mods\\|\\versions\\|\\libraries\\|\\instances\\|\\shaderpacks\\|\\resourcepacks\\"){ $score+=14; $reasons.Add("user-or-minecraft-path") | Out-Null }
    if($Name -match "\.(jar|dll|exe|ps1|bat|cmd|sys)$"){ $score+=12; $reasons.Add("executable-content") | Out-Null }
    if($Name -match "^[a-f0-9]{12,}\."){ $score+=10; $reasons.Add("hash-like-name") | Out-Null }
    if($Name -match "(?i)(client|loader|agent|inject|clicker|macro|self|clean|temp|cache)"){ $score+=9; $reasons.Add("suspicious-generic-name") | Out-Null }
    [pscustomobject]@{Score=[Math]::Min(100,$score);Reasons=@($reasons)}
}

function Score-Text([string]$Text,[string[]]$Words){
    $score=0; $r=New-Object 'System.Collections.Generic.List[string]'; $hay=([string]$Text).ToLowerInvariant()
    foreach($t in $Words){ if($t.Length -ge 3 -and $hay.Contains($t)){ $score+=28; $r.Add("token:$t") | Out-Null } }
    if($hay -match "-javaagent|-agentpath|-agentlib|jvmti|dll|inject|mixin|tweaker|fabric|forge|liteloader"){ $score+=25; $r.Add("java-or-injection-argument") | Out-Null }
    if($hay -match "\.minecraft|mods|versions|libraries|instances"){ $score+=10; $r.Add("minecraft-commandline") | Out-Null }
    [pscustomobject]@{Score=[Math]::Min(100,$score);Reasons=@($r)}
}

function Roots{
    $r=New-Object 'System.Collections.Generic.List[string]'; $home=[Environment]::GetFolderPath("UserProfile")
    $candidates=@(
        (Join-Path $home "Downloads"),(Join-Path $home "Desktop"),(Join-Path $home "Documents"),(Join-Path $home "AppData\Roaming\.minecraft"),(Join-Path $home "AppData\Roaming\.tlauncher"),(Join-Path $home "AppData\Roaming\PrismLauncher"),(Join-Path $home "AppData\Roaming\PolyMC"),(Join-Path $home "AppData\Roaming\MultiMC"),(Join-Path $home "AppData\Roaming\ModrinthApp"),(Join-Path $home "AppData\Roaming\ATLauncher"),(Join-Path $home "AppData\Local\Temp"),(Join-Path $home "AppData\Local\Packages"),(Join-Path $env:PROGRAMDATA ""),(Join-Path $env:APPDATA "Discord"),(Join-Path $env:LOCALAPPDATA "Google\Chrome\User Data")
    )
    foreach($p in $candidates){ if($p -and (Test-Path $p)){ $r.Add($p) | Out-Null } }
    if($AllDrives -or $FullSystem){ Get-PSDrive -PSProvider FileSystem | ForEach-Object { if($_.Root -and (Test-Path $_.Root)){ $r.Add($_.Root) | Out-Null } } }
    if($OnlyMinecraft){ @($r | Where-Object { $_ -match "minecraft|tlauncher|PrismLauncher|PolyMC|MultiMC|ModrinthApp|ATLauncher" } | Sort-Object -Unique) } else { @($r | Sort-Object -Unique) }
}

function Scan-JavaRuntime([string[]]$Words){
    Status "LIVE" "java, launchers and command lines" 12
    SafeRun {
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "(?i)javaw?\.exe|Minecraft|Launcher|Prism|MultiMC|PolyMC|Lunar|Badlion|Feather|TLauncher|Modrinth|CurseForge|Overwolf|Pulse" -or $_.CommandLine -match "(?i)\.minecraft|javaagent|agentpath|jvmti|fabric|forge|mods|versions" } | ForEach-Object {
            $State.Counters.Java++
            $text=($_.Name+" "+$_.ExecutablePath+" "+$_.CommandLine)
            $s=Score-Text $text $Words
            $score=[Math]::Max(25,$s.Score)
            $rs=@($s.Reasons)
            if($_.Name -match "(?i)javaw?\.exe"){ $score+=10; $rs+="running-java" }
            if($_.CommandLine -match "(?i)-javaagent|-agentpath|-agentlib|jvmti"){ $score+=40; $rs+="agent-load" }
            if($_.CommandLine -match "(?i)mods|fabric|forge|liteloader|tweaker"){ $score+=18; $rs+="modded-runtime" }
            Add-Finding "live-java" $_.Name ([string]$_.ExecutablePath) $score $rs ("pid=$($_.ProcessId); cmd="+[string]$_.CommandLine)
        }
    } "java-runtime"
}

function Scan-ProcessModules([string[]]$Words){
    Status "LIVE" "loaded dll modules" 22
    SafeRun {
        Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match "(?i)java|javaw|minecraft|launcher|pulse|lunar|badlion|feather|prism|multimc|polymc|modrinth|curseforge|overwolf" } | ForEach-Object {
            $p=$_
            SafeRun {
                foreach($m in $p.Modules){
                    $State.Counters.Modules++
                    $file=[string]$m.FileName
                    $s=Score-Item $m.ModuleName $file $Words
                    $score=$s.Score
                    $rs=@($s.Reasons)
                    if($file -match "\\Temp\\|\\AppData\\|\\Downloads\\|\\Desktop\\"){ $score+=25; $rs+="module-user-path" }
                    if($m.ModuleName -match "(?i)hook|inject|agent|click|macro|overlay|interception|rawinput"){ $score+=25; $rs+="module-name-signal" }
                    if($score -ge $TraceMinScore -or $ShowIgnored){ Add-Finding "module" $m.ModuleName $file $score $rs ("process=$($p.ProcessName);pid=$($p.Id)") }
                }
            } "modules:$($p.Id)"
        }
    } "modules"
}

function Scan-MinecraftInventory([string[]]$Words){
    Status "MINECRAFT" "mods, versions, libraries and instances" 36
    $home=[Environment]::GetFolderPath("UserProfile")
    $targets=@(
        (Join-Path $home "AppData\Roaming\.minecraft\mods"),(Join-Path $home "AppData\Roaming\.minecraft\versions"),(Join-Path $home "AppData\Roaming\.minecraft\libraries"),(Join-Path $home "AppData\Roaming\.minecraft\config"),(Join-Path $home "AppData\Roaming\PrismLauncher\instances"),(Join-Path $home "AppData\Roaming\PolyMC\instances"),(Join-Path $home "AppData\Roaming\MultiMC\instances"),(Join-Path $home "AppData\Roaming\ModrinthApp\profiles"),(Join-Path $home "AppData\Roaming\.tlauncher"),(Join-Path $home "AppData\Roaming\ATLauncher\instances")
    )
    foreach($root in $targets){
        if(Test-Path $root){
            SafeRun {
                Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction SilentlyContinue -Include *.jar,*.json,*.toml,*.cfg,*.dll,*.exe | Select-Object -First 6000 | ForEach-Object {
                    $State.Counters.Minecraft++
                    $s=Score-Item $_.Name $_.FullName $Words
                    $score=$s.Score
                    $rs=@($s.Reasons)
                    if($_.Extension -eq ".jar" -and $_.FullName -match "\\mods\\"){ $score+=18; $rs+="minecraft-mod-jar" }
                    if($_.FullName -match "(?i)\\versions\\" -and $_.Name -match "(?i)fabric|forge|quilt|lunar|badlion|feather|client|loader"){ $score+=20; $rs+="custom-version" }
                    if($score -ge $TraceMinScore -or $ShowIgnored){ Add-Finding "minecraft" $_.Name $_.FullName $score $rs "modified=$($_.LastWriteTime.ToString("s"));size=$($_.Length)" }
                }
            } "minecraft:$root"
        }
    }
}

function Scan-PrefetchRecent([string[]]$Words){
    Status "TRACE" "prefetch and recent files" 48
    $targets=@("$env:SystemRoot\Prefetch", (Join-Path ([Environment]::GetFolderPath("Recent")) ""), (Join-Path $env:APPDATA "Microsoft\Windows\Recent"))
    foreach($root in $targets){
        if(Test-Path $root){
            SafeRun {
                Get-ChildItem -LiteralPath $root -File -Force -ErrorAction SilentlyContinue | Select-Object -First 3000 | ForEach-Object {
                    if($root -match "Prefetch"){ $State.Counters.Prefetch++ } else { $State.Counters.Recent++ }
                    $s=Score-Item $_.Name $_.FullName $Words
                    $score=$s.Score
                    $rs=@($s.Reasons)
                    if($_.Name -match "(?i)JAVA|JAVAW|MINECRAFT|LAUNCHER|CLICKER|INJECT|LOADER|CLEAN|VAPE|RAVEN|SLINKY|ENTROPY|DRIP"){ $score+=28; $rs+="execution-trace-name" }
                    if($score -ge $TraceMinScore -or $ShowIgnored){ Add-Finding "execution-trace" $_.Name $_.FullName $score $rs "modified=$($_.LastWriteTime.ToString("s"))" }
                }
            } "prefetch-recent:$root"
        }
    }
}

function Scan-Files([string[]]$Words){
    $roots=Roots; $State.Counters.Roots=$roots.Count
    $limit=if($Deep -or $FullSystem){[Math]::Max($MaxCandidates,18000)}elseif($Fast){[Math]::Min($MaxCandidates,2500)}else{$MaxCandidates}
    $seen=0; $patterns=@("*.jar","*.exe","*.dll","*.sys","*.ps1","*.bat","*.cmd","*.json","*.txt","*.log","*.cfg","*.toml","*.zip","*.rar","*.7z")
    foreach($root in $roots){
        if((Get-Date) -gt $App.Deadline){break}
        Status "SCAN" $root ([int](($seen/[Math]::Max(1,$limit))*100))
        SafeRun {
            Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction SilentlyContinue -Include $patterns | Select-Object -First ([Math]::Max(1,$limit-$seen)) | ForEach-Object {
                $seen++; $State.Counters.Files++; $s=Score-Item $_.Name $_.FullName $Words
                $score=$s.Score; $rs=@($s.Reasons)
                if($_.FullName -match "(?i)\\Temp\\|\\Downloads\\|\\Desktop\\" -and $_.Extension -match "(?i)\.(exe|dll|jar|sys)"){ $score+=16; $rs+="risky-location" }
                if($_.Length -lt 4096 -and $_.Extension -match "(?i)\.(exe|dll|jar)"){ $score+=8; $rs+="tiny-executable" }
                if($score -ge $MinScore -or $ShowIgnored){ Add-Finding "file" $_.Name $_.FullName $score $rs "size=$($_.Length);modified=$($_.LastWriteTime.ToString("s"))" }
                if($seen -ge $limit -or (Get-Date) -gt $App.Deadline){ return }
            }
        } "scan:$root"
        if($seen -ge $limit){break}
    }
}

function Scan-Processes([string[]]$Words){
    Status "CHECK" "all processes" 18
    SafeRun {
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
            $State.Counters.Processes++
            $text=($_.Name+" "+$_.ExecutablePath+" "+$_.CommandLine)
            $s=Score-Text $text $Words
            if($s.Score -ge $MinScore -or $ShowIgnored){ Add-Finding "process" $_.Name ([string]$_.ExecutablePath) $s.Score $s.Reasons ("pid=$($_.ProcessId); cmd="+[string]$_.CommandLine) }
        }
    } "processes"
}

function Scan-ServicesAndTasks([string[]]$Words){
    Status "CHECK" "services and scheduled tasks" 58
    SafeRun { Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | ForEach-Object { $State.Counters.Services++; $s=Score-Item $_.Name $_.PathName $Words; if($_.PathName -match "\\AppData\\|\\Temp\\|\\Downloads\\"){ $s.Score=[Math]::Min(100,$s.Score+25); $s.Reasons=@($s.Reasons)+"service-user-path" }; if($s.Score -ge $MinScore -or $ShowIgnored){ Add-Finding "service" $_.Name $_.PathName $s.Score $s.Reasons "state=$($_.State)" } } } "services"
    SafeRun { Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object { $State.Counters.Tasks++; $joined=($_.Actions | ForEach-Object { $_.Execute+" "+$_.Arguments }) -join " "; $s=Score-Text ($_.TaskName+" "+$joined) $Words; if($s.Score -ge $MinScore -or $ShowIgnored){ Add-Finding "task" $_.TaskName $_.TaskPath $s.Score $s.Reasons $joined } } } "tasks"
}

function Scan-Registry([string[]]$Words){
    Status "CHECK" "registry autoruns" 66
    foreach($key in @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Run","HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce","HKLM:\Software\Microsoft\Windows\CurrentVersion\Run","HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce","HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run")){
        SafeRun { if(Test-Path $key){ (Get-ItemProperty -Path $key -ErrorAction SilentlyContinue).PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object { $State.Counters.Registry++; $s=Score-Text ($_.Name+" "+[string]$_.Value) $Words; if($s.Score -ge $MinScore -or $ShowIgnored){ Add-Finding "registry" $_.Name $key $s.Score $s.Reasons ([string]$_.Value) } } } } "registry:$key"
    }
}

function Scan-Drivers([string[]]$Words){
    if(-not $Drivers -and -not $Forensic -and -not $FullSystem){return}; Status "KERNEL" "drivers" 74
    SafeRun { Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | ForEach-Object { $State.Counters.Drivers++; $s=Score-Item $_.Name $_.PathName $Words; $rs=@($s.Reasons); $score=$s.Score; if($_.PathName -match "\\Temp\\|\\AppData\\|\\Downloads\\"){ $score+=35; $rs+="driver-user-path" }; if($_.State -eq "Running"){ $score+=5; $rs+="running" }; if($score -ge $MinScore -or $ShowIgnored){ Add-Finding "driver" $_.Name $_.PathName $score $rs "state=$($_.State)" } } } "drivers"
}

function Scan-Network{ if($NoDNSCache){return}; Status "TRACE" "network cache" 80; SafeRun { ipconfig /displaydns 2>$null | Select-String -Pattern "Record Name" | ForEach-Object { $State.Counters.Network++; $line=$_.Line.Trim(); if($line -match "pastebin|githubusercontent|cdn.discordapp|anonfiles|gofile|mediafire|workupload|mega|dropbox|pixeldrain"){ Add-Finding "dns" $line "" 32 @("download-domain") "" } } } "dns" }
function Scan-Usb{ if($NoUSBForensics -or (-not $USBForensics -and -not $Forensic -and -not $FullSystem)){return}; Status "TRACE" "usb history" 84; SafeRun { Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*" -ErrorAction SilentlyContinue | ForEach-Object { $State.Counters.Usb++; Add-Event "usb" $_.PSChildName ([string]$_.FriendlyName) } } "usb" }
function Scan-Wmi{ if($NoWMIForensics -or (-not $WMIForensics -and -not $Forensic -and -not $FullSystem)){return}; Status "TRACE" "wmi persistence" 88; SafeRun { Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue | ForEach-Object { $State.Counters.Wmi++; Add-Finding "wmi" $_.Name "root\subscription" 45 @("event-filter") ([string]$_.Query) }; Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue | ForEach-Object { $State.Counters.Wmi++; Add-Finding "wmi" $_.Name "root\subscription" 60 @("command-consumer") ([string]$_.CommandLineTemplate) } } "wmi" }

function Scan-Traces([string[]]$Words){
    if(-not $BrowserForensics -and -not $DiscordForensics -and -not $Forensic -and -not $FullSystem){return}; Status "TRACE" "browser and discord files" 92
    $targets=@(); if(-not $NoBrowserForensics){ $targets+=Join-Path $env:LOCALAPPDATA "Google\Chrome\User Data\Default\History"; $targets+=Join-Path $env:LOCALAPPDATA "Microsoft\Edge\User Data\Default\History" }; if(-not $NoDiscordForensics){ $targets+=Join-Path $env:APPDATA "discord\Local State"; $targets+=Join-Path $env:APPDATA "discord\settings.json" }
    foreach($p in $targets){ if(Test-Path $p){ $State.Counters.Traces++; Add-Finding "trace" (Split-Path $p -Leaf) $p 18 @("trace-present") "" } }
}

function VM-Signals{ if(-not $VMCheck){return}; Status "CHECK" "environment" 94; SafeRun { $cs=Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue; $bios=Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue; $text=(($cs.Manufacturer+" "+$cs.Model+" "+$bios.SerialNumber)-join " ").ToLowerInvariant(); if($text -match "virtualbox|vmware|qemu|xen|hyper-v|parallels"){ Add-Finding "environment" "virtualization-signal" "" 25 @("vm-string") $text } } "vm" }

function Verdict([int]$Score){ if($Score -ge 70){"DETECTED"} elseif($Score -ge 40){"SUSPICIOUS"} else {"TRACE"} }

function Save-Report{
    $data=[ordered]@{ app=$App.Name; version=$App.Version; started=$App.Started.ToString("s"); finished=(Get-Date).ToString("s"); mode=[ordered]@{fast=[bool]$Fast;deep=[bool]$Deep;fullSystem=[bool]$FullSystem;forensic=[bool]$Forensic;strictEvidence=[bool]$StrictEvidence}; counters=$State.Counters; findings=@($State.Findings | Sort-Object score -Descending | Select-Object -First $Top); ignored=@($State.Ignored | Sort-Object score -Descending | Select-Object -First $Top); events=@($State.Events) }
    $data | ConvertTo-Json -Depth 8 | Set-Content -Path $App.Report -Encoding UTF8
}

function Show-Results{
    $f=@($State.Findings | Sort-Object score -Descending | Select-Object -First $Top); $critical=@($f | Where-Object {$_.score -ge 70}).Count; $medium=@($f | Where-Object {$_.score -ge 40 -and $_.score -lt 70}).Count; $low=@($f | Where-Object {$_.score -lt 40}).Count
    Panel "SUMMARY" @("Version: $($App.Version)","Findings: $($f.Count)   Detected: $critical   Suspicious: $medium   Trace: $low","Live Java: $($State.Counters.Java)   Modules: $($State.Counters.Modules)   Minecraft items: $($State.Counters.Minecraft)","Files: $($State.Counters.Files)   Prefetch: $($State.Counters.Prefetch)   Recent: $($State.Counters.Recent)","Report: $($App.Report)") "Purple"
    if($f.Count -gt 0){ Panel "TOP FINDINGS" @($f | Select-Object -First ([Math]::Min(16,$f.Count)) | ForEach-Object { ("[{0}] {1,3} • {2} • {3} • {4}" -f (Verdict $_.score),$_.score,$_.type,$_.name,($_.reasons -join ",")) }) "Yellow" } else { Panel "RESULT" @("No suspicious items reached the selected threshold.") "Green" }
}

function Self-Test{ Banner; Panel "SELF TEST" @("PowerShell: $($PSVersionTable.PSVersion)","Build: $($App.Version)","Report path: $($App.Report)","Color mode: $(-not $NoColor)","Width: $($App.Width)") "Green" }

function Main{
    if($SelfTest){ Self-Test; return }
    Banner
    if($ScreenPrivacyGuard -and -not $NoScreenPrivacyGuard){ Panel "SCREEN GUARD" @("Mode: $ScreenGuardMode","Use a private workspace before continuing.") "Yellow"; if($ScreenGuardMode -eq "Pause"){Start-Sleep -Seconds $ScreenGuardPauseSeconds}; if($ScreenGuardMode -eq "Exit"){return} }
    $words=Tokens
    Panel "RUN CONFIG" @("Mode: $(if($FullSystem){"full system"}elseif($Deep){"deep"}elseif($Fast){"fast"}else{"standard + live forensic"})","Forensic: $([bool]$Forensic)   Drivers: $([bool]$Drivers)   VM: $([bool]$VMCheck)","Max candidates: $MaxCandidates   Time limit: $MaxMinutes min   Threshold: $MinScore","Rule tokens: $($words.Count)") "Cyan"
    if(-not $NoPrompt){ Write-Host (C "Press Enter to start scan..." "Gray") -NoNewline; [void][Console]::ReadLine() }
    Scan-JavaRuntime $words
    Scan-ProcessModules $words
    Scan-Processes $words
    Scan-MinecraftInventory $words
    Scan-PrefetchRecent $words
    Scan-ServicesAndTasks $words
    Scan-Registry $words
    Scan-Drivers $words
    Scan-Network
    Scan-Usb
    Scan-Wmi
    Scan-Traces $words
    VM-Signals
    Scan-Files $words
    Status "DONE" "writing report" 100
    Save-Report
    Show-Results
    if($OpenReport){ Invoke-Item $App.Report }
}

Main
