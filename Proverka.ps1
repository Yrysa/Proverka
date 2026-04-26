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
    [int]$MaxMinutes = 8,
    [int]$MaxCandidates = 3500,
    [int]$MaxDeepBytes = 524288,
    [int]$Top = 80,
    [int]$MinScore = 20,
    [int]$TraceMinScore = 35,
    [switch]$EvidenceUI,
    [switch]$TraceTimeline,
    [switch]$EntropyScan,
    [switch]$NoHeavyForensics,
    [switch]$NoUSNJournal,
    [switch]$NoDNSCache,
    [switch]$NoNamedPipes,
    [switch]$NoBehaviorChains,
    [int]$USNMaxLines = 1200,
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
    [int]$UiWidth = 110
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Continue"

# YRYS CHECKER v22 SAFE REFAC
# - One Main(), one pipeline, no duplicate v12/v13/v16 entry points.
# - Screen privacy uses SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE).
# - Rule tokens are not stored as plaintext; evidence reports hashed rule IDs.
# - Environment/debug/VM checks are transparent risk signals only. The script does NOT fake clean results,
#   silently crash, kill tools, or hide from analysts.

$script:Config = [ordered]@{
    Version = "22.0-safe-refactor"
    StartTime = Get-Date
    Deadline = (Get-Date).AddMinutes([Math]::Max(2, [Math]::Min(60, $MaxMinutes)))
    TempRoot = Join-Path $env:TEMP ("YRYS_CHECKER_" + ([Guid]::NewGuid().ToString("N")))
    UiWidth = [Math]::Max(96, [Math]::Min(160, $UiWidth))
    Salt = "YRYSv22|"
    ReportPath = Join-Path (Get-Location) ("YRYS_REPORT_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".json")
}

$script:State = [ordered]@{
    IsElevated = $false
    AdminMethod = "not_checked"
    ScreenPrivacy = "not_started"
    Findings = New-Object 'System.Collections.Generic.List[object]'
    Ignored = New-Object 'System.Collections.Generic.List[object]'
    HashCache = @{}
    SigCache = @{}
    RuleIndex = @{}
    Counters = [ordered]@{
        Roots = 0; Candidates = 0; Files = 0; Processes = 0; Registry = 0
        Tasks = 0; DNS = 0; USN = 0; WMI = 0; Modules = 0; Browser = 0
        Discord = 0; EnvSignals = 0; BlockedErrors = 0; Suppressed = 0
    }
}

$script:TrustedVendorTokens = @(
    "microsoft","windows","nvidia","amd","intel","oracle","adoptium","eclipse adoptium","mojang","minecraft",
    "lunar client","badlion","feather","modrinth","curseforge","overwolf","steam","discord","google","mozilla",
    "valve","epic games","java","openjdk","jetbrains","github","visual studio","logitech","razer","steelseries",
    "corsair","asus","lenovo","hp","dell","realtek","apple","adobe"
)

$script:TrustedPathFragments = @(
    "\windows\system32\","\windows\syswow64\","\windows\winsxs\","\windows\servicing\",
    "\program files\nvidia corporation\","\program files (x86)\nvidia corporation\","\program files\amd\",
    "\program files\intel\","\program files\java\","\program files\eclipse adoptium\",
    "\program files\microsoft\","\program files (x86)\microsoft\","\program files\windowsapps\",
    "\programdata\nvidia corporation\","\programdata\microsoft\windows defender\"
)

$script:UserWritableFragments = @(
    "\appdata\","\temp\","\downloads\","\desktop\","\documents\","\programdata\","\users\public\",
    "\startup\","\recent\","\.minecraft\","\.tlauncher\","\prismlauncher\","\polymc\","\multimc\",
    "\gdlauncher\","\atlauncher\","\modrinthapp\","\curseforge\","\overwolf\","\lunarclient\","\feather\",
    "\badlion client\"
)

$script:WeakAlone = @(
    "client","loader","module","mod","api","gui","service","update","helper","driver","host","render","graphics",
    "overlay","moon","dream","winter","summer","impact","velocity","thread","packet","mixin","event"
)

# Hashed knowledge base. To update:
#   1) Keep plaintext tokens outside this scanner.
#   2) Run: [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes("YRYSv22|" + $token.ToLowerInvariant()))).Replace("-","")
#   3) Add a rule object below. Do not commit plaintext tokens.
$script:YrysHashRules = @(
    [pscustomobject]@{ Id='KB0001'; Hash='1C43129BB09471D21EEB17808B0BD35AC709A0442E29941CA1257CDE6F59DF24'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0002'; Hash='033894B23D887F7068886E6D9950FACDFABF38AC06D04854450AFBE8710B4AF8'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0003'; Hash='4BF2FC6B5687A95287A69FB1514A4A378CAF1E0CB98A1D799566DBECAD6F7CC1'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0004'; Hash='6B5EA5CC606FC7A3D309DBBF3D098466F2CBEB746E50CB78A18D9322F692D850'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0005'; Hash='95461CA394A07CE3AC34887962FFE052EFC7E4702BC655176D96E92873289145'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0006'; Hash='146412226683D2EC46995A1754477660242CEA271B935AC0FDAA376C9471A3FA'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0007'; Hash='995A9DA4370E460F8C1BF87F9DFEED145A8D42DCA45AB21BAEA5AD69F4742704'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0008'; Hash='D0974E2C3EE03314ABB5B100F5B17A77BF4FCF9D641F4870098698032C7E1D51'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0009'; Hash='5D60E42E08A0D03F45493F46CEE90CACD7AB37E7DDF84167520CFF25FFEFD45D'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0010'; Hash='3772C057B286523CFA2B8A2FCFCB0D4B72E89B2C00A6380DF7E6B877FA7C4604'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0011'; Hash='E55335EB70D3C7A68C29CDE20B9962EBE52A0031ED0A1F7468456E38DF63BE44'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0012'; Hash='CF2E122BF6DB9BF4EE019EB94604AC70EA68DEE6616E5650EEC03EBC5A326817'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0013'; Hash='E8FB3BBA6A4ED9C680E10AFBC90FE08DC2EF209DD178A677A71D4057ECF8CA91'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0014'; Hash='72142FF0ECED4898FB3BACF421A4EC0682E3FAD4D88AAD4193B33F8306206A2D'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0015'; Hash='EF618014BF65604020771946C82E6B7405264EDA09C08C3C3358E981AA25902E'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0016'; Hash='A5363FFAA8DC8E64019D6E3DC614430823C8FD28F509D0657228C16E0ED5AD98'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0017'; Hash='5EBCA9E186A74FD8C6D505766224622142D21A21AF1D8DF14E5858C6D6CE9E33'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0018'; Hash='5B5FAA818C076D23919834D5EC561B13F704CADBBED530D7DC6C0A7436CDCB22'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0019'; Hash='8064BB3E7DA5774922E570FFCF461E06DBDC8AC928927312868620667A3F859E'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0020'; Hash='0E27F72A428A6109BAA7BEDECEA0888BE24BC7E296A941423486BD62833F26AC'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0021'; Hash='630BA40A109517C2714E9C0AB385D063224CC110111016F219A106E0A326942C'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0022'; Hash='AA617E11A848E9081728D65206A1C1012391AA8D519B55B4AB58AF6C067C32BA'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0023'; Hash='1AC43A66B3CC8B51EE0FB0D72EF01C350BD5E5B18779B7E7E54DB1EDBC68B71B'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0024'; Hash='CA8D7E6371DBAA8219232CB51F44DEA4C576360E66269E9DE05EA5D25DDB9F22'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0025'; Hash='E7BDEAAE51D9A74697E1E7B7B0541086891F06CCD85D769C19B23F7EFBBF5B80'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0026'; Hash='E5803DCFF1DA12CAC1D50F1ECAA4BBECC89DC94969FC7505EF88E80946F1BD7B'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0027'; Hash='E60704B700789353DBBC401B8ECFBC38809E2EF9DDB55941920B2E41A1F63AF6'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0028'; Hash='1A717A56915030EEFB68AB2AE7D97694C8599359569531D1337CC343C1BD4635'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0029'; Hash='01A2AC6DF7F7B9E364F366A98BAE13891766E565E50255138D1DE1BF5B47497E'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0030'; Hash='682A7879871CA357B4E62577D04468DC1EC088357D2DD128328CB14B3D33718C'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0031'; Hash='4E6060E6E40F7C6ECB1BC088EE44D0C58F548E980D1BB783706F371BADF84071'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0032'; Hash='DF445E8E4DBD525D3E46FC0AAFF04EEAB8B8FBE54E1F89149B07D2075D8A551A'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0033'; Hash='34526A751658C5960CA58D5F77899B86E2BDB9E74A53EBD1A78D199318FF2B50'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0034'; Hash='81E5AB5CDA751AA179EAFDA26644A773E6E157AFF099AF18F0A2354D6B5A2512'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0035'; Hash='E04FF36DB2E2AFC4A5216F462BE7DC174285473F864BE9D410D7182F4B3BB3C4'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0036'; Hash='B37643E4DA4B42CA81A783693C2070881F800ABD01E97D501EB675F20E6017D8'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0037'; Hash='F672DCF0F7EF3C3E29CCA1AB039FD871DAB36D9523EE6D7DFCE3B70E621B443C'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0038'; Hash='2498E04ACD5DD4DEA67AB07887E7F2B1B9760274194D74E060BDB5D5E68B9C21'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0039'; Hash='5048EC6F5602B520109E985A94B1CF6C991FD08F675718305E70602C23C39CF8'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0040'; Hash='3E3FDB714D769D0A4DF1E51D51053D7EC838A02E1B293A465CAEF8DA7A28B7D2'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0041'; Hash='2026243AC50586783A78FEF05350CB6C5CAFDA68D18B597342AB822AB5F24509'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0042'; Hash='9BE1E5F18607CBAAB0C9DBF97CE7684E2CD7A716987FF98D691BB75BCFBE2A99'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0043'; Hash='DA52E1C8F6E1B7ABA07537ED74ADFAE3A8925498636644E5290FED397BD4DCE7'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0044'; Hash='879A2F708FFBFB335DD49BD46CF4EF8930DE9FC25E8EC164468670BBB40AE892'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0045'; Hash='AFD6AD6C0C702677200E88DB7F038A957A46CF3EF34064EDE2C829D5723B955F'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0046'; Hash='2AFDDE041770AEACC89FACF04F138CCFAFC4D9889623BE861F86F5529C3A571C'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0047'; Hash='DE04EA4443BA80A758AC58958C43C36E4B11E1B300A50533B8C6AFB0AC08BFA0'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0048'; Hash='2CF19BE556FABF7F36474BD1629CD5D1E4585AB421C84D84B010C0E3ECF87DF3'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0049'; Hash='294ADF945E65A533FD9EA145179CB12E640E10E4DD584EB0643826F32A9815E3'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0050'; Hash='5FE50E8A02D07D140527187CA627466D3C47ACA843A40D8230A77EEA6B9A41ED'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0051'; Hash='193B9FF2C1A9FD6ADC50CC6A336898AD56C2C4FA421C981DD49F8DB8F842BF74'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0052'; Hash='E10923530575F88198A54D158C282185D279FC8C1A5231FD4C808AD9CF40654E'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0053'; Hash='0498204C6E3D20A28E6EE14A15A15EE32A624660D99E9EBD1EAA76F2CDCB5758'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0054'; Hash='9AFC32A3C19788B875A39CB77DAF3B3178F7D578FA3008BE4CFC8558E2D64BC5'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0055'; Hash='B73BFF17D9CB37902228921295EE0B5D91F96BAE405AE3B71DEF211A20E97453'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0056'; Hash='C88839FE46F59A40AF0AE13B88316918EA16FDA165C4768C849CA8568A57B519'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0057'; Hash='A75F43E5E331E3494ABCBBFABF773EFA758A37A0568EDB7545082BC091A93A0D'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0058'; Hash='CF16A65D9607BCFE511F735750AA83449FF88F9FDB9F30176550D603D959FC2E'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0059'; Hash='B1498A73CC4552FC02E3B454FB79B36C1C54F1F7F4D4F72D5FC78179503F1998'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0060'; Hash='D0E9D52AEFC2C76D0DFA2E00F0E8F8520A95B61EC76A61417D5F0758084A7B00'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0061'; Hash='33AC122273457A601F397139CA13FCD35847041B81D9AF11C89F9CBC68AF73CD'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0062'; Hash='8F99EC27EA26E54DAFCC822305C9A55A450268FBAAD4ACACFB29865FF1297250'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0063'; Hash='1917360F3C1B5A764792A8B713007815338F8C8F5BBB6995C7195A0B72990E51'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0064'; Hash='6A00AB2C5338776F52F458579207249012FB241D47448B65A13B7FD5C7ABB2FF'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0065'; Hash='9A928A5EFB0250885C2148E97A75A6222F7C3606AD9622FFA14D1F7EC1E3F738'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0066'; Hash='34331D339EBE8D0D18EA5A5ACA1110A379501FA909507557425C4D99CA9F541B'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0067'; Hash='E3F5D3EF35BA073EBC5C065F50AE2198D10FEB7E666FCEDD7446D8B20D889F17'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0068'; Hash='69C3AAD83E92B1DF95D0A0F3774F4D8CE28BB60B501D5CA9DC909235E1115EBC'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0069'; Hash='4E5769FC9F549B4BCB5795CD1A347A7EBB8987E9819C9B11FB28131E28EEE643'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0070'; Hash='E0DCBD1988E8B4DB0CBEB665A634FCE9201E83652837C6D61E7D062F07C4E64B'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0071'; Hash='E3B5F7C6716AE7FB83E6CDA8A180192267D2DEEED5B55C10BD9CB516CC04EDA5'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0072'; Hash='286634ED5CE52337EB1195991691978C411025B3CD3FE8DC9B1B07C773F87E4D'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0073'; Hash='4A3811B530AD78139A9E05D6C1710D7EBB0388CEEEE7C49CB14A500780CB1728'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0074'; Hash='91902CF30D99B6D201AFC2A8224C72BD7A8F3EFD4C482581ECD7EBF5CF8F7240'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0075'; Hash='C66BBE388C7DBCD197883F875BCD2DE90098DB42D2EE39CFA11D61A42F1A522F'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0076'; Hash='5D4639C374DD31737466CEF84C6CAD4A16CD74AFCE80564874D8C407A6331DF5'; Category='cheat_name'; Weight=85; Strong=$true },
    [pscustomobject]@{ Id='KB0077'; Hash='4F46BCF3BCC9A9468953120E4F972784A16ABC024873B38AC03BC50A45B43B34'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0078'; Hash='0CCBA7F1DE6FCDF17343C8A557FBBFC2DA7C93062081FC5B0F60EBD92B0E5C3E'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0079'; Hash='CC183A41DDB0C44DAE2B7284809A0FD64B74B7422035F7392084B8F1829BE8AB'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0080'; Hash='EDC5B165578845551C418002276EAF6A482E3DFAC8296E4817360B7ECC680363'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0081'; Hash='D55AF843AAB02CE2A51695F88AC29F42C684663312607F6DFC29BEE591AE1FB9'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0082'; Hash='A25A04C55620244DA9CB39390DC4FE36E666EBB9F3FD60BFB08F660A8B2CC1A2'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0083'; Hash='5899F7AA118DE853B46CCC23AA7D5DBE2B6C80704D25EF8A20970CE3FCAF9961'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0084'; Hash='8BA517D421851AC0F990259CBBF462F1197690BAE83985A8BB00371CDE4B2651'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0085'; Hash='44D01E2E631F3CAB75F4D4717D01EDFC329B2BC232953BFB06B0DAA63A06C3FF'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0086'; Hash='2B9299B02A4B7455AC110459C8A6352C881D185D1E17AC7211EB56FADC171127'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0087'; Hash='9A348688E4CE124F94E11C0381C94052EAAEC991C438D0D690847B4450F7A279'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0088'; Hash='78E8629BB9C63DBD31264BBFEB3E5F97F1675A5A9164B98B97B6BE97DE895C71'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0089'; Hash='3235ACB8CBAAC845F08E3808DF6EFF137EC1DCC517BEB20952BD5E328536B6F2'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0090'; Hash='2E04D54DC20D46BEB652C755C8B94E4A000F27AAD75FA6F1183F228A52143DE6'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0091'; Hash='2CEBDBCD6412FB7E12F03480201155DD1EEEE787AA3481BA4B0717B0671F6BB7'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0092'; Hash='7F6E375471A0D850428BA829AB874FF30C79F3D0A59C0BFF0EF4A8435A03D2BA'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0093'; Hash='1A7617D5F10FF9C3DB0258C439765A66B58D0F4FB0ADFB8B8927514F83C8DA4E'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0094'; Hash='8909B15B81D295CCB9C50CF9C9F82347E3B359C006CA261E9D30AE88F9E4BB24'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0095'; Hash='F20CDED8CFB7BDB1D1437085E535B9C4629E494CAEB16315727A69CC80768264'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0096'; Hash='DFD6D3F81D6BFCE1743636D8A752DE66EBC0ED6DF4320E70E1859E18EE04D2B6'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0097'; Hash='23D4DB08A2FDD73DF23283C04A8B9E015308A45C8C0A4854F1D0F3D12C35CBB9'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0098'; Hash='A80A121535A671F2CEDA364C850FC19A7417D245FDCB1A17904C8A14345B2536'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0099'; Hash='2E2549CF395ED9FB41593EF693B741F928388EBBB18E1BD850B47A1FE8FCFFC8'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0100'; Hash='3D1E78E9AD0151816C3DE32C806ADADABFB790CCFD903017A286EDBD9F338B6E'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0101'; Hash='D975024B6490588DB588F0B49348177B5F0C975054870883A868408A11928D52'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0102'; Hash='61DB347A25B6FA671E7767C860118F71C739CB3B069809499E556E73F15FC844'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0103'; Hash='31E61DA87EE50BDF7DC0392C409277B06D1C72F5292D676256C9AF166C24CDD3'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0104'; Hash='B70E4B330AAB5A7DAFD748637C554F41791A311DEB1ACB2D32CC3984A5559202'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0105'; Hash='0676D2AB9AE6A5E701AB15E0F6A2EB03EB5879C1CBAD370D8B5BC496F343FC5E'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0106'; Hash='D7179A7326F5060154F2E6781FF507A489FD723E7A5197403BCAC63E140D0044'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0107'; Hash='B43562D3CC9275AB5FED812D66C0358D81038597E5347650904487414437D66D'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0108'; Hash='DCF96EDDA575FEFD95EDED7080BCAB4DDE6176A543E166D8E8555D8BC08EA535'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0109'; Hash='815AD14C832F701CF917F2737E2D974A35B46A3BF0E9A8600EC73CFCCA612F89'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0110'; Hash='3683006B8FE43914D3AA90144D5719A82AB587BF139E5B6D28E1FCD3038FBAE7'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0111'; Hash='FE4BEB2EF6DA199E698DAF6ED06F6A62C28C464F19185763FD94C5C2EC38B267'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0112'; Hash='A584D84F5BABB8A6719BE105C7ABE6FD119F3D3A2D07AA4131D825300065A40A'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0113'; Hash='6EDA47F7CDD741EBBBD794BFBCE0E991767BAF69728EAEE2FD804291B04292FF'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0114'; Hash='ADCBF1A8F355857A45FEE2B7EEEAA016C5913ED8714852C3ADC68B0EAF264D75'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0115'; Hash='A2CD97487BD9357564A87F3AAD980C35FB27C0E77DE845581E15542ECD06B8F9'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0116'; Hash='87577E8CB763AD24A2908C098129F250AA901584077A6A6F08218855CC63E4D4'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0117'; Hash='9CC40B1E6151CA2255E482D74D0AE93152B6307809107CEA64DB07C67C18D8CA'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0118'; Hash='3DCE9C93CD6FA4A70F4FF45BB25B4A58E8065264733D02B642A1F53ADEE9FAC7'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0119'; Hash='898E742516A3132496DD66D333707082ADBBA5A6C063D44846ABA4C9E657F1FE'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0120'; Hash='7D9F2D9ACA152842CB0C5E2446838337C864C7120CA6306BC4562F8964C4D21B'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0121'; Hash='7E4040C9C9F92CC69279908F5C95F6436FA3DEC320BE454A635EA4D3BC65D1E1'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0122'; Hash='B7D6C42985D7B0709A68A7F4B0F073C1E63377B7050FD1E72DC4107D35C8D42D'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0123'; Hash='264671858FF6008989D8D3DFA9FDB16000EE3291A75DCAA42AE53B0CBE0F402A'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0124'; Hash='FF4B45870801C298A0259BA8B435B0BEE454CBD530FB828F2969FB8531CAC46C'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0125'; Hash='0061DC9328DDDAC2EE3FF1FA5CF69D7518704C3A1E3CB6C3210F2A612BFF0937'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0126'; Hash='20774914CC5939C0E594708319A0E9E30BC9C94C688809A5C0F580D2771F5359'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0127'; Hash='597A72E6E36AD1E9AFC0202B4FA72B1BEC2EF895FCE972037DFFCC29AF85EF66'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0128'; Hash='8F238DD55B0CA94CE3ED563B94317FF618F1AEF0F5F278A052F6874F4841644F'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0129'; Hash='1E14BCC353A98D6732DCE2F87ADB987DB2C21F09206C6E8BD607004BB3CC41F7'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0130'; Hash='EC79B64B3B3E2E5B722020EF0D70B7AAB7D38DB7E4AD129D9B77EF297F44799B'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0131'; Hash='350EB0936C7955A23D4D5FFF857266B4A893BD04A3275B0A7A281CCE62095D6F'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0132'; Hash='7A2D01E7871BCE3D9EFB3758675284698EA4285BC6EC6E7641178EE94154745D'; Category='strong_behavior'; Weight=70; Strong=$true },
    [pscustomobject]@{ Id='KB0133'; Hash='9511C7C0CD9055C8DF8565002DD9625436593688A8582CDAA2C09ED15E206F6E'; Category='loader_trace'; Weight=60; Strong=$true },
    [pscustomobject]@{ Id='KB0134'; Hash='E11C7C758A4F5C0877E71736719C1897414ACC599922DE0A60B0F1598E54807C'; Category='loader_trace'; Weight=60; Strong=$true },
    [pscustomobject]@{ Id='KB0135'; Hash='7D5BA1F68566931311FD5549F41B46A020B641A5606D83C9F03DBB29AFE9F5CF'; Category='loader_trace'; Weight=60; Strong=$true },
    [pscustomobject]@{ Id='KB0136'; Hash='BDF651FCF4D36D22ED08EEF2717E37BDC87B4B55F3DD62A3A4B43CEFE065E3DE'; Category='loader_trace'; Weight=60; Strong=$true },
    [pscustomobject]@{ Id='KB0137'; Hash='58A3A778890BDF2E4BFA13753A05F2E6B4BE3B45BD8CE62DBEE83C10C540109A'; Category='loader_trace'; Weight=60; Strong=$true },
    [pscustomobject]@{ Id='KB0138'; Hash='FD52DE57D6EA7D427B8FFD50A6037771F75F54810275B4E7502BE53905D34972'; Category='loader_trace'; Weight=60; Strong=$true },
    [pscustomobject]@{ Id='KB0139'; Hash='490E42330EA542459AC4B1F55643BE0AE29E850F476ACECB6ADFA698E9C97549'; Category='loader_trace'; Weight=60; Strong=$true },
    [pscustomobject]@{ Id='KB0140'; Hash='34A26533EA5888D1F56D059B34F8919796A2B8624D2BB8668A506521D3724360'; Category='loader_trace'; Weight=60; Strong=$true },
    [pscustomobject]@{ Id='KB0141'; Hash='957792759CCB2298AC083A7DECDACC301CF6D60916E3707AB8FD9AF26FA1FCE7'; Category='loader_trace'; Weight=60; Strong=$true },
    [pscustomobject]@{ Id='KB0142'; Hash='30D47D97360544ACDB51533DC7ABE4AD6AFC32125D8C072B492501FBD1C3B45F'; Category='loader_trace'; Weight=60; Strong=$true },
    [pscustomobject]@{ Id='KB0143'; Hash='7C4B22E77CF28FB586DA062F6A428CD0336B8D06C58D16A30261D2958F27C379'; Category='loader_trace'; Weight=60; Strong=$true },
    [pscustomobject]@{ Id='KB0144'; Hash='8DF4964A6AB21160C455C3EDFA83B0B6DFC2E3BCDDC345CB3762A41BD232F880'; Category='loader_trace'; Weight=60; Strong=$true },
    [pscustomobject]@{ Id='KB0145'; Hash='B8DA8C1E37D5B479D65C7D00ED7EBC526EF59190393AA46DEDEEC4611B961085'; Category='loader_trace'; Weight=60; Strong=$true },
    [pscustomobject]@{ Id='KB0146'; Hash='F5774FABBD6FF4CE50828F3C5FED8E2EE6BD96F7F6F999816450FAB709AEFAF9'; Category='loader_trace'; Weight=60; Strong=$true },
    [pscustomobject]@{ Id='KB0147'; Hash='D778B25F8FC8316E744FC98181D9289173D41E796846BA338B89AFDA6BC5E3F5'; Category='loader_trace'; Weight=60; Strong=$true },
    [pscustomobject]@{ Id='KB0148'; Hash='8798F30AA5CF51E76E78FD5F202FED0CFC01AACA85BE3DD0EA730DFB6792CCC1'; Category='loader_trace'; Weight=60; Strong=$true },
    [pscustomobject]@{ Id='KB0149'; Hash='530F3714C1C5C866705991DA911F83A4853564689DD71A8835887ACD8D11D996'; Category='loader_trace'; Weight=60; Strong=$true },
    [pscustomobject]@{ Id='KB0150'; Hash='32087F63376E6B278D457124DD48741BAAF0E0D25B1827BCC7388FFD9873E0BD'; Category='loader_trace'; Weight=60; Strong=$true },
    [pscustomobject]@{ Id='KB0151'; Hash='5A5E97FB1C4CB401B2427E66EF6FAB3008D58D562B34AA371C4C00426978DEF2'; Category='loader_trace'; Weight=60; Strong=$true },
    [pscustomobject]@{ Id='KB0152'; Hash='EF3840F7B7B0E496A22B90E41D6E5028583974746D695FB2EA774BB4304960DA'; Category='loader_trace'; Weight=60; Strong=$true },
    [pscustomobject]@{ Id='KB0153'; Hash='A90B2CA7A2411DCEC47B55CC660F62E3CA4E97EE9CCDA9540A4ACF987E0FB3A9'; Category='loader_trace'; Weight=60; Strong=$true },
    [pscustomobject]@{ Id='KB0154'; Hash='CCC96CF0492B34B850BA1BF879915CFF2A648FF433894D6260E233E43029DDEA'; Category='loader_trace'; Weight=60; Strong=$true },
    [pscustomobject]@{ Id='KB0155'; Hash='6311265E04DFB41D3E62C8B91D6580DA19C7B4D479E80524327B2B5024AB951E'; Category='loader_trace'; Weight=60; Strong=$true }
)

function Write-YLine {
    param([string]$Text = "", [string]$Color = "Gray", [switch]$NoNewline)
    try {
        if ($NoColor) { $Color = "Gray" }
        if ($NoNewline) { Write-Host $Text -ForegroundColor $Color -NoNewline }
        else { Write-Host $Text -ForegroundColor $Color }
    } catch { Write-Host $Text }
}

function Write-Rule {
    param([string]$Title = "")
    $w = [int]$script:Config.UiWidth
    if ([string]::IsNullOrWhiteSpace($Title)) {
        Write-YLine ("=" * $w) "DarkGray"
        return
    }
    $label = "[ " + $Title + " ]"
    $left = [Math]::Max(4, [int](($w - $label.Length) / 2))
    $right = [Math]::Max(4, $w - $left - $label.Length)
    Write-YLine (("=" * $left) + $label + ("=" * $right)) "DarkCyan"
}

function Write-Box {
    param([string]$Title, [string[]]$Lines, [string]$Color = "White")
    Write-Rule $Title
    foreach ($line in @($Lines)) { Write-YLine ("  " + $line) $Color }
}

function Test-Deadline {
    try { return ((Get-Date) -gt $script:Config.Deadline) } catch { return $false }
}

function Normalize-Text {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return "" }
    return ($Value.ToLowerInvariant() -replace "[\u0000-\u001F]", " ").Trim()
}

function Get-Sha256Hex {
    param([string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace("-", "").ToUpperInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Get-RuleHash {
    param([string]$Atom)
    return Get-Sha256Hex ($script:Config.Salt + (Normalize-Text $Atom))
}

function Initialize-RuleIndex {
    $script:State.RuleIndex = @{}
    foreach ($r in $script:YrysHashRules) {
        if (-not $script:State.RuleIndex.ContainsKey($r.Hash)) {
            $script:State.RuleIndex[$r.Hash] = $r
        }
    }

    # User-supplied one-off tokens are converted to hashes in memory only.
    if (-not [string]::IsNullOrWhiteSpace($Cheat)) {
        $i = 0
        foreach ($raw in ($Cheat -split "[,;]")) {
            $t = Normalize-Text $raw
            if ($t.Length -lt 3) { continue }
            $i++
            $h = Get-RuleHash $t
            if (-not $script:State.RuleIndex.ContainsKey($h)) {
                $script:State.RuleIndex[$h] = [pscustomobject]@{ Id=("USER" + $i.ToString("000")); Hash=$h; Category="user_supplied"; Weight=90; Strong=$true }
            }
        }
    }
}

function Get-TextAtoms {
    param(
        [string]$Text,
        [switch]$DeepNgrams,
        [int]$MaxAtoms = 20000
    )
    $result = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }

    $lower = Normalize-Text $Text

    foreach ($m in [Regex]::Matches($lower, "[a-z0-9][a-z0-9._-]{2,80}", "IgnoreCase")) {
        if ($result.Count -ge $MaxAtoms) { break }
        $atom = $m.Value.Trim(".-_")
        if ($atom.Length -ge 3) { [void]$result.Add($atom) }
        $compact = ($atom -replace "[^a-z0-9]", "")
        if ($compact.Length -ge 3) { [void]$result.Add($compact) }
    }

    if ($DeepNgrams) {
        $baseAtoms = @($result)
        foreach ($atom in $baseAtoms) {
            if ($result.Count -ge $MaxAtoms) { break }
            $s = ($atom -replace "[^a-z0-9.]", "")
            if ($s.Length -lt 4 -or $s.Length -gt 80) { continue }
            $maxLen = [Math]::Min(24, $s.Length)
            for ($len = 3; $len -le $maxLen; $len++) {
                if ($result.Count -ge $MaxAtoms) { break }
                for ($start = 0; $start -le ($s.Length - $len); $start++) {
                    if ($result.Count -ge $MaxAtoms) { break }
                    [void]$result.Add($s.Substring($start, $len))
                }
            }
        }
    }

    return @($result)
}

function Find-RuleHits {
    param(
        [string]$Text,
        [string]$Context = "text",
        [switch]$DeepNgrams,
        [int]$MaxAtoms = 20000
    )
    $hits = New-Object 'System.Collections.Generic.List[object]'
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($atom in Get-TextAtoms -Text $Text -DeepNgrams:$DeepNgrams -MaxAtoms $MaxAtoms) {
        $h = Get-RuleHash $atom
        if ($script:State.RuleIndex.ContainsKey($h)) {
            $r = $script:State.RuleIndex[$h]
            if (-not $seen.Contains($r.Id)) {
                [void]$seen.Add($r.Id)
                [void]$hits.Add([pscustomobject]@{
                    Id = $r.Id
                    Category = $r.Category
                    Weight = [int]$r.Weight
                    Strong = [bool]$r.Strong
                    Context = $Context
                })
            }
        }
    }
    return @($hits)
}

function Convert-ScoreToSeverity {
    param([int]$Score)
    if ($Score -ge 130) { return "CRITICAL" }
    if ($Score -ge 85) { return "HIGH" }
    if ($Score -ge 45) { return "MEDIUM" }
    if ($Score -ge 20) { return "LOW" }
    return "INFO"
}

function Add-Finding {
    param(
        [string]$Object,
        [string]$ObjectType,
        [int]$Score,
        [string]$Class,
        [string[]]$Evidence,
        [string]$Sha256 = "",
        [switch]$Trace,
        [switch]$Ignored
    )
    if (-not $Evidence -or $Evidence.Count -eq 0) { $Evidence = @("no evidence text") }
    $sev = Convert-ScoreToSeverity $Score
    $min = if ($Trace) { $TraceMinScore } else { $MinScore }

    $strongEvidence = $false
    foreach ($e in @($Evidence)) {
        if (($e -match "strong|javaagent|autorun|registry|usn|dns|wmi|module|driver|signature|rule")) {
            $strongEvidence = $true
            break
        }
    }

    $finding = [pscustomobject]@{
        Time = (Get-Date).ToString("o")
        Object = $Object
        ObjectType = $ObjectType
        Score = $Score
        Severity = $sev
        Class = $Class
        Evidence = @($Evidence)
        Sha256 = $Sha256
        Trace = [bool]$Trace
        Recommendation = if ($Trace) { "trace only: verify timeline and correlate before deciding" } elseif ($Score -ge 85) { "manual review: verify path, signature, hash and related evidence" } else { "low/medium signal: keep only if it supports stronger evidence" }
    }

    if ($Ignored) {
        [void]$script:State.Ignored.Add($finding)
        return
    }

    if ($Score -lt $min) {
        $script:State.Counters.Suppressed++
        if ($ShowIgnored) { [void]$script:State.Ignored.Add($finding) }
        return
    }
    if ($StrictEvidence -and -not $strongEvidence -and $Score -lt 85) {
        $script:State.Counters.Suppressed++
        if ($ShowIgnored) { [void]$script:State.Ignored.Add($finding) }
        return
    }
    [void]$script:State.Findings.Add($finding)
}

function Add-RuleFindingEvidence {
    param([object[]]$Hits)
    $ev = New-Object 'System.Collections.Generic.List[string]'
    foreach ($h in @($Hits | Select-Object -First 20)) {
        [void]$ev.Add(("matched hashed rule {0} category={1} context={2} weight={3}" -f $h.Id, $h.Category, $h.Context, $h.Weight))
    }
    return @($ev)
}

function Get-FileSha256Fast {
    param([string]$Path)
    if ($script:State.HashCache.ContainsKey($Path)) { return $script:State.HashCache[$Path] }
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $hash = ([BitConverter]::ToString($sha.ComputeHash($fs))).Replace("-", "").ToUpperInvariant()
            $script:State.HashCache[$Path] = $hash
            return $hash
        } finally {
            $fs.Dispose()
            $sha.Dispose()
        }
    } catch {
        $script:State.HashCache[$Path] = ""
        return ""
    }
}

function Get-AuthenticodeInfoSafe {
    param([string]$Path)
    if ($script:State.SigCache.ContainsKey($Path)) { return $script:State.SigCache[$Path] }
    $o = [pscustomobject]@{ Status="Unknown"; Subject=""; Issuer=""; Trusted=$false }
    try {
        $s = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
        $sub = ""; $iss = ""
        if ($s.SignerCertificate) {
            $sub = [string]$s.SignerCertificate.Subject
            $iss = [string]$s.SignerCertificate.Issuer
        }
        $o = [pscustomobject]@{ Status=([string]$s.Status); Subject=$sub; Issuer=$iss; Trusted=($s.Status -eq "Valid") }
    } catch {}
    $script:State.SigCache[$Path] = $o
    return $o
}

function Test-PathFragment {
    param([string]$Path, [string[]]$Fragments)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $p = $Path.ToLowerInvariant()
    foreach ($frag in $Fragments) {
        if ($p.Contains($frag.ToLowerInvariant())) { return $true }
    }
    return $false
}

function Test-TrustedPath { param([string]$Path) return (Test-PathFragment -Path $Path -Fragments $script:TrustedPathFragments) }
function Test-UserWritablePath { param([string]$Path) return (Test-PathFragment -Path $Path -Fragments $script:UserWritableFragments) }
function Test-MinecraftPath {
    param([string]$Path)
    return (Test-PathFragment -Path $Path -Fragments @(".minecraft","minecraft","tlauncher","prismlauncher","polymc","multimc","gdlauncher","atlauncher","modrinth","curseforge","lunarclient","badlion","feather"))
}

function Test-TrustedVendorText {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    $l = $Text.ToLowerInvariant()
    foreach ($t in $script:TrustedVendorTokens) {
        if ($l.Contains($t)) { return $true }
    }
    return $false
}

function Read-TextWindowFast {
    param([string]$Path, [int]$MaxBytes = 524288)
    try {
        $fi = [System.IO.FileInfo]::new($Path)
        if (-not $fi.Exists -or $fi.Length -le 0) { return "" }
        $take = [Math]::Min([int64]$MaxBytes, [int64]$fi.Length)
        $buf = New-Object byte[] ([int]$take)
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $read = $fs.Read($buf, 0, [int]$take)
            if ($read -le 0) { return "" }
            if ($read -lt $buf.Length) {
                $tmp = New-Object byte[] $read
                [Array]::Copy($buf, $tmp, $read)
                $buf = $tmp
            }
            $ascii = [System.Text.Encoding]::ASCII.GetString($buf)
            $utf8 = [System.Text.Encoding]::UTF8.GetString($buf)
            $u16 = [System.Text.Encoding]::Unicode.GetString($buf)
            return (($ascii + "`n" + $utf8 + "`n" + $u16) -replace "[^\x09\x0A\x0D\x20-\x7E]", " ")
        } finally {
            $fs.Dispose()
        }
    } catch { return "" }
}

function Get-FileVersionTextSafe {
    param([string]$Path)
    try {
        $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
        return (($vi.CompanyName + " " + $vi.ProductName + " " + $vi.FileDescription + " " + $vi.OriginalFilename) -replace "\s+", " ")
    } catch { return "" }
}

function Get-ObjectKindFromPath {
    param([string]$Path)
    try {
        $ext = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
        switch ($ext) {
            ".jar" { return "JAR" }
            ".dll" { return "DLL" }
            ".exe" { return "EXE" }
            ".lnk" { return "LNK" }
            ".pf"  { return "PREFETCH" }
            ".log" { return "LOG" }
            default { return "FILE" }
        }
    } catch { return "FILE" }
}

function Get-CommandLinePaths {
    param([string]$CommandLine)
    $paths = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return @() }
    $expanded = [Environment]::ExpandEnvironmentVariables($CommandLine)
    foreach ($text in @($CommandLine, $expanded)) {
        foreach ($m in [Regex]::Matches($text, '"([A-Za-z]:\\[^"<>|]+?\.(jar|exe|dll))"|([A-Za-z]:\\[^\s"<>|]+?\.(jar|exe|dll))', "IgnoreCase")) {
            $v = ""
            if ($m.Groups[1].Success) { $v = $m.Groups[1].Value }
            elseif ($m.Groups[3].Success) { $v = $m.Groups[3].Value }
            $v = [Environment]::ExpandEnvironmentVariables($v.Trim('"'))
            if ($v -and [System.IO.File]::Exists($v)) { [void]$paths.Add($v) }
        }
    }
    return @($paths)
}

function Initialize-Workspace {
    try { [System.IO.Directory]::CreateDirectory($script:Config.TempRoot) | Out-Null } catch {}
}

function Remove-Workspace {
    try {
        if ([System.IO.Directory]::Exists($script:Config.TempRoot)) {
            [System.IO.Directory]::Delete($script:Config.TempRoot, $true)
        }
    } catch {}
}

function Test-IsAdministrator {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p = [Security.Principal.WindowsPrincipal]::new($id)
        $isAdmin = $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        return [pscustomobject]@{ IsAdmin=$isAdmin; Method="WindowsPrincipal" }
    } catch {
        return [pscustomobject]@{ IsAdmin=$false; Method="failed" }
    }
}

function Enable-ScreenPrivacyGuard {
    if ($NoScreenPrivacyGuard) { $script:State.ScreenPrivacy = "disabled"; return }

    $code = @"
using System;
using System.Runtime.InteropServices;

public static class YrysWin32 {
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetWindowDisplayAffinity(IntPtr hWnd, uint dwAffinity);

    [DllImport("dwmapi.dll")]
    public static extern int DwmIsCompositionEnabled(out bool pfEnabled);

    [DllImport("kernel32.dll")]
    public static extern uint GetLastError();
}
"@
    try { Add-Type -TypeDefinition $code -ErrorAction SilentlyContinue | Out-Null } catch {}

    try {
        $hwnd = [YrysWin32]::GetConsoleWindow()
        if ($hwnd -eq [IntPtr]::Zero) {
            $script:State.ScreenPrivacy = "no_console_window"
            Add-Finding -Object "ScreenPrivacyGuard" -ObjectType "PRIVACY" -Score 20 -Class "privacy_guard_not_applied" -Evidence @("GetConsoleWindow returned zero; Windows Terminal/hosted console may not expose a top-level console HWND")
            return
        }

        $dwm = $false
        try { [void][YrysWin32]::DwmIsCompositionEnabled([ref]$dwm) } catch { $dwm = $false }

        $WDA_EXCLUDEFROMCAPTURE = 0x00000011
        $ok = [YrysWin32]::SetWindowDisplayAffinity($hwnd, [uint32]$WDA_EXCLUDEFROMCAPTURE)
        if ($ok) {
            $script:State.ScreenPrivacy = "enabled_wda_excludefromcapture"
        } else {
            $err = [YrysWin32]::GetLastError()
            $script:State.ScreenPrivacy = "failed_error_" + $err
            Add-Finding -Object "ScreenPrivacyGuard" -ObjectType "PRIVACY" -Score 25 -Class "privacy_guard_failed" -Evidence @("SetWindowDisplayAffinity failed; lastError=$err", "DWM composition enabled: $dwm")
        }
    } catch {
        $script:State.ScreenPrivacy = "failed_exception"
        Add-Finding -Object "ScreenPrivacyGuard" -ObjectType "PRIVACY" -Score 25 -Class "privacy_guard_failed" -Evidence @("exception: " + $_.Exception.Message)
    }
}

function Disable-ScreenPrivacyGuard {
    try {
        if ("YrysWin32" -as [type]) {
            $hwnd = [YrysWin32]::GetConsoleWindow()
            if ($hwnd -ne [IntPtr]::Zero) { [void][YrysWin32]::SetWindowDisplayAffinity($hwnd, [uint32]0) }
        }
    } catch {}
}

function Show-Banner {
    Clear-Host
    Write-YLine ""
    Write-YLine "YRYS CHECKER v22 SAFE REFAC :: forensic scanner" "Cyan"
    Write-YLine ("Admin: {0} / {1}" -f $script:State.IsElevated, $script:State.AdminMethod) "Gray"
    Write-YLine ("Screen privacy: " + $script:State.ScreenPrivacy) "Gray"
    Write-YLine ("Deadline: " + $script:Config.Deadline.ToString("HH:mm:ss")) "Gray"
    Write-YLine ("Report: " + $script:Config.ReportPath) "DarkGray"
    Write-Rule
}

function Test-SelfSyntax {
    $p = $PSCommandPath
    if (-not $p) { $p = $MyInvocation.ScriptName }
    if (-not $p) { Write-YLine "SelfTest: cannot resolve script path." "Yellow"; exit 2 }
    $errors = $null
    [void][System.Management.Automation.PSParser]::Tokenize((Get-Content -LiteralPath $p -Raw), [ref]$errors)
    if ($errors -and $errors.Count -gt 0) {
        Write-YLine "SelfTest: parser errors found." "Red"
        $errors | Format-List | Out-Host
        exit 2
    }
    Write-YLine "SelfTest: OK, no parser errors." "Green"
    exit 0
}

function Get-RootSet {
    $roots = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $add = {
        param([string]$p)
        try {
            if ([string]::IsNullOrWhiteSpace($p)) { return }
            $x = [Environment]::ExpandEnvironmentVariables($p)
            if ([System.IO.Directory]::Exists($x)) { [void]$roots.Add($x) }
        } catch {}
    }

    $appData = [Environment]::GetFolderPath([Environment+SpecialFolder]::ApplicationData)
    $localAppData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    $userProfile = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
    $desktop = [Environment]::GetFolderPath([Environment+SpecialFolder]::DesktopDirectory)
    $docs = [Environment]::GetFolderPath([Environment+SpecialFolder]::MyDocuments)

    & $add (Join-Path $appData ".minecraft")
    & $add (Join-Path $appData ".tlauncher")
    & $add (Join-Path $appData "PrismLauncher")
    & $add (Join-Path $appData "PolyMC")
    & $add (Join-Path $appData "MultiMC")
    & $add (Join-Path $appData "GDLauncher")
    & $add (Join-Path $appData "ATLauncher")
    & $add (Join-Path $appData "ModrinthApp")
    & $add (Join-Path $appData "CurseForge")
    & $add (Join-Path $localAppData "Packages")
    & $add (Join-Path $localAppData "Programs")
    & $add (Join-Path $userProfile "Downloads")
    & $add $desktop
    & $add $docs
    & $add (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Startup")

    if (-not $OnlyMinecraft) {
        & $add $env:TEMP
        if ($Deep -or $FullSystem -or $Forensic) {
            & $add $env:ProgramData
            & $add $env:ProgramFiles
            & $add ${env:ProgramFiles(x86)}
        }
        if ($FullSystem -or $HuntSystem32) {
            & $add (Join-Path $env:WINDIR "System32")
            & $add (Join-Path $env:WINDIR "SysWOW64")
        }
        if ($AllDrives -or $FullSystem) {
            try {
                foreach ($d in [System.IO.DriveInfo]::GetDrives()) {
                    if ($d.DriveType -eq [System.IO.DriveType]::Fixed -and $d.IsReady) { & $add $d.RootDirectory.FullName }
                }
            } catch {}
        }
    }

    $script:State.Counters.Roots = $roots.Count
    return @($roots)
}

function Get-FilesFast {
    param([string[]]$Roots, [string[]]$Extensions)

    $extSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($e in $Extensions) { [void]$extSet.Add($e) }

    $stack = New-Object 'System.Collections.Generic.Stack[string]'
    foreach ($r in $Roots) {
        if ([System.IO.Directory]::Exists($r)) { $stack.Push($r) }
    }

    while ($stack.Count -gt 0) {
        if (Test-Deadline) { break }
        $dir = $stack.Pop()

        try {
            foreach ($sub in [System.IO.Directory]::EnumerateDirectories($dir)) {
                if (Test-Deadline) { break }
                $stack.Push($sub)
            }
        } catch { $script:State.Counters.BlockedErrors++ }

        try {
            foreach ($f in [System.IO.Directory]::EnumerateFiles($dir)) {
                if (Test-Deadline) { break }
                try {
                    $ext = [System.IO.Path]::GetExtension($f)
                    if ($extSet.Contains($ext)) { $f }
                } catch {}
            }
        } catch { $script:State.Counters.BlockedErrors++ }
    }
}

function Test-PreCandidate {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $p = $Path.ToLowerInvariant()
    $ext = [System.IO.Path]::GetExtension($p)
    if ($ext -eq ".jar") { return $true }
    if (Test-MinecraftPath $p) { return $true }
    if (Test-UserWritablePath $p) { return $true }
    if ((Find-RuleHits -Text $p -Context "path" -DeepNgrams -MaxAtoms 6000).Count -gt 0) { return $true }
    if (($Deep -or $FullSystem -or $AllDrives) -and $ext -in @(".exe",".dll")) {
        if (Test-TrustedPath $p) {
            try {
                $fi = [System.IO.FileInfo]::new($Path)
                return ($fi.LastWriteTime -gt (Get-Date).AddDays(-45))
            } catch { return $false }
        }
        return $true
    }
    return $false
}

function Get-BaseRisk {
    param([string]$Path)
    $kind = Get-ObjectKindFromPath $Path
    $score = 0
    $ev = New-Object 'System.Collections.Generic.List[string]'
    if (Test-MinecraftPath $Path) { $score += 18; [void]$ev.Add("path context: Minecraft/launcher area") }
    if (Test-UserWritablePath $Path) { $score += 12; [void]$ev.Add("path context: user-writable area") }
    if (Test-TrustedPath $Path) { $score -= 18; [void]$ev.Add("path context: trusted Windows/vendor area") }

    $pathHits = Find-RuleHits -Text $Path -Context "path" -DeepNgrams -MaxAtoms 8000
    foreach ($h in @($pathHits | Select-Object -First 20)) {
        $score += [Math]::Min(90, [int]$h.Weight)
    }
    foreach ($e in Add-RuleFindingEvidence $pathHits) { [void]$ev.Add($e) }

    return [pscustomobject]@{ Kind=$kind; Score=$score; Evidence=@($ev) }
}

function Analyze-JarFile {
    param([string]$Path, [object]$Base)
    $score = [int]$Base.Score
    $ev = New-Object 'System.Collections.Generic.List[string]'
    foreach ($x in @($Base.Evidence)) { [void]$ev.Add($x) }

    try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue | Out-Null } catch {}
    try {
        $zip = [System.IO.Compression.ZipFile]::OpenRead($Path)
        try {
            $sb = [System.Text.StringBuilder]::new()
            $count = 0
            foreach ($entry in $zip.Entries) {
                if (Test-Deadline) { break }
                $count++
                if ($entry.FullName) {
                    [void]$sb.Append(" ")
                    [void]$sb.Append($entry.FullName)
                }
                if ($entry.FullName -match "(?i)(manifest\.mf|fabric\.mod\.json|mods\.toml|plugin\.yml|mixin|accesswidener|\.json$|\.properties$|\.txt$)" -and $entry.Length -gt 0 -and $entry.Length -lt 262144) {
                    try {
                        $st = $entry.Open()
                        try {
                            $reader = [System.IO.StreamReader]::new($st)
                            try { [void]$sb.Append(" "); [void]$sb.Append($reader.ReadToEnd()) } finally { $reader.Dispose() }
                        } finally { $st.Dispose() }
                    } catch {}
                }
                if ($count -gt 3000) { break }
            }

            $jarText = $sb.ToString()
            $hits = Find-RuleHits -Text $jarText -Context "jar" -DeepNgrams -MaxAtoms 16000
            foreach ($h in @($hits | Select-Object -First 30)) {
                $score += [Math]::Min(100, [int]$h.Weight)
            }
            foreach ($e in Add-RuleFindingEvidence $hits) { [void]$ev.Add($e) }
            if ($jarText -match "(?i)premain-class|agent-class") {
                $score += 70
                [void]$ev.Add("strong JVM evidence: jar declares Java agent manifest class")
            }
        } finally { $zip.Dispose() }
    } catch {
        $score += 2
        [void]$ev.Add("jar could not be opened as zip")
    }

    return [pscustomobject]@{ Score=$score; Evidence=@($ev); Class="jar_static_candidate" }
}

function Analyze-BinaryLight {
    param([string]$Path, [object]$Base)
    $score = [int]$Base.Score
    $ev = New-Object 'System.Collections.Generic.List[string]'
    foreach ($x in @($Base.Evidence)) { [void]$ev.Add($x) }

    $sig = $null
    $versionText = ""
    if ((Get-ObjectKindFromPath $Path) -in @("EXE","DLL")) {
        $sig = Get-AuthenticodeInfoSafe $Path
        $versionText = Get-FileVersionTextSafe $Path
        if ($sig.Trusted -and (Test-TrustedVendorText ($sig.Subject + " " + $versionText))) {
            $score -= 45
            [void]$ev.Add("mitigation: valid trusted vendor signature/version info")
        } else {
            $score += 14
            [void]$ev.Add("signature: not signed or not trusted (" + $sig.Status + ")")
        }
    }

    if ($score -ge 25 -or (Test-UserWritablePath $Path) -or -not (Test-TrustedPath $Path)) {
        $txt = (Read-TextWindowFast -Path $Path -MaxBytes $MaxDeepBytes) + " " + $versionText
        $hits = Find-RuleHits -Text $txt -Context "file_bytes" -MaxAtoms 12000
        foreach ($h in @($hits | Select-Object -First 20)) { $score += [Math]::Min(70, [int]$h.Weight) }
        foreach ($e in Add-RuleFindingEvidence $hits) { [void]$ev.Add($e) }
    }

    return [pscustomobject]@{ Score=$score; Evidence=@($ev); Class="binary_static_candidate" }
}

function Test-FalsePositiveGate {
    param([string]$Path, [int]$Score, [string[]]$Evidence)
    $joined = (@($Evidence) -join " ").ToLowerInvariant()
    if ((Test-TrustedPath $Path) -and $Score -lt 85 -and $joined -notmatch "strong|javaagent|rule") { return "trusted path weak signal only" }
    if ($joined -match "valid trusted vendor" -and $Score -lt 105 -and $joined -notmatch "javaagent|autorun|usn|dns|wmi") { return "trusted signed vendor with no strong supporting evidence" }
    return ""
}

function Analyze-FileCandidate {
    param([string]$Path, [string]$Source = "filesystem")
    if (Test-Deadline) { return }
    if (-not [System.IO.File]::Exists($Path)) { return }

    $script:State.Counters.Files++
    $base = Get-BaseRisk $Path
    $kind = $base.Kind
    $analysis = $null

    if ($kind -eq "JAR") { $analysis = Analyze-JarFile -Path $Path -Base $base }
    elseif ($kind -in @("EXE","DLL")) { $analysis = Analyze-BinaryLight -Path $Path -Base $base }
    else { $analysis = [pscustomobject]@{ Score=$base.Score; Evidence=@($base.Evidence); Class="file_candidate" } }

    $score = [int]$analysis.Score
    $ev = New-Object 'System.Collections.Generic.List[string]'
    foreach ($x in @($analysis.Evidence)) { [void]$ev.Add($x) }

    switch ($Source) {
        "process" { $score += 25; [void]$ev.Add("source: currently running or referenced by running process") }
        "module" { $score += 35; [void]$ev.Add("source: loaded module inside Java/Minecraft-related process") }
        "javaagent" { $score += 80; [void]$ev.Add("source: JVM injection-like agent path") }
        "autorun" { $score += 35; [void]$ev.Add("source: autorun/persistence reference") }
        "registry" { $score += 30; [void]$ev.Add("source: registry reference") }
        "scheduled_task" { $score += 30; [void]$ev.Add("source: scheduled task action") }
        "usn" { $score += 20; [void]$ev.Add("source: USN trace") }
        "dns" { $score += 15; [void]$ev.Add("source: DNS cache trace") }
    }

    try {
        $fi = [System.IO.FileInfo]::new($Path)
        if ($fi.LastWriteTime -gt (Get-Date).AddDays(-14)) { $score += 6; [void]$ev.Add("time: recent file write") }
        if ($fi.Length -gt 0 -and $fi.Length -lt 15360 -and $kind -in @("EXE","DLL")) { $score += 6; [void]$ev.Add("shape: very small executable/library") }
    } catch {}

    $ignoreReason = Test-FalsePositiveGate -Path $Path -Score $score -Evidence @($ev)
    $sha = if ($score -ge 45) { Get-FileSha256Fast $Path } else { "" }
    if ($ignoreReason) {
        if ($ShowIgnored) {
            Add-Finding -Object $Path -ObjectType $kind -Score $score -Class "ignored_trusted_or_weak" -Evidence (@($ev) + @("ignored: " + $ignoreReason)) -Sha256 $sha -Ignored
        }
        return
    }
    Add-Finding -Object $Path -ObjectType $kind -Score $score -Class $analysis.Class -Evidence @($ev) -Sha256 $sha
}

function Invoke-FileSystemScan {
    Write-Rule "Files"
    $roots = Get-RootSet
    foreach ($r in $roots) { Write-YLine ("  root: " + $r) "DarkGray" }
    foreach ($file in Get-FilesFast -Roots $roots -Extensions @(".jar",".exe",".dll",".lnk",".pf",".log")) {
        if (Test-Deadline) { break }
        if ($script:State.Counters.Candidates -ge $MaxCandidates) { break }
        try {
            if (Test-PreCandidate $file) {
                $script:State.Counters.Candidates++
                Analyze-FileCandidate -Path $file -Source "filesystem"
            }
        } catch { $script:State.Counters.BlockedErrors++ }
    }
}

function Invoke-ProcessScan {
    Write-Rule "Processes"
    $procs = @()
    try {
        $procs = @(Get-CimInstance Win32_Process -ErrorAction Stop)
    } catch {
        $script:State.Counters.BlockedErrors++
        try {
            $procs = @(Get-Process -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Name=$_.ProcessName; ProcessId=$_.Id; CommandLine="" } })
        } catch { $procs = @() }
    }

    foreach ($p in $procs) {
        if (Test-Deadline) { break }
        $script:State.Counters.Processes++
        try {
            $line = [string]$p.CommandLine
            $name = [string]$p.Name
            $text = $name + " " + $line
            $hits = Find-RuleHits -Text $text -Context "process" -DeepNgrams -MaxAtoms 8000
            $javaAgent = ($line -match "(?i)-javaagent|-agentpath|-agentlib|-Xbootclasspath|-Djava\.system\.class\.loader|-noverify")
            if ($hits.Count -gt 0 -or $javaAgent) {
                $score = 35
                $ev = New-Object 'System.Collections.Generic.List[string]'
                foreach ($h in @($hits | Select-Object -First 20)) { $score += [Math]::Min(70, [int]$h.Weight) }
                foreach ($e in Add-RuleFindingEvidence $hits) { [void]$ev.Add($e) }
                if ($javaAgent) { $score += 80; [void]$ev.Add("strong JVM evidence: injection-like command-line argument") }
                Add-Finding -Object ("PID {0} {1}" -f $p.ProcessId, $name) -ObjectType "PROCESS" -Score $score -Class "running_process_candidate" -Evidence @($ev)
            }
            foreach ($path in Get-CommandLinePaths $line) {
                if ($javaAgent -and $path.ToLowerInvariant().EndsWith(".jar")) { Analyze-FileCandidate -Path $path -Source "javaagent" }
                else { Analyze-FileCandidate -Path $path -Source "process" }
            }
        } catch { $script:State.Counters.BlockedErrors++ }
    }
}

function Invoke-ModuleScan {
    Write-Rule "Process Modules"
    try {
        $targets = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match "(?i)java|javaw|minecraft|launcher|lunar|badlion|feather|tlauncher|prism|polymc|multimc|gdlauncher" })
        foreach ($p in $targets) {
            if (Test-Deadline) { break }
            try {
                foreach ($m in $p.Modules) {
                    if (Test-Deadline) { break }
                    $script:State.Counters.Modules++
                    $path = [string]$m.FileName
                    if (-not $path) { continue }
                    $hits = Find-RuleHits -Text ($path + " " + $m.ModuleName) -Context "module" -DeepNgrams -MaxAtoms 4000
                    if ($hits.Count -gt 0 -or ((Test-UserWritablePath $path) -and -not (Test-TrustedPath $path))) {
                        Analyze-FileCandidate -Path $path -Source "module"
                    }
                }
            } catch { $script:State.Counters.BlockedErrors++ }
        }
    } catch { $script:State.Counters.BlockedErrors++ }
}

function Get-RegistryValueText {
    param([Microsoft.Win32.RegistryKey]$Key)
    $sb = [System.Text.StringBuilder]::new()
    try {
        foreach ($name in $Key.GetValueNames()) {
            [void]$sb.Append(" ")
            [void]$sb.Append($name)
            [void]$sb.Append("=")
            [void]$sb.Append([string]$Key.GetValue($name))
        }
    } catch {}
    return $sb.ToString()
}

function Open-RegKey {
    param([string]$Hive, [string]$SubKey, [switch]$View32)
    try {
        $h = switch ($Hive) {
            "HKCU" { [Microsoft.Win32.RegistryHive]::CurrentUser }
            "HKLM" { [Microsoft.Win32.RegistryHive]::LocalMachine }
            default { return $null }
        }
        $view = if ($View32) { [Microsoft.Win32.RegistryView]::Registry32 } else { [Microsoft.Win32.RegistryView]::Registry64 }
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($h, $view)
        return $base.OpenSubKey($SubKey)
    } catch { return $null }
}

function Invoke-RegistryScan {
    Write-Rule "Registry / Autoruns"
    $keys = @(
        @("HKCU","Software\Microsoft\Windows\CurrentVersion\Run",$false),
        @("HKCU","Software\Microsoft\Windows\CurrentVersion\RunOnce",$false),
        @("HKLM","Software\Microsoft\Windows\CurrentVersion\Run",$false),
        @("HKLM","Software\Microsoft\Windows\CurrentVersion\RunOnce",$false),
        @("HKLM","Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",$false),
        @("HKLM","Software\Microsoft\Windows NT\CurrentVersion\Windows",$false)
    )

    foreach ($k in $keys) {
        if (Test-Deadline) { break }
        $rk = Open-RegKey -Hive $k[0] -SubKey $k[1] -View32:([bool]$k[2])
        if ($null -eq $rk) { continue }
        try {
            $script:State.Counters.Registry++
            $txt = Get-RegistryValueText $rk
            $hits = Find-RuleHits -Text $txt -Context "registry" -DeepNgrams -MaxAtoms 8000
            if ($hits.Count -gt 0) {
                $score = 50
                $ev = Add-RuleFindingEvidence $hits
                foreach ($h in @($hits)) { $score += [Math]::Min(70, [int]$h.Weight) }
                Add-Finding -Object ($k[0] + ":\" + $k[1]) -ObjectType "REGISTRY" -Score $score -Class "registry_autorun_candidate" -Evidence @($ev)
            }
            foreach ($path in Get-CommandLinePaths $txt) { Analyze-FileCandidate -Path $path -Source "autorun" }
        } finally { $rk.Close() }
    }

    # IFEO / Debugger hijacks
    $ifeo = Open-RegKey -Hive "HKLM" -SubKey "Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    if ($ifeo) {
        try {
            foreach ($subName in $ifeo.GetSubKeyNames()) {
                if (Test-Deadline) { break }
                $sub = $ifeo.OpenSubKey($subName)
                if ($sub -eq $null) { continue }
                try {
                    $txt = $subName + " " + (Get-RegistryValueText $sub)
                    if ($txt -match "(?i)debugger|silentprocessexit|globalflag") {
                        $hits = Find-RuleHits -Text $txt -Context "ifeo" -DeepNgrams -MaxAtoms 6000
                        $score = 55
                        $ev = New-Object 'System.Collections.Generic.List[string]'
                        [void]$ev.Add("IFEO/SilentProcessExit debugging or hijack key exists")
                        foreach ($h in @($hits)) { $score += [Math]::Min(70, [int]$h.Weight) }
                        foreach ($e in Add-RuleFindingEvidence $hits) { [void]$ev.Add($e) }
                        Add-Finding -Object ("IFEO\" + $subName) -ObjectType "REGISTRY" -Score $score -Class "ifeo_debugger_or_hijack" -Evidence @($ev)
                    }
                    foreach ($path in Get-CommandLinePaths $txt) { Analyze-FileCandidate -Path $path -Source "registry" }
                } finally { $sub.Close() }
            }
        } finally { $ifeo.Close() }
    }

    # Services
    try {
        foreach ($svc in Get-CimInstance Win32_Service -ErrorAction SilentlyContinue) {
            if (Test-Deadline) { break }
            $txt = ([string]$svc.Name + " " + [string]$svc.DisplayName + " " + [string]$svc.PathName)
            $hits = Find-RuleHits -Text $txt -Context "service" -DeepNgrams -MaxAtoms 6000
            if ($hits.Count -gt 0) {
                $score = 60
                foreach ($h in @($hits)) { $score += [Math]::Min(70, [int]$h.Weight) }
                Add-Finding -Object ("Service: " + $svc.Name) -ObjectType "SERVICE" -Score $score -Class "service_candidate" -Evidence (Add-RuleFindingEvidence $hits)
            }
            foreach ($path in Get-CommandLinePaths ([string]$svc.PathName)) { Analyze-FileCandidate -Path $path -Source "autorun" }
        }
    } catch { $script:State.Counters.BlockedErrors++ }
}

function Invoke-ScheduledTaskScan {
    Write-Rule "Scheduled Tasks"
    try {
        foreach ($task in Get-ScheduledTask -ErrorAction SilentlyContinue) {
            if (Test-Deadline) { break }
            $script:State.Counters.Tasks++
            $text = ([string]$task.TaskName + " " + [string]$task.TaskPath + " " + ($task.Actions | Out-String) + " " + ($task.Triggers | Out-String))
            $hits = Find-RuleHits -Text $text -Context "scheduled_task" -DeepNgrams -MaxAtoms 8000
            $riskPath = ($text -match "(?i)\\appdata\\|\\temp\\|\\downloads\\|\\desktop\\")
            $logon = ($text -match "(?i)logon|startup|unlock|session")
            if ($hits.Count -gt 0 -or ($riskPath -and $logon)) {
                $score = 35
                $ev = New-Object 'System.Collections.Generic.List[string]'
                foreach ($h in @($hits)) { $score += [Math]::Min(70, [int]$h.Weight) }
                foreach ($e in Add-RuleFindingEvidence $hits) { [void]$ev.Add($e) }
                if ($riskPath) { $score += 18; [void]$ev.Add("task action references user-writable path") }
                if ($logon) { $score += 12; [void]$ev.Add("task trigger/action is logon/startup/unlock related") }
                Add-Finding -Object ($task.TaskPath + $task.TaskName) -ObjectType "SCHEDULED_TASK" -Score $score -Class "scheduled_task_persistence_candidate" -Evidence @($ev)
            }
            foreach ($path in Get-CommandLinePaths $text) { Analyze-FileCandidate -Path $path -Source "scheduled_task" }
        }
    } catch { $script:State.Counters.BlockedErrors++ }
}

function Invoke-DNSCacheScan {
    if ($NoDNSCache) { return }
    Write-Rule "DNS Cache"
    try {
        $items = @(Get-DnsClientCache -ErrorAction Stop)
        foreach ($d in $items) {
            if (Test-Deadline) { break }
            $txt = [string]$d.Entry
            $hits = Find-RuleHits -Text $txt -Context "dns" -DeepNgrams -MaxAtoms 2000
            if ($hits.Count -gt 0) {
                $script:State.Counters.DNS++
                $score = 45
                foreach ($h in @($hits)) { $score += [Math]::Min(50, [int]$h.Weight) }
                Add-Finding -Object $txt -ObjectType "DNS_CACHE" -Score $score -Class "dns_cache_trace" -Evidence (Add-RuleFindingEvidence $hits) -Trace
            }
        }
    } catch {
        $script:State.Counters.BlockedErrors++
        try {
            $raw = ipconfig /displaydns 2>$null
            $text = ($raw -join "`n")
            $hits = Find-RuleHits -Text $text -Context "dns" -DeepNgrams -MaxAtoms 15000
            if ($hits.Count -gt 0) {
                $script:State.Counters.DNS += $hits.Count
                $score = 45
                foreach ($h in @($hits)) { $score += [Math]::Min(50, [int]$h.Weight) }
                Add-Finding -Object "ipconfig displaydns" -ObjectType "DNS_CACHE" -Score $score -Class "dns_cache_trace" -Evidence (Add-RuleFindingEvidence $hits) -Trace
            }
        } catch { $script:State.Counters.BlockedErrors++ }
    }
}

function Invoke-ProcessWithTimeout {
    param([string]$FileName, [string]$Arguments, [int]$TimeoutSec = 6)
    try {
        $psi = [System.Diagnostics.ProcessStartInfo]::new()
        $psi.FileName = $FileName
        $psi.Arguments = $Arguments
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true
        $p = [System.Diagnostics.Process]::Start($psi)
        if ($p.WaitForExit($TimeoutSec * 1000)) {
            return $p.StandardOutput.ReadToEnd()
        } else {
            try { $p.Kill() } catch {}
            return ""
        }
    } catch { return "" }
}

function Invoke-USNJournalScan {
    if ($NoUSNJournal -or $NoHeavyForensics) { return }
    Write-Rule "USN Journal"
    $drives = @("C:")
    if ($AllDrives -or $FullSystem) {
        try {
            $drives = @([System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq "Fixed" -and $_.IsReady } | ForEach-Object { $_.Name.TrimEnd("\") })
        } catch {}
    }

    foreach ($d in $drives) {
        if (Test-Deadline) { break }
        $raw = Invoke-ProcessWithTimeout -FileName "fsutil.exe" -Arguments ("usn readjournal " + $d + " csv") -TimeoutSec $ExternalTimeoutSec
        if ([string]::IsNullOrWhiteSpace($raw)) { continue }
        $lines = @($raw -split "`r?`n" | Select-Object -First $USNMaxLines)
        foreach ($chunk in ($lines -join "`n") -split "(.{1,80000})") {
            if ([string]::IsNullOrWhiteSpace($chunk)) { continue }
            $hits = Find-RuleHits -Text $chunk -Context "usn" -DeepNgrams -MaxAtoms 12000
            if ($hits.Count -gt 0) {
                $script:State.Counters.USN += $hits.Count
                $score = 50
                foreach ($h in @($hits)) { $score += [Math]::Min(50, [int]$h.Weight) }
                Add-Finding -Object ("USN " + $d) -ObjectType "USN_TRACE" -Score $score -Class "usn_journal_trace" -Evidence (Add-RuleFindingEvidence $hits) -Trace
            }
        }
    }
}

function Invoke-WMIPersistenceScan {
    if ($NoWMIForensics) { return }
    Write-Rule "WMI Persistence"
    try {
        $filters = @(Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue)
        $consumers = @(Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue)
        $bindings = @(Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue)
        $text = (($filters | Out-String) + "`n" + ($consumers | Out-String) + "`n" + ($bindings | Out-String))
        if ($text.Trim().Length -gt 0) {
            $hits = Find-RuleHits -Text $text -Context "wmi" -DeepNgrams -MaxAtoms 16000
            $risk = ($consumers.Count -gt 0)
            if ($hits.Count -gt 0 -or $risk) {
                $script:State.Counters.WMI += [Math]::Max(1, $consumers.Count)
                $score = if ($risk) { 65 } else { 40 }
                $ev = New-Object 'System.Collections.Generic.List[string]'
                if ($risk) { [void]$ev.Add("WMI CommandLineEventConsumer exists in root\subscription") }
                foreach ($h in @($hits)) { $score += [Math]::Min(65, [int]$h.Weight) }
                foreach ($e in Add-RuleFindingEvidence $hits) { [void]$ev.Add($e) }
                Add-Finding -Object "root\subscription" -ObjectType "WMI_PERSISTENCE" -Score $score -Class "wmi_persistence_candidate" -Evidence @($ev)
            }
        }
    } catch { $script:State.Counters.BlockedErrors++ }
}

function Invoke-BrowserDiscordTraceScan {
    if (-not ($Forensic -or $Deep -or $FullSystem -or $BrowserForensics -or $DiscordForensics)) { return }

    Write-Rule "Browser / Discord Traces"
    $paths = New-Object 'System.Collections.Generic.List[string]'
    $local = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    $roam = [Environment]::GetFolderPath([Environment+SpecialFolder]::ApplicationData)

    if (-not $NoBrowserForensics) {
        foreach ($root in @(
            (Join-Path $local "Google\Chrome\User Data"),
            (Join-Path $local "Microsoft\Edge\User Data"),
            (Join-Path $roam "Mozilla\Firefox\Profiles")
        )) {
            if ([System.IO.Directory]::Exists($root)) {
                foreach ($f in Get-FilesFast -Roots @($root) -Extensions @(".sqlite",".db",".ldb",".log")) {
                    if ($paths.Count -gt 500) { break }
                    [void]$paths.Add($f)
                }
            }
        }
    }

    if (-not $NoDiscordForensics) {
        foreach ($root in @(
            (Join-Path $roam "discord"),
            (Join-Path $roam "discordcanary"),
            (Join-Path $roam "discordptb"),
            (Join-Path $local "Discord")
        )) {
            if ([System.IO.Directory]::Exists($root)) {
                foreach ($f in Get-FilesFast -Roots @($root) -Extensions @(".ldb",".log",".sqlite",".db",".cache",".tmp")) {
                    if ($paths.Count -gt 900) { break }
                    [void]$paths.Add($f)
                }
            }
        }
    }

    foreach ($p in $paths) {
        if (Test-Deadline) { break }
        try {
            $txt = Read-TextWindowFast -Path $p -MaxBytes ([Math]::Min([Math]::Max($MaxDeepBytes, 1048576), 2097152))
            $hits = Find-RuleHits -Text $txt -Context "browser_discord" -DeepNgrams -MaxAtoms 12000
            if ($hits.Count -gt 0) {
                if ($p -match "(?i)discord") { $script:State.Counters.Discord++ } else { $script:State.Counters.Browser++ }
                $score = 60
                foreach ($h in @($hits)) { $score += [Math]::Min(60, [int]$h.Weight) }
                Add-Finding -Object $p -ObjectType "LOCAL_TRACE_DB" -Score $score -Class "browser_or_discord_local_trace" -Evidence (Add-RuleFindingEvidence $hits) -Trace
            }
        } catch { $script:State.Counters.BlockedErrors++ }
    }
}

function Invoke-EnvironmentIntegrityScan {
    Write-Rule "Environment Integrity"
    $ev = New-Object 'System.Collections.Generic.List[string]'
    $score = 0

    try {
        if ([System.Diagnostics.Debugger]::IsAttached) {
            $score += 40
            [void]$ev.Add("PowerShell process has a managed debugger attached")
        }
    } catch {}

    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
        $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
        $text = ([string]$cs.Manufacturer + " " + [string]$cs.Model + " " + [string]$bios.SerialNumber + " " + [string]$bios.Version)
        if ($text -match "(?i)vmware|virtualbox|kvm|qemu|xen|hyper-v|virtual machine|parallels") {
            $score += 25
            [void]$ev.Add("virtualization/sandbox-like system descriptor: " + ($text -replace "\s+", " "))
        }
    } catch {}

    try {
        $toolNames = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match "^(procmon|procexp|wireshark|fiddler|windbg|x64dbg|ollydbg|ida64|ida|dnspy)$" } | Select-Object -ExpandProperty ProcessName -Unique)
        if ($toolNames.Count -gt 0) {
            $score += 20
            [void]$ev.Add("diagnostic/debugging tools currently running: " + ($toolNames -join ", "))
        }
    } catch {}

    if ($score -gt 0) {
        $script:State.Counters.EnvSignals++
        Add-Finding -Object "Local execution environment" -ObjectType "ENVIRONMENT" -Score $score -Class "environment_integrity_context" -Evidence @($ev)
    } else {
        Write-YLine "  no debugger/VM context signal found" "DarkGray"
    }
}

function Invoke-BehaviorChains {
    if ($NoBehaviorChains) { return }
    Write-Rule "Behavior Chains"
    $all = @($script:State.Findings)
    $hasJava = @($all | Where-Object { $_.Evidence -join " " -match "(?i)javaagent|jvm|jar|minecraft|launcher" }).Count -gt 0
    $hasPersistence = @($all | Where-Object { $_.ObjectType -match "REGISTRY|SERVICE|SCHEDULED_TASK|WMI" }).Count -gt 0
    $hasTrace = @($all | Where-Object { $_.Trace -eq $true }).Count -gt 0
    $hasDriver = @($all | Where-Object { $_.Evidence -join " " -match "(?i)driver|mapper|kdmapper|iqvw64|gdrv|inpout" }).Count -gt 0

    if ($hasJava -and $hasPersistence) {
        Add-Finding -Object "JVM/Minecraft + persistence" -ObjectType "BEHAVIOR_CHAIN" -Score 125 -Class "chain_java_persistence" -Evidence @("Java/Minecraft-related evidence exists", "autorun/service/task/WMI persistence evidence exists", "correlated behavior chain; review timeline")
    }
    if ($hasJava -and $hasTrace) {
        Add-Finding -Object "JVM/Minecraft + deleted/network traces" -ObjectType "BEHAVIOR_CHAIN" -Score 105 -Class "chain_java_trace" -Evidence @("Java/Minecraft-related evidence exists", "local trace evidence exists in DNS/USN/browser/Discord", "trace is not proof alone; correlate dates")
    }
    if ($hasDriver -and $hasJava) {
        Add-Finding -Object "Kernel/driver trace + Minecraft" -ObjectType "BEHAVIOR_CHAIN" -Score 135 -Class "chain_driver_java" -Evidence @("driver/mapper-like evidence exists", "Java/Minecraft evidence exists", "high-risk pattern for loaders/spoofers")
    }
}

function Save-Report {
    $report = [ordered]@{
        Version = $script:Config.Version
        Started = $script:Config.StartTime.ToString("o")
        Finished = (Get-Date).ToString("o")
        Elevated = $script:State.IsElevated
        ScreenPrivacy = $script:State.ScreenPrivacy
        Counters = $script:State.Counters
        Findings = @($script:State.Findings | Sort-Object Score -Descending)
        Ignored = if ($ShowIgnored) { @($script:State.Ignored | Sort-Object Score -Descending) } else { @() }
    }
    try {
        $json = $report | ConvertTo-Json -Depth 8
        [System.IO.File]::WriteAllText($script:Config.ReportPath, $json, [System.Text.Encoding]::UTF8)
        return $script:Config.ReportPath
    } catch {
        Write-YLine ("Could not write report: " + $_.Exception.Message) "Yellow"
        return ""
    }
}

function Show-FinalVerdict {
    Write-Rule "Final"
    $sorted = @($script:State.Findings | Sort-Object Score -Descending)
    $critical = @($sorted | Where-Object { $_.Severity -eq "CRITICAL" }).Count
    $high = @($sorted | Where-Object { $_.Severity -eq "HIGH" }).Count
    $medium = @($sorted | Where-Object { $_.Severity -eq "MEDIUM" }).Count

    $verdict = "CLEAN / no strong indicators"
    $color = "Green"
    if ($critical -gt 0) { $verdict = "CRITICAL / strong evidence requires manual review"; $color = "Red" }
    elseif ($high -gt 0) { $verdict = "HIGH / suspicious evidence requires review"; $color = "Yellow" }
    elseif ($medium -gt 0) { $verdict = "MEDIUM / weak-to-moderate indicators"; $color = "Cyan" }

    Write-YLine ("  Verdict: " + $verdict) $color
    Write-YLine ("  Findings: total={0} critical={1} high={2} medium={3} ignored={4}" -f $sorted.Count, $critical, $high, $medium, $script:State.Ignored.Count) "Gray"
    Write-YLine ("  Counters: " + (($script:State.Counters.GetEnumerator() | ForEach-Object { $_.Key + "=" + $_.Value }) -join " ")) "DarkGray"

    $i = 1
    foreach ($f in @($sorted | Select-Object -First ([Math]::Min($Top, 25)))) {
        $c = switch ($f.Severity) { "CRITICAL" {"Red"} "HIGH" {"Yellow"} "MEDIUM" {"Cyan"} default {"Gray"} }
        Write-YLine ("`n  #{0} [{1}] score={2} type={3}" -f $i, $f.Severity, $f.Score, $f.ObjectType) $c
        Write-YLine ("     " + $f.Object) "White"
        foreach ($e in @($f.Evidence | Select-Object -First 6)) { Write-YLine ("     - " + $e) "Gray" }
        if ($f.Sha256) { Write-YLine ("     sha256: " + $f.Sha256) "DarkGray" }
        $i++
    }

    $path = Save-Report
    if ($path) {
        Write-YLine ("`n  Report saved: " + $path) "Green"
        if ($OpenReport) { try { Invoke-Item -LiteralPath $path } catch {} }
    }
}

function Invoke-YrysPipeline {
    Start-Transcript -Path (Join-Path $script:Config.TempRoot "console.log") -ErrorAction SilentlyContinue | Out-Null

    Initialize-RuleIndex
    $admin = Test-IsAdministrator
    $script:State.IsElevated = [bool]$admin.IsAdmin
    $script:State.AdminMethod = [string]$admin.Method

    Enable-ScreenPrivacyGuard
    Show-Banner

    Write-Box "Policy" @(
        "This build reports environment/tamper risk instead of crashing or returning fake clean results.",
        "Rule tokens are compared as salted SHA256 hashes; evidence shows rule IDs, not plaintext tokens.",
        "Old OBS/Discord-kill logic is removed. Screen privacy uses Windows display affinity only."
    ) "Gray"

    Invoke-EnvironmentIntegrityScan
    Invoke-ProcessScan
    Invoke-ModuleScan
    Invoke-RegistryScan
    Invoke-ScheduledTaskScan
    Invoke-WMIPersistenceScan
    Invoke-DNSCacheScan

    if ($Forensic -or $Deep -or $FullSystem) {
        Invoke-USNJournalScan
        Invoke-BrowserDiscordTraceScan
    }

    Invoke-FileSystemScan
    Invoke-BehaviorChains
    Show-FinalVerdict

    try { Stop-Transcript | Out-Null } catch {}
}

function Main {
    if ($SelfTest) { Test-SelfSyntax }
    Initialize-Workspace
    try {
        Invoke-YrysPipeline
    } finally {
        Disable-ScreenPrivacyGuard
        Remove-Workspace
    }
}

Main
