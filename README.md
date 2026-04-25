[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$p = "$env:TEMP\Proverka.ps1"
$u = "https://raw.githubusercontent.com/Yrysa/Proverka/main/Proverka.ps1"

Invoke-WebRequest -Uri $u -OutFile $p -UseBasicParsing

Set-ExecutionPolicy Bypass -Scope Process -Force

$ScanArgs = @{
    FullSystem     = $true
    Forensic       = $true
    Drivers        = $true
    VMCheck        = $true
    StrictEvidence = $true
    EntropyScan    = $true
    HWIDForensics  = $true
    USBForensics   = $true
    WMIForensics   = $true
    ShowIgnored    = $true
    NoPrompt       = $true
    Cheat          = 'vape,raven,rise,drip,entropy,whiteout,slinky,liquidbounce,wurst,meteor,impact,future,rusherhack,phobos,konas,pyro,boze,prestige,thunderhack,bleachhack,forgehax,inertia,sigma,flux,tenacity,zeroday,astolfo,fdp,raven b+,dope,koid,iridium,autoclicker,clicker,injector,loader,kdmapper,drvmap,spoofer'
    MaxMinutes     = 60
    MaxCandidates  = 15000
    UiWidth        = 120
}

& $p @ScanArgs
