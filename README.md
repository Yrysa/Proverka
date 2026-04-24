$p = "$env:TEMP\Proverka.ps1"
$u = "https://raw.githubusercontent.com/Yrysa/Proverka/main/Proverka.ps1"
Invoke-WebRequest -Uri $u -OutFile $p -UseBasicParsing
powershell -NoProfile -ExecutionPolicy Bypass -File $p -Fast -NoPrompt -MaxMinutes 10
