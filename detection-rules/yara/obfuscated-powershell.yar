rule Obfuscated_PowerShell
{
    meta:
        description = "Detects PowerShell-related content containing common obfuscation indicators, including encoded command switches, dynamic execution indicators, Base64 decoding, or string replacement. These indicators are heuristic and do not independently confirm malicious activity."
        author = "Secwexen"
        date = "2026-11-22"
        reference = "https://attack.mitre.org/techniques/T1027/"
        severity = "medium"
        confidence = "medium"

    strings:
        $ps1 = "powershell" nocase
        $ps2 = "powershell.exe" nocase
        $enc = "-enc" nocase
        $iex = "IEX" nocase
        $frombase64 = "FromBase64String" nocase
        $replace = "-replace" nocase

    condition:
        1 of ($ps*) and
        1 of ($enc, $iex, $frombase64, $replace)
}
