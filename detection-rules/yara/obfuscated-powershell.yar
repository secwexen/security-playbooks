rule Obfuscated_PowerShell
{
    meta:
        author = "Secwexen"
        description = "Detects common obfuscation indicators in PowerShell command content"
        date = "2026-08-25"
        reference = "https://attack.mitre.org/techniques/T1027/"
        level = "medium"

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
