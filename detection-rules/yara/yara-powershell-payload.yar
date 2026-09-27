rule PowerShell_Encoded_Command
{
    meta:
        author = "Secwexen"
        description = "Detects PowerShell scripts or payloads using encoded (-enc) commands"
        date = "2026-03-17"
        reference = "https://attack.mitre.org/techniques/T1059/"
        level = "high"
    
    strings:
        $ps = "powershell" nocase
        $enc = "-enc" nocase

    condition:
        $ps and $enc
}
