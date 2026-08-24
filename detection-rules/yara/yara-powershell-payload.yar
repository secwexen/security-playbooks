// File: detection-rules/yara/yara_powershell_payload.yar
// Purpose: Detect PowerShell encoded (-enc) commands in scripts or memory
// Author: Secwexen
// Date: 2026-03-17
// References: https://attack.mitre.org/techniques/T1059/

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
