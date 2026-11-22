rule PowerShell_Encoded_Command
{
    meta:
        description = "Detects content containing both a PowerShell indicator and the encoded-command switch (-enc). This heuristic identifies a potentially suspicious pattern but does not confirm command execution or malicious intent."
        author = "Secwexen"
        date = "2026-11-22"
        reference = "https://attack.mitre.org/techniques/T1059/001/"
        severity = "medium"
        confidence = "low"

    strings:
        $ps = "powershell" nocase
        $enc = "-enc" nocase

    condition:
        $ps and $enc
}
