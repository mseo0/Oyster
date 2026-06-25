/*
 * Example YARA rules. ClamAV loads these directly (clamscan -d rules/).
 * Drop real rule packs here (e.g. from YARA-Rules/rules) to extend coverage.
 * Kept intentionally benign so the scanner runs out-of-the-box without flagging
 * normal files.
 */

rule Suspicious_EICAR_Test_String
{
    meta:
        description = "EICAR antivirus test string (harmless test trigger)"
        severity    = "low"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}

rule Script_Download_And_Execute
{
    meta:
        description = "Heuristic: shell that downloads then executes a payload"
        severity    = "medium"
    strings:
        $a = "curl" nocase
        $b = "wget" nocase
        $c = "| sh" nocase
        $d = "Invoke-WebRequest" nocase
        $e = "IEX" nocase
    condition:
        (any of ($a, $b, $d)) and (any of ($c, $e))
}
