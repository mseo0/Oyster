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
        description = "Heuristic: shell/script that downloads then executes a payload"
        severity    = "medium"
    strings:
        $a = "curl" nocase
        $b = "wget" nocase
        $c = "| sh" nocase
        $d = "Invoke-WebRequest" nocase
        $e = "IEX" nocase
    condition:
        // This is a SCRIPT heuristic: only consider small, non-binary files.
        // Compiled binaries (Mach-O / PE / ELF / fat) contain these byte
        // substrings ("curl", "IEX", "| sh") by sheer coincidence, which made
        // the rule fire on legitimate signed .dll/.dylib files — a false alarm.
        // Excluding executable magic + capping size removes those entirely.
        filesize < 300KB
        and uint16(0) != 0x5A4D          // not PE (MZ)
        and uint32(0) != 0x464C457F      // not ELF (\x7fELF)
        and uint32(0) != 0xFEEDFACF      // not Mach-O 64-bit
        and uint32(0) != 0xFEEDFACE      // not Mach-O 32-bit
        and uint32(0) != 0xCFFAEDFE      // not Mach-O (byte-swapped)
        and uint32(0) != 0xCEFAEDFE      // not Mach-O (byte-swapped)
        and uint32(0) != 0xBEBAFECA      // not a fat/universal binary
        and (any of ($a, $b, $d)) and (any of ($c, $e))
}
