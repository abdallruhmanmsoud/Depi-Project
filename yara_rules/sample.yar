rule SuspiciousStrings {
    meta:
        description = "Detect common suspicious strings"
        author = "Forensics Dashboard"
    strings:
        $a = "cmd.exe" nocase
        $b = "powershell" nocase
        $c = "mimikatz" nocase
        $d = "WScript.Shell" nocase
    condition:
        any of them
}

rule PE_Executable {
    meta:
        description = "Detect PE executables"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0
}
