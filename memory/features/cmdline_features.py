"""
Command Line Feature Extractor
===============================
Extracts behavioral features from normalized cmdline data.

DFIR Rationale:
  - Encoded PowerShell commands (-EncodedCommand, -e, -enc) are a primary
    attack vector for fileless malware and C2 execution
  - Base64 content in command lines indicates obfuscation
  - URL/IP presence indicates download cradles or C2 callbacks
  - LOLBin usage with suspicious arguments indicates living-off-the-land attacks
  - Command line length outliers indicate obfuscated payloads
  - Empty command lines on non-system processes are suspicious (injection)
"""

import re
import math


# ── Detection Patterns ──────────────────────────────────────────────────────

_BASE64_RE = re.compile(
    r'[A-Za-z0-9+/]{40,}={0,2}'
)

_URL_RE = re.compile(
    r'https?://[^\s"\']+',
    re.IGNORECASE
)

_IP_RE = re.compile(
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
)

_ENCODED_CMD_RE = re.compile(
    r'-(?:e|enc|encodedcommand)\s',
    re.IGNORECASE
)

_DOWNLOAD_PATTERNS = [
    r'invoke-webrequest',
    r'wget\s',
    r'curl\s',
    r'net\.webclient',
    r'downloadstring',
    r'downloadfile',
    r'downloaddata',
    r'bitstransfer',
    r'start-bitstransfer',
    r'certutil.*-urlcache',
    r'certutil.*-split',
    r'bitsadmin.*\/transfer',
]

_DOWNLOAD_RE = re.compile(
    '|'.join(_DOWNLOAD_PATTERNS),
    re.IGNORECASE
)

_EXECUTION_PATTERNS = [
    r'invoke-expression',
    r'\biex\b',
    r'invoke-command',
    r'start-process',
    r'new-object.*comobject',
    r'invoke-mimikatz',
    r'invoke-shellcode',
    r'invoke-dllinjection',
]

_EXECUTION_RE = re.compile(
    '|'.join(_EXECUTION_PATTERNS),
    re.IGNORECASE
)

_BYPASS_PATTERNS = [
    r'-(?:exec(?:utionpolicy)?)\s+bypass',
    r'-(?:nop(?:rofile)?)',
    r'-(?:w(?:indowstyle)?)\s+hidden',
    r'-(?:sta)\b',
    r'-noninteractive',
    r'set-executionpolicy\s+bypass',
    r'set-mppreference.*-disablerealtimemonitoring',
    r'amsiutils',
    r'amsiinitfailed',
]

_BYPASS_RE = re.compile(
    '|'.join(_BYPASS_PATTERNS),
    re.IGNORECASE
)

LOLBIN_NAMES = {
    "rundll32", "regsvr32", "mshta", "certutil",
    "bitsadmin", "msiexec", "wmic", "cmstp",
    "installutil", "regasm", "regsvcs", "msbuild",
    "ieexec", "control", "pcalua", "ftp",
    "csc", "vbc", "jsc",
}

# Processes that legitimately have empty/dash command lines
SYSTEM_PROCS_NO_CMDLINE = {
    "system", "registry", "secure system",
    "memory compression",
}


class CmdlineFeatureExtractor:

    def extract(self, cmdlines: list) -> dict:

        if not cmdlines:
            return self._empty_features()

        total = len(cmdlines)
        lengths = []

        powershell_count = 0
        cmd_count = 0
        encoded_cmd_count = 0
        base64_count = 0
        url_count = 0
        ip_in_cmdline_count = 0
        download_indicator_count = 0
        execution_indicator_count = 0
        bypass_indicator_count = 0
        lolbin_with_args_count = 0
        empty_cmdline_nonkernel = 0
        wscript_count = 0
        cscript_count = 0
        suspicious_length_count = 0

        for entry in cmdlines:
            cmd = entry.get("command_line", "") or ""
            proc = entry.get("process", "").lower()
            cmd_lower = cmd.lower()
            cmd_len = len(cmd)
            lengths.append(cmd_len)

            # ── PowerShell ──
            if "powershell" in proc or "pwsh" in proc or "powershell" in cmd_lower:
                powershell_count += 1

            # ── cmd.exe ──
            if proc == "cmd.exe" or cmd_lower.startswith("cmd"):
                cmd_count += 1

            # ── Encoded command ──
            if _ENCODED_CMD_RE.search(cmd):
                encoded_cmd_count += 1

            # ── Base64 ──
            if _BASE64_RE.search(cmd):
                base64_count += 1

            # ── URLs ──
            if _URL_RE.search(cmd):
                url_count += 1

            # ── IP addresses in command line ──
            if _IP_RE.search(cmd):
                ip_in_cmdline_count += 1

            # ── Download cradles ──
            if _DOWNLOAD_RE.search(cmd):
                download_indicator_count += 1

            # ── Code execution ──
            if _EXECUTION_RE.search(cmd):
                execution_indicator_count += 1

            # ── Security bypass ──
            if _BYPASS_RE.search(cmd):
                bypass_indicator_count += 1

            # ── LOLBin with arguments ──
            proc_base = proc.replace(".exe", "")
            if proc_base in LOLBIN_NAMES and cmd_len > len(proc) + 5:
                lolbin_with_args_count += 1

            # ── WScript / CScript ──
            if "wscript" in proc:
                wscript_count += 1
            if "cscript" in proc:
                cscript_count += 1

            # ── Empty cmdline on non-system process ──
            if (cmd == "" or cmd == "-") and proc not in SYSTEM_PROCS_NO_CMDLINE:
                empty_cmdline_nonkernel += 1

            # ── Suspicious length (>500 chars often indicates obfuscation) ──
            if cmd_len > 500:
                suspicious_length_count += 1

        # ── Length statistics ──
        avg_len = sum(lengths) / total if total > 0 else 0.0
        max_len = max(lengths) if lengths else 0
        non_zero = [l for l in lengths if l > 0]
        median_len = sorted(non_zero)[len(non_zero) // 2] if non_zero else 0

        len_std = 0.0
        if total > 1:
            variance = sum((l - avg_len) ** 2 for l in lengths) / (total - 1)
            len_std = math.sqrt(variance)

        # ── Composite risk score (normalized count of suspicious indicators) ──
        suspicious_total = (
            encoded_cmd_count +
            base64_count +
            download_indicator_count +
            execution_indicator_count +
            bypass_indicator_count +
            lolbin_with_args_count
        )

        return {
            # ── Counts ──
            "cmd_total_entries":            total,
            "cmd_powershell_count":         powershell_count,
            "cmd_cmd_exe_count":            cmd_count,
            "cmd_wscript_count":            wscript_count,
            "cmd_cscript_count":            cscript_count,

            # ── Obfuscation indicators ──
            "cmd_encoded_command_count":    encoded_cmd_count,
            "cmd_base64_count":            base64_count,
            "cmd_suspicious_length_count": suspicious_length_count,

            # ── Network indicators ──
            "cmd_url_count":               url_count,
            "cmd_ip_in_cmdline_count":     ip_in_cmdline_count,
            "cmd_download_indicator_count": download_indicator_count,

            # ── Execution indicators ──
            "cmd_execution_indicator_count": execution_indicator_count,
            "cmd_bypass_indicator_count":    bypass_indicator_count,
            "cmd_lolbin_with_args_count":    lolbin_with_args_count,

            # ── Anomalies ──
            "cmd_empty_nonkernel_count":   empty_cmdline_nonkernel,

            # ── Length statistics ──
            "cmd_length_avg":              round(avg_len, 4),
            "cmd_length_max":              max_len,
            "cmd_length_median":           median_len,
            "cmd_length_std":              round(len_std, 4),

            # ── Composite ──
            "cmd_suspicious_total":        suspicious_total,
            "cmd_suspicious_ratio":        round(suspicious_total / total, 4) if total > 0 else 0.0,
        }

    def _empty_features(self) -> dict:
        keys = [
            "cmd_total_entries", "cmd_powershell_count", "cmd_cmd_exe_count",
            "cmd_wscript_count", "cmd_cscript_count",
            "cmd_encoded_command_count", "cmd_base64_count",
            "cmd_suspicious_length_count",
            "cmd_url_count", "cmd_ip_in_cmdline_count",
            "cmd_download_indicator_count",
            "cmd_execution_indicator_count", "cmd_bypass_indicator_count",
            "cmd_lolbin_with_args_count",
            "cmd_empty_nonkernel_count",
            "cmd_length_avg", "cmd_length_max", "cmd_length_median",
            "cmd_length_std",
            "cmd_suspicious_total", "cmd_suspicious_ratio",
        ]
        return {k: 0 for k in keys}
