"""
Malfind Normalizer
Parses Volatility 3 windows.malfind.Malfind output.

This is the most complex parser because malfind output is multi-line:
  - Line 1: tab-separated data row (PID, Process, Start VPN, etc.)
  - Lines 2-5: hex dump (raw bytes)
  - Lines 6+: disassembly (0xADDRESS: instruction)

Only the data row (line 1) is extracted. Hex dump and disasm are skipped.

Expected header:
  PID  Process  Start VPN  End VPN  Tag  Protection  CommitCharge  PrivateMemory  File output  Notes  Hexdump  Disasm
"""

import re

from normalization.utils import (
    is_valid_data_line, is_header_line,
    safe_str, safe_int, read_lines,
)


# Patterns for lines to skip inside malfind blocks
_HEX_DUMP_RE = re.compile(
    r'^[0-9a-fA-F]{2}\s+[0-9a-fA-F]{2}\s+'
)

_DISASM_RE = re.compile(
    r'^0x[0-9a-fA-F]+:\s+'
)


class MalfindNormalizer:

    HEADER_START = "PID\tProcess\tStart VPN"
    MIN_COLUMNS = 8

    def _is_malfind_noise(self, line: str) -> bool:
        """Returns True for hex dump and disassembly lines."""
        stripped = line.strip()
        if _HEX_DUMP_RE.match(stripped):
            return True
        if _DISASM_RE.match(stripped):
            return True
        return False

    def normalize(self, filepath: str) -> list:

        print(f"[INFO] Parsing {filepath}")

        results = []
        lines = read_lines(filepath)
        header_found = False

        for line in lines:

            if not header_found:
                if is_header_line(line, self.HEADER_START):
                    header_found = True
                continue

            if not is_valid_data_line(line):
                continue

            if self._is_malfind_noise(line):
                continue

            parts = line.strip().split("\t")

            if len(parts) < self.MIN_COLUMNS:
                continue

            try:
                pid = int(parts[0])
            except ValueError:
                continue

            protection = parts[5].strip()

            results.append({
                "pid": pid,
                "process": parts[1].strip(),
                "start_vpn": safe_str(parts[2]),
                "end_vpn": safe_str(parts[3]),
                "tag": safe_str(parts[4]),
                "protection": protection,
                "commit_charge": safe_int(parts[6]),
                "private_memory": parts[7].strip() in ("1", "True", "true"),
                "file_output": safe_str(parts[8]) if len(parts) > 8 else "",
                "notes": safe_str(parts[9]) if len(parts) > 9 else "",
            })

        print(f"[INFO] Parsed {len(results)} malfind records")
        return results
