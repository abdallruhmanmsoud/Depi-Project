"""
Privilege Normalizer
Parses Volatility 3 windows.privileges.Privs output.

Expected header:
  PID  Process  Value  Privilege  Attributes  Description
"""

from normalization.utils import (
    is_valid_data_line, is_header_line,
    safe_str, safe_int, read_lines,
)


class PrivilegeNormalizer:

    HEADER_START = "PID\tProcess\tValue"
    MIN_COLUMNS = 6

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

            parts = line.strip().split("\t")

            if len(parts) < self.MIN_COLUMNS:
                continue

            try:
                pid = int(parts[0])
            except ValueError:
                continue

            attrs = parts[4].strip()

            results.append({
                "pid": pid,
                "process": parts[1].strip(),
                "value": safe_int(parts[2]),
                "privilege": parts[3].strip(),
                "attributes": attrs,
                "description": safe_str(parts[5]),
                "enabled": "Enabled" in attrs,
                "present": "Present" in attrs,
                "default": "Default" in attrs,
            })

        print(f"[INFO] Parsed {len(results)} privilege records")
        return results
