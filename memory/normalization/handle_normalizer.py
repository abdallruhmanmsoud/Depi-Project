"""
Handle Normalizer
Parses Volatility 3 windows.handles.Handles output.

Expected header:
  PID  Process  Offset  HandleValue  Type  GrantedAccess  Name
"""

from normalization.utils import (
    is_valid_data_line, is_header_line,
    safe_str, read_lines,
)


class HandleNormalizer:

    HEADER_START = "PID\tProcess\tOffset"
    MIN_COLUMNS = 7

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

            results.append({
                "pid": pid,
                "process": parts[1].strip(),
                "offset": safe_str(parts[2]),
                "handle_value": safe_str(parts[3]),
                "type": parts[4].strip(),
                "granted_access": safe_str(parts[5]),
                "name": safe_str(parts[6]),
            })

        print(f"[INFO] Parsed {len(results)} handle records")
        return results
