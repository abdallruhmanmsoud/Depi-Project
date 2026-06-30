"""
DLL Normalizer
Parses Volatility 3 windows.dlllist.DllList output.

Expected header:
  PID  Process  Base  Size  Name  Path  LoadCount  LoadTime  File output
"""

from normalization.utils import (
    is_valid_data_line, is_header_line,
    safe_str, safe_int, read_lines,
)


class DLLNormalizer:

    HEADER_START = "PID\tProcess\tBase"
    MIN_COLUMNS = 8

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

            load_count_raw = parts[6].strip()
            load_count = safe_int(load_count_raw) if load_count_raw not in ("-", "N/A", "") else None

            load_time_raw = safe_str(parts[7])
            load_time = load_time_raw if load_time_raw else None

            results.append({
                "pid": pid,
                "process": parts[1].strip(),
                "base_address": safe_str(parts[2]),
                "size": safe_str(parts[3]),
                "dll_name": safe_str(parts[4]),
                "path": safe_str(parts[5]),
                "load_count": load_count,
                "load_time": load_time,
                "file_output": safe_str(parts[8]) if len(parts) > 8 else "",
            })

        print(f"[INFO] Parsed {len(results)} DLL records")
        return results
