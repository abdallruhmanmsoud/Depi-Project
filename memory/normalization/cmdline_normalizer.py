"""
Command Line Normalizer
Parses Volatility 3 windows.cmdline.CmdLine output.

Expected header:
  PID  Process  Args
"""

from normalization.utils import (
    is_valid_data_line, is_header_line,
    safe_str, read_lines,
)


class CmdlineNormalizer:

    HEADER_START = "PID\tProcess\tArgs"
    MIN_COLUMNS = 3

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
                "command_line": safe_str(parts[2]),
            })

        print(f"[INFO] Parsed {len(results)} cmdline records")
        return results
