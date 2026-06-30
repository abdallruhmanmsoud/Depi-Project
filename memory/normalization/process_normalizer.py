"""
Process Normalizer
Parses Volatility 3 windows.pslist.PsList output.

Expected header:
  PID  PPID  ImageFileName  Offset(V)  Threads  Handles  SessionId  Wow64  CreateTime  ExitTime  File output
"""

from normalization.utils import (
    is_valid_data_line, is_header_line,
    safe_int, safe_str, safe_bool, read_lines,
)


class ProcessNormalizer:

    HEADER_START = "PID\tPPID"
    MIN_COLUMNS = 10

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

            try:
                ppid = int(parts[1])
            except ValueError:
                continue

            process = {
                "pid": pid,
                "ppid": ppid,
                "process_name": parts[2].strip(),
                "offset": safe_str(parts[3]),
                "threads": safe_int(parts[4]),
                "handles": safe_str(parts[5]),
                "session_id": safe_str(parts[6]),
                "wow64": safe_bool(parts[7]),
                "create_time": safe_str(parts[8]),
                "exit_time": None if parts[9].strip() in ("N/A", "-", "") else parts[9].strip(),
                "file_output": safe_str(parts[10]) if len(parts) > 10 else "",
            }

            results.append(process)

        print(f"[INFO] Parsed {len(results)} process records")
        return results
